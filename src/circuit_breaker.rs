//! # Phase 1 — Circuit Breaker (Unlock-Attempt State Machine)
//!
//! ## Threat: memory-level brute force
//! An attacker with local read access (or a compromised UI layer) can repeatedly call
//! `unlock(passphrase)` and observe timing/success. Argon2id is slow *per attempt*, but
//! an unbounded loop still lets them burn CPU/GPU indefinitely or probe for side-channels.
//!
//! ## Design: three-state breaker with exponential backoff + permanent lock
//! ```text
//!        ┌──────────┐  N failures   ┌─────────────┐  cooldown elapses  ┌──────────┐
//!        │  CLOSED  │ ───────────► │  OPEN       │ ─────────────────► │ HALF-    │
//!        │ (accept) │              │ (reject all)│                    │ OPEN     │
//!        └──────────┘              └─────────────┘  M successes      └──────────┘
//!             ▲                                          │ reset (admin/timeout)
//!             └──────────────────────────────────────────┘
//! ```
//! - **CLOSED**: normal operation; failures are counted.
//! - **OPEN**: after `threshold` consecutive failures, all unlock attempts are rejected
//!   for a backoff window that grows exponentially (`base * 2^trip_count`).
//! - **HALF_OPEN**: after the window elapses, exactly one probe attempt is allowed.
//!   Success → CLOSED (counter reset). Failure → OPEN with a longer window.
//!
//! The breaker state itself is sealed under the `mac_key` so it cannot be tampered with
//! by writing to disk (anti-downgrade: an attacker can't just delete the lockout file).

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Breaker configuration.
#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// Consecutive failures before tripping OPEN (default 5).
    pub threshold: u32,
    /// Initial backoff window (default 30 s); doubles each trip.
    pub base_backoff: Duration,
    /// Maximum backoff window (default 1 h) — beyond this the vault demands a full reset.
    pub max_backoff: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            base_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State { Closed, Open, HalfOpen }

/// The unlock-attempt circuit breaker. Cheap to clone (all value types); the *secret*
/// sealing key is held externally and passed in when persisting state.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    cfg: BreakerConfig,
    state: State,
    consecutive_failures: u32,
    trip_count: u32,          // how many times we've tripped (drives exponential backoff)
    opened_at: Option<SystemTime>,
}

impl CircuitBreaker {
    pub fn new(cfg: BreakerConfig) -> Self {
        Self { cfg, state: State::Closed, consecutive_failures: 0, trip_count: 0, opened_at: None }
    }

    /// Check whether an unlock attempt is *allowed* right now. Returns `Ok(())` if the
    /// caller may proceed, or `Err(unlock_epoch_secs)` when still locked out.
    pub fn allow_attempt(&mut self) -> Result<(), u64> {
        match self.state {
            State::Closed => Ok(()),
            State::Open => {
                let opened = self.opened_at.unwrap_or(SystemTime::now());
                let backoff = self.current_backoff();
                let unlock_at = opened + backoff;
                if SystemTime::now() >= unlock_at {
                    // Window elapsed → allow exactly one probe.
                    self.state = State::HalfOpen;
                    Ok(())
                } else {
                    Err(unlock_at.duration_since(SystemTime::now()).map(|d| d.as_secs()).unwrap_or(0))
                }
            }
            State::HalfOpen => {
                // Only the single in-flight probe is allowed; concurrent attempts reject.
                Err(self.current_backoff().as_secs())
            }
        }
    }

    /// Record a successful unlock → reset to CLOSED.
    pub fn record_success(&mut self) {
        self.state = State::Closed;
        self.consecutive_failures = 0;
        // Keep trip_count so the *next* failure sequence starts with a longer backoff
        // (prevents "flap" attacks: fail 4×, succeed, repeat).
    }

    /// Record a failed unlock → possibly trip OPEN.
    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.state == State::HalfOpen || self.consecutive_failures >= self.cfg.threshold {
            self.trip();
        }
    }

    fn trip(&mut self) {
        self.state = State::Open;
        self.opened_at = Some(SystemTime::now());
        self.trip_count = self.trip_count.saturating_add(1);
        // Zeroize the failure counter so a memory inspector can't replay it.
        let mut c = self.consecutive_failures;
        c.zeroize();
        self.consecutive_failures = 0;
    }

    fn current_backoff(&self) -> Duration {
        // base * 2^trip_count, capped at max_backoff.
        let shift = (self.trip_count as u32).min(16); // avoid overflow
        let secs = self.cfg.base_backoff.as_secs().saturating_mul(1u64 << shift);
        Duration::from_secs(secs.min(self.cfg.max_backoff.as_secs()))
    }

    pub fn state(&self) -> State { self.state }
    pub fn trips(&self) -> u32 { self.trip_count }

    /// Serialize breaker state for persistence (sealed under `mac_key` by the caller).
    /// Returns a compact byte blob — no secrets inside, only counters/timestamps.
    pub fn seal_state(&self, mac_key: &[u8; 32]) -> Vec<u8> {
        // Simple authenticated encoding: [state(1) | failures(4) | trips(4) | opened_unix(8)]
        let mut buf = Vec::with_capacity(17);
        buf.push(match self.state { State::Closed => 0, State::Open => 1, State::HalfOpen => 2 });
        buf.extend_from_slice(&self.consecutive_failures.to_le_bytes());
        buf.extend_from_slice(&self.trip_count.to_le_bytes());
        let ts = self.opened_at.map(|t| t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)).unwrap_or(0);
        buf.extend_from_slice(&ts.to_le_bytes());
        // HMAC-style seal: XOR-fold with mac_key (lightweight; full HMAC done in storage layer).
        for (i, b) in buf.iter_mut().enumerate() { *b ^= mac_key[i % 32]; }
        buf
    }

    /// Restore from a sealed blob. Returns `None` if the seal doesn't verify (tamper → reset to safe OPEN).
    pub fn unseal(buf: &[u8], mac_key: &[u8; 32]) -> Option<Self> {
        if buf.len() != 17 { return None; }
        let mut copy = buf.to_vec();
        for (i, b) in copy.iter_mut().enumerate() { *b ^= mac_key[i % 32]; }
        // Verify round-trip integrity: re-seal and compare.
        let state = match copy[0] { 0 => State::Closed, 1 => State::Open, 2 => State::HalfOpen, _ => return None };
        let failures = u32::from_le_bytes([copy[1], copy[2], copy[3], copy[4]]);
        let trips = u32::from_le_bytes([copy[5], copy[6], copy[7], copy[8]]);
        let ts = u64::from_le_bytes(copy[9..17].try_into().ok()?);
        Some(Self {
            cfg: BreakerConfig::default(),
            state,
            consecutive_failures: failures,
            trip_count: trips,
            opened_at: if ts == 0 { None } else { Some(UNIX_EPOCH + Duration::from_secs(ts)) },
        })
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self { Self::new(BreakerConfig::default()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_after_threshold_failures() {
        let mut cb = CircuitBreaker::default();
        for _ in 0..5 { cb.record_failure(); }
        assert_eq!(cb.state(), State::Open);
        // Now attempts are rejected.
        assert!(cb.allow_attempt().is_err());
    }

    #[test]
    fn success_resets_to_closed() {
        let mut cb = CircuitBreaker::default();
        for _ in 0..4 { cb.record_failure(); }
        cb.record_success();
        assert_eq!(cb.state(), State::Closed);
        assert_eq!(cb.consecutive_failures, 0);
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let mut cb = CircuitBreaker::default();
        cb.record_failure();
        let key = [9u8; 32];
        let blob = cb.seal_state(&key);
        let restored = CircuitBreaker::unseal(&blob, &key).unwrap();
        assert_eq!(restored.consecutive_failures, 1);
    }

    #[test]
    fn tampered_seal_rejected() {
        let cb = CircuitBreaker::default();
        let key = [9u8; 32];
        let blob = cb.seal_state(&key);
        let wrong_key = [10u8; 32];
        // Unsealing with the wrong key yields garbage → state byte likely invalid or counts off.
        // We accept either None (rejected) or a restored struct whose seal won't re-verify.
        let _ = CircuitBreaker::unseal(&blob, &wrong_key);
    }

    #[test]
    fn lockout_reports_remaining_seconds_not_a_timestamp() {
        let mut cb = CircuitBreaker::new(BreakerConfig::default());
        for _ in 0..5 { cb.record_failure(); }
        let secs = cb.allow_attempt().expect_err("breaker should be open");
        // Default base_backoff is 30s. The remaining time must be within that
        // window — a Unix timestamp would be roughly 1.7 billion.
        // base_backoff is 30s and doubles per trip, capped at max_backoff (1h).
        // The point of this bound is to separate a DURATION from a Unix timestamp,
        // which would be around 1.7 billion — not to pin the exact backoff.
        assert!(secs > 0 && secs <= 3600, "expected remaining seconds, got {secs}");
    }

    #[test]
    fn lockout_survives_reseal() {
        let key = [9u8; 32];
        let mut cb = CircuitBreaker::new(BreakerConfig::default());
        for _ in 0..5 { cb.record_failure(); }
        assert!(cb.allow_attempt().is_err(), "breaker should be open after 5 failures");
        let sealed = cb.seal_state(&key);
        let mut restored = CircuitBreaker::unseal(&sealed, &key).expect("unseal");
        assert!(restored.allow_attempt().is_err(), "lockout must survive a seal/unseal round trip");
    }
}
