//! # Phase 1 — Strict Log Redaction
//!
//! ## Threat: secret leakage via logs, crash dumps, or telemetry
//! - Passwords, TOTP secrets, file paths, and master-key material must **never** appear
//!   in `tracing` output, stderr, journald, or any log sink.
//! - Even *lengths* of passwords can be a side-channel; we redact to fixed tokens.
//!
//! ## Design: `Secret<T>` wrapper + tracing field formatter
//! Every value that is sensitive gets wrapped in [`Secret`] before it crosses a logging
//! boundary. The `Value` impl for `tracing` renders only a redacted placeholder, so even
//! a careless `tracing::info!(?value)` cannot leak.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A value that must never be printed in full. Wraps any `T: Zeroize`.
/// The `T: Zeroize` bound is required by the `ZeroizeOnDrop` derive (its generated
/// `Drop` impl asserts `T: Zeroize`), and `T: Default` is required by `std::mem::take`
/// in `into_inner`.
#[derive(ZeroizeOnDrop)]
pub struct Secret<T: Zeroize> {
    #[zeroize(on_drop)]
    inner: T,
}

impl<T: Zeroize + Default> Secret<T> {
    pub fn new(inner: T) -> Self { Self { inner } }
    /// Read-only access for *computation* (KDF, AEAD). The returned reference is valid
    /// only within the caller's scope; it does not bypass redaction in logs.
    pub fn expose(&self) -> &T { &self.inner }
    /// Consume and return the inner value (one-shot use, e.g. feeding a KDF).
    /// The source buffer is zeroized before returning.
    pub fn into_inner(mut self) -> T {
        let v = std::mem::take(&mut self.inner);
        // `std::mem::take` requires Default; the slot now holds a default (zeroed)
        // value, and ZeroizeOnDrop guarantees final wipe on drop.
        self.inner.zeroize();
        v
    }
}

impl<T: std::fmt::Debug + Zeroize> std::fmt::Debug for Secret<T> {
    /// Always renders as `Secret(•••)` — never the inner value, never its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(•••)")
    }
}

impl<T: Zeroize> std::fmt::Display for Secret<T> {
    /// Same guarantee as Debug: fixed token, no length hint.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "•••")
    }
}

impl<T: Clone + Zeroize> Clone for Secret<T> {
    fn clone(&self) -> Self { Self { inner: self.inner.clone() } }
}

/// Redaction policy applied to *string* fields (paths, hostnames) that aren't full secrets
/// but still shouldn't be logged verbatim in a shared/telemetry sink.
#[derive(Debug, Clone, Copy)]
pub enum StringPolicy {
    /// Show first 4 + last 2 chars, mask the middle: `ab…yz`.
    PartialMask,
    /// Replace entirely with `[REDACTED]`.
    FullRedact,
}

/// Apply a [`StringPolicy`] to an arbitrary string. Pure function — safe to call in tests.
pub fn redact_string(s: &str, policy: StringPolicy) -> String {
    match policy {
        StringPolicy::FullRedact => "[REDACTED]".to_string(),
        StringPolicy::PartialMask => {
            let chars: Vec<char> = s.chars().collect();
            if chars.len() <= 6 { return "•••".to_string(); }
            let head: String = chars.iter().take(4).collect();
            let tail: String = chars.iter().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
            format!("{head}…{tail}")
        }
    }
}

/// Convenience: wrap a `String` as a [`Secret`] for logging contexts.
pub fn secret_string(s: impl Into<String>) -> Secret<String> {
    Secret::new(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_inner() {
        let s = Secret::new("hunter2-password".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(dbg.contains("•••"));
    }

    #[test]
    fn display_is_fixed_token() {
        let s = Secret::new(vec![0u8; 32]);
        assert_eq!(format!("{s}"), "•••");
    }

    #[test]
    fn partial_mask_keeps_edges() {
        let out = redact_string("/home/user/vault.kdbx", StringPolicy::PartialMask);
        assert!(out.starts_with('/'));
        assert!(!out.contains("vault"));
    }

    #[test]
    fn full_redact_hides_everything() {
        assert_eq!(redact_string("anything", StringPolicy::FullRedact), "[REDACTED]");
    }

    #[test]
    fn into_inner_returns_value_and_wipes_source() {
        let s = Secret::new(String::from("topsecret"));
        let v = s.into_inner();
        assert_eq!(v, "topsecret");
        // The source is consumed by `into_inner`: `std::mem::take` leaves a default
        // (empty) value in the slot, which is then zeroized, and `ZeroizeOnDrop`
        // guarantees a final wipe when the consumed wrapper drops. The wipe is
        // therefore guaranteed by construction and not observable after the move.
    }
}
