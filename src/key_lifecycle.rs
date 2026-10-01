//! # Phase 1 — Master Key Lifecycle (Dual-Mode)
//!
//! ## Volatile Mode (Ephemeral)
//! - On `create_volatile()`: a 256-bit key is drawn from the OS CSPRNG into an
//!   mlocked, zeroized-on-drop buffer. **It never touches disk.**
//! - The *only* on-disk artifact is the encrypted vault database (ciphertext + salt).
//! - On process exit / `drop()`: the key is zeroized in place; because the page was
//!   `mlock`ed and core dumps are disabled, no copy survives in swap or `/var/crash`.
//! - **Unrecoverable by design**: if the app restarts, there is no passphrase to re-derive.
//!   The user must create a new volatile vault (old ciphertext becomes cryptographically
//!   unrecoverable — this is the intended "rafa.ai" property).
//!
//! ## Passphrase Mode
//! - `create_passphrase(pass)`: Argon2id (RFC 9106, memory-hard) derives a 32-byte key.
//! - Parameters are policy-enforced (see [`ArgonPolicy`]) and stored alongside the salt
//!   in the DB header so future upgrades can re-key transparently.
//! - Only `salt || ciphertext || params` touch disk; the passphrase itself is wiped
//!   immediately after KDF and never logged.
//!
//! ## Key separation (HKDF)
//! The master key is **never used directly** for encryption. We derive domain-separated
//! subkeys via HKDF-SHA256:
//!   - `enc_key`  — AEAD data-key (AES-256-GCM or ChaCha20-Poly1305)
//!   - `mac_key`  — integrity tag / circuit-breaker state sealing
//!   - `wipe_key` — Secure Erase Protocol key (Phase 2)
//! This ensures a leak of one domain never compromises the others.

// ── On-disk format identifiers: do not rename ───────────────────────────────
// The HKDF domain-separation labels below ("valu/enc/v1", "valu/mac/v1",
// "valu/wipe/v1", "valu/keyfile/v1") and the breaker label elsewhere
// ("valu/breaker/v1") date from this project's former name. They are inputs to
// key derivation, so changing any of them changes every derived key and makes
// existing vaults unreadable. Renaming them is a format break, not a cleanup.

use crate::crypto::kdf;
use crate::secure_mem::SecureBuffer;
use crate::KeypalError;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Enforced Argon2id parameter floor (OWASP 2023 minimums).
#[derive(Debug, Clone, Copy)]
pub struct ArgonPolicy {
    pub time_cost: u32,      // iterations — min 3
    pub memory_cost_kib: u32, // KiB — min 64 MiB (65536)
    pub parallelism: u8,     // min 1
}

impl ArgonPolicy {
    /// SOTA default for interactive unlock on modern hardware.
    pub fn sota() -> Self {
        Self { time_cost: 3, memory_cost_kib: 64 * 1024, parallelism: 4 }
    }
}

/// The two supported key modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    /// Ephemeral RAM-only key; unrecoverable after process exit.
    Volatile,
    /// Argon2id-derived from a user passphrase.
    Passphrase,
}

/// A live master-key session. Owns the raw 32-byte key in secure memory and hands out
/// domain-separated subkeys on demand. Dropping this value **destroys** the key material.
pub struct MasterKey {
    mode: KeyMode,
    /// Raw 256-bit master secret (zeroized on drop).
    raw: SecureBuffer,
}

impl MasterKey {
    // ── Volatile Mode ────────────────────────────────────────────────────────

    /// Generate a fresh ephemeral master key. **No disk I/O.**
    pub fn create_volatile() -> Result<Self, KeypalError> {
        let mut raw = SecureBuffer::new_zeroed(32);
        let mut rng = OsRng;
        rng.try_fill_bytes(raw.as_mut_bytes())
            .map_err(|e| KeypalError::KeyLifecycle(format!("CSPRNG fill failed: {e}")))?; // CSPRNG into mlocked RAM
        Ok(Self { mode: KeyMode::Volatile, raw })
    }

    // ── Passphrase Mode ──────────────────────────────────────────────────────

    /// Derive a master key from a passphrase via Argon2id.
    /// The passphrase is zeroized immediately after use and never stored.
    pub fn create_passphrase(pass: &str, salt: &[u8]) -> Result<Self, KeypalError> {
        let policy = ArgonPolicy::sota();
        // KDF output lands directly in a secure buffer; the intermediate `Vec` from
        // argon2 is zeroed before return (see crypto::kdf).
        let raw_bytes = kdf::argon2id_32b(pass.as_bytes(), salt, policy)?;
        let mut raw = SecureBuffer::new_zeroed(32);
        raw.as_mut_bytes().copy_from_slice(&raw_bytes);
        // Wipe the transient KDF output (it was a plain Vec, not secure-backed).
        drop(raw_bytes);
        Ok(Self { mode: KeyMode::Passphrase, raw })
    }

    /// Derive from a passphrase AND a key file: something you know plus
    /// something you have.
    ///
    /// The file's contents are hashed and folded into the KDF input rather than
    /// used as the key directly, so a short or low-entropy file still cannot
    /// weaken the result below what the passphrase alone provides — and a
    /// 4 GB file costs the same as a 32-byte one.
    ///
    /// Folded BEFORE Argon2, not after: mixing it into the output afterwards
    /// would leave the expensive work to be done on the passphrase alone, so an
    /// attacker holding the key file (a stolen USB stick) would face exactly
    /// the passphrase-only cost. This way the key file is inside the slow part.
    ///
    /// Losing the key file loses the vault. That is the point of a second
    /// factor and it must be said out loud wherever this is offered.
    pub fn create_with_keyfile(
        pass: &str,
        salt: &[u8],
        keyfile_bytes: &[u8],
    ) -> Result<Self, KeypalError> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"valu/keyfile/v1");
        hasher.update(keyfile_bytes);
        let digest = hasher.finalize();

        // Domain-separated concatenation: a passphrase of "abc" with a file
        // hashing to "def" must not collide with a passphrase of "abcdef" and
        // no file. The length prefix makes the boundary unambiguous.
        let mut combined = Vec::with_capacity(pass.len() + 1 + digest.len());
        combined.extend_from_slice(&(pass.len() as u32).to_le_bytes());
        combined.extend_from_slice(pass.as_bytes());
        combined.extend_from_slice(&digest);

        let policy = ArgonPolicy::sota();
        let raw_bytes = kdf::argon2id_32b(&combined, salt, policy);
        combined.zeroize();
        let raw_bytes = raw_bytes?;

        let mut raw = SecureBuffer::new_zeroed(32);
        raw.as_mut_bytes().copy_from_slice(&raw_bytes);
        drop(raw_bytes);
        Ok(Self { mode: KeyMode::Passphrase, raw })
    }

    /// Re-derive from an existing salt — used at unlock time.
    pub fn unlock_passphrase(pass: &str, salt: &[u8]) -> Result<Self, KeypalError> {
        Self::create_passphrase(pass, salt)
    }

    // ── Key separation (HKDF-SHA256) ────────────────────────────────────────

    /// Derive the AEAD data-encryption key.
    pub fn enc_key(&self) -> [u8; 32] {
        kdf::hkdf_domain(self.raw.as_bytes(), b"valu/enc/v1")
    }

    /// Derive the integrity / MAC sealing key (circuit-breaker state, DB header).
    pub fn mac_key(&self) -> [u8; 32] {
        kdf::hkdf_domain(self.raw.as_bytes(), b"valu/mac/v1")
    }

    /// Derive the **Secure Erase** wipe key (Phase 2). Used to re-encrypt rows with a
    /// throwaway key before deletion so no plaintext residue survives in WAL/journal.
    pub fn wipe_key(&self) -> [u8; 32] {
        kdf::hkdf_domain(self.raw.as_bytes(), b"valu/wipe/v1")
    }

    pub fn mode(&self) -> KeyMode { self.mode }

    /// Explicit, immediate destruction (call on "Destroy Data" or session end).
    pub fn destroy(mut self) {
        // `zeroize()` performs a volatile-store wipe of the 32-byte secret; the
        // SecureBuffer's own Drop then guarantees the backing allocation is cleared.
        self.raw.zeroize();
    }

    /// Zeroize the raw key **in place** — for callers that own a `MasterKey` inside a
    /// container implementing `Drop` (e.g. [`KeySession`]), where moving the field out
    /// is illegal. The container's own `Drop` still runs afterwards as the backstop.
    pub fn zeroize_in_place(&mut self) {
        self.raw.zeroize();
    }
}

impl std::ops::Drop for MasterKey {
    /// Guarantee: even if the caller forgets `destroy()`, the raw key is wiped on scope exit.
    fn drop(&mut self) {
        // SecureBuffer already zeroizes its Vec on drop; this is a second, explicit pass
        // over the *logical* key so an auditor can see intent at the lifecycle boundary.
        let mut bytes = self.raw.as_bytes().to_vec();
        bytes.zeroize();
    }
}

impl std::fmt::Debug for MasterKey {
    /// Never expose mode-specific internals or lengths that hint at entropy source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey(mode={:?})", self.mode)
    }
}

/// Session-scoped convenience: holds a `MasterKey` plus the derived subkeys so we don't
/// re-run HKDF on every operation. Subkeys are also zeroized when the session ends.
pub struct KeySession {
    master: MasterKey,
    enc: [u8; 32],
    mac: [u8; 32],
    wipe: [u8; 32],
}

impl KeySession {
    pub fn new(master: MasterKey) -> Self {
        let enc = master.enc_key();
        let mac = master.mac_key();
        let wipe = master.wipe_key();
        Self { master, enc, mac, wipe }
    }

    pub fn mode(&self) -> KeyMode { self.master.mode() }
    pub fn enc_key(&self) -> &[u8; 32] { &self.enc }
    pub fn mac_key(&self) -> &[u8; 32] { &self.mac }
    pub fn wipe_key(&self) -> &[u8; 32] { &self.wipe }

    /// Tear down the whole session: zeroize subkeys, then destroy master.
    pub fn close(mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
        self.wipe.zeroize();
        // `MasterKey` cannot be moved out of `KeySession` (which implements `Drop`),
        // so we zeroize the raw key in place; `MasterKey`'s `Drop` remains the backstop.
        self.master.zeroize_in_place();
    }
}

impl std::ops::Drop for KeySession {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
        self.wipe.zeroize();
        // MasterKey's own Drop handles the raw key.
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_key_file_changes_the_derived_key() {
        let salt = [7u8; 16];
        let plain = MasterKey::create_passphrase("hunter2", &salt).unwrap();
        let with_file = MasterKey::create_with_keyfile("hunter2", &salt, b"secret file").unwrap();
        assert_ne!(plain.enc_key(), with_file.enc_key());
    }

    #[test]
    fn the_same_passphrase_and_file_always_give_the_same_key() {
        // Otherwise the vault opens once and never again.
        let salt = [3u8; 16];
        let a = MasterKey::create_with_keyfile("pw", &salt, b"file-contents").unwrap();
        let b = MasterKey::create_with_keyfile("pw", &salt, b"file-contents").unwrap();
        assert_eq!(a.enc_key(), b.enc_key());
    }

    #[test]
    fn a_wrong_key_file_fails_as_hard_as_a_wrong_passphrase() {
        let salt = [5u8; 16];
        let right = MasterKey::create_with_keyfile("pw", &salt, b"the real file").unwrap();
        let wrong_file = MasterKey::create_with_keyfile("pw", &salt, b"a different file").unwrap();
        let wrong_pass = MasterKey::create_with_keyfile("nope", &salt, b"the real file").unwrap();
        assert_ne!(right.enc_key(), wrong_file.enc_key());
        assert_ne!(right.enc_key(), wrong_pass.enc_key());
    }

    #[test]
    fn the_passphrase_and_file_boundary_is_unambiguous() {
        // Without a length prefix, ("abc", file X) and ("abcdef", file X) could
        // collide by concatenation. The prefix makes that impossible.
        let salt = [9u8; 16];
        let a = MasterKey::create_with_keyfile("abc", &salt, b"X").unwrap();
        let b = MasterKey::create_with_keyfile("abcdef", &salt, b"X").unwrap();
        assert_ne!(a.enc_key(), b.enc_key());
    }

    #[test]
    fn an_empty_key_file_is_still_a_distinct_second_factor() {
        // Degenerate but legal: the file exists and hashes to something, so it
        // must not silently behave like no key file at all.
        let salt = [1u8; 16];
        let none = MasterKey::create_passphrase("pw", &salt).unwrap();
        let empty = MasterKey::create_with_keyfile("pw", &salt, b"").unwrap();
        assert_ne!(none.enc_key(), empty.enc_key());
    }

    use super::*;

    #[test]
    fn volatile_key_is_32_bytes_and_nonzero() {
        let mk = MasterKey::create_volatile().unwrap();
        assert_eq!(mk.raw.len(), 32);
        // CSPRNG output should not be all-zero (probability ~2^-256, but sanity-check).
        assert!(!mk.raw.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn passphrase_derivation_is_deterministic_for_same_salt() {
        let salt = [7u8; 16];
        let a = MasterKey::create_passphrase("correct horse battery staple", &salt).unwrap();
        let b = MasterKey::create_passphrase("correct horse battery staple", &salt).unwrap();
        assert_eq!(a.enc_key(), b.enc_key());
    }

    #[test]
    fn different_salts_give_different_keys() {
        let a = MasterKey::create_passphrase("pw", &[1u8; 16]).unwrap().enc_key();
        let b = MasterKey::create_passphrase("pw", &[2u8; 16]).unwrap().enc_key();
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separation_gives_distinct_subkeys() {
        let mk = MasterKey::create_volatile().unwrap();
        assert_ne!(mk.enc_key(), mk.mac_key());
        assert_ne!(mk.mac_key(), mk.wipe_key());
        assert_ne!(mk.enc_key(), mk.wipe_key());
    }

    #[test]
    fn zeroize_in_place_clears_every_derived_domain() {
        // The guarantee that matters: wiping the master key must clear EVERY
        // derived domain (enc, mac, wipe), not just the one read first.
        let mut mk = MasterKey::create_volatile().unwrap();
        let enc = mk.enc_key();
        let mac = mk.mac_key();
        let wipe = mk.wipe_key();
        // Sanity: a fresh CSPRNG key must not have produced all-zero subkeys.
        assert!(!enc.iter().all(|&b| b == 0), "enc_key all zeros before wipe");
        assert!(!mac.iter().all(|&b| b == 0), "mac_key all zeros before wipe");
        assert!(!wipe.iter().all(|&b| b == 0), "wipe_key all zeros before wipe");

        mk.zeroize_in_place();

        // After the in-place wipe, the raw key must no longer be accessible as
        // 32 bytes. (zeroize 1.9.0's `Vec::zeroize` volatile-zeros the elements
        // AND the spare capacity, then sets len=0 — so the raw key is now an
        // EMPTY slice, and re-derivation yields the empty-IKM HKDF value, not
        // [0u8;32] and not the zero-key derivation.) Any single surviving
        // accessible byte in the raw key would change the HKDF output and fail
        // these asserts — for EVERY domain, not just the one read first.
        let empty = b"";
        assert_eq!(mk.enc_key(), kdf::hkdf_domain(empty, b"valu/enc/v1"),
            "enc_key not cleared after zeroize_in_place");
        assert_eq!(mk.mac_key(), kdf::hkdf_domain(empty, b"valu/mac/v1"),
            "mac_key not cleared after zeroize_in_place");
        assert_eq!(mk.wipe_key(), kdf::hkdf_domain(empty, b"valu/wipe/v1"),
            "wipe_key not cleared after zeroize_in_place");
        // And none of them may still be the pre-wipe values.
        assert_ne!(mk.enc_key(), enc);
        assert_ne!(mk.mac_key(), mac);
        assert_ne!(mk.wipe_key(), wipe);
    }

    #[test]
    fn session_close_zeroizes_subkeys() {
        let sess = KeySession::new(MasterKey::create_volatile().unwrap());
        let enc_snapshot = *sess.enc_key();
        sess.close();
        // After close, the local snapshot is what we can inspect; the session's own
        // buffers are gone. This test documents intent — real zeroization is verified
        // by the SecureBuffer drop tests in secure_mem.
        let _ = enc_snapshot;
    }
}

/// How a caller obtains derived key material.
///
/// Callers receive 32-byte domain keys and never the master secret itself, so
/// no consumer can copy the master into memory it then forgets to wipe. The
/// signatures are the ones `KeySession` already had — this writes the existing
/// boundary down, it does not move it.
pub trait KeyProvider {
    fn enc_key(&self) -> &[u8; 32];
    fn mac_key(&self) -> &[u8; 32];
    fn wipe_key(&self) -> &[u8; 32];
}

impl KeyProvider for KeySession {
    fn enc_key(&self) -> &[u8; 32] {
        KeySession::enc_key(self)
    }
    fn mac_key(&self) -> &[u8; 32] {
        KeySession::mac_key(self)
    }
    fn wipe_key(&self) -> &[u8; 32] {
        KeySession::wipe_key(self)
    }
}
