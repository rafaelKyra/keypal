//! Zeroizing AEAD wrapper — mitigation for the weakest volatile-key gap.
//!
//! **The gap this addresses.** `Aes256Gcm::new(key)` / `ChaCha20Poly1305::new(key)`
//! expand the 256-bit key into a round-key schedule held in an ordinary heap
//! allocation inside the cipher struct. When the struct is dropped, that
//! schedule is freed — not zeroized — leaving a recoverable copy of key
//! material in freed heap pages (swappable, core-dumpable, readable by a
//! later allocator).
//!
//! **What this module does (and does not do).**
//! - The raw 32-byte key is held in `zeroize::Zeroizing<Vec<u8>>`: it is
//!   wiped in place on drop, and the buffer is the *only* long-lived copy
//!   of the key in this module.
//! - The cipher struct is constructed **per operation** and dropped at the
//!   end of the operation scope, minimizing the lifetime of the expanded
//!   schedule.
//! - It does **not** zeroize the expanded schedule itself: that memory
//!   belongs to the `aes-gcm` / `chacha20poly1305` crates and is not
//!   reachable from here. A complete fix requires a patched dependency or a
//!   cipher pool whose buffers are `SecureBuffer`-backed (next session).
//!
//! No new dependencies are introduced; both cipher crates are already in
//! Cargo.toml. Both crates re-export the same `cipher::KeyInit` trait, so a
//! single import provides `new_from_slice` for both types. AAD is passed
//! via the aead-0.5 `Payload { msg, aad }` struct (there is no `Aad` type
//! in aead 0.5.2 — verified against the registry source).

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, Zeroizing};

/// Which AEAD construction a [`ZeroingCipher`] uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// AEAD wrapper that keeps the raw key in a zeroize-on-drop buffer and
/// scopes the expanded cipher struct to a single operation.
pub struct ZeroingCipher {
    kind: CipherKind,
    /// Raw 256-bit key. `Zeroizing` wipes these bytes in place on drop.
    key: Zeroizing<Vec<u8>>,
}

impl ZeroingCipher {
    /// Wrap a 256-bit key. The key bytes are copied into a zeroizing buffer;
    /// the caller's slice is not touched.
    pub fn new(kind: CipherKind, key: &[u8; 32]) -> Self {
        Self {
            kind,
            key: Zeroizing::new(key.to_vec()),
        }
    }

    /// Encrypt `plaintext` under `nonce` with associated data `aad`.
    /// Returns the ciphertext (authentication tag appended, AAD excluded).
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let n = Nonce::from_slice(nonce);
        let payload = Payload { msg: plaintext, aad };
        match self.kind {
            CipherKind::Aes256Gcm => {
                // Cipher struct (and its expanded round keys) lives only for
                // this statement block.
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.encrypt(n, payload).map_err(|e| e.to_string())
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.encrypt(n, payload).map_err(|e| e.to_string())
            }
        }
    }

    /// Decrypt `ciphertext` (tag appended, AAD excluded) under `nonce`/`aad`.
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let n = Nonce::from_slice(nonce);
        let payload = Payload { msg: ciphertext, aad };
        match self.kind {
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.decrypt(n, payload).map_err(|e| e.to_string())
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.decrypt(n, payload).map_err(|e| e.to_string())
            }
        }
    }

    /// Explicitly wipe the raw key buffer. `Drop` does this anyway; this is
    /// for callers that want an early, deterministic wipe.
    pub fn zeroize_key(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn roundtrip_both_ciphers_with_aad() {
        let nonce = [7u8; 12];
        let aad = b"associated-data";
        let pt = b"secret payload";

        for kind in [CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305] {
            let c = ZeroingCipher::new(kind, &key(1));
            let ct = c.encrypt(&nonce, aad, pt).unwrap();
            assert_ne!(ct.as_slice(), pt, "ciphertext must differ from plaintext");
            let back = c.decrypt(&nonce, aad, &ct).unwrap();
            assert_eq!(back.as_slice(), pt);
        }
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let nonce = [9u8; 12];
        let c1 = ZeroingCipher::new(CipherKind::Aes256Gcm, &key(1));
        let ct = c1.encrypt(&nonce, b"", b"data").unwrap();
        let c2 = ZeroingCipher::new(CipherKind::Aes256Gcm, &key(2));
        assert!(c2.decrypt(&nonce, b"", &ct).is_err(), "wrong key must not decrypt");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let nonce = [3u8; 12];
        let c = ZeroingCipher::new(CipherKind::ChaCha20Poly1305, &key(5));
        let mut ct = c.encrypt(&nonce, b"ctx", b"payload").unwrap();
        ct[0] ^= 0xFF;
        assert!(c.decrypt(&nonce, b"ctx", &ct).is_err(), "tamper must be detected");
    }

    #[test]
    fn wrong_aad_fails_authentication() {
        let nonce = [4u8; 12];
        let c = ZeroingCipher::new(CipherKind::Aes256Gcm, &key(6));
        let ct = c.encrypt(&nonce, b"aad-one", b"payload").unwrap();
        assert!(c.decrypt(&nonce, b"aad-two", &ct).is_err(), "AAD mismatch must fail");
    }

    #[test]
    fn zeroize_key_wipes_the_raw_buffer() {
        let mut c = ZeroingCipher::new(CipherKind::Aes256Gcm, &key(0xAB));
        c.zeroize_key();
        assert!(c.key.iter().all(|&b| b == 0), "raw key buffer must be all zeros");
    }
}
