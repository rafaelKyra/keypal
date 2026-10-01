//! AEAD helpers: AES-256-GCM and ChaCha20-Poly1305.
//!
//! Both provide 256-bit confidentiality + 128-bit integrity (GCM tag / Poly1305 MAC).
//! We expose a uniform `encrypt`/`decrypt` pair so the storage layer can swap ciphers
//! without touching call sites. Nonce management is **caller's responsibility** — we
//! use a 96-bit nonce built from a per-record counter (see storage layer) to guarantee
//! uniqueness under a fixed key.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroize;
// `KeyInit` is the single `cipher::KeyInit` trait re-exported by both crates;
// one import brings `::new` into scope for both `Aes256Gcm` and `ChaCha20Poly1305`.

/// Supported AEAD ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    pub fn name(self) -> &'static str {
        match self { Cipher::Aes256Gcm => "AES-256-GCM", Cipher::ChaCha20Poly1305 => "ChaCha20-Poly1305" }
    }

    /// Nonce size in bytes (both are 96-bit / 12-byte).
    pub fn nonce_size(self) -> usize { 12 }
}

/// Encrypt `plaintext` under `key` with the given `nonce`. Returns `ciphertext || tag`.
/// The plaintext buffer is zeroized after use.
pub fn encrypt(cipher: Cipher, key: &[u8; 32], nonce: &[u8; 12], mut plaintext: Vec<u8>) -> Result<Vec<u8>, crate::VaultlingError> {
    let ct = match cipher {
        Cipher::Aes256Gcm => {
            let enc = Aes256Gcm::new(key.into());
            enc.encrypt(nonce.into(), &plaintext[..])
                .map_err(|e| crate::VaultlingError::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
        Cipher::ChaCha20Poly1305 => {
            let enc = ChaCha20Poly1305::new(key.into());
            enc.encrypt(nonce.into(), &plaintext[..])
                .map_err(|e| crate::VaultlingError::Crypto(format!("ChaCha20-Poly1305 encrypt: {e}")))?
        }
    };
    plaintext.zeroize(); // wipe the in-memory copy immediately
    Ok(ct)
}

/// Decrypt `ciphertext || tag` under `key` with `nonce`. Returns fresh plaintext.
pub fn decrypt(cipher: Cipher, key: &[u8; 32], nonce: &[u8; 12], ct_tag: &[u8]) -> Result<Vec<u8>, crate::VaultlingError> {
    match cipher {
        Cipher::Aes256Gcm => {
            let dec = Aes256Gcm::new(key.into());
            dec.decrypt(nonce.into(), ct_tag)
                .map_err(|e| crate::VaultlingError::Crypto(format!("AES-GCM decrypt (tag mismatch?): {e}")))
        }
        Cipher::ChaCha20Poly1305 => {
            let dec = ChaCha20Poly1305::new(key.into());
            dec.decrypt(nonce.into(), ct_tag)
                .map_err(|e| crate::VaultlingError::Crypto(format!("ChaCha20-Poly1305 decrypt (tag mismatch?): {e}")))
        }
    }
}

/// Build a 96-bit nonce from a domain prefix + per-record counter + per-field index.
/// Uniqueness is guaranteed as long as `(key, domain, record_id, field)` tuples never repeat.
/// The `field` index (bytes 10..12) ensures each field of a record gets a distinct nonce,
/// preventing keystream reuse across fields under the same key.
pub fn build_nonce(domain: u16, record_id: u64, field: u16) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..2].copy_from_slice(&domain.to_le_bytes());
    n[2..10].copy_from_slice(&record_id.to_le_bytes());
    n[10..12].copy_from_slice(&field.to_le_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_roundtrip() {
        let key = [7u8; 32];
        let nonce = build_nonce(1, 42, 0);
        let pt = b"hello vault world".to_vec();
        let ct = encrypt(Cipher::Aes256Gcm, &key, &nonce, pt).unwrap();
        assert_ne!(ct.as_slice(), b"hello vault world");
        let pt2 = decrypt(Cipher::Aes256Gcm, &key, &nonce, &ct).unwrap();
        assert_eq!(pt2, b"hello vault world");
    }

    #[test]
    fn chacha_roundtrip() {
        let key = [9u8; 32];
        let nonce = build_nonce(2, 7, 0);
        let pt = b"secret entry".to_vec();
        let ct = encrypt(Cipher::ChaCha20Poly1305, &key, &nonce, pt).unwrap();
        let pt2 = decrypt(Cipher::ChaCha20Poly1305, &key, &nonce, &ct).unwrap();
        assert_eq!(pt2, b"secret entry");
    }

    #[test]
    fn tamper_detection() {
        let key = [1u8; 32];
        let nonce = build_nonce(3, 1, 0);
        let ct = encrypt(Cipher::Aes256Gcm, &key, &nonce, b"data".to_vec()).unwrap();
        let mut bad = ct.clone();
        bad[0] ^= 0xFF; // flip a ciphertext byte → tag must fail
        assert!(decrypt(Cipher::Aes256Gcm, &key, &nonce, &bad).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key = [1u8; 32];
        let other = [2u8; 32];
        let nonce = build_nonce(4, 9, 0);
        let ct = encrypt(Cipher::ChaCha20Poly1305, &key, &nonce, b"x".to_vec()).unwrap();
        assert!(decrypt(Cipher::ChaCha20Poly1305, &other, &nonce, &ct).is_err());
    }

    #[test]
    fn nonce_differs_per_field() {
        assert_ne!(build_nonce(1, 42, 0), build_nonce(1, 42, 2));
        assert_ne!(build_nonce(1, 42, 1), build_nonce(1, 42, 2));
    }
}
