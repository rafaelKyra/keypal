//! # Crypto primitives — AEAD + KDF helpers
//!
//! Thin, auditable wrappers over RustCrypto. All key material flows through
//! [`crate::secure_mem::SecureBuffer`] or fixed-size `[u8; 32]` arrays that are
//! zeroized at the lifecycle boundary (see [`crate::key_lifecycle`]).

pub mod aead;
pub mod kdf;

/// Re-export the cipher selector so the storage layer can name it as `crate::crypto::Cipher`
/// without reaching into the `aead` module. The type itself lives in [`aead::Cipher`].
pub use aead::Cipher;
pub mod zeroing_cipher;
