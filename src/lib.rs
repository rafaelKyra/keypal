//! # Vaultling — SOTA Privacy-First Password Vault (Linux)
//!
//! Crate root. Module map:
//!
//! - [`secure_mem`]      — Phase 1: zeroization, `mlockall`, `SecureBuffer`
//! - [`key_lifecycle`]   — Phase 1: Volatile / Passphrase master-key lifecycle
//! - [`circuit_breaker`] — Phase 1: unlock-attempt state machine (brute-force guard)
//! - [`redaction`]       — Phase 1: log redaction wrapper (zero secrets in logs/dumps)
//! - [`storage`]         — Phase 2: encrypted SQLite wrapper + Secure Erase Protocol
//! - [`crypto`]          — AEAD helpers (AES-256-GCM / ChaCha20-Poly1305), KDF policy

pub mod circuit_breaker;
pub mod dbus;
pub mod totp;
pub mod audit;
pub mod kind;
pub mod import;
pub mod export;
pub mod crypto;
pub mod key_lifecycle;
pub mod redaction;
pub mod secure_mem;
pub mod storage;

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum VaultlingError {
    #[error("secure memory: {0}")]
    SecureMem(String),
    #[error("key lifecycle: {0}")]
    KeyLifecycle(String),
    #[error("circuit breaker open — unlock locked out (epoch secs: {0})")]
    LockedOut(u64),
    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("crypto: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, VaultlingError>;
