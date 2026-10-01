//! KDF helpers: Argon2id (master-key derivation) + HKDF-SHA256 (domain separation).

use argon2::{Argon2, Algorithm, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte master key from `pass` + `salt` using Argon2id with the given policy.
/// The output is returned as a plain `Vec<u8>` (caller immediately moves it into a
/// [`crate::secure_mem::SecureBuffer`] and wipes this transient copy).
pub fn argon2id_32b(pass: &[u8], salt: &[u8], policy: crate::key_lifecycle::ArgonPolicy) -> Result<Vec<u8>, crate::KeypalError> {
    let params = Params::new(policy.memory_cost_kib, policy.time_cost, policy.parallelism as u32, Some(32))
        .map_err(|e| crate::KeypalError::Crypto(format!("invalid Argon2 params: {e}")))?;

    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = vec![0u8; 32];
    kdf.hash_password_into(pass, salt, &mut out)
        .map_err(|e| crate::KeypalError::Crypto(format!("Argon2id KDF failed: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256 domain separation: derive a 32-byte subkey from `ikm` under an
/// application-specific `info` label. This is how we split one master key into
/// enc / mac / wipe domains without re-running the expensive KDF.
pub fn hkdf_domain(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm); // no salt (IKM is already high-entropy)
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand: 32 bytes always fits");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_lifecycle::ArgonPolicy;

    #[test]
    fn argon2id_produces_32_bytes() {
        let out = argon2id_32b(b"password", &[1u8; 16], ArgonPolicy::sota()).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn hkdf_domains_differ() {
        let ikm = [5u8; 32];
        let a = hkdf_domain(&ikm, b"domain/a");
        let b = hkdf_domain(&ikm, b"domain/b");
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_is_deterministic() {
        let ikm = [5u8; 32];
        assert_eq!(hkdf_domain(&ikm, b"x"), hkdf_domain(&ikm, b"x"));
    }
}
