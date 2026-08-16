//! TOTP — RFC 6238 time-based one-time passwords.
//!
//! A password vault that stores your second factor next to your password has
//! not obviously improved your security; what it has done is make the second
//! factor usable, so people stop disabling it. That trade is the whole reason
//! this module exists, and it is worth stating plainly rather than implying
//! that two factors in one vault are two independent factors.
//!
//! The secret itself never leaves the vault's encrypted storage until a code is
//! generated, and the generated code is public by design — it is what you type
//! into the website.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;

/// Default period in seconds. Every mainstream authenticator uses 30.
pub const PERIOD: u64 = 30;

#[derive(Debug, PartialEq)]
pub enum TotpError {
    /// The stored secret is not valid Base32.
    BadSecret,
    /// The system clock is before the Unix epoch.
    BadClock,
}

/// Accepts a raw Base32 secret or a full `otpauth://` URI.
///
/// Authenticator setup pages hand out both forms and users paste whichever
/// they were given, so refusing the URI would mean refusing half of them for no
/// reason. Whitespace and the padding some sites add are stripped: those are
/// display artefacts, not part of the secret.
pub fn normalize_secret(input: &str) -> Option<String> {
    let text = input.trim();
    let raw = if text.starts_with("otpauth://") {
        text.split(|c| c == '?' || c == '&')
            .find_map(|part| part.strip_prefix("secret="))?
            .to_string()
    } else {
        text.to_string()
    };
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .collect::<String>()
        .to_uppercase();
    if cleaned.is_empty() {
        return None;
    }
    // Only accept it if it actually decodes, so a typo is caught at save time
    // rather than surfacing as a wrong code months later.
    decode_secret(&cleaned).map(|mut bytes| {
        bytes.zeroize();
        cleaned
    })
}

fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)?;
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

/// Generate the 6-digit code for a given Unix timestamp.
pub fn code_at(secret: &str, unix_seconds: u64) -> Result<String, TotpError> {
    let mut key = decode_secret(secret).ok_or(TotpError::BadSecret)?;
    let counter = unix_seconds / PERIOD;

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| TotpError::BadSecret)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    key.zeroize();

    // RFC 4226 dynamic truncation: the low nibble of the last byte selects the
    // offset, so the whole digest contributes to which 4 bytes are used.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    Ok(format!("{:06}", binary % 1_000_000))
}

/// Generate the code for right now.
pub fn code_now(secret: &str) -> Result<String, TotpError> {
    code_at(secret, now_seconds()?)
}

/// Seconds remaining in the current window, for a countdown.
pub fn seconds_remaining() -> u64 {
    now_seconds().map(|s| PERIOD - (s % PERIOD)).unwrap_or(PERIOD)
}

fn now_seconds() -> Result<u64, TotpError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TotpError::BadClock)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B publishes expected values for the ASCII secret
    /// "12345678901234567890", which is Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
    /// Testing against the specification's own vectors is the only way to know
    /// the implementation is right rather than merely self-consistent.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_rfc6238_test_vectors() {
        // RFC 6238 lists SHA-1 values at these timestamps; the last 6 digits of
        // the published 8-digit values are what a 6-digit authenticator shows.
        assert_eq!(code_at(RFC_SECRET, 59).unwrap(), "287082");
        assert_eq!(code_at(RFC_SECRET, 1111111109).unwrap(), "081804");
        assert_eq!(code_at(RFC_SECRET, 1111111111).unwrap(), "050471");
        assert_eq!(code_at(RFC_SECRET, 1234567890).unwrap(), "005924");
        assert_eq!(code_at(RFC_SECRET, 2000000000).unwrap(), "279037");
    }

    #[test]
    fn code_is_stable_inside_a_window_and_changes_across_it() {
        // Codes must not flicker mid-window: a user typing one in has 30
        // seconds, not 30 chances at a moving target.
        // Start at a window boundary, so +1 is genuinely inside the same
        // window. Picking an arbitrary timestamp risks landing one second
        // before a boundary — 1111111109 and 1111111110 are in DIFFERENT
        // windows, which is exactly why RFC 6238 uses that pair to show codes
        // changing.
        let start = 1111111109 - (1111111109 % PERIOD);
        let a = code_at(RFC_SECRET, start).unwrap();
        assert_eq!(code_at(RFC_SECRET, start + 1).unwrap(), a);
        assert_eq!(code_at(RFC_SECRET, start + PERIOD - 1).unwrap(), a);
        assert_ne!(code_at(RFC_SECRET, start + PERIOD).unwrap(), a);
    }

    #[test]
    fn accepts_an_otpauth_uri_as_well_as_a_bare_secret() {
        let uri = format!(
            "otpauth://totp/Example:alice@example.com?secret={RFC_SECRET}&issuer=Example"
        );
        assert_eq!(normalize_secret(&uri).as_deref(), Some(RFC_SECRET));
        assert_eq!(normalize_secret(RFC_SECRET).as_deref(), Some(RFC_SECRET));
    }

    #[test]
    fn tolerates_the_spacing_and_padding_sites_add() {
        let spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(normalize_secret(spaced).as_deref(), Some(RFC_SECRET));
    }

    #[test]
    fn rejects_a_secret_that_is_not_base32() {
        // Caught at save time rather than surfacing as a wrong code later.
        assert!(normalize_secret("not valid base32 !!!").is_none());
        assert!(normalize_secret("").is_none());
        assert_eq!(code_at("!!!!", 0), Err(TotpError::BadSecret));
    }

    #[test]
    fn every_code_is_six_digits() {
        // A truncated code is a support ticket: format!("{:06}") must pad.
        for t in [0u64, 1, 59, 1234567890, 2000000000, 9999999999] {
            let code = code_at(RFC_SECRET, t).unwrap();
            assert_eq!(code.len(), 6, "code at {t} was {code}");
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
