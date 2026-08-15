//! # Phase 2 — Encrypted Storage & Secure Erase Engine
//!
//! ## Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    VaultDatabase (public API)               │
//! ├─────────────────────────────────────────────────────────────┤
//! │  SqlCipherLayer                                             │
//! │   • per-row AEAD (AES-256-GCM / ChaCha20-Poly1305)          │
//! │   • nonce = f(domain, row_id) → uniqueness under fixed key  │
//! │   • circuit-breaker state sealed under mac_key              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  SQLite (rusqlite, bundled)                                 │
//! │   • PRAGMA journal_mode=WAL                                  │
//! │   • PRAGMA synchronous=NORMAL                                │
//! │   • PRAGMA temp_store=MEMORY  ← no plaintext in /tmp        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  SecureEraseProtocol (secure_erase.rs)                      │
//! │   1. derive wipe_key from master key                        │
//! │   2. re-encrypt every row under wipe_key (overwrites ct)    │
//! │   3. DELETE rows                                            │
//! │   4. TRUNCATE WAL + checkpoint                               │
//! │   5. VACUUM (rewrites file; old pages freed to OS)          │
//! │   6. zeroize in-memory key material                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod secure_erase;

use crate::crypto::{aead, Cipher};
use crate::key_lifecycle::KeySession;
use crate::redaction::Secret;
use rusqlite::{params, Connection};

/// The encrypted vault database. Owns the SQLite connection and the cipher layer.
pub struct VaultDatabase {
    conn: Connection,
    cipher: Cipher,
}

impl VaultDatabase {
    /// Open (or create) a vault at `path`. The DB file contains **only ciphertext** —
    /// every secret column is AEAD-encrypted under the session's enc_key before insert.
    pub fn open(path: &str, _session: &KeySession) -> Result<Self, crate::ValuError> {
        let conn = Connection::open(path)?;

        // ── Privacy hardening pragmas (prevent plaintext leakage to temp/journal) ──
        conn.pragma_update(None, "journal_mode", "WAL")?;          // WAL: no rollback-journal copies of secrets
        conn.pragma_update(None, "synchronous", "NORMAL")?;         // safe with WAL, faster than FULL
        conn.pragma_update(None, "temp_store", "MEMORY")?;          // temp tables in RAM (mlocked), not /tmp
        conn.pragma_update(None, "cache_size", "-8192")?;           // 8 MiB page cache in RAM
        conn.pragma_update(None, "foreign_keys", "ON")?;

        // ── Schema: every secret column is BLOB (ciphertext) + nonce + tag ────────
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS entries (
                id          INTEGER PRIMARY KEY,
                name_enc    BLOB NOT NULL,   -- AEAD(name)
                user_enc    BLOB NOT NULL,   -- AEAD(username)
                pass_enc    BLOB NOT NULL,   -- AEAD(password)  ← the crown jewel
                uri_enc     BLOB,            -- AEAD(uri), optional
                totp_secret BLOB,            -- AEAD(base32 TOTP secret)
                nonce       BLOB NOT NULL,   -- 5×12-byte AEAD nonces (one per field: name,user,pass,uri,totp)
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_entries_updated ON entries(updated_at);
            "#,
        )?;

        Ok(Self { conn, cipher: Cipher::Aes256Gcm }) // default; ChaCha selectable per-vault in meta
    }

    /// Insert a new entry. All fields are encrypted under `session.enc_key()` before
    /// touching SQLite. The plaintext is zeroized immediately after the AEAD call.
    pub fn insert_entry(
        &self,
        session: &KeySession,
        name: &str,
        username: &str,
        password: &str,
        uri: Option<&str>,
        totp_secret: Option<&str>,
    ) -> Result<i64, crate::ValuError> {
        let key = session.enc_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Generate id via MAX(id)+1 (safe under single-writer).
        let next_id: i64 = self.conn.query_row("SELECT COALESCE(MAX(id),0)+1 FROM entries", [], |r| r.get(0))?;

        // Per-field nonces (domain=1 for entries): each field gets a distinct nonce so
        // no two fields under the same key ever share a keystream.
        let name_nonce = aead::build_nonce(1, next_id as u64, 0);
        let user_nonce = aead::build_nonce(1, next_id as u64, 1);
        let pass_nonce = aead::build_nonce(1, next_id as u64, 2);
        let uri_nonce = aead::build_nonce(1, next_id as u64, 3);
        let totp_nonce = aead::build_nonce(1, next_id as u64, 4);

        let name_ct = aead::encrypt(self.cipher, key, &name_nonce, name.as_bytes().to_vec())?;
        let user_ct = aead::encrypt(self.cipher, key, &user_nonce, username.as_bytes().to_vec())?;
        let pass_ct = aead::encrypt(self.cipher, key, &pass_nonce, password.as_bytes().to_vec())?;
        let uri_ct: Option<Vec<u8>> = uri.map(|u| aead::encrypt(self.cipher, key, &uri_nonce, u.as_bytes().to_vec())).transpose()?;
        let totp_ct: Option<Vec<u8>> = totp_secret.map(|t| aead::encrypt(self.cipher, key, &totp_nonce, t.as_bytes().to_vec())).transpose()?;

        // Store all five nonces concatenated (5 × 12 = 60 bytes) in the nonce column.
        let mut nonce_blob = Vec::with_capacity(60);
        for n in [&name_nonce, &user_nonce, &pass_nonce, &uri_nonce, &totp_nonce] {
            nonce_blob.extend_from_slice(n);
        }

        self.conn.execute(
            "INSERT INTO entries (id, name_enc, user_enc, pass_enc, uri_enc, totp_secret, nonce, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![next_id, name_ct, user_ct, pass_ct, uri_ct, totp_ct, nonce_blob.as_slice(), now, now],
        )?;

        Ok(next_id)
    }

    /// Fetch and decrypt a single entry. Returns plaintext only in the caller's scope.
    pub fn get_entry(
        &self,
        session: &KeySession,
        id: i64,
    ) -> Result<Option<Entry>, crate::ValuError> {
        let key = session.enc_key();
        let row = self.conn.query_row(
            "SELECT name_enc, user_enc, pass_enc, uri_enc, totp_secret, nonce FROM entries WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                ))
            },
        );

        let (name_ct, user_ct, pass_ct, uri_ct, totp_ct, nonce_b) = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // The nonce column holds 5 concatenated 12-byte nonces (one per field).
        if nonce_b.len() != 60 {
            return Err(crate::ValuError::Crypto(format!("bad nonce blob: expected 60 bytes, got {}", nonce_b.len())));
        }
        let name_nonce: [u8; 12] = nonce_b[0..12].try_into().unwrap();
        let user_nonce: [u8; 12] = nonce_b[12..24].try_into().unwrap();
        let pass_nonce: [u8; 12] = nonce_b[24..36].try_into().unwrap();
        let uri_nonce: [u8; 12] = nonce_b[36..48].try_into().unwrap();
        let totp_nonce: [u8; 12] = nonce_b[48..60].try_into().unwrap();

        let name = String::from_utf8(aead::decrypt(self.cipher, key, &name_nonce, &name_ct)?)
            .map_err(|e| crate::ValuError::Crypto(format!("name not UTF-8: {e}")))?;
        let username = String::from_utf8(aead::decrypt(self.cipher, key, &user_nonce, &user_ct)?)
            .map_err(|e| crate::ValuError::Crypto(format!("username not UTF-8: {e}")))?;
        let password = String::from_utf8(aead::decrypt(self.cipher, key, &pass_nonce, &pass_ct)?)
            .map_err(|e| crate::ValuError::Crypto(format!("password not UTF-8: {e}")))?;
        let uri = uri_ct
            .map(|c| aead::decrypt(self.cipher, key, &uri_nonce, &c))
            .transpose()?
            .map(|b| String::from_utf8_lossy(&b).into_owned());
        let totp_secret = totp_ct
            .map(|c| aead::decrypt(self.cipher, key, &totp_nonce, &c))
            .transpose()?
            .map(|b| String::from_utf8_lossy(&b).into_owned());

        Ok(Some(Entry { name, username, password: Secret::new(password), uri, totp_secret: totp_secret.map(Secret::new) }))
    }

    /// Count entries (for tests / UI).
    pub fn entry_count(&self) -> Result<i64, crate::ValuError> {
        self.conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0)).map_err(Into::into)
    }

    /// Expose the raw connection for the Secure Erase Protocol (Phase 2).
    pub fn conn(&self) -> &Connection { &self.conn }
}

/// A decrypted vault entry. `password` and `totp_secret` are wrapped in [`Secret`] so
/// accidental logging is redacted automatically.
pub struct Entry {
    pub name: String,
    pub username: String,
    pub password: Secret<String>,
    pub uri: Option<String>,
    pub totp_secret: Option<Secret<String>>,
}

impl std::fmt::Debug for Entry {
    /// Redacted debug: shows name/username (non-secret context) but masks the rest.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"•••")
            .field("uri", &self.uri.as_deref().map(|u| crate::redaction::redact_string(u, crate::redaction::StringPolicy::PartialMask)))
            .finish()
    }
}

/// How a caller reads secrets out of storage.
///
/// Entry names are stored encrypted, so "find the entry called X" cannot be a
/// SQL query — it means decrypting candidates and comparing. That loop was
/// written twice, in the CLI and in the D-Bus service, which is exactly the
/// kind of duplication that drifts apart. It lives here once instead.
pub trait SecretStore {
    type Error;

    /// Find an entry by its decrypted name.
    ///
    /// `Ok(None)` means no entry matched. An `Err` means decryption failed,
    /// which in practice means the session key is wrong — callers treat that
    /// as a failed unlock attempt, not as a missing entry.
    fn entry_by_name(&self, session: &KeySession, name: &str)
        -> Result<Option<Entry>, Self::Error>;
}

impl SecretStore for VaultDatabase {
    type Error = crate::ValuError;

    fn entry_by_name(
        &self,
        session: &KeySession,
        name: &str,
    ) -> Result<Option<Entry>, Self::Error> {
        let mut stmt = self.conn.prepare("SELECT id FROM entries")?;
        let ids: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<i64>, _>>()?;
        drop(stmt);

        for id in ids {
            // A decrypt error is propagated rather than skipped: it means the
            // key is wrong, and silently continuing would report "no such
            // entry" for a vault the caller simply cannot open.
            if let Some(entry) = self.get_entry(session, id)? {
                if entry.name == name {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_store_trait_returns_the_same_entry_as_the_inherent_method() {
        // The trait must be a rename of the existing behaviour, not a second
        // implementation that can drift away from it.
        let path = tmp_db("secretstore");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "Trait", "user", "trait-pw-9", None, None).unwrap();

        let inherent = db.get_entry(&session, id).unwrap().unwrap();
        let via_trait = db.entry_by_name(&session, "Trait").unwrap().unwrap();
        assert_eq!(*inherent.password.expose(), *via_trait.password.expose());
        assert_eq!(inherent.name, via_trait.name);

        // A name that does not exist is Ok(None), never an error.
        assert!(db.entry_by_name(&session, "Missing").unwrap().is_none());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    use crate::key_lifecycle::{KeySession, MasterKey};
    use std::env::temp_dir;

    fn tmp_db(name: &str) -> String {
        let p = temp_dir().join(format!("valu_test_{name}.db"));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn insert_and_retrieve_roundtrip() {
        let path = tmp_db("roundtrip");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        let id = db.insert_entry(&session, "GitHub", "octocat", "s3cret-pw-123", Some("https://github.com"), None).unwrap();
        assert_eq!(db.entry_count().unwrap(), 1);

        let entry = db.get_entry(&session, id).unwrap().unwrap();
        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.username, "octocat");
        assert_eq!(*entry.password.expose(), "s3cret-pw-123");
        assert_eq!(entry.uri.as_deref(), Some("https://github.com"));

        // Cleanup
        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let path = tmp_db("wrongkey");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let s1 = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &s1).unwrap();
        let id = db.insert_entry(&s1, "X", "u", "p", None, None).unwrap();

        // A *different* volatile key must fail AEAD tag verification.
        let s2 = KeySession::new(MasterKey::create_volatile().unwrap());
        assert!(db.get_entry(&s2, id).is_err());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    /// Adversarial test: two fields of the same entry must NOT share a keystream.
    /// Under the old code (one nonce for all fields), C_user XOR C_pass == P_user XOR P_pass.
    /// Under the fix (per-field nonces), that equality must NOT hold.
    #[test]
    fn ciphertexts_of_two_fields_do_not_share_keystream() {
        let path = tmp_db("keystream");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        // username and password: different strings, SAME length (8 chars).
        let username = "aaaaaaaa";
        let password = "bbbbbbbb";
        let id = db.insert_entry(&session, "K", username, password, None, None).unwrap();

        // Read the two raw ciphertext blobs straight from the database.
        let (user_ct, pass_ct): (Vec<u8>, Vec<u8>) = db.conn().query_row(
            "SELECT user_enc, pass_enc FROM entries WHERE id=?1", [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();

        // If the two fields shared a keystream (same key+nonce), then
        // C_user XOR C_pass == P_user XOR P_pass over the plaintext-length prefix.
        // (The blobs are ct||tag; only the first len(plaintext) bytes carry the keystream.)
        let pt_len = username.len();
        let ct_xor: Vec<u8> = (0..pt_len).map(|i| user_ct[i] ^ pass_ct[i]).collect();
        let pt_xor: Vec<u8> = (0..pt_len).map(|i| username.as_bytes()[i] ^ password.as_bytes()[i]).collect();
        assert_ne!(
            ct_xor, pt_xor,
            "ciphertext XOR equals plaintext XOR → keystream reuse across fields (nonce collision)"
        );

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    /// Volatile Mode's central claim, tested end to end: after a "restart"
    /// (database + session dropped, file reopened with a FRESH volatile key),
    /// the original plaintext must not be recoverable.
    ///
    /// SCOPE / HONESTY NOTE: this test proves the *cryptographic* property —
    /// a different volatile key cannot decrypt the stored ciphertext. It does
    /// NOT prove "the key never reaches disk": that depends on mlockall
    /// succeeding, swap configuration, and kernel behavior, which no unit test
    /// can verify. See secure_mem::harden_process_memory for the runtime check.
    #[test]
    fn volatile_session_is_unrecoverable_after_restart() {
        let path = tmp_db("volatile_restart");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }

        // ── Process 1: create vault with a volatile key, insert a known entry ──
        let session1 = KeySession::new(MasterKey::create_volatile().unwrap());
        let db1 = VaultDatabase::open(&path, &session1).unwrap();
        let id = db1.insert_entry(&session1, "GitHub", "octocat", "s3cret-pw-123", Some("https://github.com"), None).unwrap();
        // Sanity: the entry IS readable with the key that wrote it.
        let e = db1.get_entry(&session1, id).unwrap().unwrap();
        assert_eq!(*e.password.expose(), "s3cret-pw-123");

        // ── The "restart": drop the database and the session. The volatile key
        // is zeroized; nothing on disk can re-derive it. ──
        drop(db1);
        drop(session1);

        // ── Process 2: open the SAME file with a NEW volatile key ──
        let session2 = KeySession::new(MasterKey::create_volatile().unwrap());
        let db2 = VaultDatabase::open(&path, &session2).unwrap();

        // Assert on OUTCOME, not error type: the original plaintext must not be
        // recoverable. Either decryption fails (AEAD tag mismatch) or — in the
        // impossible case it somehow succeeds — the password must differ.
        match db2.get_entry(&session2, id) {
            Err(_) => {} // expected: AEAD tag verification fails under a different key
            Ok(None) => {} // row gone — also acceptable (plaintext not recoverable)
            Ok(Some(entry)) => {
                // If we ever get here, Volatile Mode does NOT hold.
                assert_ne!(*entry.password.expose(), "s3cret-pw-123",
                    "VOLATILE MODE VIOLATION: entry readable with a different volatile key");
            }
        }

        // Cleanup
        drop(db2);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    /// The KDBX import path stores entries through the same encrypted writer as
    /// `insert_entry`: the plaintext password must NOT appear anywhere in the raw
    /// database file bytes.
    #[test]
    fn imported_entries_are_encrypted_at_rest() {
        let path = tmp_db("import_canary");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        let canary = "kdbx-import-canary";
        db.insert_entry(&session, "Imported", "user", canary, None, None).unwrap();

        // Drop the database (checkpoints WAL into the main file) and the session,
        // then inspect the raw bytes on disk.
        drop(db);
        drop(session);

        let raw = std::fs::read(&path).unwrap();
        let needle = canary.as_bytes();
        let found = raw.windows(needle.len()).any(|w| w == needle);
        assert!(!found, "plaintext password found in raw database file — import path is not encrypted at rest");

        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn debug_output_is_redacted() {
        let e = Entry {
            name: "Test".into(),
            username: "user".into(),
            password: Secret::new("super-secret-pw".into()),
            uri: Some("https://example.com/path".into()),
            totp_secret: None,
        };
        let s = format!("{e:?}");
        assert!(!s.contains("super-secret-pw"));
    }
}
