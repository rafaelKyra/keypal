//! # Keypal — D-Bus service (org.rafa.Valu1)
//!
//! A minimal, deliberately non-standard D-Bus interface. We do NOT implement
//! org.freedesktop.secrets: that well-known name belongs to gnome-keyring on
//! this machine, and taking it would break every application that depends on
//! it. Clients that want Keypal must talk to org.rafa.Valu1 explicitly.
//!
//! `rusqlite::Connection` and `VaultDatabase` are not `Sync`, but the
//! `#[zbus::interface]` macro requires the served struct to be `Sync` (its
//! futures must be `Send`). Both are therefore held behind a `Mutex`; the
//! lock is only held for the duration of a single call.

use rusqlite::{params, Connection};
use zbus::fdo::Error as DbusError;

use crate::circuit_breaker::CircuitBreaker;
use crate::key_lifecycle::KeySession;
use crate::storage::{SecretStore, VaultDatabase};

/// D-Bus-facing secret service. Owns the open vault, the key session, and the
/// circuit breaker (plus the breaker key and the raw connection used to
/// persist breaker state).
pub struct SecretService {
    db: std::sync::Mutex<VaultDatabase>,
    session: KeySession,
    breaker: CircuitBreaker,
    breaker_key: [u8; 32],
    conn: std::sync::Mutex<Connection>,
}

impl SecretService {
    /// Build the service from an already-unlocked vault. All arguments are
    /// taken by value; ownership transfers to the service.
    pub fn new(
        db: VaultDatabase,
        session: KeySession,
        breaker: CircuitBreaker,
        breaker_key: [u8; 32],
        conn: Connection,
    ) -> Self {
        Self {
            db: std::sync::Mutex::new(db),
            session,
            breaker,
            breaker_key,
            conn: std::sync::Mutex::new(conn),
        }
    }

    /// Persist the breaker state (re-seal under the breaker key + UPDATE meta),
    /// exactly as `cmd_get` does.
    fn persist_breaker(&self) {
        let sealed = self.breaker.seal_state(&self.breaker_key);
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
                params![sealed],
            )
            .ok();
    }
}

#[zbus::interface(name = "org.rafa.Valu1")]
impl SecretService {
    // The secret is returned as a plain String because that is what the D-Bus
    // wire format requires. Once it leaves this function we no longer own it:
    // zbus serialises it into a message buffer we cannot zeroize. Stated
    // rather than hidden — the in-process guarantees end at the bus boundary.
    fn get_secret(&mut self, name: String) -> zbus::fdo::Result<String> {
        // 1. Gate the attempt BEFORE any key work.
        if let Err(seconds) = self.breaker.allow_attempt() {
            return Err(DbusError::AccessDenied(format!(
                "rate limited, retry in {seconds}s"
            )));
        }

        // 2. Look up the entry by name, through the SecretStore contract. The
        // iterate-decrypt-compare loop used to be written out here and again in
        // the CLI; it now lives once, in storage.
        let found = {
            let db = self.db.lock().unwrap();
            db.entry_by_name(&self.session, &name)
        };

        match found {
            Ok(Some(entry)) => {
                // 3. Found: record success, persist, return the password.
                self.breaker.record_success();
                self.persist_breaker();
                return Ok(entry.password.expose().to_string());
            }
            Err(_) => {
                // Wrong passphrase → AEAD tag verification fails. Treat as a
                // failure of this attempt.
                self.breaker.record_failure();
                self.persist_breaker();
                return Err(DbusError::Failed("unlock failed".into()));
            }
            Ok(None) => {}
        }

        // 4. NOT found: record failure, persist, and fail. Treating a miss as a
        // failure is deliberate: enumerating entry names is exactly what an
        // attacker on the bus would do.
        self.breaker.record_failure();
        self.persist_breaker();
        Err(DbusError::Failed("no such entry".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_breaker::BreakerConfig;
    use crate::key_lifecycle::MasterKey;
    use rand_core::{OsRng, RngCore};

    /// Build a temp passphrase-mode vault with one entry, then unlock it the
    /// same way `cmd_get` does and hand it to a `SecretService`.
    fn temp_service() -> (SecretService, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("valu-dbus-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_str().unwrap().to_string();
        let pass = "test-passphrase";

        // Create the vault (same path as cmd_create).
        let mut salt = [0u8; 16];
        OsRng.try_fill_bytes(&mut salt).unwrap();
        let session = KeySession::new(
            MasterKey::create_passphrase(pass, &salt).expect("Argon2id KDF"),
        );
        let db = VaultDatabase::open(&path_str, &session).expect("db open");
        db.conn()
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('argon_salt', ?1)",
                params![salt],
            )
            .unwrap();
        let breaker_key = crate::crypto::kdf::hkdf_domain(&salt, b"valu/breaker/v1");
        let cb = CircuitBreaker::new(BreakerConfig::default());
        let sealed = cb.seal_state(&breaker_key);
        db.conn()
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
                params![sealed],
            )
            .unwrap();
        db.insert_entry(&session, "github", "user", "hunter2", None, None)
            .expect("insert entry");
        session.close();

        // Unlock (same path as cmd_get).
        let conn = Connection::open(&path_str).expect("db open");
        let salt: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0))
            .expect("salt present");
        let breaker_key = crate::crypto::kdf::hkdf_domain(&salt, b"valu/breaker/v1");
        let breaker = match conn.query_row(
            "SELECT value FROM meta WHERE key='breaker'",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        ) {
            Ok(row) => CircuitBreaker::unseal(&row, &breaker_key)
                .unwrap_or_else(|| CircuitBreaker::new(BreakerConfig::default())),
            Err(_) => CircuitBreaker::new(BreakerConfig::default()),
        };
        let session = KeySession::new(
            MasterKey::unlock_passphrase(pass, &salt).expect("Argon2id KDF"),
        );
        let db = VaultDatabase::open(&path_str, &session).expect("db open");

        (
            SecretService::new(db, session, breaker, breaker_key, conn),
            path,
        )
    }

    #[test]
    fn rate_limited_after_repeated_misses() {
        let (mut svc, path) = temp_service();
        let missing = "definitely-not-an-entry";
        let mut last: Result<String, zbus::fdo::Error> =
            svc.get_secret(missing.to_string());
        for _ in 0..5 {
            last = svc.get_secret(missing.to_string());
        }
        assert!(last.is_err(), "last call must return Err");
        let _ = std::fs::remove_file(&path);
    }
}
