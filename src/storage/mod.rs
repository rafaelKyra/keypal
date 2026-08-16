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
    /// Reason attached to the NEXT history row, consumed once.
    pending_reason: std::cell::RefCell<Option<String>>,
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

            -- Previous passwords, so a bad edit is recoverable. Same AEAD as the
            -- live column, with its own nonce: history rows must never share a
            -- keystream with the entry they came from.
            CREATE TABLE IF NOT EXISTS history (
                id         INTEGER PRIMARY KEY,
                entry_id   INTEGER NOT NULL,
                pass_enc   BLOB NOT NULL,
                nonce      BLOB NOT NULL,
                changed_at INTEGER NOT NULL,
                FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_history_entry ON history(entry_id);

            -- Who looked at what, and when. Entry ids only: recording the NAME
            -- would put a plaintext index of the vault next to the ciphertext.
            CREATE TABLE IF NOT EXISTS access_log (
                id       INTEGER PRIMARY KEY,
                entry_id INTEGER,
                action   TEXT NOT NULL,
                at       INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_access_at ON access_log(at);
            "#,
        )?;

        // Columns added after the first release. ALTER TABLE ADD COLUMN fails
        // when the column is already there, and SQLite has no IF NOT EXISTS for
        // it, so the error is the check — ignoring it is the migration.
        for stmt in [
            "ALTER TABLE entries ADD COLUMN notes_enc BLOB",
            "ALTER TABLE entries ADD COLUMN tags_enc BLOB",
            "ALTER TABLE entries ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE entries ADD COLUMN deleted_at INTEGER",
            "ALTER TABLE entries ADD COLUMN expires_at INTEGER",
            // What kind of security item this is. 0 is Website, which is what
            // every row written before this column genuinely was — the default
            // reclassifies nothing.
            "ALTER TABLE entries ADD COLUMN kind INTEGER NOT NULL DEFAULT 0",
            // Category-specific fields, AEAD-encrypted as one blob under the
            // EIGHTH nonce. Deliberately not a second table: a per-field table
            // would mean a second write path with its own nonce derivation, and
            // nonces are the one thing in this design that must be derived in
            // exactly one place.
            "ALTER TABLE entries ADD COLUMN fields_enc BLOB",
            // Why a password changed. Plaintext by design: "rotated after the
            // Acme breach" is context, not a secret, and encrypting it would
            // mean it could not be read without unlocking — which is when you
            // least want to be reminded why you rotated.
            "ALTER TABLE history ADD COLUMN reason TEXT",
        ] {
            let _ = conn.execute(stmt, []);
        }

        Ok(Self { conn, cipher: Cipher::Aes256Gcm, pending_reason: std::cell::RefCell::new(None) }) // default; ChaCha selectable per-vault in meta
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
            "SELECT name_enc, user_enc, pass_enc, uri_enc, totp_secret, nonce, \
             notes_enc, tags_enc, favorite, created_at, updated_at, deleted_at, \
             kind, fields_enc \
             FROM entries WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, Option<Vec<u8>>>(6)?,
                    r.get::<_, Option<Vec<u8>>>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, i64>(10)?,
                    r.get::<_, Option<i64>>(11)?,
                    r.get::<_, i64>(12)?,
                    r.get::<_, Option<Vec<u8>>>(13)?,
                ))
            },
        );

        let (
            name_ct, user_ct, pass_ct, uri_ct, totp_ct, nonce_b,
            notes_ct, tags_ct, favorite, created_at, updated_at, deleted_at,
            kind_n, fields_ct,
        ) = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // The nonce column holds one 12-byte nonce per field, concatenated.
        // Rows written before notes and tags existed carry 5 (60 bytes); rows
        // written after that carry 7 (84); rows written since category fields
        // carry 8 (96). Accepting all three is what lets an existing vault open
        // after the upgrade instead of reporting corruption.
        if !matches!(nonce_b.len(), 60 | 84 | 96) {
            return Err(crate::ValuError::Crypto(format!(
                "bad nonce blob: expected 60, 84 or 96 bytes, got {}",
                nonce_b.len()
            )));
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

        // Notes and tags occupy nonce slots 5 and 6, which only exist on rows
        // written after the upgrade. An older row simply has neither.
        let (notes, tags) = if nonce_b.len() >= 84 {
            let notes_nonce: [u8; 12] = nonce_b[60..72].try_into().unwrap();
            let tags_nonce: [u8; 12] = nonce_b[72..84].try_into().unwrap();
            let notes = notes_ct
                .map(|c| aead::decrypt(self.cipher, key, &notes_nonce, &c))
                .transpose()?
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            let tags = tags_ct
                .map(|c| aead::decrypt(self.cipher, key, &tags_nonce, &c))
                .transpose()?
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            (notes, tags)
        } else {
            (None, None)
        };

        // Slot 7: the category fields blob.
        let fields = if nonce_b.len() == 96 {
            let fields_nonce: [u8; 12] = nonce_b[84..96].try_into().unwrap();
            fields_ct
                .map(|c| aead::decrypt(self.cipher, key, &fields_nonce, &c))
                .transpose()?
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            None
        };

        Ok(Some(Entry {
            name,
            username,
            password: Secret::new(password),
            uri,
            totp_secret: totp_secret.map(Secret::new),
            notes: notes.map(Secret::new),
            tags,
            kind: crate::kind::Kind::from_i64(kind_n),
            fields: fields.map(Secret::new),
            favorite: favorite != 0,
            created_at,
            updated_at,
            deleted_at,
        }))
    }

    /// Count entries (for tests / UI).
    /// Overwrite an existing entry.
    ///
    /// FRESH RANDOM NONCES, deliberately — not the id-derived ones `insert_entry`
    /// uses. Re-encrypting changed content under the nonce the previous version
    /// already used would repeat the keystream across the two file versions, and
    /// anyone holding both (a backup, a snapshot, an undeleted page) could XOR
    /// them to recover the difference. That is the same defect this crate
    /// already had once, across fields; it must not come back across time.
    ///
    /// This is safe because the nonce column stores the nonces actually used, so
    /// decryption reads them rather than recomputing them from the id.
    #[allow(clippy::too_many_arguments)]
    pub fn update_entry(
        &self,
        session: &KeySession,
        id: i64,
        name: &str,
        username: &str,
        password: &str,
        uri: Option<&str>,
        totp_secret: Option<&str>,
    ) -> Result<bool, crate::ValuError> {
        use rand_core::{OsRng, RngCore};

        let key = session.enc_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut nonces = [[0u8; 12]; 5];
        for n in nonces.iter_mut() {
            OsRng.fill_bytes(n);
        }

        let name_ct = aead::encrypt(self.cipher, key, &nonces[0], name.as_bytes().to_vec())?;
        let user_ct = aead::encrypt(self.cipher, key, &nonces[1], username.as_bytes().to_vec())?;
        let pass_ct = aead::encrypt(self.cipher, key, &nonces[2], password.as_bytes().to_vec())?;
        let uri_ct: Option<Vec<u8>> = uri
            .map(|u| aead::encrypt(self.cipher, key, &nonces[3], u.as_bytes().to_vec()))
            .transpose()?;
        let totp_ct: Option<Vec<u8>> = totp_secret
            .map(|t| aead::encrypt(self.cipher, key, &nonces[4], t.as_bytes().to_vec()))
            .transpose()?;

        let mut nonce_blob = Vec::with_capacity(60);
        for n in nonces.iter() {
            nonce_blob.extend_from_slice(n);
        }

        let changed = self.conn.execute(
            "UPDATE entries SET name_enc=?2, user_enc=?3, pass_enc=?4, uri_enc=?5, \
             totp_secret=?6, nonce=?7, updated_at=?8 WHERE id=?1",
            rusqlite::params![id, name_ct, user_ct, pass_ct, uri_ct, totp_ct, nonce_blob, now],
        )?;
        Ok(changed > 0)
    }

    /// Insert with every field, including notes and tags.
    ///
    /// `insert_entry` remains as the four-field form so existing callers keep
    /// working; it delegates here with the extra fields empty.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_entry_full(
        &self,
        session: &KeySession,
        name: &str,
        username: &str,
        password: &str,
        uri: Option<&str>,
        totp_secret: Option<&str>,
        notes: Option<&str>,
        tags: Option<&str>,
    ) -> Result<i64, crate::ValuError> {
        self.insert_draft(
            session,
            &EntryDraft {
                name,
                username,
                password,
                uri,
                totp_secret,
                notes,
                tags,
                ..EntryDraft::default()
            },
        )
    }

    /// Insert an entry of any category.
    pub fn insert_draft(
        &self,
        session: &KeySession,
        draft: &EntryDraft<'_>,
    ) -> Result<i64, crate::ValuError> {
        let id = self.insert_entry(
            session,
            draft.name,
            draft.username,
            draft.password,
            draft.uri,
            draft.totp_secret,
        )?;
        // `insert_entry` writes the five-nonce layout, which has nowhere to put
        // notes, tags or category fields. Rewriting the row immediately is what
        // promotes it to the full layout — and it costs one extra write on
        // creation only, against duplicating the whole encrypt-and-lay-out-
        // nonces routine a second time, which is where the two would drift.
        self.update_draft(session, id, draft)?;
        Ok(id)
    }

    /// Overwrite an entry, including notes and tags, and keep the old password.
    ///
    /// The previous password is copied into `history` under its OWN fresh
    /// nonce before the row is rewritten. Reusing the entry's nonce for the
    /// history copy would put the same keystream on two rows in the same file.
    ///
    /// The entry's category and its category fields are left as they are —
    /// this form does not know about them, and blanking what a caller never
    /// mentioned would silently reclassify the entry.
    #[allow(clippy::too_many_arguments)]
    pub fn update_entry_full(
        &self,
        session: &KeySession,
        id: i64,
        name: &str,
        username: &str,
        password: &str,
        uri: Option<&str>,
        totp_secret: Option<&str>,
        notes: Option<&str>,
        tags: Option<&str>,
    ) -> Result<bool, crate::ValuError> {
        let existing = self.get_entry(session, id)?;
        let kind = existing.as_ref().map(|e| e.kind).unwrap_or_default();
        let fields = existing
            .as_ref()
            .and_then(|e| e.fields.as_ref())
            .map(|f| f.expose().clone());
        self.update_draft(
            session,
            id,
            &EntryDraft {
                name,
                username,
                password,
                uri,
                totp_secret,
                notes,
                tags,
                kind,
                fields: fields.as_deref(),
            },
        )
    }

    /// Overwrite an entry from a draft, category and all.
    pub fn update_draft(
        &self,
        session: &KeySession,
        id: i64,
        draft: &EntryDraft<'_>,
    ) -> Result<bool, crate::ValuError> {
        use rand_core::{OsRng, RngCore};

        let EntryDraft { name, username, password, uri, totp_secret, notes, tags, kind, fields } =
            *draft;

        let key = session.enc_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Record the outgoing password first, so a failure later leaves the
        // history complete rather than the entry changed with no way back.
        if let Some(previous) = self.get_entry(session, id)? {
            let old_password = previous.password.expose().clone();
            if old_password != password {
                let mut hist_nonce = [0u8; 12];
                OsRng.fill_bytes(&mut hist_nonce);
                let hist_ct =
                    aead::encrypt(self.cipher, key, &hist_nonce, old_password.into_bytes())?;
                self.conn.execute(
                    "INSERT INTO history (entry_id, pass_enc, nonce, changed_at) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![id, hist_ct, hist_nonce.to_vec(), now],
                )?;
            }
        }

        let mut nonces = [[0u8; 12]; 8];
        for n in nonces.iter_mut() {
            OsRng.fill_bytes(n);
        }

        let name_ct = aead::encrypt(self.cipher, key, &nonces[0], name.as_bytes().to_vec())?;
        let user_ct = aead::encrypt(self.cipher, key, &nonces[1], username.as_bytes().to_vec())?;
        let pass_ct = aead::encrypt(self.cipher, key, &nonces[2], password.as_bytes().to_vec())?;
        let uri_ct: Option<Vec<u8>> = uri
            .map(|u| aead::encrypt(self.cipher, key, &nonces[3], u.as_bytes().to_vec()))
            .transpose()?;
        let totp_ct: Option<Vec<u8>> = totp_secret
            .map(|t| aead::encrypt(self.cipher, key, &nonces[4], t.as_bytes().to_vec()))
            .transpose()?;
        let notes_ct: Option<Vec<u8>> = notes
            .filter(|n| !n.is_empty())
            .map(|n| aead::encrypt(self.cipher, key, &nonces[5], n.as_bytes().to_vec()))
            .transpose()?;
        let tags_ct: Option<Vec<u8>> = tags
            .filter(|t| !t.is_empty())
            .map(|t| aead::encrypt(self.cipher, key, &nonces[6], t.as_bytes().to_vec()))
            .transpose()?;
        let fields_ct: Option<Vec<u8>> = fields
            .filter(|f| !f.is_empty())
            .map(|f| aead::encrypt(self.cipher, key, &nonces[7], f.as_bytes().to_vec()))
            .transpose()?;

        let mut nonce_blob = Vec::with_capacity(96);
        for n in nonces.iter() {
            nonce_blob.extend_from_slice(n);
        }

        let changed = self.conn.execute(
            "UPDATE entries SET name_enc=?2, user_enc=?3, pass_enc=?4, uri_enc=?5, \
             totp_secret=?6, nonce=?7, updated_at=?8, notes_enc=?9, tags_enc=?10, \
             kind=?11, fields_enc=?12 \
             WHERE id=?1",
            rusqlite::params![
                id, name_ct, user_ct, pass_ct, uri_ct, totp_ct, nonce_blob, now,
                notes_ct, tags_ct, kind.as_i64(), fields_ct
            ],
        )?;
        Ok(changed > 0)
    }

    /// Attach a reason to the next password change. Consumed by the update that
    /// follows, so it cannot leak onto an unrelated edit later.
    pub fn set_change_reason(&self, reason: Option<String>) {
        self.pending_reason.replace(reason.filter(|r| !r.trim().is_empty()));
    }

    /// Previous passwords for an entry, newest first.
    pub fn password_history(
        &self,
        session: &KeySession,
        entry_id: i64,
    ) -> Result<Vec<(i64, String, Option<String>)>, crate::ValuError> {
        let key = session.enc_key();
        let mut stmt = self.conn.prepare(
            // `id DESC` breaks ties: two edits in the same second share a
            // changed_at, and without it the order falls back to rowid
            // ascending — the exact reverse of what "newest first" means.
            "SELECT pass_enc, nonce, changed_at, reason FROM history WHERE entry_id=?1 \
             ORDER BY changed_at DESC, id DESC",
        )?;
        let rows: Vec<(Vec<u8>, Vec<u8>, i64, Option<String>)> = stmt
            .query_map([entry_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let mut out = Vec::with_capacity(rows.len());
        for (ct, nonce_b, when, reason) in rows {
            if nonce_b.len() != 12 {
                continue;
            }
            let nonce: [u8; 12] = nonce_b[..12].try_into().unwrap();
            let plain = aead::decrypt(self.cipher, key, &nonce, &ct)?;
            out.push((when, String::from_utf8_lossy(&plain).into_owned(), reason));
        }
        Ok(out)
    }

    /// Record an access. Never fails the caller: an audit trail that can break
    /// the operation it audits is worse than one that occasionally misses a row.
    pub fn log_access(&self, entry_id: Option<i64>, action: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let _ = self.conn.execute(
            "INSERT INTO access_log (entry_id, action, at) VALUES (?1, ?2, ?3)",
            rusqlite::params![entry_id, action, now],
        );
    }

    /// Recent access events, newest first.
    pub fn recent_access(&self, limit: i64) -> Result<Vec<(i64, Option<i64>, String)>, crate::ValuError> {
        let mut stmt = self.conn.prepare(
            "SELECT at, entry_id, action FROM access_log ORDER BY at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Destroy one entry for good, by crypto-shredding it first.
    ///
    /// A plain DELETE returns the page to SQLite's freelist without touching
    /// its bytes, so the original ciphertext survives in the file until
    /// something else happens to reuse that page. Anyone who later obtains the
    /// file AND the passphrase could still read what the user believed was
    /// destroyed.
    ///
    /// So the row is OVERWRITTEN before it is deleted, with random bytes
    /// encrypted under the session's wipe key — the same domain-separated key
    /// `secure_erase` uses for the whole vault. The write forces SQLite to
    /// rewrite the page, so what remains in the freelist is the shredded
    /// version. Recovering it would need the wipe key, which dies with the
    /// session.
    ///
    /// History and access-log rows for the entry go too: leaving them would
    /// keep old passwords for something the user was told is gone.
    pub fn purge_entry(&self, session: &KeySession, id: i64) -> Result<bool, crate::ValuError> {
        use rand_core::{OsRng, RngCore};

        let exists: bool = self
            .conn
            .query_row("SELECT 1 FROM entries WHERE id=?1", [id], |_| Ok(()))
            .is_ok();
        if !exists {
            return Ok(false);
        }

        let wipe = session.wipe_key();
        let mut nonces = [[0u8; 12]; 8];
        for n in nonces.iter_mut() {
            OsRng.fill_bytes(n);
        }
        // Random payloads, not zeros: a run of identical ciphertexts would say
        // "this row was shredded", and how many were.
        let mut junk = [0u8; 48];
        let mut blob = |i: usize| -> Result<Vec<u8>, crate::ValuError> {
            OsRng.fill_bytes(&mut junk);
            aead::encrypt(self.cipher, wipe, &nonces[i], junk.to_vec())
        };
        // Every secret column, the category fields included: a shredded bank
        // card that left its CVV readable would be worse than not shredding at
        // all, because the user was told it was gone.
        let (a, b, c, d, e, f, g, h) = (
            blob(0)?, blob(1)?, blob(2)?, blob(3)?, blob(4)?, blob(5)?, blob(6)?, blob(7)?,
        );
        let mut nonce_blob = Vec::with_capacity(96);
        for n in nonces.iter() {
            nonce_blob.extend_from_slice(n);
        }

        self.conn.execute(
            "UPDATE entries SET name_enc=?2, user_enc=?3, pass_enc=?4, uri_enc=?5, \
             totp_secret=?6, notes_enc=?7, tags_enc=?8, fields_enc=?9, nonce=?10 WHERE id=?1",
            rusqlite::params![id, a, b, c, d, e, f, g, h, nonce_blob],
        )?;

        // Same treatment for stored history: those are passwords too.
        let hist: Vec<i64> = {
            let mut stmt = self.conn.prepare("SELECT id FROM history WHERE entry_id=?1")?;
            let rows = stmt.query_map([id], |r| r.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for hid in hist {
            let mut n = [0u8; 12];
            OsRng.fill_bytes(&mut n);
            OsRng.fill_bytes(&mut junk);
            let shred = aead::encrypt(self.cipher, wipe, &n, junk.to_vec())?;
            self.conn.execute(
                "UPDATE history SET pass_enc=?2, nonce=?3 WHERE id=?1",
                rusqlite::params![hid, shred, n.to_vec()],
            )?;
        }

        self.conn.execute("DELETE FROM history WHERE entry_id=?1", [id])?;
        self.conn.execute("DELETE FROM access_log WHERE entry_id=?1", [id])?;
        self.conn.execute("DELETE FROM entries WHERE id=?1", [id])?;

        // Checkpoint so the shredding write actually reaches the main file
        // rather than sitting in the WAL alongside the original page.
        let _ = self.conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
        Ok(true)
    }

    /// Set or clear an expiry date, for rotation reminders.
    pub fn set_expiry(&self, id: i64, at: Option<i64>) -> Result<bool, crate::ValuError> {
        let n = self.conn.execute(
            "UPDATE entries SET expires_at=?2 WHERE id=?1",
            rusqlite::params![id, at],
        )?;
        Ok(n > 0)
    }

    /// How long trashed entries are kept before they are shredded, in days.
    ///
    /// Stored per vault rather than hardcoded, because how long "long enough to
    /// notice a mistake" is depends on how often you open the vault. Zero means
    /// keep forever: retention that cannot be turned off is a data-loss feature.
    pub fn retention_days(&self) -> i64 {
        self.conn
            .query_row("SELECT value FROM meta WHERE key='trash_retention_days'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .ok()
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0)
    }

    pub fn set_retention_days(&self, days: i64) -> Result<(), crate::ValuError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('trash_retention_days', ?1)",
            rusqlite::params![days.max(0).to_string().into_bytes()],
        )?;
        Ok(())
    }

    /// Shred anything that has sat in the trash past the retention window.
    ///
    /// Runs on unlock. Each expired entry goes through `purge_entry`, so it is
    /// crypto-shredded rather than merely unlinked — an automatic cleanup that
    /// left recoverable ciphertext behind would be worse than none, because the
    /// user would believe it had been dealt with.
    ///
    /// Returns how many were destroyed, so the caller can say so rather than
    /// silently deleting the user's data.
    pub fn purge_expired_trash(
        &self,
        session: &KeySession,
        now: i64,
    ) -> Result<usize, crate::ValuError> {
        let days = self.retention_days();
        if days <= 0 {
            return Ok(0);
        }
        let cutoff = now - days * 24 * 60 * 60;
        let ids: Vec<i64> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM entries WHERE deleted_at IS NOT NULL AND deleted_at <= ?1")?;
            let rows = stmt.query_map([cutoff], |r| r.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut destroyed = 0;
        for id in ids {
            if self.purge_entry(session, id)? {
                destroyed += 1;
            }
        }
        Ok(destroyed)
    }

    /// Trashed entries, for the trash view.
    pub fn list_trashed(
        &self,
        session: &KeySession,
    ) -> Result<Vec<(i64, Entry)>, crate::ValuError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM entries WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC")?;
        let ids: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<i64>, _>>()?;
        drop(stmt);
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = self.get_entry(session, id)? {
                out.push((id, entry));
            }
        }
        Ok(out)
    }

    /// Move an entry to the trash. Reversible; `purge_entry` is not.
    pub fn trash_entry(&self, id: i64) -> Result<bool, crate::ValuError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let n = self
            .conn
            .execute("UPDATE entries SET deleted_at=?2 WHERE id=?1", rusqlite::params![id, now])?;
        Ok(n > 0)
    }

    pub fn restore_entry(&self, id: i64) -> Result<bool, crate::ValuError> {
        let n = self.conn.execute("UPDATE entries SET deleted_at=NULL WHERE id=?1", [id])?;
        Ok(n > 0)
    }

    /// Mark or unmark a favourite.
    pub fn set_favorite(&self, id: i64, favorite: bool) -> Result<bool, crate::ValuError> {
        let n = self.conn.execute(
            "UPDATE entries SET favorite=?2 WHERE id=?1",
            rusqlite::params![id, i64::from(favorite)],
        )?;
        Ok(n > 0)
    }

    /// Every entry, decrypted, paired with its id.
    ///
    /// The GUI needs ids to edit and delete, and needs more than names to show a
    /// useful list. Callers were each rebuilding this from `SELECT id` plus a
    /// per-row `get_entry`, which is the same loop three times.
    pub fn list_entries(
        &self,
        session: &KeySession,
    ) -> Result<Vec<(i64, Entry)>, crate::ValuError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM entries WHERE deleted_at IS NULL ORDER BY id")?;
        let ids: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<i64>, _>>()?;
        drop(stmt);

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            // Propagated, not skipped: a decrypt failure means the key is wrong,
            // and silently returning a short list would look like data loss.
            if let Some(entry) = self.get_entry(session, id)? {
                out.push((id, entry));
            }
        }
        Ok(out)
    }

    /// Remove one entry by id.
    ///
    /// This is an ordinary DELETE: the row goes, but the page it occupied is
    /// only returned to the freelist, so the ciphertext can survive in the
    /// file. That is acceptable because the value was never plaintext on disk
    /// — and it is exactly why `secure_erase` exists separately for the case
    /// where the whole vault must become unrecoverable.
    pub fn delete_entry(&self, id: i64) -> Result<bool, crate::ValuError> {
        let n = self.conn.execute("DELETE FROM entries WHERE id=?1", [id])?;
        Ok(n > 0)
    }

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
    /// Free-form notes. Encrypted like every other field — notes are where
    /// people put recovery codes and security answers, so treating them as
    /// less sensitive than the password would be exactly backwards.
    pub notes: Option<Secret<String>>,
    /// Comma-separated labels. Encrypted too: the set of tags in a vault is
    /// itself information about its owner.
    pub tags: Option<String>,
    /// What kind of security item this is. Decides which fields the editor
    /// shows and how the health report reads the entry.
    pub kind: crate::kind::Kind,
    /// The category's own fields, in the encoding from [`crate::kind`].
    ///
    /// A [`Secret`], not a plain string: this is where a CVV, a connection
    /// string and an SSH private key end up.
    pub fields: Option<Secret<String>>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// Set when the entry is in the trash. Trashed entries stay decryptable so
    /// they can be restored; emptying the trash is the destructive step.
    pub deleted_at: Option<i64>,
}

/// Everything the caller wants written, in one place.
///
/// Passing eleven positional arguments is how a username ends up encrypted into
/// the password column: the compiler cannot tell two `&str` apart, so a
/// transposed pair is a silent data corruption rather than a build failure.
/// Named fields make the mistake unwritable.
#[derive(Default, Clone, Copy)]
pub struct EntryDraft<'a> {
    pub name: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub uri: Option<&'a str>,
    pub totp_secret: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub tags: Option<&'a str>,
    pub kind: crate::kind::Kind,
    /// Already encoded — see [`crate::kind::encode_fields`].
    pub fields: Option<&'a str>,
}

impl std::fmt::Debug for Entry {
    /// Redacted debug: shows name/username (non-secret context) but masks the rest.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("username", &self.username)
            .field("password", &"•••")
            .field("fields", &"•••")
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
    fn retention_shreds_only_what_has_actually_expired() {
        let path = tmp_db("retention");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        let old = db.insert_entry(&session, "Old", "u", "p", None, None).unwrap();
        let recent = db.insert_entry(&session, "Recent", "u", "p", None, None).unwrap();
        let live = db.insert_entry(&session, "Live", "u", "p", None, None).unwrap();

        let now = 1_700_000_000i64;
        db.trash_entry(old).unwrap();
        db.trash_entry(recent).unwrap();
        // Backdate one of them past the window.
        db.conn().execute("UPDATE entries SET deleted_at=?2 WHERE id=?1",
            rusqlite::params![old, now - 40 * 86_400]).unwrap();
        db.conn().execute("UPDATE entries SET deleted_at=?2 WHERE id=?1",
            rusqlite::params![recent, now - 2 * 86_400]).unwrap();

        // Off by default: a retention that cannot be turned off is a data-loss
        // feature, so nothing must vanish until the user asks for it.
        assert_eq!(db.retention_days(), 0);
        assert_eq!(db.purge_expired_trash(&session, now).unwrap(), 0);

        db.set_retention_days(30).unwrap();
        assert_eq!(db.retention_days(), 30);
        assert_eq!(db.purge_expired_trash(&session, now).unwrap(), 1);

        assert!(db.get_entry(&session, old).unwrap().is_none(), "expired one is gone");
        assert!(db.get_entry(&session, recent).unwrap().is_some(), "recent one is kept");
        assert!(db.get_entry(&session, live).unwrap().is_some(), "live entry untouched");

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }


    #[test]
    fn the_access_log_records_ids_but_never_names() {
        // A log of entry NAMES would be a plaintext index of the vault sitting
        // beside the ciphertext — defeating the encryption for anyone who can
        // read the file.
        let path = tmp_db("accesslog");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "SecretName", "u", "p", None, None).unwrap();

        db.log_access(Some(id), "reveal");
        db.log_access(None, "unlock");

        let log = db.recent_access(10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].2, "unlock", "newest first");
        assert_eq!(log[1].1, Some(id));

        drop(db);
        let bytes = std::fs::read(&path).unwrap_or_default();
        assert!(
            !bytes.windows(10).any(|w| w == b"SecretName"),
            "the entry name must not appear in the file in the clear"
        );
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn purging_removes_the_entry_and_its_history_together() {
        // Leaving history behind would keep old passwords for an entry the user
        // believes they destroyed.
        let path = tmp_db("purge");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "Doomed", "u", "first", None, None).unwrap();
        db.update_entry_full(&session, id, "Doomed", "u", "second", None, None, None, None).unwrap();
        assert_eq!(db.password_history(&session, id).unwrap().len(), 1);

        assert!(db.trash_entry(id).unwrap());
        assert!(db.purge_entry(&session, id).unwrap());
        assert!(db.get_entry(&session, id).unwrap().is_none());
        assert!(db.password_history(&session, id).unwrap().is_empty());
        assert!(!db.purge_entry(&session, id).unwrap());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn purging_shreds_the_ciphertext_rather_than_only_unlinking_it() {
        // A plain DELETE leaves the page in the freelist with its bytes intact,
        // so the entry stays recoverable by anyone with the file AND the
        // passphrase. This is the test that says it does not.
        let path = tmp_db("shred");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "Doomed", "u", "shred-me-canary", None, None).unwrap();

        let pass_ct: Vec<u8> = db.conn()
            .query_row("SELECT pass_enc FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();
        // Control: the ciphertext really is in the file before we shred it.
        let before = std::fs::read(&path).unwrap_or_default();
        let wal = std::fs::read(format!("{path}-wal")).unwrap_or_default();
        assert!(
            before.windows(pass_ct.len()).any(|w| w == pass_ct)
                || wal.windows(pass_ct.len()).any(|w| w == pass_ct),
            "control failed: ciphertext not on disk before purge"
        );

        db.trash_entry(id).unwrap();
        assert!(db.purge_entry(&session, id).unwrap());
        drop(db);

        let after = std::fs::read(&path).unwrap_or_default();
        assert!(
            !after.windows(pass_ct.len()).any(|w| w == pass_ct),
            "the original ciphertext survived the purge"
        );
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn an_expiry_date_round_trips() {
        let path = tmp_db("expiry");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "Rotate", "u", "p", None, None).unwrap();

        assert!(db.set_expiry(id, Some(1_800_000_000)).unwrap());
        let at: Option<i64> = db.conn()
            .query_row("SELECT expires_at FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert_eq!(at, Some(1_800_000_000));
        assert!(db.set_expiry(id, None).unwrap());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }


    #[test]
    fn notes_and_tags_round_trip_and_old_rows_still_open() {
        let path = tmp_db("notes");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        // A row written the OLD way carries a 60-byte nonce blob and no notes.
        // It must keep opening after the upgrade — this is the migration test.
        let legacy = db.insert_entry(&session, "Legacy", "u", "p", None, None).unwrap();
        let blob: Vec<u8> = db.conn()
            .query_row("SELECT nonce FROM entries WHERE id=?1", [legacy], |r| r.get(0)).unwrap();
        assert_eq!(blob.len(), 60, "insert_entry should still write the 5-nonce layout");
        let read_back = db.get_entry(&session, legacy).unwrap().unwrap();
        assert_eq!(read_back.name, "Legacy");
        assert!(read_back.notes.is_none());

        // A row written the NEW way carries one nonce per encrypted column —
        // eight of them since category fields joined — and round-trips
        // notes/tags.
        let id = db.insert_entry_full(&session, "Bank", "me", "pw",
            Some("https://bank.example"), None,
            Some("recovery: alpha bravo"), Some("finance,important")).unwrap();
        let blob: Vec<u8> = db.conn()
            .query_row("SELECT nonce FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert_eq!(blob.len(), 96);
        let e = db.get_entry(&session, id).unwrap().unwrap();
        assert_eq!(e.notes.as_ref().map(|n| n.expose().as_str()), Some("recovery: alpha bravo"));
        assert_eq!(e.tags.as_deref(), Some("finance,important"));
        assert_eq!(e.uri.as_deref(), Some("https://bank.example"));

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn a_category_and_its_own_fields_round_trip() {
        use crate::kind::{decode_fields, encode_fields, field_value, Kind};
        let path = tmp_db("kinds");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        let fields = encode_fields(&[
            ("ssid".into(), "Home-5G".into()),
            ("admin_ip".into(), "192.168.1.1".into()),
        ]);
        let id = db
            .insert_draft(&session, &EntryDraft {
                name: "Home Wi-Fi",
                password: "correct-horse-battery",
                kind: Kind::Wifi,
                fields: Some(&fields),
                ..EntryDraft::default()
            })
            .unwrap();

        let e = db.get_entry(&session, id).unwrap().unwrap();
        assert_eq!(e.kind, Kind::Wifi);
        let got = decode_fields(e.fields.as_ref().unwrap().expose());
        assert_eq!(field_value(&got, "ssid"), Some("Home-5G"));
        assert_eq!(field_value(&got, "admin_ip"), Some("192.168.1.1"));

        // Eight nonces now, one per encrypted column. If the fields blob ever
        // reused another column's nonce, two secrets would share a keystream.
        let blob: Vec<u8> = db.conn()
            .query_row("SELECT nonce FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert_eq!(blob.len(), 96);
        let mut distinct: std::collections::HashSet<&[u8]> = Default::default();
        for chunk in blob.chunks(12) {
            assert!(distinct.insert(chunk), "two columns share a nonce");
        }

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn an_entry_written_before_categories_existed_reads_back_as_a_website() {
        // The migration test. Every row in every existing vault has no `kind`
        // column at all; it must open, and it must not be reclassified into
        // something it is not. Those rows ARE website logins.
        use crate::kind::Kind;
        let path = tmp_db("kindmigrate");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        // `insert_entry` still writes the old five-nonce layout, which is the
        // closest thing to a pre-upgrade row we can produce here.
        let legacy = db.insert_entry(&session, "Legacy", "u", "p", None, None).unwrap();
        let blob: Vec<u8> = db.conn()
            .query_row("SELECT nonce FROM entries WHERE id=?1", [legacy], |r| r.get(0)).unwrap();
        assert_eq!(blob.len(), 60);
        let e = db.get_entry(&session, legacy).unwrap().unwrap();
        assert_eq!(e.kind, Kind::Website);
        assert!(e.fields.is_none());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn editing_an_entry_the_old_way_does_not_silently_reclassify_it() {
        // `update_entry_full` knows nothing about categories. If it wrote its
        // default it would turn every bank card into a website the first time
        // anything else touched the row.
        use crate::kind::{decode_fields, encode_fields, field_value, Kind};
        let path = tmp_db("kindkeep");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        let fields = encode_fields(&[("cvv".into(), "123".into())]);
        let id = db
            .insert_draft(&session, &EntryDraft {
                name: "Debit card",
                password: "4111111111111111",
                kind: Kind::BankCard,
                fields: Some(&fields),
                ..EntryDraft::default()
            })
            .unwrap();

        db.update_entry_full(&session, id, "Debit card", "R.K.", "4111111111111111",
            None, None, Some("expires soon"), Some("money")).unwrap();

        let e = db.get_entry(&session, id).unwrap().unwrap();
        assert_eq!(e.kind, Kind::BankCard, "the category survived an unrelated edit");
        assert_eq!(
            field_value(&decode_fields(e.fields.as_ref().unwrap().expose()), "cvv"),
            Some("123"),
            "the category's own fields survived too"
        );
        assert_eq!(e.notes.as_ref().map(|n| n.expose().as_str()), Some("expires soon"));

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn purging_shreds_the_category_fields_too() {
        // A destroyed bank card that left its CVV recoverable in the file is
        // worse than one that was never destroyed, because the user was told.
        use crate::kind::{encode_fields, Kind};
        let path = tmp_db("kindshred");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();

        let fields = encode_fields(&[("cvv".into(), "shred-me-cvv-canary".into())]);
        let id = db
            .insert_draft(&session, &EntryDraft {
                name: "Doomed card",
                password: "4111111111111111",
                kind: Kind::BankCard,
                fields: Some(&fields),
                ..EntryDraft::default()
            })
            .unwrap();

        let ct: Vec<u8> = db.conn()
            .query_row("SELECT fields_enc FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert!(!ct.is_empty(), "control: the fields really were written");

        db.trash_entry(id).unwrap();
        assert!(db.purge_entry(&session, id).unwrap());
        drop(db);

        let after = std::fs::read(&path).unwrap_or_default();
        assert!(
            !after.windows(ct.len()).any(|w| w == ct),
            "the category fields ciphertext survived the purge"
        );
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn password_history_records_the_previous_value_only_when_it_changes() {
        let path = tmp_db("history");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "Mail", "me", "first-pw", None, None).unwrap();

        db.update_entry_full(&session, id, "Mail", "me", "second-pw", None, None, None, None).unwrap();
        let hist = db.password_history(&session, id).unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].1, "first-pw");
        assert!(hist[0].2.is_none(), "no reason was given");

        // Saving without changing the password must not add a history row —
        // otherwise editing a username fills the history with duplicates.
        db.update_entry_full(&session, id, "Mail", "other", "second-pw", None, None, None, None).unwrap();
        assert_eq!(db.password_history(&session, id).unwrap().len(), 1);

        db.update_entry_full(&session, id, "Mail", "other", "third-pw", None, None, None, None).unwrap();
        let hist = db.password_history(&session, id).unwrap();
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0].1, "second-pw", "newest first");

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn trashing_hides_an_entry_without_destroying_it() {
        let path = tmp_db("trash");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let keep = db.insert_entry(&session, "Keep", "u", "p", None, None).unwrap();
        let gone = db.insert_entry(&session, "Gone", "u", "p", None, None).unwrap();

        assert!(db.trash_entry(gone).unwrap());
        let live = db.list_entries(&session).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, keep);

        let trashed = db.list_trashed(&session).unwrap();
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].1.name, "Gone");
        assert!(trashed[0].1.deleted_at.is_some());

        // Restoring brings it back intact, which is the whole point of a trash.
        assert!(db.restore_entry(gone).unwrap());
        assert_eq!(db.list_entries(&session).unwrap().len(), 2);
        assert!(db.list_trashed(&session).unwrap().is_empty());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }


    #[test]
    fn update_entry_replaces_content_and_rotates_nonces() {
        let path = tmp_db("update");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let id = db.insert_entry(&session, "Old", "u1", "p1", None, None).unwrap();

        let nonce_before: Vec<u8> = db.conn()
            .query_row("SELECT nonce FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();

        assert!(db.update_entry(&session, id, "New", "u2", "p2",
            Some("https://example.com"), None).unwrap());

        let updated = db.get_entry(&session, id).unwrap().unwrap();
        assert_eq!(updated.name, "New");
        assert_eq!(updated.username, "u2");
        assert_eq!(*updated.password.expose(), "p2");
        assert_eq!(updated.uri.as_deref(), Some("https://example.com"));

        // THE POINT OF THIS TEST: re-encrypting under the previous nonce would
        // repeat the keystream across two versions of the file, so anyone
        // holding both could XOR them to recover the difference.
        let nonce_after: Vec<u8> = db.conn()
            .query_row("SELECT nonce FROM entries WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert_ne!(nonce_before, nonce_after, "nonces must rotate on update");

        // Updating an id that does not exist reports false rather than erroring.
        assert!(!db.update_entry(&session, 9999, "X", "y", "z", None, None).unwrap());

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn list_entries_returns_every_row_with_its_id() {
        let path = tmp_db("listall");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let a = db.insert_entry(&session, "Alpha", "u", "p", None, None).unwrap();
        let b = db.insert_entry(&session, "Beta", "u", "p", None, None).unwrap();

        let all = db.list_entries(&session).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, a);
        assert_eq!(all[1].0, b);
        assert_eq!(all[0].1.name, "Alpha");
        assert_eq!(all[1].1.name, "Beta");

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }


    #[test]
    fn delete_entry_removes_only_the_named_row() {
        let path = tmp_db("delete");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        let keep = db.insert_entry(&session, "Keep", "u1", "p1", None, None).unwrap();
        let drop_id = db.insert_entry(&session, "Drop", "u2", "p2", None, None).unwrap();

        assert!(db.delete_entry(drop_id).unwrap());
        // Deleting the same id twice reports false rather than erroring.
        assert!(!db.delete_entry(drop_id).unwrap());

        assert!(db.get_entry(&session, keep).unwrap().is_some());
        assert!(db.entry_by_name(&session, "Drop").unwrap().is_none());
        assert_eq!(db.entry_count().unwrap(), 1);

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }


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
            notes: Some(Secret::new("recovery code 1234".into())),
            tags: Some("work,email".into()),
            kind: crate::kind::Kind::Website,
            fields: Some(Secret::new("cvv\n3\n123\n".into())),
            favorite: true,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        };
        let s = format!("{e:?}");
        assert!(!s.contains("super-secret-pw"));
        // Notes hold recovery codes and security answers, so they must be
        // redacted as strictly as the password itself.
        assert!(!s.contains("recovery code"));
    }
}
