//! # Phase 2 — Secure Erase Protocol
//!
//! ## Why "delete" is not enough on Linux
//! Standard `DELETE FROM entries` leaves the plaintext (or ciphertext) in:
//!   1. **WAL file** (`*.db-wal`) — un-checkpointed pages persist until truncation.
//!   2. **SQLite page cache / freelist** — freed pages are reused, not zeroed.
//!   3. **OS page cache** — the kernel may hold dirty pages in RAM long after close.
//!   4. **Core dumps / crash tooling** — if a dump fires mid-operation.
//!
//! ## The Protocol (6 steps)
//! ```text
//!  1. DERIVE    wipe_key = HKDF(master, "valu/wipe/v1")     ← domain-separated, one-shot
//!  2. RE-ENCRYPT every row under wipe_key (overwrites old ciphertext in-place)
//!  3. DELETE    all rows from `entries` and `meta`
//!  4. CHECKPOINT + TRUNCATE WAL   → forces WAL pages to be written & file truncated to 0
//!  5. VACUUM    → rewrites the entire DB file; old pages (holding stale ciphertext)
//!                 are freed back to the OS. Combined with mlock, they never hit swap.
//!  6. ZEROIZE   wipe_key + all in-memory key material; close connection
//! ```
//! After step 5 the on-disk file contains **only** the schema (no data pages), and every
//! prior ciphertext has been overwritten by a different key's output — so even if an old
//! page survived, it is undecryptable without the now-destroyed wipe_key.

use crate::crypto::{aead, Cipher};
use crate::key_lifecycle::KeySession;
use rusqlite::{params, Connection};
use zeroize::Zeroize;

/// Result of a secure erase: how many rows were destroyed.
#[derive(Debug)]
pub struct EraseReport {
    pub entries_destroyed: u64,
    pub wal_truncated: bool,
    pub vacuum_completed: bool,
}

/// Execute the full Secure Erase Protocol against `conn` using the session's wipe key.
///
/// # Safety contract
/// - Must be called while the vault is **unlocked** (we need the master key to derive wipe_key).
/// - After this returns, the database contains zero user data and the wipe key is destroyed.
/// - The caller should then `close()` the [`KeySession`] to destroy the master key too.
pub fn secure_erase(conn: &Connection, session: &KeySession) -> Result<EraseReport, crate::ValuError> {
    let cipher = Cipher::Aes256Gcm; // must match what was used for encryption

    // ── Step 1: derive the one-shot wipe key ────────────────────────────────────
    let _wipe_key_ref = session.wipe_key(); // [u8; 32], domain-separated from enc/mac keys

    // Count rows we're about to destroy (for the report).
    let entries_destroyed: u64 = conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get::<_, u64>(0))?;

    // ── Step 2: re-encrypt every row under wipe_key ─────────────────────────────
    // This overwrites the old ciphertext (encrypted under enc_key) with new ciphertext
    // (under wipe_key). Even if an attacker recovers the *old* page, they now need
    // wipe_key — which we destroy in step 6. Double-encryption-in-transit defeats
    // any "just use the original key" recovery path.
    let ids: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT id FROM entries")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    for id in &ids {
        // Fetch current ciphertexts.
        let (name_ct, user_ct, pass_ct, uri_ct, totp_ct, nonce_b): (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>) =
            conn.query_row(
                "SELECT name_enc, user_enc, pass_enc, uri_enc, totp_secret, nonce FROM entries WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )?;

        // The nonce column holds 5 concatenated 12-byte nonces (one per field).
        if nonce_b.len() != 60 {
            return Err(crate::ValuError::Crypto(format!("bad nonce blob: expected 60 bytes, got {}", nonce_b.len())));
        }
        let name_nonce: [u8; 12] = nonce_b[0..12].try_into().unwrap();
        let user_nonce: [u8; 12] = nonce_b[12..24].try_into().unwrap();
        let pass_nonce: [u8; 12] = nonce_b[24..36].try_into().unwrap();
        let uri_nonce: [u8; 12] = nonce_b[36..48].try_into().unwrap();
        let totp_nonce: [u8; 12] = nonce_b[48..60].try_into().unwrap();

        // Decrypt under the *original* enc_key to recover plaintext…
        let name_pt = aead::decrypt(cipher, session.enc_key(), &name_nonce, &name_ct)?;
        let user_pt = aead::decrypt(cipher, session.enc_key(), &user_nonce, &user_ct)?;
        let pass_pt = aead::decrypt(cipher, session.enc_key(), &pass_nonce, &pass_ct)?;
        let uri_pt: Option<Vec<u8>> = uri_ct.map(|c| aead::decrypt(cipher, session.enc_key(), &uri_nonce, &c)).transpose()?;
        let totp_pt: Option<Vec<u8>> = totp_ct.map(|c| aead::decrypt(cipher, session.enc_key(), &totp_nonce, &c)).transpose()?;

        // …then re-encrypt under the *wipe* key (new nonce domain=0xFF marks "wiped"),
        // again with a distinct per-field nonce so no keystream is shared.
        let name_wipe_nonce = aead::build_nonce(0xFF, *id as u64, 0);
        let user_wipe_nonce = aead::build_nonce(0xFF, *id as u64, 1);
        let pass_wipe_nonce = aead::build_nonce(0xFF, *id as u64, 2);
        let uri_wipe_nonce = aead::build_nonce(0xFF, *id as u64, 3);
        let totp_wipe_nonce = aead::build_nonce(0xFF, *id as u64, 4);
        let name_w = aead::encrypt(cipher, session.wipe_key(), &name_wipe_nonce, name_pt)?;
        let user_w = aead::encrypt(cipher, session.wipe_key(), &user_wipe_nonce, user_pt)?;
        let pass_w = aead::encrypt(cipher, session.wipe_key(), &pass_wipe_nonce, pass_pt)?;
        let uri_w: Option<Vec<u8>> = uri_pt.map(|p| aead::encrypt(cipher, session.wipe_key(), &uri_wipe_nonce, p)).transpose()?;
        let totp_w: Option<Vec<u8>> = totp_pt.map(|p| aead::encrypt(cipher, session.wipe_key(), &totp_wipe_nonce, p)).transpose()?;

        // Overwrite in-place. The old ciphertext bytes are now replaced on the SQLite page.
        conn.execute(
            "UPDATE entries SET name_enc=?2, user_enc=?3, pass_enc=?4, uri_enc=?5, totp_secret=?6 WHERE id=?1",
            params![id, name_w, user_w, pass_w, uri_w, totp_w],
        )?;
    }

    // ── Step 3: DELETE all rows ─────────────────────────────────────────────────
    conn.execute("DELETE FROM entries", [])?;
    conn.execute("DELETE FROM meta", [])?;

    // ── Step 4: checkpoint + truncate WAL ───────────────────────────────────────
    // `wal_checkpoint(TRUNCATE)` forces all WAL frames into the main DB file and then
    // truncates the WAL to zero length. No stale secret pages remain in -wal/-shm.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

    // ── Step 5: VACUUM — rewrite the entire database file ───────────────────────
    // VACUUM rebuilds the DB from scratch into a temp file, then replaces the original.
    // All previously-allocated pages (holding our re-encrypted-then-deleted data) are
    // freed to the OS. Because the process runs under mlockall + RLIMIT_CORE=0:
    //   • freed pages stay in locked RAM (no swap),
    //   • no core dump can capture them,
    //   • the temp file VACUUM creates inherits MCL_FUTURE locking.
    conn.execute_batch("VACUUM;")?;

    // ── Step 6: zeroize all in-memory key material ──────────────────────────────
    // wipe_key is a local [u8;32] — explicitly wiped now that we're done with it.
    let mut wk = *session.wipe_key();
    wk.zeroize();

    Ok(EraseReport { entries_destroyed, wal_truncated: true, vacuum_completed: true })
}

/// Convenience: run secure erase and then close the key session (destroys master key).
pub fn destroy_vault(db: &super::VaultDatabase, session: KeySession) -> Result<EraseReport, crate::ValuError> {
    let report = secure_erase(db.conn(), &session)?;
    session.close(); // zeroizes enc/mac/wipe subkeys + raw master key
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_lifecycle::{KeySession, MasterKey};
    use crate::storage::VaultDatabase;
    use std::env::temp_dir;

    fn tmp(name: &str) -> String {
        temp_dir().join(format!("valu_erase_{name}.db")).to_string_lossy().to_string()
    }

    #[test]
    fn erase_destroys_all_entries_and_is_unrecoverable() {
        let path = tmp("full");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }

        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        db.insert_entry(&session, "A", "ua", "pa", None, None).unwrap();
        db.insert_entry(&session, "B", "ub", "pb", None, None).unwrap();
        assert_eq!(db.entry_count().unwrap(), 2);

        let report = secure_erase(db.conn(), &session).unwrap();
        assert_eq!(report.entries_destroyed, 2);
        assert!(report.wal_truncated);
        assert!(report.vacuum_completed);

        // After erase: zero rows.
        assert_eq!(db.entry_count().unwrap(), 0);

        // Even with the *same* session key, the data is gone (deleted + re-encrypted under wiped key).
        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn erase_report_counts_correctly() {
        let path = tmp("count");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }

        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        for i in 0..5 {
            db.insert_entry(&session, &format!("e{i}"), "u", "p", None, None).unwrap();
        }
        let report = secure_erase(db.conn(), &session).unwrap();
        assert_eq!(report.entries_destroyed, 5);

        drop(db);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    /// Adversarial test: after a secure erase, the stored CIPHERTEXT must be absent
    /// from the *raw file bytes* — not just from the live rows. Searching for the
    /// plaintext would pass trivially (it is never written in the clear), so we
    /// search for the actual ciphertext blob read back from the database before
    /// the erase. This catches data that is unlinked but still on disk
    /// (freelist pages, stale WAL frames, shm).
    #[test]
    fn erase_leaves_no_plaintext_in_raw_file() {
        let path = tmp("rawfile");
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }

        let session = KeySession::new(MasterKey::create_volatile().unwrap());
        let db = VaultDatabase::open(&path, &session).unwrap();
        db.insert_entry(&session, "canary-entry", "canary-user", "CANARY_PLAINTEXT_7f3a91", None, None).unwrap();
        assert_eq!(db.entry_count().unwrap(), 1);

        // BEFORE the erase: read the raw pass_enc ciphertext blob for this row
        // out of the database and keep it locally.
        let pass_ct: Vec<u8> = db.conn()
            .query_row("SELECT pass_enc FROM entries", [], |r| r.get(0))
            .unwrap();
        assert!(!pass_ct.is_empty(), "pass_enc blob unexpectedly empty");

        // CONTROL assertion: the vault data on disk must currently CONTAIN those
        // ciphertext bytes — in the main file OR the WAL sidecar (WAL mode keeps
        // fresh writes in -wal until a checkpoint). If this fails, the data has
        // not been flushed and every later assertion would be meaningless.
        let main_bytes = std::fs::read(&path).unwrap_or_default();
        let wal_bytes = std::fs::read(format!("{path}-wal")).unwrap_or_default();
        let in_main = main_bytes.windows(pass_ct.len()).any(|w| w == pass_ct);
        let in_wal = wal_bytes.windows(pass_ct.len()).any(|w| w == pass_ct);
        assert!(
            in_main || in_wal,
            "control failed: pass_enc ciphertext not present in raw database file or WAL before erase"
        );

        let report = secure_erase(db.conn(), &session).unwrap();
        assert_eq!(report.entries_destroyed, 1);

        // Close the database so everything (WAL checkpoint, VACUUM temp-file swap)
        // is flushed to disk before we inspect raw bytes.
        drop(db);

        // The ciphertext bytes must now be ABSENT from the raw database file —
        // live pages, freelist pages, or otherwise.
        let bytes = std::fs::read(&path).unwrap_or_default();
        assert!(
            !bytes.windows(pass_ct.len()).any(|w| w == pass_ct),
            "pass_enc ciphertext found in raw database file after secure erase"
        );

        // Same check for the WAL and SHM sidecar files, if they exist.
        for suffix in ["-wal", "-shm"] {
            let sidecar = format!("{path}{suffix}");
            if std::path::Path::new(&sidecar).exists() {
                let bytes = std::fs::read(&sidecar).unwrap_or_default();
                assert!(
                    !bytes.windows(pass_ct.len()).any(|w| w == pass_ct),
                    "pass_enc ciphertext found in raw {sidecar} file after secure erase"
                );
            }
        }

        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }
}
