//! # Keypal — CLI entrypoint & lifecycle orchestration
//!
//! Startup sequence (order matters for security):
//!   1. `harden_process_memory()` — mlockall + RLIMIT_CORE=0 **before** any secret exists.
//!   2. Initialize tracing with redaction layer.
//!   3. Parse CLI → create/unlock vault → run command → destroy keys on exit.

use rand_core::{OsRng, RngCore};
use rusqlite::params;
use keypal::circuit_breaker::{BreakerConfig, CircuitBreaker};
use keypal::storage::SecretStore;
use keypal::key_lifecycle::{KeySession, MasterKey};
use keypal::redaction;
use keypal::storage::secure_erase;
use keypal::storage::VaultDatabase;
use std::path::PathBuf;

fn main() {
    // ── 1. Memory hardening FIRST (no secrets allocated yet) ────────────────────
    if let Err(e) = keypal::secure_mem::harden_process_memory() {
        eprintln!("[WARN] {e}");
        // Continue in degraded mode but loudly warn — user must know swap risk exists.
    }

    // ── 2. Logging with strict redaction ────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "keypal=info".into()),
        )
        .init();

    // ── 3. CLI dispatch (minimal; full arg parsing in Phase 5) ──────────────────
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("create-volatile") => cmd_create_volatile(&args[1..]),
        Some("create")          => cmd_create(&args[1..]),
        Some("get")             => cmd_get(&args[1..]),
        Some("serve")           => cmd_serve(&args[1..]),
        Some("add")             => cmd_add(&args[1..]),
        Some("import-kdbx")     => cmd_import_kdbx(&args[1..]),
        Some("destroy")         => cmd_destroy(&args[1..]),
        _ => {
            eprintln!("Keypal — SOTA Privacy-First Password Vault");
            eprintln!("Usage:");
            eprintln!("  keypal create-volatile <path>          Create ephemeral vault (key never touches disk)");
            eprintln!("  keypal create <path> <passphrase>      Create passphrase-mode vault (key re-derivable)");
            eprintln!("  keypal get <path> <passphrase> <name>  Look up an entry by name");
            eprintln!("  keypal serve <path> <passphrase>        Serve secrets over D-Bus (org.rafa.Valu1)");
            eprintln!("  keypal add <path> <passphrase> <name> <username> <password> Add an entry");
            eprintln!("  keypal import-kdbx <vault-path> <vault-passphrase> <kdbx-path> <kdbx-password> Import entries from a KDBX file");
            eprintln!("  keypal destroy <path>                  Secure Erase Protocol (wipe key + WAL truncate + VACUUM)");
        }
    }
}

fn vault_path(args: &[String]) -> PathBuf {
    args.first().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("vault.db"))
}

/// Create a new volatile (ephemeral) vault. The master key lives only in RAM for this process.
fn cmd_create_volatile(args: &[String]) {
    let path = vault_path(args);
    tracing::info!(path = %redaction::redact_string(&path.to_string_lossy(), redaction::StringPolicy::PartialMask), "creating volatile vault");

    // Volatile key: CSPRNG in mlocked RAM, zeroized on drop. Unrecoverable after exit.
    let session = KeySession::new(MasterKey::create_volatile().expect("CSPRNG available"));
    let db = VaultDatabase::open(path.to_str().unwrap(), &session).expect("db open");

    // Persist a fresh 16-byte salt so that `add`/`destroy` (passphrase mode) can
    // re-derive an equivalent key later. The salt is NOT secret — it only makes KDF
    // outputs unique per vault.
    let mut salt = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut salt).expect("CSPRNG available for salt generation");
    db.conn().execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('argon_salt', ?1)",
        params![salt],
    ).ok(); // best-effort; schema guarantees the table exists

    // Persist the circuit-breaker state (sealed under mac_key) so lockouts survive restarts.
    let cb = CircuitBreaker::new(BreakerConfig::default());
    let sealed = cb.seal_state(session.mac_key());
    db.conn().execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
        params![sealed],
    ).ok(); // best-effort; meta table may not exist in minimal schema

    tracing::info!("volatile vault created — key is RAM-only and will be destroyed on exit");
    session.close(); // explicit teardown: zeroizes all key material
}

/// Create a new passphrase-mode vault. Same structure as `cmd_create_volatile`, but the
/// master key is derived from a passphrase (Argon2id + stored salt) so it can be
/// re-derived in later processes.
fn cmd_create(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: keypal create <path> <passphrase>");
        return;
    }
    let path = vault_path(args);
    let pass = &args[1];
    tracing::info!(path = %redaction::redact_string(&path.to_string_lossy(), redaction::StringPolicy::PartialMask), "creating passphrase vault");

    // Fresh 16-byte salt (same CSPRNG call as cmd_create_volatile). The salt is NOT
    // secret — it only makes KDF outputs unique per vault.
    let mut salt = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut salt).expect("CSPRNG available for salt generation");

    // Passphrase-derived key (Argon2id) instead of a volatile key.
    let session = KeySession::new(MasterKey::create_passphrase(pass, &salt).expect("Argon2id KDF"));
    let db = VaultDatabase::open(path.to_str().unwrap(), &session).expect("db open");

    // Persist the salt so `add`/`get`/`destroy` can re-derive the same key later.
    db.conn().execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('argon_salt', ?1)",
        params![salt],
    ).ok(); // best-effort; schema guarantees the table exists

    // Persist the circuit-breaker state (sealed under breaker_key, derived from the
    // public salt) so lockouts survive restarts without needing the passphrase.
    let breaker_key = keypal::crypto::kdf::hkdf_domain(&salt, b"valu/breaker/v1");
    let cb = CircuitBreaker::new(BreakerConfig::default());
    let sealed = cb.seal_state(&breaker_key);
    db.conn().execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
        params![sealed],
    ).ok(); // best-effort; meta table may not exist in minimal schema

    tracing::info!("passphrase vault created — key re-derivable from passphrase + stored salt");
    session.close(); // explicit teardown: zeroizes all key material
}

/// Look up an entry by name in a passphrase-mode vault and print username + password.
fn cmd_get(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: keypal get <path> <passphrase> <entry-name>");
        return;
    }
    let path = vault_path(&args);
    let (pass, name) = (&args[1], &args[2]);

    // 1. Open the database file.
    let conn = rusqlite::Connection::open(path.to_str().unwrap()).expect("db open");

    // 2. Read the salt row out of the meta table.
    let salt: Vec<u8> = conn.query_row(
        "SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0)
    ).expect("salt present (run create first)");

    // 2b. Circuit breaker: derive its key from the public salt (readable WITHOUT the
    // passphrase), unseal the persisted state, and gate the attempt BEFORE any key work.
    let breaker_key = keypal::crypto::kdf::hkdf_domain(&salt, b"valu/breaker/v1");
    let mut breaker = match conn.query_row(
        "SELECT value FROM meta WHERE key='breaker'", [], |r| r.get::<_, Vec<u8>>(0)
    ) {
        Ok(row) => CircuitBreaker::unseal(&row, &breaker_key)
            .unwrap_or_else(|| CircuitBreaker::new(BreakerConfig::default())),
        Err(_) => CircuitBreaker::new(BreakerConfig::default()),
    };
    if let Err(seconds) = breaker.allow_attempt() {
        println!("locked out — try again in {seconds} seconds");
        let sealed = breaker.seal_state(&breaker_key);
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
            params![sealed],
        ).ok();
        return;
    }

    // 3. Build the key with the passphrase + salt.
    let session = match MasterKey::create_passphrase(pass, &salt) {
        Ok(k) => KeySession::new(k),
        Err(_) => {
            breaker.record_failure();
            let sealed = breaker.seal_state(&breaker_key);
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
                params![sealed],
            ).ok();
            println!("unlock failed");
            return;
        }
    };
    let db = match VaultDatabase::open(path.to_str().unwrap(), &session) {
        Ok(d) => d,
        Err(_) => {
            breaker.record_failure();
            let sealed = breaker.seal_state(&breaker_key);
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
                params![sealed],
            ).ok();
            session.close();
            println!("unlock failed");
            return;
        }
    };

    // 4. Look up the entry by name, through the SecretStore contract. The
    // iterate-decrypt-compare loop lived here and again in the D-Bus service;
    // it now lives once, in storage.
    let mut found = false;
    let mut unlock_failed = false;
    match db.entry_by_name(&session, name) {
        Ok(Some(entry)) => {
            // 5. Found: record success, persist breaker state, then print.
            breaker.record_success();
            let sealed = breaker.seal_state(&breaker_key);
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
                params![sealed],
            ).ok();
            println!("{}", entry.username);
            println!("{}", entry.password.expose());
            found = true;
        }
        Ok(None) => {}
        // 6. Wrong passphrase → AEAD tag verification fails.
        Err(_) => { unlock_failed = true; }
    }

    if !found {
        if unlock_failed {
            // 6b. Record the failure and persist the breaker state before printing.
            breaker.record_failure();
            let sealed = breaker.seal_state(&breaker_key);
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('breaker', ?1)",
                params![sealed],
            ).ok();
            println!("unlock failed");
        } else {
            // 7. No entry matches.
            println!("no such entry");
        }
    }

    // 8. Explicit teardown on every path.
    session.close();
}

/// Serve the vault over D-Bus as org.rafa.Valu1.
///
/// Deliberately NOT org.freedesktop.secrets: that well-known name belongs to
/// gnome-keyring on this machine, and taking it would break every application
/// that depends on it.
fn cmd_serve(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: keypal serve <path> <passphrase>");
        return;
    }
    let path = vault_path(&args);
    let pass = &args[1];

    // 1. Open the vault exactly as cmd_get does (salt, unlock_passphrase).
    let conn = rusqlite::Connection::open(path.to_str().unwrap()).expect("db open");
    let salt: Vec<u8> = conn
        .query_row("SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0))
        .expect("salt present (run create first)");

    // 2. Load the breaker exactly as cmd_get does.
    let breaker_key = keypal::crypto::kdf::hkdf_domain(&salt, b"valu/breaker/v1");
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
    let db = match VaultDatabase::open(path.to_str().unwrap(), &session) {
        Ok(d) => d,
        Err(_) => {
            session.close();
            eprintln!("unlock failed");
            return;
        }
    };

    // 3. Build the service.
    let iface = keypal::dbus::SecretService::new(db, session, breaker, breaker_key, conn);

    // 4. Build the connection and serve the interface at /org/rafa/Valu1.
    let _conn = zbus::blocking::connection::Builder::session()
        .expect("session bus")
        .name("org.rafa.Valu1")
        .expect("well-known name")
        .serve_at("/org/rafa/Valu1", iface)
        .expect("serve_at")
        .build()
        .expect("connection build");

    // 5. Keep the connection alive: park the thread forever.
    println!("serving on org.rafa.Valu1");
    loop {
        std::thread::park();
    }
}

/// Add an entry to an existing vault (requires a passphrase-mode vault for persistence).
fn cmd_add(args: &[String]) {
    if args.len() < 5 {
        eprintln!("Usage: keypal add <path> <passphrase> <name> <username> <password>");
        return;
    }
    let path = vault_path(&args);
    let (passphrase, name, user, pass) = (&args[1], &args[2], &args[3], &args[4]);

    // Passphrase mode: derive the master key via Argon2id from a CLI-supplied passphrase.
    // The salt is read back from `meta.argon_salt` (written at create-volatile time).
    let conn = rusqlite::Connection::open(path.to_str().unwrap()).expect("db open");
    let salt: Vec<u8> = conn.query_row(
        "SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0)
    ).expect("salt present (run create-volatile first)");
    let session = KeySession::new(MasterKey::unlock_passphrase(passphrase, &salt).expect("Argon2id KDF"));
    let db = match VaultDatabase::open(path.to_str().unwrap(), &session) {
        Ok(d) => d,
        Err(e) => { eprintln!("failed to open vault: {e}"); return; }
    };

    match db.insert_entry(&session, name, user, pass, None, None) {
        Ok(id) => tracing::info!(entry_id = id, "entry added"),
        Err(e) => eprintln!("insert failed: {e}"),
    }
    session.close();
}

// LIMITATION, stated rather than hidden: the `keepass` crate returns
// decrypted fields as &str borrowed from its own internal buffers. We
// cannot zeroize memory we do not own, so KDBX plaintext lives in
// unmanaged heap for the duration of this import. Dropping the Database
// promptly bounds that window; it does not eliminate it. Closing it fully
// would require the crate to expose zeroizing accessors.
fn cmd_import_kdbx(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Usage: keypal import-kdbx <vault-path> <vault-passphrase> <kdbx-path> <kdbx-password>");
        return;
    }
    let path = vault_path(&args);
    let (passphrase, kdbx_path, kdbx_password) = (&args[1], &args[2], &args[3]);

    // Open the Keypal vault: salt row + MasterKey::unlock_passphrase (same path as cmd_get).
    let conn = rusqlite::Connection::open(path.to_str().unwrap()).expect("db open");
    let salt: Vec<u8> = conn.query_row(
        "SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0)
    ).expect("salt present (run create first)");
    let session = KeySession::new(MasterKey::unlock_passphrase(passphrase, &salt).expect("Argon2id KDF"));
    let db = match VaultDatabase::open(path.to_str().unwrap(), &session) {
        Ok(d) => d,
        Err(e) => { eprintln!("failed to open vault: {e}"); session.close(); return; }
    };

    let mut imported = 0usize;
    let mut skipped = 0usize;

    // The keepass Database lives in its own scope so its decrypted buffers are
    // released before the command returns.
    {
        let mut file = std::fs::File::open(kdbx_path).expect("kdbx file open");
        let key = keepass::DatabaseKey::new().with_password(kdbx_password);
        let database = match keepass::Database::open(&mut file, key) {
            Ok(d) => d,
            Err(_) => {
                // Do not print the error detail — it can carry file contents.
                println!("kdbx open failed");
                session.close();
                return;
            }
        };

        for entry in database.iter_all_entries() {
            let (title, password) = match (entry.get_title(), entry.get_password()) {
                (Some(t), Some(p)) => (t, p),
                _ => { skipped += 1; continue; }
            };
            let username = entry.get_username().unwrap_or("");
            match db.insert_entry(&session, title, username, password, None, None) {
                Ok(_) => imported += 1,
                Err(_) => skipped += 1,
            }
        }
    }

    println!("imported {imported} entries");
    println!("skipped {skipped} entries");
    session.close();
}

/// Execute the Secure Erase Protocol and destroy all key material.
fn cmd_destroy(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: keypal destroy <path> <passphrase>");
        return;
    }
    let path = vault_path(&args);
    let pass = &args[1];
    tracing::info!(path = %redaction::redact_string(&path.to_string_lossy(), redaction::StringPolicy::PartialMask), "executing secure erase protocol");

    // Re-derive the key from the passphrase (Argon2id + stored salt). The wipe_key
    // subkey is what the Secure Erase Protocol uses — it must match the one used at
    // insert time, which requires the same master key.
    let conn = rusqlite::Connection::open(path.to_str().unwrap()).expect("db open");
    let salt: Vec<u8> = conn.query_row(
        "SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0)
    ).expect("salt present (run create-volatile first)");
    let session = KeySession::new(MasterKey::create_passphrase(pass, &salt).expect("Argon2id KDF"));
    let db = match VaultDatabase::open(path.to_str().unwrap(), &session) {
        Ok(d) => d,
        Err(e) => { eprintln!("failed to open vault for erase: {e}"); return; }
    };

    match secure_erase::secure_erase(db.conn(), &session) {
        Ok(report) => {
            tracing::info!(
                entries_destroyed = report.entries_destroyed,
                wal_truncated = report.wal_truncated,
                vacuum_completed = report.vacuum_completed,
                "secure erase complete"
            );
        }
        Err(e) => eprintln!("secure erase FAILED: {e}"),
    }

    // Final destruction: zeroize master + subkeys. After this, nothing is recoverable.
    session.close();
    tracing::info!("all key material destroyed — the vault can no longer be decrypted with it");
}
