//! Build a throwaway vault holding one entry of each of several categories.
//!
//! This exists for the screenshot loop. Checking that sixteen category forms
//! look right needs a vault with those categories in it, and hand-typing one
//! through the interface every time the layout changes is how a layout stops
//! being checked.
//!
//! NOT a tool for real data: the passphrase is written in the source below, in
//! the clear, and the vault is deleted and recreated on every run.
//!
//!     cargo run --example seed_demo -- /tmp/demo-vault.db
//!
//! Then photograph it:
//!
//!     KEYPAL_SHOT=/tmp/x.png KEYPAL_SHOT_VAULT=/tmp/demo-vault.db \
//!     KEYPAL_SHOT_PASS=demo-passphrase KEYPAL_SHOT_PANEL=detail \
//!     KEYPAL_SHOT_KIND=13 ./target/release/keypal-gui

use rand_core::{OsRng, RngCore};
use valu::key_lifecycle::{KeySession, MasterKey};
use valu::kind::{encode_fields, Kind};
use valu::storage::{EntryDraft, VaultDatabase};

fn main() {
    let path = std::env::args().nth(1).unwrap();
    for s in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{s}")); }
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let session = KeySession::new(MasterKey::create_passphrase("demo-passphrase", &salt).unwrap());
    let db = VaultDatabase::open(&path, &session).unwrap();
    db.conn().execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('argon_salt', ?1)",
        rusqlite::params![salt.to_vec()]).unwrap();

    let mut add = |name: &str, kind: Kind, user: &str, pw: &str, uri: Option<&str>, f: &[(&str,&str)], tags: &str| {
        let fields = encode_fields(&f.iter().map(|(k,v)| (k.to_string(), v.to_string())).collect::<Vec<_>>());
        db.insert_draft(&session, &EntryDraft {
            name, username: user, password: pw, uri, kind,
            fields: Some(&fields), tags: Some(tags), ..EntryDraft::default()
        }).unwrap();
    };

    add("GitHub", Kind::Website, "octocat", "T7#kq9Zm!wR2xL4vB8n", Some("https://github.com"), &[], "work");
    add("Fastmail", Kind::Email, "me@example.com", "hV3$pQ8!zN6wE2rT", None,
        &[("server","imap.fastmail.com"),("port","993")], "work");
    add("GitHub 2FA", Kind::Authenticator, "", "", None, &[], "work");
    add("Stripe live key", Kind::ApiKey, "", "sk_live_51H8xQ2eZvKYlo2C", None,
        &[("service","Stripe"),("expires","2027-01-31")], "work");
    add("Deploy key", Kind::SshKey, "git", "aB3!kQ9#mZ2wR7xL", None,
        &[("private_key","-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END-----"),("host","git@github.com")], "work");
    add("build-01", Kind::Server, "root", "P9!xK2#mQ7wZ4rT8", None,
        &[("host","build-01.example.com"),("port","22")], "infra");
    add("Orders database", Kind::Database, "orders_rw", "dB7$kQ2!mZ9wX4rT", None,
        &[("engine","PostgreSQL"),("host","db.example.com"),("port","5432"),("dsn","postgres://orders_rw@db.example.com/orders")], "infra");
    add("Home Wi-Fi", Kind::Wifi, "", "correct-horse-battery-staple-9", None,
        &[("ssid","Home-5G"),("admin_ip","192.168.1.1")], "home");
    add("Debit card", Kind::BankCard, "R. K.", "4111 1111 1111 1111", None,
        &[("expires","09/29"),("cvv","123")], "money");
    add("Passport details", Kind::SecureNote, "", "", None, &[], "personal");
    add("GitHub recovery codes", Kind::RecoveryCodes, "", "", None,
        &[("codes","a1b2-c3d4\ne5f6-g7h8\ni9j0-k1l2")], "work");
    add("IntelliJ IDEA", Kind::License, "R. K.", "IJ-9K2M-4XQ7-ZR31", None,
        &[("product","IntelliJ IDEA Ultimate")], "");
    println!("seeded {}", path);
}
