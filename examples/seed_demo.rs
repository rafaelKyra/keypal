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
use keypal::key_lifecycle::{KeySession, MasterKey};
use keypal::kind::{encode_fields, Kind};
use keypal::storage::{EntryDraft, VaultDatabase};

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

    // A few of each, so the grouped navigation pane has something to group and
    // every count is a number rather than a 1.
    add("GitHub", Kind::Website, "octocat", "T7#kq9Zm!wR2xL4vB8n", Some("https://github.com"), &[], "work,dev");
    add("Cloudflare", Kind::Website, "rk", "Xp4!nQ8#vZ2mL9wR", Some("https://dash.cloudflare.com"), &[], "work,infra");
    add("Bank of Somewhere", Kind::Website, "rk1982", "Kq7$mZ3!wX9pR2vT", Some("https://bank.example"), &[], "money");
    add("Local council", Kind::Website, "r.k", "hunter2", Some("https://council.example"), &[], "personal");

    add("Fastmail", Kind::Email, "me@example.com", "hV3$pQ8!zN6wE2rT", None,
        &[("server","imap.fastmail.com"),("port","993")], "work");
    add("Personal Gmail", Kind::Email, "demo@example.com", "demo-password-not-real", None,
        &[("server","imap.gmail.com"),("port","993")], "personal");

    add("GitHub 2FA", Kind::Authenticator, "", "", None, &[], "work,dev");
    add("Bank 2FA", Kind::Authenticator, "", "", None, &[], "money");

    add("build-01", Kind::Server, "root", "P9!xK2#mQ7wZ4rT8", None,
        &[("host","build-01.example.com"),("port","22")], "infra");
    add("web-02", Kind::Server, "deploy", "W3$nK8!qZ2mX7pL", None,
        &[("host","web-02.example.com"),("port","22")], "infra");
    add("NAS at home", Kind::Server, "admin", "N4#pQ9!kZ2wM7xR", None,
        &[("host","192.168.1.20"),("port","22")], "home");

    add("Orders database", Kind::Database, "orders_rw", "dB7$kQ2!mZ9wX4rT", None,
        &[("engine","PostgreSQL"),("host","db.example.com"),("port","5432"),
          ("dsn","postgres://orders_rw@db.example.com/orders")], "infra,work");
    add("Analytics warehouse", Kind::Database, "analyst", "aN3!wQ7#kZ8mP2xL", None,
        &[("engine","ClickHouse"),("host","dw.example.com"),("port","9000"),
          ("dsn","clickhouse://analyst@dw.example.com/main")], "work");

    add("Deploy key", Kind::SshKey, "git", "aB3!kQ9#mZ2wR7xL", None,
        &[("private_key","-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUA\nAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz\n-----END OPENSSH PRIVATE KEY-----"),
          ("host","git@github.com")], "work,dev");
    add("Laptop key", Kind::SshKey, "rk", "lP7$mZ4!kQ8wX2rN", None,
        &[("private_key","-----BEGIN OPENSSH PRIVATE KEY-----\nc2Vjb25kIGtleSBmb3IgdGhlIGxhcHRvcA\n-----END OPENSSH PRIVATE KEY-----"),
          ("host","rk@build-01.example.com")], "infra");

    add("Stripe live key", Kind::ApiKey, "", "sk_live_51H8xQ2eZvKYlo2C7pR", None,
        &[("service","Stripe"),("expires","2027-01-31")], "work,money");
    add("OpenWeather", Kind::ApiKey, "", "8f2a91c4d77b4e0fa312", None,
        &[("service","OpenWeather"),("expires","")], "dev");
    add("Hetzner API token", Kind::ApiKey, "", "hz_9KpQ2mZ4wX7rT3nL8vB", None,
        &[("service","Hetzner Cloud"),("expires","2026-12-01")], "infra");

    add("Office VPN", Kind::Vpn, "rk", "vP8!kQ3#mZ7wX2rN", None,
        &[("server","vpn.example.com"),("protocol","WireGuard")], "work");
    add("Travel VPN", Kind::Vpn, "rk", "tV4$mQ9!kZ2wP7xR", None,
        &[("server","eu.vpn.example"),("protocol","OpenVPN")], "personal");

    add("Home Wi-Fi", Kind::Wifi, "", "correct-horse-battery-staple-9", None,
        &[("ssid","Home-5G"),("admin_ip","192.168.1.1")], "home");
    add("Office Wi-Fi", Kind::Wifi, "", "Qk7!mZ3#pW9xR2vN4t", None,
        &[("ssid","Acme-Staff"),("admin_ip","10.0.0.1")], "work");

    add("Work laptop", Kind::Device, "rk", "lQ8!mZ4#pK7wX2rN", None,
        &[("os","Linux")], "work");
    add("Old Android", Kind::Device, "rk", "1234", None, &[("os","Android")], "personal");

    add("Debit card", Kind::BankCard, "R. K.", "4111 1111 1111 1111", None,
        &[("expires","09/29"),("cvv","123")], "money");
    add("Business credit card", Kind::BankCard, "R. K. / Acme SRL", "5500 0000 0000 0004", None,
        &[("expires","03/28"),("cvv","456")], "money,work");

    add("Hardware wallet", Kind::CryptoWallet, "", "witch collapse practice feed shame open despair creek road again ice least", None,
        &[("network","Bitcoin")], "money");
    add("Ethereum hot wallet", Kind::CryptoWallet, "", "gravity machine north sort system female filter attitude volume fold club stay", None,
        &[("network","Ethereum")], "money");

    add("Code signing certificate", Kind::Certificate, "", "cS9!mQ4#pZ7wX2rN", None,
        &[("issuer","DigiCert"),("expires","2027-06-30")], "work,dev");
    add("Mail server TLS", Kind::Certificate, "", "tL3$kQ8!mZ2wP9xR", None,
        &[("issuer","Let\'s Encrypt"),("expires","2026-11-14")], "infra");

    add("GitHub recovery codes", Kind::RecoveryCodes, "", "", None,
        &[("codes","a1b2-c3d4\ne5f6-g7h8\ni9j0-k1l2\nm3n4-o5p6")], "work,dev");
    add("Bank recovery codes", Kind::RecoveryCodes, "", "", None,
        &[("codes","884213\n119047\n560328\n771905")], "money");

    add("Passport details", Kind::SecureNote, "", "", None, &[], "personal");
    add("Alarm code and key holder", Kind::SecureNote, "", "", None, &[], "home");

    add("IntelliJ IDEA", Kind::License, "R. K.", "IJ-9K2M-4XQ7-ZR31", None,
        &[("product","IntelliJ IDEA Ultimate")], "work,dev");
    add("Affinity Photo", Kind::License, "R. K.", "AP-7742-1180-KQ93", None,
        &[("product","Affinity Photo 2")], "personal");

    println!("seeded {}", path);
}
