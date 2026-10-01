//! Getting data back out.
//!
//! A vault you cannot leave is a vault you should not enter. Export exists so
//! the answer to "what if this project dies" is a file you already have, not a
//! support ticket.
//!
//! Two shapes, for two different jobs:
//!
//!   - `backup` copies the encrypted database. It stays encrypted under the
//!     same passphrase, so it is safe to put on a USB stick or a NAS.
//!   - `to_csv` produces PLAINTEXT, because that is the only thing every other
//!     manager can read. It is the dangerous one, and the API says so: the
//!     function name, this comment, and the caller-facing warning all state it.
//!     A convenience that quietly writes every password to disk unencrypted
//!     would undo the entire project.

use std::io::Write;
use std::path::{Path, PathBuf};

/// One row on the way out. Mirrors what `import::Incoming` reads back in, so a
/// Keypal export re-imports into Keypal without loss.
pub struct Outgoing {
    pub name: String,
    pub username: String,
    pub password: String,
    pub uri: Option<String>,
    pub totp: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<String>,
}

fn quote(field: &str) -> String {
    // Always quote. Costs a few bytes and removes every question about commas,
    // quotes and newlines in notes.
    format!("\"{}\"", field.replace('"', "\"\""))
}

/// Serialise entries as CSV.
///
/// PLAINTEXT. Every password appears in the clear. The caller is responsible
/// for telling the user before writing it and for choosing where it lands.
pub fn to_csv(rows: &[Outgoing]) -> String {
    let mut out = String::from("name,username,password,url,totp,notes,tags\n");
    for r in rows {
        out.push_str(&quote(&r.name));
        out.push(',');
        out.push_str(&quote(&r.username));
        out.push(',');
        out.push_str(&quote(&r.password));
        out.push(',');
        out.push_str(&quote(r.uri.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&quote(r.totp.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&quote(r.notes.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&quote(r.tags.as_deref().unwrap_or("")));
        out.push('\n');
    }
    out
}

/// Write a CSV export with owner-only permissions.
///
/// 0600 from the moment it exists: creating the file world-readable and
/// tightening it afterwards leaves a window in which every password on the
/// machine is readable by every user on it.
pub fn write_csv(path: &Path, csv: &str) -> Result<(), String> {
    use std::fs::OpenOptions;
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| e.to_string())?;
    file.write_all(csv.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

/// Copy the encrypted vault beside itself, timestamped.
///
/// The copy is ciphertext under the same passphrase, so it needs no extra
/// protection — and deliberately no extra passphrase either, because a backup
/// locked behind a second secret is one people cannot open when they need it.
///
/// WAL matters here: recent writes may still live in `-wal` rather than the
/// main file, so a naive copy of the `.db` alone can be missing the newest
/// entries. The database is checkpointed first.
pub fn backup(vault: &Path, conn: &rusqlite::Connection) -> Result<PathBuf, String> {
    conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")
        .map_err(|e| format!("could not checkpoint before backup: {e}"))?;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = vault
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault".into());
    let target = vault.with_file_name(format!("{name}-backup-{stamp}.db"));

    std::fs::copy(vault, &target).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, pw: &str, notes: Option<&str>) -> Outgoing {
        Outgoing {
            name: name.into(),
            username: "me".into(),
            password: pw.into(),
            uri: Some("https://x.example".into()),
            totp: None,
            notes: notes.map(|s| s.into()),
            tags: None,
        }
    }

    #[test]
    fn a_valu_export_reimports_into_valu_without_loss() {
        // The round trip is the only test that matters for an export format:
        // a file nothing can read back is not a backup.
        let rows = vec![
            row("GitHub", "s3cret", None),
            row("Bank, Ltd", "pw,with,commas", Some("he said \"hi\"\nsecond line")),
        ];
        let csv = to_csv(&rows);
        let (_, back) = crate::import::parse(&csv).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].name, "GitHub");
        assert_eq!(back[1].name, "Bank, Ltd");
        assert_eq!(back[1].password, "pw,with,commas");
        assert_eq!(
            back[1].notes.as_deref(),
            Some("he said \"hi\"\nsecond line"),
            "quotes and newlines must survive the round trip"
        );
    }

    #[test]
    fn every_field_is_quoted_so_separators_cannot_leak_structure() {
        let csv = to_csv(&[row("A", "b", None)]);
        let line = csv.lines().nth(1).unwrap();
        assert!(line.starts_with("\"A\",\"me\",\"b\""), "got {line}");
    }

    #[test]
    fn an_empty_vault_exports_a_header_and_nothing_else() {
        let csv = to_csv(&[]);
        assert_eq!(csv.lines().count(), 1);
        assert!(csv.starts_with("name,username,password"));
    }

    #[cfg(unix)]
    #[test]
    fn a_csv_export_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("valu-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.csv");
        write_csv(&path, "name,username,password\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // Not 0644-then-chmod: the file must never exist readable by others,
        // not even briefly.
        assert_eq!(mode, 0o600, "export was mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
