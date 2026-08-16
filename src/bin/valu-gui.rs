// The GUI links the vault library directly, in-process: secrets never cross a
// serialisation boundary the way they would through a web frontend or an IPC
// bridge. What egui itself keeps — the String behind a password box, glyph
// caches for revealed text, the clipboard — is not memory we own or can
// zeroize. Stated rather than hidden.
//
// There is deliberately no native file dialog. `rfd` needs Wayland development
// packages this machine does not have, and requiring a system package to open
// your own vault is a worse answer than not needing one: the lock screen scans
// for vaults and lists them, so the common case is a single click.

use eframe::egui;
use rand_core::{OsRng, RngCore};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use valu::key_lifecycle::{KeySession, MasterKey};
use valu::storage::VaultDatabase;
use valu::totp;

// ── Palette ─────────────────────────────────────────────────────────────────
const BG: egui::Color32 = egui::Color32::from_rgb(0x11, 0x13, 0x18);
const SURFACE: egui::Color32 = egui::Color32::from_rgb(0x1a, 0x1d, 0x24);
const SURFACE_HI: egui::Color32 = egui::Color32::from_rgb(0x25, 0x29, 0x33);
const LINE: egui::Color32 = egui::Color32::from_rgb(0x2a, 0x2f, 0x3a);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x6e, 0x9f, 0xff);
const TEXT: egui::Color32 = egui::Color32::from_rgb(0xe8, 0xea, 0xef);
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x8c, 0x93, 0xa4);
const DANGER: egui::Color32 = egui::Color32::from_rgb(0xff, 0x6b, 0x6b);
const WARN: egui::Color32 = egui::Color32::from_rgb(0xf0, 0xb4, 0x5f);
const OK: egui::Color32 = egui::Color32::from_rgb(0x5d, 0xd6, 0x8e);

/// How long a copied secret may sit in the clipboard.
///
/// The clipboard is readable by every application on the desktop, so a password
/// left there outlives the moment it was needed. Twenty seconds is long enough
/// to paste and short enough to matter.
const CLIPBOARD_TTL: Duration = Duration::from_secs(20);

/// Idle time before the vault locks itself.
const IDLE_LOCK: Duration = Duration::from_secs(5 * 60);

#[derive(PartialEq, Clone, Copy)]
enum Level {
    None,
    Ok,
    Bad,
}

/// Only one panel is open at a time. A window showing an add form, an import
/// form and a delete confirmation at once is how people paste a password into
/// the wrong field.
#[derive(PartialEq, Clone)]
enum Panel {
    List,
    Editor,
    Import,
    ImportCsv,
    Export,
    History(i64),
    Trash,
    Confirm(i64, String),
    ConfirmPurge(i64, String),
    ChangePass,
}

#[derive(PartialEq, Clone, Copy)]
enum Sort {
    Name,
    Recent,
}

/// One entry as the list needs it: the id for editing, plus decrypted fields.
#[derive(Clone)]
struct Row {
    id: i64,
    favorite: bool,
    updated_at: i64,
    name: String,
    username: String,
    uri: Option<String>,
    totp: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    password: String,
}

/// The editor works on a copy, so cancelling changes nothing and saving is one
/// explicit act.
#[derive(Default, Clone)]
struct Draft {
    id: Option<i64>, // None = new entry
    name: String,
    username: String,
    password: String,
    uri: String,
    totp: String,
    tags: String,
    notes: String,
    show_password: bool,
}

struct App {
    // locked
    vaults: Vec<PathBuf>,
    selected: Option<PathBuf>,
    manual_path: String,
    passphrase: String,
    creating: bool,
    new_path: String,
    new_pass: String,
    new_pass_again: String,

    // unlocked
    panel: Panel,
    filter: String,
    tag_filter: Option<String>,
    sort: Sort,
    rows: Vec<Row>,
    open_entry: Option<i64>,
    reveal_password: bool,
    reveal_notes: bool,
    focus_search: bool,
    draft: Draft,
    import_path: String,
    import_pass: String,
    csv_path: String,
    export_path: String,
    keyfile_path: String,
    trash_rows: Vec<(i64, String)>,
    history_rows: Vec<(i64, String, Option<String>)>,
    change_old: String,
    change_new: String,
    change_again: String,

    // shared
    status: String,
    level: Level,
    session: Option<KeySession>,
    db: Option<VaultDatabase>,
    vault_path: Option<PathBuf>,
    clipboard_set_at: Option<Instant>,
    last_input: Instant,
}

impl Default for App {
    fn default() -> Self {
        Self {
            vaults: discover_vaults(),
            selected: None,
            manual_path: String::new(),
            passphrase: String::new(),
            creating: false,
            new_path: free_vault_path(),
            new_pass: String::new(),
            new_pass_again: String::new(),
            panel: Panel::List,
            filter: String::new(),
            tag_filter: None,
            sort: Sort::Name,
            rows: Vec::new(),
            open_entry: None,
            reveal_password: false,
            reveal_notes: false,
            focus_search: false,
            draft: Draft::default(),
            import_path: String::new(),
            import_pass: String::new(),
            csv_path: String::new(),
            export_path: home().join("valu-export.csv").display().to_string(),
            keyfile_path: String::new(),
            trash_rows: Vec::new(),
            history_rows: Vec::new(),
            change_old: String::new(),
            change_new: String::new(),
            change_again: String::new(),
            status: String::new(),
            level: Level::None,
            session: None,
            db: None,
            vault_path: None,
            clipboard_set_at: None,
            last_input: Instant::now(),
        }
    }
}

/// A vault filename that does not exist yet.
///
/// Defaulting to ~/vault.db means the second vault a user creates is refused
/// with "a file already exists there", which reads as a dead end rather than as
/// a suggestion to rename.
fn free_vault_path() -> String {
    let base = home();
    let first = base.join("vault.db");
    if !first.exists() {
        return first.display().to_string();
    }
    for n in 2..100 {
        let candidate = base.join(format!("vault-{n}.db"));
        if !candidate.exists() {
            return candidate.display().to_string();
        }
    }
    first.display().to_string()
}

/// Seconds since the epoch as a plain date. No chrono: one format string does
/// not justify a dependency in a security-sensitive crate.
fn format_when(unix: i64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    // Civil-from-days, Howard Hinnant's algorithm — exact, no lookup tables.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
}

/// Find vaults so the user never has to type a path. A vault is a SQLite file
/// with an `argon_salt` row in `meta` — the row unlocking needs — so this finds
/// real vaults rather than every .db lying around.
fn discover_vaults() -> Vec<PathBuf> {
    let h = home();
    let mut roots = vec![h.clone()];
    for sub in ["Documents", "Desktop", ".local/share/valu"] {
        roots.push(h.join(sub));
    }
    let mut found = Vec::new();
    for root in roots {
        let Ok(dir) = std::fs::read_dir(&root) else { continue };
        for item in dir.flatten() {
            let path = item.path();
            if path.is_file()
                && path.extension().map(|e| e == "db" || e == "vault").unwrap_or(false)
                && looks_like_vault(&path)
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn looks_like_vault(path: &Path) -> bool {
    let Ok(conn) = rusqlite::Connection::open(path) else { return false };
    conn.query_row("SELECT 1 FROM meta WHERE key='argon_salt'", [], |_| Ok(()))
        .is_ok()
}

fn read_salt(path: &Path) -> Result<Vec<u8>, String> {
    let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
    conn.query_row("SELECT value FROM meta WHERE key='argon_salt'", [], |r| r.get(0))
        .map_err(|_| "not a VALU vault, or it has no salt".to_string())
}

/// 20 characters from a 69-symbol alphabet ≈ 122 bits.
///
/// Rejection sampling, not `byte % len`: the remainder is biased toward the
/// first `256 % len` symbols, which quietly costs entropy exactly where it
/// matters. Visually ambiguous characters (l, I, 1, O, 0) are left out — a
/// password nobody can read back is one they replace with a worse one.
fn generate_password() -> String {
    const ALPHABET: &[u8] =
        b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";
    let n = ALPHABET.len();
    let limit = 256 - (256 % n);
    let mut out = String::with_capacity(20);
    let mut buf = [0u8; 64];
    while out.len() < 20 {
        OsRng.fill_bytes(&mut buf);
        for b in buf.iter() {
            if (*b as usize) < limit {
                out.push(ALPHABET[*b as usize % n] as char);
                if out.len() == 20 {
                    break;
                }
            }
        }
    }
    out
}

/// Rough entropy in bits: length times log2 of the character classes present.
///
/// Not a dictionary check — "Password1!" scores respectably here and is
/// terrible — so the label always says "estimate".
fn strength(password: &str) -> (f32, &'static str, egui::Color32) {
    if password.is_empty() {
        return (0.0, "", MUTED);
    }
    let mut classes = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) { classes += 26; }
    if password.chars().any(|c| c.is_ascii_uppercase()) { classes += 26; }
    if password.chars().any(|c| c.is_ascii_digit()) { classes += 10; }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) { classes += 33; }
    let bits = password.chars().count() as f32 * (classes.max(2) as f32).log2();
    match bits as u32 {
        0..=45 => (bits, "weak", DANGER),
        46..=69 => (bits, "fair", WARN),
        70..=99 => (bits, "good", OK),
        _ => (bits, "strong", OK),
    }
}

impl App {
    fn set(&mut self, msg: impl Into<String>, level: Level) {
        self.status = msg.into();
        self.level = level;
    }

    fn target_path(&self) -> Option<PathBuf> {
        if !self.manual_path.trim().is_empty() {
            return Some(PathBuf::from(self.manual_path.trim()));
        }
        self.selected.clone()
    }

    fn reload(&mut self) {
        let (Some(db), Some(session)) = (self.db.as_ref(), self.session.as_ref()) else { return };
        match db.list_entries(session) {
            Ok(list) => {
                self.rows = list
                    .into_iter()
                    .map(|(id, e)| Row {
                        id,
                        favorite: e.favorite,
                        updated_at: e.updated_at,
                        name: e.name,
                        username: e.username,
                        uri: e.uri,
                        totp: e.totp_secret.map(|s| s.expose().clone()),
                        tags: e.tags,
                        notes: e.notes.map(|n| n.expose().clone()),
                        password: e.password.expose().clone(),
                    })
                    .collect();
            }
            Err(e) => self.set(e.to_string(), Level::Bad),
        }
    }

    fn create_vault(&mut self) {
        let path = self.new_path.trim().to_string();
        if path.is_empty() {
            return self.set("Choose where to put the vault", Level::Bad);
        }
        if Path::new(&path).exists() {
            return self.set("A file already exists there", Level::Bad);
        }
        if self.new_pass.chars().count() < 8 {
            return self.set("Passphrase must be at least 8 characters", Level::Bad);
        }
        if self.new_pass != self.new_pass_again {
            return self.set("The two passphrases do not match", Level::Bad);
        }
        let pass = self.new_pass.clone();
        let keyfile = self.keyfile_path.trim().to_string();
        self.new_pass.clear();
        self.new_pass_again.clear();

        let built = (|| -> Result<(), String> {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let master = if keyfile.is_empty() {
                MasterKey::create_passphrase(&pass, &salt).map_err(|e| e.to_string())?
            } else {
                let bytes = std::fs::read(&keyfile)
                    .map_err(|_| "cannot read that key file".to_string())?;
                MasterKey::create_with_keyfile(&pass, &salt, &bytes).map_err(|e| e.to_string())?
            };
            let session = KeySession::new(master);
            let db = VaultDatabase::open(&path, &session).map_err(|e| e.to_string())?;
            db.conn()
                .execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('argon_salt', ?1)",
                    rusqlite::params![salt.to_vec()],
                )
                .map_err(|e| e.to_string())?;
            drop(db);
            session.close();
            Ok(())
        })();

        match built {
            Ok(()) => {
                self.vaults = discover_vaults();
                self.selected = Some(PathBuf::from(&path));
                self.manual_path.clear();
                self.creating = false;
                self.set("Vault created — now unlock it", Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn unlock(&mut self) {
        let Some(path) = self.target_path() else {
            return self.set("Choose a vault first", Level::Bad);
        };
        let pass = self.passphrase.clone();
        let keyfile = self.keyfile_path.trim().to_string();
        // Cleared the moment it is used. This resets the String's length only —
        // the bytes stay in egui's allocation until reused, which is the caveat
        // in the header comment.
        self.passphrase.clear();

        let opened = (|| -> Result<(VaultDatabase, KeySession), String> {
            // Separate causes get separate messages. Reporting "wrong
            // passphrase" for a missing file sends people to retype a
            // passphrase that was never the problem.
            if !path.exists() {
                return Err(format!("no file at {}", path.display()));
            }
            let salt = read_salt(&path)?;
            let master = if keyfile.is_empty() {
                MasterKey::unlock_passphrase(&pass, &salt).map_err(|e| e.to_string())?
            } else {
                let bytes = std::fs::read(&keyfile)
                    .map_err(|_| "cannot read that key file".to_string())?;
                MasterKey::create_with_keyfile(&pass, &salt, &bytes).map_err(|e| e.to_string())?
            };
            let session = KeySession::new(master);
            let db = match VaultDatabase::open(path.to_str().unwrap_or_default(), &session) {
                Ok(d) => d,
                Err(e) => {
                    session.close();
                    return Err(e.to_string());
                }
            };
            // Decrypt one row to tell a wrong passphrase from an empty vault.
            // Without this, a wrong passphrase opens a window showing nothing,
            // which reads as data loss.
            if let Ok(id) =
                db.conn().query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get::<_, i64>(0))
            {
                if db.get_entry(&session, id).is_err() {
                    session.close();
                    return Err("wrong passphrase".into());
                }
            }
            Ok((db, session))
        })();

        match opened {
            Ok((db, session)) => {
                self.db = Some(db);
                self.session = Some(session);
                self.vault_path = Some(path);
                self.reload();
                let n = self.rows.len();
                self.panel = Panel::List;
                self.open_entry = None;
                self.filter.clear();
                self.last_input = Instant::now();
                self.set(format!("Unlocked — {n} entries"), Level::Ok);
            }
            Err(why) => {
                self.db = None;
                self.session = None;
                self.rows.clear();
                self.set(
                    if why.contains("passphrase") { "Wrong passphrase".into() } else { why },
                    Level::Bad,
                );
            }
        }
    }

    fn lock(&mut self, reason: &str) {
        if let Some(session) = self.session.take() {
            session.close(); // zeroizes every derived key
        }
        self.db = None;
        self.vault_path = None;
        self.rows.clear();
        self.open_entry = None;
        self.reveal_password = false;
        self.reveal_notes = false;
        self.draft = Draft::default();
        self.filter.clear();
        self.import_path.clear();
        self.import_pass.clear();
        self.change_old.clear();
        self.change_new.clear();
        self.change_again.clear();
        self.panel = Panel::List;
        self.set(reason, Level::None);
    }

    fn save_draft(&mut self) {
        let d = self.draft.clone();
        if d.name.trim().is_empty() {
            return self.set("Give the entry a name", Level::Bad);
        }
        if d.password.is_empty() {
            return self.set("Give the entry a password", Level::Bad);
        }
        // Validate the TOTP secret now rather than letting a typo surface as a
        // wrong code weeks later.
        let totp_clean = if d.totp.trim().is_empty() {
            None
        } else {
            match totp::normalize_secret(&d.totp) {
                Some(s) => Some(s),
                None => return self.set("That is not a valid two-factor secret", Level::Bad),
            }
        };
        let uri = if d.uri.trim().is_empty() { None } else { Some(d.uri.trim().to_string()) };

        let done = match (self.db.as_ref(), self.session.as_ref()) {
            (Some(db), Some(session)) => match d.id {
                Some(id) => db
                    .update_entry_full(session, id, d.name.trim(), d.username.trim(),
                                       &d.password, uri.as_deref(), totp_clean.as_deref(),
                                       Some(d.notes.trim()), Some(d.tags.trim()))
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                None => db
                    .insert_entry_full(session, d.name.trim(), d.username.trim(),
                                       &d.password, uri.as_deref(), totp_clean.as_deref(),
                                       Some(d.notes.trim()), Some(d.tags.trim()))
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            },
            _ => Err("vault is locked".into()),
        };

        match done {
            Ok(()) => {
                let verb = if d.id.is_some() { "Updated" } else { "Added" };
                let name = d.name.trim().to_string();
                self.draft = Draft::default();
                self.reload();
                self.panel = Panel::List;
                self.set(format!("{verb} {name}"), Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn delete(&mut self, id: i64, name: &str) {
        // Trash, not destroy. Deleting the wrong entry is the mistake people
        // actually make, and a vault with no undo turns a slip into data loss.
        // `purge_entry`, from the trash view, is the irreversible one.
        let done = match self.db.as_ref() {
            Some(db) => db.trash_entry(id).map(|_| ()).map_err(|e| e.to_string()),
            None => Err("vault is locked".into()),
        };
        match done {
            Ok(()) => {
                self.open_entry = None;
                self.reload();
                self.panel = Panel::List;
                self.set(format!("{name} moved to trash"), Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn import_kdbx(&mut self) {
        let path = self.import_path.trim().to_string();
        if path.is_empty() {
            return self.set("Give the path to a .kdbx file", Level::Bad);
        }
        let pass = self.import_pass.clone();
        self.import_pass.clear();
        let (Some(db), Some(session)) = (self.db.as_ref(), self.session.as_ref()) else {
            return self.set("vault is locked", Level::Bad);
        };

        let result = (|| -> Result<(usize, usize), String> {
            let mut file = std::fs::File::open(&path).map_err(|_| "cannot open that file")?;
            let key = keepass::DatabaseKey::new().with_password(&pass);
            let kdbx = keepass::Database::open(&mut file, key)
                .map_err(|_| "wrong password, or not a KDBX 4 file")?;
            let (mut ok, mut skipped) = (0usize, 0usize);
            for entry in kdbx.iter_all_entries() {
                match (entry.get_title(), entry.get_password()) {
                    (Some(title), Some(password)) => {
                        let user = entry.get_username().unwrap_or("");
                        let url = entry.get("URL").filter(|u| !u.is_empty());
                        // KeePass stores TOTP under "otp" as an otpauth URI;
                        // normalize_secret handles both that and a bare secret.
                        let otp = entry.get("otp").and_then(totp::normalize_secret);
                        db.insert_entry(session, title, user, password, url, otp.as_deref())
                            .map_err(|e| e.to_string())?;
                        ok += 1;
                    }
                    _ => skipped += 1,
                }
            }
            Ok((ok, skipped))
        })();

        match result {
            Ok((ok, skipped)) => {
                self.import_path.clear();
                self.reload();
                self.panel = Panel::List;
                self.set(format!("Imported {ok} entries, skipped {skipped}"), Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    /// Re-key the vault: derive a new master and rewrite every entry under it.
    ///
    /// Each row goes through `update_entry`, which rotates its nonces, so the
    /// old ciphertext is replaced rather than re-encrypted in place. The salt is
    /// written LAST and only after every row succeeded: until that line the old
    /// passphrase still opens the vault, so an interrupted re-key is survivable.
    fn change_passphrase(&mut self) {
        if self.change_new.chars().count() < 8 {
            return self.set("New passphrase must be at least 8 characters", Level::Bad);
        }
        if self.change_new != self.change_again {
            return self.set("The two new passphrases do not match", Level::Bad);
        }
        let Some(path) = self.vault_path.clone() else {
            return self.set("vault is locked", Level::Bad);
        };
        let (old, new) = (self.change_old.clone(), self.change_new.clone());
        self.change_old.clear();
        self.change_new.clear();
        self.change_again.clear();

        let result = (|| -> Result<usize, String> {
            let salt = read_salt(&path)?;
            let old_master = MasterKey::unlock_passphrase(&old, &salt).map_err(|e| e.to_string())?;
            let old_session = KeySession::new(old_master);
            let db = VaultDatabase::open(path.to_str().unwrap_or_default(), &old_session)
                .map_err(|e| e.to_string())?;
            let entries = db.list_entries(&old_session).map_err(|_| "wrong current passphrase")?;

            let mut new_salt = [0u8; 16];
            OsRng.fill_bytes(&mut new_salt);
            let new_master =
                MasterKey::create_passphrase(&new, &new_salt).map_err(|e| e.to_string())?;
            let new_session = KeySession::new(new_master);

            let count = entries.len();
            for (id, e) in entries {
                db.update_entry(
                    &new_session,
                    id,
                    &e.name,
                    &e.username,
                    e.password.expose(),
                    e.uri.as_deref(),
                    e.totp_secret.as_ref().map(|s| s.expose().as_str()),
                )
                .map_err(|err| err.to_string())?;
            }

            db.conn()
                .execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('argon_salt', ?1)",
                    rusqlite::params![new_salt.to_vec()],
                )
                .map_err(|e| e.to_string())?;

            drop(db);
            old_session.close();
            new_session.close();
            Ok(count)
        })();

        match result {
            Ok(n) => self.lock(&format!("Passphrase changed, {n} entries re-keyed — unlock again")),
            Err(why) => self.set(
                if why.contains("passphrase") { "Current passphrase is wrong".into() } else { why },
                Level::Bad,
            ),
        }
    }
}

// ── Styling ─────────────────────────────────────────────────────────────────

fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = BG;
    v.extreme_bg_color = egui::Color32::from_rgb(0x0d, 0x0f, 0x13);
    v.override_text_color = Some(TEXT);
    v.selection.bg_fill = ACCENT.linear_multiply(0.35);
    v.hyperlink_color = ACCENT;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, LINE);

    let r = egui::Rounding::same(9.0);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
    ] {
        w.rounding = r;
    }
    v.widgets.inactive.bg_fill = SURFACE_HI;
    v.widgets.inactive.weak_bg_fill = SURFACE_HI;
    v.widgets.hovered.bg_fill = ACCENT.linear_multiply(0.5);
    v.widgets.hovered.weak_bg_fill = ACCENT.linear_multiply(0.5);
    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.weak_bg_fill = ACCENT;
    ctx.set_visuals(v);

    let mut s = (*ctx.style()).clone();
    s.spacing.item_spacing = egui::vec2(10.0, 9.0);
    s.spacing.button_padding = egui::vec2(13.0, 7.0);
    s.spacing.interact_size.y = 30.0;
    ctx.set_style(s);
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(SURFACE)
        .rounding(egui::Rounding::same(13.0))
        .inner_margin(egui::Margin::same(16.0))
        .show(ui, add)
        .inner
}

fn label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(12.0).color(MUTED));
}

fn field(ui: &mut egui::Ui, value: &mut String, hint: &str, secret: bool) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .password(secret)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(egui::Margin::symmetric(10.0, 7.0)),
    )
}

fn primary(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add_sized(
        [130.0, 34.0],
        egui::Button::new(egui::RichText::new(text).size(14.0).strong().color(BG)).fill(ACCENT),
    )
    .clicked()
}

fn meter(ui: &mut egui::Ui, password: &str) {
    let (bits, word, color) = strength(password);
    if word.is_empty() {
        return;
    }
    ui.label(
        egui::RichText::new(format!("{word} — about {bits:.0} bits (estimate)"))
            .size(11.0)
            .color(color),
    );
}

// ── UI ──────────────────────────────────────────────────────────────────────

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // A TOTP code counts down, so repaint even when nothing is clicked.
        ctx.request_repaint_after(Duration::from_millis(500));

        if ctx.input(|i| !i.events.is_empty() || i.pointer.velocity() != egui::Vec2::ZERO) {
            self.last_input = Instant::now();
        }

        // Clipboard hygiene: overwrite rather than clear. An empty clipboard is
        // itself a signal, and some managers ignore a clear.
        if let Some(at) = self.clipboard_set_at {
            if at.elapsed() >= CLIPBOARD_TTL {
                ctx.output_mut(|o| o.copied_text = " ".into());
                self.clipboard_set_at = None;
                self.set("Clipboard cleared", Level::None);
            }
        }

        if self.db.is_some() && self.last_input.elapsed() >= IDLE_LOCK {
            self.lock("Locked after 5 minutes idle");
        }

        // Lock when the window stops being visible. Minimising is how people
        // "put it away", and an unlocked vault sitting in the background is the
        // state an attacker at the keyboard hopes to find.
        if self.db.is_some() && ctx.input(|i| i.viewport().minimized.unwrap_or(false)) {
            self.lock("Locked on minimise");
        }

        // Keyboard first: a password manager is used dozens of times a day, and
        // reaching for the mouse each time is what makes people stop using one.
        if self.db.is_some() {
            let (lock, copy, close, find) = ctx.input(|i| {
                (
                    i.key_pressed(egui::Key::L) && i.modifiers.ctrl,
                    i.key_pressed(egui::Key::C) && i.modifiers.ctrl,
                    i.key_pressed(egui::Key::Escape),
                    i.key_pressed(egui::Key::Slash) && !i.modifiers.ctrl,
                )
            });
            if lock {
                self.lock("Locked");
            } else if close {
                if self.panel != Panel::List {
                    self.panel = Panel::List;
                } else if self.open_entry.is_some() {
                    self.open_entry = None;
                }
            } else if copy {
                if let Some(row) = self
                    .open_entry
                    .and_then(|id| self.rows.iter().find(|r| r.id == id).cloned())
                {
                    ctx.output_mut(|o| o.copied_text = row.password.clone());
                    self.clipboard_set_at = Some(Instant::now());
                    self.set("Password copied — clipboard clears in 20s", Level::None);
                }
            } else if find {
                self.focus_search = true;
            }
        }

        // A locked vault, a modal form, and the browsing view are three
        // different shapes. Only the last one earns three panes; forcing the
        // others into it would put an empty sidebar next to a password prompt.
        let browsing = self.db.is_some() && self.panel == Panel::List;

        egui::TopBottomPanel::top("head")
            .frame(egui::Frame::none().fill(BG).inner_margin(egui::Margin::symmetric(20.0, 14.0)))
            .show(ctx, |ui| self.header(ui));

        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::none().fill(SURFACE).inner_margin(egui::Margin::symmetric(20.0, 8.0)))
            .show(ctx, |ui| self.status_bar(ui));

        if browsing {
            egui::SidePanel::left("nav")
                .resizable(true)
                .default_width(210.0)
                .frame(egui::Frame::none().fill(BG).inner_margin(egui::Margin::symmetric(16.0, 14.0)))
                .show(ctx, |ui| self.sidebar(ui));

            // The detail pane holds a copy of the selected row rather than a
            // borrow, because drawing it mutates self (copy timestamps, panel
            // switches) and the borrow checker is right to refuse both at once.
            if let Some(row) = self
                .open_entry
                .and_then(|id| self.rows.iter().find(|r| r.id == id).cloned())
            {
                egui::SidePanel::right("details")
                    .resizable(true)
                    .default_width(330.0)
                    .frame(
                        egui::Frame::none()
                            .fill(BG)
                            .inner_margin(egui::Margin::symmetric(16.0, 14.0)),
                    )
                    .show(ctx, |ui| {
                        egui::ScrollArea::vertical().show(ui, |ui| self.detail(ui, &row));
                    });
            }
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG).inner_margin(egui::Margin::symmetric(16.0, 14.0)))
            .show(ctx, |ui| {
                if self.db.is_some() {
                    self.unlocked(ui);
                } else if self.creating {
                    self.create_view(ui);
                } else {
                    self.locked(ui);
                }
            });
    }
}

impl App {
    /// Bottom bar: where the vault is, how it scores, and how long the session
    /// has left.
    ///
    /// The countdown is shown rather than sprung. An auto-lock that fires with
    /// no warning reads as a crash, and people respond by disabling it — which
    /// is the opposite of what it is for.
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if !self.status.is_empty() {
                let color = match self.level {
                    Level::Ok => OK,
                    Level::Bad => DANGER,
                    Level::None => MUTED,
                };
                ui.label(egui::RichText::new(&self.status).size(12.0).color(color));
            } else if let Some(p) = &self.vault_path {
                ui.label(egui::RichText::new(p.display().to_string()).size(11.0).color(MUTED));
            }

            if self.db.is_some() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let left = IDLE_LOCK.saturating_sub(self.last_input.elapsed()).as_secs();
                    let (m, sec) = (left / 60, left % 60);
                    // Warn while there is still time to do something about it.
                    let color = if left <= 60 { WARN } else { MUTED };
                    ui.label(
                        egui::RichText::new(format!("locks in {m}:{sec:02}"))
                            .size(12.0)
                            .color(color),
                    );
                    ui.add_space(12.0);
                    let report = self.security_report();
                    let sc = report.score;
                    let color = if sc >= 85 { OK } else if sc >= 60 { WARN } else { DANGER };
                    ui.label(
                        egui::RichText::new(format!("health {sc}"))
                            .size(12.0)
                            .strong()
                            .color(color),
                    );
                });
            }
        });
    }

    fn security_report(&self) -> valu::audit::Report {
        let inputs: Vec<valu::audit::AuditInput> = self
            .rows
            .iter()
            .map(|r| valu::audit::AuditInput {
                id: r.id,
                name: &r.name,
                password: &r.password,
                has_totp: r.totp.is_some(),
                has_uri: r.uri.is_some(),
                updated_at: r.updated_at,
                expires_at: None,
            })
            .collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        valu::audit::audit(&inputs, now)
    }

    /// Left pane: tag filters with counts, and the health summary.
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        label(ui, "VAULT");
        ui.add_space(4.0);

        let total = self.rows.len();
        let all_selected = self.tag_filter.is_none();
        if ui
            .selectable_label(
                all_selected,
                egui::RichText::new(format!("  All entries   {total}"))
                    .color(if all_selected { ACCENT } else { TEXT }),
            )
            .clicked()
        {
            self.tag_filter = None;
        }

        let favs = self.rows.iter().filter(|r| r.favorite).count();
        if favs > 0 {
            let on = self.tag_filter.as_deref() == Some("\u{2605}");
            if ui
                .selectable_label(
                    on,
                    egui::RichText::new(format!("  Favourites   {favs}"))
                        .color(if on { ACCENT } else { TEXT }),
                )
                .clicked()
            {
                self.tag_filter = if on { None } else { Some("\u{2605}".into()) };
            }
        }

        // Tags, with how many entries carry each. A tag list without counts
        // makes you click every one to find out where anything is.
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for r in &self.rows {
            for t in r.tags.as_deref().unwrap_or("").split(',') {
                let t = t.trim();
                if !t.is_empty() {
                    *counts.entry(t.to_string()).or_insert(0) += 1;
                }
            }
        }
        if !counts.is_empty() {
            ui.add_space(12.0);
            label(ui, "TAGS");
            ui.add_space(4.0);
            egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                for (tag, n) in counts {
                    let on = self.tag_filter.as_deref() == Some(tag.as_str());
                    if ui
                        .selectable_label(
                            on,
                            egui::RichText::new(format!("  {tag}   {n}"))
                                .color(if on { ACCENT } else { TEXT }),
                        )
                        .clicked()
                    {
                        self.tag_filter = if on { None } else { Some(tag.clone()) };
                    }
                }
            });
        }

        ui.add_space(14.0);
        label(ui, "HEALTH");
        ui.add_space(4.0);
        let report = self.security_report();
        let sc = report.score;
        let color = if sc >= 85 { OK } else if sc >= 60 { WARN } else { DANGER };
        ui.label(egui::RichText::new(format!("{sc}/100")).size(22.0).strong().color(color));
        ui.add(
            egui::ProgressBar::new(sc as f32 / 100.0)
                .desired_width(150.0)
                .fill(color),
        );
        ui.add_space(6.0);
        for (n, what, c) in [
            (report.reused, "reused", DANGER),
            (report.weak, "weak", WARN),
            (report.stale, "over a year old", MUTED),
        ] {
            if n > 0 {
                ui.label(egui::RichText::new(format!("{n} {what}")).size(11.0).color(c));
            }
        }
        if report.findings.is_empty() && total > 0 {
            ui.label(egui::RichText::new("nothing to fix").size(11.0).color(OK));
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("VALU").size(26.0).strong().color(TEXT));
            ui.add_space(2.0);
            ui.label(egui::RichText::new("password vault").size(12.0).color(MUTED));
            if self.db.is_some() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock").clicked() {
                        self.lock("Locked");
                    }
                    if ui.button("Passphrase…").clicked() {
                        self.panel = Panel::ChangePass;
                    }
                });
            }
        });
        ui.add_space(2.0);
    }

    fn locked(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            label(ui, "YOUR VAULTS");
            ui.add_space(4.0);
            if self.vaults.is_empty() {
                ui.label(egui::RichText::new("None found in your home folder.").color(MUTED));
            } else {
                let vaults = self.vaults.clone();
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    for path in vaults {
                        let name = path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.display().to_string());
                        let chosen = self.selected.as_ref() == Some(&path);
                        let t = if chosen {
                            egui::RichText::new(format!("  {name}")).color(ACCENT).strong()
                        } else {
                            egui::RichText::new(format!("  {name}")).color(TEXT)
                        };
                        if ui.selectable_label(chosen, t).clicked() {
                            self.selected = Some(path.clone());
                            self.manual_path.clear();
                        }
                    }
                });
            }

            ui.add_space(10.0);
            label(ui, "OR A PATH");
            field(ui, &mut self.manual_path, "/home/you/vault.db", false);

            ui.add_space(10.0);
            label(ui, "PASSPHRASE");
            let p = field(ui, &mut self.passphrase, "your passphrase", true);
            let entered = p.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            ui.add_space(10.0);
            label(ui, "KEY FILE (optional second factor)");
            field(ui, &mut self.keyfile_path, "leave empty if you do not use one", false);
            ui.label(
                egui::RichText::new(
                    "Something you know plus something you have. Lose the file and the \
                     vault is gone — that is what makes it a second factor.",
                )
                .size(11.0)
                .color(MUTED),
            );

            ui.add_space(8.0);
            match self.target_path() {
                Some(p) => ui.label(
                    egui::RichText::new(format!("Will open: {}", p.display()))
                        .size(11.0)
                        .color(MUTED),
                ),
                None => ui.label(
                    egui::RichText::new("Pick a vault above, or type a path")
                        .size(11.0)
                        .color(WARN),
                ),
            };

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if primary(ui, "Unlock") || entered {
                    self.unlock();
                }
                if ui.button("New vault…").clicked() {
                    self.creating = true;
                    self.set("", Level::None);
                }
            });
        });
    }

    fn create_view(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(egui::RichText::new("New vault").size(17.0).strong());
            ui.add_space(8.0);
            label(ui, "FILE");
            field(ui, &mut self.new_path, "/home/you/vault.db", false);
            ui.add_space(8.0);
            label(ui, "PASSPHRASE");
            let mut p = self.new_pass.clone();
            field(ui, &mut p, "at least 8 characters", true);
            self.new_pass = p;
            meter(ui, &self.new_pass.clone());
            ui.add_space(8.0);
            label(ui, "REPEAT");
            field(ui, &mut self.new_pass_again, "the same again", true);
            ui.add_space(8.0);
            label(ui, "KEY FILE (optional second factor)");
            field(ui, &mut self.keyfile_path, "any file you will still have next year", false);
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "There is no recovery. Lose this passphrase and the vault is gone.",
                )
                .size(12.0)
                .color(WARN),
            );
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary(ui, "Create") {
                    self.create_vault();
                }
                if ui.button("Cancel").clicked() {
                    self.creating = false;
                    self.new_pass.clear();
                    self.new_pass_again.clear();
                    self.set("", Level::None);
                }
            });
        });
    }

    fn unlocked(&mut self, ui: &mut egui::Ui) {
        match self.panel.clone() {
            Panel::Editor => return self.editor(ui),
            Panel::Import => return self.import_view(ui),
            Panel::ChangePass => return self.change_view(ui),
            Panel::Confirm(id, name) => return self.confirm(ui, id, &name),
            Panel::ConfirmPurge(id, name) => return self.confirm_purge(ui, id, &name),
            Panel::ImportCsv => return self.import_csv_view(ui),
            Panel::Export => return self.export_view(ui),
            Panel::History(id) => return self.history_view(ui, id),
            Panel::Trash => return self.trash_view(ui),
            Panel::List => {}
        }

        ui.horizontal(|ui| {
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Search…   ( / )")
                    .desired_width(200.0)
                    .margin(egui::Margin::symmetric(10.0, 7.0)),
            );
            if self.focus_search {
                search.request_focus();
                self.focus_search = false;
            }
            if ui.button("+ Add").clicked() {
                self.draft = Draft::default();
                self.panel = Panel::Editor;
                self.open_entry = None;
            }
            ui.menu_button("Import ▾", |ui| {
                if ui.button("From a CSV export…").clicked() {
                    self.panel = Panel::ImportCsv;
                    ui.close_menu();
                }
                if ui.button("From a KeePass .kdbx…").clicked() {
                    self.panel = Panel::Import;
                    ui.close_menu();
                }
            });
            ui.menu_button("More ▾", |ui| {
                if ui.button("Export & backup…").clicked() {
                    self.panel = Panel::Export;
                    ui.close_menu();
                }
                if ui.button("Trash…").clicked() {
                    self.load_trash();
                    self.panel = Panel::Trash;
                    ui.close_menu();
                }
                if ui.button("Change passphrase…").clicked() {
                    self.panel = Panel::ChangePass;
                    ui.close_menu();
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let t = match self.sort {
                    Sort::Name => "A–Z",
                    Sort::Recent => "Newest",
                };
                if ui.button(t).clicked() {
                    self.sort = match self.sort {
                        Sort::Name => Sort::Recent,
                        Sort::Recent => Sort::Name,
                    };
                }
            });
        });
        ui.add_space(10.0);

        let needle = self.filter.to_lowercase();
        let mut shown: Vec<Row> = self
            .rows
            .iter()
            .filter(|r| {
                // Search covers every field the user can see, so "the gmail
                // one" is findable by name, login, address or label.
                needle.is_empty()
                    || r.name.to_lowercase().contains(&needle)
                    || r.username.to_lowercase().contains(&needle)
                    || r.uri.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                    || r.tags.as_deref().unwrap_or("").to_lowercase().contains(&needle)
            })
            .filter(|r| match self.tag_filter.as_deref() {
                None => true,
                Some("\u{2605}") => r.favorite,
                Some(tag) => r
                    .tags
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .any(|t| t.trim() == tag),
            })
            .cloned()
            .collect();
        match self.sort {
            Sort::Name => shown.sort_by_key(|r| r.name.to_lowercase()),
            Sort::Recent => shown.sort_by(|a, b| b.id.cmp(&a.id)),
        }

        let total = self.rows.len();
        card(ui, |ui| {
            if total == 0 {
                ui.label(
                    egui::RichText::new("This vault is empty. Add an entry to begin.").color(MUTED),
                );
                return;
            }
            if shown.is_empty() {
                ui.label(egui::RichText::new("Nothing matches that search").color(MUTED));
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                let last = shown.len().saturating_sub(1);
                for (i, row) in shown.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&row.name).size(14.0).strong());
                            let mut sub = row.username.clone();
                            if row.totp.is_some() {
                                if !sub.is_empty() {
                                    sub.push_str("   ");
                                }
                                sub.push_str("• 2FA");
                            }
                            if !sub.trim().is_empty() {
                                ui.label(egui::RichText::new(sub).size(11.0).color(MUTED));
                            }
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Open").clicked() {
                                self.open_entry = Some(row.id);
                                self.reveal_password = false;
                                self.reveal_notes = false;
                            }
                        });
                    });
                    if i != last {
                        ui.add_space(2.0);
                        ui.separator();
                    }
                }
            });
        });
    }

    fn detail(&mut self, ui: &mut egui::Ui, row: &Row) {
        let mut copy_now: Option<String> = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&row.name).size(18.0).strong().color(ACCENT));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        self.open_entry = None;
                    }
                    if ui.button(egui::RichText::new("Delete").color(DANGER)).clicked() {
                        self.panel = Panel::Confirm(row.id, row.name.clone());
                    }
                    if ui.button("History").clicked() {
                        self.load_history(row.id);
                        self.panel = Panel::History(row.id);
                    }
                    if ui.button("Edit").clicked() {
                        self.draft = Draft {
                            id: Some(row.id),
                            name: row.name.clone(),
                            username: row.username.clone(),
                            password: row.password.clone(),
                            uri: row.uri.clone().unwrap_or_default(),
                            totp: row.totp.clone().unwrap_or_default(),
                            tags: row.tags.clone().unwrap_or_default(),
                            notes: row.notes.clone().unwrap_or_default(),
                            show_password: false,
                        };
                        self.panel = Panel::Editor;
                    }
                });
            });
            ui.add_space(8.0);

            if !row.username.is_empty() {
                label(ui, "USERNAME");
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&row.username).size(14.0).monospace());
                    if ui.small_button("Copy").clicked() {
                        copy_now = Some(row.username.clone());
                    }
                });
                ui.add_space(6.0);
            }

            label(ui, "PASSWORD");
            ui.horizontal(|ui| {
                let shown = if self.reveal_password {
                    row.password.clone()
                } else {
                    "•".repeat(row.password.chars().count().min(24))
                };
                ui.label(egui::RichText::new(shown).size(14.0).monospace());
                if ui
                    .small_button(if self.reveal_password { "Hide" } else { "Show" })
                    .clicked()
                {
                    self.reveal_password = !self.reveal_password;
                    if self.reveal_password {
                        if let Some(db) = self.db.as_ref() {
                            db.log_access(Some(row.id), "reveal");
                        }
                    }
                }
                if ui.small_button("Copy").clicked() {
                    copy_now = Some(row.password.clone());
                }
            });
            meter(ui, &row.password);

            if let Some(uri) = &row.uri {
                ui.add_space(6.0);
                label(ui, "URL");
                ui.horizontal(|ui| {
                    ui.hyperlink_to(egui::RichText::new(uri).size(13.0), uri);
                    if ui.small_button("Copy").clicked() {
                        copy_now = Some(uri.clone());
                    }
                });
            }

            if let Some(tags) = row.tags.as_deref().filter(|t| !t.trim().is_empty()) {
                ui.add_space(6.0);
                label(ui, "TAGS");
                ui.horizontal_wrapped(|ui| {
                    for t in tags.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                        egui::Frame::none()
                            .fill(SURFACE_HI)
                            .rounding(egui::Rounding::same(10.0))
                            .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(t).size(11.0).color(ACCENT));
                            });
                    }
                });
            }

            if let Some(notes) = row.notes.as_deref().filter(|n| !n.trim().is_empty()) {
                ui.add_space(6.0);
                label(ui, "NOTES");
                // Notes routinely hold recovery codes, so they are hidden until
                // asked for, exactly like the password.
                if self.reveal_notes {
                    ui.label(egui::RichText::new(notes).size(13.0));
                    if ui.small_button("Hide notes").clicked() {
                        self.reveal_notes = false;
                    }
                } else if ui.small_button("Show notes").clicked() {
                    self.reveal_notes = true;
                }
            }

            if let Some(secret) = &row.totp {
                ui.add_space(8.0);
                label(ui, "TWO-FACTOR CODE");
                match totp::code_now(secret) {
                    Ok(code) => {
                        let left = totp::seconds_remaining();
                        let hot = left <= 5;
                        // Two groups of three: easier to read and to type.
                        let pretty = format!("{} {}", &code[..3], &code[3..]);
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(pretty)
                                    .size(24.0)
                                    .monospace()
                                    .strong()
                                    .color(if hot { WARN } else { OK }),
                            );
                            if ui.small_button("Copy").clicked() {
                                copy_now = Some(code.clone());
                            }
                            ui.label(
                                egui::RichText::new(format!("{left}s"))
                                    .size(12.0)
                                    .color(if hot { WARN } else { MUTED }),
                            );
                        });
                        ui.add(
                            egui::ProgressBar::new(left as f32 / totp::PERIOD as f32)
                                .desired_width(200.0)
                                .fill(if hot { WARN } else { ACCENT }),
                        );
                    }
                    Err(_) => {
                        ui.label(
                            egui::RichText::new("stored two-factor secret is unreadable")
                                .color(DANGER),
                        );
                    }
                }
            }

            if let Some(value) = copy_now {
                ui.output_mut(|o| o.copied_text = value);
                self.clipboard_set_at = Some(Instant::now());
                self.set("Copied — clipboard clears in 20s", Level::None);
            }
        });
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            let editing = self.draft.id.is_some();
            ui.label(
                egui::RichText::new(if editing { "Edit entry" } else { "New entry" })
                    .size(17.0)
                    .strong(),
            );
            ui.add_space(8.0);

            label(ui, "NAME");
            let mut name = self.draft.name.clone();
            field(ui, &mut name, "GitHub", false);
            self.draft.name = name;

            ui.add_space(8.0);
            label(ui, "USERNAME");
            let mut user = self.draft.username.clone();
            field(ui, &mut user, "you@example.com", false);
            self.draft.username = user;

            ui.add_space(8.0);
            label(ui, "PASSWORD");
            ui.horizontal(|ui| {
                let mut pw = self.draft.password.clone();
                let w = (ui.available_width() - 190.0).max(120.0);
                ui.add(
                    egui::TextEdit::singleline(&mut pw)
                        .password(!self.draft.show_password)
                        .hint_text("password")
                        .desired_width(w)
                        .margin(egui::Margin::symmetric(10.0, 7.0)),
                );
                self.draft.password = pw;
                if ui
                    .small_button(if self.draft.show_password { "Hide" } else { "Show" })
                    .clicked()
                {
                    self.draft.show_password = !self.draft.show_password;
                }
                if ui.button("Generate").clicked() {
                    self.draft.password = generate_password();
                    self.draft.show_password = true;
                }
            });
            meter(ui, &self.draft.password.clone());

            ui.add_space(8.0);
            label(ui, "URL (optional)");
            let mut uri = self.draft.uri.clone();
            field(ui, &mut uri, "https://github.com", false);
            self.draft.uri = uri;

            ui.add_space(8.0);
            label(ui, "TAGS (optional, comma separated)");
            let mut tg = self.draft.tags.clone();
            field(ui, &mut tg, "work, email", false);
            self.draft.tags = tg;

            ui.add_space(8.0);
            label(ui, "NOTES (optional)");
            let mut nt = self.draft.notes.clone();
            ui.add(
                egui::TextEdit::multiline(&mut nt)
                    .hint_text("recovery codes, security answers…")
                    .desired_width(f32::INFINITY)
                    .desired_rows(3),
            );
            self.draft.notes = nt;

            ui.add_space(8.0);
            label(ui, "TWO-FACTOR SECRET (optional)");
            let mut t = self.draft.totp.clone();
            field(ui, &mut t, "base32 secret, or an otpauth:// link", false);
            self.draft.totp = t;
            ui.label(
                egui::RichText::new("Paste what the site shows next to its QR code.")
                    .size(11.0)
                    .color(MUTED),
            );

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary(ui, if editing { "Save" } else { "Add" }) {
                    self.save_draft();
                }
                if ui.button("Cancel").clicked() {
                    self.draft = Draft::default();
                    self.panel = Panel::List;
                }
            });
        });
    }

    fn history_view(&mut self, ui: &mut egui::Ui, id: i64) {
        let name = self
            .rows
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_default();
        card(ui, |ui| {
            ui.label(egui::RichText::new(format!("Password history — {name}")).size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Newest first. Restoring puts the old password back and \
                                     records the current one in its place.")
                    .size(12.0)
                    .color(MUTED),
            );
            ui.add_space(10.0);

            if self.history_rows.is_empty() {
                ui.label(
                    egui::RichText::new("This password has never been changed.").color(MUTED),
                );
            } else {
                let rows = self.history_rows.clone();
                let mut restore: Option<String> = None;
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    for (n, (when, old, reason)) in rows.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("{}.", n + 1)).size(12.0).color(MUTED),
                            );
                            // Masked by default: an old password is usually
                            // still in use somewhere else.
                            ui.label(
                                egui::RichText::new("•".repeat(old.chars().count().min(20)))
                                    .monospace(),
                            );
                            ui.label(
                                egui::RichText::new(format_when(*when)).size(11.0).color(MUTED),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("Restore").clicked() {
                                        restore = Some(old.clone());
                                    }
                                    if ui.small_button("Copy").clicked() {
                                        ui.output_mut(|o| o.copied_text = old.clone());
                                    }
                                },
                            );
                        });
                        if let Some(why) = reason.as_deref().filter(|r| !r.is_empty()) {
                            ui.label(
                                egui::RichText::new(format!("    {why}")).size(11.0).color(MUTED),
                            );
                        }
                        ui.separator();
                    }
                });
                if let Some(old) = restore {
                    self.restore_password(id, &old);
                }
            }

            ui.add_space(12.0);
            if ui.button("Back").clicked() {
                self.history_rows.clear();
                self.panel = Panel::List;
            }
        });
    }

    fn restore_password(&mut self, id: i64, old: &str) {
        let Some(row) = self.rows.iter().find(|r| r.id == id).cloned() else { return };
        let done = match (self.db.as_ref(), self.session.as_ref()) {
            (Some(db), Some(session)) => db
                .update_entry_full(
                    session, id, &row.name, &row.username, old,
                    row.uri.as_deref(), row.totp.as_deref(),
                    row.notes.as_deref(), row.tags.as_deref(),
                )
                .map(|_| ())
                .map_err(|e| e.to_string()),
            _ => Err("vault is locked".into()),
        };
        match done {
            Ok(()) => {
                self.load_history(id);
                self.reload();
                self.set("Password restored", Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn load_history(&mut self, id: i64) {
        if let (Some(db), Some(session)) = (self.db.as_ref(), self.session.as_ref()) {
            self.history_rows = db.password_history(session, id).unwrap_or_default();
        }
    }

    fn trash_view(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(egui::RichText::new("Trash").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Deleted entries stay here until you empty it. Emptying cannot be undone.",
                )
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(10.0);

            if self.trash_rows.is_empty() {
                ui.label(egui::RichText::new("The trash is empty.").color(MUTED));
            } else {
                let rows = self.trash_rows.clone();
                let (mut restore, mut purge): (Option<i64>, Option<(i64, String)>) = (None, None);
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    for (id, name) in rows {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&name).size(14.0));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .small_button(
                                            egui::RichText::new("Delete forever").color(DANGER),
                                        )
                                        .clicked()
                                    {
                                        // Confirmed separately: this is the one
                                        // action in the app with no way back.
                                        purge = Some((id, name.clone()));
                                    }
                                    if ui.small_button("Restore").clicked() {
                                        restore = Some(id);
                                    }
                                },
                            );
                        });
                        ui.separator();
                    }
                });
                if let Some(id) = restore {
                    if let Some(db) = self.db.as_ref() {
                        let _ = db.restore_entry(id);
                    }
                    self.reload();
                    self.load_trash();
                    self.set("Entry restored", Level::Ok);
                }
                if let Some((id, name)) = purge {
                    self.panel = Panel::ConfirmPurge(id, name);
                }
            }

            ui.add_space(12.0);
            if ui.button("Back").clicked() {
                self.panel = Panel::List;
            }
        });
    }

    fn load_trash(&mut self) {
        if let (Some(db), Some(session)) = (self.db.as_ref(), self.session.as_ref()) {
            self.trash_rows = db
                .list_trashed(session)
                .unwrap_or_default()
                .into_iter()
                .map(|(id, e)| (id, e.name))
                .collect();
        }
    }

    fn import_csv_view(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(egui::RichText::new("Import a CSV export").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Chrome, Firefox, Bitwarden, LastPass or KeePass. The format is \
                     detected from the header row.",
                )
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "That file holds your passwords in the clear. Delete it once the \
                     import is done.",
                )
                .size(12.0)
                .color(WARN),
            );
            ui.add_space(10.0);
            label(ui, "CSV FILE");
            field(ui, &mut self.csv_path, "/home/you/passwords.csv", false);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary(ui, "Import") {
                    self.do_csv_import();
                }
                if ui.button("Cancel").clicked() {
                    self.csv_path.clear();
                    self.panel = Panel::List;
                }
            });
        });
    }

    fn do_csv_import(&mut self) {
        let path = self.csv_path.trim().to_string();
        if path.is_empty() {
            return self.set("Give the path to a CSV file", Level::Bad);
        }
        let (Some(db), Some(session)) = (self.db.as_ref(), self.session.as_ref()) else {
            return self.set("vault is locked", Level::Bad);
        };
        let result = (|| -> Result<(String, usize), String> {
            let text = std::fs::read_to_string(&path).map_err(|_| "cannot read that file")?;
            let (source, rows) = valu::import::parse(&text).map_err(|e| e.to_string())?;
            for r in &rows {
                db.insert_entry_full(
                    session, &r.name, &r.username, &r.password,
                    r.uri.as_deref(), r.totp.as_deref(),
                    r.notes.as_deref(), r.tags.as_deref(),
                )
                .map_err(|e| e.to_string())?;
            }
            Ok((source.name().to_string(), rows.len()))
        })();
        match result {
            Ok((source, n)) => {
                self.csv_path.clear();
                self.reload();
                self.panel = Panel::List;
                self.set(format!("Imported {n} entries from {source}"), Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn export_view(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(egui::RichText::new("Export and backup").size(17.0).strong());
            ui.add_space(8.0);

            label(ui, "ENCRYPTED BACKUP");
            ui.label(
                egui::RichText::new(
                    "A copy of the vault, still encrypted under this passphrase. Safe to \
                     keep on a USB stick.",
                )
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(6.0);
            if ui.button("Create backup now").clicked() {
                self.do_backup();
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(10.0);

            label(ui, "PLAINTEXT CSV");
            ui.label(
                egui::RichText::new(
                    "Every password in the clear, readable by anything. Only for moving \
                     to another manager — delete it immediately afterwards.",
                )
                .size(12.0)
                .color(DANGER),
            );
            ui.add_space(6.0);
            field(ui, &mut self.export_path, "/home/you/valu-export.csv", false);
            ui.add_space(8.0);
            if ui
                .add_sized(
                    [190.0, 32.0],
                    egui::Button::new(
                        egui::RichText::new("Export unencrypted CSV").size(13.0).color(BG),
                    )
                    .fill(DANGER),
                )
                .clicked()
            {
                self.do_csv_export();
            }

            ui.add_space(14.0);
            if ui.button("Done").clicked() {
                self.panel = Panel::List;
            }
        });
    }

    fn do_backup(&mut self) {
        let Some(path) = self.vault_path.clone() else { return };
        let Some(db) = self.db.as_ref() else { return };
        match valu::export::backup(&path, db.conn()) {
            Ok(target) => {
                db.log_access(None, "backup");
                self.set(format!("Backup written to {}", target.display()), Level::Ok);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn do_csv_export(&mut self) {
        let target = self.export_path.trim().to_string();
        if target.is_empty() {
            return self.set("Choose where to write the CSV", Level::Bad);
        }
        let rows: Vec<valu::export::Outgoing> = self
            .rows
            .iter()
            .map(|r| valu::export::Outgoing {
                name: r.name.clone(),
                username: r.username.clone(),
                password: r.password.clone(),
                uri: r.uri.clone(),
                totp: r.totp.clone(),
                notes: r.notes.clone(),
                tags: r.tags.clone(),
            })
            .collect();
        let n = rows.len();
        let csv = valu::export::to_csv(&rows);
        match valu::export::write_csv(std::path::Path::new(&target), &csv) {
            Ok(()) => {
                if let Some(db) = self.db.as_ref() {
                    db.log_access(None, "export_csv");
                }
                self.set(format!("{n} entries written in the clear to {target}"), Level::Bad);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn import_view(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(egui::RichText::new("Import from KeePass").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Entries are copied in; the .kdbx file is left untouched.")
                    .size(12.0)
                    .color(MUTED),
            );
            ui.add_space(8.0);
            label(ui, "KDBX FILE");
            field(ui, &mut self.import_path, "/home/you/passwords.kdbx", false);
            ui.add_space(8.0);
            label(ui, "ITS PASSWORD");
            field(ui, &mut self.import_pass, "the KeePass password", true);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary(ui, "Import") {
                    self.import_kdbx();
                }
                if ui.button("Cancel").clicked() {
                    self.import_path.clear();
                    self.import_pass.clear();
                    self.panel = Panel::List;
                }
            });
        });
    }

    fn change_view(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(egui::RichText::new("Change passphrase").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Every entry is re-encrypted under the new key.")
                    .size(12.0)
                    .color(MUTED),
            );
            ui.add_space(8.0);
            label(ui, "CURRENT");
            field(ui, &mut self.change_old, "current passphrase", true);
            ui.add_space(8.0);
            label(ui, "NEW");
            let mut n = self.change_new.clone();
            field(ui, &mut n, "at least 8 characters", true);
            self.change_new = n;
            meter(ui, &self.change_new.clone());
            ui.add_space(8.0);
            label(ui, "REPEAT NEW");
            field(ui, &mut self.change_again, "the same again", true);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary(ui, "Change") {
                    self.change_passphrase();
                }
                if ui.button("Cancel").clicked() {
                    self.change_old.clear();
                    self.change_new.clear();
                    self.change_again.clear();
                    self.panel = Panel::List;
                }
            });
        });
    }

    fn confirm_purge(&mut self, ui: &mut egui::Ui, id: i64, name: &str) {
        card(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("Destroy “{name}” for good?"))
                    .size(17.0)
                    .strong()
                    .color(DANGER),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "The entry and every stored version of its password are overwritten \
                     with random data encrypted under a wipe key, then removed. The wipe \
                     key dies when you lock the vault.",
                )
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("There is no undo, and no recovery from a backup made after this.")
                    .size(12.0)
                    .color(WARN),
            );
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        [150.0, 34.0],
                        egui::Button::new(
                            egui::RichText::new("Destroy").size(14.0).strong().color(BG),
                        )
                        .fill(DANGER),
                    )
                    .clicked()
                {
                    self.do_purge(id, name);
                }
                if ui.button("Keep it").clicked() {
                    self.panel = Panel::Trash;
                }
            });
        });
    }

    fn do_purge(&mut self, id: i64, name: &str) {
        let done = match (self.db.as_ref(), self.session.as_ref()) {
            (Some(db), Some(session)) => {
                db.log_access(Some(id), "purge");
                db.purge_entry(session, id).map(|_| ()).map_err(|e| e.to_string())
            }
            _ => Err("vault is locked".into()),
        };
        match done {
            Ok(()) => {
                self.load_trash();
                self.panel = Panel::Trash;
                self.set(format!("{name} destroyed"), Level::None);
            }
            Err(why) => self.set(why, Level::Bad),
        }
    }

    fn confirm(&mut self, ui: &mut egui::Ui, id: i64, name: &str) {
        card(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("Delete “{name}”?"))
                    .size(17.0)
                    .strong()
                    .color(DANGER),
            );
            ui.add_space(4.0);
            ui.label(egui::RichText::new("This cannot be undone.").size(12.0).color(MUTED));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        [120.0, 34.0],
                        egui::Button::new(
                            egui::RichText::new("Delete").size(14.0).strong().color(BG),
                        )
                        .fill(DANGER),
                    )
                    .clicked()
                {
                    let n = name.to_string();
                    self.delete(id, &n);
                }
                if ui.button("Keep it").clicked() {
                    self.panel = Panel::List;
                }
            });
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([660.0, 740.0])
            .with_min_inner_size([480.0, 540.0])
            .with_title("VALU"),
        ..Default::default()
    };
    eframe::run_native(
        "VALU",
        options,
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(App::default()))
        }),
    )
}
