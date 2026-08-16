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
use valu::kind::{self, Kind};
use valu::storage::{EntryDraft, VaultDatabase};
use valu::totp;

// ── Palette ─────────────────────────────────────────────────────────────────
//
// Two themes, one set of roles. Naming the roles rather than the colours means
// every widget below is written once: swapping the theme swaps the values, not
// the code — and no screen can drift into a hardcoded colour that stays dark
// when everything around it turns light.

#[derive(Clone, Copy)]
struct Palette {
    bg: egui::Color32,
    surface: egui::Color32,
    surface_hi: egui::Color32,
    line: egui::Color32,
    accent: egui::Color32,
    text: egui::Color32,
    muted: egui::Color32,
    danger: egui::Color32,
    warn: egui::Color32,
    ok: egui::Color32,
    /// Text drawn ON the accent colour. Dark on a light theme, and vice versa —
    /// the one value that must not simply follow `text`, or primary buttons
    /// become unreadable.
    on_accent: egui::Color32,
}

const DARK: Palette = Palette {
    bg: egui::Color32::from_rgb(0x11, 0x13, 0x18),
    surface: egui::Color32::from_rgb(0x1a, 0x1d, 0x24),
    surface_hi: egui::Color32::from_rgb(0x25, 0x29, 0x33),
    line: egui::Color32::from_rgb(0x2a, 0x2f, 0x3a),
    accent: egui::Color32::from_rgb(0xe8, 0xb3, 0x4a),
    text: egui::Color32::from_rgb(0xe8, 0xea, 0xef),
    muted: egui::Color32::from_rgb(0x8c, 0x93, 0xa4),
    danger: egui::Color32::from_rgb(0xff, 0x6b, 0x6b),
    warn: egui::Color32::from_rgb(0xf0, 0xb4, 0x5f),
    ok: egui::Color32::from_rgb(0x5d, 0xd6, 0x8e),
    on_accent: egui::Color32::from_rgb(0x1a, 0x14, 0x05),
};

const LIGHT: Palette = Palette {
    bg: egui::Color32::from_rgb(0xf6, 0xf7, 0xf9),
    surface: egui::Color32::from_rgb(0xff, 0xff, 0xff),
    surface_hi: egui::Color32::from_rgb(0xe9, 0xec, 0xf1),
    line: egui::Color32::from_rgb(0xd8, 0xdd, 0xe5),
    accent: egui::Color32::from_rgb(0xb5, 0x7c, 0x10),
    text: egui::Color32::from_rgb(0x1a, 0x1d, 0x24),
    // Darker than the dark theme's muted: grey that reads as "secondary" on
    // black is nearly invisible on white.
    muted: egui::Color32::from_rgb(0x5f, 0x67, 0x76),
    danger: egui::Color32::from_rgb(0xc0, 0x28, 0x28),
    warn: egui::Color32::from_rgb(0xa8, 0x86, 0x0a),
    ok: egui::Color32::from_rgb(0x1a, 0x7f, 0x4b),
    on_accent: egui::Color32::from_rgb(0xff, 0xff, 0xff),
};

// The palette in force. Set when the theme changes, read by every helper.
// Thread-local rather than `static mut`: egui draws on one thread, so this is
// both correct and free, and it needs no `unsafe`.
thread_local! {
    static PALETTE: std::cell::Cell<Palette> = const { std::cell::Cell::new(DARK) };
}

fn pal() -> Palette {
    PALETTE.with(|c| c.get())
}

fn set_palette(light: bool) {
    PALETTE.with(|c| c.set(if light { LIGHT } else { DARK }));
}

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
    Settings,
    Help,
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
    kind: Kind,
    /// Already decoded, so the list and the detail pane do not each re-parse it.
    fields: Vec<(String, String)>,
}

/// The editor works on a copy, so cancelling changes nothing and saving is one
/// explicit act.
#[derive(Default, Clone)]
struct Draft {
    id: Option<i64>, // None = new entry
    kind: Kind,
    name: String,
    username: String,
    password: String,
    uri: String,
    totp: String,
    tags: String,
    notes: String,
    show_password: bool,
    /// Every category field the user has typed, by key.
    ///
    /// Keyed rather than positional, and never pruned when the category
    /// changes: someone who picks "Server", fills in the host, then realises it
    /// is really a "Database" would otherwise lose the host on the way. The
    /// save only writes the keys the chosen category actually declares, so the
    /// stray ones cost nothing but do not vanish while the form is open.
    fields: std::collections::HashMap<String, String>,
    /// Which secret category fields are currently revealed, by key.
    shown_fields: std::collections::HashSet<String>,
}

impl Draft {
    /// The value for one category field, empty if never typed.
    fn field(&self, key: &str) -> String {
        self.fields.get(key).cloned().unwrap_or_default()
    }

    /// The fields the CHOSEN category declares, in declaration order, ready to
    /// be encoded. Anything left over from a category the user tried and
    /// abandoned is dropped here rather than written to disk.
    fn declared_fields(&self) -> Vec<(String, String)> {
        self.kind
            .extra()
            .iter()
            .map(|f| (f.key.to_string(), self.field(f.key).trim().to_string()))
            .collect()
    }
}

struct App {
    // locked
    vaults: Vec<PathBuf>,
    selected: Option<PathBuf>,
    manual_path: String,
    passphrase: String,
    creating: bool,
    /// The in-app file browser on the lock screen, and where it is pointed.
    file_browser: bool,
    browse_dir: PathBuf,
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
    /// Which category fields the detail pane is currently showing in the clear.
    /// Cleared whenever another entry is opened, and on lock.
    revealed_fields: std::collections::HashSet<String>,
    /// Filter the list to one category, from the sidebar.
    kind_filter: Option<Kind>,
    /// Families the user has folded shut in the navigation pane.
    collapsed_groups: std::collections::HashSet<kind::Group>,
    focus_search: bool,
    show_help_locked: bool,
    loading_text: bool,
    text_path: String,
    unlocking_since: Option<Instant>,
    shot_requested: bool,
    shot_countdown: u32,
    draft: Draft,
    import_path: String,
    import_pass: String,
    csv_path: String,
    export_path: String,
    keyfile_path: String,
    retention_input: String,
    light: bool,
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
            file_browser: false,
            browse_dir: home(),
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
            revealed_fields: Default::default(),
            kind_filter: None,
            collapsed_groups: Default::default(),
            focus_search: false,
            show_help_locked: false,
            loading_text: false,
            text_path: String::new(),
            unlocking_since: None,
            shot_requested: false,
            shot_countdown: 8,
            draft: Draft::default(),
            import_path: String::new(),
            import_pass: String::new(),
            csv_path: String::new(),
            export_path: portable_root()
                .unwrap_or_else(home)
                .join("keypal-export.csv")
                .display()
                .to_string(),
            keyfile_path: String::new(),
            retention_input: "0".into(),
            light: false,
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
    let base = portable_root().unwrap_or_else(home);
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

/// True when the application is running as a portable install.
///
/// Marked by a `.keypal-portable` file beside the executable, which is the only
/// signal that cannot be faked by where the user happens to have launched from.
/// In portable mode nothing outside the medium is read or written: the point of
/// carrying a vault on a stick is that the machine you plug it into keeps no
/// trace, and scanning $HOME would defeat that on the first run.
fn portable_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.to_path_buf();
    if dir.join(".keypal-portable").exists() {
        Some(dir)
    } else {
        None
    }
}

/// Find vaults so the user never has to type a path. A vault is a SQLite file
/// with an `argon_salt` row in `meta` — the row unlocking needs — so this finds
/// real vaults rather than every .db lying around.
fn discover_vaults() -> Vec<PathBuf> {
    if let Some(root) = portable_root() {
        let mut found = Vec::new();
        for dir in [root.clone(), root.join("vaults")] {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for item in entries.flatten() {
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
        return found;
    }

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
        return (0.0, "", pal().muted);
    }
    let mut classes = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) { classes += 26; }
    if password.chars().any(|c| c.is_ascii_uppercase()) { classes += 26; }
    if password.chars().any(|c| c.is_ascii_digit()) { classes += 10; }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) { classes += 33; }
    let bits = password.chars().count() as f32 * (classes.max(2) as f32).log2();
    match bits as u32 {
        0..=45 => (bits, "weak", pal().danger),
        46..=69 => (bits, "fair", pal().warn),
        70..=99 => (bits, "good", pal().ok),
        _ => (bits, "strong", pal().ok),
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
                        kind: e.kind,
                        fields: e
                            .fields
                            .as_ref()
                            .map(|f| kind::decode_fields(f.expose()))
                            .unwrap_or_default(),
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
        self.unlocking_since = Some(Instant::now());
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
                // Retention runs here, once, on a vault we have just proven we
                // can decrypt — shredding needs the wipe key, so it cannot run
                // while locked.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let shredded = match (self.db.as_ref(), self.session.as_ref()) {
                    (Some(db), Some(session)) => {
                        db.log_access(None, "unlock");
                        db.purge_expired_trash(session, now).unwrap_or(0)
                    }
                    _ => 0,
                };
                self.reload();
                let n = self.rows.len();
                self.panel = Panel::List;
                self.open_entry = None;
                self.filter.clear();
                self.last_input = Instant::now();
                // Said out loud: silently destroying the user's data, even data
                // they trashed, is how a cleanup feature becomes a betrayal.
                self.set(
                    if shredded > 0 {
                        format!("Unlocked — {n} entries ({shredded} shredded from trash)")
                    } else {
                        format!("Unlocked — {n} entries")
                    },
                    Level::Ok,
                );
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
        self.revealed_fields.clear();
        self.kind_filter = None;
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
        // Only where the category has one. Demanding a password from a secure
        // note or a set of recovery codes would be the password-manager
        // assumption reasserting itself in the one place it does most harm:
        // refusing to save the user's data.
        match d.kind.secret_label() {
            Some(what) if d.password.is_empty() => {
                return self.set(format!("Give the entry a {}", what.to_lowercase()), Level::Bad);
            }
            _ => {}
        }
        // Validate the TOTP secret now rather than letting a typo surface as a
        // wrong code weeks later.
        let totp_clean = if !d.kind.uses_totp() || d.totp.trim().is_empty() {
            None
        } else {
            match totp::normalize_secret(&d.totp) {
                Some(s) => Some(s),
                None => return self.set("That is not a valid two-factor secret", Level::Bad),
            }
        };
        // A category with nowhere to show a field must not keep a value in it:
        // an invisible URL that still counted towards the health report would
        // be a finding about something the user cannot see or fix.
        let uri = Some(d.uri.trim())
            .filter(|u| !u.is_empty() && d.kind.uri_label().is_some())
            .map(str::to_string);
        let username = if d.kind.username_label().is_some() { d.username.trim() } else { "" };
        let fields = kind::encode_fields(&d.declared_fields());

        let entry = EntryDraft {
            name: d.name.trim(),
            username,
            password: &d.password,
            uri: uri.as_deref(),
            totp_secret: totp_clean.as_deref(),
            notes: Some(d.notes.trim()),
            tags: Some(d.tags.trim()),
            kind: d.kind,
            fields: Some(&fields),
        };

        let done = match (self.db.as_ref(), self.session.as_ref()) {
            (Some(db), Some(session)) => match d.id {
                Some(id) => db.update_draft(session, id, &entry).map(|_| ()).map_err(|e| e.to_string()),
                None => db.insert_draft(session, &entry).map(|_| ()).map_err(|e| e.to_string()),
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

/// Install the bundled monospace face.
///
/// Compiled into the binary with `include_bytes!`, so there is no file to
/// find, nothing to load at runtime and nothing an attacker can substitute by
/// editing the directory. egui already parses TTF for its default faces, so
/// this uses machinery that is present either way.
///
/// It matters for a vault specifically: passwords and one-time codes are read
/// character by character, and a proportional face makes 0/O and 1/l/I
/// ambiguous exactly where a misread costs you a login.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "keypal-mono".to_owned(),
        egui::FontData::from_static(include_bytes!("../../assets/mono.ttf")),
    );
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "keypal-mono".to_owned());
    ctx.set_fonts(fonts);
}

fn apply_theme(ctx: &egui::Context, light: bool) {
    set_palette(light);
    let c = pal();
    let mut v = if light { egui::Visuals::light() } else { egui::Visuals::dark() };
    v.panel_fill = c.bg;
    v.window_fill = c.bg;
    // The inside of a text field. Hardcoded near-black until now, which left
    // every search box and every input a dark slab on the light theme — the
    // exact failure the palette comment at the top of this file warns about.
    // A shade off the card it sits on, in the same direction the dark theme
    // goes: there the field is darker than its surface, so here it is slightly
    // darker than white. Pure white would match the card exactly and leave the
    // field with no edge at all.
    v.extreme_bg_color = if light {
        egui::Color32::from_rgb(0xef, 0xf1, 0xf6)
    } else {
        egui::Color32::from_rgb(0x0d, 0x0f, 0x13)
    };
    v.override_text_color = Some(c.text);
    v.selection.bg_fill = c.accent.linear_multiply(0.35);
    v.hyperlink_color = c.accent;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, c.line);

    let r = egui::Rounding::same(9.0);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
    ] {
        w.rounding = r;
    }
    v.widgets.inactive.bg_fill = c.surface_hi;
    v.widgets.inactive.weak_bg_fill = c.surface_hi;
    v.widgets.hovered.bg_fill = c.accent.linear_multiply(0.5);
    v.widgets.hovered.weak_bg_fill = c.accent.linear_multiply(0.5);
    v.widgets.active.bg_fill = c.accent;
    v.widgets.active.weak_bg_fill = c.accent;
    ctx.set_visuals(v);

    let mut s = (*ctx.style()).clone();
    s.spacing.item_spacing = egui::vec2(10.0, 9.0);
    s.spacing.button_padding = egui::vec2(13.0, 7.0);
    s.spacing.interact_size.y = 30.0;
    ctx.set_style(s);
}

/// A form laid out at a readable width instead of stretched across the window.
///
/// A 400px field spread over 1800px of window is not more usable for being
/// bigger — the eye loses the line, and the empty space reads as a broken
/// layout. Every modal panel goes through this so they all share one measure.
/// A reading page: much wider than a form, because it holds prose.
///
/// A form is a column of fields and 560px is right for it. Running several
/// screens of explanation through the same measure put a wall of text in a
/// small box in the middle of an empty window — the reader gets a keyhole view
/// of a document and has to scroll four times as far to read it.
fn page<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    // Capped all the same. Prose set across 1600px of window is a line the eye
    // loses its place on returning; somewhere near ninety characters is where
    // reading stops being work.
    const MEASURE: f32 = 900.0;
    let avail = ui.available_rect_before_wrap();
    let width = avail.width().min(MEASURE);
    let pad = ((avail.width() - width) / 2.0).max(0.0);
    // An explicit rectangle, NOT a horizontal layout with a spacer. A
    // horizontal sizes itself to its contents' height, so a scroll area placed
    // inside one is handed almost no height and clips its text to two lines —
    // which is exactly how this page came to show its title and nothing else.
    let rect = egui::Rect::from_min_size(
        avail.min + egui::vec2(pad, 0.0),
        egui::vec2(width, avail.height()),
    );
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| add(ui)).inner
}

fn form<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    const MEASURE: f32 = 560.0;
    let width = ui.available_width().min(MEASURE);
    // Centred, not merely narrowed. Capping the width alone left the card
    // pinned to the left edge with a third of the window empty beside it,
    // which looks like a layout that ran out rather than one that was chosen.
    let pad = ((ui.available_width() - width) / 2.0).max(0.0);
    ui.horizontal(|ui| {
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.set_max_width(width);
            card(ui, add)
        })
        .inner
    })
    .inner
}

/// A raised surface.
///
/// Fill alone is not enough separation on a dark theme: two greys a few points
/// apart read as one flat plane. A hairline plus a soft shadow gives the card
/// an edge and a little height, which is what makes an interface look built
/// rather than drawn.
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(pal().surface)
        .rounding(egui::Rounding::same(14.0))
        .stroke(egui::Stroke::new(1.0_f32, pal().line))
        .shadow(egui::epaint::Shadow {
            offset: egui::vec2(0.0, 2.0),
            blur: 12.0,
            spread: 0.0,
            color: egui::Color32::from_black_alpha(60),
        })
        .inner_margin(egui::Margin::same(18.0))
        .show(ui, add)
        .inner
}

/// The app mark: a rounded accent tile with the initial.
///
/// One saturated shape in an otherwise quiet interface. Without it the header
/// is two lines of grey text and the window has no focal point at all.
/// The mascot, as the launcher shows it.
///
/// Embedded at COMPILE time, not read from disk. The rest of the interface is
/// drawn rather than loaded, and the reason given for that still stands: an
/// icon file sitting beside the binary is one an attacker can swap, and a
/// decoder pointed at it is parsing surface a vault did not need. Neither
/// applies to bytes baked into the executable — they cannot be replaced
/// without replacing the program, and the PNG is fixed and known, decoded once
/// at startup by a crate already linked in for screenshots.
///
/// What it buys: the mark on screen is the same painting as the icon in the
/// menu, pixel for pixel, instead of a redrawing of it that drifts.
const MASCOT_PNG: &[u8] = include_bytes!("../../assets/mascot.png");

thread_local! {
    static MASCOT: std::cell::RefCell<Option<Option<egui::TextureHandle>>> =
        const { std::cell::RefCell::new(None) };
}

/// Decode and upload the mascot once. `None` means it could not be decoded, in
/// which case the caller draws the mark by hand instead — a missing picture
/// must not be a missing logo.
fn mascot_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    MASCOT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some((|| {
                let decoder = png::Decoder::new(MASCOT_PNG);
                let mut reader = decoder.read_info().ok()?;
                let mut buf = vec![0; reader.output_buffer_size()];
                let info = reader.next_frame(&mut buf).ok()?;
                if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight
                {
                    return None;
                }
                let image = egui::ColorImage::from_rgba_unmultiplied(
                    [info.width as usize, info.height as usize],
                    &buf[..info.buffer_size()],
                );
                Some(ctx.load_texture("mascot", image, egui::TextureOptions::LINEAR))
            })());
        }
        slot.as_ref().and_then(|t| t.clone())
    })
}

fn logo(ui: &mut egui::Ui, size: f32) {
    if let Some(tex) = mascot_texture(ui.ctx()) {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        egui::Image::new(&tex).paint_at(ui, rect);
        return;
    }
    // Fallback: the same silhouette drawn by hand, for the case where the
    // embedded picture cannot be decoded.
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let p = ui.painter();
    let c = pal();
    let u = size / 24.0;
    let at = |x: f32, y: f32| {
        egui::pos2(rect.center().x + (x - 12.0) * u, rect.center().y + (y - 12.0) * u)
    };
    let shield = c.accent.gamma_multiply(0.45);

    // Shield, offset right so it reads as standing BEHIND the key rather than
    // being obscured by it.
    p.add(egui::Shape::convex_polygon(
        vec![
            at(14.0, 2.0), at(22.0, 5.5), at(22.0, 12.5),
            at(14.0, 21.0), at(6.0, 12.5), at(6.0, 5.5),
        ],
        shield,
        egui::Stroke::NONE,
    ));

    // Key bow: large, because it carries the face. The first attempt sized it
    // to fit the grid and the eyes ended up two pixels apart at 52px.
    p.circle_filled(at(8.6, 12.6), 6.4 * u, c.accent);
    p.circle_filled(at(8.6, 12.6), 5.3 * u, c.accent.gamma_multiply(1.2));

    // Shaft and teeth, pointing right out from behind the shield.
    p.add(egui::Shape::convex_polygon(
        vec![at(14.0, 11.0), at(23.0, 11.0), at(23.0, 14.2), at(14.0, 14.2)],
        c.accent,
        egui::Stroke::NONE,
    ));
    for x in [17.4_f32, 20.6] {
        p.add(egui::Shape::convex_polygon(
            vec![at(x, 14.2), at(x + 1.6, 14.2), at(x + 1.6, 17.0), at(x, 17.0)],
            c.accent,
            egui::Stroke::NONE,
        ));
    }

    // The face is what makes it a pal rather than a padlock.
    let eye = (size * 0.058).max(1.2);
    p.circle_filled(at(6.5, 11.0), eye, c.on_accent);
    p.circle_filled(at(10.7, 11.0), eye, c.on_accent);
    p.add(egui::Shape::line(
        vec![at(6.2, 14.4), at(8.6, 16.2), at(11.0, 14.4)],
        egui::Stroke::new((1.6 * u).max(1.2), c.on_accent),
    ));
}

/// A quiet column of drifting hex glyphs down one edge.
///
/// SECURITY NOTE, because this is the obvious place to get it wrong: the
/// glyphs are RANDOM, never real ciphertext from the vault. Drawing actual
/// encrypted bytes would put fragments of the user's file on screen for anyone
/// looking over a shoulder or taking a screenshot. Ciphertext is not secret,
/// but it is not decoration either, and a vault should not display its own
/// contents for atmosphere.
///
/// Everything here is arithmetic on positions and opacity — no assets, no
/// decoding, nothing read from disk.
fn cipher_rain(ui: &mut egui::Ui, rect: egui::Rect, t: f64, intensity: f32) {
    const COLS: usize = 7;
    const GLYPHS: &[u8] = b"0123456789ABCDEF";
    let p = ui.painter().with_clip_rect(rect);
    let c = pal();

    for col in 0..COLS {
        let x = rect.left() + (col as f32 + 0.5) * (rect.width() / COLS as f32);
        // Each column drifts at its own speed and offset, so they never march
        // in step — a lockstep grid reads as a progress bar, not as noise.
        let speed = 26.0 + (col as f64 * 13.0) % 40.0;
        let phase = (col as f64 * 97.0) % 400.0;
        let head = ((t * speed + phase) % (rect.height() as f64 + 220.0)) as f32 - 110.0;

        for k in 0..11 {
            let y = rect.top() + head - k as f32 * 17.0;
            if y < rect.top() - 20.0 || y > rect.bottom() + 20.0 {
                continue;
            }
            // Deterministic from position and a slow time step, so a glyph
            // holds for a moment instead of flickering every frame.
            let seed = (col * 31 + k * 17) as f64 + (t * 3.0).floor();
            let g = GLYPHS[(seed.abs() as usize * 2654435761) % GLYPHS.len()] as char;
            let fade = (1.0 - k as f32 / 11.0).powf(1.6);
            p.text(
                egui::pos2(x, y),
                egui::Align2::CENTER_CENTER,
                g,
                egui::FontId::monospace(13.0),
                c.accent.gamma_multiply(fade * intensity),
            );
        }
    }
}

/// Icons drawn as shapes, not loaded as images.
///
/// Deliberate: an image file needs a decoder running over data at startup, and
/// a vault should not grow parsing surface for decoration. Drawn icons cost
/// nothing to parse, cannot be swapped by someone editing files beside the
/// binary, take the theme colour for free, and stay crisp at any size or
/// display scale.
#[derive(Clone, Copy, PartialEq)]
enum Icon {
    Key,
    Shield,
    Eye,
    EyeOff,
    Copy,
    Edit,
    Trash,
    Plus,
    Search,
    Import,
    Export,
    Lock,
    Clock,
    Tag,
    Settings,
    Help,
    Close,

    // ── One per category ─────────────────────────────────────────────────
    // A category the user cannot recognise at a glance is a category they
    // will not bother choosing, and the whole idea collapses back into one
    // undifferentiated list. So each gets a shape, not a colour swatch: shape
    // survives greyscale, small sizes and colour-blindness, all three of which
    // a colour alone does not.
    Globe,
    Envelope,
    ShieldClock,
    Bolt,
    Terminal,
    Stack,
    Cylinder,
    Wave,
    Monitor,
    Tunnel,
    Rosette,
    ListLines,
    Coin,
    Card,
    Sheet,
    Seal,
}

/// The shape that stands for a category.
fn kind_icon(k: Kind) -> Icon {
    match k {
        Kind::Website => Icon::Globe,
        Kind::Email => Icon::Envelope,
        Kind::Authenticator => Icon::ShieldClock,
        Kind::ApiKey => Icon::Bolt,
        Kind::SshKey => Icon::Terminal,
        Kind::Server => Icon::Stack,
        Kind::Database => Icon::Cylinder,
        Kind::Wifi => Icon::Wave,
        Kind::Device => Icon::Monitor,
        Kind::Vpn => Icon::Tunnel,
        Kind::Certificate => Icon::Rosette,
        Kind::RecoveryCodes => Icon::ListLines,
        Kind::CryptoWallet => Icon::Coin,
        Kind::BankCard => Icon::Card,
        Kind::SecureNote => Icon::Sheet,
        Kind::License => Icon::Seal,
    }
}

/// The colour that stands for a category.
///
/// Hue only, at a fixed saturation and lightness chosen per theme, so no
/// category can come out unreadable against either background. The hues are
/// spread deliberately rather than generated, so that neighbours in the
/// sidebar are never neighbours on the colour wheel.
fn kind_color(k: Kind) -> egui::Color32 {
    const HUES: [f32; 16] = [
        205.0, // Website      blue
        150.0, // Email        green
        265.0, // Authenticator violet
        45.0,  // API key      amber
        20.0,  // SSH key      orange
        220.0, // Server       indigo
        190.0, // Database     teal
        170.0, // Wi-Fi        sea green
        240.0, // Device       periwinkle
        280.0, // VPN          purple
        330.0, // Certificate  pink
        95.0,  // Recovery     lime
        35.0,  // Wallet       gold
        0.0,   // Bank card    red
        60.0,  // Note         yellow
        310.0, // Licence      magenta
    ];
    let hue = HUES[k.as_i64() as usize % 16] / 360.0;
    let light_bg = pal().bg.r() > 128;
    // `Hsva` is LINEAR, not sRGB: a value of 0.68 comes out around 0.85 on
    // screen. Read as sRGB numbers these look sensible and render washed out,
    // which is how the first version put pastel icons on a white sidebar.
    egui::Color32::from(egui::ecolor::Hsva::new(
        hue,
        if light_bg { 0.90 } else { 0.58 },
        if light_bg { 0.26 } else { 0.92 },
        1.0,
    ))
}

/// Draw `icon` into a square of `size`, in `color`, taking layout space.
fn icon(ui: &mut egui::Ui, icon: Icon, size: f32, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    draw_icon(ui.painter(), rect, icon, color);
}

/// Draw `icon` into `rect` without taking layout space.
///
/// Split out from `icon` so a row that paints its own background and aligns its
/// own columns — the navigation pane — can place the glyph exactly, instead of
/// nesting layouts that each re-measure and drift apart by a pixel.
fn draw_icon(p: &egui::Painter, rect: egui::Rect, icon: Icon, color: egui::Color32) {
    let size = rect.width().min(rect.height());
    let c = rect.center();
    let u = size / 24.0; // the shapes below are described on a 24-unit grid
    let w = 1.7 * u;
    let stroke = egui::Stroke::new(w, color);
    let at = |x: f32, y: f32| egui::pos2(c.x + (x - 12.0) * u, c.y + (y - 12.0) * u);
    let line = |p: &egui::Painter, a: (f32, f32), b: (f32, f32)| {
        p.line_segment([at(a.0, a.1), at(b.0, b.1)], stroke);
    };

    match icon {
        Icon::Key => {
            p.circle_stroke(at(8.5, 8.5), 4.0 * u, stroke);
            line(p, (11.5, 11.5), (19.0, 19.0));
            line(p, (16.0, 16.0), (18.0, 14.0));
        }
        Icon::Shield => {
            let pts = vec![at(12.0, 3.0), at(20.0, 6.5), at(20.0, 12.0)];
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(20.0, 12.0), at(12.0, 21.0), at(4.0, 12.0)];
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(4.0, 12.0), at(4.0, 6.5), at(12.0, 3.0)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Eye | Icon::EyeOff => {
            let pts = vec![at(3.0, 12.0), at(8.0, 6.5), at(16.0, 6.5), at(21.0, 12.0)];
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(21.0, 12.0), at(16.0, 17.5), at(8.0, 17.5), at(3.0, 12.0)];
            p.add(egui::Shape::line(pts, stroke));
            p.circle_stroke(at(12.0, 12.0), 2.6 * u, stroke);
            if icon == Icon::EyeOff {
                line(p, (4.0, 20.0), (20.0, 4.0));
            }
        }
        Icon::Copy => {
            p.rect_stroke(
                egui::Rect::from_min_max(at(9.0, 3.0), at(21.0, 15.0)),
                egui::Rounding::same(2.0 * u),
                stroke,
            );
            let pts = vec![at(15.0, 18.0), at(3.0, 18.0), at(3.0, 6.0)];
            p.add(egui::Shape::line(pts, stroke));
            line(p, (3.0, 18.0), (15.0, 18.0));
            line(p, (15.0, 18.0), (15.0, 15.0));
        }
        Icon::Edit => {
            let pts = vec![at(4.0, 20.0), at(4.0, 15.0), at(16.0, 3.0), at(21.0, 8.0), at(9.0, 20.0)];
            p.add(egui::Shape::line(pts, stroke));
            line(p, (4.0, 20.0), (9.0, 20.0));
        }
        Icon::Trash => {
            line(p, (3.5, 6.0), (20.5, 6.0));
            line(p, (9.0, 6.0), (9.0, 3.5));
            line(p, (9.0, 3.5), (15.0, 3.5));
            line(p, (15.0, 3.5), (15.0, 6.0));
            let pts = vec![at(5.5, 6.0), at(6.5, 20.5), at(17.5, 20.5), at(18.5, 6.0)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Plus => {
            line(p, (12.0, 5.0), (12.0, 19.0));
            line(p, (5.0, 12.0), (19.0, 12.0));
        }
        Icon::Search => {
            p.circle_stroke(at(10.5, 10.5), 6.0 * u, stroke);
            line(p, (15.0, 15.0), (20.0, 20.0));
        }
        Icon::Import | Icon::Export => {
            let pts = vec![at(4.0, 15.0), at(4.0, 20.0), at(20.0, 20.0), at(20.0, 15.0)];
            p.add(egui::Shape::line(pts, stroke));
            if icon == Icon::Import {
                line(p, (12.0, 3.0), (12.0, 15.0));
                let pts = vec![at(7.5, 10.5), at(12.0, 15.0), at(16.5, 10.5)];
                p.add(egui::Shape::line(pts, stroke));
            } else {
                line(p, (12.0, 15.0), (12.0, 3.0));
                let pts = vec![at(7.5, 7.5), at(12.0, 3.0), at(16.5, 7.5)];
                p.add(egui::Shape::line(pts, stroke));
            }
        }
        Icon::Lock => {
            p.rect_stroke(
                egui::Rect::from_min_max(at(4.5, 10.5), at(19.5, 20.5)),
                egui::Rounding::same(2.0 * u),
                stroke,
            );
            let pts = vec![at(8.0, 10.5), at(8.0, 7.0), at(12.0, 4.0), at(16.0, 7.0), at(16.0, 10.5)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Clock => {
            p.circle_stroke(at(12.0, 12.0), 8.5 * u, stroke);
            line(p, (12.0, 7.0), (12.0, 12.0));
            line(p, (12.0, 12.0), (16.0, 14.0));
        }
        Icon::Tag => {
            let pts = vec![at(3.5, 3.5), at(11.0, 3.5), at(20.5, 13.0), at(13.0, 20.5), at(3.5, 11.0), at(3.5, 3.5)];
            p.add(egui::Shape::line(pts, stroke));
            p.circle_filled(at(7.5, 7.5), 1.6 * u, color);
        }
        Icon::Settings => {
            p.circle_stroke(at(12.0, 12.0), 3.4 * u, stroke);
            for k in 0..6 {
                let a = std::f32::consts::TAU * k as f32 / 6.0;
                let (dx, dy) = (a.cos(), a.sin());
                p.line_segment(
                    [
                        egui::pos2(c.x + dx * 6.0 * u, c.y + dy * 6.0 * u),
                        egui::pos2(c.x + dx * 9.5 * u, c.y + dy * 9.5 * u),
                    ],
                    stroke,
                );
            }
        }
        Icon::Help => {
            p.circle_stroke(at(12.0, 12.0), 8.5 * u, stroke);
            let pts = vec![at(9.0, 9.5), at(12.0, 7.0), at(15.0, 9.5), at(12.0, 13.0), at(12.0, 14.5)];
            p.add(egui::Shape::line(pts, stroke));
            p.circle_filled(at(12.0, 18.0), 1.2 * u, color);
        }
        Icon::Close => {
            line(p, (6.0, 6.0), (18.0, 18.0));
            line(p, (18.0, 6.0), (6.0, 18.0));
        }

        // ── Categories ───────────────────────────────────────────────────
        Icon::Globe => {
            p.circle_stroke(at(12.0, 12.0), 8.5 * u, stroke);
            line(p, (3.5, 12.0), (20.5, 12.0));
            // The meridian: an ellipse, drawn as a polyline because a circle
            // stroke would read as a second globe rather than as depth.
            let mut pts = Vec::new();
            for i in 0..=24 {
                let a = std::f32::consts::TAU * i as f32 / 24.0;
                pts.push(at(12.0 + 4.6 * a.sin(), 12.0 - 8.5 * a.cos()));
            }
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Envelope => {
            p.rect_stroke(
                egui::Rect::from_min_max(at(3.0, 5.5), at(21.0, 18.5)),
                egui::Rounding::same(2.0 * u),
                stroke,
            );
            let pts = vec![at(3.0, 7.0), at(12.0, 13.5), at(21.0, 7.0)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::ShieldClock => {
            // A shield, because it guards; a hand, because it is the clock that
            // makes the code change.
            let pts = vec![at(12.0, 3.0), at(20.0, 6.5), at(20.0, 12.0), at(12.0, 21.0)];
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(12.0, 21.0), at(4.0, 12.0), at(4.0, 6.5), at(12.0, 3.0)];
            p.add(egui::Shape::line(pts, stroke));
            line(p, (12.0, 8.0), (12.0, 12.0));
            line(p, (12.0, 12.0), (15.0, 13.5));
        }
        Icon::Bolt => {
            let pts = vec![at(13.5, 2.5), at(5.5, 13.5), at(11.0, 13.5), at(10.5, 21.5), at(18.5, 10.5), at(13.0, 10.5), at(13.5, 2.5)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Terminal => {
            p.rect_stroke(
                egui::Rect::from_min_max(at(3.0, 4.5), at(21.0, 19.5)),
                egui::Rounding::same(2.0 * u),
                stroke,
            );
            let pts = vec![at(7.0, 9.5), at(10.5, 12.5), at(7.0, 15.5)];
            p.add(egui::Shape::line(pts, stroke));
            line(p, (13.0, 15.5), (17.5, 15.5));
        }
        Icon::Stack => {
            for y in [5.5f32, 11.0, 16.5] {
                p.rect_stroke(
                    egui::Rect::from_min_max(at(3.5, y), at(20.5, y + 3.6)),
                    egui::Rounding::same(1.2 * u),
                    stroke,
                );
                p.circle_filled(at(6.5, y + 1.8), 1.0 * u, color);
            }
        }
        Icon::Cylinder => {
            // Top ellipse, then the two sides and the front of the base.
            let ellipse = |cy: f32, from: f32, to: f32| {
                let mut pts = Vec::new();
                let steps = 24;
                for i in 0..=steps {
                    let a = from + (to - from) * i as f32 / steps as f32;
                    pts.push(at(12.0 + 7.5 * a.cos(), cy + 3.2 * a.sin()));
                }
                pts
            };
            use std::f32::consts::{PI, TAU};
            p.add(egui::Shape::line(ellipse(6.5, 0.0, TAU), stroke));
            line(p, (4.5, 6.5), (4.5, 17.5));
            line(p, (19.5, 6.5), (19.5, 17.5));
            p.add(egui::Shape::line(ellipse(17.5, 0.0, PI), stroke));
        }
        Icon::Wave => {
            // Three arcs and a dot: the universal shape for "signal", and the
            // only one that stays legible at 14 pixels.
            for r in [4.0f32, 7.5, 11.0] {
                let mut pts = Vec::new();
                for i in 0..=16 {
                    let a = std::f32::consts::PI * (0.15 + 0.7 * i as f32 / 16.0);
                    pts.push(at(12.0 - r * a.cos(), 18.0 - r * a.sin()));
                }
                p.add(egui::Shape::line(pts, stroke));
            }
            p.circle_filled(at(12.0, 18.5), 1.5 * u, color);
        }
        Icon::Monitor => {
            p.rect_stroke(
                egui::Rect::from_min_max(at(2.5, 4.0), at(21.5, 16.0)),
                egui::Rounding::same(2.0 * u),
                stroke,
            );
            line(p, (12.0, 16.0), (12.0, 19.5));
            line(p, (7.5, 19.5), (16.5, 19.5));
        }
        Icon::Tunnel => {
            // A tunnel mouth: straight walls with a domed top, and a smaller
            // opening inside it. The first attempt was two bare arches sitting
            // on the baseline, which at 14 pixels read as a half-closed eye —
            // the walls are what make it a way *through* something.
            let mouth = |r: f32, shoulder: f32| {
                let mut pts = vec![at(12.0 - r, 20.5)];
                for i in 0..=20 {
                    let a = std::f32::consts::PI * i as f32 / 20.0;
                    pts.push(at(12.0 - r * a.cos(), shoulder - r * a.sin()));
                }
                pts.push(at(12.0 + r, 20.5));
                pts
            };
            p.add(egui::Shape::line(mouth(8.5, 13.5), stroke));
            p.add(egui::Shape::line(mouth(3.6, 13.5), stroke));
            line(p, (3.5, 20.5), (20.5, 20.5));
        }
        Icon::Rosette => {
            p.circle_stroke(at(12.0, 9.0), 6.0 * u, stroke);
            let pts = vec![at(8.5, 13.8), at(7.0, 21.5), at(12.0, 18.5), at(17.0, 21.5), at(15.5, 13.8)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::ListLines => {
            for y in [7.0f32, 12.0, 17.0] {
                p.circle_filled(at(5.0, y), 1.4 * u, color);
                line(p, (9.5, y), (20.0, y));
            }
        }
        Icon::Coin => {
            p.circle_stroke(at(12.0, 12.0), 8.5 * u, stroke);
            line(p, (12.0, 5.5), (12.0, 18.5));
            let pts = vec![at(15.0, 8.5), at(10.0, 8.5), at(8.5, 10.5), at(10.0, 12.0), at(15.0, 12.0)];
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(15.0, 12.0), at(16.0, 13.8), at(14.5, 15.5), at(9.0, 15.5)];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Card => {
            p.rect_stroke(
                egui::Rect::from_min_max(at(2.5, 5.5), at(21.5, 18.5)),
                egui::Rounding::same(2.5 * u),
                stroke,
            );
            line(p, (2.5, 9.5), (21.5, 9.5));
            line(p, (6.0, 14.5), (11.0, 14.5));
        }
        Icon::Sheet => {
            // A page with the corner turned: it holds text, and nothing else.
            let pts = vec![at(5.0, 3.0), at(14.0, 3.0), at(19.0, 8.0), at(19.0, 21.0), at(5.0, 21.0), at(5.0, 3.0)];
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(14.0, 3.0), at(14.0, 8.0), at(19.0, 8.0)];
            p.add(egui::Shape::line(pts, stroke));
            for y in [12.0f32, 15.5] {
                line(p, (8.0, y), (16.0, y));
            }
        }
        Icon::Seal => {
            // A scalloped disc: the shape of something stamped as genuine.
            // Eight lobes, not ten — at 14 pixels the finer scallop stopped
            // being a shape and became a fuzzy edge, and the tick inside it
            // was lost in the noise.
            let mut pts = Vec::new();
            let lobes = 8.0f32;
            for i in 0..=64 {
                let a = std::f32::consts::TAU * i as f32 / 64.0;
                let r = 7.9 + 1.5 * (a * lobes).cos();
                pts.push(at(12.0 + r * a.cos(), 12.0 + r * a.sin()));
            }
            p.add(egui::Shape::line(pts, stroke));
            let pts = vec![at(8.0, 12.2), at(10.8, 15.0), at(16.0, 9.0)];
            p.add(egui::Shape::line(pts, stroke));
        }
    }
}

/// A button with an icon and a label, which is what a toolbar should be.
fn icon_button(ui: &mut egui::Ui, glyph: Icon, text: &str) -> bool {
    // Same pill as every other button. The first version drew the icon and
    // label bare, so these read as floating text next to real buttons — one
    // toolbar with two different ideas of what a button looks like.
    let id = ui.next_auto_id();
    ui.skip_ahead_auto_ids(1);
    let painter = ui.painter().clone();
    let bg = painter.add(egui::Shape::Noop);

    let inner = ui
        .scope(|ui| {
            ui.horizontal(|ui| {
                ui.add_space(9.0);
                icon(ui, glyph, 14.0, pal().text);
                ui.add_space(5.0);
                ui.label(egui::RichText::new(text).size(13.0));
                ui.add_space(9.0);
            });
        })
        .response;

    let rect = inner.rect.expand2(egui::vec2(0.0, 5.0));
    let click = ui.interact(rect, id, egui::Sense::click());
    let fill = if click.hovered() {
        pal().accent.linear_multiply(0.45)
    } else {
        pal().surface_hi
    };
    painter.set(
        bg,
        egui::Shape::rect_filled(rect, egui::Rounding::same(9.0), fill),
    );
    if click.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    click.clicked()
}

/// A coloured initial for an entry.
///
/// A list of forty identical rows is read line by line; a list with a colour
/// and a letter per row is scanned. The colour comes from the name, so it is
/// stable — the same entry looks the same every time, which is what makes it
/// recognisable rather than decorative.
///
/// Hue only: saturation and lightness are fixed so no entry can come out
/// unreadable against either theme.
fn avatar(ui: &mut egui::Ui, name: &str, size: f32) {
    let initial = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".into());

    // FNV-1a: tiny, well-distributed, and stable across runs — unlike the
    // standard hasher, which is randomly seeded per process and would give the
    // same entry a different colour every launch.
    let mut hash: u32 = 2_166_136_261;
    for b in name.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    let hue = (hash % 360) as f32 / 360.0;
    let fill = egui::ecolor::Hsva::new(hue, 0.55, if pal().bg.r() > 128 { 0.85 } else { 0.55 }, 1.0);

    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::Rounding::same(size * 0.3), egui::Color32::from(fill));
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initial,
        egui::FontId::proportional(size * 0.5),
        egui::Color32::WHITE,
    );
}

/// One row of the navigation pane.
///
/// Every row in the left pane goes through here: the totals, the group
/// headings, the categories, the tags. That is the point — a pane where each
/// kind of row was laid out by its own code drifted into four different
/// indents and three different ways of showing a number, which reads as
/// carelessness even when nobody can say why.
///
/// Counts are right-aligned against the pane edge. Trailing them after the
/// label ("Website   2") puts every number at a different x, so the column
/// cannot be read down; aligned, it can be, and comparing two categories stops
/// being work.
#[allow(clippy::too_many_arguments)]
fn nav_row(
    ui: &mut egui::Ui,
    glyph: Option<Icon>,
    text: &str,
    count: Option<usize>,
    selected: bool,
    tint: egui::Color32,
    indent: f32,
    strong: bool,
) -> egui::Response {
    const H: f32 = 27.0;
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, H), egui::Sense::click());
    let p = ui.painter();

    if selected {
        p.rect_filled(rect, egui::Rounding::same(7.0), tint.linear_multiply(0.20));
    } else if resp.hovered() {
        p.rect_filled(rect, egui::Rounding::same(7.0), pal().surface_hi);
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    let text_color = if selected { tint } else if strong { pal().text } else { pal().muted };
    let mut x = rect.left() + indent;
    if let Some(g) = glyph {
        const S: f32 = 14.0;
        let r = egui::Rect::from_center_size(
            egui::pos2(x + S / 2.0, rect.center().y),
            egui::vec2(S, S),
        );
        draw_icon(p, r, g, if selected { tint } else { tint.gamma_multiply(0.92) });
        x += S + 8.0;
    }

    // The count is drawn first so its width is known, then the label is
    // clipped to what is left. A long category name must never run underneath
    // its own number.
    let mut right = rect.right() - 4.0;
    if let Some(n) = count {
        let galley = p.layout_no_wrap(
            n.to_string(),
            egui::FontId::proportional(11.5),
            if selected { tint } else { pal().muted },
        );
        let at = egui::pos2(right - galley.size().x, rect.center().y - galley.size().y / 2.0);
        p.galley(at, galley.clone(), pal().text);
        right -= galley.size().x + 10.0;
    }

    let avail = (right - x).max(10.0);
    let galley = p.layout(
        text.to_string(),
        egui::FontId::proportional(if strong { 12.5 } else { 12.5 }),
        text_color,
        avail,
    );
    p.galley(
        egui::pos2(x, rect.center().y - galley.size().y / 2.0),
        galley,
        text_color,
    );

    resp
}

/// A small triangle that says whether a group is open.
fn disclosure(p: &egui::Painter, rect: egui::Rect, open: bool, color: egui::Color32) {
    let c = rect.center();
    let s = 3.6;
    let pts = if open {
        vec![
            egui::pos2(c.x - s, c.y - s * 0.6),
            egui::pos2(c.x + s, c.y - s * 0.6),
            egui::pos2(c.x, c.y + s * 0.8),
        ]
    } else {
        vec![
            egui::pos2(c.x - s * 0.6, c.y - s),
            egui::pos2(c.x - s * 0.6, c.y + s),
            egui::pos2(c.x + s * 0.8, c.y),
        ]
    };
    p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
}

fn label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(12.0).color(pal().muted));
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
        egui::Button::new(egui::RichText::new(text).size(14.0).strong().color(pal().on_accent))
            .fill(pal().accent),
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
        // A TOTP code counts down and the lock screen animates, so repaint on a
        // timer rather than only on input. Slower when locked: nothing there
        // needs sixty frames a second, and a vault should not spin a laptop fan
        // while it sits waiting for a passphrase.
        ctx.request_repaint_after(Duration::from_millis(if self.db.is_some() {
            500
        } else {
            50
        }));

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

        // ── Design feedback loop ────────────────────────────────────────────
        //
        // KEYPAL_SHOT=<path> makes the window photograph itself: F12 (or the
        // env var alone, on the first frames) asks egui for the framebuffer and
        // writes a PNG. Wayland refuses X11 screen capture, so without this the
        // only way to see the interface is to ask the user for a screenshot —
        // which makes every visual change a round trip through another person.
        //
        // Debug affordance, not a feature: it is off unless the variable is
        // set, and it captures nothing a person looking at the screen cannot
        // already see. It is still worth being deliberate about — a vault that
        // can silently write images of its own unlocked contents would be a
        // poor vault, which is why there is no default path and no UI for it.
        if ctx.input(|i| i.key_pressed(egui::Key::F12)) {
            self.shot_requested = true;
        }
        if self.shot_requested {
            self.shot_requested = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
        }
        if let Some(path) = std::env::var("KEYPAL_SHOT").ok().filter(|p| !p.is_empty()) {
            // Optionally open a vault first, so the screens behind the lock can
            // be photographed too. Only ever reached with KEYPAL_SHOT set.
            if self.shot_countdown == 8 {
                // Outside the unlock block: the browser lives on the LOCK
                // screen, which is what you get when no vault is given.
                if std::env::var("KEYPAL_SHOT_BROWSE").is_ok() {
                    self.file_browser = true;
                    self.browse_dir = home();
                }
                if let (Ok(v), Ok(pw)) =
                    (std::env::var("KEYPAL_SHOT_VAULT"), std::env::var("KEYPAL_SHOT_PASS"))
                {
                    // KEYPAL_SHOT_LIGHT=1 photographs the light theme. Colour
                    // chosen per theme is exactly the kind of thing that goes
                    // wrong in only one of them, and stays wrong because only
                    // the other one is ever looked at.
                    if std::env::var("KEYPAL_SHOT_LIGHT").is_ok() {
                        self.light = true;
                        apply_theme(ctx, true);
                    }
                    self.manual_path = v;
                    self.passphrase = pw;
                    self.unlock();
                    if let Ok(panel) = std::env::var("KEYPAL_SHOT_PANEL") {
                        self.panel = match panel.as_str() {
                            "editor" => Panel::Editor,
                            "import" => Panel::ImportCsv,
                            "export" => Panel::Export,
                            "settings" => Panel::Settings,
                            "help" => Panel::Help,
                            "trash" => Panel::Trash,
                            _ => Panel::List,
                        };
                        // KEYPAL_SHOT_KIND=<number> picks a category: which
                        // form the editor shows, and which entry the detail
                        // pane opens. Without it only the default form can be
                        // seen, and sixteen forms that nobody can look at are
                        // sixteen forms nobody has checked.
                        let want = std::env::var("KEYPAL_SHOT_KIND")
                            .ok()
                            .and_then(|k| k.trim().parse::<i64>().ok())
                            .map(Kind::from_i64);
                        if let Some(k) = want {
                            self.draft.kind = k;
                            // On the list, the same variable narrows the
                            // navigation pane's category filter, so the
                            // filtered state can be photographed too.
                            if panel == "list" {
                                self.kind_filter = Some(k);
                            }
                        }
                        // KEYPAL_SHOT_SEARCH=<text> types into the search box.
                        if let Ok(q) = std::env::var("KEYPAL_SHOT_SEARCH") {
                            self.filter = q;
                        }
                        if panel == "detail" {
                            let row = self.rows.iter().find(|r| want.is_none_or(|k| r.kind == k));
                            self.open_entry = row.map(|r| r.id);
                            // KEYPAL_SHOT_REVEAL=1 opens every hidden field, so
                            // the revealed layout can be checked too — it is
                            // the state a masked field is never photographed in
                            // and therefore the one that breaks unnoticed.
                            if std::env::var("KEYPAL_SHOT_REVEAL").is_ok() {
                                self.reveal_password = true;
                                self.reveal_notes = true;
                                if let Some(r) = row {
                                    self.revealed_fields =
                                        r.fields.iter().map(|(k, _)| k.clone()).collect();
                                }
                            }
                        }
                    }
                }
            }
            self.shot_countdown = self.shot_countdown.saturating_sub(1);
            if self.shot_countdown == 1 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            }
            let image = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = image {
                let [w, h] = image.size;
                let mut png = Vec::new();
                {
                    let mut enc = png::Encoder::new(&mut png, w as u32, h as u32);
                    enc.set_color(png::ColorType::Rgba);
                    enc.set_depth(png::BitDepth::Eight);
                    if let Ok(mut writer) = enc.write_header() {
                        let bytes: Vec<u8> = image
                            .pixels
                            .iter()
                            .flat_map(|p| [p.r(), p.g(), p.b(), p.a()])
                            .collect();
                        let _ = writer.write_image_data(&bytes);
                    }
                }
                let _ = std::fs::write(&path, png);
                // `_exit`, not `exit`. The PNG is already written and closed,
                // so nothing is lost by skipping the atexit handlers — and
                // running them tears the Wayland connection down underneath
                // the clipboard thread, which is still blocked in
                // `wl_display_read_events`. That race segfaulted roughly one
                // run in three, after a correct screenshot: a crash that says
                // nothing about the program and makes every other crash report
                // harder to believe.
                unsafe { libc::_exit(0) };
            }
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

        // No title bar on the lock screen: the hero below already carries the
        // mark and the name, and showing both put the same two lines twice
        // within eighty pixels of each other.
        if self.db.is_some() || self.creating || self.show_help_locked {
            egui::TopBottomPanel::top("head")
                .frame(
                    egui::Frame::none()
                        .fill(pal().bg)
                        .inner_margin(egui::Margin::symmetric(20.0, 14.0)),
                )
                .show(ctx, |ui| self.header(ui));
        }

        // Nothing to report while locked, and an empty grey band at the foot of
        // the first screen reads as a rendering fault.
        if self.db.is_some() || !self.status.is_empty() {
        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::none().fill(pal().surface).inner_margin(egui::Margin::symmetric(20.0, 8.0)))
            .show(ctx, |ui| self.status_bar(ui));
        }

        if browsing {
            egui::SidePanel::left("nav")
                .resizable(true)
                .default_width(236.0)
                .frame(egui::Frame::none().fill(pal().bg).inner_margin(egui::Margin::symmetric(16.0, 14.0)))
                .show(ctx, |ui| self.sidebar(ui));

            // The detail pane holds a copy of the selected row rather than a
            // borrow, because drawing it mutates self (copy timestamps, panel
            // switches) and the borrow checker is right to refuse both at once.
            // The detail pane is always there, even with nothing selected.
            // Letting it appear and disappear made the list jump sideways on
            // every click, which is disorienting in a way people feel without
            // being able to name.
            let selected = self
                .open_entry
                .and_then(|id| self.rows.iter().find(|r| r.id == id).cloned());
            egui::SidePanel::right("details")
                .resizable(true)
                .default_width(376.0)
                .frame(
                    egui::Frame::none()
                        .fill(pal().bg)
                        .inner_margin(egui::Margin::symmetric(16.0, 14.0)),
                )
                .show(ctx, |ui| match selected {
                    Some(row) => {
                        egui::ScrollArea::vertical().show(ui, |ui| self.detail(ui, &row));
                    }
                    None => {
                        // The cipher rain, kept alive inside the unlocked
                        // window — but only here, in the one pane that is
                        // genuinely empty. Behind the list or the editor it
                        // would be moving texture under text somebody is
                        // reading, which is decoration bought with legibility.
                        //
                        // A third of the lock screen's intensity: at the lock
                        // screen it is the subject, here it is the wallpaper,
                        // and something you sit in front of all day must be
                        // quiet enough to ignore.
                        let t = ui.input(|i| i.time);
                        let rect = ui.available_rect_before_wrap();
                        cipher_rain(ui, rect, t, 0.16);
                        // Repaint only while this pane is showing, so an idle
                        // window with an entry open is not animating anything.
                        ui.ctx().request_repaint_after(Duration::from_millis(60));

                        ui.add_space(ui.available_height() * 0.30);
                        ui.vertical_centered(|ui| {
                            logo(ui, 46.0);
                            ui.add_space(12.0);
                            ui.label(
                                egui::RichText::new("Nothing selected")
                                    .size(14.0)
                                    .color(pal().text),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new("Pick an entry to see it here")
                                    .size(11.5)
                                    .color(pal().muted),
                            );
                        });
                    }
                });
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(pal().bg).inner_margin(egui::Margin::symmetric(16.0, 14.0)))
            .show(ctx, |ui| {
                if self.db.is_some() {
                    self.unlocked(ui);
                } else if self.show_help_locked {
                    self.help_view(ui);
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
                    Level::Ok => pal().ok,
                    Level::Bad => pal().danger,
                    Level::None => pal().muted,
                };
                ui.label(egui::RichText::new(&self.status).size(12.0).color(color));
            } else if let Some(p) = &self.vault_path {
                ui.label(egui::RichText::new(p.display().to_string()).size(11.0).color(pal().muted));
            }

            if self.db.is_some() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let left = IDLE_LOCK.saturating_sub(self.last_input.elapsed()).as_secs();
                    let (m, sec) = (left / 60, left % 60);
                    // Warn while there is still time to do something about it.
                    let color = if left <= 60 { pal().warn } else { pal().muted };
                    ui.label(
                        egui::RichText::new(format!("locks in {m}:{sec:02}"))
                            .size(12.0)
                            .color(color),
                    );
                    ui.add_space(12.0);
                    let report = self.security_report();
                    let sc = report.score;
                    let color = if sc >= 85 { pal().ok } else if sc >= 60 { pal().warn } else { pal().danger };
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
                kind: r.kind,
            })
            .collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        valu::audit::audit(&inputs, now)
    }

    /// Left pane: tag filters with counts, and the health summary.
    /// The navigation pane: search, then the vault organised by family.
    ///
    /// Everything here works on `self.rows`, which is already decrypted and in
    /// memory. The counts, the groups and the search are arithmetic over that —
    /// nothing new is written down, no index of names is built, and nothing
    /// touches the file. A sidebar that had to be fast by keeping a plaintext
    /// index beside the ciphertext would be a sidebar that undoes the vault.
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let total = self.rows.len();

        // ── Search, at the top of the pane ────────────────────────────────
        // It lives here rather than in the toolbar because searching and
        // narrowing by category are the same act — finding the thing — and
        // splitting them across two panes made the user look in two places.
        let search = ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .hint_text("Search…   ( / )")
                .desired_width(f32::INFINITY)
                .margin(egui::Margin::symmetric(10.0, 7.0)),
        );
        if self.focus_search {
            search.request_focus();
            self.focus_search = false;
        }
        if !self.filter.is_empty() {
            // How much the search is hiding, said plainly. Otherwise a stale
            // filter looks like a half-empty vault.
            let shown = self.matching_rows().len();
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("{shown} of {total}"))
                        .size(11.0)
                        .color(pal().muted),
                );
                if ui.small_button("clear").clicked() {
                    self.filter.clear();
                }
            });
        }

        ui.add_space(10.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // ── Totals ───────────────────────────────────────────────────
            let all_selected = self.tag_filter.is_none() && self.kind_filter.is_none();
            if nav_row(ui, Some(Icon::Stack), "All entries", Some(total), all_selected,
                       pal().accent, 2.0, true).clicked()
            {
                self.tag_filter = None;
                self.kind_filter = None;
            }

            let favs = self.rows.iter().filter(|r| r.favorite).count();
            if favs > 0 {
                let on = self.tag_filter.as_deref() == Some("\u{2605}");
                if nav_row(ui, Some(Icon::Shield), "Favourites", Some(favs), on,
                           pal().accent, 2.0, true).clicked()
                {
                    self.tag_filter = if on { None } else { Some("\u{2605}".into()) };
                }
            }

            // ── Categories, by family ────────────────────────────────────
            let mut per_kind: std::collections::HashMap<Kind, usize> = Default::default();
            for r in &self.rows {
                *per_kind.entry(r.kind).or_insert(0) += 1;
            }

            ui.add_space(12.0);
            label(ui, "CATEGORIES");
            ui.add_space(3.0);

            for g in kind::GROUPS {
                let subtotal: usize = g.kinds().iter().filter_map(|k| per_kind.get(k)).sum();
                // A family with nothing in it is a drawer with no contents.
                // Showing all four regardless would push the tags and the
                // health score off the bottom of a pane that is mostly empty.
                if subtotal == 0 {
                    continue;
                }
                let open = !self.collapsed_groups.contains(&g);

                let resp = nav_row(ui, None, g.label(), Some(subtotal), false,
                                   pal().accent, 16.0, true);
                // The triangle is painted after the row so it sits on top of
                // the hover fill rather than under it.
                disclosure(
                    ui.painter(),
                    egui::Rect::from_center_size(
                        egui::pos2(resp.rect.left() + 7.0, resp.rect.center().y),
                        egui::vec2(12.0, 12.0),
                    ),
                    open,
                    pal().muted,
                );
                if resp.clicked() {
                    if open {
                        self.collapsed_groups.insert(g);
                    } else {
                        self.collapsed_groups.remove(&g);
                    }
                }
                if !open {
                    continue;
                }

                for k in g.kinds() {
                    let Some(n) = per_kind.get(k).copied() else { continue };
                    let on = self.kind_filter == Some(*k);
                    if nav_row(ui, Some(kind_icon(*k)), k.label(), Some(n), on,
                               kind_color(*k), 16.0, true).clicked()
                    {
                        // Clicking the active one clears it, so the filter can
                        // be undone where it was set rather than only from the
                        // "All entries" row.
                        self.kind_filter = if on { None } else { Some(*k) };
                    }
                }
                ui.add_space(2.0);
            }

            // ── Tags ─────────────────────────────────────────────────────
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
                ui.add_space(10.0);
                label(ui, "TAGS");
                ui.add_space(3.0);
                for (tag, n) in counts {
                    let on = self.tag_filter.as_deref() == Some(tag.as_str());
                    if nav_row(ui, Some(Icon::Tag), &tag, Some(n), on, pal().accent, 2.0, true)
                        .clicked()
                    {
                        self.tag_filter = if on { None } else { Some(tag.clone()) };
                    }
                }
            }

            // ── Health ───────────────────────────────────────────────────
            ui.add_space(14.0);
            label(ui, "HEALTH");
            ui.add_space(4.0);
            let report = self.security_report();
            let sc = report.score;
            let color =
                if sc >= 85 { pal().ok } else if sc >= 60 { pal().warn } else { pal().danger };
            ui.label(egui::RichText::new(format!("{sc}")).size(30.0).strong().color(color));
            ui.add_space(2.0);
            // Slim: this is a status line, not the subject of the pane. At full
            // height it was a block of colour that pulled the eye away from the
            // list, which is what the window is actually for.
            ui.add(
                egui::ProgressBar::new(sc as f32 / 100.0)
                    .desired_width(ui.available_width().min(170.0))
                    .desired_height(5.0)
                    .fill(color),
            );
            ui.add_space(6.0);
            for (n, what, c) in [
                (report.reused, "reused", pal().danger),
                (report.weak, "weak", pal().warn),
                (report.stale, "over a year old", pal().muted),
            ] {
                if n > 0 {
                    ui.label(egui::RichText::new(format!("{n} {what}")).size(11.0).color(c));
                }
            }
            if report.findings.is_empty() && total > 0 {
                ui.label(egui::RichText::new("nothing to fix").size(11.0).color(pal().ok));
            }
            ui.add_space(8.0);
        });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            logo(ui, 32.0);
            ui.add_space(10.0);
            ui.vertical(|ui| {
                ui.add_space(1.0);
                ui.label(
                    egui::RichText::new("Keypal")
                        .size(21.0)
                        .strong()
                        .color(pal().text),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "security vault  ·  v{}  ·  by Rafael Kyra",
                        env!("CARGO_PKG_VERSION")
                    ))
                        .size(10.5)
                        .color(pal().muted),
                );
            });
            if self.db.is_some() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icon_button(ui, Icon::Lock, "Lock") {
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
        // Down the left edge only, at low opacity: present enough to suggest
        // the machinery, quiet enough that the passphrase field stays the
        // subject of the screen.
        let full = ui.max_rect();
        let strip = egui::Rect::from_min_size(
            full.min,
            egui::vec2((full.width() * 0.13).min(120.0), full.height()),
        );
        let t = ui.input(|i| i.time);
        // The surge is honest: it runs while Argon2 is actually working, which
        // takes real time, so the animation reports the wait rather than
        // decorating an instant.
        let busy = self.unlocking_since.map(|s| s.elapsed().as_secs_f32() < 2.0).unwrap_or(false);
        cipher_rain(ui, strip, t, if busy { 0.55 } else { 0.16 });

        // The first screen anyone sees. It was a grey form on a grey field;
        // now it carries the mark and one line saying what this is, because a
        // lock screen with no identity reads as an error dialog.
        ui.add_space(26.0);
        ui.vertical_centered(|ui| {
            logo(ui, 52.0);
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Keypal").size(26.0).strong().color(pal().text));
            ui.add_space(3.0);
            ui.label(
                egui::RichText::new("Your keys and passwords, kept on this machine and nowhere else")
                    .size(12.5)
                    .color(pal().muted),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!(
                    "version {}  ·  by Rafael Kyra",
                    env!("CARGO_PKG_VERSION")
                ))
                .size(11.0)
                .color(pal().muted),
            );
        });
        ui.add_space(18.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
        form(ui, |ui| {
            label(ui, "YOUR VAULTS");
            ui.add_space(4.0);
            // Where they were found, said out loud. "Your vaults" with no
            // folder beside it leaves the user unable to answer the one
            // question that matters for a backup: where is my file?
            ui.label(
                egui::RichText::new(format!("found in {}", home().display()))
                    .size(11.0)
                    .color(pal().muted),
            );
            ui.add_space(4.0);
            if self.vaults.is_empty() {
                ui.label(egui::RichText::new("None found in your home folder.").color(pal().muted));
            } else {
                let vaults = self.vaults.clone();
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    for path in vaults {
                        let name = path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.display().to_string());
                        let chosen = self.selected.as_ref() == Some(&path);
                        let size = std::fs::metadata(&path)
                            .map(|m| format!("{} KB", m.len() / 1024))
                            .unwrap_or_default();
                        let t = if chosen {
                            egui::RichText::new(format!("  {name}   {size}"))
                                .color(pal().accent)
                                .strong()
                        } else {
                            egui::RichText::new(format!("  {name}   {size}")).color(pal().text)
                        };
                        if ui.selectable_label(chosen, t).clicked() {
                            self.selected = Some(path.clone());
                            self.manual_path.clear();
                            self.file_browser = false;
                        }
                    }
                });
            }

            ui.add_space(10.0);
            label(ui, "OR A PATH");
            ui.horizontal(|ui| {
                let w = (ui.available_width() - 96.0).max(120.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.manual_path)
                        .hint_text("/home/you/vault.db")
                        .desired_width(w)
                        .margin(egui::Margin::symmetric(10.0, 7.0)),
                );
                if ui.button(if self.file_browser { "Close" } else { "Browse…" }).clicked() {
                    self.file_browser = !self.file_browser;
                    if self.file_browser && self.browse_dir.as_os_str().is_empty() {
                        self.browse_dir = home();
                    }
                }
            });
            if self.file_browser {
                self.browse_view(ui);
            }

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
                .color(pal().muted),
            );

            ui.add_space(8.0);
            match self.target_path() {
                Some(p) => ui.label(
                    egui::RichText::new(format!("Will open: {}", p.display()))
                        .size(11.0)
                        .color(pal().muted),
                ),
                None => ui.label(
                    egui::RichText::new("Pick a vault above, or type a path")
                        .size(11.0)
                        .color(pal().warn),
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("What is this?").clicked() {
                        self.panel = Panel::Help;
                        self.show_help_locked = true;
                    }
                });
            });
        });
        });
    }

    /// A file browser, built rather than borrowed.
    ///
    /// There is still no native dialog: `rfd` wants Wayland development
    /// packages this machine does not have, and needing a system package
    /// installed before you can open your own vault is a worse answer than not
    /// needing one. This reads directory names and nothing else — it never
    /// opens a file, so browsing to a folder full of strangers' data parses
    /// none of it.
    ///
    /// Only directories and `.db` files are listed. Showing every file would
    /// bury the two or three that can actually be opened.
    fn browse_view(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        egui::Frame::none()
            .fill(pal().surface_hi)
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::symmetric(10.0, 8.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Plain words, no arrow glyph: the embedded monospace
                    // font has no U+2191 and drew it as an empty box.
                    if ui.small_button("Up").clicked() {
                        if let Some(parent) = self.browse_dir.parent() {
                            self.browse_dir = parent.to_path_buf();
                        }
                    }
                    if ui.small_button("Home").clicked() {
                        self.browse_dir = home();
                    }
                    ui.label(
                        egui::RichText::new(self.browse_dir.display().to_string())
                            .size(11.0)
                            .color(pal().muted),
                    );
                });
                ui.add_space(4.0);

                // Read once per frame. A directory that cannot be read says so
                // rather than showing an empty list, which would look like an
                // empty folder and send the user hunting in the wrong place.
                let mut dirs: Vec<PathBuf> = Vec::new();
                let mut files: Vec<PathBuf> = Vec::new();
                match std::fs::read_dir(&self.browse_dir) {
                    Ok(entries) => {
                        for e in entries.flatten() {
                            let p = e.path();
                            let hidden = p
                                .file_name()
                                .map(|n| n.to_string_lossy().starts_with('.'))
                                .unwrap_or(false);
                            if hidden {
                                continue;
                            }
                            if p.is_dir() {
                                dirs.push(p);
                            } else if p.extension().is_some_and(|x| x == "db") {
                                files.push(p);
                            }
                        }
                    }
                    Err(e) => {
                        ui.label(
                            egui::RichText::new(format!("cannot read this folder — {e}"))
                                .size(11.5)
                                .color(pal().danger),
                        );
                    }
                }
                dirs.sort();
                files.sort();

                if dirs.is_empty() && files.is_empty() {
                    ui.label(
                        egui::RichText::new("nothing here to open")
                            .size(11.5)
                            .color(pal().muted),
                    );
                }

                egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                    for d in dirs {
                        let name = d.file_name().unwrap_or_default().to_string_lossy().to_string();
                        if nav_row(ui, None, &format!("  {name}/"), None, false,
                                   pal().accent, 4.0, false).clicked()
                        {
                            self.browse_dir = d.clone();
                        }
                    }
                    for f in files {
                        let name = f.file_name().unwrap_or_default().to_string_lossy().to_string();
                        let vault = looks_like_vault(&f);
                        let kb = std::fs::metadata(&f).map(|m| (m.len() / 1024) as usize).unwrap_or(0);
                        // A .db that is not a Keypal vault is still listed, but
                        // greyed: hiding it would leave the user staring at a
                        // folder they know contains the file.
                        let resp = nav_row(
                            ui,
                            Some(if vault { Icon::Lock } else { Icon::Sheet }),
                            &name,
                            Some(kb),
                            self.manual_path == f.display().to_string(),
                            if vault { pal().accent } else { pal().muted },
                            4.0,
                            vault,
                        );
                        if resp.clicked() {
                            self.manual_path = f.display().to_string();
                            self.selected = None;
                            self.file_browser = false;
                        }
                    }
                });
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("sizes in KB · only folders and .db files are shown")
                        .size(10.5)
                        .color(pal().muted),
                );
            });
    }

    fn create_view(&mut self, ui: &mut egui::Ui) {
        form(ui, |ui| {
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
                .color(pal().warn),
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

    /// The rows that survive the search box and the two filters.
    ///
    /// One implementation, because the navigation pane reports how many match
    /// and the list shows them. Two copies of this would eventually disagree,
    /// and the pane would confidently print a number the list contradicts.
    fn matching_rows(&self) -> Vec<Row> {
        let needle = self.filter.to_lowercase();
        self.rows
            .iter()
            .filter(|r| {
                // Search covers every field the user can see, so "the gmail
                // one" is findable by name, login, address or label.
                needle.is_empty()
                    || r.name.to_lowercase().contains(&needle)
                    || r.username.to_lowercase().contains(&needle)
                    || r.uri.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                    || r.tags.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                    // The category name too: typing "card" should find the
                    // bank cards even though no entry is called that.
                    || r.kind.label().to_lowercase().contains(&needle)
            })
            .filter(|r| self.kind_filter.is_none_or(|k| r.kind == k))
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
            .collect()
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
            Panel::Settings => return self.settings_view(ui),
            Panel::Help => return self.help_view(ui),
            Panel::List => {}
        }

        // Wrapping, not clipping. At the widths the three panes leave, a fixed
        // row silently cut "More" down to "Mor" — a button nobody can read is a
        // button nobody presses.
        // No search box here: it lives at the top of the navigation pane, with
        // the categories, because narrowing by word and narrowing by kind are
        // the same act. Moving it also gave this row the space it never had —
        // "More" used to be clipped to "Mor".
        ui.horizontal_wrapped(|ui| {
            if icon_button(ui, Icon::Plus, "Add") {
                self.draft = Draft::default();
                self.panel = Panel::Editor;
                self.open_entry = None;
            }
            ui.menu_button("Import  v", |ui| {
                if ui.button("From a CSV export…").clicked() {
                    self.panel = Panel::ImportCsv;
                    ui.close_menu();
                }
                if ui.button("From a KeePass .kdbx…").clicked() {
                    self.panel = Panel::Import;
                    ui.close_menu();
                }
            });
            ui.menu_button("More  v", |ui| {
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
                if ui.button("How this protects you…").clicked() {
                    self.panel = Panel::Help;
                    ui.close_menu();
                }
                if ui.button("Settings…").clicked() {
                    self.retention_input = self
                        .db
                        .as_ref()
                        .map(|d| d.retention_days().to_string())
                        .unwrap_or_else(|| "0".into());
                    self.panel = Panel::Settings;
                    ui.close_menu();
                }
            });
            // Inline, NOT in a right-aligned sub-layout. A `right_to_left`
            // scope inside a wrapped row claims all the width still going,
            // leaving the button before it whatever is left — which is how
            // "More" spent two sessions being drawn as "Mor".
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
        ui.add_space(10.0);

        let mut shown = self.matching_rows();
        match self.sort {
            Sort::Name => shown.sort_by_key(|r| r.name.to_lowercase()),
            Sort::Recent => shown.sort_by(|a, b| b.id.cmp(&a.id)),
        }

        let total = self.rows.len();
        card(ui, |ui| {
            if total == 0 {
                ui.add_space(28.0);
                ui.vertical_centered(|ui| {
                    logo(ui, 54.0);
                    ui.add_space(14.0);
                    ui.label(
                        egui::RichText::new("Your vault is empty")
                            .size(17.0)
                            .strong()
                            .color(pal().text),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "Add a password, a key, a card or a note — or bring what you already have.",
                        )
                        .size(12.5)
                        .color(pal().muted),
                    );
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        ui.add_space(ui.available_width() / 2.0 - 130.0);
                        if primary(ui, "Add an entry") {
                            self.draft = Draft::default();
                            self.panel = Panel::Editor;
                        }
                        if ui.button("Import…").clicked() {
                            self.panel = Panel::ImportCsv;
                        }
                    });
                    ui.add_space(24.0);
                });
                return;
            }
            if shown.is_empty() {
                ui.label(egui::RichText::new("Nothing matches that search").color(pal().muted));
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                let last = shown.len().saturating_sub(1);
                for (i, row) in shown.iter().enumerate() {
                    let selected = self.open_entry == Some(row.id);
                    // The whole row is the target. A dedicated Open button asks
                    // the user to aim at 60 pixels when 700 were available.
                    // A Frame, not a hand-painted rectangle. The first attempt
                    // painted into `available_rect_before_wrap()`, which is the
                    // whole remaining panel rather than this row — so selecting
                    // an entry flooded everything below it with colour. A Frame
                    // is sized by its own contents, which is the only thing that
                    // can be correct here.
                    let resp = egui::Frame::none()
                        .fill(if selected {
                            pal().accent.linear_multiply(0.16)
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .rounding(egui::Rounding::same(9.0))
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                avatar(ui, &row.name, 30.0);
                                ui.add_space(4.0);
                                ui.vertical(|ui| {
                                    ui.label(
                                        egui::RichText::new(&row.name)
                                            .size(14.0)
                                            .strong()
                                            .color(if selected { pal().accent } else { pal().text }),
                                    );
                                    // The category on the second line, as a
                                    // shape and a word. Without it a mixed
                                    // vault reads as one undifferentiated list
                                    // and the categories may as well not exist.
                                    ui.horizontal(|ui| {
                                        icon(ui, kind_icon(row.kind), 11.0, kind_color(row.kind));
                                        ui.add_space(4.0);
                                        let mut sub = row.kind.label().to_string();
                                        if !row.username.is_empty() {
                                            sub.push_str("  ·  ");
                                            sub.push_str(&row.username);
                                        }
                                        if row.totp.is_some() && row.kind != Kind::Authenticator {
                                            sub.push_str("  ·  2FA");
                                        }
                                        ui.label(
                                            egui::RichText::new(sub).size(11.0).color(pal().muted),
                                        );
                                    });
                                });
                            });
                        })
                        .response
                        .interact(egui::Sense::click());

                    if resp.hovered() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                    if resp.clicked() {
                        self.open_entry = Some(row.id);
                        self.reveal_password = false;
                        self.reveal_notes = false;
                        self.revealed_fields.clear();
                    }
                    if i != last {
                        ui.add_space(3.0);
                    }
                }
            });
        });
    }

    fn detail(&mut self, ui: &mut egui::Ui, row: &Row) {
        let mut copy_now: Option<String> = None;
        card(ui, |ui| {
            // Name on its own line. Sharing a row with four buttons meant the
            // name was the thing that got clipped — the one label that tells
            // you which entry you are looking at.
            ui.horizontal(|ui| {
                avatar(ui, &row.name, 34.0);
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(&row.name).size(18.0).strong().color(pal().accent));
                    // What this is, under what it is called. Two entries named
                    // "Acme" — the login and the API key — are otherwise
                    // indistinguishable at the top of the pane.
                    ui.horizontal(|ui| {
                        icon(ui, kind_icon(row.kind), 12.0, kind_color(row.kind));
                        ui.add_space(3.0);
                        ui.label(
                            egui::RichText::new(row.kind.label())
                                .size(11.0)
                                .color(kind_color(row.kind)),
                        );
                    });
                });
            });
            ui.add_space(10.0);

            // The thing people came for, as one big button: nine times out of
            // ten opening an entry means copying its secret, and that was a
            // 60-pixel "Copy" three rows down among five identical ones.
            if let Some(what) = row.kind.secret_label() {
                if !row.password.is_empty() {
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(
                                [ui.available_width().min(230.0), 34.0],
                                egui::Button::new(
                                    egui::RichText::new(format!("Copy {}", what.to_lowercase()))
                                        .size(13.5)
                                        .strong()
                                        .color(pal().on_accent),
                                )
                                .fill(pal().accent),
                            )
                            .clicked()
                        {
                            copy_now = Some(row.password.clone());
                        }
                    });
                    ui.add_space(8.0);
                }
            }

            // Edit is the common action and leads. Delete used to sit second,
            // one slot from the button people reach for without looking —
            // it is now behind a menu, which is where an irreversible thing
            // belongs.
            ui.horizontal_wrapped(|ui| {
                    if icon_button(ui, Icon::Edit, "Edit") {
                        self.draft = Draft {
                            id: Some(row.id),
                            kind: row.kind,
                            name: row.name.clone(),
                            username: row.username.clone(),
                            password: row.password.clone(),
                            uri: row.uri.clone().unwrap_or_default(),
                            totp: row.totp.clone().unwrap_or_default(),
                            tags: row.tags.clone().unwrap_or_default(),
                            notes: row.notes.clone().unwrap_or_default(),
                            show_password: false,
                            fields: row.fields.iter().cloned().collect(),
                            shown_fields: Default::default(),
                        };
                        self.panel = Panel::Editor;
                    }
                    if icon_button(ui, Icon::Clock, "History") {
                        self.load_history(row.id);
                        self.panel = Panel::History(row.id);
                    }
                    ui.menu_button("More  v", |ui| {
                        if ui.button("Move to trash…").clicked() {
                            self.panel = Panel::Confirm(row.id, row.name.clone());
                            ui.close_menu();
                        }
                    });
                    if icon_button(ui, Icon::Close, "Close") {
                        self.open_entry = None;
                    }
            });
            ui.add_space(10.0);

            if !row.username.is_empty() {
                label(ui, &row.kind.username_label().unwrap_or("USERNAME").to_uppercase());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&row.username).size(14.0).monospace());
                    if ui.small_button("Copy").clicked() {
                        copy_now = Some(row.username.clone());
                    }
                });
                ui.add_space(6.0);
            }

            if let Some(secret_label) = row.kind.secret_label() {
                label(ui, &secret_label.to_uppercase());
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
                if row.kind.audits_password_strength() {
                    meter(ui, &row.password);
                }
            }

            // The category's own fields, in the order the category declares
            // them rather than the order they happen to sit in the blob.
            for spec in row.kind.extra() {
                let Some(value) = kind::field_value(&row.fields, spec.key).filter(|v| !v.is_empty())
                else {
                    continue;
                };
                ui.add_space(6.0);
                label(ui, &spec.label.to_uppercase());
                let key = spec.key.to_string();
                let revealed = !spec.secret || self.revealed_fields.contains(&key);

                // The buttons, then the value. For a one-line field they share
                // a row; for a private key they cannot — a multi-line value
                // pushes the buttons down beside its last line, where they read
                // as belonging to whatever comes next.
                let mut controls = |ui: &mut egui::Ui, revealed_now: bool| {
                    if spec.secret
                        && ui.small_button(if revealed_now { "Hide" } else { "Show" }).clicked()
                    {
                        if revealed_now {
                            self.revealed_fields.remove(&key);
                        } else {
                            self.revealed_fields.insert(key.clone());
                            if let Some(db) = self.db.as_ref() {
                                db.log_access(Some(row.id), "reveal");
                            }
                        }
                    }
                    if ui.small_button("Copy").clicked() {
                        copy_now = Some(value.to_string());
                    }
                };

                let masked = "•".repeat(value.chars().count().min(24));
                let shown = if revealed { value } else { masked.as_str() };

                if spec.multiline && revealed {
                    ui.horizontal(|ui| controls(ui, revealed));
                    ui.add_space(2.0);
                    // Its own frame, so a pasted key is visibly one block
                    // rather than text that happens to have line breaks.
                    egui::Frame::none()
                        .fill(pal().surface_hi)
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(shown).size(12.0).monospace());
                        });
                } else {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new(shown).size(13.0).monospace());
                        controls(ui, revealed);
                    });
                }
            }

            if let Some(uri) = &row.uri {
                ui.add_space(6.0);
                label(ui, &row.kind.uri_label().unwrap_or("URL").to_uppercase());
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
                            .fill(pal().surface_hi)
                            .rounding(egui::Rounding::same(10.0))
                            .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(t).size(11.0).color(pal().accent));
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
                                    .color(if hot { pal().warn } else { pal().ok }),
                            );
                            if ui.small_button("Copy").clicked() {
                                copy_now = Some(code.clone());
                            }
                            ui.label(
                                egui::RichText::new(format!("{left}s"))
                                    .size(12.0)
                                    .color(if hot { pal().warn } else { pal().muted }),
                            );
                        });
                        ui.add(
                            egui::ProgressBar::new(left as f32 / totp::PERIOD as f32)
                                .desired_width(200.0)
                                .fill(if hot { pal().warn } else { pal().accent }),
                        );
                    }
                    Err(_) => {
                        ui.label(
                            egui::RichText::new("stored two-factor secret is unreadable")
                                .color(pal().danger),
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

    /// The sixteen categories as a grid of shapes, not a dropdown.
    ///
    /// A dropdown hides fifteen of the sixteen until you open it, so choosing
    /// means reading a list from memory of what might be in it. Laid out at
    /// once, the choice is recognition rather than recall — and the icons make
    /// it recognition by shape, which is faster than by word.
    fn kind_picker(&mut self, ui: &mut egui::Ui) {
        const PER_ROW: usize = 4;
        const CELL: f32 = 118.0;

        for chunk in kind::ALL.chunks(PER_ROW) {
            ui.horizontal(|ui| {
                for k in chunk {
                    let k = *k;
                    let on = self.draft.kind == k;
                    let tint = kind_color(k);

                    let (rect, resp) = ui.allocate_exact_size(
                        egui::vec2(CELL, 34.0),
                        egui::Sense::click(),
                    );
                    let hot = resp.hovered();
                    let fill = if on {
                        tint.linear_multiply(0.30)
                    } else if hot {
                        pal().surface_hi
                    } else {
                        egui::Color32::TRANSPARENT
                    };
                    ui.painter().rect_filled(rect, egui::Rounding::same(8.0), fill);
                    if on {
                        ui.painter().rect_stroke(
                            rect,
                            egui::Rounding::same(8.0),
                            egui::Stroke::new(1.2_f32, tint),
                        );
                    }
                    // Drawn straight into the allocated rectangle: a nested
                    // horizontal layout here would re-measure and let the
                    // longest label push its neighbours out of the grid.
                    let mut child = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(rect.shrink2(egui::vec2(8.0, 0.0)))
                            .layout(egui::Layout::left_to_right(egui::Align::Center)),
                    );
                    icon(&mut child, kind_icon(k), 16.0, tint);
                    child.add_space(6.0);
                    child.label(
                        egui::RichText::new(k.label())
                            .size(11.5)
                            .color(if on { pal().text } else { pal().muted }),
                    );

                    if hot {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                    if resp.clicked() {
                        self.draft.kind = k;
                    }
                }
            });
            ui.add_space(3.0);
        }
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        form(ui, |ui| {
            let editing = self.draft.id.is_some();
            ui.label(
                egui::RichText::new(if editing { "Edit entry" } else { "New entry" })
                    .size(17.0)
                    .strong(),
            );
            ui.add_space(8.0);

            // The category comes FIRST, because everything below it depends on
            // the answer. Asking for it last — or hiding it in a menu — is what
            // turns a categorised vault back into a list of website logins with
            // an unused dropdown.
            label(ui, "WHAT IS THIS?");
            ui.add_space(2.0);
            self.kind_picker(ui);

            ui.add_space(10.0);
            let k = self.draft.kind;

            label(ui, "NAME");
            let mut name = self.draft.name.clone();
            field(ui, &mut name, k.name_hint(), false);
            self.draft.name = name;

            if let Some(user_label) = k.username_label() {
                ui.add_space(8.0);
                label(ui, &user_label.to_uppercase());
                let mut user = self.draft.username.clone();
                let hint = if k == Kind::Email { "you@example.com" } else { "you" };
                field(ui, &mut user, hint, false);
                self.draft.username = user;
            }

            if let Some(secret_label) = k.secret_label() {
                ui.add_space(8.0);
                label(ui, &secret_label.to_uppercase());
                ui.horizontal(|ui| {
                    let mut pw = self.draft.password.clone();
                    // Generating a card number or a licence key is nonsense;
                    // the button only appears where a fresh random secret is a
                    // thing the user could actually want.
                    let generatable = k.audits_password_strength();
                    let reserved = if generatable { 190.0 } else { 110.0 };
                    let w = (ui.available_width() - reserved).max(120.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut pw)
                            .password(!self.draft.show_password)
                            .hint_text(secret_label.to_lowercase())
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
                    if generatable && ui.button("Generate").clicked() {
                        self.draft.password = generate_password();
                        self.draft.show_password = true;
                    }
                });
                // The strength meter only where strength is a meaningful thing
                // to report. A bar telling someone their card number is weak is
                // advice they cannot take.
                if k.audits_password_strength() {
                    meter(ui, &self.draft.password.clone());
                }
            }

            // The category's own fields, in the order the category declares.
            for spec in k.extra() {
                ui.add_space(8.0);
                label(ui, &spec.label.to_uppercase());
                let key = spec.key.to_string();
                let mut value = self.draft.field(&key);
                if spec.multiline {
                    let revealed = self.draft.shown_fields.contains(&key);
                    if spec.secret && !revealed {
                        if ui.small_button(format!("Show {}", spec.label.to_lowercase())).clicked() {
                            self.draft.shown_fields.insert(key.clone());
                        }
                        if !value.is_empty() {
                            ui.label(
                                egui::RichText::new(format!("{} characters stored", value.chars().count()))
                                    .size(11.0)
                                    .color(pal().muted),
                            );
                        }
                    } else {
                        ui.add(
                            egui::TextEdit::multiline(&mut value)
                                .hint_text(spec.hint)
                                .desired_width(f32::INFINITY)
                                .desired_rows(4),
                        );
                        if spec.secret && ui.small_button("Hide").clicked() {
                            self.draft.shown_fields.remove(&key);
                        }
                    }
                } else if spec.secret {
                    let revealed = self.draft.shown_fields.contains(&key);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut value)
                                .password(!revealed)
                                .hint_text(spec.hint)
                                // Reserve enough for the button. Too tight and
                                // the row overflows, which widens the whole
                                // form — so the panel jumped a few pixels
                                // sideways every time the category changed.
                                .desired_width((ui.available_width() - 84.0).max(120.0))
                                .margin(egui::Margin::symmetric(10.0, 7.0)),
                        );
                        if ui.small_button(if revealed { "Hide" } else { "Show" }).clicked() {
                            if revealed {
                                self.draft.shown_fields.remove(&key);
                            } else {
                                self.draft.shown_fields.insert(key.clone());
                            }
                        }
                    });
                } else {
                    field(ui, &mut value, spec.hint, false);
                }
                self.draft.fields.insert(key, value);
            }

            if let Some(uri_label) = k.uri_label() {
                ui.add_space(8.0);
                label(ui, &format!("{} (OPTIONAL)", uri_label.to_uppercase()));
                let mut uri = self.draft.uri.clone();
                field(ui, &mut uri, "https://github.com", false);
                self.draft.uri = uri;
            }

            ui.add_space(8.0);
            label(ui, "TAGS (optional, comma separated)");
            let mut tg = self.draft.tags.clone();
            field(ui, &mut tg, "work, email", false);
            self.draft.tags = tg;

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                // For a secure note the note is not an extra — it is the entry.
                label(ui, if k == Kind::SecureNote { "NOTE" } else { "NOTES (optional)" });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Load a text file…").clicked() {
                        self.loading_text = !self.loading_text;
                    }
                });
            });
            if self.loading_text {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.text_path)
                            .hint_text("/home/you/key.txt")
                            .desired_width(ui.available_width() - 90.0)
                            .margin(egui::Margin::symmetric(10.0, 7.0)),
                    );
                    if ui.button("Load").clicked() {
                        let path = self.text_path.trim().to_string();
                        match valu::import::read_text_file(std::path::Path::new(&path)) {
                            Ok(text) => {
                                // Appended, never overwritten: silently
                                // replacing whatever the user had already typed
                                // is not a load, it is a loss.
                                if !self.draft.notes.is_empty() {
                                    self.draft.notes.push_str("\n\n");
                                }
                                self.draft.notes.push_str(&text);
                                let kb = text.len() / 1024;
                                self.set(format!("Loaded {kb} KB into notes"), Level::Ok);
                                self.loading_text = false;
                                self.text_path.clear();
                            }
                            Err(e) => self.set(e.to_string(), Level::Bad),
                        }
                    }
                });
                ui.label(
                    egui::RichText::new(
                        "Any text file up to 1 MB — an SSH key, an API token, a recovery \
                         sheet. It is encrypted with the rest of the entry. For anything \
                         larger, or for binary files, use an encrypted volume and keep \
                         its passphrase here.",
                    )
                    .size(11.0)
                    .color(pal().muted),
                );
                ui.add_space(4.0);
            }
            let mut nt = self.draft.notes.clone();
            ui.add(
                egui::TextEdit::multiline(&mut nt)
                    .hint_text("recovery codes, security answers…")
                    .desired_width(f32::INFINITY)
                    .desired_rows(3),
            );
            self.draft.notes = nt;

            if k.uses_totp() {
                ui.add_space(8.0);
                // For an authenticator this is not an optional extra — it is
                // the entry.
                label(
                    ui,
                    if k == Kind::Authenticator {
                        "TWO-FACTOR SECRET"
                    } else {
                        "TWO-FACTOR SECRET (optional)"
                    },
                );
                let mut t = self.draft.totp.clone();
                field(ui, &mut t, "base32 secret, or an otpauth:// link", false);
                self.draft.totp = t;
                ui.label(
                    egui::RichText::new("Paste what the site shows next to its QR code.")
                        .size(11.0)
                        .color(pal().muted),
                );
            }

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
        form(ui, |ui| {
            ui.label(egui::RichText::new(format!("Password history — {name}")).size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Newest first. Restoring puts the old password back and \
                                     records the current one in its place.")
                    .size(12.0)
                    .color(pal().muted),
            );
            ui.add_space(10.0);

            if self.history_rows.is_empty() {
                ui.label(
                    egui::RichText::new("This password has never been changed.").color(pal().muted),
                );
            } else {
                let rows = self.history_rows.clone();
                let mut restore: Option<String> = None;
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    for (n, (when, old, reason)) in rows.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("{}.", n + 1)).size(12.0).color(pal().muted),
                            );
                            // Masked by default: an old password is usually
                            // still in use somewhere else.
                            ui.label(
                                egui::RichText::new("•".repeat(old.chars().count().min(20)))
                                    .monospace(),
                            );
                            ui.label(
                                egui::RichText::new(format_when(*when)).size(11.0).color(pal().muted),
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
                                egui::RichText::new(format!("    {why}")).size(11.0).color(pal().muted),
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
        form(ui, |ui| {
            ui.label(egui::RichText::new("Trash").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Deleted entries stay here until you empty it. Emptying cannot be undone.",
                )
                .size(12.0)
                .color(pal().muted),
            );
            ui.add_space(10.0);

            if self.trash_rows.is_empty() {
                ui.label(egui::RichText::new("The trash is empty.").color(pal().muted));
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
                                            egui::RichText::new("Delete forever").color(pal().danger),
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
        form(ui, |ui| {
            ui.label(egui::RichText::new("Import a CSV export").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Chrome, Firefox, Bitwarden, LastPass or KeePass. The format is \
                     detected from the header row.",
                )
                .size(12.0)
                .color(pal().muted),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "That file holds your passwords in the clear. Delete it once the \
                     import is done.",
                )
                .size(12.0)
                .color(pal().warn),
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
        form(ui, |ui| {
            ui.label(egui::RichText::new("Export and backup").size(17.0).strong());
            ui.add_space(8.0);

            label(ui, "ENCRYPTED BACKUP");
            ui.label(
                egui::RichText::new(
                    "A copy of the vault, still encrypted under this passphrase. Safe to \
                     keep on a USB stick.",
                )
                .size(12.0)
                .color(pal().muted),
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
                .color(pal().danger),
            );
            ui.add_space(6.0);
            field(ui, &mut self.export_path, "/home/you/keypal-export.csv", false);
            ui.add_space(8.0);
            if ui
                .add_sized(
                    [190.0, 32.0],
                    egui::Button::new(
                        egui::RichText::new("Export unencrypted CSV").size(13.0).color(pal().on_accent),
                    )
                    .fill(pal().danger),
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
        form(ui, |ui| {
            ui.label(egui::RichText::new("Import from KeePass").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Entries are copied in; the .kdbx file is left untouched.")
                    .size(12.0)
                    .color(pal().muted),
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
        form(ui, |ui| {
            ui.label(egui::RichText::new("Change passphrase").size(17.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Every entry is re-encrypted under the new key.")
                    .size(12.0)
                    .color(pal().muted),
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

    fn help_view(&mut self, ui: &mut egui::Ui) {
        // Written as prose the user can check against the code, not as
        // marketing. Every claim here is one the tests enforce; the limits
        // section exists because a security page that lists only strengths is
        // an advertisement.
        // Back FIRST, at the top left, before the reader has scrolled anywhere.
        // The only way out used to be a Close button at the foot of six screens
        // of prose — so anyone who opened this page by accident had to read it
        // all, or guess, to get out.
        let locked = self.show_help_locked;
        page(ui, |ui| {
            ui.horizontal(|ui| {
                if icon_button(ui, Icon::Close, if locked { "Back to start" } else { "Back to vault" })
                {
                    self.panel = Panel::List;
                    self.show_help_locked = false;
                }
            });
            ui.add_space(6.0);
            // KEYPAL_SHOT_SCROLL=<pixels> starts this page part-way down, so
            // the sections below the fold can be photographed. Ignored unless
            // a screenshot is being taken.
            let mut area = egui::ScrollArea::vertical();
            if let Some(y) = std::env::var("KEYPAL_SHOT_SCROLL")
                .ok()
                .and_then(|v| v.trim().parse::<f32>().ok())
            {
                area = area.vertical_scroll_offset(y);
            }
            area.show(ui, |ui| {
                let h = |ui: &mut egui::Ui, t: &str| {
                    ui.add_space(14.0);
                    ui.label(egui::RichText::new(t).size(15.0).strong().color(pal().accent));
                    ui.add_space(5.0);
                };
                let para = |ui: &mut egui::Ui, t: &str| {
                    ui.label(egui::RichText::new(t).size(13.5).color(pal().text));
                    ui.add_space(7.0);
                };
                // Paths are shown in monospace: a path is something you copy
                // and type, not something you read as a sentence.
                let path_line = |ui: &mut egui::Ui, what: &str, p: String| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new(what).size(12.5).color(pal().muted));
                        ui.label(egui::RichText::new(p).size(12.5).monospace().color(pal().text));
                    });
                    ui.add_space(3.0);
                };

                ui.horizontal(|ui| {
                    logo(ui, 40.0);
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("How this protects you").size(21.0).strong());
                        ui.label(
                            egui::RichText::new(format!(
                                "Keypal {}  ·  by Rafael Kyra",
                                env!("CARGO_PKG_VERSION")
                            ))
                            .size(11.5)
                            .color(pal().muted),
                        );
                    });
                });
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("Written to be checked, not believed.")
                        .size(12.0)
                        .color(pal().muted),
                );

                h(ui, "What it is");
                para(ui, "A vault for security items that keeps everything on this \
                          machine. There is no account, no server, no sync, and nothing \
                          is sent anywhere — including to us.");
                para(ui, "Passwords are only one of sixteen kinds of thing it holds: \
                          API keys, SSH keys, servers, databases, Wi-Fi networks, VPNs, \
                          certificates, recovery codes, crypto wallets, bank cards, \
                          licences, secure notes. Each has its own form, so a card has \
                          a CVV and an expiry rather than a password and four lines of \
                          notes pretending to be one.");

                h(ui, "How your passwords are protected");
                para(ui, "Your passphrase is put through Argon2id, the winner of the \
                          Password Hashing Competition, tuned to the profile RFC 9106 \
                          recommends for interactive use: three passes over 64 MiB of \
                          memory. The memory cost is the point — it makes guessing \
                          expensive on graphics cards, which is how passphrases are \
                          actually attacked.");
                para(ui, "The result never encrypts anything directly. It is split by \
                          HKDF into separate keys for encryption, authentication and \
                          erasure, so no single key does two jobs.");
                para(ui, "Entries are encrypted with AES-256-GCM. Every field gets its \
                          own nonce, and editing an entry generates fresh ones. That \
                          detail matters more than it sounds: reusing a nonce would let \
                          anyone holding the file recover the difference between two \
                          values without ever knowing the key.");

                h(ui, "What is on disk, and what is not");
                para(ui, "The vault is one SQLite file. Names, usernames, passwords, \
                          URLs, notes, tags and two-factor secrets are all ciphertext — \
                          the name of an entry is as protected as its password, so the \
                          file does not reveal which accounts you hold.");
                para(ui, "Not encrypted, because they cannot be: the Argon2 salt, which \
                          is not secret by design, and the access log's entry ids and \
                          timestamps. The log deliberately stores no names — a list of \
                          names beside the ciphertext would undo the encryption for \
                          anyone who read the file.");

                h(ui, "Deleting really deletes");
                para(ui, "Deleting moves an entry to the trash, which is reversible. \
                          Destroying it is not, and it does more than a database DELETE \
                          would: SQLite hands the page back to its free list without \
                          touching the bytes, so the old ciphertext survives in the file. \
                          Instead the row and every stored version of its password are \
                          overwritten with random data encrypted under a separate wipe \
                          key, which forces the page to be rewritten. That key exists \
                          only while the vault is open, and is wiped from memory when \
                          you lock it.");

                h(ui, "While it is running");
                para(ui, "Key material is locked into RAM so the system cannot page it \
                          to swap, and overwritten when the vault locks. The interface \
                          is compiled into the same program as the vault, so a revealed \
                          password never crosses a boundary into memory we do not \
                          control — which is why this is not built on a web view.");
                para(ui, "Rust is used for the same reason: whole classes of bug that \
                          leak memory contents in C — buffer overruns, use-after-free — \
                          are rejected before the program is built. It is also fast, but \
                          that is a side benefit, not the reason.");

                h(ui, "Where the protection stops");
                para(ui, "Copying to the clipboard puts a password somewhere every \
                          application can read. It is overwritten after twenty seconds, \
                          which is a limit, not a fix.");
                para(ui, "During key derivation Argon2 needs 64 MiB that cannot be \
                          locked under the default system limit, so it may be paged. \
                          Raising the limit closes that gap.");
                para(ui, "Importing from KeePass decrypts through another library, whose \
                          buffers are not ours to wipe. Secrets served over D-Bus leave \
                          our control at the bus.");
                para(ui, "And nothing here defends a machine that is already \
                          compromised. A keylogger sees your passphrase as you type it, \
                          whatever the vault does afterwards.");

                h(ui, "The program is not obfuscated, on purpose");
                para(ui, "Security here does not rest on the code being secret. Your key \
                          comes from your passphrase; someone who reads every line gains \
                          nothing. An encrypted binary has to decrypt itself to run, so \
                          it carries its own key — a lock with the key taped to it — \
                          while blocking the independent review that would find real \
                          flaws. AES is public for the same reason.");

                h(ui, "Where everything is on this machine");
                para(ui, "Nothing is hidden and nothing is in a database you cannot \
                          copy. Your vault is one ordinary file — back it up by copying \
                          it, move it by moving it. These are the real paths on this \
                          machine, read from the running program rather than written \
                          into this page:");
                path_line(
                    ui,
                    "The program ",
                    std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "unknown".into()),
                );
                path_line(
                    ui,
                    "Vaults are looked for in ",
                    home().display().to_string(),
                );
                path_line(
                    ui,
                    "Open vault ",
                    self.vault_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "none — the vault is locked".into()),
                );
                if let Some(root) = portable_root() {
                    path_line(ui, "Portable mode, so everything stays in ", root.display().to_string());
                }
                para(ui, "Beside the vault file SQLite keeps two companions while it is \
                          open, ending in -wal and -shm. Copy them along with the vault \
                          if you back it up while the program is running; on a clean \
                          close there is nothing in them.");
                para(ui, "The program writes nothing else: no configuration in your home \
                          folder, no cache, no logs, no temporary copies. Temporary \
                          tables are held in memory precisely so no fragment of a \
                          decrypted entry is written to /tmp.");

                h(ui, "Carrying it on a USB stick");
                para(ui, "Put an empty file named .keypal-portable beside the program and \
                          it reads and writes only on that medium, touching nothing on \
                          the host. Your vault travels with you and the borrowed machine \
                          keeps no trace — though it can still keep the clipboard, and \
                          swap is out of our hands there too.");

                ui.add_space(14.0);
                if ui.button("Close").clicked() {
                    self.panel = Panel::List;
                    self.show_help_locked = false;
                }
            });
        });
    }

    fn settings_view(&mut self, ui: &mut egui::Ui) {
        form(ui, |ui| {
            ui.label(egui::RichText::new("Settings").size(17.0).strong());
            ui.add_space(10.0);

            label(ui, "TRASH RETENTION");
            ui.label(
                egui::RichText::new(
                    "Days before a trashed entry is shredded automatically on unlock. \
                     0 keeps everything until you empty the trash yourself.",
                )
                .size(12.0)
                .color(pal().muted),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.retention_input)
                        .desired_width(70.0)
                        .margin(egui::Margin::symmetric(10.0, 7.0)),
                );
                ui.label(egui::RichText::new("days").size(12.0).color(pal().muted));
                if ui.button("Save").clicked() {
                    match self.retention_input.trim().parse::<i64>() {
                        Ok(d) if d >= 0 => {
                            if let Some(db) = self.db.as_ref() {
                                let _ = db.set_retention_days(d);
                            }
                            self.set(
                                if d == 0 {
                                    "Trash kept until emptied by hand".to_string()
                                } else {
                                    format!("Trash shredded after {d} days")
                                },
                                Level::Ok,
                            );
                        }
                        _ => self.set("Give a whole number of days", Level::Bad),
                    }
                }
            });

            ui.add_space(16.0);
            label(ui, "APPEARANCE");
            ui.add_space(4.0);
            if ui
                .checkbox(&mut self.light, "Light theme")
                .changed()
            {
                apply_theme(ui.ctx(), self.light);
            }

            ui.add_space(16.0);
            label(ui, "RECENT ACTIVITY");
            ui.label(
                egui::RichText::new(
                    "Entry ids only — a log of names would be a plaintext index of the \
                     vault sitting beside the ciphertext.",
                )
                .size(11.0)
                .color(pal().muted),
            );
            ui.add_space(4.0);
            let log = self
                .db
                .as_ref()
                .and_then(|db| db.recent_access(12).ok())
                .unwrap_or_default();
            if log.is_empty() {
                ui.label(egui::RichText::new("Nothing recorded yet.").size(12.0).color(pal().muted));
            } else {
                egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                    for (at, entry, action) in log {
                        let who = match entry {
                            Some(id) => self
                                .rows
                                .iter()
                                .find(|r| r.id == id)
                                .map(|r| r.name.clone())
                                .unwrap_or_else(|| format!("entry {id}")),
                            None => "vault".to_string(),
                        };
                        ui.label(
                            egui::RichText::new(format!("{}   {action}   {who}", format_when(at)))
                                .size(11.0)
                                .color(pal().muted),
                        );
                    }
                });
            }

            ui.add_space(14.0);
            if ui.button("Done").clicked() {
                self.panel = Panel::List;
            }
        });
    }

    fn confirm_purge(&mut self, ui: &mut egui::Ui, id: i64, name: &str) {
        form(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("Destroy “{name}” for good?"))
                    .size(17.0)
                    .strong()
                    .color(pal().danger),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "The entry and every stored version of its password are overwritten \
                     with random data encrypted under a wipe key, then removed. The wipe \
                     key dies when you lock the vault.",
                )
                .size(12.0)
                .color(pal().muted),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("There is no undo, and no recovery from a backup made after this.")
                    .size(12.0)
                    .color(pal().warn),
            );
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        [150.0, 34.0],
                        egui::Button::new(
                            egui::RichText::new("Destroy").size(14.0).strong().color(pal().on_accent),
                        )
                        .fill(pal().danger),
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
        form(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("Delete “{name}”?"))
                    .size(17.0)
                    .strong()
                    .color(pal().danger),
            );
            ui.add_space(4.0);
            ui.label(egui::RichText::new("This cannot be undone.").size(12.0).color(pal().muted));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        [120.0, 34.0],
                        egui::Button::new(
                            egui::RichText::new("Delete").size(14.0).strong().color(pal().on_accent),
                        )
                        .fill(pal().danger),
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
            .with_inner_size([980.0, 820.0])
            .with_min_inner_size([620.0, 620.0])
            .with_title("Keypal"),
        ..Default::default()
    };
    eframe::run_native(
        "Keypal",
        options,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            apply_theme(&cc.egui_ctx, false);
            Ok(Box::new(App::default()))
        }),
    )
}
