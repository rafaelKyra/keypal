//! What kind of thing an entry is, and which fields that kind actually has.
//!
//! This is the line between a password manager and a manager of security
//! items. A password manager has one form and asks you to bend everything into
//! it: a Wi-Fi key becomes a "password" with the SSID typed into the notes, an
//! SSH key becomes a note, a bank card becomes four lines of free text. The
//! form knows nothing, so the user does the classifying, badly, by hand.
//!
//! Here the category comes first and the form follows from it. Choose "Bank
//! card" and you get a number, an expiry, a CVV and a holder — named, in the
//! right order, with the secret ones hidden by default.
//!
//! ## Sixteen, and not more
//!
//! Sixteen is enough to cover what people actually keep and few enough that the
//! choice is still a choice. Past roughly twenty categories the list stops being
//! scannable, classifying becomes work, and everything lands in whichever
//! catch-all is nearest — which is the state we started from, with extra steps.
//!
//! ## Where the fields live
//!
//! Most categories reuse the columns the vault already encrypts: the login
//! name, the primary secret, the address, the TOTP seed. Only what is genuinely
//! new to a category — an SSID, a card's CVV, a database engine — goes into the
//! `fields` blob, encrypted under its own nonce like every other column.
//!
//! Mapping each category's *one* crown-jewel secret onto the existing password
//! column is deliberate. It means reveal-on-demand, clipboard expiry, password
//! history and crypto-shredding work for a seed phrase and an API token without
//! a second implementation of any of them. What changes is the label and what
//! the audit makes of it — a card number is a secret, but calling it "weak"
//! because it is sixteen digits would be nonsense.

/// One category-specific field: the parts that do not fit an existing column.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Field {
    /// Stable identifier. Stored on disk, so it must never change once shipped.
    pub key: &'static str,
    /// What the user sees.
    pub label: &'static str,
    /// Hidden behind a reveal, and never shown in a list.
    pub secret: bool,
    /// Rendered as a text area rather than one line.
    pub multiline: bool,
    /// Placeholder text, to show the expected shape rather than explain it.
    pub hint: &'static str,
}

const fn f(key: &'static str, label: &'static str, hint: &'static str) -> Field {
    Field { key, label, secret: false, multiline: false, hint }
}
const fn s(key: &'static str, label: &'static str, hint: &'static str) -> Field {
    Field { key, label, secret: true, multiline: false, hint }
}
const fn m(key: &'static str, label: &'static str, hint: &'static str) -> Field {
    Field { key, label, secret: true, multiline: true, hint }
}

/// The sixteen categories.
///
/// The discriminants are written on disk in `entries.kind`, so they are fixed
/// forever. `Website` is 0 because that is what every row written before this
/// column existed is, in fact, and a migration that silently reclassified them
/// would be a lie about the user's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i64)]
pub enum Kind {
    Website = 0,
    Email = 1,
    Authenticator = 2,
    ApiKey = 3,
    SshKey = 4,
    Server = 5,
    Database = 6,
    Wifi = 7,
    Device = 8,
    Vpn = 9,
    Certificate = 10,
    RecoveryCodes = 11,
    CryptoWallet = 12,
    BankCard = 13,
    SecureNote = 14,
    License = 15,
}

pub const ALL: [Kind; 16] = [
    Kind::Website,
    Kind::Email,
    Kind::Authenticator,
    Kind::ApiKey,
    Kind::SshKey,
    Kind::Server,
    Kind::Database,
    Kind::Wifi,
    Kind::Device,
    Kind::Vpn,
    Kind::Certificate,
    Kind::RecoveryCodes,
    Kind::CryptoWallet,
    Kind::BankCard,
    Kind::SecureNote,
    Kind::License,
];

impl Default for Kind {
    fn default() -> Self {
        Kind::Website
    }
}

/// The family a category belongs to.
///
/// Sixteen flat headings is a list you read; four families of three to seven is
/// a list you scan. The grouping is by what you are doing when you reach for
/// the entry — signing in, working on a machine, paying for something, proving
/// who you are — rather than by what the secret technically is. Someone looking
/// for a database password is thinking "the server stuff", not "a credential
/// with a host and a port".
///
/// These are presentation only. Nothing about a group is written to disk, so
/// regrouping later costs a recompile and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    SignIn,
    Machines,
    Money,
    Documents,
}

pub const GROUPS: [Group; 4] = [Group::SignIn, Group::Machines, Group::Money, Group::Documents];

impl Group {
    pub fn label(self) -> &'static str {
        match self {
            Group::SignIn => "Accounts",
            Group::Machines => "Machines & networks",
            Group::Money => "Money",
            Group::Documents => "Documents & keys",
        }
    }

    /// The categories in this family, in the order they should be listed.
    pub fn kinds(self) -> &'static [Kind] {
        match self {
            Group::SignIn => &[Kind::Website, Kind::Email, Kind::Authenticator],
            Group::Machines => &[
                Kind::Server,
                Kind::Database,
                Kind::SshKey,
                Kind::ApiKey,
                Kind::Vpn,
                Kind::Wifi,
                Kind::Device,
            ],
            Group::Money => &[Kind::BankCard, Kind::CryptoWallet],
            Group::Documents => &[
                Kind::Certificate,
                Kind::RecoveryCodes,
                Kind::SecureNote,
                Kind::License,
            ],
        }
    }
}

impl Kind {
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    /// Which family this category is listed under.
    pub fn group(self) -> Group {
        match self {
            Kind::Website | Kind::Email | Kind::Authenticator => Group::SignIn,
            Kind::Server
            | Kind::Database
            | Kind::SshKey
            | Kind::ApiKey
            | Kind::Vpn
            | Kind::Wifi
            | Kind::Device => Group::Machines,
            Kind::BankCard | Kind::CryptoWallet => Group::Money,
            Kind::Certificate | Kind::RecoveryCodes | Kind::SecureNote | Kind::License => {
                Group::Documents
            }
        }
    }

    /// An unknown number reads back as `Website` rather than failing.
    ///
    /// A vault written by a later version with a seventeenth category must
    /// still open here: showing that entry under the wrong heading is
    /// recoverable, refusing to open the vault is not.
    pub fn from_i64(v: i64) -> Self {
        ALL.get(v as usize).copied().unwrap_or(Kind::Website)
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Website => "Website",
            Kind::Email => "Email account",
            Kind::Authenticator => "Authenticator",
            Kind::ApiKey => "API key",
            Kind::SshKey => "SSH key",
            Kind::Server => "Server",
            Kind::Database => "Database",
            Kind::Wifi => "Router / Wi-Fi",
            Kind::Device => "Device",
            Kind::Vpn => "VPN",
            Kind::Certificate => "Certificate",
            Kind::RecoveryCodes => "Recovery codes",
            Kind::CryptoWallet => "Crypto wallet",
            Kind::BankCard => "Bank card",
            Kind::SecureNote => "Secure note",
            Kind::License => "Software licence",
        }
    }

    /// What the entry's name means for this category, as a placeholder.
    pub fn name_hint(self) -> &'static str {
        match self {
            Kind::Website => "GitHub",
            Kind::Email => "Work mail",
            Kind::Authenticator => "GitHub 2FA",
            Kind::ApiKey => "Stripe live key",
            Kind::SshKey => "Deploy key",
            Kind::Server => "build-01",
            Kind::Database => "Orders database",
            Kind::Wifi => "Home Wi-Fi",
            Kind::Device => "Work laptop",
            Kind::Vpn => "Office VPN",
            Kind::Certificate => "Signing certificate",
            Kind::RecoveryCodes => "GitHub recovery codes",
            Kind::CryptoWallet => "Hardware wallet",
            Kind::BankCard => "Debit card",
            Kind::SecureNote => "Passport details",
            Kind::License => "IntelliJ IDEA",
        }
    }

    /// The login name, if the category has one. `None` hides the field.
    pub fn username_label(self) -> Option<&'static str> {
        match self {
            Kind::Website => Some("Username"),
            Kind::Email => Some("Address"),
            Kind::SshKey | Kind::Server | Kind::Device | Kind::Vpn => Some("Username"),
            Kind::Database => Some("Username"),
            Kind::License | Kind::BankCard => Some("Holder"),
            _ => None,
        }
    }

    /// The one secret that goes in the password column, and what to call it.
    ///
    /// `None` means this category has no single primary secret — a secure note
    /// or a set of recovery codes carries its content elsewhere.
    pub fn secret_label(self) -> Option<&'static str> {
        match self {
            Kind::Website | Kind::Email | Kind::Server | Kind::Database
            | Kind::Device | Kind::Vpn => Some("Password"),
            Kind::Wifi => Some("Wi-Fi password"),
            Kind::ApiKey => Some("Key"),
            Kind::SshKey => Some("Passphrase"),
            Kind::Certificate => Some("Passphrase"),
            Kind::CryptoWallet => Some("Seed phrase"),
            Kind::BankCard => Some("Card number"),
            Kind::License => Some("Licence key"),
            Kind::Authenticator | Kind::RecoveryCodes | Kind::SecureNote => None,
        }
    }

    /// The address field, if it means anything here.
    pub fn uri_label(self) -> Option<&'static str> {
        match self {
            Kind::Website => Some("URL"),
            Kind::ApiKey => Some("Documentation URL"),
            Kind::Wifi => Some("Admin page"),
            Kind::License => Some("Vendor page"),
            _ => None,
        }
    }

    /// Whether a two-factor seed belongs on this category at all.
    pub fn uses_totp(self) -> bool {
        matches!(self, Kind::Website | Kind::Email | Kind::Authenticator | Kind::CryptoWallet)
    }

    /// Fields with no existing column of their own.
    pub fn extra(self) -> &'static [Field] {
        // Named consts rather than inline arrays: a `&[f(..)]` inside a method
        // builds a temporary on the stack, which cannot be handed back as
        // `'static`. A const item is the const context that makes these real
        // statics.
        const EMAIL: &[Field] = &[
            f("server", "Mail server", "imap.example.com"),
            f("port", "Port", "993"),
        ];
        const API_KEY: &[Field] = &[
            f("service", "Service", "Stripe"),
            f("expires", "Expires", "2027-01-31"),
        ];
        const SSH: &[Field] = &[
            m("private_key", "Private key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            f("host", "Host", "git@github.com"),
        ];
        const SERVER: &[Field] = &[
            f("host", "Host", "build-01.example.com"),
            f("port", "Port", "22"),
        ];
        const DATABASE: &[Field] = &[
            f("engine", "Engine", "PostgreSQL"),
            f("host", "Host", "db.example.com"),
            f("port", "Port", "5432"),
            s("dsn", "Connection string", "postgres://user:pass@host/db"),
        ];
        const WIFI: &[Field] = &[
            f("ssid", "Network name (SSID)", "Home-5G"),
            f("admin_ip", "Admin address", "192.168.1.1"),
        ];
        const DEVICE: &[Field] = &[f("os", "System", "Linux / Windows / Android")];
        const VPN: &[Field] = &[
            f("server", "Server", "vpn.example.com"),
            f("protocol", "Protocol", "WireGuard"),
        ];
        const CERTIFICATE: &[Field] = &[
            f("issuer", "Issued by", "Let's Encrypt"),
            f("expires", "Expires", "2027-01-31"),
        ];
        const RECOVERY: &[Field] = &[m("codes", "Backup codes", "one code per line")];
        const WALLET: &[Field] = &[f("network", "Network", "Bitcoin / Ethereum")];
        const CARD: &[Field] = &[
            f("expires", "Expires", "09/29"),
            s("cvv", "Security code", "123"),
        ];
        const LICENCE: &[Field] = &[f("product", "Product", "IntelliJ IDEA Ultimate")];

        match self {
            Kind::Website | Kind::Authenticator | Kind::SecureNote => &[],
            Kind::Email => EMAIL,
            Kind::ApiKey => API_KEY,
            Kind::SshKey => SSH,
            Kind::Server => SERVER,
            Kind::Database => DATABASE,
            Kind::Wifi => WIFI,
            Kind::Device => DEVICE,
            Kind::Vpn => VPN,
            Kind::Certificate => CERTIFICATE,
            Kind::RecoveryCodes => RECOVERY,
            Kind::CryptoWallet => WALLET,
            Kind::BankCard => CARD,
            Kind::License => LICENCE,
        }
    }

    /// Whether the primary secret is a password a human chose, and can
    /// therefore be too weak or reused.
    ///
    /// A generated API token, a card number, a seed phrase and a licence key
    /// are all secrets, but none of them is something the user picked or could
    /// improve. Scoring them as weak passwords would fill the health report
    /// with findings nobody can act on, which is how a health report becomes
    /// something people stop reading.
    pub fn audits_password_strength(self) -> bool {
        matches!(
            self,
            Kind::Website
                | Kind::Email
                | Kind::Server
                | Kind::Database
                | Kind::Device
                | Kind::Vpn
                | Kind::Wifi
                | Kind::SshKey
                | Kind::Certificate
        )
    }

    /// Whether a missing second factor is worth mentioning.
    ///
    /// Only for categories where a second factor is a thing the service offers.
    /// An authenticator entry *is* the second factor; telling it to get one
    /// would be nonsense.
    pub fn wants_two_factor(self) -> bool {
        matches!(self, Kind::Website | Kind::Email)
    }
}

// ── The fields blob ───────────────────────────────────────────────────────
//
// Length-prefixed, not delimited. Values are arbitrary user text: an SSH
// private key contains newlines, a connection string can contain anything, and
// a pasted file can contain any byte at all. Any format that hunts for a
// separator eventually meets a value containing it, and the failure is silent
// corruption of a secret — the one failure mode a vault cannot have.
//
// One record: `key\n<byte length>\n<value>\n`.

/// Serialise category fields. Empty values are dropped: storing them would
/// grow the ciphertext for nothing and make "field absent" and "field cleared"
/// two states where one will do.
pub fn encode_fields(fields: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in fields {
        if v.is_empty() || k.is_empty() {
            continue;
        }
        out.push_str(k);
        out.push('\n');
        out.push_str(&v.len().to_string());
        out.push('\n');
        out.push_str(v);
        out.push('\n');
    }
    out
}

/// Parse a fields blob. Anything malformed ends the parse and returns what was
/// read so far, rather than erroring: a blob that cannot be read fully is still
/// worth showing in part, and refusing the whole entry over it would lose more
/// than it protects.
pub fn decode_fields(blob: &str) -> Vec<(String, String)> {
    let b = blob.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < b.len() {
        let Some(k_end) = memchr(b, i, b'\n') else { break };
        let Ok(key) = std::str::from_utf8(&b[i..k_end]) else { break };
        let Some(l_end) = memchr(b, k_end + 1, b'\n') else { break };
        let Ok(len) = std::str::from_utf8(&b[k_end + 1..l_end])
            .unwrap_or("x")
            .parse::<usize>()
        else {
            break;
        };
        let v_start = l_end + 1;
        let Some(v_end) = v_start.checked_add(len).filter(|e| *e <= b.len()) else { break };
        let Ok(value) = std::str::from_utf8(&b[v_start..v_end]) else { break };
        out.push((key.to_string(), value.to_string()));
        // Step over the trailing newline if it is there; tolerate its absence
        // on the last record rather than dropping that record.
        i = if b.get(v_end) == Some(&b'\n') { v_end + 1 } else { v_end };
    }
    out
}

fn memchr(hay: &[u8], from: usize, needle: u8) -> Option<usize> {
    hay.get(from..)?.iter().position(|c| *c == needle).map(|p| p + from)
}

/// Look one field up out of an already-parsed list.
pub fn field_value<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_category_has_a_distinct_number_and_survives_the_round_trip() {
        // These numbers are on disk. If one ever moves, every vault written
        // before the move reads its entries under the wrong category.
        for (i, k) in ALL.iter().enumerate() {
            assert_eq!(k.as_i64(), i as i64, "{} moved", k.label());
            assert_eq!(Kind::from_i64(k.as_i64()), *k);
        }
        assert_eq!(Kind::Website.as_i64(), 0, "rows written before this column are websites");
    }

    #[test]
    fn a_category_from_a_newer_version_does_not_break_the_vault() {
        // Refusing to open a vault because one row names an unknown category
        // would lose the other 400 entries over a cosmetic problem.
        assert_eq!(Kind::from_i64(99), Kind::Website);
        assert_eq!(Kind::from_i64(-1), Kind::Website);
    }

    #[test]
    fn category_labels_are_unique() {
        // Two categories reading the same in the sidebar is a category the user
        // cannot choose deliberately.
        let mut seen = std::collections::HashSet::new();
        for k in ALL {
            assert!(seen.insert(k.label()), "duplicate label {}", k.label());
        }
    }

    #[test]
    fn extra_field_keys_are_unique_within_a_category() {
        // Two fields sharing a key means the second silently overwrites the
        // first on save.
        for k in ALL {
            let mut seen = std::collections::HashSet::new();
            for f in k.extra() {
                assert!(seen.insert(f.key), "{}: duplicate field key {}", k.label(), f.key);
            }
        }
    }

    #[test]
    fn a_category_with_no_secret_and_no_fields_would_be_an_empty_form() {
        // Every category must offer somewhere to put something. A form with
        // nothing but a name is a category that should not exist.
        for k in ALL {
            let has_somewhere = k.secret_label().is_some()
                || !k.extra().is_empty()
                || k.uses_totp()
                || k == Kind::SecureNote; // the note itself is the content
            assert!(has_somewhere, "{} has nowhere to put anything", k.label());
        }
    }

    #[test]
    fn every_category_is_in_exactly_one_group() {
        // A category in no group is invisible in the sidebar; a category in two
        // is counted twice in the totals. Both are silent, and both make the
        // numbers beside the headings wrong — which is worse than having no
        // numbers, because the wrong ones are believed.
        let mut listed: Vec<Kind> = GROUPS.iter().flat_map(|g| g.kinds().iter().copied()).collect();
        listed.sort();
        let mut expected = ALL.to_vec();
        expected.sort();
        assert_eq!(listed, expected, "a category is missing from, or repeated in, the groups");

        // And the two directions must agree: `kind.group()` is what the filter
        // uses, `group.kinds()` is what the sidebar draws.
        for g in GROUPS {
            for k in g.kinds() {
                assert_eq!(k.group(), g, "{} is drawn under {} but reports {}",
                    k.label(), g.label(), k.group().label());
            }
        }
    }

    #[test]
    fn group_labels_are_unique_and_no_group_is_empty() {
        let mut seen = std::collections::HashSet::new();
        for g in GROUPS {
            assert!(seen.insert(g.label()), "duplicate group label {}", g.label());
            assert!(!g.kinds().is_empty(), "{} has no categories", g.label());
        }
    }

    #[test]
    fn fields_round_trip() {
        let input = vec![
            ("ssid".to_string(), "Home-5G".to_string()),
            ("admin_ip".to_string(), "192.168.1.1".to_string()),
        ];
        let blob = encode_fields(&input);
        assert_eq!(decode_fields(&blob), input);
        assert_eq!(field_value(&decode_fields(&blob), "ssid"), Some("Home-5G"));
        assert_eq!(field_value(&decode_fields(&blob), "nope"), None);
    }

    #[test]
    fn a_value_containing_newlines_survives_intact() {
        // THE POINT OF THE LENGTH PREFIX. An SSH private key is the ordinary
        // case, not the edge case, and a delimiter-hunting format truncates it
        // at the first line break — silently destroying a secret.
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\nAAAA\n-----END-----";
        let input = vec![("private_key".to_string(), key.to_string())];
        let blob = encode_fields(&input);
        assert_eq!(decode_fields(&blob), input);
    }

    #[test]
    fn a_value_that_looks_like_the_format_itself_survives() {
        // The adversarial case: a value containing what looks like a complete
        // record. With a length prefix it is just bytes.
        let nasty = "cvv\n3\n999\nextra\n1\nX";
        let input = vec![("codes".to_string(), nasty.to_string())];
        let blob = encode_fields(&input);
        let out = decode_fields(&blob);
        assert_eq!(out.len(), 1, "an injected record must not appear");
        assert_eq!(out[0].1, nasty);
    }

    #[test]
    fn empty_values_are_not_stored() {
        let input = vec![
            ("a".to_string(), String::new()),
            ("b".to_string(), "kept".to_string()),
        ];
        assert_eq!(decode_fields(&encode_fields(&input)), vec![("b".to_string(), "kept".to_string())]);
        assert!(decode_fields("").is_empty());
    }

    #[test]
    fn a_truncated_blob_yields_what_survived_rather_than_nothing() {
        let full = encode_fields(&[
            ("a".to_string(), "first".to_string()),
            ("b".to_string(), "second".to_string()),
        ]);
        let cut = &full[..full.len() - 4];
        let out = decode_fields(cut);
        assert_eq!(out.first().map(|(k, v)| (k.as_str(), v.as_str())), Some(("a", "first")));
    }

    #[test]
    fn a_lying_length_does_not_panic_or_read_past_the_end() {
        assert!(decode_fields("k\n9999\nshort").is_empty());
        assert!(decode_fields("k\nnotanumber\nv\n").is_empty());
        assert!(decode_fields("no-newlines-at-all").is_empty());
    }

    #[test]
    fn an_authenticator_is_not_asked_for_a_second_factor() {
        // It IS the second factor.
        assert!(!Kind::Authenticator.wants_two_factor());
        assert!(Kind::Website.wants_two_factor());
    }

    #[test]
    fn a_note_has_no_password_so_it_cannot_have_a_weak_one() {
        assert!(Kind::SecureNote.secret_label().is_none());
        assert!(!Kind::SecureNote.audits_password_strength());
        // A card number is a secret, but "weak" is not a thing it can be.
        assert!(Kind::BankCard.secret_label().is_some());
        assert!(!Kind::BankCard.audits_password_strength());
    }
}
