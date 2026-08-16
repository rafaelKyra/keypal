//! CSV import from the exports other password managers produce.
//!
//! This is the on-ramp. Nobody retypes two hundred passwords, so a vault that
//! cannot read a competitor's export is a vault nobody moves into.
//!
//! Each manager names its columns differently and none of them declare which
//! they are, so the format is detected from the header row rather than asked
//! for. Getting that wrong silently would map passwords into the notes field,
//! which is why an unrecognised header is an error rather than a guess.

/// A parsed row, ready to insert.
#[derive(Debug, PartialEq, Clone)]
pub struct Incoming {
    pub name: String,
    pub username: String,
    pub password: String,
    pub uri: Option<String>,
    pub totp: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<String>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Source {
    Chrome,
    Firefox,
    Bitwarden,
    LastPass,
    KeePass,
    /// Headers we recognised field-by-field without matching a known product.
    Generic,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::Chrome => "Chrome",
            Source::Firefox => "Firefox",
            Source::Bitwarden => "Bitwarden",
            Source::LastPass => "LastPass",
            Source::KeePass => "KeePass",
            Source::Generic => "generic CSV",
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ImportError {
    Empty,
    /// No column that could hold a password.
    NoPasswordColumn,
    /// A row had fewer fields than the header promised.
    RaggedRow(usize),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Empty => write!(f, "the file is empty"),
            ImportError::NoPasswordColumn => {
                write!(f, "no password column — is this a password export?")
            }
            ImportError::RaggedRow(n) => write!(f, "row {n} has the wrong number of columns"),
        }
    }
}

/// Split one CSV line, honouring quotes and doubled quotes.
///
/// Written out rather than pulled from a crate because the subset CSV exports
/// actually use is small, and a password manager should not grow a dependency
/// tree for it. Handles the cases that appear in real exports: quoted fields,
/// commas inside quotes, `""` as a literal quote, and CRLF.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut field));
            }
            '\r' => {}
            _ => field.push(c),
        }
    }
    out.push(field);
    out
}

/// A CSV record may span several lines when a field contains a newline —
/// notes routinely do. Fields are joined back together before splitting.
fn records(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quotes = 0usize;
    for line in text.lines() {
        quotes += line.chars().filter(|c| *c == '"').count();
        if current.is_empty() {
            current = line.to_string();
        } else {
            current.push('\n');
            current.push_str(line);
        }
        // An even number of quotes means every one that opened has closed, so
        // the record is complete.
        if quotes % 2 == 0 {
            out.push(std::mem::take(&mut current));
            quotes = 0;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.retain(|r| !r.trim().is_empty());
    out
}

fn find(headers: &[String], names: &[&str]) -> Option<usize> {
    headers
        .iter()
        .position(|h| names.iter().any(|n| h.eq_ignore_ascii_case(n)))
}

/// Detect the product from its header row.
pub fn detect(headers: &[String]) -> Source {
    let has = |n: &str| headers.iter().any(|h| h.eq_ignore_ascii_case(n));
    if has("login_uri") && has("login_password") {
        Source::Bitwarden
    } else if has("url") && has("username") && has("password") && has("grouping") {
        Source::LastPass
    } else if has("Group") && has("Title") && has("Password") {
        Source::KeePass
    } else if has("httpRealm") || has("formActionOrigin") || (has("url") && has("timeCreated")) {
        Source::Firefox
    } else if has("name") && has("url") && has("username") && has("password") {
        Source::Chrome
    } else {
        Source::Generic
    }
}

/// Parse a CSV export into rows ready for the vault.
pub fn parse(text: &str) -> Result<(Source, Vec<Incoming>), ImportError> {
    let recs = records(text);
    if recs.is_empty() {
        return Err(ImportError::Empty);
    }

    let headers: Vec<String> = split_csv_line(&recs[0])
        .into_iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_string())
        .collect();
    let source = detect(&headers);

    // Column aliases across every product we know, plus the obvious generics.
    let i_pass = find(&headers, &["password", "login_password", "pass"])
        .ok_or(ImportError::NoPasswordColumn)?;
    let i_name = find(&headers, &["name", "title", "account", "item name"]);
    let i_user = find(&headers, &["username", "login_username", "user", "login", "email"]);
    let i_uri = find(&headers, &["url", "login_uri", "uri", "website", "site"]);
    let i_totp = find(&headers, &["totp", "login_totp", "otpauth", "otp"]);
    let i_notes = find(&headers, &["notes", "note", "comment", "extra"]);
    let i_tags = find(&headers, &["grouping", "group", "folder", "category", "tags"]);

    let get = |row: &[String], idx: Option<usize>| -> Option<String> {
        idx.and_then(|i| row.get(i))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let mut out = Vec::new();
    for (n, rec) in recs.iter().enumerate().skip(1) {
        let row = split_csv_line(rec);
        // Trailing empty columns are common and harmless; a row that is short
        // of the password column is not.
        if row.len() <= i_pass {
            return Err(ImportError::RaggedRow(n + 1));
        }
        let password = row[i_pass].trim().to_string();
        // Rows with no password are bookmarks, not credentials. Chrome and
        // Firefox both emit them.
        if password.is_empty() {
            continue;
        }
        let name = get(&row, i_name)
            .or_else(|| get(&row, i_uri))
            .unwrap_or_else(|| "Untitled".to_string());

        out.push(Incoming {
            name,
            username: get(&row, i_user).unwrap_or_default(),
            password,
            uri: get(&row, i_uri),
            totp: get(&row, i_totp).and_then(|t| crate::totp::normalize_secret(&t)),
            notes: get(&row, i_notes),
            tags: get(&row, i_tags),
        });
    }

    Ok((source, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_chrome_export() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com,octocat,s3cret,\n\
                   Mail,https://mail.example,me@example.com,other-pw,hello\n";
        let (source, rows) = parse(csv).unwrap();
        assert_eq!(source, Source::Chrome);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "GitHub");
        assert_eq!(rows[0].username, "octocat");
        assert_eq!(rows[0].password, "s3cret");
        assert_eq!(rows[0].uri.as_deref(), Some("https://github.com"));
        assert_eq!(rows[1].notes.as_deref(), Some("hello"));
    }

    #[test]
    fn reads_a_bitwarden_export_including_its_totp_column() {
        let csv = "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
                   Work,,login,Bank,,,https://bank.example,me,pw123,GEZDGNBVGY3TQOJQ\n";
        let (source, rows) = parse(csv).unwrap();
        assert_eq!(source, Source::Bitwarden);
        assert_eq!(rows[0].password, "pw123");
        assert_eq!(rows[0].username, "me");
        assert_eq!(rows[0].totp.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
        assert_eq!(rows[0].tags.as_deref(), Some("Work"));
    }

    #[test]
    fn reads_a_lastpass_export() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://x.example,user,pw,,some note,X Account,Personal,0\n";
        let (source, rows) = parse(csv).unwrap();
        assert_eq!(source, Source::LastPass);
        assert_eq!(rows[0].name, "X Account");
        assert_eq!(rows[0].notes.as_deref(), Some("some note"));
        assert_eq!(rows[0].tags.as_deref(), Some("Personal"));
    }

    #[test]
    fn reads_a_keepass_export() {
        let csv = "Group,Title,Username,Password,URL,Notes\n\
                   Root/Web,Forum,me,pw,https://f.example,note here\n";
        let (source, rows) = parse(csv).unwrap();
        assert_eq!(source, Source::KeePass);
        assert_eq!(rows[0].name, "Forum");
        assert_eq!(rows[0].tags.as_deref(), Some("Root/Web"));
    }

    #[test]
    fn keeps_commas_and_quotes_that_live_inside_fields() {
        // A note containing a comma is the single most common way a naive
        // splitter corrupts an import — every field after it shifts by one.
        let csv = "name,username,password,notes\n\
                   \"Bank, Ltd\",me,\"pw,with,commas\",\"he said \"\"hi\"\"\"\n";
        let (_, rows) = parse(csv).unwrap();
        assert_eq!(rows[0].name, "Bank, Ltd");
        assert_eq!(rows[0].password, "pw,with,commas");
        assert_eq!(rows[0].notes.as_deref(), Some("he said \"hi\""));
    }

    #[test]
    fn keeps_a_note_that_spans_several_lines() {
        let csv = "name,username,password,notes\n\
                   Site,me,pw,\"line one\nline two\"\n";
        let (_, rows) = parse(csv).unwrap();
        assert_eq!(rows.len(), 1, "a quoted newline must not split the record");
        assert_eq!(rows[0].notes.as_deref(), Some("line one\nline two"));
    }

    #[test]
    fn skips_rows_that_carry_no_password() {
        // Chrome and Firefox both export bookmark-like rows with an empty
        // password. Importing them would fill the vault with entries that
        // unlock nothing.
        let csv = "name,url,username,password\n\
                   Real,https://a.example,me,pw\n\
                   Bookmark,https://b.example,,\n";
        let (_, rows) = parse(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Real");
    }

    #[test]
    fn falls_back_to_the_url_when_a_row_has_no_name() {
        let csv = "url,username,password\nhttps://x.example,me,pw\n";
        let (_, rows) = parse(csv).unwrap();
        assert_eq!(rows[0].name, "https://x.example");
    }

    #[test]
    fn refuses_a_file_that_has_no_password_column() {
        // Better to refuse than to guess: a wrong guess maps passwords into
        // the notes field, and the user finds out much later.
        let csv = "name,url,description\nA,https://a.example,hello\n";
        assert_eq!(parse(csv), Err(ImportError::NoPasswordColumn));
        assert_eq!(parse(""), Err(ImportError::Empty));
    }

    #[test]
    fn tolerates_a_utf8_bom_and_crlf() {
        // Exports from Windows tools carry both, and a BOM glued to the first
        // header name would stop it matching.
        let csv = "\u{feff}name,username,password\r\nSite,me,pw\r\n";
        let (_, rows) = parse(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Site");
        assert_eq!(rows[0].password, "pw");
    }
}
