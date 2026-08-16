//! Vault health: which passwords are weak, reused, or stale.
//!
//! Every serious password manager has this, and for the same reason: a vault
//! full of secrets is not the same as a vault full of GOOD secrets. Storing a
//! password you also use on four other sites protects it from nobody.
//!
//! Everything here is offline arithmetic over already-decrypted entries. There
//! is deliberately no breach lookup: checking against Have I Been Pwned would
//! mean sending a hash prefix of every password to a third party, and a vault
//! whose whole premise is that secrets never leave the machine should not do
//! that quietly. It belongs behind an explicit, separate opt-in.

/// Why a single entry was flagged. An entry can collect several.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Issue {
    /// Estimated entropy below the weak threshold.
    Weak,
    /// The same password appears on another entry in this vault.
    Reused,
    /// Not changed in over a year.
    Stale,
    /// Past its expiry date.
    Expired,
    /// No two-factor secret, though the entry has a URL — so it is a real
    /// account somewhere, not a note to self.
    NoTwoFactor,
}

impl Issue {
    /// How much this costs the score, out of 100.
    ///
    /// Reuse is weighted hardest because it is the one flaw that turns someone
    /// else's breach into yours, and no amount of password strength helps.
    fn weight(self) -> f32 {
        match self {
            Issue::Reused => 30.0,
            Issue::Weak => 25.0,
            Issue::Expired => 20.0,
            Issue::Stale => 10.0,
            Issue::NoTwoFactor => 5.0,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Issue::Weak => "weak password",
            Issue::Reused => "reused on another entry",
            Issue::Stale => "not changed in over a year",
            Issue::Expired => "past its expiry date",
            Issue::NoTwoFactor => "no two-factor code",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: i64,
    pub name: String,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone)]
pub struct Report {
    /// 0–100. An empty vault scores 100: nothing is wrong with it.
    pub score: u32,
    pub findings: Vec<Finding>,
    pub total_entries: usize,
    pub weak: usize,
    pub reused: usize,
    pub stale: usize,
    pub expired: usize,
}

/// Below this many bits, call it weak.
///
/// 50 bits is roughly a 10-character mixed-case password with a digit. It is
/// not a bright line — entropy estimates never are — but it separates
/// "generated" from "typed from memory", which is the distinction that matters.
const WEAK_BITS: f32 = 50.0;

/// A year in seconds.
const STALE_AFTER: i64 = 365 * 24 * 60 * 60;

/// Estimate entropy the same way the UI's strength meter does, so a password
/// the editor calls weak is the same one the report flags.
pub fn entropy_bits(password: &str) -> f32 {
    if password.is_empty() {
        return 0.0;
    }
    let mut classes = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) { classes += 26; }
    if password.chars().any(|c| c.is_ascii_uppercase()) { classes += 26; }
    if password.chars().any(|c| c.is_ascii_digit()) { classes += 10; }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) { classes += 33; }
    password.chars().count() as f32 * (classes.max(2) as f32).log2()
}

/// One entry as the audit needs to see it.
pub struct AuditInput<'a> {
    pub id: i64,
    pub name: &'a str,
    pub password: &'a str,
    pub has_totp: bool,
    pub has_uri: bool,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

/// Score a vault. `now` is passed in so the result is testable rather than
/// dependent on the clock.
pub fn audit(entries: &[AuditInput<'_>], now: i64) -> Report {
    // Count each distinct password once so reuse is symmetric: if two entries
    // share a password, BOTH are flagged. Flagging only the later one would
    // suggest the first is fine.
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for e in entries {
        *seen.entry(e.password).or_insert(0) += 1;
    }

    let mut findings = Vec::new();
    let (mut weak, mut reused, mut stale, mut expired) = (0, 0, 0, 0);

    for e in entries {
        let mut issues = Vec::new();

        if entropy_bits(e.password) < WEAK_BITS {
            issues.push(Issue::Weak);
            weak += 1;
        }
        if seen.get(e.password).copied().unwrap_or(0) > 1 {
            issues.push(Issue::Reused);
            reused += 1;
        }
        if let Some(at) = e.expires_at {
            if at <= now {
                issues.push(Issue::Expired);
                expired += 1;
            }
        }
        // Expiry supersedes staleness: reporting both for the same entry says
        // the same thing twice and double-charges the score.
        if !issues.contains(&Issue::Expired) && now.saturating_sub(e.updated_at) > STALE_AFTER {
            issues.push(Issue::Stale);
            stale += 1;
        }
        if e.has_uri && !e.has_totp {
            issues.push(Issue::NoTwoFactor);
        }

        if !issues.is_empty() {
            findings.push(Finding { id: e.id, name: e.name.to_string(), issues });
        }
    }

    // Score: average penalty per entry, so a vault of 500 good entries is not
    // dragged down by one bad one the way a total would drag it.
    let score = if entries.is_empty() {
        100
    } else {
        let penalty: f32 = findings
            .iter()
            .map(|f| f.issues.iter().map(|i| i.weight()).sum::<f32>())
            .sum();
        let average = penalty / entries.len() as f32;
        (100.0 - average).clamp(0.0, 100.0).round() as u32
    };

    // Worst first: a report you have to scroll to find the problem in is a
    // report nobody acts on.
    findings.sort_by(|a, b| {
        let pa: f32 = a.issues.iter().map(|i| i.weight()).sum();
        let pb: f32 = b.issues.iter().map(|i| i.weight()).sum();
        pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
    });

    Report {
        score,
        findings,
        total_entries: entries.len(),
        weak,
        reused,
        stale,
        expired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn entry<'a>(id: i64, name: &'a str, pw: &'a str) -> AuditInput<'a> {
        AuditInput {
            id,
            name,
            password: pw,
            has_totp: false,
            has_uri: false,
            updated_at: NOW,
            expires_at: None,
        }
    }

    #[test]
    fn an_empty_vault_is_not_a_broken_one() {
        let report = audit(&[], NOW);
        assert_eq!(report.score, 100);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_strong_unique_password_raises_nothing() {
        let report = audit(&[entry(1, "Good", "T7#kq9Zm!wR2xL4vB8n")], NOW);
        assert_eq!(report.score, 100);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn both_halves_of_a_reused_pair_are_flagged() {
        // Flagging only the second would imply the first is fine, and the user
        // would fix one and leave the pair intact.
        let report = audit(
            &[
                entry(1, "Mail", "T7#kq9Zm!wR2xL4vB8n"),
                entry(2, "Bank", "T7#kq9Zm!wR2xL4vB8n"),
            ],
            NOW,
        );
        assert_eq!(report.reused, 2);
        assert_eq!(report.findings.len(), 2);
        for f in &report.findings {
            assert!(f.issues.contains(&Issue::Reused));
        }
    }

    #[test]
    fn a_short_password_is_weak() {
        let report = audit(&[entry(1, "Bad", "hunter2")], NOW);
        assert!(report.findings[0].issues.contains(&Issue::Weak));
        assert_eq!(report.weak, 1);
        assert!(report.score < 100);
    }

    #[test]
    fn expiry_supersedes_staleness_rather_than_stacking_with_it() {
        // Both would say the same thing twice and charge the score twice.
        let old = NOW - (400 * 24 * 60 * 60);
        let e = AuditInput {
            id: 1,
            name: "Old",
            password: "T7#kq9Zm!wR2xL4vB8n",
            has_totp: false,
            has_uri: false,
            updated_at: old,
            expires_at: Some(NOW - 10),
        };
        let report = audit(&[e], NOW);
        let issues = &report.findings[0].issues;
        assert!(issues.contains(&Issue::Expired));
        assert!(!issues.contains(&Issue::Stale));
        assert_eq!(report.stale, 0);
    }

    #[test]
    fn an_untouched_password_goes_stale_after_a_year() {
        let e = AuditInput {
            updated_at: NOW - (366 * 24 * 60 * 60),
            ..entry(1, "Ancient", "T7#kq9Zm!wR2xL4vB8n")
        };
        let report = audit(&[e], NOW);
        assert!(report.findings[0].issues.contains(&Issue::Stale));
    }

    #[test]
    fn a_site_login_without_two_factor_is_noted_but_barely_penalised() {
        // A missing second factor is advice, not a defect; it must not sink an
        // otherwise healthy vault.
        let e = AuditInput {
            has_uri: true,
            ..entry(1, "Site", "T7#kq9Zm!wR2xL4vB8n")
        };
        let report = audit(&[e], NOW);
        assert!(report.findings[0].issues.contains(&Issue::NoTwoFactor));
        assert!(report.score >= 95, "score was {}", report.score);
    }

    #[test]
    fn one_bad_entry_does_not_sink_a_large_healthy_vault() {
        // The score is an average penalty, not a total: otherwise every vault
        // trends to zero as it grows, and the number stops meaning anything.
        // Distinct passwords, deliberately: giving them all the same one would
        // make every entry Reused, which is what the audit is supposed to
        // catch — and would test the opposite of what this test claims.
        let pool: Vec<String> = (0..99).map(|i| format!("T7#kq9Zm!wR2xL4vB{i:03}")).collect();
        let mut entries: Vec<AuditInput> = pool
            .iter()
            .enumerate()
            .map(|(i, pw)| AuditInput {
                id: i as i64,
                name: "Good",
                password: pw,
                has_totp: false,
                has_uri: false,
                updated_at: NOW,
                expires_at: None,
            })
            .collect();
        entries.push(entry(100, "Bad", "abc"));
        let report = audit(&entries, NOW);
        assert!(report.score > 90, "score was {}", report.score);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn the_worst_entry_is_reported_first() {
        let report = audit(
            &[
                AuditInput { has_uri: true, ..entry(1, "Minor", "T7#kq9Zm!wR2xL4vB8n") },
                entry(2, "Terrible", "abc"),
                entry(3, "AlsoTerrible", "abc"),
            ],
            NOW,
        );
        // The reused-and-weak pair outranks the merely-missing-2FA entry.
        assert_ne!(report.findings[0].name, "Minor");
        assert!(report.findings[0].issues.len() >= 2);
    }
}
