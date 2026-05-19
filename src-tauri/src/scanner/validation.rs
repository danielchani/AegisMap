use crate::error::AppError;

const MAX_TARGET_LEN: usize = 253;
const MAX_PORT_RANGE_LEN: usize = 100;

/// Curated read-only NSE scripts that are safe for authorized reconnaissance.
/// No destructive, brute-force, or exploit scripts are permitted.
const NSE_ALLOWLIST: &[&str] = &[
    "http-title",
    "http-headers",
    "http-server-header",
    "ssl-cert",
    "ssh-hostkey",
    "smb-security-mode",
    "smb2-security-mode",
    "ftp-anon",
    "rdp-enum-encryption",
    "dns-service-discovery",
    "banner",
    "smtp-commands",
    "imap-capabilities",
    "pop3-capabilities",
];

/// Validates a list of NSE script names against the curated allowlist.
/// Rejects any name not on the list — users can never pass arbitrary scripts.
pub fn validate_nse_scripts(scripts: &[String]) -> Result<(), AppError> {
    for script in scripts {
        let name = script.trim();
        if !NSE_ALLOWLIST.contains(&name) {
            return Err(AppError::InvalidTarget(format!(
                "NSE script not in allowlist: {:?}", name
            )));
        }
    }
    Ok(())
}

/// Validates a port range string such as "22", "80,443", "1-1024", or "22,80-443,8443".
/// Only digits, commas, and hyphens are accepted.
pub fn validate_port_range(input: &str) -> Result<&str, AppError> {
    let t = input.trim();
    if t.is_empty() {
        return Err(AppError::InvalidTarget("port range must not be empty".into()));
    }
    if t.len() > MAX_PORT_RANGE_LEN {
        return Err(AppError::InvalidTarget(format!(
            "port range exceeds maximum length of {} characters",
            MAX_PORT_RANGE_LEN
        )));
    }
    // Allowlist: only digits, commas, hyphens
    if let Some(bad) = t.chars().find(|c| !matches!(c, '0'..='9' | ',' | '-')) {
        return Err(AppError::InvalidTarget(format!(
            "port range contains invalid character: {:?}",
            bad
        )));
    }
    // Must not start with '-' (would be interpreted as a flag)
    if t.starts_with('-') {
        return Err(AppError::InvalidTarget(
            "port range must not start with '-'".into(),
        ));
    }
    Ok(t)
}

const MAX_DECOYS: usize = 8;
const MAX_DECOY_LIST_LEN: usize = 256;

/// Validates a decoy list string for the nmap -D flag.
/// Accepts comma-separated IPv4/IPv6 addresses and the keywords ME, RND, and RND:N.
/// Rejects anything that could be interpreted as a shell metacharacter or nmap flag.
pub fn validate_decoys(input: &str) -> Result<&str, AppError> {
    let t = input.trim();
    if t.is_empty() {
        return Err(AppError::InvalidTarget("decoy list must not be empty".into()));
    }
    if t.len() > MAX_DECOY_LIST_LEN {
        return Err(AppError::InvalidTarget(format!(
            "decoy list exceeds maximum length of {} characters",
            MAX_DECOY_LIST_LEN
        )));
    }
    let parts: Vec<&str> = t.split(',').collect();
    if parts.len() > MAX_DECOYS {
        return Err(AppError::InvalidTarget(format!(
            "too many decoys: {} (maximum is {})",
            parts.len(), MAX_DECOYS
        )));
    }
    for part in &parts {
        let p = part.trim();
        if p.is_empty() {
            return Err(AppError::InvalidTarget("empty entry in decoy list".into()));
        }
        // Keyword ME (real source IP position marker)
        if p.eq_ignore_ascii_case("ME") { continue; }
        // Keyword RND (random IP)
        if p.eq_ignore_ascii_case("RND") { continue; }
        // Keyword RND:N (N random IPs)
        let upper = p.to_ascii_uppercase();
        if upper.starts_with("RND:") {
            let n = &p[4..];
            if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            return Err(AppError::InvalidTarget(format!(
                "invalid RND entry in decoy list: {:?}", p
            )));
        }
        // Must be a valid IP address: only digits, dots (IPv4), hex digits and colons (IPv6)
        if p.chars().any(|c| !matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F' | '.' | ':')) {
            return Err(AppError::InvalidTarget(format!(
                "decoy contains invalid character in entry {:?}", p
            )));
        }
        // Must not start with a dash (would be a flag)
        if p.starts_with('-') {
            return Err(AppError::InvalidTarget(
                "decoy entry must not start with '-'".into()
            ));
        }
    }
    Ok(t)
}

/// Timing template must be 0–4 (paranoid to aggressive).
/// T5 (insane) is deliberately excluded — not useful for authorized testing.
pub fn validate_timing(t: u8) -> Result<u8, AppError> {
    if t <= 4 {
        Ok(t)
    } else {
        Err(AppError::InvalidTarget(format!(
            "timing template must be 0–4, got {}", t
        )))
    }
}

/// IPv4 CIDR must be at least /20 (≤ 4 096 hosts).
/// IPv6 CIDR must be at least /48.
/// Non-CIDR targets (plain IPs, hostnames, ranges) are passed through unchanged.
const MIN_IPV4_PREFIX: u32 = 20;
const MIN_IPV6_PREFIX: u32 = 48;

/// Validates that a CIDR prefix length is not so broad that it would initiate a
/// massive unintended scan.  This is a defence-in-depth control — the Tauri
/// commands layer calls this after `validate_target`.
pub fn validate_cidr_scope(target: &str) -> Result<(), AppError> {
    let t = target.trim();
    let Some(slash) = t.rfind('/') else {
        return Ok(()); // no CIDR notation — nothing to check
    };

    let prefix_str = &t[slash + 1..];
    if prefix_str.is_empty() || !prefix_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::InvalidTarget(
            "CIDR prefix length must be a non-negative integer".into(),
        ));
    }

    let prefix: u32 = prefix_str.parse().map_err(|_| {
        AppError::InvalidTarget("CIDR prefix length out of range".into())
    })?;

    let host_part = &t[..slash];
    if host_part.contains(':') {
        // IPv6 address
        if prefix > 128 {
            return Err(AppError::InvalidTarget(
                "IPv6 CIDR prefix must be 0–128".into(),
            ));
        }
        if prefix < MIN_IPV6_PREFIX {
            return Err(AppError::InvalidTarget(format!(
                "IPv6 CIDR /{prefix} is too broad; minimum allowed is /{MIN_IPV6_PREFIX}"
            )));
        }
    } else {
        // IPv4 address (or hostname with CIDR — nmap accepts this too)
        if prefix > 32 {
            return Err(AppError::InvalidTarget(
                "IPv4 CIDR prefix must be 0–32".into(),
            ));
        }
        if prefix < MIN_IPV4_PREFIX {
            return Err(AppError::InvalidTarget(format!(
                "IPv4 CIDR /{prefix} is too broad; \
                 minimum allowed is /{MIN_IPV4_PREFIX} (≤ 4 096 hosts)"
            )));
        }
    }

    Ok(())
}

fn is_valid_target_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | ':' | '/' | '[' | ']' | '*')
}

pub fn validate_target(input: &str) -> Result<&str, AppError> {
    let t = input.trim();

    if t.is_empty() {
        return Err(AppError::InvalidTarget("target must not be empty".into()));
    }
    if t.len() > MAX_TARGET_LEN {
        return Err(AppError::InvalidTarget(format!(
            "target exceeds maximum length of {} characters",
            MAX_TARGET_LEN
        )));
    }
    if input.contains('\n') || input.contains('\r') {
        return Err(AppError::InvalidTarget(
            "target must not contain newlines".into(),
        ));
    }
    if t.starts_with('-') {
        return Err(AppError::InvalidTarget(
            "target must not start with '-'".into(),
        ));
    }
    if let Some(bad) = t.chars().find(|c| !is_valid_target_char(*c)) {
        return Err(AppError::InvalidTarget(format!(
            "target contains disallowed character: {:?}",
            bad
        )));
    }

    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ipv4() {
        assert!(validate_target("192.168.1.1").is_ok());
    }

    #[test]
    fn accepts_cidr() {
        assert!(validate_target("10.0.0.0/24").is_ok());
    }

    #[test]
    fn accepts_hostname() {
        assert!(validate_target("example.com").is_ok());
    }

    #[test]
    fn accepts_ipv4_range() {
        assert!(validate_target("192.168.1.1-20").is_ok());
    }

    #[test]
    fn accepts_ipv6() {
        assert!(validate_target("::1").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_target("").is_err());
    }

    #[test]
    fn rejects_whitespace_only() {
        assert!(validate_target("   ").is_err());
    }

    #[test]
    fn rejects_multiline() {
        assert!(validate_target("10.0.0.1\n192.168.1.1").is_err());
    }

    #[test]
    fn rejects_semicolon_injection() {
        assert!(validate_target("10.0.0.1; rm -rf /").is_err());
    }

    #[test]
    fn rejects_pipe_injection() {
        assert!(validate_target("10.0.0.1 | cat /etc/passwd").is_err());
    }

    #[test]
    fn rejects_flag_prefix() {
        assert!(validate_target("-sS").is_err());
    }

    #[test]
    fn rejects_backtick_injection() {
        assert!(validate_target("host`id`").is_err());
    }

    #[test]
    fn rejects_dollar_expansion() {
        assert!(validate_target("$HOST").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(MAX_TARGET_LEN + 1);
        assert!(validate_target(&long).is_err());
    }

    // ── validate_cidr_scope tests ────────────────────────────────────────────

    #[test]
    fn cidr_accepts_plain_ip_no_slash() {
        assert!(validate_cidr_scope("192.168.1.1").is_ok());
    }

    #[test]
    fn cidr_accepts_hostname_no_slash() {
        assert!(validate_cidr_scope("example.com").is_ok());
    }

    #[test]
    fn cidr_accepts_ipv4_slash24() {
        assert!(validate_cidr_scope("10.0.0.0/24").is_ok());
    }

    #[test]
    fn cidr_accepts_ipv4_slash20_boundary() {
        assert!(validate_cidr_scope("10.0.0.0/20").is_ok());
    }

    #[test]
    fn cidr_accepts_ipv4_slash32() {
        assert!(validate_cidr_scope("10.0.0.1/32").is_ok());
    }

    #[test]
    fn cidr_rejects_ipv4_slash19() {
        assert!(validate_cidr_scope("10.0.0.0/19").is_err());
    }

    #[test]
    fn cidr_rejects_ipv4_slash0() {
        assert!(validate_cidr_scope("0.0.0.0/0").is_err());
    }

    #[test]
    fn cidr_rejects_ipv4_slash8() {
        assert!(validate_cidr_scope("10.0.0.0/8").is_err());
    }

    #[test]
    fn cidr_rejects_ipv4_prefix_too_large() {
        assert!(validate_cidr_scope("10.0.0.1/33").is_err());
    }

    #[test]
    fn cidr_accepts_ipv6_slash48_boundary() {
        assert!(validate_cidr_scope("2001:db8::/48").is_ok());
    }

    #[test]
    fn cidr_accepts_ipv6_slash64() {
        assert!(validate_cidr_scope("2001:db8::/64").is_ok());
    }

    #[test]
    fn cidr_rejects_ipv6_slash47() {
        assert!(validate_cidr_scope("2001:db8::/47").is_err());
    }

    #[test]
    fn cidr_rejects_ipv6_slash0() {
        assert!(validate_cidr_scope("::/0").is_err());
    }

    #[test]
    fn cidr_rejects_ipv6_prefix_too_large() {
        assert!(validate_cidr_scope("::1/129").is_err());
    }

    #[test]
    fn cidr_rejects_non_numeric_prefix() {
        assert!(validate_cidr_scope("10.0.0.0/abc").is_err());
    }
}
