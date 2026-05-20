pub struct ProgressHint {
    pub percent: f32,
    pub etc_seconds: Option<u32>,
}

/// Parses nmap `--stats-every` lines such as:
/// "Connect Scan Timing: About 2.45% done; ETC: 17:30 (0:00:38 remaining)"
pub fn parse_progress(line: &str) -> Option<ProgressHint> {
    let percent_end = line.find("% done")?;
    let about_start = line[..percent_end].rfind("About ")? + 6;
    let percent: f32 = line[about_start..percent_end].trim().parse().ok()?;
    let etc_seconds = parse_remaining_seconds(line);
    Some(ProgressHint { percent, etc_seconds })
}

fn parse_remaining_seconds(line: &str) -> Option<u32> {
    let open = line.find('(')?;
    let kw = line.find(" remaining)")?;
    if kw <= open {
        return None;
    }
    let parts: Vec<u32> = line[open + 1..kw]
        .trim()
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<u32>>>()?;
    match parts.as_slice() {
        [m, s] => Some(m * 60 + s),
        [h, m, s] => Some(h * 3600 + m * 60 + s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_percent_and_remaining() {
        let line = "Connect Scan Timing: About 2.45% done; ETC: 17:30 (0:00:38 remaining)";
        let h = parse_progress(line).unwrap();
        assert!((h.percent - 2.45).abs() < 0.001);
        assert_eq!(h.etc_seconds, Some(38));
    }

    #[test]
    fn parses_remaining_with_minutes() {
        let line = "SYN Scan Timing: About 50.00% done; ETC: 10:00 (0:01:30 remaining)";
        let h = parse_progress(line).unwrap();
        assert_eq!(h.etc_seconds, Some(90));
    }

    #[test]
    fn returns_none_for_plain_line() {
        assert!(parse_progress("Nmap scan report for 192.168.1.1").is_none());
    }

    #[test]
    fn requires_about_keyword() {
        assert!(parse_progress("Scan 5% done but no About prefix").is_none());
    }

    #[test]
    fn no_remaining_gives_none_etc() {
        let line = "Timing: About 75.00% done; ETC: 10:00";
        let h = parse_progress(line).unwrap();
        assert_eq!(h.etc_seconds, None);
    }
}
