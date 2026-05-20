use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NmapStatus {
    pub installed: bool,
    pub executable_path: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
}

pub fn detect() -> NmapStatus {
    let Some(path) = resolve_nmap_path() else {
        return NmapStatus {
            installed: false,
            executable_path: None,
            version: None,
            error: Some("nmap executable not found".into()),
        };
    };
    match Command::new(&path).arg("--version").output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            NmapStatus {
                installed: true,
                executable_path: Some(path.to_string_lossy().into_owned()),
                version: parse_version(&stdout),
                error: None,
            }
        }
        Err(e) => NmapStatus {
            installed: false,
            executable_path: None,
            version: None,
            error: Some(e.to_string()),
        },
    }
}

pub fn resolve_nmap_path() -> Option<PathBuf> {
    if let Ok(p) = which::which("nmap") {
        return Some(p);
    }
    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

// Parses "Nmap version 7.94 ( https://nmap.org )" → "7.94"
fn parse_version(output: &str) -> Option<String> {
    output
        .lines()
        .next()?
        .split_whitespace()
        .nth(2)
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_version_line() {
        let raw = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64\n";
        assert_eq!(parse_version(raw), Some("7.94".to_string()));
    }

    #[test]
    fn parse_empty_output() {
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn parse_malformed_output() {
        assert_eq!(parse_version("version"), None);
    }
}
