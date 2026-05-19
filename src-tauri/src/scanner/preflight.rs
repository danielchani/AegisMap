use crate::error::AppError;
use crate::models::ScanProfile;

/// Returns true for profiles that require raw-socket access.
///
/// On Linux/macOS: process must run as root (EUID 0).
/// On Windows: Npcap must be installed (kernel driver in System32\Npcap).
pub fn profile_requires_elevation(profile: &ScanProfile) -> bool {
    matches!(
        profile,
        ScanProfile::StealthSyn
            | ScanProfile::AckProbe
            | ScanProfile::EvasionScan
            | ScanProfile::UdpCommon
            | ScanProfile::OsDetect
    )
}

/// Returns true if the current process has the privileges needed for raw-socket scans.
pub fn has_raw_socket_access() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Npcap installs a kernel driver; check for its System32 directory.
        std::path::Path::new(r"C:\Windows\System32\Npcap").is_dir()
            || std::path::Path::new(r"C:\Windows\SysWOW64\Npcap").is_dir()
    }

    #[cfg(target_os = "linux")]
    {
        // /proc/self/status: "Uid: ruid euid suid fsuid" — field index 2 is EUID.
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(2))
                    .and_then(|uid| uid.parse::<u32>().ok())
            })
            .map(|euid| euid == 0)
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|uid| uid == 0)
            .unwrap_or(false)
    }

    // Fallback for unsupported platforms — allow and let nmap report the error.
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        true
    }
}

/// Returns an error if `profile` requires elevation and the process is not elevated.
/// Call this before spawning nmap to give users an immediate, actionable message
/// rather than a raw nmap exit-code failure.
pub fn check_profile_privileges(profile: &ScanProfile) -> Result<(), AppError> {
    if !profile_requires_elevation(profile) {
        return Ok(());
    }
    if has_raw_socket_access() {
        return Ok(());
    }
    Err(AppError::ScanFailed(
        "This scan profile requires elevated privileges. \
         On Linux/macOS: run AegisMap as root or via sudo. \
         On Windows: install Npcap (https://npcap.com) and run AegisMap as Administrator."
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_profiles_require_elevation() {
        assert!(profile_requires_elevation(&ScanProfile::StealthSyn));
        assert!(profile_requires_elevation(&ScanProfile::AckProbe));
        assert!(profile_requires_elevation(&ScanProfile::EvasionScan));
        assert!(profile_requires_elevation(&ScanProfile::UdpCommon));
        assert!(profile_requires_elevation(&ScanProfile::OsDetect));
    }

    #[test]
    fn standard_profiles_do_not_require_elevation() {
        assert!(!profile_requires_elevation(&ScanProfile::QuickCommonPorts));
        assert!(!profile_requires_elevation(&ScanProfile::StandardTcp));
        assert!(!profile_requires_elevation(&ScanProfile::LightServiceDetection));
    }

    #[test]
    fn check_passes_for_non_privileged_profile() {
        // QuickCommonPorts never needs root — must always succeed regardless of OS state.
        assert!(check_profile_privileges(&ScanProfile::QuickCommonPorts).is_ok());
        assert!(check_profile_privileges(&ScanProfile::StandardTcp).is_ok());
    }
}
