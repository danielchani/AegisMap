use std::path::Path;
use std::time::Duration;

use crate::models::ScanProfile;

/// Builds the full nmap argument list for the given profile.
///
/// Arguments are inserted in this order (nmap processes them left-to-right):
///   profile_flags … [timing] [-D decoys] [--source-port n] [-p range]
///   [--script names] -oX <xml_path> <target>
///
/// Timing rules:
/// - `timing_override` (0–4) always wins; it is appended after the profile args so
///   nmap uses the last -T flag seen (nmap's documented behaviour).
/// - StealthSyn / AckProbe / EvasionScan default to T2 (polite) when no override is given.
/// - All other profiles embed T4 in their base arg list.
pub fn scan_args(
    profile: &ScanProfile,
    target: &str,
    xml_path: &Path,
    port_range: Option<&str>,
    scripts: Option<&[String]>,
    decoys: Option<&str>,
    timing_override: Option<u8>,
    source_port: Option<u16>,
) -> Vec<String> {
    let xml = xml_path.to_string_lossy().into_owned();

    let mut args: Vec<String> = match profile {
        ScanProfile::QuickCommonPorts => {
            vec!["-sT", "--top-ports", "100", "-T4", "-v", "--stats-every", "1s"]
        }
        ScanProfile::StandardTcp => {
            vec!["-sT", "-T4", "-v", "--stats-every", "1s"]
        }
        ScanProfile::LightServiceDetection => {
            vec!["-sT", "-sV", "--version-light", "-T4", "-v", "--stats-every", "1s"]
        }
        ScanProfile::OsDetect => {
            vec!["-sT", "-sV", "-O", "--version-light", "-T4", "-v", "--stats-every", "1s"]
        }
        ScanProfile::UdpCommon => {
            // -sU requires root/admin; nmap reports an error via stderr if not elevated.
            vec!["-sU", "--top-ports", "20", "-T4", "-v", "--stats-every", "1s"]
        }
        ScanProfile::StealthSyn => {
            // Half-open SYN scan — never completes the three-way handshake.
            // Quieter than connect scan; requires root (Linux) or Npcap (Windows).
            vec!["-sS", "--top-ports", "1000", "-v", "--stats-every", "1s"]
        }
        ScanProfile::AckProbe => {
            // ACK scan — maps firewall rulesets by testing RST (unfiltered) vs drop (filtered).
            // Does NOT detect open ports; use alongside another scan.
            // Requires root (Linux) or Npcap (Windows).
            vec!["-sA", "--top-ports", "1000", "-v", "--stats-every", "1s"]
        }
        ScanProfile::EvasionScan => {
            // SYN scan with IP decoys + packet fragmentation.
            // Decoys confuse simple IDS log correlation; -f splits TCP headers across
            // two IP fragments, defeating naive packet-filter signatures.
            // Requires root (Linux) or Npcap (Windows).
            vec!["-sS", "-f", "--top-ports", "1000", "-v", "--stats-every", "1s"]
        }
    }
    .into_iter()
    .map(String::from)
    .collect();

    // Timing — appended last so the override wins over any T4 in the base args.
    let timing = timing_override
        .map(|t| format!("-T{}", t))
        .or_else(|| {
            matches!(
                profile,
                ScanProfile::StealthSyn | ScanProfile::AckProbe | ScanProfile::EvasionScan
            )
            .then(|| "-T2".to_string())
        });
    if let Some(t) = timing {
        args.push(t);
    }

    // Decoys — EvasionScan defaults to RND:5 if the user did not specify any.
    let effective_decoys = decoys.or_else(|| {
        matches!(profile, ScanProfile::EvasionScan).then_some("RND:5")
    });
    if let Some(d) = effective_decoys {
        args.push("-D".to_string());
        args.push(d.to_string());
    }

    // Source-port spoofing — useful for crossing stateful firewalls (e.g. --source-port 53).
    if let Some(sp) = source_port {
        args.push("--source-port".to_string());
        args.push(sp.to_string());
    }

    if let Some(range) = port_range {
        args.push("-p".to_string());
        args.push(range.to_string());
    }

    if let Some(script_list) = scripts {
        if !script_list.is_empty() {
            args.push("--script".to_string());
            args.push(script_list.join(","));
        }
    }

    args.push("-oX".to_string());
    args.push(xml);
    args.push(target.to_string());
    args
}

/// Hard timeout per profile.  The watchdog thread in executor.rs sleeps this
/// long then kills the child if it is still running.
pub fn profile_timeout(profile: &ScanProfile) -> Duration {
    match profile {
        ScanProfile::QuickCommonPorts      => Duration::from_secs(90),
        ScanProfile::StandardTcp           => Duration::from_secs(600),
        ScanProfile::LightServiceDetection => Duration::from_secs(600),
        ScanProfile::OsDetect              => Duration::from_secs(300),
        ScanProfile::UdpCommon             => Duration::from_secs(300),
        // Stealth profiles run at T2 (polite timing) — allow more time
        ScanProfile::StealthSyn            => Duration::from_secs(480),
        ScanProfile::AckProbe              => Duration::from_secs(480),
        // Evasion adds fragmentation overhead on top of decoys
        ScanProfile::EvasionScan           => Duration::from_secs(600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn xml() -> PathBuf { PathBuf::from("/tmp/scan.xml") }
    fn args(p: &ScanProfile) -> Vec<String> {
        scan_args(p, "10.0.0.1", &xml(), None, None, None, None, None)
    }

    #[test]
    fn quick_includes_top_ports() {
        let a = args(&ScanProfile::QuickCommonPorts);
        assert!(a.contains(&"--top-ports".to_string()));
        assert!(a.contains(&"100".to_string()));
    }

    #[test]
    fn standard_no_top_ports() {
        let a = args(&ScanProfile::StandardTcp);
        assert!(!a.contains(&"--top-ports".to_string()));
    }

    #[test]
    fn light_service_includes_sv() {
        let a = args(&ScanProfile::LightServiceDetection);
        assert!(a.contains(&"-sV".to_string()));
        assert!(a.contains(&"--version-light".to_string()));
    }

    #[test]
    fn os_detect_includes_o_flag() {
        let a = args(&ScanProfile::OsDetect);
        assert!(a.contains(&"-O".to_string()));
    }

    #[test]
    fn udp_common_uses_su_flag() {
        let a = args(&ScanProfile::UdpCommon);
        assert!(a.contains(&"-sU".to_string()));
        assert!(a.contains(&"--top-ports".to_string()));
        assert!(a.contains(&"20".to_string()));
    }

    #[test]
    fn stealth_uses_ss_flag() {
        let a = args(&ScanProfile::StealthSyn);
        assert!(a.contains(&"-sS".to_string()));
        assert!(!a.contains(&"-sT".to_string()));
    }

    #[test]
    fn stealth_defaults_to_t2() {
        let a = args(&ScanProfile::StealthSyn);
        assert!(a.contains(&"-T2".to_string()));
        assert!(!a.contains(&"-T4".to_string()));
    }

    #[test]
    fn ack_probe_uses_sa_flag() {
        let a = args(&ScanProfile::AckProbe);
        assert!(a.contains(&"-sA".to_string()));
    }

    #[test]
    fn evasion_includes_fragmentation() {
        let a = args(&ScanProfile::EvasionScan);
        assert!(a.contains(&"-sS".to_string()));
        assert!(a.contains(&"-f".to_string()));
    }

    #[test]
    fn evasion_adds_default_decoys_when_none_set() {
        let a = args(&ScanProfile::EvasionScan);
        let d_pos = a.iter().position(|x| x == "-D").expect("-D must be present");
        assert_eq!(a[d_pos + 1], "RND:5");
    }

    #[test]
    fn evasion_uses_caller_decoys_over_default() {
        let a = scan_args(
            &ScanProfile::EvasionScan, "10.0.0.1", &xml(),
            None, None, Some("192.168.1.1,ME"), None, None,
        );
        let d_pos = a.iter().position(|x| x == "-D").unwrap();
        assert_eq!(a[d_pos + 1], "192.168.1.1,ME");
    }

    #[test]
    fn decoys_placed_after_timing_before_port_range() {
        let a = scan_args(
            &ScanProfile::StealthSyn, "target", &xml(),
            Some("80,443"), None, Some("RND:3"), None, None,
        );
        let d_pos  = a.iter().position(|x| x == "-D").unwrap();
        let p_pos  = a.iter().position(|x| x == "-p").unwrap();
        let ox_pos = a.iter().position(|x| x == "-oX").unwrap();
        assert!(d_pos < p_pos && p_pos < ox_pos);
    }

    #[test]
    fn timing_override_appended_after_profile_timing() {
        // For existing profiles that embed T4, the override (T1) appears last
        let a = scan_args(
            &ScanProfile::StandardTcp, "target", &xml(),
            None, None, None, Some(1), None,
        );
        let t4_pos = a.iter().position(|x| x == "-T4").unwrap();
        let t1_pos = a.iter().position(|x| x == "-T1").unwrap();
        assert!(t4_pos < t1_pos, "override must appear after the profile default");
    }

    #[test]
    fn timing_override_appended_for_stealth_profile() {
        let a = scan_args(
            &ScanProfile::StealthSyn, "target", &xml(),
            None, None, None, Some(3), None,
        );
        // Override replaces the default T2 (only one timing flag present)
        let t3_pos = a.iter().position(|x| x == "-T3").unwrap();
        // T2 should NOT be present since override is set
        assert!(!a.contains(&"-T2".to_string()));
        assert!(a[t3_pos] == "-T3");
    }

    #[test]
    fn source_port_inserted_before_ox() {
        let a = scan_args(
            &ScanProfile::StealthSyn, "target", &xml(),
            None, None, None, None, Some(53),
        );
        let sp_pos = a.iter().position(|x| x == "--source-port").unwrap();
        let ox_pos = a.iter().position(|x| x == "-oX").unwrap();
        assert_eq!(a[sp_pos + 1], "53");
        assert!(sp_pos < ox_pos);
    }

    #[test]
    fn all_profiles_end_with_target() {
        for profile in [
            ScanProfile::QuickCommonPorts,
            ScanProfile::StandardTcp,
            ScanProfile::LightServiceDetection,
            ScanProfile::OsDetect,
            ScanProfile::UdpCommon,
            ScanProfile::StealthSyn,
            ScanProfile::AckProbe,
            ScanProfile::EvasionScan,
        ] {
            let a = args(&profile);
            assert_eq!(a.last().unwrap(), "10.0.0.1", "profile {:?} must end with target", profile);
        }
    }

    #[test]
    fn port_range_inserted_before_ox() {
        let a = scan_args(&ScanProfile::StandardTcp, "target", &xml(), Some("22,80,443"), None, None, None, None);
        let p_pos  = a.iter().position(|x| x == "-p").unwrap();
        let ox_pos = a.iter().position(|x| x == "-oX").unwrap();
        assert_eq!(a[p_pos + 1], "22,80,443");
        assert!(p_pos < ox_pos);
    }

    #[test]
    fn nse_scripts_inserted_correctly() {
        let scripts = vec!["http-title".to_string(), "ssl-cert".to_string()];
        let a = scan_args(&ScanProfile::StandardTcp, "target", &xml(), None, Some(&scripts), None, None, None);
        let sc_pos = a.iter().position(|x| x == "--script").unwrap();
        let ox_pos = a.iter().position(|x| x == "-oX").unwrap();
        assert_eq!(a[sc_pos + 1], "http-title,ssl-cert");
        assert!(sc_pos < ox_pos);
    }

    #[test]
    fn xml_path_preceded_by_ox_flag() {
        let a = args(&ScanProfile::StandardTcp);
        let ox_pos = a.iter().position(|x| x == "-oX").unwrap();
        assert_eq!(a[ox_pos + 1], xml().to_string_lossy().as_ref());
    }

    #[test]
    fn no_arg_contains_shell_metachar() {
        for profile in [
            ScanProfile::LightServiceDetection,
            ScanProfile::StealthSyn,
            ScanProfile::EvasionScan,
        ] {
            let a = args(&profile);
            for arg in &a {
                assert!(!arg.contains(';'), "profile {profile:?} arg {arg:?} has semicolon");
                assert!(!arg.contains('&'), "profile {profile:?} arg {arg:?} has ampersand");
                assert!(!arg.contains('|'), "profile {profile:?} arg {arg:?} has pipe");
                assert!(!arg.contains('$'), "profile {profile:?} arg {arg:?} has dollar");
            }
        }
    }

    #[test]
    fn profile_timeout_values_are_positive() {
        for profile in [
            ScanProfile::QuickCommonPorts,
            ScanProfile::StandardTcp,
            ScanProfile::LightServiceDetection,
            ScanProfile::OsDetect,
            ScanProfile::UdpCommon,
            ScanProfile::StealthSyn,
            ScanProfile::AckProbe,
            ScanProfile::EvasionScan,
        ] {
            assert!(profile_timeout(&profile).as_secs() > 0);
        }
    }

    #[test]
    fn quick_timeout_shorter_than_full_tcp() {
        assert!(
            profile_timeout(&ScanProfile::QuickCommonPorts) <
            profile_timeout(&ScanProfile::StandardTcp)
        );
    }

    #[test]
    fn stealth_timeout_longer_than_quick() {
        assert!(
            profile_timeout(&ScanProfile::StealthSyn) >
            profile_timeout(&ScanProfile::QuickCommonPorts)
        );
    }
}
