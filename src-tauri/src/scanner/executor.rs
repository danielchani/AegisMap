use std::io::BufRead;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;
use crate::models::{ScanProfile, ScanRequest};
use crate::scanner::{
    nmap, preflight, profiles, progress,
    stream::ScanStreamEvent,
    validation::{self, validate_cidr_scope, validate_decoys, validate_nse_scripts, validate_port_range, validate_timing},
    xml_parser,
};

struct ScanStateInner {
    child: Option<std::process::Child>,
    xml_path: Option<PathBuf>,
    cancelled: bool,
    timed_out: bool,
}

pub struct ScanState(Mutex<ScanStateInner>);

impl ScanState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(ScanStateInner {
            child: None,
            xml_path: None,
            cancelled: false,
            timed_out: false,
        })))
    }
}

pub fn temp_xml_path() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("aegismap-{}.xml", ts))
}

/// Returns true if the stderr line indicates a privilege/capability error.
/// Used to provide a clearer error message than "nmap exited with code 1".
fn is_privilege_error(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("requires root")
        || l.contains("requires superuser")
        || l.contains("requires administrator")
        || l.contains("you requested a scan type which requires")
        || l.contains("operation not permitted")
        || l.contains("must be root")
        || l.contains("access is denied")
        || l.contains("no raw tcp mode")
        || l.contains("pcap_error")
        || l.contains("failed to initialize winpcap")
        || l.contains("npcap is not installed")
}

pub fn start_scan(
    request: &ScanRequest,
    channel: tauri::ipc::Channel<ScanStreamEvent>,
    state: &Arc<ScanState>,
) -> Result<(), AppError> {
    let validated = validation::validate_target(&request.target)?;
    validate_cidr_scope(validated)?;
    preflight::check_profile_privileges(&request.profile)?;

    let nmap_path = nmap::resolve_nmap_path()
        .ok_or_else(|| AppError::NmapNotFound("nmap executable not found".into()))?;

    {
        let mut inner = state.0.lock().unwrap();
        if inner.child.is_some() {
            return Err(AppError::ScanFailed("a scan is already in progress".into()));
        }
        inner.cancelled  = false;
        inner.timed_out  = false;
    }

    // Validate optional parameters
    let port_range: Option<&str> = if let Some(ref pr) = request.port_range {
        Some(validate_port_range(pr)?)
    } else {
        None
    };

    if let Some(ref scripts) = request.scripts {
        validate_nse_scripts(scripts)?;
    }
    let scripts_slice: Option<&[String]> = request.scripts.as_deref();

    let decoys_opt: Option<&str> = if let Some(ref d) = request.decoys {
        Some(validate_decoys(d)?)
    } else {
        None
    };

    let timing_opt: Option<u8> = if let Some(t) = request.timing_override {
        Some(validate_timing(t)?)
    } else {
        None
    };

    if let Some(sp) = request.source_port {
        if sp == 0 {
            return Err(AppError::InvalidTarget("source_port must be 1–65535".into()));
        }
    }

    let xml_path = temp_xml_path();
    let args = profiles::scan_args(
        &request.profile, validated, &xml_path,
        port_range, scripts_slice,
        decoys_opt, timing_opt, request.source_port,
    );
    let timeout = profiles::profile_timeout(&request.profile);

    let mut child = std::process::Command::new(&nmap_path)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AppError::ScanFailed(format!("failed to launch nmap: {}", e)))?;

    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();

    {
        let mut inner = state.0.lock().unwrap();
        inner.child    = Some(child);
        inner.xml_path = Some(xml_path);
    }

    let scan_target  = validated.to_owned();
    let scan_profile: ScanProfile = request.profile.clone();
    let watchdog_profile = request.profile.clone();

    channel.send(ScanStreamEvent::Started).ok();

    // ── Watchdog thread ───────────────────────────────────────────────────────
    let watchdog_state = Arc::clone(state);
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        let child_opt = {
            let mut inner = watchdog_state.0.lock().unwrap();
            if inner.child.is_some() && !inner.cancelled {
                inner.timed_out = true;
                inner.child.take()
            } else {
                None
            }
        };
        if let Some(mut child) = child_opt {
            child.kill().ok();
            child.wait().ok();
        }
        let _ = watchdog_profile;
    });

    // ── Stderr reader — detects privilege errors ──────────────────────────────
    // Shares a flag with the stdout reader so it can emit a better error message.
    let priv_err_flag = Arc::new(Mutex::new(false));
    let priv_err_writer = Arc::clone(&priv_err_flag);

    let ch_err = channel.clone();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr_pipe).lines() {
            match line {
                Ok(l) => {
                    if is_privilege_error(&l) {
                        *priv_err_writer.lock().unwrap() = true;
                    }
                    ch_err.send(ScanStreamEvent::StderrLine { line: l }).ok();
                }
                Err(_) => break,
            }
        }
    });

    // ── Stdout reader — owns the terminal event ───────────────────────────────
    let watcher_state = Arc::clone(state);
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout_pipe).lines() {
            match line {
                Ok(l) => {
                    if let Some(hint) = progress::parse_progress(&l) {
                        channel.send(ScanStreamEvent::ProgressHint {
                            percent: hint.percent,
                            etc_seconds: hint.etc_seconds,
                        }).ok();
                    }
                    channel.send(ScanStreamEvent::StdoutLine { line: l }).ok();
                }
                Err(_) => break,
            }
        }

        let (child_opt, xml_path_opt, cancelled, timed_out) = {
            let mut inner = watcher_state.0.lock().unwrap();
            (inner.child.take(), inner.xml_path.take(), inner.cancelled, inner.timed_out)
        };

        let exit_code = child_opt
            .and_then(|mut c| c.wait().ok())
            .and_then(|s| s.code())
            .unwrap_or(-1);

        // Terminal event priority: timed_out > cancelled > privilege_error > exit_code
        if timed_out {
            channel.send(ScanStreamEvent::Failed {
                message: format!("scan timed out after {}s", timeout.as_secs()),
            }).ok();
        } else if cancelled {
            channel.send(ScanStreamEvent::Cancelled).ok();
        } else if exit_code == 0 {
            if let Some(xml_path) = xml_path_opt {
                match std::fs::read_to_string(&xml_path) {
                    Ok(content) => match xml_parser::parse_xml(&content, &scan_target, &scan_profile) {
                        Ok(report) => {
                            channel.send(ScanStreamEvent::ParsedResult { report }).ok();
                        }
                        Err(e) => {
                            channel.send(ScanStreamEvent::StderrLine {
                                line: format!("[warning] XML parse failed: {}", e),
                            }).ok();
                        }
                    },
                    Err(e) => {
                        channel.send(ScanStreamEvent::StderrLine {
                            line: format!("[warning] could not read XML output: {}", e),
                        }).ok();
                    }
                }
                std::fs::remove_file(&xml_path).ok();
            }
            channel.send(ScanStreamEvent::Completed { exit_code: 0 }).ok();
        } else {
            // Check if stderr indicated a privilege/capability problem and emit
            // a more actionable message than the raw exit code.
            let had_priv_error = *priv_err_flag.lock().unwrap();
            let message = if had_priv_error {
                "Elevated privileges required for this scan profile. \
                 On Linux run as root or via sudo. \
                 On Windows install Npcap and run AegisMap as Administrator."
                    .to_string()
            } else {
                format!("nmap exited with code {}", exit_code)
            };
            channel.send(ScanStreamEvent::Failed { message }).ok();
        }
    });

    Ok(())
}

pub fn cancel_scan(state: &Arc<ScanState>) -> Result<(), AppError> {
    let child_opt = {
        let mut inner = state.0.lock().unwrap();
        inner.cancelled = true;
        inner.child.take()
    };
    if let Some(mut child) = child_opt {
        child.kill().ok();
        child.wait().ok();
    }
    Ok(())
}
