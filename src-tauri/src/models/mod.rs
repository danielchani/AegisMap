use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfile {
    QuickCommonPorts,
    StandardTcp,
    LightServiceDetection,
    OsDetect,
    UdpCommon,    // top-20 UDP ports; requires root/admin
    StealthSyn,   // -sS SYN scan — incomplete handshake, requires root/admin
    AckProbe,     // -sA ACK scan for firewall ruleset mapping, requires root/admin
    EvasionScan,  // -sF + -f FIN scan + packet fragmentation, requires root/admin
}

/// Frontend sends camelCase keys; `rename_all` maps them to Rust snake_case fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub target: String,
    pub profile: ScanProfile,
    #[serde(default)]
    pub port_range: Option<String>,
    /// NSE script names — validated against a backend allowlist before use.
    #[serde(default)]
    pub scripts: Option<Vec<String>>,
    /// Decoy IP list for -D flag: comma-separated IPv4/IPv6 addresses + ME/RND keywords.
    /// Validated strictly before use — no shell metacharacters allowed.
    #[serde(default)]
    pub decoys: Option<String>,
    /// Timing template override 0–4 (paranoid to aggressive).
    /// None = use profile default. Validated to be 0–4 before use.
    #[serde(default)]
    pub timing_override: Option<u8>,
    /// Source port override for --source-port. Validated 1–65535.
    #[serde(default)]
    pub source_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScriptResult {
    pub id: String,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortEntry {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostResult {
    pub address: String,
    pub hostname: Option<String>,
    pub status: String,
    pub ports: Vec<PortEntry>,
    /// Script results from NSE (both host-level and port-level, flattened).
    pub script_results: Vec<ScriptResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub target: String,
    pub profile: ScanProfile,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub elapsed_seconds: Option<f64>,
    pub hosts: Vec<HostResult>,
}

// Kept for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanResult {
    pub hosts: Vec<HostResult>,
    pub elapsed_seconds: f64,
}
