use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanProfile {
    QuickCommonPorts,
    StandardTcp,
    LightServiceDetection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub profile: ScanProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortEntry {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostResult {
    pub address: String,
    pub hostname: String,
    pub ports: Vec<PortEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanResult {
    pub hosts: Vec<HostResult>,
    pub elapsed_seconds: f64,
}
