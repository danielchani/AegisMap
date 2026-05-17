use serde::Serialize;

#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "kind", content = "message")]
pub enum AppError {
    #[error("Nmap not found: {0}")]
    NmapNotFound(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("IO error: {0}")]
    Io(String),
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}
