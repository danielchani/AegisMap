use std::sync::Arc;

use crate::error::AppError;
use crate::intelligence::http::{HttpProbeRequest, HttpProbeResult};
use crate::models::ScanRequest;
use crate::scanner::{
    executor::{self, ScanState},
    nmap::{self, NmapStatus},
    stream::ScanStreamEvent,
    validation,
};

#[tauri::command]
pub fn detect_nmap() -> NmapStatus {
    nmap::detect()
}

#[tauri::command]
pub fn validate_scan_request(request: ScanRequest) -> Result<(), AppError> {
    validation::validate_target(&request.target)?;
    Ok(())
}

#[tauri::command]
pub fn start_scan(
    request: ScanRequest,
    channel: tauri::ipc::Channel<ScanStreamEvent>,
    state: tauri::State<'_, Arc<ScanState>>,
) -> Result<(), AppError> {
    executor::start_scan(&request, channel, &state)
}

#[tauri::command]
pub fn cancel_scan(state: tauri::State<'_, Arc<ScanState>>) -> Result<(), AppError> {
    executor::cancel_scan(&state)
}

// ── Native intelligence commands ────────────────────────────────────────────────

/// Performs an opt-in HTTP/HTTPS surface probe against a single host.
/// Network/TLS failures are embedded in `result.error` rather than returned
/// as `Err`, so the frontend always receives a displayable result.
/// Only validation errors (bad address, invalid port/timeout) propagate as `Err`.
#[tauri::command]
pub async fn probe_http(request: HttpProbeRequest) -> Result<HttpProbeResult, AppError> {
    validation::validate_target(&request.address)?;
    if request.address.contains('/') {
        return Err(AppError::InvalidTarget(
            "HTTP probe requires a single host, not a CIDR range".into(),
        ));
    }
    if request.port == 0 {
        return Err(AppError::InvalidTarget("port must be 1–65535".into()));
    }
    if request.timeout_secs == 0 || request.timeout_secs > 30 {
        return Err(AppError::InvalidTarget(
            "timeout_secs must be 1–30".into(),
        ));
    }
    Ok(crate::intelligence::http::probe(request).await)
}

// ── Session persistence commands ────────────────────────────────────────────────

#[tauri::command]
pub fn save_session(
    app_handle: tauri::AppHandle,
    id: String,
    name: String,
    hosts: serde_json::Value,
) -> Result<(), AppError> {
    crate::persistence::save_session(&app_handle, &id, &name, hosts)
}

#[tauri::command]
pub fn load_session(
    app_handle: tauri::AppHandle,
    id: String,
) -> Result<crate::persistence::PersistedSession, AppError> {
    crate::persistence::load_session(&app_handle, &id)
}

#[tauri::command]
pub fn list_sessions(
    app_handle: tauri::AppHandle,
) -> Result<Vec<crate::persistence::SessionListing>, AppError> {
    crate::persistence::list_sessions(&app_handle)
}

#[tauri::command]
pub fn delete_session(
    app_handle: tauri::AppHandle,
    id: String,
) -> Result<(), AppError> {
    crate::persistence::delete_session(&app_handle, &id)
}
