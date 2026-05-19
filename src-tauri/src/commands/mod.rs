use std::sync::Arc;

use crate::db::DbConn;
use crate::error::AppError;
use crate::intelligence::http::{HttpProbeRequest, HttpProbeResult};
use crate::intelligence::tls::{TlsProbeRequest, TlsProbeResult};
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

/// Performs a raw TLS handshake to capture the certificate chain, negotiated
/// TLS version, and cipher suite. Network/TLS errors are embedded in result.error.
/// Only validation errors propagate as Err.
#[tauri::command]
pub async fn probe_tls(request: TlsProbeRequest) -> Result<TlsProbeResult, AppError> {
    validation::validate_target(&request.address)?;
    if request.address.contains('/') {
        return Err(AppError::InvalidTarget(
            "TLS probe requires a single host, not a CIDR range".into(),
        ));
    }
    if request.port == 0 {
        return Err(AppError::InvalidTarget("port must be 1–65535".into()));
    }
    if request.timeout_secs == 0 || request.timeout_secs > 30 {
        return Err(AppError::InvalidTarget("timeout_secs must be 1–30".into()));
    }
    Ok(crate::intelligence::tls::probe(request).await)
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

// ── SQLite active session commands ─────────────────────────────────────────────

#[tauri::command]
pub fn get_active_session(db: tauri::State<'_, DbConn>) -> Result<Vec<serde_json::Value>, AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::get_active_session(&conn)
}

#[tauri::command]
pub fn save_active_session(
    db: tauri::State<'_, DbConn>,
    hosts: Vec<serde_json::Value>,
) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::save_active_session(&conn, &hosts)
}

#[tauri::command]
pub fn clear_active_session(db: tauri::State<'_, DbConn>) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::clear_active_session(&conn)
}

// ── SQLite named session commands ──────────────────────────────────────────────

#[tauri::command]
pub fn save_named_session(
    db: tauri::State<'_, DbConn>,
    name: String,
    hosts: Vec<serde_json::Value>,
) -> Result<String, AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::save_named_session(&conn, &name, &hosts)
}

#[tauri::command]
pub fn load_named_session(
    db: tauri::State<'_, DbConn>,
    id: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::load_named_session(&conn, &id)
}

#[tauri::command]
pub fn list_named_sessions(
    db: tauri::State<'_, DbConn>,
) -> Result<Vec<crate::db_session::SessionListing>, AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::list_named_sessions(&conn)
}

#[tauri::command]
pub fn delete_named_session(
    db: tauri::State<'_, DbConn>,
    id: String,
) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    crate::db_session::delete_named_session(&conn, &id)
}

// ── Migration commands ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn check_migration_needed(db: tauri::State<'_, DbConn>) -> bool {
    let conn = db.lock().unwrap();
    crate::db_session::check_migration_needed(&conn)
}

#[tauri::command]
pub fn migrate_from_legacy(
    db: tauri::State<'_, DbConn>,
    app_handle: tauri::AppHandle,
    data: crate::db_migrate::LegacyData,
) -> Result<crate::db_migrate::MigrationReport, AppError> {
    let conn = db.lock().unwrap();
    crate::db_migrate::migrate_from_legacy(&conn, data, &app_handle)
}

// ── SQLite audit log commands ──────────────────────────────────────────────────

#[tauri::command]
pub fn append_audit_entry(
    db: tauri::State<'_, DbConn>,
    action: String,
    details: String,
) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    crate::db_audit::append_entry(&conn, &action, &details)
}

#[tauri::command]
pub fn load_audit_entries(
    db: tauri::State<'_, DbConn>,
    limit: Option<u32>,
) -> Result<Vec<crate::db_audit::AuditEntry>, AppError> {
    let conn = db.lock().unwrap();
    crate::db_audit::load_entries(&conn, limit)
}

#[tauri::command]
pub fn verify_audit_chain(
    db: tauri::State<'_, DbConn>,
) -> Result<crate::db_audit::VerifyResult, AppError> {
    let conn = db.lock().unwrap();
    crate::db_audit::verify_chain(&conn)
}

#[tauri::command]
pub fn clear_audit_log(db: tauri::State<'_, DbConn>) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    crate::db_audit::clear(&conn)
}

// ── Findings & Evidence commands ───────────────────────────────────────────────

#[tauri::command]
pub fn create_finding(
    db: tauri::State<'_, DbConn>,
    finding: crate::db_findings::FindingInput,
) -> Result<String, AppError> {
    let conn = db.lock().unwrap();
    let id = crate::db_findings::create_finding(&conn, finding)?;
    // Audit
    crate::db_audit::append_entry(&conn, "FINDING_CREATE", &id).ok();
    Ok(id)
}

#[tauri::command]
pub fn update_finding(
    db: tauri::State<'_, DbConn>,
    id: String,
    patch: crate::db_findings::FindingPatch,
) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    // Capture old status for audit
    let old_status = crate::db_findings::get_finding(&conn, &id)
        .ok().and_then(|f| f["status"].as_str().map(String::from))
        .unwrap_or_default();
    crate::db_findings::update_finding(&conn, &id, patch)?;
    let new_status = crate::db_findings::get_finding(&conn, &id)
        .ok().and_then(|f| f["status"].as_str().map(String::from))
        .unwrap_or_default();
    if old_status != new_status {
        crate::db_audit::append_entry(&conn, "FINDING_STATUS", &format!("{id} · {old_status} → {new_status}")).ok();
    }
    Ok(())
}

#[tauri::command]
pub fn delete_finding(
    db: tauri::State<'_, DbConn>,
    id: String,
) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    let title = crate::db_findings::get_finding(&conn, &id)
        .ok().and_then(|f| f["title"].as_str().map(String::from))
        .unwrap_or_default();
    crate::db_findings::delete_finding(&conn, &id)?;
    crate::db_audit::append_entry(&conn, "FINDING_DELETE", &format!("{id} · {title}")).ok();
    Ok(())
}

#[tauri::command]
pub fn list_findings(
    db: tauri::State<'_, DbConn>,
    session_id: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let conn = db.lock().unwrap();
    crate::db_findings::list_findings(&conn, &session_id)
}

#[tauri::command]
pub fn attach_evidence(
    db: tauri::State<'_, DbConn>,
    evidence: crate::db_findings::EvidenceInput,
) -> Result<String, AppError> {
    let conn = db.lock().unwrap();
    let finding_id = evidence.finding_id.clone();
    let ev_id = crate::db_findings::attach_evidence(&conn, evidence)?;
    crate::db_audit::append_entry(&conn, "EVIDENCE_ATTACH", &format!("{ev_id} → finding {finding_id}")).ok();
    Ok(ev_id)
}

#[tauri::command]
pub fn delete_evidence(
    db: tauri::State<'_, DbConn>,
    id: String,
) -> Result<(), AppError> {
    let conn = db.lock().unwrap();
    crate::db_findings::delete_evidence(&conn, &id)
}

#[tauri::command]
pub fn list_evidence_for_finding(
    db: tauri::State<'_, DbConn>,
    finding_id: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let conn = db.lock().unwrap();
    crate::db_findings::list_evidence_for_finding(&conn, &finding_id)
}
