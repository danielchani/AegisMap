use std::sync::Arc;

use crate::db::DbConn;
use crate::error::AppError;
use crate::intelligence::cve::{CveFetchResult, CveRateState, CveRateStatus};
use crate::intelligence::dns::{DnsQueryRequest, DnsQueryResult};
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

/// Performs opt-in DNS enrichment for a single IP or hostname.
/// PTR, A/AAAA, CNAME, MX, NS, TXT.  Network/resolution errors are embedded
/// in `result.error`; only validation errors (CIDR, bad timeout) propagate as `Err`.
#[tauri::command]
pub async fn dns_query(request: DnsQueryRequest) -> Result<DnsQueryResult, AppError> {
    validation::validate_target(&request.address)?;
    if request.address.contains('/') {
        return Err(AppError::InvalidTarget(
            "DNS query requires a single host, not a CIDR range".into(),
        ));
    }
    if request.timeout_secs == 0 || request.timeout_secs > 30 {
        return Err(AppError::InvalidTarget("timeout_secs must be 1–30".into()));
    }
    Ok(crate::intelligence::dns::query(request).await)
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
    // Log the clear action before wiping — this entry will be removed too,
    // but it creates a record in any external log sinks and shows intent.
    crate::db_audit::append_entry(&conn, "AUDIT_CLEAR", "Audit log cleared by user").ok();
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

// ── Live CVE lookup commands ──────────────────────────────────────────────────

/// Fetch CVEs from the NVD API for a product keyword.
/// Checks the SQLite cache first (24 h TTL). Enforces server-side rate limits.
/// Confidence is always "candidate" — the frontend must not auto-confirm.
#[tauri::command]
pub async fn fetch_live_cves(
    db: tauri::State<'_, DbConn>,
    rate_state: tauri::State<'_, Arc<CveRateState>>,
    product: String,
    version: Option<String>,
) -> Result<CveFetchResult, AppError> {
    use crate::intelligence::cve;

    let product = cve::validate_product_name(&product)?.to_string();

    // Normalised cache key: lowercase product (version not included so one cache
    // entry covers all versions of a product)
    let cache_key = product.to_ascii_lowercase();

    // Serve from cache if fresh
    {
        let conn = db.lock().unwrap();
        if let Some(cached) = cve::cache_get(&conn, &cache_key) {
            return Ok(cached);
        }
    }

    // Enforce rate limit before making a live request
    let api_key_opt: Option<String> = {
        let conn = db.lock().unwrap();
        cve::get_nvd_key(&conn)
    };
    let has_key = api_key_opt.is_some();
    let wait_ms = rate_state.check_and_claim(has_key);
    if wait_ms > 0 {
        return Err(AppError::PersistenceError(format!(
            "RATE_LIMIT:{}",
            wait_ms
        )));
    }

    // Build keyword: "product version" if version provided, else just product
    let keyword = match &version {
        Some(v) if !v.trim().is_empty() => {
            let v = v.trim();
            // Validate version string (same char-set as product)
            cve::validate_product_name(v)?;
            format!("{} {}", product, v)
        }
        _ => product.clone(),
    };

    let (entries, total) = cve::fetch_from_nvd(&keyword, api_key_opt.as_deref()).await?;

    // Store in cache
    let fetched_at;
    let expires_at;
    {
        let conn = db.lock().unwrap();
        cve::cache_put(&conn, &cache_key, &entries, total)?;
        // Re-read to get the stored timestamps
        let cached = cve::cache_get(&conn, &cache_key).unwrap_or_else(|| CveFetchResult {
            product_key: cache_key.clone(),
            entries: entries.clone(),
            fetched_at: chrono::Utc::now().to_rfc3339(),
            expires_at: chrono::Utc::now().to_rfc3339(),
            from_cache: false,
            total_available: total,
        });
        fetched_at = cached.fetched_at;
        expires_at = cached.expires_at;
    }

    Ok(CveFetchResult {
        product_key: cache_key,
        entries,
        fetched_at,
        expires_at,
        from_cache: false,
        total_available: total,
    })
}

/// Returns how many milliseconds until the next CVE fetch is allowed (0 = ready).
#[tauri::command]
pub fn cve_rate_status(
    db: tauri::State<'_, DbConn>,
    rate_state: tauri::State<'_, Arc<CveRateState>>,
) -> CveRateStatus {
    let conn = db.lock().unwrap();
    let api_key = crate::intelligence::cve::get_nvd_key(&conn);
    let has_api_key = api_key.is_some();
    CveRateStatus {
        millis_until_ready: rate_state.millis_until_ready(has_api_key),
        has_api_key,
    }
}

/// Stores (or clears) the NVD API key in the settings table.
/// Pass `None` or omit to remove the key.
#[tauri::command]
pub fn set_nvd_api_key(
    db: tauri::State<'_, DbConn>,
    key: Option<String>,
) -> Result<(), AppError> {
    use crate::intelligence::cve;
    if let Some(ref k) = key {
        if !k.is_empty() {
            cve::validate_api_key(k)?;
        }
    }
    let conn = db.lock().unwrap();
    cve::set_nvd_key(&conn, key.as_deref().filter(|k| !k.is_empty()))
}

/// Returns whether an NVD API key is configured (does not return the key itself).
#[tauri::command]
pub fn get_nvd_api_key_status(db: tauri::State<'_, DbConn>) -> bool {
    let conn = db.lock().unwrap();
    crate::intelligence::cve::get_nvd_key(&conn).is_some()
}
