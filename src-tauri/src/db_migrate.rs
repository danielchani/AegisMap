use crate::{db_audit, db_session, error::AppError};

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    pub active_session_migrated: bool,
    pub named_sessions_migrated: usize,
    pub file_sessions_migrated: usize,
    pub audit_entries_migrated: usize,
    pub errors: Vec<String>,
}

/// Payload sent from the frontend containing legacy localStorage data.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyData {
    /// `{ version: 1, savedAt, hosts: HostResult[] }` or null
    pub active_session: Option<serde_json::Value>,
    /// `[{ id, name, savedAt, hosts }]` or null
    pub named_sessions: Option<serde_json::Value>,
    /// `{ version: 2, entries: AuditEntry[] }` or null
    pub audit_entries: Option<serde_json::Value>,
}

/// One-shot migration from legacy storage → SQLite.
/// Called by the frontend on first launch when `check_migration_needed` returns true.
pub fn migrate_from_legacy(
    conn: &rusqlite::Connection,
    data: LegacyData,
    app: &tauri::AppHandle,
) -> Result<MigrationReport, AppError> {
    let mut report = MigrationReport {
        active_session_migrated: false,
        named_sessions_migrated: 0,
        file_sessions_migrated: 0,
        audit_entries_migrated: 0,
        errors: Vec::new(),
    };

    // ── Active session ─────────────────────────────────────────────────────────
    if let Some(ref session) = data.active_session {
        if let Some(hosts) = session["hosts"].as_array() {
            if !hosts.is_empty() {
                match db_session::save_active_session(conn, hosts) {
                    Ok(_) => report.active_session_migrated = true,
                    Err(e) => report.errors.push(format!("active session: {e}")),
                }
            }
        }
    }

    // ── Named sessions from localStorage ──────────────────────────────────────
    if let Some(ref sessions) = data.named_sessions {
        if let Some(arr) = sessions.as_array() {
            for s in arr {
                let name = s["name"].as_str().unwrap_or("Unnamed").to_string();
                if let Some(hosts) = s["hosts"].as_array() {
                    match db_session::save_named_session(conn, &name, hosts) {
                        Ok(_) => report.named_sessions_migrated += 1,
                        Err(e) => report.errors.push(format!("named session '{name}': {e}")),
                    }
                }
            }
        }
    }

    // ── Named sessions from JSON files on disk ─────────────────────────────────
    match migrate_file_sessions(conn, app) {
        Ok(n) => report.file_sessions_migrated = n,
        Err(e) => report.errors.push(format!("file sessions: {e}")),
    }

    // ── Audit log ──────────────────────────────────────────────────────────────
    if let Some(ref audit) = data.audit_entries {
        // Supports both v1 (plain array) and v2 ({version, entries}) formats
        let entries = if let Some(arr) = audit.as_array() {
            arr.clone()
        } else if let Some(arr) = audit["entries"].as_array() {
            arr.clone()
        } else {
            Vec::new()
        };

        if !entries.is_empty() {
            match db_audit::migrate_entries(conn, &entries) {
                Ok(n) => report.audit_entries_migrated = n,
                Err(e) => report.errors.push(format!("audit log: {e}")),
            }
        }
    }

    Ok(report)
}

/// Reads existing JSON session files from the app data directory and imports them.
fn migrate_file_sessions(
    conn: &rusqlite::Connection,
    app: &tauri::AppHandle,
) -> Result<usize, AppError> {
    use tauri::Manager;

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::DatabaseError(format!("data dir: {e}")))?;
    let sessions_dir = data_dir.join("sessions");

    if !sessions_dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    let entries =
        std::fs::read_dir(&sessions_dir).map_err(|e| AppError::DatabaseError(format!("read dir: {e}")))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let name = parsed["name"].as_str().unwrap_or("Imported Session").to_string();
        if let Some(hosts) = parsed["hosts"].as_array() {
            if !hosts.is_empty() {
                if db_session::save_named_session(conn, &name, hosts).is_ok() {
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}
