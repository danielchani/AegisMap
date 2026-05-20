//! File-based session persistence — stores sessions as JSON files
//! in the app's data directory, replacing fragile localStorage.

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedSession {
    pub version: u32,
    pub saved_at: String,
    pub name: String,
    pub hosts: serde_json::Value, // opaque JSON — validated frontend-side
}

#[derive(Debug, Serialize)]
pub struct SessionListing {
    pub id: String,
    pub name: String,
    pub saved_at: String,
    pub host_count: usize,
}

fn now_iso() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    // Simple ISO-ish timestamp without chrono dependency
    format!("{}", ts)
}

fn sessions_dir(app_handle: &tauri::AppHandle) -> Result<PathBuf, AppError> {
    use tauri::Manager;
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| AppError::PersistenceError(format!("cannot resolve app data dir: {}", e)))?;
    let dir = data_dir.join("sessions");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn session_path(app_handle: &tauri::AppHandle, id: &str) -> Result<PathBuf, AppError> {
    // Sanitize ID to prevent path traversal
    let sanitized: String = id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if sanitized.is_empty() || sanitized.len() > 128 {
        return Err(AppError::PersistenceError("invalid session ID".into()));
    }
    Ok(sessions_dir(app_handle)?.join(format!("{}.json", sanitized)))
}

pub fn save_session(
    app_handle: &tauri::AppHandle,
    id: &str,
    name: &str,
    hosts_json: serde_json::Value,
) -> Result<(), AppError> {
    let host_count = hosts_json.as_array().map(|a| a.len()).unwrap_or(0);
    if host_count == 0 {
        return Err(AppError::PersistenceError("session has no hosts".into()));
    }

    let session = PersistedSession {
        version: 1,
        saved_at: now_iso(),
        name: name.to_string(),
        hosts: hosts_json,
    };

    let path = session_path(app_handle, id)?;
    let json = serde_json::to_string_pretty(&session)
        .map_err(|e| AppError::PersistenceError(format!("serialization failed: {}", e)))?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn load_session(
    app_handle: &tauri::AppHandle,
    id: &str,
) -> Result<PersistedSession, AppError> {
    let path = session_path(app_handle, id)?;
    let content = std::fs::read_to_string(&path)
        .map_err(|e| AppError::PersistenceError(format!("could not read session: {}", e)))?;
    let session: PersistedSession = serde_json::from_str(&content)
        .map_err(|e| AppError::PersistenceError(format!("corrupt session file: {}", e)))?;
    Ok(session)
}

pub fn list_sessions(app_handle: &tauri::AppHandle) -> Result<Vec<SessionListing>, AppError> {
    let dir = sessions_dir(app_handle)?;
    let mut listings = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(session) = serde_json::from_str::<PersistedSession>(&content) {
                        let id = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let host_count = session.hosts.as_array().map(|a| a.len()).unwrap_or(0);
                        listings.push(SessionListing {
                            id,
                            name: session.name,
                            saved_at: session.saved_at,
                            host_count,
                        });
                    }
                }
            }
        }
    }

    listings.sort_by(|a, b| b.saved_at.cmp(&a.saved_at));
    Ok(listings)
}

pub fn delete_session(app_handle: &tauri::AppHandle, id: &str) -> Result<(), AppError> {
    let path = session_path(app_handle, id)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}
