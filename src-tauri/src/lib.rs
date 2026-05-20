pub mod commands;
pub mod db;
pub mod db_audit;
pub mod db_findings;
pub mod db_migrate;
pub mod db_session;
pub mod error;
pub mod intelligence;
pub mod models;
pub mod persistence;
pub mod scanner;

use std::sync::{Arc, Mutex};

use tauri::Manager as _;
use scanner::executor::ScanState;
use intelligence::cve::CveRateState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Open (or create) the SQLite database during app setup so it's
            // available as managed state before any command runs.
            match db::open_db(app.handle()) {
                Ok(conn) => {
                    app.manage(Arc::new(Mutex::new(conn)) as db::DbConn);
                }
                Err(e) => {
                    eprintln!("[AegisMap] Database init failed: {e} — running with in-memory fallback (data will not persist)");
                    // Provide a fallback in-memory DB with schema applied so
                    // commands don't hit missing-table errors.
                    let fallback = rusqlite::Connection::open_in_memory()
                        .expect("in-memory fallback");
                    fallback.execute_batch(db::SCHEMA_SQL)
                        .expect("in-memory schema init");
                    app.manage(Arc::new(Mutex::new(fallback)) as db::DbConn);
                }
            }
            Ok(())
        })
        .manage(ScanState::new())
        .manage(CveRateState::new())
        .invoke_handler(tauri::generate_handler![
            // Nmap scan
            commands::detect_nmap,
            commands::validate_scan_request,
            commands::start_scan,
            commands::cancel_scan,
            // Intelligence probes
            commands::probe_http,
            commands::probe_tls,
            commands::dns_query,
            // Active session (SQLite)
            commands::get_active_session,
            commands::save_active_session,
            commands::clear_active_session,
            // Named sessions (SQLite)
            commands::save_named_session,
            commands::load_named_session,
            commands::list_named_sessions,
            commands::delete_named_session,
            // Migration
            commands::check_migration_needed,
            commands::migrate_from_legacy,
            // Audit log (SQLite)
            commands::append_audit_entry,
            commands::load_audit_entries,
            commands::verify_audit_chain,
            commands::clear_audit_log,
            // Findings & Evidence
            commands::create_finding,
            commands::update_finding,
            commands::delete_finding,
            commands::list_findings,
            commands::attach_evidence,
            commands::delete_evidence,
            commands::list_evidence_for_finding,
            // Legacy JSON-file session commands (kept during transition)
            commands::save_session,
            commands::load_session,
            commands::list_sessions,
            commands::delete_session,
            // Live CVE lookup (NVD API v2)
            commands::fetch_live_cves,
            commands::cve_rate_status,
            commands::set_nvd_api_key,
            commands::get_nvd_api_key_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
