pub mod commands;
pub mod error;
pub mod intelligence;
pub mod models;
pub mod persistence;
pub mod scanner;

use scanner::executor::ScanState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ScanState::new())
        .invoke_handler(tauri::generate_handler![
            commands::detect_nmap,
            commands::validate_scan_request,
            commands::start_scan,
            commands::cancel_scan,
            commands::save_session,
            commands::load_session,
            commands::list_sessions,
            commands::delete_session,
            commands::probe_http,
            commands::probe_tls,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
