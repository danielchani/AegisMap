use std::sync::{Arc, Mutex};

use crate::error::AppError;

/// Shared database connection handle injected as Tauri managed state.
pub type DbConn = Arc<Mutex<rusqlite::Connection>>;

// ── Schema ────────────────────────────────────────────────────────────────────

const SCHEMA_SQL: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- 'active' = current working session (one row); 'named' = user snapshots
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL CHECK(type IN ('active','named')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    address         TEXT    NOT NULL,
    hostname        TEXT,
    status          TEXT    NOT NULL DEFAULT 'up',
    scanned_at      TEXT,
    workflow_status TEXT,
    notes           TEXT,
    port_history    TEXT,       -- JSON [{ts,open}]
    ports_diff      TEXT,       -- JSON {added:[],removed:[]}
    http_probes     TEXT,       -- JSON HttpProbeResult[]
    tls_probes      TEXT,       -- JSON TlsProbeResult[]
    script_results  TEXT,       -- JSON ScriptResult[]
    UNIQUE(session_id, address)
);

CREATE TABLE IF NOT EXISTS ports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    protocol TEXT    NOT NULL,
    state    TEXT    NOT NULL,
    service  TEXT    NOT NULL DEFAULT '',
    product  TEXT,
    version  TEXT,
    note     TEXT,              -- per-port analyst note
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS host_tags (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag     TEXT    NOT NULL,
    PRIMARY KEY(host_id, tag)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    details   TEXT    NOT NULL,
    hash      TEXT    NOT NULL   -- 64-char SHA-256 hex
);

CREATE INDEX IF NOT EXISTS idx_hosts_session ON hosts(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_host    ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_tags_host     ON host_tags(host_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(timestamp);
"#;

// ── Connection factory ────────────────────────────────────────────────────────

/// Opens (or creates) the AegisMap SQLite database, applies the schema, and
/// enables WAL mode + foreign keys. Called once in Tauri's setup hook.
pub fn open_db(app: &tauri::AppHandle) -> Result<rusqlite::Connection, AppError> {
    use tauri::Manager;
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::DatabaseError(format!("cannot resolve app data dir: {e}")))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| AppError::DatabaseError(format!("cannot create data dir: {e}")))?;

    let db_path = data_dir.join("aegismap.db");
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| AppError::DatabaseError(format!("cannot open database at {db_path:?}: {e}")))?;

    // WAL gives better read/write concurrency and crash recovery.
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| AppError::DatabaseError(format!("WAL pragma: {e}")))?;

    conn.execute_batch(SCHEMA_SQL)
        .map_err(|e| AppError::DatabaseError(format!("schema init: {e}")))?;

    conn.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, datetime('now'))",
        [],
    )
    .map_err(|e| AppError::DatabaseError(format!("schema_version insert: {e}")))?;

    Ok(conn)
}

/// Opens an in-memory database with the schema applied — used in unit tests.
#[cfg(test)]
pub fn open_test_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(SCHEMA_SQL).expect("schema");
    conn
}
