use std::sync::{Arc, Mutex};

use crate::error::AppError;

/// Shared database connection handle injected as Tauri managed state.
pub type DbConn = Arc<Mutex<rusqlite::Connection>>;

// ── Schema ────────────────────────────────────────────────────────────────────

pub const SCHEMA_SQL: &str = r#"
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
    dns_results     TEXT,       -- JSON DnsQueryResult[]
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

-- Analyst findings (linked to a session; never auto-confirmed)
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    title             TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
    confidence        TEXT NOT NULL CHECK(confidence IN ('observed','heuristic','candidate','confirmed')),
    status            TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','needs_review','confirmed','false_positive','accepted_risk','remediated')),
    affected_hosts    TEXT NOT NULL,       -- JSON string[]
    affected_ports    TEXT,               -- JSON string[]
    summary           TEXT NOT NULL,
    technical_details TEXT,
    remediation       TEXT,
    ext_refs          TEXT,               -- JSON string[] (CVE IDs, URLs)
    source            TEXT NOT NULL,       -- analyst/cve_candidate/version_advisory/service_advisory/script_result
    source_ref        TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

-- Evidence items linked to findings
CREATE TABLE IF NOT EXISTS evidence (
    id           TEXT PRIMARY KEY,
    finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    session_id   TEXT NOT NULL,
    type         TEXT NOT NULL,            -- scan_snapshot/script_output/probe_result/advisory_match/manual_note
    host_address TEXT,
    port_ref     TEXT,
    excerpt      TEXT NOT NULL,
    raw_data     TEXT,                     -- JSON snapshot
    hash         TEXT,                     -- SHA-256 of raw_data
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_session    ON hosts(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_host       ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_tags_host        ON host_tags(host_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts         ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

-- Key-value settings store (e.g. NVD API key)
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- CVE lookup cache — keyed by normalised product name, 24 h TTL
CREATE TABLE IF NOT EXISTS cve_cache (
    product_key TEXT PRIMARY KEY,
    fetched_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    entry_count INTEGER NOT NULL DEFAULT 0,
    data        TEXT NOT NULL  -- JSON array of LiveCveEntry
);
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

    // Safe additive migration: adds dns_results column to existing databases.
    // Silently ignored if the column already exists (fresh installs have it from SCHEMA_SQL).
    conn.execute_batch("ALTER TABLE hosts ADD COLUMN dns_results TEXT;").ok();

    Ok(conn)
}

/// Opens an in-memory database with the schema applied — used in unit tests.
#[cfg(test)]
pub fn open_test_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(SCHEMA_SQL).expect("schema");
    conn
}
