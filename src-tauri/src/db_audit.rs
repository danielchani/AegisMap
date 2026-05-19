use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::error::AppError;

const CHAIN_PREFIX: &str = "aegismap-audit-chain-v2";
const CHAIN_GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub details: String,
    pub hash: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub valid: bool,
    pub broken_at: Option<usize>,
    pub entry_count: usize,
}

// ── Hash computation ──────────────────────────────────────────────────────────

/// Computes the SHA-256 chain hash for one audit entry.
/// Input format is identical to the TypeScript implementation in auditLog.ts so
/// entries migrated from localStorage verify correctly.
fn compute_hash(prev_hash: &str, timestamp: &str, action: &str, details: &str) -> String {
    let input = format!("{CHAIN_PREFIX}:{prev_hash}:{timestamp}:{action}:{details}");
    let result = Sha256::digest(input.as_bytes());
    result.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Appends one entry to the audit log, computing the SHA-256 chain hash.
pub fn append_entry(
    conn: &rusqlite::Connection,
    action: &str,
    details: &str,
) -> Result<(), AppError> {
    let prev_hash: String = conn
        .query_row(
            "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| CHAIN_GENESIS.to_string());

    let timestamp = Utc::now().to_rfc3339();
    let hash = compute_hash(&prev_hash, &timestamp, action, details);

    conn.execute(
        "INSERT INTO audit_log (timestamp, action, details, hash) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![timestamp, action, details, hash],
    )
    .map_err(|e| AppError::DatabaseError(format!("audit insert: {e}")))?;

    Ok(())
}

/// Loads audit entries ordered chronologically (oldest first).
/// Pass `limit` to fetch the most recent N entries (useful for display).
pub fn load_entries(
    conn: &rusqlite::Connection,
    limit: Option<u32>,
) -> Result<Vec<AuditEntry>, AppError> {
    let sql = if let Some(n) = limit {
        // Fetch newest N, then reverse for chronological order
        format!(
            "SELECT timestamp, action, details, hash FROM audit_log ORDER BY id DESC LIMIT {n}"
        )
    } else {
        "SELECT timestamp, action, details, hash FROM audit_log ORDER BY id".to_string()
    };

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| AppError::DatabaseError(format!("prepare audit load: {e}")))?;

    let mut entries = Vec::new();
    let mut rows = stmt
        .query([])
        .map_err(|e| AppError::DatabaseError(format!("query audit: {e}")))?;

    while let Some(row) = rows
        .next()
        .map_err(|e| AppError::DatabaseError(format!("audit row: {e}")))?
    {
        entries.push(AuditEntry {
            timestamp: row.get(0).map_err(AppError::from)?,
            action:    row.get(1).map_err(AppError::from)?,
            details:   row.get(2).map_err(AppError::from)?,
            hash:      row.get(3).map_err(AppError::from)?,
        });
    }

    if limit.is_some() {
        entries.reverse();
    }
    Ok(entries)
}

/// Verifies the full SHA-256 chain. Returns which entry is broken (if any).
pub fn verify_chain(conn: &rusqlite::Connection) -> Result<VerifyResult, AppError> {
    let entries = load_entries(conn, None)?;
    let count = entries.len();

    if count == 0 {
        return Ok(VerifyResult { valid: true, broken_at: None, entry_count: 0 });
    }

    for (i, entry) in entries.iter().enumerate() {
        let prev = if i == 0 {
            CHAIN_GENESIS.to_string()
        } else {
            entries[i - 1].hash.clone()
        };
        let expected = compute_hash(&prev, &entry.timestamp, &entry.action, &entry.details);
        if expected != entry.hash {
            return Ok(VerifyResult { valid: false, broken_at: Some(i), entry_count: count });
        }
    }

    Ok(VerifyResult { valid: true, broken_at: None, entry_count: count })
}

/// Deletes all audit log entries.
pub fn clear(conn: &rusqlite::Connection) -> Result<(), AppError> {
    conn.execute("DELETE FROM audit_log", [])
        .map_err(|e| AppError::DatabaseError(format!("clear audit: {e}")))?;
    Ok(())
}

/// Imports existing audit entries from legacy localStorage data, re-signing
/// each with SHA-256 so the new chain is consistent.
pub fn migrate_entries(
    conn: &rusqlite::Connection,
    entries: &[serde_json::Value],
) -> Result<usize, AppError> {
    let mut count = 0;
    let mut prev_hash = CHAIN_GENESIS.to_string();

    for entry in entries {
        let timestamp = match entry["timestamp"].as_str() {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => continue,
        };
        let action  = entry["action"].as_str().unwrap_or("").to_string();
        let details = entry["details"].as_str().unwrap_or("").to_string();

        let hash = compute_hash(&prev_hash, &timestamp, &action, &details);

        conn.execute(
            "INSERT OR IGNORE INTO audit_log (timestamp, action, details, hash) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![timestamp, action, details, hash],
        )
        .map_err(|e| AppError::DatabaseError(format!("migrate audit entry: {e}")))?;

        prev_hash = hash;
        count += 1;
    }

    Ok(count)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_test_db;

    #[test]
    fn append_and_load() {
        let conn = open_test_db();
        append_entry(&conn, "TEST", "detail").unwrap();
        append_entry(&conn, "TEST2", "detail2").unwrap();
        let entries = load_entries(&conn, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "TEST");
        assert_eq!(entries[1].action, "TEST2");
        assert_eq!(entries[0].hash.len(), 64);
    }

    #[test]
    fn hashes_are_64_hex_chars() {
        let conn = open_test_db();
        append_entry(&conn, "ACT", "det").unwrap();
        let entries = load_entries(&conn, None).unwrap();
        let hash = &entries[0].hash;
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_intact_chain() {
        let conn = open_test_db();
        append_entry(&conn, "A", "1").unwrap();
        append_entry(&conn, "B", "2").unwrap();
        append_entry(&conn, "C", "3").unwrap();
        let r = verify_chain(&conn).unwrap();
        assert!(r.valid);
        assert_eq!(r.entry_count, 3);
    }

    #[test]
    fn verify_empty_chain() {
        let conn = open_test_db();
        let r = verify_chain(&conn).unwrap();
        assert!(r.valid);
        assert_eq!(r.entry_count, 0);
    }

    #[test]
    fn verify_detects_tampered_entry() {
        let conn = open_test_db();
        append_entry(&conn, "A", "1").unwrap();
        append_entry(&conn, "B", "2").unwrap();
        // Tamper directly
        conn.execute("UPDATE audit_log SET details = 'TAMPERED' WHERE action = 'B'", []).unwrap();
        let r = verify_chain(&conn).unwrap();
        assert!(!r.valid);
        assert_eq!(r.broken_at, Some(1));
    }

    #[test]
    fn verify_detects_deleted_entry() {
        let conn = open_test_db();
        append_entry(&conn, "A", "1").unwrap();
        append_entry(&conn, "B", "2").unwrap();
        append_entry(&conn, "C", "3").unwrap();
        conn.execute("DELETE FROM audit_log WHERE action = 'B'", []).unwrap();
        let r = verify_chain(&conn).unwrap();
        assert!(!r.valid);
    }

    #[test]
    fn load_with_limit_returns_newest_first_then_reversed() {
        let conn = open_test_db();
        for i in 0..5u32 {
            append_entry(&conn, &format!("A{i}"), "x").unwrap();
        }
        let entries = load_entries(&conn, Some(3)).unwrap();
        assert_eq!(entries.len(), 3);
        // Should be the last 3, chronological order (A2, A3, A4)
        assert_eq!(entries[0].action, "A2");
        assert_eq!(entries[2].action, "A4");
    }

    #[test]
    fn migrate_entries_preserves_content() {
        let conn = open_test_db();
        let legacy = vec![
            serde_json::json!({"timestamp":"2024-01-01T00:00:00Z","action":"SCAN_START","details":"10.0.0.1","hash":"old_djb2_hash"}),
            serde_json::json!({"timestamp":"2024-01-01T00:01:00Z","action":"SCAN_COMPLETE","details":"3 hosts","hash":"another_old"}),
        ];
        let count = migrate_entries(&conn, &legacy).unwrap();
        assert_eq!(count, 2);
        let entries = load_entries(&conn, None).unwrap();
        assert_eq!(entries[0].action, "SCAN_START");
        assert_eq!(entries[1].action, "SCAN_COMPLETE");
        // New hashes are SHA-256, not the old djb2 values
        assert_ne!(entries[0].hash, "old_djb2_hash");
        assert_eq!(entries[0].hash.len(), 64);
        // Verify the migrated chain is intact
        let r = verify_chain(&conn).unwrap();
        assert!(r.valid);
    }

    #[test]
    fn clear_removes_all() {
        let conn = open_test_db();
        append_entry(&conn, "A", "1").unwrap();
        clear(&conn).unwrap();
        assert_eq!(load_entries(&conn, None).unwrap().len(), 0);
    }
}
