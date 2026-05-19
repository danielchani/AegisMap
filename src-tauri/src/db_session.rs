use chrono::Utc;

use crate::error::AppError;

const ACTIVE_SESSION_ID: &str = "active";

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionListing {
    pub id: String,
    pub name: String,
    pub saved_at: String,
    pub host_count: usize,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn json_opt(v: &serde_json::Value) -> Option<String> {
    if v.is_null() { None } else { Some(v.to_string()) }
}

/// Ensures the session row exists (upserts name and updated_at).
fn ensure_session(
    conn: &rusqlite::Connection,
    id: &str,
    name: &str,
    session_type: &str,
) -> Result<(), AppError> {
    let now = now_iso();
    conn.execute(
        "INSERT INTO sessions (id, name, type, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
        rusqlite::params![id, name, session_type, now, now],
    )
    .map_err(|e| AppError::DatabaseError(format!("ensure_session: {e}")))?;
    Ok(())
}

/// Upserts a single host and all its related data for the given session.
fn save_host(
    conn: &rusqlite::Connection,
    session_id: &str,
    host: &serde_json::Value,
) -> Result<(), AppError> {
    let address = host["address"]
        .as_str()
        .ok_or_else(|| AppError::DatabaseError("host.address is required".into()))?;

    conn.execute(
        "INSERT INTO hosts
           (session_id, address, hostname, status, scanned_at, workflow_status, notes,
            port_history, ports_diff, http_probes, tls_probes, script_results)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         ON CONFLICT(session_id, address) DO UPDATE SET
           hostname        = excluded.hostname,
           status          = excluded.status,
           scanned_at      = excluded.scanned_at,
           workflow_status = excluded.workflow_status,
           notes           = excluded.notes,
           port_history    = excluded.port_history,
           ports_diff      = excluded.ports_diff,
           http_probes     = excluded.http_probes,
           tls_probes      = excluded.tls_probes,
           script_results  = excluded.script_results",
        rusqlite::params![
            session_id,
            address,
            host["hostname"].as_str(),
            host["status"].as_str().unwrap_or("up"),
            host["scannedAt"].as_str(),
            host["workflowStatus"].as_str(),
            host["notes"].as_str(),
            json_opt(&host["portHistory"]),
            json_opt(&host["portsDiff"]),
            json_opt(&host["httpProbes"]),
            json_opt(&host["tlsProbes"]),
            json_opt(&host["script_results"]),
        ],
    )
    .map_err(|e| AppError::DatabaseError(format!("upsert host {address}: {e}")))?;

    // Get the rowid for the (just-upserted) host
    let host_id: i64 = conn
        .query_row(
            "SELECT id FROM hosts WHERE session_id = ?1 AND address = ?2",
            rusqlite::params![session_id, address],
            |r| r.get(0),
        )
        .map_err(|e| AppError::DatabaseError(format!("get host id: {e}")))?;

    save_ports(conn, host_id, host)?;
    save_tags(conn, host_id, host)?;
    Ok(())
}

fn save_ports(
    conn: &rusqlite::Connection,
    host_id: i64,
    host: &serde_json::Value,
) -> Result<(), AppError> {
    // Delete-and-reinsert keeps ports in sync with the current scan.
    conn.execute("DELETE FROM ports WHERE host_id = ?1", [host_id])
        .map_err(|e| AppError::DatabaseError(format!("delete ports: {e}")))?;

    let port_notes = host["portNotes"].as_object();

    if let Some(ports) = host["ports"].as_array() {
        for p in ports {
            let port_num = p["port"].as_i64().unwrap_or(0) as i32;
            let protocol = p["protocol"].as_str().unwrap_or("tcp");
            let key = format!("{port_num}/{protocol}");
            let note = port_notes
                .and_then(|m| m.get(&key))
                .and_then(|v| v.as_str());

            conn.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service, product, version, note)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    host_id, port_num, protocol,
                    p["state"].as_str().unwrap_or(""),
                    p["service"].as_str().unwrap_or(""),
                    p["product"].as_str(),
                    p["version"].as_str(),
                    note,
                ],
            )
            .map_err(|e| AppError::DatabaseError(format!("insert port {port_num}: {e}")))?;
        }
    }
    Ok(())
}

fn save_tags(
    conn: &rusqlite::Connection,
    host_id: i64,
    host: &serde_json::Value,
) -> Result<(), AppError> {
    conn.execute("DELETE FROM host_tags WHERE host_id = ?1", [host_id])
        .map_err(|e| AppError::DatabaseError(format!("delete tags: {e}")))?;

    if let Some(tags) = host["tags"].as_array() {
        for tag in tags {
            if let Some(t) = tag.as_str() {
                conn.execute(
                    "INSERT OR IGNORE INTO host_tags (host_id, tag) VALUES (?1, ?2)",
                    rusqlite::params![host_id, t],
                )
                .map_err(|e| AppError::DatabaseError(format!("insert tag: {e}")))?;
            }
        }
    }
    Ok(())
}

/// Loads all hosts for the given session, reconstructing the HostResult JSON.
fn load_hosts_for_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    // Collect host IDs + basic fields
    struct HostRow {
        id: i64, address: String, hostname: Option<String>, status: String,
        scanned_at: Option<String>, workflow_status: Option<String>,
        notes: Option<String>, port_history: Option<String>,
        ports_diff: Option<String>, http_probes: Option<String>,
        tls_probes: Option<String>, script_results: Option<String>,
    }

    let mut stmt = conn.prepare(
        "SELECT id, address, hostname, status, scanned_at, workflow_status, notes,
                port_history, ports_diff, http_probes, tls_probes, script_results
         FROM hosts WHERE session_id = ?1 ORDER BY id",
    )
    .map_err(|e| AppError::DatabaseError(format!("prepare hosts: {e}")))?;

    let mut host_rows: Vec<HostRow> = Vec::new();
    let mut rows = stmt
        .query([session_id])
        .map_err(|e| AppError::DatabaseError(format!("query hosts: {e}")))?;

    while let Some(r) = rows.next().map_err(AppError::from)? {
        host_rows.push(HostRow {
            id:              r.get(0).map_err(AppError::from)?,
            address:         r.get(1).map_err(AppError::from)?,
            hostname:        r.get(2).map_err(AppError::from)?,
            status:          r.get(3).map_err(AppError::from)?,
            scanned_at:      r.get(4).map_err(AppError::from)?,
            workflow_status: r.get(5).map_err(AppError::from)?,
            notes:           r.get(6).map_err(AppError::from)?,
            port_history:    r.get(7).map_err(AppError::from)?,
            ports_diff:      r.get(8).map_err(AppError::from)?,
            http_probes:     r.get(9).map_err(AppError::from)?,
            tls_probes:      r.get(10).map_err(AppError::from)?,
            script_results:  r.get(11).map_err(AppError::from)?,
        });
    }
    drop(rows); // release borrow on stmt

    let mut result = Vec::new();
    for hr in host_rows {
        // Load ports
        let (ports_arr, port_notes_map) = load_ports_for_host(conn, hr.id)?;
        // Load tags
        let tags = load_tags_for_host(conn, hr.id)?;

        let mut h = serde_json::json!({
            "address": hr.address,
            "status":  hr.status,
            "ports":   ports_arr,
            "tags":    tags,
            "portNotes": port_notes_map,
        });

        if let Some(v) = hr.hostname        { h["hostname"]       = v.into(); }
        if let Some(v) = hr.scanned_at      { h["scannedAt"]      = v.into(); }
        if let Some(v) = hr.workflow_status  { h["workflowStatus"] = v.into(); }
        if let Some(v) = hr.notes           { h["notes"]          = v.into(); }

        // Parse stored JSON blobs back into values
        if let Some(v) = hr.port_history {
            h["portHistory"] = serde_json::from_str(&v).unwrap_or(serde_json::json!([]));
        }
        if let Some(v) = hr.ports_diff {
            h["portsDiff"] = serde_json::from_str(&v).unwrap_or(serde_json::Value::Null);
        }
        if let Some(v) = hr.http_probes {
            h["httpProbes"] = serde_json::from_str(&v).unwrap_or(serde_json::json!([]));
        }
        if let Some(v) = hr.tls_probes {
            h["tlsProbes"] = serde_json::from_str(&v).unwrap_or(serde_json::json!([]));
        }
        if let Some(v) = hr.script_results {
            h["script_results"] = serde_json::from_str(&v).unwrap_or(serde_json::json!([]));
        }

        result.push(h);
    }

    Ok(result)
}

fn load_ports_for_host(
    conn: &rusqlite::Connection,
    host_id: i64,
) -> Result<(Vec<serde_json::Value>, serde_json::Value), AppError> {
    let mut stmt = conn.prepare(
        "SELECT port, protocol, state, service, product, version, note
         FROM ports WHERE host_id = ?1 ORDER BY port, protocol",
    )
    .map_err(|e| AppError::DatabaseError(format!("prepare ports load: {e}")))?;

    let mut ports = Vec::new();
    let mut port_notes = serde_json::Map::new();
    let mut rows = stmt.query([host_id]).map_err(AppError::from)?;

    while let Some(r) = rows.next().map_err(AppError::from)? {
        let port:     i32           = r.get(0).map_err(AppError::from)?;
        let protocol: String        = r.get(1).map_err(AppError::from)?;
        let state:    String        = r.get(2).map_err(AppError::from)?;
        let service:  String        = r.get(3).map_err(AppError::from)?;
        let product:  Option<String>= r.get(4).map_err(AppError::from)?;
        let version:  Option<String>= r.get(5).map_err(AppError::from)?;
        let note:     Option<String>= r.get(6).map_err(AppError::from)?;

        if let Some(n) = note {
            port_notes.insert(format!("{port}/{protocol}"), serde_json::json!(n));
        }

        let mut p = serde_json::json!({
            "port": port, "protocol": protocol, "state": state, "service": service,
        });
        if let Some(v) = product { p["product"] = v.into(); }
        if let Some(v) = version { p["version"] = v.into(); }
        ports.push(p);
    }

    Ok((ports, serde_json::Value::Object(port_notes)))
}

fn load_tags_for_host(
    conn: &rusqlite::Connection,
    host_id: i64,
) -> Result<Vec<String>, AppError> {
    let mut stmt = conn
        .prepare("SELECT tag FROM host_tags WHERE host_id = ?1 ORDER BY tag")
        .map_err(AppError::from)?;
    let mut tags = Vec::new();
    let mut rows = stmt.query([host_id]).map_err(AppError::from)?;
    while let Some(r) = rows.next().map_err(AppError::from)? {
        tags.push(r.get::<_, String>(0).map_err(AppError::from)?);
    }
    Ok(tags)
}

// ── Active session ────────────────────────────────────────────────────────────

/// Persists the full working session atomically.
/// Hosts not in the incoming list are deleted; hosts in the list are upserted.
pub fn save_active_session(
    conn: &rusqlite::Connection,
    hosts: &[serde_json::Value],
) -> Result<(), AppError> {
    ensure_session(conn, ACTIVE_SESSION_ID, "Active Session", "active")?;

    // Remove hosts that are no longer in the session
    let addresses: Vec<&str> = hosts
        .iter()
        .filter_map(|h| h["address"].as_str())
        .collect();

    if addresses.is_empty() {
        conn.execute(
            "DELETE FROM hosts WHERE session_id = ?1",
            [ACTIVE_SESSION_ID],
        )
        .map_err(|e| AppError::DatabaseError(format!("delete all hosts: {e}")))?;
    } else {
        // Build a parameterised IN clause
        let placeholders: Vec<String> =
            (1..=addresses.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "DELETE FROM hosts WHERE session_id = '{ACTIVE_SESSION_ID}' AND address NOT IN ({})",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&sql).map_err(AppError::from)?;
        // Pass addresses as params
        for (i, addr) in addresses.iter().enumerate() {
            stmt.raw_bind_parameter(i + 1, *addr).map_err(AppError::from)?;
        }
        stmt.raw_execute().map_err(AppError::from)?;
    }

    for host in hosts {
        save_host(conn, ACTIVE_SESSION_ID, host)?;
    }

    // Update session timestamp
    conn.execute(
        "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now_iso(), ACTIVE_SESSION_ID],
    )
    .map_err(AppError::from)?;

    Ok(())
}

/// Loads all hosts from the active session. Returns an empty array if no session.
pub fn get_active_session(
    conn: &rusqlite::Connection,
) -> Result<Vec<serde_json::Value>, AppError> {
    // Check if active session exists
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = 'active'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    if !exists {
        return Ok(Vec::new());
    }

    load_hosts_for_session(conn, ACTIVE_SESSION_ID)
}

/// Deletes all hosts from the active session (the session row is kept).
pub fn clear_active_session(conn: &rusqlite::Connection) -> Result<(), AppError> {
    conn.execute(
        "DELETE FROM hosts WHERE session_id = ?1",
        [ACTIVE_SESSION_ID],
    )
    .map_err(|e| AppError::DatabaseError(format!("clear active session: {e}")))?;
    Ok(())
}

// ── Named sessions ────────────────────────────────────────────────────────────

/// Saves a named snapshot. Returns the new session ID.
pub fn save_named_session(
    conn: &rusqlite::Connection,
    name: &str,
    hosts: &[serde_json::Value],
) -> Result<String, AppError> {
    let id = format!("named-{}", Utc::now().timestamp_millis());
    ensure_session(conn, &id, name, "named")?;

    for host in hosts {
        save_host(conn, &id, host)?;
    }

    Ok(id)
}

/// Loads all hosts from a named session.
pub fn load_named_session(
    conn: &rusqlite::Connection,
    id: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1 AND type = 'named'",
            [id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    if !exists {
        return Err(AppError::DatabaseError(format!("named session '{id}' not found")));
    }

    load_hosts_for_session(conn, id)
}

/// Lists all named sessions, ordered by most recently updated.
pub fn list_named_sessions(
    conn: &rusqlite::Connection,
) -> Result<Vec<SessionListing>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.name, s.updated_at, COUNT(h.id)
         FROM sessions s
         LEFT JOIN hosts h ON h.session_id = s.id
         WHERE s.type = 'named'
         GROUP BY s.id
         ORDER BY s.updated_at DESC",
    )
    .map_err(|e| AppError::DatabaseError(format!("list sessions prepare: {e}")))?;

    let mut listings = Vec::new();
    let mut rows = stmt.query([]).map_err(AppError::from)?;

    while let Some(r) = rows.next().map_err(AppError::from)? {
        listings.push(SessionListing {
            id:         r.get(0).map_err(AppError::from)?,
            name:       r.get(1).map_err(AppError::from)?,
            saved_at:   r.get(2).map_err(AppError::from)?,
            host_count: r.get::<_, i64>(3).map_err(AppError::from)? as usize,
        });
    }

    Ok(listings)
}

/// Deletes a named session and all associated host data (cascade).
pub fn delete_named_session(
    conn: &rusqlite::Connection,
    id: &str,
) -> Result<(), AppError> {
    conn.execute(
        "DELETE FROM sessions WHERE id = ?1 AND type = 'named'",
        [id],
    )
    .map_err(|e| AppError::DatabaseError(format!("delete session: {e}")))?;
    Ok(())
}

// ── Migration check ───────────────────────────────────────────────────────────

/// Returns true if the database has no sessions yet (fresh install or pre-migration).
pub fn check_migration_needed(conn: &rusqlite::Connection) -> bool {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap_or(0);
    count == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_test_db;

    fn sample_host(addr: &str) -> serde_json::Value {
        serde_json::json!({
            "address": addr,
            "hostname": "host.example.com",
            "status": "up",
            "scannedAt": "2024-01-01T00:00:00Z",
            "workflowStatus": "discovered",
            "notes": "test note",
            "tags": ["critical", "web"],
            "portNotes": { "80/tcp": "nginx here" },
            "portHistory": [{"ts": "2024-01-01T00:00:00Z", "open": 2}],
            "portsDiff": {"added": [443], "removed": []},
            "httpProbes": [],
            "tlsProbes": [],
            "script_results": [],
            "ports": [
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24"},
            ]
        })
    }

    #[test]
    fn active_session_round_trip() {
        let conn = open_test_db();
        let hosts = vec![sample_host("192.168.1.1"), sample_host("192.168.1.2")];
        save_active_session(&conn, &hosts).unwrap();

        let loaded = get_active_session(&conn).unwrap();
        assert_eq!(loaded.len(), 2);

        let h = loaded.iter().find(|h| h["address"] == "192.168.1.1").unwrap();
        assert_eq!(h["hostname"], "host.example.com");
        assert_eq!(h["workflowStatus"], "discovered");
        assert_eq!(h["notes"], "test note");
        assert_eq!(h["ports"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn tags_preserved_across_save_load() {
        let conn = open_test_db();
        save_active_session(&conn, &[sample_host("10.0.0.1")]).unwrap();
        let loaded = get_active_session(&conn).unwrap();
        let tags = loaded[0]["tags"].as_array().unwrap();
        assert!(tags.iter().any(|t| t == "critical"));
        assert!(tags.iter().any(|t| t == "web"));
    }

    #[test]
    fn port_notes_preserved() {
        let conn = open_test_db();
        save_active_session(&conn, &[sample_host("10.0.0.1")]).unwrap();
        let loaded = get_active_session(&conn).unwrap();
        assert_eq!(loaded[0]["portNotes"]["80/tcp"], "nginx here");
    }

    #[test]
    fn duplicate_host_is_upserted_not_duplicated() {
        let conn = open_test_db();
        save_active_session(&conn, &[sample_host("10.0.0.1")]).unwrap();
        let mut updated = sample_host("10.0.0.1");
        updated["notes"] = "updated note".into();
        save_active_session(&conn, &[updated]).unwrap();

        let loaded = get_active_session(&conn).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0]["notes"], "updated note");
    }

    #[test]
    fn clear_active_session_removes_hosts() {
        let conn = open_test_db();
        save_active_session(&conn, &[sample_host("10.0.0.1")]).unwrap();
        clear_active_session(&conn).unwrap();
        assert_eq!(get_active_session(&conn).unwrap().len(), 0);
    }

    #[test]
    fn named_session_lifecycle() {
        let conn = open_test_db();
        let id = save_named_session(&conn, "My Snap", &[sample_host("172.16.0.1")]).unwrap();

        let list = list_named_sessions(&conn).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "My Snap");
        assert_eq!(list[0].host_count, 1);

        let hosts = load_named_session(&conn, &id).unwrap();
        assert_eq!(hosts[0]["address"], "172.16.0.1");

        delete_named_session(&conn, &id).unwrap();
        assert!(list_named_sessions(&conn).unwrap().is_empty());
    }

    #[test]
    fn check_migration_needed_true_on_empty_db() {
        let conn = open_test_db();
        assert!(check_migration_needed(&conn));
    }

    #[test]
    fn check_migration_needed_false_after_save() {
        let conn = open_test_db();
        save_active_session(&conn, &[sample_host("1.2.3.4")]).unwrap();
        assert!(!check_migration_needed(&conn));
    }
}
