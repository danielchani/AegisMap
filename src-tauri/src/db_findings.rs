use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::error::AppError;

// ── Input types (from frontend) ───────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingInput {
    pub session_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub status: Option<String>,
    pub affected_hosts: Vec<String>,
    pub affected_ports: Option<Vec<String>>,
    pub summary: String,
    pub technical_details: Option<String>,
    pub remediation: Option<String>,
    /// Frontend sends this field as "references" (renamed to avoid Rust keyword)
    #[serde(rename = "references")]
    pub ext_refs: Option<Vec<String>>,
    pub source: String,
    pub source_ref: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingPatch {
    pub title: Option<String>,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub status: Option<String>,
    pub affected_hosts: Option<Vec<String>>,
    pub affected_ports: Option<Vec<String>>,
    pub summary: Option<String>,
    pub technical_details: Option<String>,
    pub remediation: Option<String>,
    #[serde(rename = "references")]
    pub ext_refs: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceInput {
    pub finding_id: String,
    pub session_id: String,
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub host_address: Option<String>,
    pub port_ref: Option<String>,
    pub excerpt: String,
    pub raw_data: Option<String>,
}

// ── ID generation ─────────────────────────────────────────────────────────────

fn new_finding_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    format!("f-{}-{}", Utc::now().timestamp_millis(), C.fetch_add(1, Ordering::SeqCst))
}

fn new_evidence_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    format!("e-{}-{}", Utc::now().timestamp_millis(), C.fetch_add(1, Ordering::SeqCst))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Enforces the security rule: cve_candidate source always gets candidate confidence.
fn enforce_confidence(source: &str, confidence: &str) -> String {
    match source {
        "cve_candidate" => "candidate".to_string(),
        "version_advisory" => {
            if confidence == "confirmed" { "heuristic".to_string() } else { confidence.to_string() }
        }
        _ => confidence.to_string(),
    }
}

// ── Finding CRUD ──────────────────────────────────────────────────────────────

pub fn create_finding(
    conn: &rusqlite::Connection,
    input: FindingInput,
) -> Result<String, AppError> {
    let id = new_finding_id();
    let now = now_iso();
    let confidence = enforce_confidence(&input.source, &input.confidence);
    let status = input.status.as_deref().unwrap_or("draft");

    conn.execute(
        "INSERT INTO findings
           (id, session_id, title, severity, confidence, status,
            affected_hosts, affected_ports, summary, technical_details,
            remediation, ext_refs, source, source_ref, created_at, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        rusqlite::params![
            id,
            input.session_id,
            input.title,
            input.severity,
            confidence,
            status,
            serde_json::to_string(&input.affected_hosts).unwrap_or_default(),
            input.affected_ports.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            input.summary,
            input.technical_details,
            input.remediation,
            input.ext_refs.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            input.source,
            input.source_ref,
            now,
            now,
        ],
    )
    .map_err(|e| AppError::DatabaseError(format!("create finding: {e}")))?;

    Ok(id)
}

pub fn update_finding(
    conn: &rusqlite::Connection,
    id: &str,
    patch: FindingPatch,
) -> Result<(), AppError> {
    let now = now_iso();

    // Load current row for fields we won't touch
    let current = get_finding(conn, id)?;

    let title      = patch.title      .unwrap_or_else(|| current["title"].as_str().unwrap_or("").to_string());
    let severity   = patch.severity   .unwrap_or_else(|| current["severity"].as_str().unwrap_or("").to_string());
    let status     = patch.status     .unwrap_or_else(|| current["status"].as_str().unwrap_or("draft").to_string());
    let summary    = patch.summary    .unwrap_or_else(|| current["summary"].as_str().unwrap_or("").to_string());
    let confidence = patch.confidence.map(|c| {
        let source = current["source"].as_str().unwrap_or("");
        enforce_confidence(source, &c)
    }).unwrap_or_else(|| current["confidence"].as_str().unwrap_or("").to_string());

    let affected_hosts = patch.affected_hosts
        .map(|v| serde_json::to_string(&v).unwrap_or_default())
        .unwrap_or_else(|| current["affectedHosts"].to_string());
    let affected_ports = patch.affected_ports
        .map(|v| Some(serde_json::to_string(&v).unwrap_or_default()))
        .unwrap_or_else(|| current["affectedPorts"].as_str().map(String::from));

    let technical_details = patch.technical_details
        .or_else(|| current["technicalDetails"].as_str().map(String::from));
    let remediation = patch.remediation
        .or_else(|| current["remediation"].as_str().map(String::from));
    let ext_refs = patch.ext_refs
        .map(|v| Some(serde_json::to_string(&v).unwrap_or_default()))
        .unwrap_or_else(|| current["references"].as_str().map(String::from));

    conn.execute(
        "UPDATE findings SET title=?1, severity=?2, confidence=?3, status=?4,
         affected_hosts=?5, affected_ports=?6, summary=?7, technical_details=?8,
         remediation=?9, ext_refs=?10, updated_at=?11 WHERE id=?12",
        rusqlite::params![
            title, severity, confidence, status,
            affected_hosts, affected_ports, summary, technical_details,
            remediation, ext_refs, now, id,
        ],
    )
    .map_err(|e| AppError::DatabaseError(format!("update finding: {e}")))?;

    Ok(())
}

pub fn delete_finding(conn: &rusqlite::Connection, id: &str) -> Result<(), AppError> {
    conn.execute("DELETE FROM findings WHERE id = ?1", [id])
        .map_err(|e| AppError::DatabaseError(format!("delete finding: {e}")))?;
    Ok(())
}

pub fn list_findings(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, title, severity, confidence, status,
                affected_hosts, affected_ports, summary, technical_details,
                remediation, ext_refs, source, source_ref, created_at, updated_at
         FROM findings WHERE session_id = ?1 ORDER BY created_at DESC",
    )
    .map_err(|e| AppError::DatabaseError(format!("prepare list findings: {e}")))?;

    let mut findings = Vec::new();
    let mut rows = stmt.query([session_id]).map_err(AppError::from)?;

    while let Some(r) = rows.next().map_err(AppError::from)? {
        findings.push(row_to_finding_json(r)?);
    }
    Ok(findings)
}

pub fn get_finding(conn: &rusqlite::Connection, id: &str) -> Result<serde_json::Value, AppError> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, title, severity, confidence, status,
                affected_hosts, affected_ports, summary, technical_details,
                remediation, ext_refs, source, source_ref, created_at, updated_at
         FROM findings WHERE id = ?1",
    )
    .map_err(AppError::from)?;

    let mut rows = stmt.query([id]).map_err(AppError::from)?;
    let r = rows.next().map_err(AppError::from)?
        .ok_or_else(|| AppError::DatabaseError(format!("finding '{id}' not found")))?;
    row_to_finding_json(r)
}

fn row_to_finding_json(r: &rusqlite::Row<'_>) -> Result<serde_json::Value, AppError> {
    let affected_hosts_str: String = r.get(6).map_err(AppError::from)?;
    let affected_ports_str: Option<String> = r.get(7).map_err(AppError::from)?;
    let refs_str: Option<String> = r.get(11).map_err(AppError::from)?;

    let affected_hosts: serde_json::Value =
        serde_json::from_str(&affected_hosts_str).unwrap_or(serde_json::json!([]));
    let affected_ports: serde_json::Value = affected_ports_str
        .as_deref()
        .map(|s| serde_json::from_str(s).unwrap_or(serde_json::json!([])))
        .unwrap_or(serde_json::json!([]));
    let ext_refs: serde_json::Value = refs_str
        .as_deref()
        .map(|s| serde_json::from_str(s).unwrap_or(serde_json::json!([])))
        .unwrap_or(serde_json::json!([]));

    let mut obj = serde_json::json!({
        "id":             r.get::<_, String>(0).map_err(AppError::from)?,
        "sessionId":      r.get::<_, String>(1).map_err(AppError::from)?,
        "title":          r.get::<_, String>(2).map_err(AppError::from)?,
        "severity":       r.get::<_, String>(3).map_err(AppError::from)?,
        "confidence":     r.get::<_, String>(4).map_err(AppError::from)?,
        "status":         r.get::<_, String>(5).map_err(AppError::from)?,
        "affectedHosts":  affected_hosts,
        "affectedPorts":  affected_ports,
        "summary":        r.get::<_, String>(8).map_err(AppError::from)?,
        "source":         r.get::<_, String>(12).map_err(AppError::from)?,
        "evidenceIds":    serde_json::json!([]),
        "references":   ext_refs,
        "createdAt":      r.get::<_, String>(14).map_err(AppError::from)?,
        "updatedAt":      r.get::<_, String>(15).map_err(AppError::from)?,
    });

    if let Ok(Some(v)) = r.get::<_, Option<String>>(9)  { obj["technicalDetails"] = v.into(); }
    if let Ok(Some(v)) = r.get::<_, Option<String>>(10) { obj["remediation"]      = v.into(); }
    if let Ok(Some(v)) = r.get::<_, Option<String>>(13) { obj["sourceRef"]        = v.into(); }

    Ok(obj)
}

// ── Evidence CRUD ─────────────────────────────────────────────────────────────

pub fn attach_evidence(
    conn: &rusqlite::Connection,
    input: EvidenceInput,
) -> Result<String, AppError> {
    let id = new_evidence_id();
    let now = now_iso();

    // Compute SHA-256 of raw_data if present
    let hash = input.raw_data.as_deref().map(|data| {
        let result = Sha256::digest(data.as_bytes());
        result.iter().map(|b| format!("{b:02x}")).collect::<String>()
    });

    conn.execute(
        "INSERT INTO evidence (id, finding_id, session_id, type, host_address, port_ref, excerpt, raw_data, hash, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            id,
            input.finding_id,
            input.session_id,
            input.evidence_type,
            input.host_address,
            input.port_ref,
            input.excerpt,
            input.raw_data,
            hash,
            now,
        ],
    )
    .map_err(|e| AppError::DatabaseError(format!("attach evidence: {e}")))?;

    Ok(id)
}

pub fn delete_evidence(conn: &rusqlite::Connection, id: &str) -> Result<(), AppError> {
    conn.execute("DELETE FROM evidence WHERE id = ?1", [id])
        .map_err(|e| AppError::DatabaseError(format!("delete evidence: {e}")))?;
    Ok(())
}

pub fn list_evidence_for_finding(
    conn: &rusqlite::Connection,
    finding_id: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT id, finding_id, session_id, type, host_address, port_ref,
                excerpt, raw_data, hash, created_at
         FROM evidence WHERE finding_id = ?1 ORDER BY created_at",
    )
    .map_err(AppError::from)?;

    let mut items = Vec::new();
    let mut rows = stmt.query([finding_id]).map_err(AppError::from)?;

    while let Some(r) = rows.next().map_err(AppError::from)? {
        let mut item = serde_json::json!({
            "id":         r.get::<_, String>(0).map_err(AppError::from)?,
            "findingId":  r.get::<_, String>(1).map_err(AppError::from)?,
            "sessionId":  r.get::<_, String>(2).map_err(AppError::from)?,
            "type":       r.get::<_, String>(3).map_err(AppError::from)?,
            "excerpt":    r.get::<_, String>(6).map_err(AppError::from)?,
            "createdAt":  r.get::<_, String>(9).map_err(AppError::from)?,
        });
        if let Ok(Some(v)) = r.get::<_, Option<String>>(4) { item["hostAddress"] = v.into(); }
        if let Ok(Some(v)) = r.get::<_, Option<String>>(5) { item["portRef"]     = v.into(); }
        if let Ok(Some(v)) = r.get::<_, Option<String>>(7) { item["rawData"]     = v.into(); }
        if let Ok(Some(v)) = r.get::<_, Option<String>>(8) { item["hash"]        = v.into(); }
        items.push(item);
    }
    Ok(items)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_test_db;

    fn sample_session(conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO sessions (id, name, type, created_at, updated_at) VALUES ('s1','Test','active','2024-01-01','2024-01-01')",
            [],
        ).unwrap();
    }

    fn sample_input(session_id: &str) -> FindingInput {
        FindingInput {
            session_id: session_id.to_string(),
            title: "Test Finding".to_string(),
            severity: "high".to_string(),
            confidence: "candidate".to_string(),
            status: None,
            affected_hosts: vec!["10.0.0.1".to_string()],
            affected_ports: Some(vec!["443/tcp".to_string()]),
            summary: "Test summary".to_string(),
            technical_details: None,
            remediation: None,
            ext_refs: Some(vec!["CVE-2024-0001".to_string()]),
            source: "cve_candidate".to_string(),
            source_ref: Some("CVE-2024-0001".to_string()),
        }
    }

    #[test]
    fn create_and_list() {
        let conn = open_test_db();
        sample_session(&conn);
        let id = create_finding(&conn, sample_input("s1")).unwrap();
        let findings = list_findings(&conn, "s1").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["id"], id);
        assert_eq!(findings[0]["title"], "Test Finding");
    }

    #[test]
    fn get_finding_roundtrip() {
        let conn = open_test_db();
        sample_session(&conn);
        let id = create_finding(&conn, sample_input("s1")).unwrap();
        let f = get_finding(&conn, &id).unwrap();
        assert_eq!(f["severity"], "high");
        assert_eq!(f["status"], "draft");
        assert_eq!(f["source"], "cve_candidate");
        assert_eq!(f["affectedHosts"][0], "10.0.0.1");
    }

    #[test]
    fn cve_candidate_source_enforces_candidate_confidence() {
        let conn = open_test_db();
        sample_session(&conn);
        let mut input = sample_input("s1");
        input.source = "cve_candidate".to_string();
        input.confidence = "confirmed".to_string(); // should be overridden
        let id = create_finding(&conn, input).unwrap();
        let f = get_finding(&conn, &id).unwrap();
        // Backend must override to "candidate"
        assert_eq!(f["confidence"], "candidate");
    }

    #[test]
    fn update_status_transition() {
        let conn = open_test_db();
        sample_session(&conn);
        let id = create_finding(&conn, sample_input("s1")).unwrap();
        update_finding(&conn, &id, FindingPatch {
            status: Some("confirmed".to_string()),
            title: None, severity: None, confidence: None,
            affected_hosts: None, affected_ports: None, summary: None,
            technical_details: None, remediation: None, ext_refs: None,
        }).unwrap();
        let f = get_finding(&conn, &id).unwrap();
        assert_eq!(f["status"], "confirmed");
    }

    #[test]
    fn delete_finding_cascades_evidence() {
        let conn = open_test_db();
        sample_session(&conn);
        let finding_id = create_finding(&conn, sample_input("s1")).unwrap();
        attach_evidence(&conn, EvidenceInput {
            finding_id: finding_id.clone(),
            session_id: "s1".to_string(),
            evidence_type: "advisory_match".to_string(),
            host_address: Some("10.0.0.1".to_string()),
            port_ref: None, excerpt: "test".to_string(), raw_data: None,
        }).unwrap();
        delete_finding(&conn, &finding_id).unwrap();
        let evidence = list_evidence_for_finding(&conn, &finding_id).unwrap();
        assert!(evidence.is_empty()); // cascaded
    }

    #[test]
    fn attach_evidence_computes_hash() {
        let conn = open_test_db();
        sample_session(&conn);
        let finding_id = create_finding(&conn, sample_input("s1")).unwrap();
        let ev_id = attach_evidence(&conn, EvidenceInput {
            finding_id: finding_id.clone(),
            session_id: "s1".to_string(),
            evidence_type: "advisory_match".to_string(),
            host_address: None, port_ref: None,
            excerpt: "CVE-2024-0001 matched".to_string(),
            raw_data: Some(r#"{"cvss":9.8}"#.to_string()),
        }).unwrap();
        let items = list_evidence_for_finding(&conn, &finding_id).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], ev_id);
        let hash = items[0]["hash"].as_str().unwrap_or("");
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn list_findings_filtered_by_session() {
        let conn = open_test_db();
        sample_session(&conn);
        conn.execute(
            "INSERT INTO sessions (id, name, type, created_at, updated_at) VALUES ('s2','Other','named','2024-01-01','2024-01-01')",
            [],
        ).unwrap();
        create_finding(&conn, sample_input("s1")).unwrap();
        create_finding(&conn, {
            let mut i = sample_input("s2");
            i.title = "Other session finding".to_string();
            i
        }).unwrap();
        assert_eq!(list_findings(&conn, "s1").unwrap().len(), 1);
        assert_eq!(list_findings(&conn, "s2").unwrap().len(), 1);
    }
}
