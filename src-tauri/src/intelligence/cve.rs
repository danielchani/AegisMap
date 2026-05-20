use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::error::AppError;

// ── Constants ─────────────────────────────────────────────────────────────────

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MAX_RESULTS_PER_PAGE: u32 = 20;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024; // 2 MB hard cap
/// NVD public rate limit: 5 req/30 s → 6 s minimum. +0.5 s buffer for latency.
const RATE_LIMIT_NO_KEY_MS: u64 = 6_500;
const RATE_LIMIT_WITH_KEY_MS: u64 = 700;
const CACHE_TTL_SECS: i64 = 86_400; // 24 hours
const SETTINGS_KEY_NVD: &str = "nvd_api_key";

// ── Rate limiter ──────────────────────────────────────────────────────────────

/// Shared across all Tauri commands — enforces NVD rate limits server-side.
/// Uses std Mutex (never held across an await).
pub struct CveRateState {
    last_request_at: Mutex<Option<Instant>>,
}

impl CveRateState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { last_request_at: Mutex::new(None) })
    }

    /// Returns 0 and records the current time if a request may proceed.
    /// Returns the milliseconds to wait if the rate window is still open.
    pub fn check_and_claim(&self, has_api_key: bool) -> u64 {
        let min_delay = Duration::from_millis(
            if has_api_key { RATE_LIMIT_WITH_KEY_MS } else { RATE_LIMIT_NO_KEY_MS },
        );
        let mut guard = self.last_request_at.lock().unwrap();
        if let Some(last) = *guard {
            let elapsed = last.elapsed();
            if elapsed < min_delay {
                return (min_delay - elapsed).as_millis() as u64;
            }
        }
        *guard = Some(Instant::now());
        0
    }

    /// Non-mutating peek at how long until the next request is allowed.
    pub fn millis_until_ready(&self, has_api_key: bool) -> u64 {
        let min_delay = Duration::from_millis(
            if has_api_key { RATE_LIMIT_WITH_KEY_MS } else { RATE_LIMIT_NO_KEY_MS },
        );
        let guard = self.last_request_at.lock().unwrap();
        if let Some(last) = *guard {
            let elapsed = last.elapsed();
            if elapsed < min_delay {
                return (min_delay - elapsed).as_millis() as u64;
            }
        }
        0
    }
}

// ── Public output types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveCveEntry {
    /// Validated CVE identifier matching CVE-NNNN-N+.
    pub cve_id: String,
    pub published: String,
    pub last_modified: String,
    /// English description, truncated to 2 000 chars.
    pub description: String,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v3_severity: Option<String>,
    pub cvss_v2_score: Option<f64>,
    /// HTTPS-only reference URLs, capped at 10.
    pub references: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveFetchResult {
    pub product_key: String,
    pub entries: Vec<LiveCveEntry>,
    pub fetched_at: String,
    pub expires_at: String,
    pub from_cache: bool,
    pub total_available: u32,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveRateStatus {
    pub millis_until_ready: u64,
    pub has_api_key: bool,
}

// ── NVD API response shapes (deserialization only, never leaves this module) ──

#[derive(serde::Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(serde::Deserialize)]
struct NvdVulnerability { cve: NvdCve }

#[derive(serde::Deserialize)]
struct NvdCve {
    id: String,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    #[serde(default)]
    references: Vec<NvdReference>,
}

#[derive(serde::Deserialize)]
struct NvdDescription { lang: String, value: String }

#[derive(serde::Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)] cvss_v31: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV30", default)] cvss_v30: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV2",  default)] cvss_v2:  Vec<NvdCvssV2Metric>,
}

#[derive(serde::Deserialize)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssV3Data,
}
#[derive(serde::Deserialize)]
struct NvdCvssV3Data {
    #[serde(rename = "baseScore")]    base_score: f64,
    #[serde(rename = "baseSeverity")] base_severity: String,
}

#[derive(serde::Deserialize)]
struct NvdCvssV2Metric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssV2Data,
}
#[derive(serde::Deserialize)]
struct NvdCvssV2Data {
    #[serde(rename = "baseScore")] base_score: f64,
}

#[derive(serde::Deserialize)]
struct NvdReference { url: String }

// ── Input validation ──────────────────────────────────────────────────────────

/// Validates a product keyword for NVD search. Alphanumeric, space, `-`, `.`, `_`.
pub fn validate_product_name(s: &str) -> Result<&str, AppError> {
    let t = s.trim();
    if t.is_empty() || t.len() > 100 {
        return Err(AppError::InvalidTarget("product name must be 1–100 characters".into()));
    }
    for c in t.chars() {
        if !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | ' ' | '-' | '.' | '_') {
            return Err(AppError::InvalidTarget(
                format!("product name contains invalid character: {:?}", c),
            ));
        }
    }
    Ok(t)
}

/// Validates an NVD API key: alphanumeric and hyphens only, max 100 chars.
pub fn validate_api_key(key: &str) -> Result<(), AppError> {
    if key.len() > 100 {
        return Err(AppError::InvalidTarget("API key too long".into()));
    }
    for c in key.chars() {
        if !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-') {
            return Err(AppError::InvalidTarget(
                format!("API key contains invalid character: {:?}", c),
            ));
        }
    }
    Ok(())
}

fn validate_cve_id(id: &str) -> Option<String> {
    let id = id.trim();
    if !id.starts_with("CVE-") { return None; }
    let rest = &id[4..];
    let mut parts = rest.splitn(2, '-');
    let year = parts.next()?;
    let num  = parts.next()?;
    if year.len() == 4 && year.chars().all(|c| c.is_ascii_digit())
        && !num.is_empty() && num.chars().all(|c| c.is_ascii_digit())
    {
        Some(id.to_string())
    } else {
        None
    }
}

fn validate_cvss(score: f64) -> Option<f64> {
    if (0.0..=10.0).contains(&score) { Some(score) } else { None }
}

fn validate_severity(s: &str) -> Option<String> {
    match s.to_ascii_uppercase().as_str() {
        "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" => Some(s.to_ascii_uppercase()),
        _ => None,
    }
}

fn validate_ref_url(url: &str) -> Option<String> {
    let u = url.trim();
    (u.starts_with("https://") && u.len() <= 512).then(|| u.to_string())
}

// ── Response parsing ──────────────────────────────────────────────────────────

fn parse_response(nvd: NvdResponse) -> (Vec<LiveCveEntry>, u32) {
    let total = nvd.total_results;
    let entries = nvd.vulnerabilities
        .into_iter()
        .filter_map(|v| parse_cve(v.cve))
        .collect();
    (entries, total)
}

fn parse_cve(cve: NvdCve) -> Option<LiveCveEntry> {
    let cve_id = validate_cve_id(&cve.id)?;

    let description = cve.descriptions.iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.chars().take(2000).collect::<String>())
        .unwrap_or_default();

    let (cvss_v3_score, cvss_v3_severity) = cve.metrics.as_ref()
        .and_then(|m| m.cvss_v31.first().or_else(|| m.cvss_v30.first()))
        .map(|c| (validate_cvss(c.cvss_data.base_score), validate_severity(&c.cvss_data.base_severity)))
        .unwrap_or((None, None));

    let cvss_v2_score = cve.metrics.as_ref()
        .and_then(|m| m.cvss_v2.first())
        .and_then(|c| validate_cvss(c.cvss_data.base_score));

    let references: Vec<String> = cve.references.into_iter()
        .filter_map(|r| validate_ref_url(&r.url))
        .take(10)
        .collect();

    Some(LiveCveEntry { cve_id, published: cve.published, last_modified: cve.last_modified,
        description, cvss_v3_score, cvss_v3_severity, cvss_v2_score, references })
}

// ── SQLite cache helpers ──────────────────────────────────────────────────────

pub fn cache_get(conn: &rusqlite::Connection, product_key: &str) -> Option<CveFetchResult> {
    let now = Utc::now().to_rfc3339();
    conn.query_row(
        "SELECT data, fetched_at, expires_at, entry_count FROM cve_cache
         WHERE product_key = ?1 AND expires_at > ?2",
        rusqlite::params![product_key, now],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                  row.get::<_, String>(2)?, row.get::<_, i64>(3)?)),
    ).ok().and_then(|(data, fetched_at, expires_at, total)| {
        serde_json::from_str::<Vec<LiveCveEntry>>(&data).ok().map(|entries| CveFetchResult {
            product_key: product_key.to_string(), entries, fetched_at, expires_at,
            from_cache: true, total_available: total as u32,
        })
    })
}

pub fn cache_put(
    conn: &rusqlite::Connection,
    product_key: &str,
    entries: &[LiveCveEntry],
    total_available: u32,
) -> Result<(), AppError> {
    let now = Utc::now();
    let fetched_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(CACHE_TTL_SECS)).to_rfc3339();
    let data = serde_json::to_string(entries)?;
    conn.execute(
        "INSERT INTO cve_cache (product_key, fetched_at, expires_at, entry_count, data)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(product_key) DO UPDATE SET
           fetched_at = excluded.fetched_at, expires_at = excluded.expires_at,
           entry_count = excluded.entry_count, data = excluded.data",
        rusqlite::params![product_key, fetched_at, expires_at, total_available as i64, data],
    )?;
    Ok(())
}

// ── Settings helpers ──────────────────────────────────────────────────────────

pub fn settings_get(conn: &rusqlite::Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        rusqlite::params![key],
        |r| r.get(0),
    ).ok()
}

pub fn settings_set(
    conn: &rusqlite::Connection,
    key: &str,
    value: Option<&str>,
) -> Result<(), AppError> {
    match value {
        Some(v) => { conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, v],
        )?; }
        None => { conn.execute("DELETE FROM settings WHERE key = ?1", rusqlite::params![key])?; }
    }
    Ok(())
}

pub fn get_nvd_key(conn: &rusqlite::Connection) -> Option<String> {
    settings_get(conn, SETTINGS_KEY_NVD)
}

pub fn set_nvd_key(conn: &rusqlite::Connection, key: Option<&str>) -> Result<(), AppError> {
    settings_set(conn, SETTINGS_KEY_NVD, key)
}

// ── Main fetch ────────────────────────────────────────────────────────────────

/// Makes the NVD API request.  Caller must have called `rate_state.check_and_claim`
/// first and must not call this on the UI thread.
pub async fn fetch_from_nvd(
    product: &str,
    api_key: Option<&str>,
) -> Result<(Vec<LiveCveEntry>, u32), AppError> {
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::PersistenceError(format!("HTTP client init: {e}")))?;

    let mut req = client
        .get(NVD_API_BASE)
        .query(&[("keywordSearch", product), ("resultsPerPage", &MAX_RESULTS_PER_PAGE.to_string())]);

    if let Some(key) = api_key {
        req = req.header("apiKey", key);
    }

    let resp = req.send().await
        .map_err(|e| AppError::PersistenceError(format!("NVD request failed: {e}")))?;

    match resp.status() {
        s if s == reqwest::StatusCode::FORBIDDEN =>
            return Err(AppError::PersistenceError("NVD API returned 403 — check API key".into())),
        s if s == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            return Err(AppError::PersistenceError("NVD API rate limit exceeded (429)".into())),
        s if !s.is_success() =>
            return Err(AppError::PersistenceError(format!("NVD API returned HTTP {s}"))),
        _ => {}
    }

    let bytes = resp.bytes().await
        .map_err(|e| AppError::PersistenceError(format!("NVD response read failed: {e}")))?;

    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(AppError::PersistenceError("NVD response exceeds 2 MB size limit".into()));
    }

    let nvd: NvdResponse = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::PersistenceError(format!("NVD JSON parse error: {e}")))?;

    Ok(parse_response(nvd))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("
            CREATE TABLE cve_cache (
                product_key TEXT PRIMARY KEY,
                fetched_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                data        TEXT NOT NULL
            );
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ").unwrap();
        conn
    }

    #[test]
    fn product_name_valid() {
        assert!(validate_product_name("OpenSSH").is_ok());
        assert!(validate_product_name("nginx 1.24").is_ok());
        assert!(validate_product_name("apache-httpd").is_ok());
        assert!(validate_product_name("mysql_8.0").is_ok());
    }

    #[test]
    fn product_name_rejects_injection() {
        assert!(validate_product_name("nginx; rm -rf /").is_err());
        assert!(validate_product_name("apache&cmd=exec").is_err());
        assert!(validate_product_name("test|pipe").is_err());
        assert!(validate_product_name("foo<script>").is_err());
        assert!(validate_product_name("path/traversal").is_err());
        assert!(validate_product_name("").is_err());
        assert!(validate_product_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn api_key_validation() {
        assert!(validate_api_key("abc123-DEF456").is_ok());
        assert!(validate_api_key("valid-key-0001").is_ok());
        assert!(validate_api_key("key with spaces").is_err());
        assert!(validate_api_key("key$pecial").is_err());
        assert!(validate_api_key(&"a".repeat(101)).is_err());
    }

    #[test]
    fn cve_id_valid_formats() {
        assert_eq!(validate_cve_id("CVE-2023-12345"), Some("CVE-2023-12345".to_string()));
        assert_eq!(validate_cve_id("CVE-2021-44228"), Some("CVE-2021-44228".to_string()));
        assert_eq!(validate_cve_id(" CVE-2023-99999 "), Some("CVE-2023-99999".to_string()));
    }

    #[test]
    fn cve_id_invalid_formats() {
        assert_eq!(validate_cve_id("cve-2023-12345"), None); // must be uppercase
        assert_eq!(validate_cve_id("CVE-23-12345"), None);   // year must be 4 digits
        assert_eq!(validate_cve_id("CVE-2023-"), None);       // num part required
        assert_eq!(validate_cve_id("not-a-cve"), None);
        assert_eq!(validate_cve_id("CVE-202X-12345"), None);  // non-digit year
        assert_eq!(validate_cve_id("CVE-2023-abc"), None);    // non-digit num
    }

    #[test]
    fn cvss_score_range() {
        assert_eq!(validate_cvss(0.0), Some(0.0));
        assert_eq!(validate_cvss(7.5), Some(7.5));
        assert_eq!(validate_cvss(10.0), Some(10.0));
        assert_eq!(validate_cvss(-0.1), None);
        assert_eq!(validate_cvss(10.1), None);
        assert_eq!(validate_cvss(f64::NAN), None);
    }

    #[test]
    fn severity_normalisation() {
        assert_eq!(validate_severity("HIGH"), Some("HIGH".to_string()));
        assert_eq!(validate_severity("critical"), Some("CRITICAL".to_string()));
        assert_eq!(validate_severity("Medium"), Some("MEDIUM".to_string()));
        assert_eq!(validate_severity("extreme"), None);
    }

    #[test]
    fn ref_url_https_only() {
        assert!(validate_ref_url("https://nvd.nist.gov/vuln/detail/CVE-2023-1").is_some());
        assert!(validate_ref_url("http://insecure.example.com").is_none());
        assert!(validate_ref_url("javascript:alert(1)").is_none());
        assert!(validate_ref_url(&format!("https://x.com/{}", "a".repeat(510))).is_none());
        assert!(validate_ref_url("").is_none());
    }

    #[test]
    fn parse_valid_nvd_response() {
        let json = r#"{
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-12345",
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-06-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                    },
                    "references": [{"url": "https://nvd.nist.gov/detail/CVE-2023-12345"}]
                }
            }]
        }"#;
        let nvd: NvdResponse = serde_json::from_str(json).unwrap();
        let (entries, total) = parse_response(nvd);
        assert_eq!(total, 1);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.cve_id, "CVE-2023-12345");
        assert_eq!(e.cvss_v3_score, Some(9.8));
        assert_eq!(e.cvss_v3_severity.as_deref(), Some("CRITICAL"));
        assert_eq!(e.description, "A test vulnerability.");
        assert_eq!(e.references.len(), 1);
    }

    #[test]
    fn filters_invalid_cve_ids_from_response() {
        let json = r#"{
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "NOT-A-CVE-ID",
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Bad entry."}]
                }
            }]
        }"#;
        let nvd: NvdResponse = serde_json::from_str(json).unwrap();
        let (entries, _) = parse_response(nvd);
        assert_eq!(entries.len(), 0, "invalid CVE ID must be filtered out");
    }

    #[test]
    fn filters_http_references() {
        let json = r#"{
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-99999",
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test."}],
                    "references": [
                        {"url": "http://insecure.com/vuln"},
                        {"url": "https://safe.example.com/cve"}
                    ]
                }
            }]
        }"#;
        let nvd: NvdResponse = serde_json::from_str(json).unwrap();
        let (entries, _) = parse_response(nvd);
        assert_eq!(entries[0].references.len(), 1);
        assert!(entries[0].references[0].starts_with("https://"));
    }

    #[test]
    fn rate_limiter_blocks_rapid_requests() {
        let state = CveRateState::new();
        assert_eq!(state.check_and_claim(false), 0, "first request must be allowed");
        let wait = state.check_and_claim(false);
        assert!(wait > 0, "immediate second request must be rate-limited");
        assert!(wait <= RATE_LIMIT_NO_KEY_MS);
    }

    #[test]
    fn rate_limiter_with_key_shorter_window() {
        let state = CveRateState::new();
        state.check_and_claim(true);
        let wait_key    = state.millis_until_ready(true);
        let wait_no_key = state.millis_until_ready(false);
        // With key window (700 ms) ≤ without key window (6500 ms)
        assert!(wait_key <= wait_no_key || wait_key == 0);
    }

    #[test]
    fn millis_until_ready_non_mutating() {
        let state = CveRateState::new();
        assert_eq!(state.millis_until_ready(false), 0);
        // calling peek twice should give same result (no side effects)
        assert_eq!(state.millis_until_ready(false), 0);
    }

    #[test]
    fn cache_roundtrip() {
        let conn = test_db();
        let entries = vec![LiveCveEntry {
            cve_id: "CVE-2023-11111".to_string(),
            published: "2023-01-01T00:00:00".to_string(),
            last_modified: "2023-01-01T00:00:00".to_string(),
            description: "Test entry.".to_string(),
            cvss_v3_score: Some(7.5),
            cvss_v3_severity: Some("HIGH".to_string()),
            cvss_v2_score: None,
            references: vec!["https://example.com/cve".to_string()],
        }];
        cache_put(&conn, "nginx", &entries, 42).unwrap();
        let result = cache_get(&conn, "nginx").unwrap();
        assert!(result.from_cache);
        assert_eq!(result.total_available, 42);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].cve_id, "CVE-2023-11111");
    }

    #[test]
    fn cache_miss_returns_none() {
        let conn = test_db();
        assert!(cache_get(&conn, "nonexistent-product").is_none());
    }

    #[test]
    fn settings_roundtrip() {
        let conn = test_db();
        assert!(settings_get(&conn, "nvd_api_key").is_none());
        settings_set(&conn, "nvd_api_key", Some("test-key-123")).unwrap();
        assert_eq!(settings_get(&conn, "nvd_api_key").as_deref(), Some("test-key-123"));
        settings_set(&conn, "nvd_api_key", None).unwrap();
        assert!(settings_get(&conn, "nvd_api_key").is_none());
    }

    #[test]
    fn description_truncated_at_2000_chars() {
        let long_desc = "x".repeat(3000);
        let json = format!(r#"{{
            "totalResults": 1,
            "vulnerabilities": [{{
                "cve": {{
                    "id": "CVE-2023-77777",
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-01T00:00:00.000",
                    "descriptions": [{{"lang": "en", "value": "{}"}}]
                }}
            }}]
        }}"#, long_desc);
        let nvd: NvdResponse = serde_json::from_str(&json).unwrap();
        let (entries, _) = parse_response(nvd);
        assert_eq!(entries[0].description.len(), 2000);
    }

    #[test]
    fn references_capped_at_10() {
        let refs: String = (0..15)
            .map(|i| format!(r#"{{"url": "https://example.com/{i}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(r#"{{
            "totalResults": 1,
            "vulnerabilities": [{{
                "cve": {{
                    "id": "CVE-2023-88888",
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-01T00:00:00.000",
                    "descriptions": [{{"lang": "en", "value": "Test."}}],
                    "references": [{}]
                }}
            }}]
        }}"#, refs);
        let nvd: NvdResponse = serde_json::from_str(&json).unwrap();
        let (entries, _) = parse_response(nvd);
        assert_eq!(entries[0].references.len(), 10, "references must be capped at 10");
    }
}
