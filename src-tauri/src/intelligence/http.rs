use std::time::{Duration, Instant};

use chrono::Utc;
use reqwest::{
    header::HeaderMap,
    redirect,
    ClientBuilder,
};
use serde::{Deserialize, Serialize};

// ── Request / response models ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpProbeRequest {
    /// Single host or IP address — no CIDR ranges (validated in command layer).
    pub address: String,
    pub port: u16,
    pub use_https: bool,
    /// Follow up to 5 HTTP redirects; final URL recorded in `final_url`.
    pub follow_redirects: bool,
    /// Request timeout in seconds (1–30).
    pub timeout_secs: u8,
    /// Accept self-signed / expired TLS certificates — on by default for pentest use.
    pub accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpProbeResult {
    pub url: String,
    /// Final URL after any redirects (equals `url` when no redirect occurred).
    pub final_url: String,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub x_powered_by: Option<String>,
    pub content_type: Option<String>,
    pub response_time_ms: u64,
    pub response_size_bytes: Option<u64>,
    pub security_headers: SecurityHeaders,
    /// Human-readable technology fingerprint strings, e.g. `"Server: nginx/1.24"`.
    pub technology_hints: Vec<String>,
    /// Network or TLS error message — populated instead of returning `Err`
    /// so the UI can distinguish "probe ran, server refused" from a validation error.
    pub error: Option<String>,
    pub probed_at: String, // ISO-8601
}

/// Presence/absence of common HTTP security response headers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityHeaders {
    pub hsts: Option<String>,
    pub content_security_policy: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub cross_origin_opener_policy: Option<String>,
    pub cross_origin_resource_policy: Option<String>,
    pub cross_origin_embedder_policy: Option<String>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Performs an HTTP/HTTPS GET probe against `req.address:req.port`.
///
/// Network and TLS errors are captured in `result.error` rather than
/// propagated as `Err` — callers receive a result they can always display.
pub async fn probe(req: HttpProbeRequest) -> HttpProbeResult {
    let scheme = if req.use_https { "https" } else { "http" };
    let url = format!("{}://{}:{}/", scheme, req.address, req.port);
    let probed_at = Utc::now().to_rfc3339();

    let redirect_policy = if req.follow_redirects {
        redirect::Policy::limited(5)
    } else {
        redirect::Policy::none()
    };

    let client = match ClientBuilder::new()
        .user_agent("AegisMap/0.1 (Authorized Security Probe)")
        .timeout(Duration::from_secs(req.timeout_secs as u64))
        .danger_accept_invalid_certs(req.accept_invalid_certs)
        .redirect(redirect_policy)
        .build()
    {
        Ok(c) => c,
        Err(e) => return error_result(&url, &probed_at, e.to_string()),
    };

    let start = Instant::now();
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return error_result(&url, &probed_at, e.to_string()),
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let status_code = response.status().as_u16();
    let status_text = response.status().canonical_reason().map(String::from);
    let final_url = response.url().to_string();
    let headers = response.headers().clone();

    let server = header_str(&headers, "server");
    let x_powered_by = header_str(&headers, "x-powered-by");
    let content_type = header_str(&headers, "content-type");
    let security_headers = extract_security_headers(&headers);
    let technology_hints = extract_technology_hints(&headers);

    // Read body — cap at 64 KiB to avoid large downloads.
    let body = match response.bytes().await {
        Ok(b) => b,
        Err(_) => Default::default(),
    };
    let body_size = body.len() as u64;
    let body_text = String::from_utf8_lossy(&body[..body.len().min(65536)]);
    let title = extract_title(&body_text);

    HttpProbeResult {
        url,
        final_url,
        status_code: Some(status_code),
        status_text,
        title,
        server,
        x_powered_by,
        content_type,
        response_time_ms: elapsed_ms,
        response_size_bytes: Some(body_size),
        security_headers,
        technology_hints,
        error: None,
        probed_at,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn error_result(url: &str, probed_at: &str, message: String) -> HttpProbeResult {
    HttpProbeResult {
        url: url.to_string(),
        final_url: url.to_string(),
        status_code: None,
        status_text: None,
        title: None,
        server: None,
        x_powered_by: None,
        content_type: None,
        response_time_ms: 0,
        response_size_bytes: None,
        security_headers: SecurityHeaders::default(),
        technology_hints: Vec::new(),
        error: Some(message),
        probed_at: probed_at.to_string(),
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Extracts the text of the first `<title>` element from an HTML string.
/// Matching is case-insensitive; result has leading/trailing whitespace trimmed
/// and basic HTML entities decoded.
pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    // Find `<title` (allow attributes like <title lang="en">)
    let open_start = lower.find("<title")?;
    let tag_close = lower[open_start..].find('>')?;
    let content_start = open_start + tag_close + 1;
    let end_tag = lower[content_start..].find("</title>")?;
    let raw = html[content_start..content_start + end_tag].trim();
    if raw.is_empty() {
        return None;
    }
    Some(decode_html_entities(raw))
}

/// Decodes a small set of HTML entities that frequently appear in page titles.
pub fn decode_html_entities(s: &str) -> String {
    // Numeric decimal references first (&#NNN;)
    let mut result = numeric_entity_decode(s);
    // Named entities
    result = result
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&ndash;", "–")
        .replace("&mdash;", "—")
        .replace("&laquo;", "«")
        .replace("&raquo;", "»");
    result
}

fn numeric_entity_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '&' && s[i..].starts_with("&#") {
            // find the closing ';'
            if let Some(semi) = s[i + 2..].find(';') {
                let num_str = &s[i + 2..i + 2 + semi];
                if let Ok(n) = num_str.parse::<u32>() {
                    if let Some(ch) = char::from_u32(n) {
                        out.push(ch);
                        // skip the rest of the entity
                        let skip = 2 + semi + 1; // "&#" + digits + ";"
                        let mut skipped = 0;
                        while skipped < skip - 1 {
                            if chars.next().is_some() { skipped += 1; }
                        }
                        continue;
                    }
                }
            }
        }
        out.push(c);
    }
    out
}

/// Extracts the 10 standard security response headers into a typed struct.
pub fn extract_security_headers(headers: &HeaderMap) -> SecurityHeaders {
    let get = |name: &str| header_str(headers, name);
    SecurityHeaders {
        hsts:                        get("strict-transport-security"),
        content_security_policy:     get("content-security-policy"),
        x_frame_options:             get("x-frame-options"),
        x_content_type_options:      get("x-content-type-options"),
        x_xss_protection:            get("x-xss-protection"),
        referrer_policy:             get("referrer-policy"),
        permissions_policy:          get("permissions-policy"),
        cross_origin_opener_policy:  get("cross-origin-opener-policy"),
        cross_origin_resource_policy: get("cross-origin-resource-policy"),
        cross_origin_embedder_policy: get("cross-origin-embedder-policy"),
    }
}

/// Builds human-readable technology hint strings from response headers.
pub fn extract_technology_hints(headers: &HeaderMap) -> Vec<String> {
    let mut hints: Vec<String> = Vec::new();

    if let Some(s) = header_str(headers, "server")         { hints.push(format!("Server: {s}")); }
    if let Some(s) = header_str(headers, "x-powered-by")   { hints.push(format!("Powered-By: {s}")); }
    if let Some(s) = header_str(headers, "x-generator")    { hints.push(format!("Generator: {s}")); }
    if let Some(s) = header_str(headers, "x-aspnet-version") { hints.push(format!("ASP.NET: {s}")); }
    if let Some(s) = header_str(headers, "x-aspnetmvc-version") { hints.push(format!("ASP.NET MVC: {s}")); }
    if let Some(s) = header_str(headers, "via")            { hints.push(format!("Via: {s}")); }

    // Cookie-name fingerprinting
    let cookies: Vec<_> = headers.get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for c in &cookies {
        let cl = c.to_ascii_lowercase();
        if cl.contains("phpsessid")          { push_unique(&mut hints, "Runtime: PHP"); }
        if cl.contains("jsessionid")         { push_unique(&mut hints, "Runtime: Java/Tomcat"); }
        if cl.contains("asp.net_sessionid")  { push_unique(&mut hints, "Runtime: ASP.NET"); }
        if cl.contains("rack.session")       { push_unique(&mut hints, "Runtime: Ruby/Rack"); }
        if cl.contains("laravel_session")    { push_unique(&mut hints, "Framework: Laravel"); }
        if cl.contains("django")             { push_unique(&mut hints, "Framework: Django"); }
    }

    hints
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    let owned = s.to_string();
    if !v.contains(&owned) {
        v.push(owned);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    // ── extract_title ─────────────────────────────────────────────────────────

    #[test]
    fn title_extracted_from_simple_html() {
        let html = "<html><head><title>Hello World</title></head></html>";
        assert_eq!(extract_title(html), Some("Hello World".into()));
    }

    #[test]
    fn title_handles_uppercase_tags() {
        let html = "<HTML><HEAD><TITLE>Hi</TITLE></HEAD></HTML>";
        assert_eq!(extract_title(html), Some("Hi".into()));
    }

    #[test]
    fn title_handles_mixed_case_tags() {
        let html = "<Title>Mixed</TITLE>";
        assert_eq!(extract_title(html), Some("Mixed".into()));
    }

    #[test]
    fn title_trims_whitespace() {
        let html = "<title>  spaces  </title>";
        assert_eq!(extract_title(html), Some("spaces".into()));
    }

    #[test]
    fn title_returns_none_when_absent() {
        let html = "<html><body>No title here</body></html>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn title_returns_none_for_empty_tag() {
        let html = "<title></title>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn title_with_attributes_on_tag() {
        let html = r#"<title lang="en">Page</title>"#;
        assert_eq!(extract_title(html), Some("Page".into()));
    }

    // ── decode_html_entities ──────────────────────────────────────────────────

    #[test]
    fn entity_decodes_named() {
        assert_eq!(decode_html_entities("A &amp; B"), "A & B");
        assert_eq!(decode_html_entities("&lt;div&gt;"), "<div>");
        assert_eq!(decode_html_entities("&quot;x&quot;"), "\"x\"");
        assert_eq!(decode_html_entities("&nbsp;"), " ");
    }

    #[test]
    fn entity_decodes_numeric_decimal() {
        assert_eq!(decode_html_entities("&#65;"), "A");   // 'A'
        assert_eq!(decode_html_entities("&#169;"), "©"); // copyright
    }

    #[test]
    fn entity_title_roundtrip() {
        let html = "<title>Hello &amp; World &#8212; Test</title>";
        assert_eq!(extract_title(html), Some("Hello & World — Test".into()));
    }

    // ── extract_security_headers ──────────────────────────────────────────────

    #[test]
    fn security_headers_extracted() {
        let h = make_headers(&[
            ("strict-transport-security", "max-age=31536000; includeSubDomains"),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
        ]);
        let sh = extract_security_headers(&h);
        assert_eq!(sh.hsts.as_deref(), Some("max-age=31536000; includeSubDomains"));
        assert_eq!(sh.x_frame_options.as_deref(), Some("DENY"));
        assert_eq!(sh.x_content_type_options.as_deref(), Some("nosniff"));
    }

    #[test]
    fn missing_security_headers_are_none() {
        let h = make_headers(&[]);
        let sh = extract_security_headers(&h);
        assert!(sh.hsts.is_none());
        assert!(sh.content_security_policy.is_none());
        assert!(sh.x_frame_options.is_none());
        assert!(sh.referrer_policy.is_none());
        assert!(sh.permissions_policy.is_none());
    }

    // ── extract_technology_hints ──────────────────────────────────────────────

    #[test]
    fn tech_hints_server_header() {
        let h = make_headers(&[("server", "nginx/1.24.0")]);
        let hints = extract_technology_hints(&h);
        assert!(hints.iter().any(|s| s == "Server: nginx/1.24.0"));
    }

    #[test]
    fn tech_hints_powered_by() {
        let h = make_headers(&[("x-powered-by", "PHP/8.2.1")]);
        let hints = extract_technology_hints(&h);
        assert!(hints.iter().any(|s| s == "Powered-By: PHP/8.2.1"));
    }

    #[test]
    fn tech_hints_php_from_phpsessid_cookie() {
        let h = make_headers(&[("set-cookie", "PHPSESSID=abc123; path=/")]);
        let hints = extract_technology_hints(&h);
        assert!(hints.iter().any(|s| s == "Runtime: PHP"));
    }

    #[test]
    fn tech_hints_java_from_jsessionid_cookie() {
        let h = make_headers(&[("set-cookie", "JSESSIONID=xyz; path=/; HttpOnly")]);
        let hints = extract_technology_hints(&h);
        assert!(hints.iter().any(|s| s == "Runtime: Java/Tomcat"));
    }

    #[test]
    fn tech_hints_no_duplicates() {
        // Two Set-Cookie lines both hinting PHP
        let mut h = HeaderMap::new();
        h.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=1; path=/"),
        );
        h.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=2; path=/admin"),
        );
        let hints = extract_technology_hints(&h);
        assert_eq!(hints.iter().filter(|s| *s == "Runtime: PHP").count(), 1);
    }

    #[test]
    fn tech_hints_empty_for_no_revealing_headers() {
        let h = make_headers(&[("content-length", "1234")]);
        let hints = extract_technology_hints(&h);
        assert!(hints.is_empty());
    }
}
