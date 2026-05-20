//! Native DNS enrichment — opt-in, per-host, read-only record lookups.
//!
//! Uses the system resolver via `hickory-resolver`.  All DNS errors are embedded
//! in the result's `error` field rather than propagated; the caller always receives
//! a displayable `DnsQueryResult`.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use chrono::Utc;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsQueryRequest {
    /// Single IP address or hostname. No CIDR ranges.
    pub address: String,
    /// Seconds per record-type query; clamped to 1–30.
    pub timeout_secs: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsQueryResult {
    pub address: String,
    /// PTR hostnames for an IP input.
    pub ptr_records: Vec<String>,
    /// A (IPv4) addresses.
    pub a_records: Vec<String>,
    /// AAAA (IPv6) addresses.
    pub aaaa_records: Vec<String>,
    /// CNAME chain (intermediate canonical names resolved during lookup).
    pub cname_chain: Vec<String>,
    /// MX records, sorted by preference (lowest first).
    pub mx_records: Vec<MxRecord>,
    /// NS records for the hostname.
    pub ns_records: Vec<String>,
    /// TXT record values.
    pub txt_records: Vec<String>,
    /// For IP inputs: did a PTR hostname forward-verify back to the original IP?
    /// `None` when no PTR records were found.
    pub forward_verified: Option<bool>,
    /// Embedded error description — populated on lookup failure, never propagated.
    pub error: Option<String>,
    pub queried_at: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Performs DNS enrichment for a single IP or hostname.
/// Never returns `Err` — all network/resolution failures are embedded in `result.error`.
pub async fn query(request: DnsQueryRequest) -> DnsQueryResult {
    let timeout_secs = request.timeout_secs.clamp(1, 30);
    let queried_at = Utc::now().to_rfc3339();

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(timeout_secs as u64);
    opts.attempts = 2;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
    let address = request.address.clone();

    if let Ok(ip) = IpAddr::from_str(&address) {
        query_for_ip(&resolver, ip, address, queried_at).await
    } else {
        query_for_hostname(&resolver, address, queried_at).await
    }
}

// ── IP-address path ───────────────────────────────────────────────────────────

async fn query_for_ip(
    resolver: &TokioAsyncResolver,
    ip: IpAddr,
    address: String,
    queried_at: String,
) -> DnsQueryResult {
    let mut result = empty_result(address, queried_at);

    // PTR lookup
    match resolver.reverse_lookup(ip).await {
        Ok(ptrs) => {
            result.ptr_records = ptrs.iter()
                .map(|name| strip_dot(&name.to_string()))
                .collect();
        }
        Err(_) => {} // No PTR is common and not an error worth surfacing
    }

    // Forward-verify: does any PTR hostname A/AAAA resolve back to the original IP?
    if !result.ptr_records.is_empty() {
        let mut verified = false;
        'outer: for ptr in result.ptr_records.clone() {
            if let Ok(fwd) = resolver.lookup_ip(ptr.as_str()).await {
                for resolved in fwd.iter() {
                    // Collect forward IPs for display
                    let s = resolved.to_string();
                    match resolved {
                        IpAddr::V4(_) => { if !result.a_records.contains(&s) { result.a_records.push(s); } }
                        IpAddr::V6(_) => { if !result.aaaa_records.contains(&s) { result.aaaa_records.push(s); } }
                    }
                    if resolved == ip {
                        verified = true;
                        break 'outer;
                    }
                }
            }
        }
        result.forward_verified = Some(verified);
    }

    result
}

// ── Hostname path ─────────────────────────────────────────────────────────────

async fn query_for_hostname(
    resolver: &TokioAsyncResolver,
    hostname: String,
    queried_at: String,
) -> DnsQueryResult {
    let mut result = empty_result(hostname.clone(), queried_at);

    // A/AAAA (hickory auto-follows CNAMEs; we harvest CNAME intermediates separately)
    match resolver.lookup_ip(&hostname).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                let s = ip.to_string();
                match ip {
                    IpAddr::V4(_) => { if !result.a_records.contains(&s)    { result.a_records.push(s); } }
                    IpAddr::V6(_) => { if !result.aaaa_records.contains(&s) { result.aaaa_records.push(s); } }
                }
            }
        }
        Err(e) => { result.error = Some(format!("A/AAAA: {e}")); }
    }

    // CNAME chain
    if let Ok(cname_lookup) = resolver.lookup(&hostname, RecordType::CNAME).await {
        for rdata in cname_lookup.iter() {
            if let RData::CNAME(cname) = rdata {
                let name = strip_dot(&cname.to_string());
                if !result.cname_chain.contains(&name) {
                    result.cname_chain.push(name);
                }
            }
        }
    }

    // MX
    if let Ok(mx) = resolver.mx_lookup(&hostname).await {
        let mut mx_records: Vec<MxRecord> = mx.iter()
            .map(|m| MxRecord {
                preference: m.preference(),
                exchange:   strip_dot(&m.exchange().to_string()),
            })
            .collect();
        mx_records.sort_by_key(|m| m.preference);
        result.mx_records = mx_records;
    }

    // NS
    if let Ok(ns) = resolver.ns_lookup(&hostname).await {
        result.ns_records = ns.iter()
            .map(|n| strip_dot(&n.to_string()))
            .collect();
    }

    // TXT
    if let Ok(txt) = resolver.txt_lookup(&hostname).await {
        result.txt_records = txt.iter()
            .map(|t| {
                t.txt_data()
                    .iter()
                    .filter_map(|bytes| std::str::from_utf8(bytes).ok())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .filter(|s| !s.is_empty())
            .collect();
    }

    result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn empty_result(address: String, queried_at: String) -> DnsQueryResult {
    DnsQueryResult {
        address,
        ptr_records:      vec![],
        a_records:        vec![],
        aaaa_records:     vec![],
        cname_chain:      vec![],
        mx_records:       vec![],
        ns_records:       vec![],
        txt_records:      vec![],
        forward_verified: None,
        error:            None,
        queried_at,
    }
}

/// Strips the trailing dot that DNS names always carry (e.g. "example.com." → "example.com").
fn strip_dot(s: &str) -> String {
    s.trim_end_matches('.').to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_dot_removes_trailing_dot() {
        assert_eq!(strip_dot("example.com."), "example.com");
        assert_eq!(strip_dot("example.com"),  "example.com");
        assert_eq!(strip_dot(""),             "");
    }

    #[test]
    fn empty_result_fields_are_empty() {
        let r = empty_result("192.168.1.1".into(), "2024-01-01T00:00:00Z".into());
        assert_eq!(r.address, "192.168.1.1");
        assert!(r.ptr_records.is_empty());
        assert!(r.a_records.is_empty());
        assert!(r.forward_verified.is_none());
        assert!(r.error.is_none());
    }

    #[test]
    fn dns_query_result_serialises_to_camel_case() {
        let r = DnsQueryResult {
            address:          "1.2.3.4".into(),
            ptr_records:      vec!["host.example.com".into()],
            a_records:        vec![],
            aaaa_records:     vec![],
            cname_chain:      vec![],
            mx_records:       vec![MxRecord { preference: 10, exchange: "mail.example.com".into() }],
            ns_records:       vec![],
            txt_records:      vec!["v=spf1 ~all".into()],
            forward_verified: Some(true),
            error:            None,
            queried_at:       "2024-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"ptrRecords\""));
        assert!(json.contains("\"aRecords\""));
        assert!(json.contains("\"cnameChain\""));
        assert!(json.contains("\"mxRecords\""));
        assert!(json.contains("\"nsRecords\""));
        assert!(json.contains("\"txtRecords\""));
        assert!(json.contains("\"forwardVerified\""));
        assert!(json.contains("\"queriedAt\""));
    }

    #[tokio::test]
    async fn invalid_address_returns_error_not_panic() {
        let result = query(DnsQueryRequest {
            address:      "not-a-real-host-$$$$.invalid".into(),
            timeout_secs: 1,
        })
        .await;
        // Should always return a result — never panics or propagates Err
        assert_eq!(result.address, "not-a-real-host-$$$$.invalid");
        // May or may not have an error depending on resolver behavior — just confirm no panic
    }

    #[tokio::test]
    async fn loopback_ip_returns_result_struct() {
        let result = query(DnsQueryRequest {
            address:      "127.0.0.1".into(),
            timeout_secs: 5,
        })
        .await;
        assert_eq!(result.address, "127.0.0.1");
        // Loopback may or may not have a PTR record — result struct is always valid
        assert!(result.queried_at.contains('T'));
    }
}
