use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

// ── Request / response models ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsProbeRequest {
    pub address: String,
    pub port: u16,
    /// Request timeout in seconds (1–30). Applied to both TCP connect and TLS handshake.
    pub timeout_secs: u8,
    /// Accept self-signed / expired certificates — on by default for pentest use.
    pub accept_invalid_certs: bool,
    /// Optional hostname to use as the TLS SNI (Server Name Indication) value.
    /// When probing an IP address, set this to the known hostname so the server
    /// presents the correct certificate for the vhost. The TCP connection still
    /// goes to `address`; only the TLS ClientHello server_name extension changes.
    #[serde(default)]
    pub sni_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsProbeResult {
    pub address: String,
    pub port: u16,
    /// Negotiated TLS version, e.g. "TLS 1.3".
    pub tls_version: Option<String>,
    /// Negotiated cipher suite name, e.g. "TLS13_AES_256_GCM_SHA384".
    pub cipher_suite: Option<String>,
    /// True for known-weak cipher suites (RC4, DES, 3DES, EXPORT, NULL, ANON).
    pub cipher_is_weak: bool,
    /// Certificate chain — leaf certificate first. May be empty on error.
    pub certificate_chain: Vec<CertInfo>,
    pub connection_time_ms: u64,
    /// Network / TLS error — present when the probe ran but failed.
    pub error: Option<String>,
    pub probed_at: String, // ISO-8601
}

/// Parsed fields from a single X.509 certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    /// Subject Alternative Name DNS entries and IP addresses.
    pub subject_san: Vec<String>,
    pub issuer: Option<String>,
    pub not_before: String,  // ISO-8601
    pub not_after: String,   // ISO-8601
    /// Days remaining until certificate expiry; negative means already expired.
    pub days_until_expiry: Option<i64>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub serial: Option<String>, // colon-separated hex bytes
}

// ── Custom TLS certificate verifier ──────────────────────────────────────────
// Accepts any certificate (pentest default) and captures the chain for parsing.

#[derive(Debug)]
struct CapturingVerifier {
    certs: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut certs = self.certs.lock().unwrap();
        certs.push(end_entity.to_vec());
        for cert in intermediates {
            certs.push(cert.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Performs a raw TLS handshake to `req.address:req.port`.
///
/// The full certificate chain is captured via a custom verifier that always
/// accepts the connection (pentest mode), then each certificate is parsed with
/// x509-parser. TLS version and cipher suite are extracted from the session.
///
/// Network / TLS errors are embedded in `result.error` rather than returned
/// as `Err` so that callers always receive a displayable result.
pub async fn probe(req: TlsProbeRequest) -> TlsProbeResult {
    let addr = format!("{}:{}", req.address, req.port);
    let probed_at = Utc::now().to_rfc3339();
    let timeout_dur = Duration::from_secs(req.timeout_secs as u64);

    // Build the TLS server name (SNI).
    // Prefer sni_override (e.g. the known hostname from Nmap) over the raw address so
    // that virtual-hosted TLS servers present the correct certificate.
    // The TCP connection always goes to `address`; only the TLS ClientHello SNI changes.
    let sni_source = req.sni_override.as_deref().unwrap_or(req.address.as_str());
    let server_name: ServerName<'static> = if req.sni_override.is_none() {
        // No override — fall back to address, which may be an IP.
        if let Ok(ip) = req.address.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            match ServerName::try_from(req.address.as_str()) {
                Ok(sn) => sn.to_owned(),
                Err(e) => {
                    return error_result(&req.address, req.port, &probed_at,
                        format!("invalid server name: {e}"));
                }
            }
        }
    } else {
        // Use the provided hostname as SNI — must be a DNS name, not an IP.
        match ServerName::try_from(sni_source) {
            Ok(sn) => sn.to_owned(),
            Err(e) => {
                return error_result(&req.address, req.port, &probed_at,
                    format!("invalid SNI hostname: {e}"));
            }
        }
    };

    // TCP connect with timeout.
    let tcp = match tokio::time::timeout(
        timeout_dur,
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return error_result(&req.address, req.port, &probed_at, e.to_string()),
        Err(_) => return error_result(&req.address, req.port, &probed_at,
            "TCP connection timed out".into()),
    };

    let start = Instant::now();

    // Build TLS config with the cert-capturing custom verifier.
    let cert_store: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(CapturingVerifier { certs: Arc::clone(&cert_store) });

    let config = match ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    {
        Ok(b) => b
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
        Err(e) => {
            return error_result(&req.address, req.port, &probed_at,
                format!("TLS config error: {e}"));
        }
    };

    let connector = TlsConnector::from(Arc::new(config));

    // TLS handshake with timeout.
    let tls_stream = match tokio::time::timeout(
        timeout_dur,
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return error_result(&req.address, req.port, &probed_at, e.to_string()),
        Err(_) => return error_result(&req.address, req.port, &probed_at,
            "TLS handshake timed out".into()),
    };

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Extract TLS session metadata before consuming the stream.
    let (_, conn) = tls_stream.get_ref();

    let tls_version = conn.protocol_version().map(|v| {
        use rustls::ProtocolVersion;
        match v {
            ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
            ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
            ProtocolVersion::TLSv1_1 => "TLS 1.1 (deprecated)".to_string(),
            ProtocolVersion::TLSv1_0 => "TLS 1.0 (deprecated)".to_string(),
            other => format!("{:?}", other),
        }
    });

    let cipher_suite = conn.negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));
    let cipher_is_weak = cipher_suite.as_deref().map(is_weak_cipher).unwrap_or(false);

    // Release the stream (closes the TCP connection).
    drop(tls_stream);

    // Parse the captured certificate chain.
    let raw_certs = cert_store.lock().unwrap().clone();
    let certificate_chain = raw_certs.iter().filter_map(|der| parse_cert(der)).collect();

    TlsProbeResult {
        address: req.address,
        port: req.port,
        tls_version,
        cipher_suite,
        cipher_is_weak,
        certificate_chain,
        connection_time_ms: elapsed_ms,
        error: None,
        probed_at,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn error_result(address: &str, port: u16, probed_at: &str, message: String) -> TlsProbeResult {
    TlsProbeResult {
        address: address.to_string(),
        port,
        tls_version: None,
        cipher_suite: None,
        cipher_is_weak: false,
        certificate_chain: Vec::new(),
        connection_time_ms: 0,
        error: Some(message),
        probed_at: probed_at.to_string(),
    }
}

/// Returns true for known-weak cipher names (checked case-insensitively).
pub fn is_weak_cipher(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ["_RC4_", "_DES_", "_3DES_", "EXPORT", "_NULL_", "_ANON_", "_MD5_"]
        .iter()
        .any(|weak| upper.contains(weak))
}

/// Parses a single DER-encoded X.509 certificate.
/// Returns `None` if parsing fails rather than propagating errors.
fn parse_cert(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(String::from);

    let issuer = Some(cert.issuer().to_string());

    // Subject Alternative Names
    let mut subject_san: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(name) => subject_san.push((*name).to_string()),
                    GeneralName::IPAddress(bytes) => {
                        if bytes.len() == 4 {
                            subject_san.push(format!(
                                "{}.{}.{}.{}",
                                bytes[0], bytes[1], bytes[2], bytes[3]
                            ));
                        } else if bytes.len() == 16 {
                            let groups: Vec<String> = bytes
                                .chunks(2)
                                .map(|g| format!("{:02x}{:02x}", g[0], g[1]))
                                .collect();
                            subject_san.push(groups.join(":"));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Validity dates via Unix timestamps to avoid direct time crate dependency.
    let not_before_secs = cert.validity().not_before.timestamp();
    let not_after_secs  = cert.validity().not_after.timestamp();
    let now_secs = Utc::now().timestamp();

    let not_before = chrono::DateTime::from_timestamp(not_before_secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "unknown".to_string());
    let not_after = chrono::DateTime::from_timestamp(not_after_secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "unknown".to_string());

    let days_until_expiry = Some((not_after_secs - now_secs) / 86400);
    let is_expired = not_after_secs < now_secs;

    // Self-signed: issuer DN == subject DN
    let is_self_signed = cert.issuer() == cert.subject();

    let serial = {
        let bytes = cert.raw_serial();
        if bytes.is_empty() {
            None
        } else {
            Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
        }
    };

    Some(CertInfo {
        subject_cn,
        subject_san,
        issuer,
        not_before,
        not_after,
        days_until_expiry,
        is_self_signed,
        is_expired,
        serial,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cipher weakness classification ────────────────────────────────────────

    #[test]
    fn weak_rc4_detected() {
        assert!(is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA"));
    }

    #[test]
    fn weak_des_detected() {
        assert!(is_weak_cipher("TLS_RSA_WITH_DES_CBC_SHA"));
    }

    #[test]
    fn weak_3des_detected() {
        assert!(is_weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
    }

    #[test]
    fn weak_null_detected() {
        assert!(is_weak_cipher("TLS_RSA_WITH_NULL_SHA"));
    }

    #[test]
    fn weak_export_detected() {
        assert!(is_weak_cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5"));
    }

    #[test]
    fn modern_aes_gcm_not_weak() {
        assert!(!is_weak_cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    }

    #[test]
    fn tls13_aes_not_weak() {
        assert!(!is_weak_cipher("TLS13_AES_256_GCM_SHA384"));
    }

    // ── Error result structure ────────────────────────────────────────────────

    #[test]
    fn error_result_has_empty_cert_chain() {
        let r = error_result("10.0.0.1", 443, "2026-01-01T00:00:00Z", "refused".into());
        assert!(r.certificate_chain.is_empty());
        assert!(r.error.is_some());
        assert!(!r.cipher_is_weak);
    }

    // ── Certificate parsing ───────────────────────────────────────────────────

    fn make_self_signed_cert(cn: &str, san_dns: &[&str]) -> Vec<u8> {
        use rcgen::{CertificateParams, DnType, KeyPair, SanType};
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.subject_alt_names = san_dns
            .iter()
            .map(|s| SanType::DnsName((*s).try_into().unwrap()))
            .collect();
        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    #[test]
    fn cert_parsed_from_der() {
        let der = make_self_signed_cert("test.example.com", &["test.example.com"]);
        let info = parse_cert(&der).expect("cert should parse");
        assert_eq!(info.subject_cn.as_deref(), Some("test.example.com"));
    }

    #[test]
    fn self_signed_detected() {
        let der = make_self_signed_cert("self.example.com", &[]);
        let info = parse_cert(&der).unwrap();
        assert!(info.is_self_signed);
    }

    #[test]
    fn san_dns_extracted() {
        let der = make_self_signed_cert("host.example.com", &["host.example.com", "alt.example.com"]);
        let info = parse_cert(&der).unwrap();
        assert!(info.subject_san.contains(&"host.example.com".to_string()));
        assert!(info.subject_san.contains(&"alt.example.com".to_string()));
    }

    #[test]
    fn fresh_cert_not_expired() {
        let der = make_self_signed_cert("fresh.example.com", &[]);
        let info = parse_cert(&der).unwrap();
        assert!(!info.is_expired);
        assert!(info.days_until_expiry.unwrap_or(-1) > 0);
    }

    #[test]
    fn serial_number_present() {
        let der = make_self_signed_cert("serial.example.com", &[]);
        let info = parse_cert(&der).unwrap();
        assert!(info.serial.is_some());
        assert!(!info.serial.unwrap().is_empty());
    }

    #[test]
    fn invalid_der_returns_none() {
        let result = parse_cert(b"not a valid certificate at all");
        assert!(result.is_none());
    }
}
