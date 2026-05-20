use crate::error::AppError;
use crate::models::{HostResult, PortEntry, ScanProfile, ScanReport, ScriptResult};

pub fn parse_xml(xml: &str, target: &str, profile: &ScanProfile) -> Result<ScanReport, AppError> {
    let opts = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(xml, opts)
        .map_err(|e| AppError::ScanFailed(format!("XML parse error: {}", e)))?;

    let root = doc.root_element(); // <nmaprun>

    let started_at = root.attribute("startstr").map(str::to_owned);

    let finished = root.descendants().find(|n| n.has_tag_name("finished"));

    let completed_at = finished
        .and_then(|n| n.attribute("timestr"))
        .map(str::to_owned);

    let elapsed_seconds = finished
        .and_then(|n| n.attribute("elapsed"))
        .and_then(|s| s.parse::<f64>().ok());

    let hosts = root
        .children()
        .filter(|n| n.has_tag_name("host"))
        .map(parse_host)
        .collect();

    Ok(ScanReport {
        target: target.to_owned(),
        profile: profile.clone(),
        started_at,
        completed_at,
        elapsed_seconds,
        hosts,
    })
}

fn parse_host(host: roxmltree::Node) -> HostResult {
    let status = host
        .children()
        .find(|n| n.has_tag_name("status"))
        .and_then(|n| n.attribute("state"))
        .unwrap_or("unknown")
        .to_owned();

    // Prefer IPv4; fall back to first address element
    let address = host
        .children()
        .filter(|n| n.has_tag_name("address"))
        .find(|n| n.attribute("addrtype") == Some("ipv4"))
        .or_else(|| host.children().find(|n| n.has_tag_name("address")))
        .and_then(|n| n.attribute("addr"))
        .unwrap_or("")
        .to_owned();

    let hostname = host
        .descendants()
        .find(|n| n.has_tag_name("hostname"))
        .and_then(|n| n.attribute("name"))
        .map(str::to_owned);

    let ports = host
        .descendants()
        .filter(|n| n.has_tag_name("port"))
        .map(parse_port)
        .collect();

    // Collect all <script> elements — both from <hostscript> and inside <port> elements
    let script_results: Vec<ScriptResult> = host
        .descendants()
        .filter(|n| n.has_tag_name("script"))
        .map(|n| ScriptResult {
            id:     n.attribute("id").unwrap_or("").to_owned(),
            output: n.attribute("output").unwrap_or("").to_owned(),
        })
        .collect();

    HostResult { address, hostname, status, ports, script_results }
}

fn parse_port(port: roxmltree::Node) -> PortEntry {
    let port_num = port
        .attribute("portid")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let protocol = port.attribute("protocol").unwrap_or("tcp").to_owned();

    let state = port
        .children()
        .find(|n| n.has_tag_name("state"))
        .and_then(|n| n.attribute("state"))
        .unwrap_or("unknown")
        .to_owned();

    let svc = port.children().find(|n| n.has_tag_name("service"));

    let service = svc.and_then(|n| n.attribute("name")).unwrap_or("").to_owned();
    let product = svc.and_then(|n| n.attribute("product")).map(str::to_owned);
    let version = svc.and_then(|n| n.attribute("version")).map(str::to_owned);

    PortEntry { port: port_num, protocol, state, service, product, version }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanProfile;

    const FIXTURE: &str = include_str!("fixtures/simple_scan.xml");

    fn report() -> ScanReport {
        parse_xml(FIXTURE, "127.0.0.1", &ScanProfile::QuickCommonPorts).unwrap()
    }

    #[test]
    fn parses_single_host() {
        assert_eq!(report().hosts.len(), 1);
    }

    #[test]
    fn parses_host_address() {
        assert_eq!(report().hosts[0].address, "127.0.0.1");
    }

    #[test]
    fn parses_hostname() {
        assert_eq!(report().hosts[0].hostname.as_deref(), Some("localhost"));
    }

    #[test]
    fn parses_host_status_up() {
        assert_eq!(report().hosts[0].status, "up");
    }

    #[test]
    fn parses_port_count() {
        assert_eq!(report().hosts[0].ports.len(), 3);
    }

    #[test]
    fn parses_open_port_with_service_details() {
        let ssh = report()
            .hosts[0]
            .ports
            .iter()
            .find(|p| p.port == 22)
            .unwrap()
            .clone();
        assert_eq!(ssh.protocol, "tcp");
        assert_eq!(ssh.state, "open");
        assert_eq!(ssh.service, "ssh");
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("8.9p1"));
    }

    #[test]
    fn parses_port_without_product() {
        let http = report()
            .hosts[0]
            .ports
            .iter()
            .find(|p| p.port == 80)
            .unwrap()
            .clone();
        assert_eq!(http.service, "http");
        assert!(http.product.is_none());
        assert!(http.version.is_none());
    }

    #[test]
    fn parses_closed_port() {
        let proxy = report()
            .hosts[0]
            .ports
            .iter()
            .find(|p| p.port == 8080)
            .unwrap()
            .clone();
        assert_eq!(proxy.state, "closed");
    }

    #[test]
    fn parses_scan_timing() {
        let r = report();
        assert!(r.started_at.is_some());
        assert!(r.completed_at.is_some());
        assert!((r.elapsed_seconds.unwrap() - 2.50).abs() < 0.001);
    }

    #[test]
    fn rejects_malformed_xml() {
        let result = parse_xml("<not valid xml>>>", "t", &ScanProfile::StandardTcp);
        assert!(result.is_err());
    }
}
