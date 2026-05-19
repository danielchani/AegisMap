import { hostRiskLevel, RISK_LABEL } from "../lib/riskScore";
import { getAdvisory, SEVERITY_COLOR } from "../data/cveHints";
import { lookupCVEs, hostCVESummary } from "../data/cveDatabase";
import { calculateConfidence } from "../lib/fingerprint";
import type { HostResult, PentestFinding, ScanReport } from "../types";
import { CONFIDENCE_LABEL, FINDING_STATUS_LABEL } from "../types";

interface Props {
  report: ScanReport;
  sessionHosts: HostResult[];
  findings?: PentestFinding[];
}

const RISK_ORDER = ["critical", "high", "medium", "low", "clean"] as const;

const SEV_COLOR: Record<string, string> = { info: "#6b7280", low: "#4ade80", medium: "#fb923c", high: "#f87171", critical: "#e11d48" };
const SEV_ORDER = ["critical","high","medium","low","info"] as const;

export function PrintReport({ report, sessionHosts, findings = [] }: Props) {
  const now  = new Date().toLocaleString();
  const total = sessionHosts.reduce((s, h) => s + h.ports.filter((p) => p.state === "open").length, 0);
  const riskCounts = Object.fromEntries(RISK_ORDER.map((r) => [r, 0])) as Record<string, number>;
  sessionHosts.forEach((h) => { riskCounts[hostRiskLevel(h)]++; });

  // Weighted score
  const score = Math.min(100, Math.round(
    (riskCounts.critical * 20 + riskCounts.high * 10 + riskCounts.medium * 5 + riskCounts.low * 2) /
    Math.max(sessionHosts.length, 1) * 10
  ));

  return (
    <div className="print-only" style={{ display: "none" }}>
      <style>{`
        @media print {
          .print-only { display: block !important; }
          .no-print   { display: none  !important; }
          body { background: white !important; color: #111 !important; font-family: 'Segoe UI', system-ui, sans-serif; font-size: 11px; }
          .pr-section { page-break-inside: avoid; margin-bottom: 20px; }
          .pr-table { width: 100%; border-collapse: collapse; font-size: 10px; margin-top: 6px; }
          .pr-table th, .pr-table td { border: 1px solid #ddd; padding: 5px 8px; text-align: left; }
          .pr-table th { background: #f0f0f0; font-weight: 600; font-size: 9px; text-transform: uppercase; letter-spacing: 0.05em; }
          .pr-risk-high     { color: #c00; }
          .pr-risk-medium   { color: #b60; }
          .pr-risk-low      { color: #660; }
          .pr-risk-clean    { color: #080; }
          .pr-risk-critical { color: #900; font-weight: bold; }
          .pr-badge { display: inline-block; padding: 1px 6px; border: 1px solid; font-size: 9px; font-weight: 600; letter-spacing: 0.05em; }
          .pr-cve { background: #fff0f0; border: 1px solid #fcc; padding: 4px 8px; margin: 3px 0; font-size: 10px; }
          .pr-header { border-bottom: 3px solid #111; padding-bottom: 12px; margin-bottom: 20px; }
          .pr-metric { display: inline-block; text-align: center; padding: 8px 16px; border: 1px solid #ddd; margin-right: 8px; }
          .pr-metric-value { font-size: 20px; font-weight: 700; }
          .pr-metric-label { font-size: 8px; text-transform: uppercase; letter-spacing: 0.1em; color: #666; }
          .pr-host-card { border: 1px solid #ccc; padding: 12px; margin-bottom: 12px; page-break-inside: avoid; }
          .pr-host-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
          .pr-risk-bar { display: flex; height: 6px; margin-top: 8px; }
          .pr-risk-bar > div { min-width: 4px; }
          h1 { font-size: 20px; margin: 0 0 4px; }
          h2 { font-size: 14px; margin: 0 0 8px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
          h3 { font-size: 12px; margin: 0 0 4px; }
        }
      `}</style>

      {/* Header */}
      <div className="pr-header">
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div>
            <h1>AegisMap Reconnaissance Report</h1>
            <p style={{ color: "#666", margin: "2px 0", fontSize: "10px" }}>
              Generated: {now} · Target: {report.target} · Profile: {report.profile}
            </p>
          </div>
          <div style={{ marginLeft: "auto", textAlign: "right" }}>
            <div style={{ fontSize: "24px", fontWeight: 700, color: score > 50 ? "#c00" : score > 20 ? "#b60" : "#080" }}>
              {score}/100
            </div>
            <div style={{ fontSize: "8px", letterSpacing: "0.1em", color: "#666" }}>RISK SCORE</div>
          </div>
        </div>
      </div>

      {/* Executive summary */}
      <div className="pr-section">
        <h2>Executive Summary</h2>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" }}>
          {[
            { label: "HOSTS", value: String(sessionHosts.length) },
            { label: "OPEN PORTS", value: String(total) },
            { label: "CRITICAL", value: String(riskCounts.critical) },
            { label: "HIGH RISK", value: String(riskCounts.high) },
            { label: "MEDIUM", value: String(riskCounts.medium) },
          ].map(({ label, value }) => (
            <div key={label} className="pr-metric">
              <div className="pr-metric-value">{value}</div>
              <div className="pr-metric-label">{label}</div>
            </div>
          ))}
        </div>
        {/* Risk distribution bar */}
        <div className="pr-risk-bar">
          {RISK_ORDER.map((r) => {
            const count = riskCounts[r] ?? 0;
            if (count === 0) return null;
            const colors: Record<string, string> = { critical: "#e11d48", high: "#f87171", medium: "#fb923c", low: "#a3e635", clean: "#4ade80" };
            return <div key={r} style={{ flex: count, background: colors[r] }} />;
          })}
        </div>
        <div style={{ fontSize: "9px", color: "#666", marginTop: "4px" }}>
          {RISK_ORDER.map((r) => riskCounts[r] > 0 ? `${r.toUpperCase()}: ${riskCounts[r]}` : null).filter(Boolean).join(" · ")}
        </div>
      </div>

      {/* Per-host findings */}
      {sessionHosts.map((host) => {
        const open = host.ports.filter((p) => p.state === "open");
        const risk = hostRiskLevel(host);
        const cveSummary = hostCVESummary(host.ports);
        const confidence = calculateConfidence(host);
        const riskColors: Record<string, string> = { critical: "#e11d48", high: "#f87171", medium: "#fb923c", low: "#a3e635", clean: "#4ade80" };

        return (
          <div key={host.address} className="pr-host-card">
            <div className="pr-host-header">
              <h3 style={{ margin: 0, flex: 1 }}>
                {host.address}{host.hostname ? ` (${host.hostname})` : ""}
              </h3>
              <span className="pr-badge" style={{ borderColor: riskColors[risk], color: riskColors[risk] }}>
                {RISK_LABEL[risk]}
              </span>
              <span style={{ fontSize: "9px", color: "#666" }}>
                Confidence: {confidence.overall}%
              </span>
            </div>

            <p style={{ fontSize: "10px", color: "#555", margin: "0 0 6px" }}>
              Status: <strong>{host.status}</strong> · {open.length} open port{open.length !== 1 ? "s" : ""}
              {host.workflowStatus ? ` · Workflow: ${host.workflowStatus.toUpperCase()}` : ""}
              {host.scannedAt ? ` · Last scan: ${new Date(host.scannedAt).toLocaleString()}` : ""}
            </p>

            {host.tags && host.tags.length > 0 && (
              <p style={{ fontSize: "9px", margin: "0 0 4px" }}>
                Tags: {host.tags.join(", ")}
              </p>
            )}

            {host.notes && (
              <p style={{ fontSize: "10px", margin: "4px 0", fontStyle: "italic", color: "#444" }}>
                {host.notes}
              </p>
            )}

            {/* CVE summary */}
            {cveSummary.total > 0 && (
              <div style={{ margin: "6px 0", padding: "6px 8px", background: "#fff5f5", border: "1px solid #fcc" }}>
                <strong style={{ fontSize: "10px" }}>Known CVEs: {cveSummary.total}</strong>
                <span style={{ fontSize: "9px", marginLeft: "8px", color: "#666" }}>
                  ({cveSummary.critical > 0 ? `${cveSummary.critical} critical, ` : ""}
                  {cveSummary.high > 0 ? `${cveSummary.high} high, ` : ""}
                  {cveSummary.medium > 0 ? `${cveSummary.medium} medium` : ""})
                </span>
                {cveSummary.topCVE && (
                  <div style={{ fontSize: "9px", marginTop: "3px", color: "#900" }}>
                    Top: {cveSummary.topCVE.id} (CVSS {cveSummary.topCVE.cvss}) — {cveSummary.topCVE.summary}
                  </div>
                )}
              </div>
            )}

            {/* Open ports table */}
            {open.length > 0 && (
              <table className="pr-table">
                <thead>
                  <tr>
                    <th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th><th>Advisory</th><th>CVEs</th>
                  </tr>
                </thead>
                <tbody>
                  {open.map((p) => {
                    const adv = getAdvisory(p.port, p.service);
                    const cves = lookupCVEs(p.product, p.version);
                    return (
                      <tr key={`${p.port}/${p.protocol}`}>
                        <td style={{ fontFamily: "monospace" }}>{p.port}</td>
                        <td>{p.protocol}</td>
                        <td>{p.service || "—"}</td>
                        <td>{p.product ?? "—"}</td>
                        <td>{p.version ?? "—"}</td>
                        <td style={{ color: adv ? SEVERITY_COLOR[adv.severity] : undefined, fontSize: "9px" }}>
                          {adv ? `⚠ ${adv.label}: ${adv.detail}` : "—"}
                        </td>
                        <td style={{ fontSize: "9px" }}>
                          {cves.length > 0
                            ? cves.slice(0, 2).map((c) => `${c.id} (${c.cvss})`).join(", ")
                            : "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {/* Script results */}
            {(host.script_results?.length ?? 0) > 0 && (
              <div style={{ marginTop: "6px" }}>
                <strong style={{ fontSize: "10px" }}>Script Results:</strong>
                {host.script_results!.map((s, i) => (
                  <p key={i} style={{ marginLeft: "12px", fontSize: "10px", margin: "2px 0 2px 12px" }}>
                    <strong>{s.id}:</strong> {s.output.slice(0, 200)}{s.output.length > 200 ? "…" : ""}
                  </p>
                ))}
              </div>
            )}

            {/* Per-port notes */}
            {host.portNotes && Object.keys(host.portNotes).length > 0 && (
              <div style={{ marginTop: "6px" }}>
                <strong style={{ fontSize: "10px" }}>Port Notes:</strong>
                {Object.entries(host.portNotes).map(([key, note]) => (
                  <p key={key} style={{ fontSize: "10px", margin: "2px 0 2px 12px" }}>
                    <strong>{key}:</strong> {note}
                  </p>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {/* Findings section — confirmed + needs_review only */}
      {(() => {
        const reportFindings = findings
          .filter(f => f.status === "confirmed" || f.status === "needs_review")
          .sort((a, b) => SEV_ORDER.indexOf(a.severity as typeof SEV_ORDER[number]) - SEV_ORDER.indexOf(b.severity as typeof SEV_ORDER[number]));
        if (reportFindings.length === 0) return null;
        const confirmedCount = reportFindings.filter(f => f.status === "confirmed").length;
        return (
          <>
            <div style={{ marginTop: "20px", marginBottom: "12px", borderBottom: "2px solid #333" }}>
              <h2 style={{ fontSize: "13px", fontWeight: 700, margin: "0 0 4px", letterSpacing: "0.08em" }}>FINDINGS</h2>
              <p style={{ fontSize: "10px", color: "#666", margin: 0 }}>
                {reportFindings.length} finding{reportFindings.length !== 1 ? "s" : ""} ({confirmedCount} confirmed) — draft findings excluded
              </p>
            </div>
            {reportFindings.map((f, i) => (
              <div key={f.id} style={{ marginBottom: "16px", paddingBottom: "12px", borderBottom: i < reportFindings.length - 1 ? "1px solid #eee" : "none" }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: "8px", marginBottom: "4px" }}>
                  <span style={{ fontSize: "8px", padding: "1px 6px", color: SEV_COLOR[f.severity] ?? "#666", border: `1px solid ${SEV_COLOR[f.severity] ?? "#666"}`, letterSpacing: "0.1em", textTransform: "uppercase" as const, fontWeight: 700 }}>{f.severity}</span>
                  <span style={{ fontSize: "8px", color: "#999" }}>{CONFIDENCE_LABEL[f.confidence]}</span>
                  <span style={{ fontSize: "8px", color: "#999" }}>{FINDING_STATUS_LABEL[f.status]}</span>
                  <h3 style={{ fontSize: "11px", fontWeight: 600, margin: 0 }}>{f.title}</h3>
                </div>
                {(f.affectedHosts.length > 0 || f.affectedPorts?.length) && (
                  <p style={{ fontSize: "9px", color: "#666", margin: "2px 0" }}>
                    {f.affectedHosts.join(", ")}{f.affectedPorts?.length ? ` · ${f.affectedPorts.join(", ")}` : ""}
                  </p>
                )}
                <p style={{ fontSize: "10px", margin: "4px 0", lineHeight: 1.5 }}>{f.summary}</p>
                {f.remediation && (
                  <p style={{ fontSize: "10px", margin: "4px 0", color: "#444" }}><strong>Remediation:</strong> {f.remediation}</p>
                )}
                {f.references?.length ? (
                  <p style={{ fontSize: "9px", color: "#888", margin: "2px 0" }}>Ref: {f.references.join(", ")}</p>
                ) : null}
              </div>
            ))}
          </>
        );
      })()}

      {/* Footer */}
      <div style={{ marginTop: "24px", borderTop: "1px solid #ddd", paddingTop: "8px", fontSize: "9px", color: "#999" }}>
        AegisMap v0.1.0 · Report generated {now} · {sessionHosts.length} hosts · {total} open ports · Risk score: {score}/100
        {findings.length > 0 && ` · ${findings.filter(f => f.status === "confirmed").length} confirmed finding(s)`}
      </div>
    </div>
  );
}
