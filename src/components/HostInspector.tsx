import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getAdvisory, SEVERITY_COLOR } from "../data/cveHints";
import { getVersionAdvisory } from "../data/knownVersions";
import { formatScanAge, useNow } from "../hooks/useScanAge";
import { hostRiskLevel, RISK_COLOR, RISK_LABEL } from "../lib/riskScore";
import type {
  CertInfo, HostResult, HttpProbeRequest, HttpProbeResult,
  PortEntry, ScanProfile, SecurityHeaders, TlsProbeRequest,
  TlsProbeResult, WorkflowStatus,
} from "../types";

interface Props {
  host: HostResult;
  onRescan?: (address: string, profile?: ScanProfile) => void;
  isBusy?: boolean;
  onUpdateHost?: (address: string, patch: Partial<HostResult>) => void;
}

const WORKFLOW: { key: WorkflowStatus; label: string; color: string }[] = [
  { key: "discovered", label: "DISC",   color: "#38bdf8" },
  { key: "enumerated", label: "ENUM",   color: "#a78bfa" },
  { key: "tested",     label: "TESTED", color: "#fbbf24" },
  { key: "vulnerable", label: "VULN",   color: "#f87171" },
  { key: "mitigated",  label: "MITIG",  color: "#6b7280" },
];

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 4443, 5000, 9000]);

function statusColor(code: number | undefined): string {
  if (!code) return "var(--text-dim)";
  if (code < 300) return "var(--success)";
  if (code < 400) return "var(--accent)";
  if (code < 500) return "var(--warning)";
  return "var(--danger)";
}

const SEC_HEADER_LABELS: { key: keyof SecurityHeaders; label: string }[] = [
  { key: "hsts",                      label: "HSTS" },
  { key: "contentSecurityPolicy",     label: "CSP" },
  { key: "xFrameOptions",             label: "X-FRAME" },
  { key: "xContentTypeOptions",       label: "X-CTYPE" },
  { key: "xXssProtection",            label: "XSS-P" },
  { key: "referrerPolicy",            label: "REFER" },
  { key: "permissionsPolicy",         label: "PERMS" },
  { key: "crossOriginOpenerPolicy",   label: "COOP" },
  { key: "crossOriginResourcePolicy", label: "CORP" },
  { key: "crossOriginEmbedderPolicy", label: "COEP" },
];

function portColor(port: number): string {
  if ([22, 2222, 222].includes(port))                                  return "#4ade80";
  if ([80, 443, 8080, 8443, 8000, 3000, 5000, 9000].includes(port))   return "#38bdf8";
  if ([21, 20, 990].includes(port))                                    return "#a78bfa";
  if ([25, 465, 587, 143, 993, 110, 995].includes(port))              return "#fbbf24";
  if ([3306, 5432, 1433, 1521, 27017, 6379, 5984].includes(port))     return "#fb923c";
  if ([53, 5353].includes(port))                                       return "#e879f9";
  if ([445, 139, 135].includes(port))                                  return "#94a3b8";
  return "#67e8f9";
}

function SLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)", marginBottom: "6px" }}>
      <span style={{ color: "var(--accent)", opacity: 0.5 }}>◈</span>
      {children}
      <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
    </div>
  );
}

function Sparkline({ history }: { history: { ts: string; open: number }[] }) {
  if (history.length < 2) return null;
  const W = 64, H = 18, pad = 1;
  const maxOpen = Math.max(...history.map((h) => h.open), 1);
  const pts = history.map((h, i) => {
    const x = pad + (i / (history.length - 1)) * (W - pad * 2);
    const y = H - pad - (h.open / maxOpen) * (H - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return (
    <svg width={W} height={H} style={{ display: "block", marginBottom: "6px" }}>
      <polyline points={pts.join(" ")} fill="none" stroke="var(--accent)" strokeWidth="1.2" opacity="0.7" />
      {history.map((h, i) => {
        const x = pad + (i / (history.length - 1)) * (W - pad * 2);
        const y = H - pad - (h.open / maxOpen) * (H - pad * 2);
        return <circle key={i} cx={x} cy={y} r="1.5" fill="var(--accent)" opacity="0.9" />;
      })}
    </svg>
  );
}

function CertCard({ cert, isLeaf }: { cert: CertInfo; isLeaf: boolean }) {
  const expColor = cert.isExpired ? "var(--danger)"
    : (cert.daysUntilExpiry ?? 999) < 30 ? "var(--warning)"
    : "var(--success)";
  return (
    <div style={{ marginTop: "5px", padding: "5px 8px", background: "rgba(0,0,0,0.18)", borderLeft: `2px solid ${isLeaf ? "var(--accent)" : "var(--border)"}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap", marginBottom: "3px" }}>
        <span style={{ fontSize: "8px", letterSpacing: "0.1em", color: isLeaf ? "var(--accent2)" : "var(--text-dim)" }}>
          {isLeaf ? "LEAF" : "CA"}
        </span>
        {cert.isSelfSigned && (
          <span style={{ fontSize: "7px", padding: "0 4px", color: "var(--warning)", border: "1px solid var(--warning)" }}>SELF-SIGNED</span>
        )}
        {cert.isExpired && (
          <span style={{ fontSize: "7px", padding: "0 4px", color: "var(--danger)", border: "1px solid var(--danger)" }}>EXPIRED</span>
        )}
        {!cert.isExpired && cert.daysUntilExpiry !== undefined && cert.daysUntilExpiry < 30 && (
          <span style={{ fontSize: "7px", padding: "0 4px", color: "var(--warning)", border: "1px solid var(--warning)" }}>
            EXPIRES IN {cert.daysUntilExpiry}d
          </span>
        )}
        {!cert.isExpired && cert.daysUntilExpiry !== undefined && cert.daysUntilExpiry >= 30 && (
          <span style={{ fontSize: "7px", color: expColor }}>{cert.daysUntilExpiry}d left</span>
        )}
      </div>
      {cert.subjectCn && (
        <div style={{ fontFamily: "monospace", fontSize: "10px", color: "var(--text-hi)", marginBottom: "2px" }}>
          CN={cert.subjectCn}
        </div>
      )}
      {cert.subjectSan.length > 0 && (
        <div style={{ fontSize: "9px", color: "var(--text-dim)", marginBottom: "2px", wordBreak: "break-all" }}>
          SAN: {cert.subjectSan.join(", ")}
        </div>
      )}
      {cert.issuer && (
        <div style={{ fontSize: "8px", color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          Issuer: {cert.issuer}
        </div>
      )}
      <div style={{ fontSize: "8px", color: "var(--text-dim)", marginTop: "2px" }}>
        {cert.notBefore.slice(0, 10)} → <span style={{ color: expColor }}>{cert.notAfter.slice(0, 10)}</span>
      </div>
    </div>
  );
}

export function HostInspector({ host, onRescan, isBusy, onUpdateHost }: Props) {
  const openPorts = host.ports.filter((p) => p.state === "open");
  const up        = host.status === "up";
  const now       = useNow();
  const { label: ageLabel, isStale } = formatScanAge(host.scannedAt, now);
  const risk = hostRiskLevel(host);
  const wfState = host.workflowStatus;

  const [tagInput,      setTagInput]     = useState("");
  const [expandedPort,  setExpandedPort] = useState<string | null>(null);
  const [portNoteVal,   setPortNoteVal]  = useState("");
  const [probingPorts,  setProbingPorts]    = useState<Set<number>>(new Set());
  const [probeError,    setProbeError]      = useState<string | null>(null);
  const [tlsProbingPorts, setTlsProbingPorts] = useState<Set<number>>(new Set());
  const [tlsProbeError,   setTlsProbeError]   = useState<string | null>(null);

  const webPorts = openPorts.filter(
    (p) => WEB_PORTS.has(p.port) ||
           p.service.toLowerCase().includes("http") ||
           p.service.toLowerCase().includes("ssl"),
  );

  async function handleProbeHttp(p: PortEntry) {
    setProbingPorts((prev) => new Set([...prev, p.port]));
    setProbeError(null);
    const isHttps =
      p.port === 443 || p.port === 8443 ||
      p.service.toLowerCase().includes("https") ||
      p.service.toLowerCase().includes("ssl");
    try {
      const result = await invoke<HttpProbeResult>("probe_http", {
        request: {
          address: host.address,
          port: p.port,
          useHttps: isHttps,
          followRedirects: true,
          timeoutSecs: 10,
          acceptInvalidCerts: true,
          // Send the known hostname as the Host header so virtual-hosted servers
          // respond for the correct vhost instead of returning 403/default page.
          hostnameOverride: host.hostname ?? undefined,
        } satisfies HttpProbeRequest,
      });
      onUpdateHost?.(host.address, {
        httpProbes: [...(host.httpProbes ?? []), result],
      });
    } catch (err) {
      setProbeError(typeof err === "string" ? err : JSON.stringify(err));
    } finally {
      setProbingPorts((prev) => { const n = new Set(prev); n.delete(p.port); return n; });
    }
  }

  const TLS_PORTS = new Set([443, 8443, 4443, 636, 993, 995, 465, 5986, 8883]);
  const tlsPorts = openPorts.filter(
    (p) => TLS_PORTS.has(p.port) ||
           p.service.toLowerCase().includes("https") ||
           p.service.toLowerCase().includes("ssl") ||
           p.service.toLowerCase().includes("imaps") ||
           p.service.toLowerCase().includes("smtps") ||
           p.service.toLowerCase().includes("pop3s"),
  );

  async function handleProbeTls(p: PortEntry) {
    setTlsProbingPorts((prev) => new Set([...prev, p.port]));
    setTlsProbeError(null);
    try {
      const result = await invoke<TlsProbeResult>("probe_tls", {
        request: {
          address: host.address,
          port: p.port,
          timeoutSecs: 10,
          acceptInvalidCerts: true,
          // Use the known hostname as the TLS SNI so virtual-hosted servers
          // present the correct certificate instead of dropping the handshake.
          sniOverride: host.hostname ?? undefined,
        } satisfies TlsProbeRequest,
      });
      onUpdateHost?.(host.address, {
        tlsProbes: [...(host.tlsProbes ?? []), result],
      });
    } catch (err) {
      setTlsProbeError(typeof err === "string" ? err : JSON.stringify(err));
    } finally {
      setTlsProbingPorts((prev) => { const n = new Set(prev); n.delete(p.port); return n; });
    }
  }

  const knownTags = host.tags ?? [];

  function addTag(tag: string) {
    const t = tag.trim().toLowerCase().replace(/[^a-z0-9-_]/g, "");
    if (!t || knownTags.includes(t)) return;
    onUpdateHost?.(host.address, { tags: [...knownTags, t] });
    setTagInput("");
  }

  function removeTag(tag: string) {
    onUpdateHost?.(host.address, { tags: knownTags.filter((t) => t !== tag) });
  }

  function openPortNote(key: string) {
    setPortNoteVal(host.portNotes?.[key] ?? "");
    setExpandedPort(expandedPort === key ? null : key);
  }

  function savePortNote(key: string) {
    const next = { ...(host.portNotes ?? {}) };
    if (portNoteVal.trim()) next[key] = portNoteVal.trim();
    else delete next[key];
    onUpdateHost?.(host.address, { portNotes: next });
    setExpandedPort(null);
  }

  return (
    <div style={{ marginTop: "0.5rem" }}>
      {/* Host summary */}
      <div style={{
        background: "var(--bg-surface)", border: "1px solid var(--border)",
        borderLeft: `2px solid ${up ? RISK_COLOR[risk] : "var(--danger)"}`,
        padding: "8px 10px", marginBottom: "8px",
        display: "flex", alignItems: "center", gap: "8px", fontSize: "11px", flexWrap: "wrap",
      }}>
        <span style={{ fontFamily: "monospace", color: "var(--text-hi)", fontWeight: 600 }}>{host.address}</span>
        {host.hostname && <span style={{ color: "var(--text-dim)" }}>{host.hostname}</span>}
        <span style={{ color: up ? "var(--success)" : "var(--danger)", fontSize: "9px", letterSpacing: "0.1em" }}>{host.status.toUpperCase()}</span>
        <span style={{ color: "var(--accent)", fontSize: "10px" }}>{openPorts.length} OPEN</span>
        {risk !== "clean" && <span style={{ fontSize: "8px", padding: "1px 5px", color: RISK_COLOR[risk], border: `1px solid ${RISK_COLOR[risk]}`, letterSpacing: "0.08em" }}>⚠ {RISK_LABEL[risk]}</span>}
        {ageLabel && <span style={{ fontSize: "9px", color: isStale ? "var(--warning)" : "var(--text-dim)", marginLeft: "auto" }} title={host.scannedAt}>{isStale ? "⚠ " : ""}{ageLabel}</span>}
        {onRescan && <button onClick={() => onRescan(host.address)} disabled={isBusy} title="Re-scan with current profile" style={{ padding: "2px 8px", fontSize: "9px", letterSpacing: "0.1em", color: isBusy ? "var(--text-dim)" : "var(--accent2)", border: `1px solid ${isBusy ? "var(--border)" : "var(--accent2)"}`, background: "transparent", transition: "all 0.15s" }}>↺ RE-SCAN</button>}
      </div>

      {/* Workflow status */}
      {onUpdateHost && (
        <div style={{ marginBottom: "8px" }}>
          <SLabel>WORKFLOW STATUS</SLabel>
          <div style={{ display: "flex", gap: "4px" }}>
            {WORKFLOW.map((w) => {
              const active = wfState === w.key;
              return (
                <button key={w.key} onClick={() => onUpdateHost(host.address, { workflowStatus: active ? undefined : w.key })}
                  style={{ flex: 1, padding: "3px 2px", fontSize: "7px", letterSpacing: "0.08em", textAlign: "center" as const, background: active ? `${w.color}22` : "transparent", color: active ? w.color : "var(--text-dim)", border: `1px solid ${active ? w.color : "var(--border)"}`, transition: "all 0.12s" }}
                  title={w.key}
                >
                  {w.label}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Tags */}
      {onUpdateHost && (
        <div style={{ marginBottom: "8px" }}>
          <SLabel>TAGS</SLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginBottom: "5px" }}>
            {knownTags.map((tag) => (
              <span key={tag} style={{ display: "inline-flex", alignItems: "center", gap: "3px", padding: "1px 6px", fontSize: "8px", letterSpacing: "0.08em", color: "var(--accent2)", border: "1px solid var(--accent2)", background: "rgba(56,189,248,0.08)" }}>
                {tag}
                <button onClick={() => removeTag(tag)} style={{ background: "transparent", border: "none", color: "var(--accent2)", cursor: "pointer", fontSize: "10px", lineHeight: 1, padding: 0 }}>×</button>
              </span>
            ))}
            {knownTags.length === 0 && <span style={{ fontSize: "9px", color: "var(--text-dim)" }}>No tags</span>}
          </div>
          <div style={{ display: "flex", gap: "4px" }}>
            <input
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") addTag(tagInput); }}
              placeholder="Add tag…"
              style={{ flex: 1, padding: "3px 7px", fontSize: "9px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--border)", outline: "none" }}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent2)")}
              onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
            />
            <button onClick={() => addTag(tagInput)} disabled={!tagInput.trim()} style={{ padding: "3px 8px", fontSize: "9px", color: "var(--accent2)", border: "1px solid var(--accent2)", background: "transparent", cursor: "pointer" }}>+</button>
          </div>
        </div>
      )}

      {/* Port change diff */}
      {host.portsDiff && (host.portsDiff.added.length > 0 || host.portsDiff.removed.length > 0) && (
        <div style={{ marginBottom: "8px", padding: "6px 10px", background: "rgba(0,0,0,0.3)", border: "1px solid var(--border)", fontSize: "10px", display: "flex", gap: "12px", flexWrap: "wrap" }}>
          <span style={{ fontSize: "9px", color: "var(--text-dim)", letterSpacing: "0.1em" }}>CHANGES SINCE LAST SCAN</span>
          {host.portsDiff.added.length > 0 && <span style={{ color: "var(--success)" }}>+{host.portsDiff.added.map((p) => <code key={p} style={{ marginLeft: "4px" }}>{p}</code>)}</span>}
          {host.portsDiff.removed.length > 0 && <span style={{ color: "var(--danger)" }}>−{host.portsDiff.removed.map((p) => <code key={p} style={{ marginLeft: "4px" }}>{p}</code>)}</span>}
        </div>
      )}

      {/* Open ports table */}
      {openPorts.length === 0 ? (
        <div style={{ fontSize: "11px", color: "var(--text-dim)", padding: "4px 0" }}>No open ports found.</div>
      ) : (
        <>
          <SLabel>OPEN PORTS</SLabel>
          {host.portHistory && host.portHistory.length >= 2 && (
            <div style={{ marginBottom: "6px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Sparkline history={host.portHistory} />
              <span style={{ fontSize: "8px", color: "var(--text-dim)", letterSpacing: "0.06em" }}>
                open port history (last {host.portHistory.length} scans)
              </span>
            </div>
          )}
          <div style={{ border: "1px solid var(--border)", overflowX: "auto" }}>
            <div style={{ display: "grid", gridTemplateColumns: "50px 44px 80px 1fr 76px 1fr 24px", padding: "4px 8px", fontSize: "9px", letterSpacing: "0.12em", color: "var(--text-dim)", borderBottom: "1px solid var(--border)", minWidth: "460px" }}>
              <span>PORT</span><span>PROTO</span><span>SERVICE</span><span>PRODUCT</span><span>VERSION</span><span>ADVISORY</span><span />
            </div>
            {openPorts.map((p) => {
              const adv     = getAdvisory(p.port, p.service);
              const verAdv  = getVersionAdvisory(p.product, p.version);
              const isNew   = host.portsDiff?.added.includes(p.port);
              const portKey = `${p.port}/${p.protocol}`;
              const noteSet = !!host.portNotes?.[portKey];

              return (
                <>
                  <div key={portKey} style={{ display: "grid", gridTemplateColumns: "50px 44px 80px 1fr 76px 1fr 24px", padding: "5px 8px", fontSize: "11px", borderBottom: expandedPort === portKey ? "none" : "1px solid var(--border)", alignItems: "center", background: isNew ? "rgba(74,222,128,0.05)" : "transparent", minWidth: "460px" }}>
                    <span style={{ fontFamily: "monospace", color: portColor(p.port), fontWeight: 600 }}>
                      {p.port}{isNew && <span style={{ fontSize: "7px", color: "var(--success)", marginLeft: "3px" }}>NEW</span>}
                    </span>
                    <span style={{ color: "var(--text-dim)", fontSize: "9px" }}>{p.protocol.toUpperCase()}</span>
                    <span style={{ color: "var(--text-hi)" }}>{p.service || "—"}</span>
                    <span style={{ color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.product ?? "—"}</span>
                    <span style={{ color: "var(--text-dim)", fontSize: "10px" }}>{p.version ?? "—"}</span>
                    <span style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      {adv && (
                        <span title={adv.detail} style={{ display: "inline-flex", alignItems: "center", gap: "3px", fontSize: "8px", padding: "1px 5px", border: `1px solid ${SEVERITY_COLOR[adv.severity]}`, color: SEVERITY_COLOR[adv.severity], letterSpacing: "0.06em", cursor: "default" }}>⚠ {adv.label}</span>
                      )}
                      {verAdv && (
                        <span title={verAdv.message} style={{ display: "inline-flex", alignItems: "center", gap: "3px", fontSize: "8px", padding: "1px 5px", border: `1px solid ${verAdv.type === "eol" ? "var(--danger)" : "var(--warning)"}`, color: verAdv.type === "eol" ? "var(--danger)" : "var(--warning)", letterSpacing: "0.06em", cursor: "default" }}>
                          {verAdv.type === "eol" ? "⚠ EOL" : "⬆ UPDATE"}
                        </span>
                      )}
                    </span>
                    <button
                      onClick={() => openPortNote(portKey)}
                      title={noteSet ? "Edit port note" : "Add port note"}
                      style={{ fontSize: "10px", color: noteSet ? "var(--accent2)" : "var(--text-dim)", background: "transparent", border: `1px solid ${noteSet ? "var(--accent2)" : "transparent"}`, cursor: "pointer", padding: "1px 3px" }}
                    >
                      {noteSet ? "✎" : "+"}
                    </button>
                  </div>
                  {expandedPort === portKey && onUpdateHost && (
                    <div key={`${portKey}-note`} style={{ padding: "5px 8px 8px", borderBottom: "1px solid var(--border)", background: "rgba(0,0,0,0.2)", minWidth: "460px" }}>
                      {host.portNotes?.[portKey] && expandedPort !== portKey && (
                        <div style={{ fontSize: "9px", color: "var(--text-dim)", marginBottom: "3px", whiteSpace: "pre-wrap" }}>{host.portNotes[portKey]}</div>
                      )}
                      <textarea
                        autoFocus
                        value={portNoteVal}
                        onChange={(e) => setPortNoteVal(e.target.value)}
                        placeholder="Port note…"
                        rows={2}
                        style={{ width: "100%", resize: "vertical", padding: "4px 6px", fontSize: "10px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--accent)", outline: "none", fontFamily: "var(--font)" }}
                      />
                      <div style={{ display: "flex", gap: "4px", marginTop: "4px" }}>
                        <button onClick={() => savePortNote(portKey)} style={{ padding: "2px 8px", fontSize: "8px", color: "var(--accent)", border: "1px solid var(--accent)", background: "transparent", cursor: "pointer" }}>SAVE</button>
                        <button onClick={() => setExpandedPort(null)} style={{ padding: "2px 8px", fontSize: "8px", color: "var(--text-dim)", border: "1px solid var(--border)", background: "transparent", cursor: "pointer" }}>CANCEL</button>
                      </div>
                    </div>
                  )}
                </>
              );
            })}
          </div>
        </>
      )}

      {/* HTTP PROBE — buttons to trigger surface probes on detected web ports */}
      {webPorts.length > 0 && onUpdateHost && (
        <div style={{ marginTop: "8px" }}>
          <SLabel>HTTP PROBE <span style={{ fontSize: "8px", fontWeight: 400, opacity: 0.6 }}>(opt-in)</span></SLabel>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {webPorts.map((p) => {
              const busy = probingPorts.has(p.port);
              return (
                <button
                  key={p.port}
                  onClick={() => handleProbeHttp(p)}
                  disabled={busy}
                  style={{
                    padding: "3px 8px", fontSize: "9px", letterSpacing: "0.08em",
                    color: busy ? "var(--text-dim)" : "var(--accent2)",
                    border: `1px solid ${busy ? "var(--border)" : "var(--accent2)"}`,
                    background: busy ? "transparent" : "rgba(56,189,248,0.06)",
                    cursor: busy ? "default" : "pointer", transition: "all 0.12s",
                  }}
                >
                  {busy ? "…" : "◉"} :{p.port}/{p.protocol.toUpperCase()}
                </button>
              );
            })}
          </div>
          {probeError && (
            <div style={{ marginTop: "4px", fontSize: "9px", color: "var(--danger)" }}>
              {probeError}
            </div>
          )}
        </div>
      )}

      {/* HTTP SURFACE — results from previous probes, newest first */}
      {(host.httpProbes?.length ?? 0) > 0 && (
        <div style={{ marginTop: "8px" }}>
          <SLabel>HTTP SURFACE ({host.httpProbes!.length})</SLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {[...host.httpProbes!].reverse().map((probe, i) => {
              const sc = probe.statusCode;
              const scColor = statusColor(sc);
              const isError = !!probe.error;
              return (
                <div
                  key={i}
                  style={{
                    border: "1px solid var(--border)",
                    borderLeft: `2px solid ${isError ? "var(--danger)" : scColor}`,
                    padding: "7px 10px", fontSize: "10px",
                    background: "rgba(0,0,0,0.15)",
                  }}
                >
                  {/* Row 1: status + URL + timing */}
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "4px" }}>
                    {sc && (
                      <span style={{ fontFamily: "monospace", fontWeight: 700, color: scColor, fontSize: "11px" }}>
                        {sc}
                      </span>
                    )}
                    {probe.statusText && (
                      <span style={{ fontSize: "9px", color: scColor, letterSpacing: "0.06em" }}>
                        {probe.statusText}
                      </span>
                    )}
                    <span style={{ color: "var(--text-dim)", fontSize: "9px", fontFamily: "monospace", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {probe.finalUrl !== probe.url ? `${probe.url} → ${probe.finalUrl}` : probe.url}
                    </span>
                    <span style={{ fontSize: "9px", color: "var(--text-dim)", flexShrink: 0 }}>
                      {probe.responseTimeMs}ms
                    </span>
                    <button
                      onClick={() => onUpdateHost?.(host.address, { httpProbes: host.httpProbes!.filter((p) => p.url !== probe.url) })}
                      title="Dismiss"
                      style={{ flexShrink: 0, background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "14px", lineHeight: 1, padding: "0 2px", opacity: 0.6 }}
                    >×</button>
                  </div>

                  {/* Network error */}
                  {probe.error && (
                    <div style={{ color: "var(--danger)", fontSize: "9px", marginBottom: "4px" }}>
                      ✗ {probe.error}
                    </div>
                  )}

                  {/* Title */}
                  {probe.title && (
                    <div style={{ color: "var(--text-hi)", marginBottom: "4px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {probe.title}
                    </div>
                  )}

                  {/* Tech hints */}
                  {probe.technologyHints.length > 0 && (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "3px", marginBottom: "5px" }}>
                      {probe.technologyHints.map((h, j) => (
                        <span key={j} style={{ padding: "1px 5px", fontSize: "8px", color: "var(--accent2)", border: "1px solid rgba(56,189,248,0.3)", letterSpacing: "0.04em" }}>
                          {h}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Security header scorecard */}
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
                    {SEC_HEADER_LABELS.map(({ key, label }) => {
                      const present = !!probe.securityHeaders[key];
                      return (
                        <span
                          key={key}
                          title={present ? `${label}: ${probe.securityHeaders[key]}` : `${label}: missing`}
                          style={{
                            padding: "1px 5px", fontSize: "7px", letterSpacing: "0.08em",
                            color: present ? "var(--success)" : "rgba(248,113,113,0.6)",
                            border: `1px solid ${present ? "rgba(74,222,128,0.4)" : "rgba(248,113,113,0.25)"}`,
                          }}
                        >
                          {present ? "✓" : "✗"} {label}
                        </span>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TLS CERT — probe buttons for TLS-capable ports */}
      {tlsPorts.length > 0 && onUpdateHost && (
        <div style={{ marginTop: "8px" }}>
          <SLabel>TLS CERT <span style={{ fontSize: "8px", fontWeight: 400, opacity: 0.6 }}>(opt-in)</span></SLabel>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {tlsPorts.map((p) => {
              const busy = tlsProbingPorts.has(p.port);
              return (
                <button
                  key={p.port}
                  onClick={() => handleProbeTls(p)}
                  disabled={busy}
                  style={{
                    padding: "3px 8px", fontSize: "9px", letterSpacing: "0.08em",
                    color: busy ? "var(--text-dim)" : "var(--accent)",
                    border: `1px solid ${busy ? "var(--border)" : "var(--accent)"}`,
                    background: busy ? "transparent" : "var(--accent-dim)",
                    cursor: busy ? "default" : "pointer", transition: "all 0.12s",
                  }}
                >
                  {busy ? "…" : "🔒"} :{p.port}/{p.protocol.toUpperCase()}
                </button>
              );
            })}
          </div>
          {tlsProbeError && (
            <div style={{ marginTop: "4px", fontSize: "9px", color: "var(--danger)" }}>
              {tlsProbeError}
            </div>
          )}
        </div>
      )}

      {/* TLS CERTIFICATE — results from previous TLS probes, newest first */}
      {(host.tlsProbes?.length ?? 0) > 0 && (
        <div style={{ marginTop: "8px" }}>
          <SLabel>TLS CERTIFICATES ({host.tlsProbes!.length})</SLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {[...host.tlsProbes!].reverse().map((probe, i) => {
              const leaf = probe.certificateChain[0];
              const isError = !!probe.error;
              const weakColor = "var(--warning)";
              return (
                <div
                  key={i}
                  style={{
                    border: "1px solid var(--border)",
                    borderLeft: `2px solid ${isError ? "var(--danger)" : leaf?.isExpired ? "var(--danger)" : probe.cipherIsWeak ? weakColor : "var(--accent)"}`,
                    padding: "7px 10px", fontSize: "10px",
                    background: "rgba(0,0,0,0.15)",
                  }}
                >
                  {/* Row 1: TLS version + cipher + timing */}
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "4px" }}>
                    {probe.tlsVersion && (
                      <span style={{ fontFamily: "monospace", fontWeight: 700, color: "var(--accent)", fontSize: "11px" }}>
                        {probe.tlsVersion}
                      </span>
                    )}
                    {probe.cipherSuite && (
                      <span style={{ fontSize: "8px", fontFamily: "monospace", color: probe.cipherIsWeak ? weakColor : "var(--text-dim)" }}>
                        {probe.cipherSuite}
                        {probe.cipherIsWeak && <span style={{ marginLeft: "4px", color: weakColor }}>⚠ WEAK</span>}
                      </span>
                    )}
                    <span style={{ marginLeft: "auto", fontSize: "9px", color: "var(--text-dim)", flexShrink: 0 }}>
                      :{probe.port} · {probe.connectionTimeMs}ms
                    </span>
                    <button
                      onClick={() => onUpdateHost?.(host.address, { tlsProbes: host.tlsProbes!.filter((p) => p.port !== probe.port) })}
                      title="Dismiss"
                      style={{ flexShrink: 0, background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "14px", lineHeight: 1, padding: "0 2px", opacity: 0.6 }}
                    >×</button>
                  </div>

                  {/* Network error */}
                  {probe.error && (
                    <div style={{ color: "var(--danger)", fontSize: "9px", marginBottom: "4px" }}>
                      ✗ {probe.error}
                    </div>
                  )}

                  {/* Certificate chain */}
                  {probe.certificateChain.map((cert, ci) => (
                    <CertCard key={ci} cert={cert} isLeaf={ci === 0} />
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* NSE script results */}
      {(host.script_results?.length ?? 0) > 0 && (
        <div style={{ marginTop: "8px" }}>
          <SLabel>SCRIPT RESULTS ({host.script_results!.length})</SLabel>
          <div style={{ border: "1px solid var(--border)" }}>
            {host.script_results!.map((s, i) => (
              <div key={i} style={{ padding: "5px 8px", borderBottom: i < host.script_results!.length - 1 ? "1px solid var(--border)" : "none", fontSize: "10px" }}>
                <span style={{ color: "var(--accent2)", fontFamily: "monospace", fontSize: "9px", letterSpacing: "0.06em" }}>{s.id}</span>
                <div style={{ color: "var(--text)", marginTop: "2px", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{s.output}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Notes editor */}
      {onUpdateHost && (
        <div style={{ marginTop: "8px" }}>
          <SLabel>NOTES</SLabel>
          <textarea
            value={host.notes ?? ""}
            onChange={(e) => onUpdateHost(host.address, { notes: e.target.value || undefined })}
            placeholder="Add analyst notes, findings, or observations…"
            rows={3}
            style={{
              width: "100%", resize: "vertical",
              padding: "6px 8px", fontSize: "10px", lineHeight: "1.5",
              background: "var(--bg-input)", color: "var(--text-hi)",
              border: "1px solid var(--border)", fontFamily: "var(--font)",
              outline: "none",
            }}
            onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
            onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
          />
        </div>
      )}
    </div>
  );
}
