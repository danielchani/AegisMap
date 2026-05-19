import { useEffect, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { AttackSurface } from "./AttackSurface";
import { AuditLog } from "./AuditLog";
import { FindingsPanel } from "./FindingsPanel";
import { HostInspector } from "./HostInspector";
import { ResultsTable } from "./ResultsTable";
import { ScopeManager } from "./ScopeManager";
import { isInScope } from "../lib/scopeUtils";
import type {
  HostResult, PortFamily, PentestFinding, ScanProfile, ScanReport,
  ScanRequest, ScanStatus, ScanStreamEvent,
} from "../types";

// ── NSE allowlist mirrors backend (UI convenience — backend re-validates) ──────
const NSE_SCRIPTS = [
  { id: "http-title",        label: "HTTP Title",      hint: "Page title" },
  { id: "http-headers",      label: "HTTP Headers",    hint: "Server headers" },
  { id: "ssl-cert",          label: "SSL Cert",        hint: "TLS cert info" },
  { id: "ssh-hostkey",       label: "SSH Hostkey",     hint: "Key fingerprint" },
  { id: "smb-security-mode", label: "SMB Security",    hint: "Signing / guest" },
  { id: "ftp-anon",          label: "FTP Anon",        hint: "Anonymous login" },
  { id: "banner",            label: "Banner Grab",     hint: "Service banners" },
  { id: "http-server-header",label: "Server Header",   hint: "Server string" },
];

interface ScannerPanelProps {
  status: ScanStatus;
  report: ScanReport | null;
  sessionHostCount: number;
  selectedHost: HostResult | null;
  portFilter: PortFamily;
  authorizedRanges: string[];
  activeTab?: "scan" | "results" | "inspect" | "audit" | "findings";
  findings?: PentestFinding[];
  sessionId?: string;
  onFindingsChange?: (findings: PentestFinding[]) => void;
  onStatusChange:       (s: ScanStatus) => void;
  onReportChange:       (r: ScanReport | null) => void;
  onSelectHost:         (h: HostResult | null) => void;
  onRemoveHost:         (address: string) => void;
  onUpdateHost:         (address: string, patch: Partial<HostResult>) => void;
  onSetPortFilter:      (f: PortFamily) => void;
  onSetAuthorizedRanges:(r: string[]) => void;
  onStdoutLine?:        (line: string) => void;
  onScanStart?:         () => void;
  onClearSession:       () => void;
  onPrint:              () => void;
  onScanStarted?:       (target: string, profile: string, scopeWarned: boolean) => void;
  onScanComplete?:      (target: string, hostCount: number) => void;
}

const PROFILES: { value: ScanProfile; label: string; hint: string; privileged?: true }[] = [
  { value: "quick_common_ports",      label: "QUICK",   hint: "top 100"      },
  { value: "standard_tcp",            label: "TCP",     hint: "all ports"    },
  { value: "light_service_detection", label: "SERVICE", hint: "version"      },
  { value: "os_detect",               label: "OS",      hint: "needs root"   },
  { value: "udp_common",              label: "UDP",     hint: "top 20 UDP"   },
  { value: "stealth_syn",  label: "STEALTH", hint: "-sS half-open", privileged: true },
  { value: "ack_probe",    label: "ACK",     hint: "firewall map",  privileged: true },
  { value: "evasion_scan", label: "EVASION", hint: "decoys + frag", privileged: true },
];

const PRIVILEGED_PROFILES: ReadonlySet<ScanProfile> = new Set([
  "stealth_syn", "ack_probe", "evasion_scan", "os_detect", "udp_common",
]);

const FILTER_CHIPS: { key: PortFamily; label: string }[] = [
  { key: null, label: "ALL" }, { key: "web", label: "WEB" }, { key: "ssh", label: "SSH" },
  { key: "db", label: "DB" }, { key: "mail", label: "MAIL" }, { key: "dns", label: "DNS" },
];

function SLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)", marginBottom: "7px" }}>
      <span style={{ color: "var(--accent)", opacity: 0.5 }}>◈</span>
      {children}
      <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
    </div>
  );
}

function StatusDot({ status }: { status: ScanStatus }) {
  const col =
    status === "running" || status === "starting" ? "var(--accent)" :
    status === "completed"                        ? "var(--success)" :
    status === "failed"                           ? "var(--danger)"  :
    status === "cancelling"                       ? "var(--warning)" : "var(--border-hi)";
  const pulse = status === "running" || status === "starting";
  return (
    <span style={{ display: "inline-block", width: "6px", height: "6px", borderRadius: "50%", background: col, boxShadow: pulse ? `0 0 7px ${col}` : "none", flexShrink: 0, animation: pulse ? "dotPulse 1s ease-in-out infinite" : "none" }} />
  );
}

export function ScannerPanel({
  status, report, sessionHostCount, selectedHost, portFilter, authorizedRanges,
  activeTab = "scan",
  findings, sessionId, onFindingsChange,
  onStatusChange, onReportChange, onSelectHost, onRemoveHost, onUpdateHost,
  onSetPortFilter, onSetAuthorizedRanges, onStdoutLine, onScanStart, onClearSession,
  onPrint, onScanStarted, onScanComplete,
}: ScannerPanelProps) {
  const [target,        setTarget]       = useState("");
  const [profile,       setProfile]      = useState<ScanProfile>("quick_common_ports");
  const [portRange,     setPortRange]    = useState("");
  const [decoys,        setDecoys]       = useState("");
  const [sourcePort,    setSourcePort]   = useState("");
  const [selectedScripts, setSelectedScripts] = useState<Set<string>>(new Set());
  const [errorMsg,      setErrorMsg]     = useState<string | null>(null);
  const [logLines,      setLogLines]     = useState<string[]>([]);
  const [progress,      setProgress]     = useState<number | null>(null);
  const [eta,           setEta]          = useState<number | null>(null);
  const [importErr,     setImportErr]    = useState<string | null>(null);
  const [scopeWarning,  setScopeWarning] = useState(false);
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [scanQueue,     setScanQueue]    = useState<string[]>([]);
  const fileInputRef     = useRef<HTMLInputElement>(null);
  const logRef           = useRef<HTMLDivElement>(null);
  const queueAutoStart   = useRef<string | null>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  // Auto-start next queued scan after a terminal event
  useEffect(() => {
    if ((status === "completed" || status === "failed") && queueAutoStart.current) {
      const addr = queueAutoStart.current;
      queueAutoStart.current = null;
      const t = setTimeout(() => runScan(addr, profile, true), 400);
      return () => clearTimeout(t);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  // Global export shortcut
  useEffect(() => {
    const fn = () => handleExportJSON();
    window.addEventListener("aegismap:export", fn as EventListener);
    return () => window.removeEventListener("aegismap:export", fn as EventListener);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report]);

  // Scope warning when target changes
  useEffect(() => {
    if (!target.trim() || authorizedRanges.length === 0) { setScopeWarning(false); return; }
    setScopeWarning(!isInScope(target.trim(), authorizedRanges));
  }, [target, authorizedRanges]);

  function handleEvent(e: ScanStreamEvent) {
    switch (e.type) {
      case "started":        setLogLines((p) => [...p, "› scan initialised"]); break;
      case "stdout_line":    setLogLines((p) => [...p, e.data.line]); onStdoutLine?.(e.data.line); break;
      case "stderr_line":    setLogLines((p) => [...p, `! ${e.data.line}`]); break;
      case "progress_hint":  setProgress(e.data.percent); setEta(e.data.etc_seconds ?? null); break;
      case "parsed_result":
        onReportChange(e.data.report);
        onScanComplete?.(e.data.report.target, e.data.report.hosts.length);
        break;
      case "completed":
        onStatusChange("completed"); setProgress(100); setEta(null);
        setLogLines((p) => [...p, "› scan complete"]);
        setScanQueue((q) => { if (q.length > 0) { queueAutoStart.current = q[0]; return q.slice(1); } return q; });
        break;
      case "cancelled":
        onStatusChange("idle"); setProgress(null); setEta(null);
        setLogLines((p) => [...p, "› scan cancelled"]);
        break;
      case "failed":
        onStatusChange("failed"); setErrorMsg(e.data.message); setEta(null);
        setLogLines((p) => [...p, `✗ ${e.data.message}`]);
        setScanQueue((q) => { if (q.length > 0) { queueAutoStart.current = q[0]; return q.slice(1); } return q; });
        break;
    }
  }

  async function runScan(targetAddress: string, scanProfile: ScanProfile, override = false) {
    if (scopeWarning && !override && !scopeConfirmed) return;
    setScopeConfirmed(false);
    onScanStart?.();
    onStatusChange("starting");
    setErrorMsg(null);
    setLogLines([]);
    setProgress(null);
    onScanStarted?.(targetAddress, scanProfile, scopeWarning && override);

    const req: ScanRequest = { target: targetAddress, profile: scanProfile };
    if (portRange.trim()) req.portRange = portRange.trim();
    if (selectedScripts.size > 0) req.scripts = [...selectedScripts];
    if (decoys.trim()) req.decoys = decoys.trim();
    const sp = parseInt(sourcePort.trim(), 10);
    if (!isNaN(sp) && sp >= 1 && sp <= 65535) req.sourcePort = sp;

    const ch = new Channel<ScanStreamEvent>();
    ch.onmessage = handleEvent;
    try {
      await invoke("start_scan", { request: req, channel: ch });
      onStatusChange("running");
    } catch (err: unknown) {
      onStatusChange("failed");
      setErrorMsg(typeof err === "string" ? err : JSON.stringify(err));
    }
  }

  const handleStart  = () => runScan(target, profile);
  const handleRescan = (address: string) => runScan(address, profile, true);

  async function handleCancel() {
    onStatusChange("cancelling");
    try { await invoke("cancel_scan"); } catch { /* best-effort */ }
  }

  // ── Export helpers ───────────────────────────────────────────────────────────

  function dl(content: string, mime: string, name: string) {
    const url = URL.createObjectURL(new Blob([content], { type: mime }));
    Object.assign(document.createElement("a"), { href: url, download: name }).click();
    URL.revokeObjectURL(url);
  }

  function handleExportJSON() {
    if (!report?.hosts.length) return;
    dl(JSON.stringify({ exportedAt: new Date().toISOString(), hosts: report.hosts }, null, 2), "application/json", `aegismap-${Date.now()}.json`);
  }

  function handleExportCSV() {
    if (!report?.hosts.length) return;
    const rows = ["address,hostname,status,open_ports,services,scanned_at,risk"];
    for (const h of report.hosts) {
      const open = h.ports.filter((p) => p.state === "open");
      rows.push([h.address, h.hostname ?? "", h.status, String(open.length), `"${open.map((p) => p.service).filter(Boolean).join(";")}"`, h.scannedAt ?? ""].join(","));
    }
    dl(rows.join("\n"), "text/csv", `aegismap-${Date.now()}.csv`);
  }

  function handleExportMD() {
    if (!report?.hosts.length) return;
    const lines = [`# AegisMap Report\nGenerated: ${new Date().toLocaleString()}\n`, `## Summary\n- ${report.hosts.length} host(s) · ${report.hosts.reduce((s, h) => s + h.ports.filter((p) => p.state === "open").length, 0)} open ports\n`];
    for (const h of report.hosts) {
      const open = h.ports.filter((p) => p.state === "open");
      lines.push(`### ${h.address}${h.hostname ? ` (${h.hostname})` : ""} — ${h.status.toUpperCase()}`);
      if (h.notes) lines.push(`> ${h.notes}`);
      if (open.length > 0) {
        lines.push("| Port | Proto | Service | Product | Version |", "|------|-------|---------|---------|---------|");
        open.forEach((p) => lines.push(`| ${p.port} | ${p.protocol} | ${p.service || "—"} | ${p.product ?? "—"} | ${p.version ?? "—"} |`));
      }
      if (h.script_results?.length) h.script_results.forEach((s) => lines.push(`\n**${s.id}:** ${s.output}`));
      lines.push("");
    }
    dl(lines.join("\n"), "text/markdown", `aegismap-${Date.now()}.md`);
  }

  /** Sanitize a string field to prevent XSS — strips HTML tags and control chars */
  function sanitizeField(val: unknown, maxLen = 1000): string | undefined {
    if (val === undefined || val === null) return undefined;
    if (typeof val !== "string") return undefined;
    return val
      .replace(/<[^>]*>/g, "")             // strip HTML tags
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip control chars (keep \n\r\t)
      .replace(/javascript\s*:/gi, "")     // strip JS protocol
      .replace(/on\w+\s*=/gi, "")          // strip event handlers
      .slice(0, maxLen);
  }

  /** Sanitize an imported host — strip potential XSS from all string fields */
  function sanitizeHost(h: HostResult): HostResult {
    return {
      ...h,
      address:  sanitizeField(h.address, 253) ?? h.address,
      hostname: sanitizeField(h.hostname, 253),
      notes:    sanitizeField(h.notes, 5000),
      tags:     h.tags?.map((t) => sanitizeField(t, 50) ?? "").filter(Boolean),
      portNotes: h.portNotes
        ? Object.fromEntries(
            Object.entries(h.portNotes).map(([k, v]) => [
              sanitizeField(k, 20) ?? k,
              sanitizeField(v, 2000) ?? "",
            ])
          )
        : undefined,
      ports: h.ports.map((p) => ({
        ...p,
        service: sanitizeField(p.service, 100) ?? p.service ?? "",
        product: sanitizeField(p.product, 200),
        version: sanitizeField(p.version, 100),
      })),
      script_results: h.script_results?.map((s) => ({
        id: sanitizeField(s.id, 100) ?? s.id,
        output: sanitizeField(s.output, 5000) ?? s.output,
      })),
    };
  }

  function isValidHost(h: unknown): h is HostResult {
    if (!h || typeof h !== "object") return false;
    const o = h as Record<string, unknown>;
    return typeof o.address === "string" && o.address.length > 0 && o.address.length <= 253 &&
      typeof o.status === "string" &&
      Array.isArray(o.ports) &&
      (o.ports as unknown[]).every((p: unknown) => {
        const port = p as Record<string, unknown>;
        return typeof port.port === "number" && port.port >= 0 && port.port <= 65535 &&
          typeof port.state === "string";
      }) &&
      (o.notes === undefined || (typeof o.notes === "string" && (o.notes as string).length <= 5000));
  }

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]; if (!file) return;
    setImportErr(null);
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data  = JSON.parse(ev.target?.result as string);
        const raw   = data.hosts ?? data;
        if (!Array.isArray(raw)) throw new Error("Expected hosts array");
        const valid   = (raw as unknown[]).filter(isValidHost).map(sanitizeHost);
        const rejected = raw.length - valid.length;
        if (valid.length === 0) throw new Error("No valid hosts found in file");
        onReportChange({ ...(report ?? { target: "imported", profile: "quick_common_ports" as ScanProfile, hosts: [] }), hosts: valid });
        setLogLines((p) => [...p, `› imported ${valid.length} host(s)${rejected > 0 ? ` (${rejected} rejected)` : ""}`]);
        if (rejected > 0) setImportErr(`${rejected} entr${rejected === 1 ? "y" : "ies"} rejected (invalid schema)`);
      } catch (err) { setImportErr(`Import failed: ${err instanceof Error ? err.message : String(err)}`); }
    };
    reader.readAsText(file); e.target.value = "";
  }

  const busy    = ["starting", "running", "cancelling"].includes(status);
  const canScan = !busy && target.trim().length > 0;
  const has     = sessionHostCount > 0;

  const showScan     = activeTab === "scan";
  const showResults  = activeTab === "results";
  const showInspect  = activeTab === "inspect";
  const showAudit    = activeTab === "audit";
  const showFindings = activeTab === "findings";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem", padding: "0 0 1.5rem" }}>

      {/* Attack surface dashboard — visible on scan & results tabs */}
      {(showScan || showResults) && has && report && <AttackSurface hosts={report.hosts} onPrint={onPrint} />}

      <div style={{ display: "flex", flexDirection: "column", gap: "1rem", padding: "1rem 1rem 0" }}>

      {/* ═══════════ SCAN TAB ═══════════ */}
      {showScan && <>

        {/* TARGET */}
        <div>
          <SLabel>TARGET ACQUISITION</SLabel>
          <div
            className="bracketed"
            style={{ display: "flex", alignItems: "center", gap: "8px", background: "var(--bg-input)", border: `1px solid ${scopeWarning ? "var(--warning)" : "var(--border)"}`, padding: "0 10px", height: "36px" }}
            onFocusCapture={(e) => !scopeWarning && (e.currentTarget.style.borderColor = "var(--accent)")}
            onBlurCapture={(e)  => !scopeWarning && (e.currentTarget.style.borderColor = "var(--border)")}
          >
            <span style={{ color: scopeWarning ? "var(--warning)" : "var(--accent)", opacity: 0.7, fontSize: "11px", userSelect: "none" }}>
              {scopeWarning ? "⚠" : "›"}
            </span>
            <input
              id="scan-target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && canScan && handleStart()}
              placeholder="host, IP, or CIDR…"
              disabled={busy}
              style={{ flex: 1, background: "transparent", color: "var(--text-hi)", fontSize: "12px" }}
            />
          </div>
          {scopeWarning && !scopeConfirmed && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px", padding: "5px 8px", background: "rgba(251,191,36,0.07)", border: "1px solid var(--warning)", fontSize: "9px", color: "var(--warning)", letterSpacing: "0.06em" }}>
              <span style={{ flex: 1 }}>⚠ Target outside defined scope</span>
              <button onClick={() => { setScopeConfirmed(true); }} style={{ padding: "1px 6px", fontSize: "8px", color: "var(--warning)", border: "1px solid var(--warning)", background: "transparent", cursor: "pointer", letterSpacing: "0.1em" }}>PROCEED</button>
              <button onClick={() => setTarget("")} style={{ padding: "1px 6px", fontSize: "8px", color: "var(--text-dim)", border: "1px solid var(--border)", background: "transparent", cursor: "pointer" }}>CANCEL</button>
            </div>
          )}
          <input
            value={portRange}
            onChange={(e) => setPortRange(e.target.value)}
            placeholder="Ports override: 22,80,443 or 1-1024  (optional)"
            disabled={busy}
            style={{ marginTop: "5px", width: "100%", padding: "4px 10px", background: "var(--bg-input)", color: "var(--text-dim)", border: "1px solid var(--border)", fontSize: "10px" }}
          />
        </div>

        {/* PROFILE */}
        <div>
          <SLabel>SCAN PROFILE</SLabel>
          <div style={{ display: "flex", gap: "4px" }}>
            {PROFILES.map((p) => {
              const active = profile === p.value;
              return (
                <button key={p.value} onClick={() => setProfile(p.value)} disabled={busy} style={{ flex: 1, padding: "5px 2px", textAlign: "center" as const, fontSize: "8px", letterSpacing: "0.1em", background: active ? "var(--accent-dim)" : "var(--bg-input)", color: active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, transition: "all 0.15s" }}>
                  <div style={{ fontWeight: active ? 700 : 400 }}>{p.label}</div>
                  <div style={{ opacity: 0.45, marginTop: "1px", fontSize: "7px" }}>{p.hint}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* PRIVILEGE WARNING — stealth/ack/evasion/os/udp */}
        {PRIVILEGED_PROFILES.has(profile) && (
          <div style={{ display: "flex", gap: "8px", padding: "6px 10px", background: "rgba(251,191,36,0.06)", border: "1px solid rgba(251,191,36,0.35)", fontSize: "9px", color: "var(--warning)", letterSpacing: "0.05em", lineHeight: "1.5" }}>
            <span style={{ flexShrink: 0 }}>⚠</span>
            <div>
              {profile === "stealth_syn" && "STEALTH SYN requires root on Linux or Npcap + Administrator on Windows. Half-open scan — never completes the TCP handshake."}
              {profile === "ack_probe"   && "ACK PROBE requires root on Linux or Npcap + Administrator on Windows. Maps firewall rules; does not identify open ports on its own."}
              {profile === "evasion_scan" && "EVASION SCAN requires root on Linux or Npcap + Administrator on Windows. Sends fragmented packets with IP decoys to confuse IDS/firewall logging. Use only on authorised targets."}
              {profile === "os_detect"   && "OS DETECTION may require elevated privileges for raw socket access."}
              {profile === "udp_common"  && "UDP SCAN requires root on Linux or Administrator on Windows."}
            </div>
          </div>
        )}

        {/* EVASION OPTIONS — decoys and source-port (shown for all stealth profiles) */}
        {(profile === "evasion_scan" || profile === "stealth_syn" || profile === "ack_probe") && (
          <div>
            <SLabel>EVASION OPTIONS</SLabel>
            <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
              <div>
                <label style={{ fontSize: "8px", letterSpacing: "0.1em", color: "var(--text-dim)", display: "block", marginBottom: "3px" }}>
                  DECOYS <span style={{ opacity: 0.5 }}>— comma-separated IPs / ME / RND / RND:N (max 8)</span>
                </label>
                <input
                  value={decoys}
                  onChange={(e) => setDecoys(e.target.value)}
                  placeholder={profile === "evasion_scan" ? "defaults to RND:5 when blank" : "e.g. 192.168.1.5,ME,RND:3"}
                  disabled={busy}
                  style={{ width: "100%", padding: "4px 10px", background: "var(--bg-input)", color: "var(--text-dim)", border: "1px solid var(--border)", fontSize: "10px" }}
                />
              </div>
              <div>
                <label style={{ fontSize: "8px", letterSpacing: "0.1em", color: "var(--text-dim)", display: "block", marginBottom: "3px" }}>
                  SOURCE PORT <span style={{ opacity: 0.5 }}>— spoof source port (e.g. 53, 80)</span>
                </label>
                <input
                  value={sourcePort}
                  onChange={(e) => setSourcePort(e.target.value)}
                  placeholder="optional, 1–65535"
                  disabled={busy}
                  style={{ width: "100%", padding: "4px 10px", background: "var(--bg-input)", color: "var(--text-dim)", border: "1px solid var(--border)", fontSize: "10px" }}
                />
              </div>
            </div>
          </div>
        )}

        {/* NSE SCRIPTS */}
        <div>
          <SLabel>NSE SCRIPTS <span style={{ fontSize: "8px", fontWeight: 400, opacity: 0.6 }}>(reconnaissance only)</span></SLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
            {NSE_SCRIPTS.map((s) => {
              const on = selectedScripts.has(s.id);
              return (
                <button
                  key={s.id}
                  title={s.hint}
                  onClick={() => {
                    const next = new Set(selectedScripts);
                    on ? next.delete(s.id) : next.add(s.id);
                    setSelectedScripts(next);
                  }}
                  disabled={busy}
                  style={{ padding: "2px 6px", fontSize: "8px", letterSpacing: "0.08em", background: on ? "rgba(56,189,248,0.12)" : "transparent", color: on ? "var(--accent2)" : "var(--text-dim)", border: `1px solid ${on ? "var(--accent2)" : "var(--border)"}`, transition: "all 0.12s" }}
                >
                  {s.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* SCOPE MANAGER */}
        <ScopeManager ranges={authorizedRanges} onChange={onSetAuthorizedRanges} />

        {/* ACTIONS */}
        <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
          {!busy ? (
            <div style={{ display: "flex", gap: "4px" }}>
              <button className="hud-btn" onClick={handleStart} disabled={!canScan} style={{ flex: 1, color: canScan ? "var(--accent)" : "var(--text-dim)", borderColor: canScan ? "var(--accent)" : "var(--border)", background: canScan ? "var(--accent-dim)" : "transparent" }}>
                ▶ INITIATE SCAN
              </button>
              <button
                title="Add to scan queue"
                onClick={() => { if (target.trim()) { setScanQueue((q) => [...q, target.trim()]); setTarget(""); } }}
                disabled={!target.trim()}
                style={{ padding: "0 10px", fontSize: "10px", color: target.trim() ? "var(--text-dim)" : "var(--border)", border: `1px solid ${target.trim() ? "var(--border)" : "transparent"}`, background: "transparent", cursor: target.trim() ? "pointer" : "default", letterSpacing: "0.08em" }}
              >+ Q</button>
            </div>
          ) : (
            <button className="hud-btn" onClick={handleCancel} disabled={status === "cancelling"} style={{ color: "var(--danger)", borderColor: "var(--danger)", background: "rgba(248,113,113,0.06)" }}>
              ■ ABORT
            </button>
          )}
          {has && !busy && (
            <>
              <div style={{ display: "flex", gap: "4px" }}>
                {[{ l: "JSON", fn: handleExportJSON }, { l: "CSV", fn: handleExportCSV }, { l: "MD", fn: handleExportMD }, { l: "PDF", fn: onPrint }].map(({ l, fn }) => (
                  <button key={l} className="hud-btn" onClick={fn} style={{ flex: 1, height: "24px", fontSize: "8px", color: "var(--accent2)", borderColor: "var(--border)", background: "transparent", letterSpacing: "0.1em" }}>↓ {l}</button>
                ))}
                <button className="hud-btn" onClick={() => fileInputRef.current?.click()} style={{ flex: 1, height: "24px", fontSize: "8px", color: "var(--text-dim)", borderColor: "var(--border)", background: "transparent", letterSpacing: "0.1em" }}>↑ IMP</button>
                <input ref={fileInputRef} type="file" accept=".json" onChange={handleImport} style={{ display: "none" }} />
              </div>
              <button className="hud-btn" onClick={onClearSession} style={{ height: "24px", fontSize: "9px", color: "var(--text-dim)", borderColor: "var(--border)", background: "transparent", letterSpacing: "0.1em" }}>
                ✕ CLEAR ({sessionHostCount})
              </button>
            </>
          )}
          {!has && !busy && (
            <>
              <button className="hud-btn" onClick={() => fileInputRef.current?.click()} style={{ height: "26px", fontSize: "9px", color: "var(--text-dim)", borderColor: "var(--border)", background: "transparent", letterSpacing: "0.1em" }}>↑ IMPORT SESSION</button>
              <input ref={fileInputRef} type="file" accept=".json" onChange={handleImport} style={{ display: "none" }} />
            </>
          )}
          {importErr && <div style={{ fontSize: "10px", color: "var(--danger)" }}>{importErr}</div>}

          {/* SCAN QUEUE */}
          {scanQueue.length > 0 && (
            <div style={{ marginTop: "2px" }}>
              <div style={{ fontSize: "8px", color: "var(--text-dim)", letterSpacing: "0.12em", marginBottom: "3px" }}>◈ QUEUE ({scanQueue.length})</div>
              {scanQueue.map((addr, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "3px 6px", background: "var(--bg-input)", border: "1px solid var(--border)", marginBottom: "2px" }}>
                  <span style={{ flex: 1, fontSize: "10px", fontFamily: "monospace", color: i === 0 ? "var(--accent)" : "var(--text-dim)" }}>{i === 0 ? "› " : ""}{addr}</span>
                  <button onClick={() => setScanQueue((q) => q.filter((_, qi) => qi !== i))} style={{ fontSize: "10px", color: "var(--text-dim)", background: "transparent", border: "none", cursor: "pointer" }}>×</button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* PORT FILTER */}
        {has && (
          <div>
            <SLabel>PORT FILTER</SLabel>
            <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
              {FILTER_CHIPS.map(({ key, label }) => {
                const active = portFilter === key;
                return (
                  <button key={label} onClick={() => onSetPortFilter(active ? null : key)} style={{ padding: "3px 8px", fontSize: "8px", letterSpacing: "0.12em", background: active ? "var(--accent-dim)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, transition: "all 0.12s" }}>
                    {label}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* STATUS */}
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: progress !== null ? "7px" : 0 }}>
            <StatusDot status={status} />
            <span style={{ fontSize: "10px", letterSpacing: "0.12em", color: status === "completed" ? "var(--success)" : status === "failed" ? "var(--danger)" : status === "idle" ? "var(--text-dim)" : "var(--text-hi)" }}>
              {status.toUpperCase()}
            </span>
            {errorMsg && <span style={{ fontSize: "10px", color: "var(--danger)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{errorMsg}</span>}
            {progress !== null && (
              <span style={{ marginLeft: "auto", fontSize: "10px", color: "var(--accent)", flexShrink: 0, display: "flex", gap: "6px", alignItems: "center" }}>
                {progress.toFixed(1)}%
                {eta !== null && eta > 0 && (
                  <span style={{ color: "var(--text-dim)", fontSize: "9px" }}>~{eta < 60 ? `${eta}s` : `${Math.ceil(eta / 60)}m`}</span>
                )}
              </span>
            )}
          </div>
          {progress !== null && (
            <div style={{ height: "2px", background: "var(--border)", position: "relative" }}>
              <div style={{ position: "absolute", top: 0, left: 0, bottom: 0, width: `${Math.min(progress, 100)}%`, background: "var(--accent)", boxShadow: "0 0 6px var(--accent)", transition: "width 0.35s ease-out" }} />
            </div>
          )}
        </div>

        {/* CONSOLE */}
        {logLines.length > 0 && (
          <div>
            <SLabel>CONSOLE</SLabel>
            <div ref={logRef} style={{ height: "130px", overflowY: "auto", background: "#020c10", border: "1px solid var(--border)", padding: "7px 10px", fontSize: "10.5px", lineHeight: "1.65" }}>
              {logLines.map((line, i) => (
                <div key={i} style={{ color: line.startsWith("!") ? "var(--danger)" : line.startsWith("›") || line.startsWith("✗") ? "var(--text-dim)" : "#2dcc80", whiteSpace: "pre", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        )}

      </>}
      {/* ═══════════ END SCAN TAB ═══════════ */}

      {/* ═══════════ RESULTS TAB ═══════════ */}
      {showResults && <>
        {/* PORT FILTER */}
        {has && (
          <div>
            <SLabel>PORT FILTER</SLabel>
            <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
              {FILTER_CHIPS.map(({ key, label }) => {
                const active = portFilter === key;
                return (
                  <button key={label} onClick={() => onSetPortFilter(active ? null : key)} style={{ padding: "3px 8px", fontSize: "8px", letterSpacing: "0.12em", background: active ? "var(--accent-dim)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, transition: "all 0.12s" }}>
                    {label}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {report && report.hosts.length > 0 && (
          <ResultsTable report={report} selectedAddress={selectedHost?.address ?? null} onSelect={onSelectHost} onRemoveHost={onRemoveHost} />
        )}

        {!has && (
          <div style={{ padding: "2rem 0", textAlign: "center", fontSize: "11px", color: "var(--text-dim)" }}>
            No hosts yet — run a scan or import a session.
          </div>
        )}

        {has && !busy && (
          <div style={{ display: "flex", gap: "4px" }}>
            {[{ l: "JSON", fn: handleExportJSON }, { l: "CSV", fn: handleExportCSV }, { l: "MD", fn: handleExportMD }, { l: "PDF", fn: onPrint }].map(({ l, fn }) => (
              <button key={l} className="hud-btn" onClick={fn} style={{ flex: 1, height: "24px", fontSize: "8px", color: "var(--accent2)", borderColor: "var(--border)", background: "transparent", letterSpacing: "0.1em" }}>↓ {l}</button>
            ))}
          </div>
        )}
      </>}
      {/* ═══════════ END RESULTS TAB ═══════════ */}

      {/* ═══════════ INSPECT TAB ═══════════ */}
      {showInspect && <>
        {selectedHost ? (
          <HostInspector host={selectedHost} onRescan={handleRescan} isBusy={busy} onUpdateHost={onUpdateHost} />
        ) : (
          <div style={{ padding: "2rem 0", textAlign: "center", fontSize: "11px", color: "var(--text-dim)" }}>
            Select a host from the 3D view or the results table to inspect.
          </div>
        )}
      </>}
      {/* ═══════════ END INSPECT TAB ═══════════ */}

      {/* ═══════════ AUDIT TAB ═══════════ */}
      {showAudit && (
        <div style={{ marginTop: "0.5rem" }}>
          <AuditLog />
        </div>
      )}
      {/* ═══════════ END AUDIT TAB ═══════════ */}

      {/* ═══════════ FINDINGS TAB ═══════════ */}
      {showFindings && sessionId && (
        <FindingsPanel
          sessionId={sessionId}
          findings={findings ?? []}
          onFindingsChange={onFindingsChange ?? (() => {})}
        />
      )}
      {/* ═══════════ END FINDINGS TAB ═══════════ */}

      </div>
    </div>
  );
}
