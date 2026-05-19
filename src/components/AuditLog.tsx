import { useEffect, useState } from "react";
import { clearAudit, loadAudit, verifyAuditChain } from "../lib/auditLog";
import type { AuditEntry } from "../lib/auditLog";

export function AuditLog() {
  const [open,      setOpen]      = useState(false);
  const [entries,   setEntries]   = useState<AuditEntry[]>([]);
  const [integrity, setIntegrity] = useState<{ valid: boolean; brokenAt?: number } | null>(null);
  const [migrated,  setMigrated]  = useState(false);
  const [verifying, setVerifying] = useState(false);

  // Load entries when panel first opens
  useEffect(() => {
    if (open && entries.length === 0) {
      loadAudit(50).then((e) => setEntries([...e].reverse())).catch(() => {});
    }
  }, [open]);

  async function runVerify() {
    setVerifying(true);
    try {
      const result = await verifyAuditChain();
      setIntegrity(result);
      if (result.migrated) setMigrated(true);
    } finally {
      setVerifying(false);
    }
  }

  async function handleRefresh() {
    const entries = await loadAudit(50);
    setEntries([...entries].reverse());
    void runVerify();
  }

  async function handleClear() {
    if (!window.confirm("Clear the entire audit log?")) return;
    await clearAudit();
    setEntries([]);
    setIntegrity(null);
    setMigrated(false);
  }

  function handleExport() {
    loadAudit().then((allEntries) => {
      const text = allEntries
        .map((e) => `[${e.timestamp}] ${e.action}: ${e.details} [sha256:${e.hash}]`)
        .join("\n");
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      Object.assign(document.createElement("a"), {
        href: url, download: `aegismap-audit-${Date.now()}.txt`,
      }).click();
      URL.revokeObjectURL(url);
    }).catch(() => {});
  }

  return (
    <div style={{ padding: "0 1rem" }}>
      {/* Toggle */}
      <div
        onClick={() => { setOpen((o) => !o); if (!open) void handleRefresh(); }}
        style={{
          display: "flex", alignItems: "center", gap: "8px", cursor: "pointer",
          fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)",
        }}
      >
        <span style={{ color: "var(--accent)", opacity: 0.5 }}>◈</span>
        AUDIT LOG
        <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
        {entries.length > 0 && <span>{entries.length} entries</span>}
        {integrity && (
          <span style={{
            fontSize: "7px", padding: "1px 4px", letterSpacing: "0.1em",
            color: integrity.valid ? "var(--success)" : "var(--danger)",
            border: `1px solid ${integrity.valid ? "var(--success)" : "var(--danger)"}`,
          }}>
            {integrity.valid ? "✓ CHAIN INTACT" : `✗ CHAIN BROKEN @${integrity.brokenAt}`}
          </span>
        )}
        <span style={{ fontSize: "8px" }}>{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div style={{ marginTop: "7px" }}>
          {/* Migration notice */}
          {migrated && (
            <div style={{
              padding: "5px 8px", marginBottom: "6px",
              background: "rgba(56,189,248,0.07)", border: "1px solid rgba(56,189,248,0.35)",
              fontSize: "9px", color: "var(--accent)", letterSpacing: "0.06em",
            }}>
              ℹ Audit log upgraded to SHA-256 chain. Previous signatures reset — all entries preserved.
            </div>
          )}

          {/* Chain broken warning */}
          {integrity && !integrity.valid && (
            <div style={{
              padding: "5px 8px", marginBottom: "6px",
              background: "rgba(248,113,113,0.08)", border: "1px solid var(--danger)",
              fontSize: "9px", color: "var(--danger)", letterSpacing: "0.06em",
            }}>
              ✗ SHA-256 chain broken at entry #{integrity.brokenAt} — one or more entries may have been modified, inserted, or deleted.
            </div>
          )}

          {/* Controls */}
          <div style={{ display: "flex", gap: "4px", marginBottom: "4px" }}>
            <button onClick={() => void handleRefresh()} style={{ fontSize: "8px", padding: "2px 6px", color: "var(--text-dim)", border: "1px solid var(--border)", background: "transparent", letterSpacing: "0.1em" }}>
              REFRESH
            </button>
            <button
              onClick={() => void runVerify()}
              disabled={verifying}
              title="SHA-256 chain — detects structural changes to the log"
              style={{ fontSize: "8px", padding: "2px 6px", color: verifying ? "var(--text-dim)" : "var(--accent)", border: `1px solid ${verifying ? "var(--border)" : "var(--accent)"}`, background: "transparent", letterSpacing: "0.1em" }}
            >
              {verifying ? "…" : "✓ VERIFY"}
            </button>
            <button onClick={handleExport} style={{ fontSize: "8px", padding: "2px 6px", color: "var(--accent2)", border: "1px solid var(--accent2)", background: "transparent", letterSpacing: "0.1em" }}>
              ↓ EXPORT TXT
            </button>
            <button onClick={() => void handleClear()} style={{ fontSize: "8px", padding: "2px 6px", color: "var(--danger)", border: "1px solid var(--danger)", background: "transparent", letterSpacing: "0.1em" }}>
              CLEAR
            </button>
          </div>
          <div style={{ fontSize: "7px", color: "var(--text-dim)", marginBottom: "6px", letterSpacing: "0.04em", opacity: 0.7 }}>
            SQLite · SHA-256 chain · detects structural changes · not forensic-grade
          </div>

          {entries.length === 0 ? (
            <div style={{ fontSize: "10px", color: "var(--text-dim)", padding: "4px 0" }}>
              No audit entries yet.
            </div>
          ) : (
            <div style={{ maxHeight: "180px", overflowY: "auto", background: "#020c10", border: "1px solid var(--border)", padding: "6px 8px" }}>
              {entries.map((e, i) => (
                <div key={i} style={{ fontSize: "9px", lineHeight: "1.7", fontFamily: "monospace" }}>
                  <span style={{ color: "var(--text-dim)" }}>
                    {new Date(e.timestamp).toLocaleTimeString()} {new Date(e.timestamp).toLocaleDateString()}
                  </span>
                  {" "}
                  <span style={{ color: "var(--accent)", letterSpacing: "0.06em" }}>{e.action}</span>
                  {" "}
                  <span style={{ color: "var(--text)" }}>{e.details}</span>
                  {" "}
                  <span style={{ color: "var(--border-hi)", fontSize: "7px" }}>{e.hash?.slice(0, 8)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
