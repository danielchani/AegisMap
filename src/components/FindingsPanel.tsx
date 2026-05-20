import { useState } from "react";
import { createFinding, deleteFinding } from "../lib/findings";
import { FindingDetail } from "./FindingDetail";
import type {
  PentestFinding, FindingSeverity, FindingStatus, FindingConfidence,
} from "../types";
import { CONFIDENCE_LABEL, FINDING_STATUS_LABEL } from "../types";

const SEVERITY_COLOR: Record<FindingSeverity, string> = {
  info: "var(--text-dim)", low: "var(--success)", medium: "var(--warning)",
  high: "#f87171", critical: "#e11d48",
};

interface Props {
  sessionId: string;
  findings: PentestFinding[];
  onFindingsChange: (findings: PentestFinding[]) => void;
}

type SevFilter = "all" | FindingSeverity;
type StatusFilter = "all" | FindingStatus;

export function FindingsPanel({ sessionId, findings, onFindingsChange }: Props) {
  const [sevFilter,    setSevFilter]    = useState<SevFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [selectedId,   setSelectedId]   = useState<string | null>(null);
  const [creating,     setCreating]     = useState(false);

  // New finding form state
  const [newTitle,   setNewTitle]   = useState("");
  const [newSev,     setNewSev]     = useState<FindingSeverity>("medium");
  const [newSummary, setNewSummary] = useState("");
  const [saving,     setSaving]     = useState(false);

  const filtered = findings.filter(f => {
    if (sevFilter !== "all" && f.severity !== sevFilter) return false;
    if (statusFilter !== "all" && f.status !== statusFilter) return false;
    return true;
  });

  const selectedFinding = findings.find(f => f.id === selectedId) ?? null;

  async function handleCreate() {
    if (!newTitle.trim() || !newSummary.trim()) return;
    setSaving(true);
    try {
      const id = await createFinding({
        sessionId,
        title:         newTitle.trim(),
        severity:      newSev,
        confidence:    "observed" as FindingConfidence,
        status:        "draft",
        affectedHosts: [],
        summary:       newSummary.trim(),
        source:        "analyst",
      });
      // Refresh list
      const newFinding: PentestFinding = {
        id, sessionId, title: newTitle.trim(), severity: newSev,
        confidence: "observed", status: "draft", affectedHosts: [],
        summary: newSummary.trim(), source: "analyst", evidenceIds: [],
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      };
      onFindingsChange([newFinding, ...findings]);
      setCreating(false);
      setNewTitle(""); setNewSummary(""); setNewSev("medium");
      setSelectedId(id);
    } catch (err) { console.error("[AegisMap] Finding create failed:", err); } finally {
      setSaving(false);
    }
  }

  function handleUpdate(id: string, patch: Partial<PentestFinding>) {
    onFindingsChange(findings.map(f => f.id === id ? { ...f, ...patch } : f));
  }

  function handleDelete(id: string) {
    onFindingsChange(findings.filter(f => f.id !== id));
    if (selectedId === id) setSelectedId(null);
  }

  const severityOptions: SevFilter[] = ["all", "critical", "high", "medium", "low", "info"];
  const statusOptions: StatusFilter[] = ["all", "draft", "needs_review", "confirmed", "false_positive", "accepted_risk", "remediated"];

  function chipStyle(active: boolean, color: string) {
    return {
      padding: "2px 8px", fontSize: "8px", letterSpacing: "0.1em",
      color:      active ? color : "var(--text-dim)",
      border:     `1px solid ${active ? color : "var(--border)"}`,
      background: active ? `${color}15` : "transparent",
      cursor: "pointer", transition: "all 0.12s",
    };
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "10px", padding: "8px 12px" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)" }}>
          ◈ FINDINGS
        </span>
        <span style={{ fontSize: "8px", color: "var(--accent)", background: "var(--accent-dim)", padding: "1px 5px" }}>
          {findings.length}
        </span>
        <div style={{ flex: 1 }} />
        <button
          onClick={() => setCreating(c => !c)}
          style={{ fontSize: "9px", padding: "2px 8px", color: "var(--accent)", border: "1px solid var(--accent)", background: creating ? "var(--accent-dim)" : "transparent", cursor: "pointer", letterSpacing: "0.08em" }}
        >
          + NEW FINDING
        </button>
      </div>

      {/* New finding form */}
      {creating && (
        <div style={{ border: "1px solid var(--accent)", padding: "8px 10px", background: "var(--accent-dim)" }}>
          <div style={{ fontSize: "9px", letterSpacing: "0.1em", color: "var(--accent)", marginBottom: "6px" }}>NEW FINDING</div>
          <input
            autoFocus
            value={newTitle}
            onChange={e => setNewTitle(e.target.value)}
            placeholder="Title…"
            style={{ width: "100%", padding: "4px 8px", fontSize: "11px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--border)", outline: "none", marginBottom: "5px" }}
          />
          <div style={{ display: "flex", gap: "4px", marginBottom: "5px" }}>
            {(["info","low","medium","high","critical"] as FindingSeverity[]).map(s => (
              <button key={s} onClick={() => setNewSev(s)} style={{ flex:1, padding:"2px 0", fontSize:"8px", textTransform:"uppercase", color: newSev===s ? SEVERITY_COLOR[s] : "var(--text-dim)", border:`1px solid ${newSev===s ? SEVERITY_COLOR[s] : "var(--border)"}`, background:"transparent", cursor:"pointer" }}>{s}</button>
            ))}
          </div>
          <textarea
            value={newSummary}
            onChange={e => setNewSummary(e.target.value)}
            placeholder="Observation summary…"
            rows={2}
            style={{ width: "100%", padding: "4px 8px", fontSize: "10px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--border)", outline: "none", resize: "vertical", fontFamily: "var(--font)", marginBottom: "5px" }}
          />
          <div style={{ display: "flex", gap: "4px" }}>
            <button onClick={() => void handleCreate()} disabled={!newTitle.trim() || !newSummary.trim() || saving} style={{ flex:1, padding:"3px 0", fontSize:"9px", color:"var(--accent)", border:"1px solid var(--accent)", background:"transparent", cursor:"pointer" }}>{saving ? "…" : "CREATE"}</button>
            <button onClick={() => setCreating(false)} style={{ flex:1, padding:"3px 0", fontSize:"9px", color:"var(--text-dim)", border:"1px solid var(--border)", background:"transparent", cursor:"pointer" }}>CANCEL</button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
        <div style={{ display: "flex", gap: "3px", flexWrap: "wrap" }}>
          {severityOptions.map(s => (
            <button key={s} onClick={() => setSevFilter(s)} style={chipStyle(sevFilter === s, s === "all" ? "var(--accent)" : SEVERITY_COLOR[s as FindingSeverity])}>
              {s.toUpperCase()}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", gap: "3px", flexWrap: "wrap" }}>
          {statusOptions.map(s => (
            <button key={s} onClick={() => setStatusFilter(s)} style={chipStyle(statusFilter === s, "var(--accent2)")}>
              {s === "all" ? "ALL STATUS" : FINDING_STATUS_LABEL[s as FindingStatus]}
            </button>
          ))}
        </div>
      </div>

      {/* Findings table */}
      {filtered.length === 0 ? (
        <div style={{ fontSize: "11px", color: "var(--text-dim)", padding: "12px 0", textAlign: "center" }}>
          {findings.length === 0
            ? "No findings yet. Use CVE/advisory badges or + NEW FINDING to add one."
            : "No findings match the current filters."}
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)" }}>
          {/* Table header */}
          <div style={{ display: "grid", gridTemplateColumns: "56px 1fr 90px 80px 56px", padding: "4px 8px", fontSize: "8px", letterSpacing: "0.12em", color: "var(--text-dim)", borderBottom: "1px solid var(--border)", background: "rgba(0,0,0,0.2)" }}>
            <span>SEV</span><span>TITLE</span><span>CONFIDENCE</span><span>STATUS</span><span />
          </div>
          {filtered.map(f => (
            <div
              key={f.id}
              onClick={() => setSelectedId(selectedId === f.id ? null : f.id)}
              style={{
                display: "grid", gridTemplateColumns: "56px 1fr 90px 80px 56px",
                padding: "6px 8px", fontSize: "10px", cursor: "pointer",
                borderBottom: "1px solid var(--border)",
                background: selectedId === f.id ? "rgba(56,189,248,0.05)" : "transparent",
                alignItems: "center",
              }}
            >
              <span style={{ fontSize: "8px", padding: "1px 5px", color: SEVERITY_COLOR[f.severity], border: `1px solid ${SEVERITY_COLOR[f.severity]}44`, letterSpacing: "0.06em", textAlign: "center" }}>
                {f.severity.toUpperCase()}
              </span>
              <span style={{ color: "var(--text-hi)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingLeft: "4px" }}>
                {f.title}
              </span>
              <span style={{ fontSize: "8px", color: "var(--text-dim)", letterSpacing: "0.04em" }}>
                {CONFIDENCE_LABEL[f.confidence]}
              </span>
              <span style={{ fontSize: "8px", color: "var(--text-dim)" }}>
                {FINDING_STATUS_LABEL[f.status]}
              </span>
              <button
                onClick={e => { e.stopPropagation(); void deleteFinding(f.id).then(() => handleDelete(f.id)); }}
                style={{ fontSize: "11px", color: "var(--text-dim)", border: "none", background: "transparent", cursor: "pointer" }}
              >×</button>
            </div>
          ))}
        </div>
      )}

      {/* Inline detail */}
      {selectedFinding && (
        <FindingDetail
          finding={selectedFinding}
          onUpdate={handleUpdate}
          onDelete={handleDelete}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}
      