import { useEffect, useState } from "react";
import { updateFinding, deleteFinding, listEvidence } from "../lib/findings";
import type {
  PentestFinding, EvidenceItem, FindingStatus, FindingConfidence,
  FindingSeverity,
} from "../types";
import { CONFIDENCE_LABEL, FINDING_STATUS_LABEL } from "../types";

const SEVERITY_COLOR: Record<FindingSeverity, string> = {
  info:     "var(--text-dim)",
  low:      "var(--success)",
  medium:   "var(--warning)",
  high:     "#f87171",
  critical: "#e11d48",
};

const STATUS_OPTIONS: FindingStatus[] = [
  "draft", "needs_review", "confirmed", "false_positive", "accepted_risk", "remediated",
];

const CONFIDENCE_COLOR: Record<FindingConfidence, string> = {
  observed:  "var(--text-dim)",
  heuristic: "var(--warning)",
  candidate: "#fb923c",
  confirmed: "var(--danger)",
};

interface Props {
  finding: PentestFinding;
  onUpdate: (id: string, patch: Partial<PentestFinding>) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}

function SLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)", marginBottom: "5px" }}>
      <span style={{ color: "var(--accent)", opacity: 0.5 }}>◈</span>
      {children}
      <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
    </div>
  );
}

export function FindingDetail({ finding, onUpdate, onDelete, onClose }: Props) {
  const [editing, setEditing]   = useState(false);
  const [title,   setTitle]     = useState(finding.title);
  const [summary, setSummary]   = useState(finding.summary);
  const [details, setDetails]   = useState(finding.technicalDetails ?? "");
  const [remedy,  setRemedy]    = useState(finding.remediation ?? "");
  const [status,  setStatus]    = useState<FindingStatus>(finding.status);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [saving,   setSaving]   = useState(false);

  useEffect(() => {
    listEvidence(finding.id).then(setEvidence).catch(() => {});
  }, [finding.id]);

  async function handleSave() {
    setSaving(true);
    try {
      await updateFinding(finding.id, {
        title, summary,
        technicalDetails: details || undefined,
        remediation: remedy || undefined,
        status,
      });
      onUpdate(finding.id, { title, summary, technicalDetails: details || undefined, remediation: remedy || undefined, status });
      setEditing(false);
    } catch { /* silently ignored */ } finally {
      setSaving(false);
    }
  }

  async function handleStatusChange(s: FindingStatus) {
    setStatus(s);
    try {
      await updateFinding(finding.id, { status: s });
      onUpdate(finding.id, { status: s });
    } catch { /* silently ignored */ }
  }

  async function handleDelete() {
    if (!window.confirm(`Delete finding "${finding.title}"?`)) return;
    await deleteFinding(finding.id);
    onDelete(finding.id);
  }

  const sevColor = SEVERITY_COLOR[finding.severity];
  const confLabel = CONFIDENCE_LABEL[finding.confidence];
  const confColor = CONFIDENCE_COLOR[finding.confidence];

  return (
    <div style={{ border: "1px solid var(--border)", borderLeft: `2px solid ${sevColor}`, background: "rgba(0,0,0,0.2)", padding: "10px 12px", marginTop: "8px", fontSize: "10px" }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px", flexWrap: "wrap" }}>
        <span style={{ fontSize: "8px", padding: "1px 6px", color: sevColor, border: `1px solid ${sevColor}`, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          {finding.severity}
        </span>
        <span style={{ fontSize: "8px", padding: "1px 6px", color: confColor, border: `1px solid ${confColor}44`, letterSpacing: "0.08em" }}>
          {confLabel}
        </span>
        <span style={{ fontSize: "8px", padding: "1px 6px", color: "var(--text-dim)", border: "1px solid var(--border)", letterSpacing: "0.08em" }}>
          {FINDING_STATUS_LABEL[finding.status]}
        </span>
        <div style={{ flex: 1 }} />
        {!editing && (
          <button onClick={() => setEditing(true)} style={{ fontSize: "8px", padding: "1px 6px", color: "var(--accent2)", border: "1px solid var(--accent2)", background: "transparent", cursor: "pointer" }}>EDIT</button>
        )}
        <button onClick={handleDelete} style={{ fontSize: "8px", padding: "1px 6px", color: "var(--danger)", border: "1px solid var(--danger)", background: "transparent", cursor: "pointer" }}>DELETE</button>
        <button onClick={onClose} style={{ fontSize: "10px", padding: "0 6px", color: "var(--text-dim)", border: "none", background: "transparent", cursor: "pointer" }}>×</button>
      </div>

      {/* Title */}
      {editing ? (
        <input
          value={title}
          onChange={e => setTitle(e.target.value)}
          style={{ width: "100%", padding: "4px 8px", fontSize: "11px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--accent)", outline: "none", marginBottom: "6px" }}
        />
      ) : (
        <div style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--text-hi)", marginBottom: "6px", fontWeight: 600 }}>{finding.title}</div>
      )}

      {/* Affected */}
      <div style={{ fontSize: "9px", color: "var(--text-dim)", marginBottom: "6px" }}>
        {finding.affectedHosts.join(", ")}
        {finding.affectedPorts?.length ? ` · ${finding.affectedPorts.join(", ")}` : ""}
      </div>

      {/* Summary */}
      <div style={{ marginBottom: "6px" }}>
        <SLabel>SUMMARY</SLabel>
        {editing ? (
          <textarea
            value={summary}
            onChange={e => setSummary(e.target.value)}
            rows={3}
            style={{ width: "100%", padding: "4px 8px", fontSize: "10px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--border)", outline: "none", resize: "vertical", fontFamily: "var(--font)" }}
          />
        ) : (
          <div style={{ color: "var(--text)", lineHeight: "1.5" }}>{finding.summary}</div>
        )}
      </div>

      {/* Status selector */}
      <div style={{ marginBottom: "6px" }}>
        <SLabel>STATUS</SLabel>
        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
          {STATUS_OPTIONS.map(s => (
            <button
              key={s}
              onClick={() => void handleStatusChange(s)}
              style={{
                padding: "2px 7px", fontSize: "8px", letterSpacing: "0.06em",
                color:      status === s ? "var(--accent)" : "var(--text-dim)",
                border:     `1px solid ${status === s ? "var(--accent)" : "var(--border)"}`,
                background: status === s ? "var(--accent-dim)" : "transparent",
                cursor: "pointer", transition: "all 0.12s",
              }}
            >
              {FINDING_STATUS_LABEL[s]}
            </button>
          ))}
        </div>
      </div>

      {/* Technical details (edit only) */}
      {editing && (
        <div style={{ marginBottom: "6px" }}>
          <SLabel>TECHNICAL DETAILS</SLabel>
          <textarea
            value={details}
            onChange={e => setDetails(e.target.value)}
            placeholder="Technical notes, reproduction steps…"
            rows={3}
            style={{ width: "100%", padding: "4px 8px", fontSize: "10px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--border)", outline: "none", resize: "vertical", fontFamily: "var(--font)" }}
          />
          <SLabel>REMEDIATION</SLabel>
          <textarea
            value={remedy}
            onChange={e => setRemedy(e.target.value)}
            placeholder="Recommended fix or mitigation…"
            rows={2}
            style={{ width: "100%", padding: "4px 8px", fontSize: "10px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--border)", outline: "none", resize: "vertical", fontFamily: "var(--font)" }}
          />
          <div style={{ display: "flex", gap: "4px", marginTop: "6px" }}>
            <button onClick={() => void handleSave()} disabled={saving} style={{ flex: 1, padding: "3px 0", fontSize: "9px", color: "var(--accent)", border: "1px solid var(--accent)", background: "transparent", cursor: "pointer" }}>
              {saving ? "…" : "SAVE"}
            </button>
            <button onClick={() => { setEditing(false); setTitle(finding.title); setSummary(finding.summary); }} style={{ flex: 1, padding: "3px 0", fontSize: "9px", color: "var(--text-dim)", border: "1px solid var(--border)", background: "transparent", cursor: "pointer" }}>CANCEL</button>
          </div>
        </div>
      )}

      {/* Non-edit detail view */}
      {!editing && finding.technicalDetails && (
        <div style={{ marginBottom: "6px" }}>
          <SLabel>TECHNICAL DETAILS</SLabel>
          <div style={{ color: "var(--text)", lineHeight: "1.5", whiteSpace: "pre-wrap" }}>{finding.technicalDetails}</div>
        </div>
      )}
      {!editing && finding.remediation && (
        <div style={{ marginBottom: "6px" }}>
          <SLabel>REMEDIATION</SLabel>
          <div style={{ color: "var(--text)", lineHeight: "1.5" }}>{finding.remediation}</div>
        </div>
      )}

      {/* Evidence */}
      {evidence.length > 0 && (
        <div style={{ marginTop: "6px" }}>
          <SLabel>EVIDENCE ({evidence.length})</SLabel>
          {evidence.map(ev => (
            <div key={ev.id} style={{ padding: "4px 8px", marginBottom: "3px", background: "rgba(0,0,0,0.25)", border: "1px solid var(--border)", fontSize: "9px" }}>
              <span style={{ color: "var(--accent2)", letterSpacing: "0.08em", marginRight: "6px" }}>{ev.type}</span>
              <span style={{ color: "var(--text-dim)" }}>{ev.excerpt.slice(0, 120)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
