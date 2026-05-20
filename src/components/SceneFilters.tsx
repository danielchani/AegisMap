/**
 * 3D scene filtering controls — overlay on the visualization canvas.
 * Supports three modes: Network (default), Diff, and Confidence.
 */

import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { RISK_COLOR, type RiskLevel } from "../lib/riskScore";
import { DIFF_COLOR, CONFIDENCE_COLOR, getConfidenceTier } from "../lib/sceneMode";
import type { SceneMode } from "../types";
import type { SessionDiffReport } from "../lib/sessionDiff";

interface ListedSession {
  id: string;
  name: string;
  savedAt: string;
  hostCount: number;
}

interface Props {
  // Existing
  visibleRiskLevels: Set<string>;
  onToggleRiskLevel: (level: string) => void;
  showLabels: boolean;
  onToggleLabels: () => void;
  showConnections: boolean;
  onToggleConnections: () => void;
  hostCount: number;
  // Mode
  sceneMode: SceneMode;
  onSceneModeChange: (mode: SceneMode) => void;
  // Diff
  diffReport?: SessionDiffReport | null;
  diffBaselineName?: string;
  onLoadDiffBaseline?: (id: string, name: string) => void;
  visibleDiffStates: Set<string>;
  onToggleDiffState: (state: string) => void;
  // Confidence
  confidenceMap?: Map<string, number>;
}

const RISK_LEVELS: Array<{ key: RiskLevel; label: string }> = [
  { key: "critical", label: "CRIT" },
  { key: "high",     label: "HIGH" },
  { key: "medium",   label: "MED" },
  { key: "low",      label: "LOW" },
  { key: "clean",    label: "OK" },
];

const DIFF_STATES = [
  { key: "added",     label: "⊕ ADDED",   color: DIFF_COLOR.added },
  { key: "removed",   label: "⊖ REMOVED", color: DIFF_COLOR.removed },
  { key: "changed",   label: "◆ CHANGED", color: DIFF_COLOR.changed },
  { key: "unchanged", label: "— SAME",    color: "#64748b" },
];

const SCENE_MODES: Array<{ key: SceneMode; label: string }> = [
  { key: "network",    label: "NETWORK" },
  { key: "diff",       label: "DIFF" },
  { key: "confidence", label: "CONFIDENCE" },
];

export function SceneFilters({
  visibleRiskLevels, onToggleRiskLevel,
  showLabels, onToggleLabels,
  showConnections, onToggleConnections,
  hostCount,
  sceneMode, onSceneModeChange,
  diffReport, diffBaselineName, onLoadDiffBaseline,
  visibleDiffStates, onToggleDiffState,
  confidenceMap,
}: Props) {
  const [expanded,      setExpanded]      = useState(false);
  const [savedSessions, setSavedSessions] = useState<ListedSession[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(false);

  // Load session list when entering diff mode or when panel expands in diff mode
  useEffect(() => {
    if (sceneMode === "diff" && expanded) {
      setLoadingSessions(true);
      invoke<ListedSession[]>("list_named_sessions")
        .then(setSavedSessions)
        .catch(() => setSavedSessions([]))
        .finally(() => setLoadingSessions(false));
    }
  }, [sceneMode, expanded]);

  if (hostCount === 0) return null;

  // Confidence tier summary
  const confidenceTierCounts = confidenceMap
    ? (() => {
        let high = 0, medium = 0, low = 0;
        for (const v of confidenceMap.values()) {
          const t = getConfidenceTier(v);
          if (t === "high") high++;
          else if (t === "medium") medium++;
          else low++;
        }
        return { high, medium, low };
      })()
    : null;

  return (
    <div style={{
      position: "absolute", top: "10px", left: "10px", zIndex: 10,
      display: "flex", flexDirection: "column", gap: "4px",
    }}>
      {/* Toggle button — label changes by mode */}
      <button
        onClick={() => setExpanded((e) => !e)}
        style={{
          fontSize: "9px", padding: "4px 8px", letterSpacing: "0.1em",
          background: "rgba(2,11,24,0.85)",
          color: expanded ? "var(--accent)" : "var(--text-dim)",
          border: `1px solid ${expanded ? "var(--accent)" : "var(--border)"}`,
          cursor: "pointer", backdropFilter: "blur(8px)", transition: "all 0.15s",
        }}
      >
        {sceneMode === "diff"       ? "◈ DIFF MODE" :
         sceneMode === "confidence" ? "◈ CONFIDENCE MODE" :
         "⚙ FILTERS"} {expanded ? "▲" : "▼"}
      </button>

      {expanded && (
        <div style={{
          background: "rgba(2,11,24,0.92)", border: "1px solid var(--border)",
          padding: "8px", backdropFilter: "blur(8px)",
          display: "flex", flexDirection: "column", gap: "8px", minWidth: "168px",
        }}>

          {/* ── Scene mode selector ─────────────────────────────── */}
          <div>
            <div style={{ fontSize: "8px", letterSpacing: "0.14em", color: "var(--text-dim)", marginBottom: "4px" }}>
              SCENE MODE
            </div>
            <div style={{ display: "flex", gap: "3px" }}>
              {SCENE_MODES.map(({ key, label }) => {
                const active = sceneMode === key;
                return (
                  <button key={key} onClick={() => onSceneModeChange(key)}
                    style={{
                      flex: 1, padding: "2px 4px", fontSize: "7px", letterSpacing: "0.06em",
                      color: active ? "#020b18" : "var(--text-dim)",
                      background: active ? "var(--accent)" : "transparent",
                      border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                      cursor: "pointer", transition: "all 0.12s",
                    }}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* ── Network mode: risk levels + display toggles ────────── */}
          {sceneMode === "network" && (
            <>
              <div>
                <div style={{ fontSize: "8px", letterSpacing: "0.14em", color: "var(--text-dim)", marginBottom: "4px" }}>
                  RISK LEVELS
                </div>
                <div style={{ display: "flex", gap: "3px", flexWrap: "wrap" }}>
                  {RISK_LEVELS.map(({ key, label }) => {
                    const active = visibleRiskLevels.has(key);
                    return (
                      <button key={key} onClick={() => onToggleRiskLevel(key)} style={{
                        padding: "2px 5px", fontSize: "7px", letterSpacing: "0.08em",
                        color: active ? RISK_COLOR[key] : "var(--text-dim)",
                        background: active ? `${RISK_COLOR[key]}18` : "transparent",
                        border: `1px solid ${active ? RISK_COLOR[key] : "var(--border)"}`,
                        cursor: "pointer", transition: "all 0.12s", opacity: active ? 1 : 0.5,
                      }}>
                        {label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
                {[
                  { active: showLabels,      onToggle: onToggleLabels,      color: "var(--accent)",  label: "HOST LABELS" },
                  { active: showConnections, onToggle: onToggleConnections,  color: "var(--accent2)", label: "CONNECTIONS" },
                ].map(({ active, onToggle, color, label }) => (
                  <label key={label} style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "8px", color: "var(--text-dim)", cursor: "pointer", letterSpacing: "0.08em" }}>
                    <span style={{
                      width: "10px", height: "10px",
                      border: `1px solid ${active ? color : "var(--border)"}`,
                      background: active ? `${color}22` : "transparent",
                      display: "inline-flex", alignItems: "center", justifyContent: "center",
                      fontSize: "7px", color,
                    }} onClick={onToggle}>
                      {active ? "✓" : ""}
                    </span>
                    <span onClick={onToggle}>{label}</span>
                  </label>
                ))}
              </div>
            </>
          )}

          {/* ── Diff mode controls ──────────────────────────────── */}
          {sceneMode === "diff" && (
            <>
              {/* Session picker */}
              <div>
                <div style={{ fontSize: "8px", letterSpacing: "0.14em", color: "var(--text-dim)", marginBottom: "4px" }}>
                  COMPARE WITH
                </div>
                {loadingSessions ? (
                  <div style={{ fontSize: "8px", color: "var(--text-dim)" }}>Loading sessions…</div>
                ) : savedSessions.length === 0 ? (
                  <div style={{ fontSize: "8px", color: "var(--text-dim)" }}>No saved sessions.</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: "2px", maxHeight: "120px", overflowY: "auto" }}>
                    {savedSessions.map((s) => {
                      const active = diffBaselineName === s.name;
                      return (
                        <button key={s.id}
                          onClick={() => onLoadDiffBaseline?.(s.id, s.name)}
                          style={{
                            textAlign: "left", padding: "3px 6px", fontSize: "8px",
                            color: active ? "var(--accent)" : "var(--text-hi)",
                            background: active ? "rgba(0,255,170,0.08)" : "transparent",
                            border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                            cursor: "pointer", letterSpacing: "0.04em",
                          }}
                        >
                          <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "140px" }}>
                            {s.name}
                          </span>
                          <span style={{ fontSize: "7px", color: "var(--text-dim)" }}>
                            {s.hostCount} host{s.hostCount !== 1 ? "s" : ""} · {new Date(s.savedAt).toLocaleDateString()}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Diff summary */}
              {diffReport && (
                <div style={{ fontSize: "8px", letterSpacing: "0.06em", display: "flex", flexWrap: "wrap", gap: "4px" }}>
                  {diffReport.hostsAdded > 0 && (
                    <span style={{ color: DIFF_COLOR.added }}>⊕{diffReport.hostsAdded}</span>
                  )}
                  {diffReport.hostsRemoved > 0 && (
                    <span style={{ color: "#94a3b8" }}>⊖{diffReport.hostsRemoved}</span>
                  )}
                  {diffReport.hostsChanged > 0 && (
                    <span style={{ color: DIFF_COLOR.changed }}>◆{diffReport.hostsChanged}</span>
                  )}
                  {diffReport.hostsUnchanged > 0 && (
                    <span style={{ color: "var(--text-dim)" }}>—{diffReport.hostsUnchanged}</span>
                  )}
                </div>
              )}

              {/* Diff state toggles */}
              {diffReport && (
                <div>
                  <div style={{ fontSize: "8px", letterSpacing: "0.14em", color: "var(--text-dim)", marginBottom: "4px" }}>
                    SHOW / HIDE
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                    {DIFF_STATES.map(({ key, label, color }) => {
                      const active = visibleDiffStates.has(key);
                      return (
                        <button key={key} onClick={() => onToggleDiffState(key)} style={{
                          textAlign: "left", padding: "2px 5px", fontSize: "7px",
                          letterSpacing: "0.08em",
                          color: active ? color : "var(--text-dim)",
                          background: active ? `${color}14` : "transparent",
                          border: `1px solid ${active ? color : "var(--border)"}`,
                          cursor: "pointer", opacity: active ? 1 : 0.55,
                        }}>
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── Confidence mode controls ────────────────────────── */}
          {sceneMode === "confidence" && (
            <>
              <div>
                <div style={{ fontSize: "8px", letterSpacing: "0.14em", color: "var(--text-dim)", marginBottom: "5px" }}>
                  CONFIDENCE LEGEND
                </div>
                {[
                  { tier: "high",   label: "HIGH ≥75",  count: confidenceTierCounts?.high   ?? 0, color: CONFIDENCE_COLOR.high },
                  { tier: "medium", label: "MED 45–74", count: confidenceTierCounts?.medium ?? 0, color: CONFIDENCE_COLOR.medium },
                  { tier: "low",    label: "LOW <45",   count: confidenceTierCounts?.low    ?? 0, color: CONFIDENCE_COLOR.low },
                ].map(({ label, count, color }) => (
                  <div key={label} style={{ display: "flex", alignItems: "center", gap: "5px", marginBottom: "3px", fontSize: "8px" }}>
                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: color, flexShrink: 0 }} />
                    <span style={{ color: "var(--text-dim)", letterSpacing: "0.06em" }}>{label}</span>
                    <span style={{ marginLeft: "auto", color, fontFamily: "monospace", fontSize: "9px" }}>{count}</span>
                  </div>
                ))}
              </div>
              <div style={{ fontSize: "7px", color: "var(--text-dim)", letterSpacing: "0.06em", lineHeight: 1.5 }}>
                Arc ring = confidence %<br />
                Select a host to see breakdown
              </div>
            </>
          )}

        </div>
      )}
    </div>
  );
}
