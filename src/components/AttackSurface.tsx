import { useMemo } from "react";
import { hostRiskLevel, RISK_COLOR } from "../lib/riskScore";
import type { HostResult, PentestFinding } from "../types";

interface Props {
  hosts: HostResult[];
  onPrint: () => void;
  findings?: PentestFinding[];
}

const RISK_ORDER = ["critical", "high", "medium", "low", "clean"] as const;

export function AttackSurface({ hosts, onPrint, findings }: Props) {
  const stats = useMemo(() => {
    const totalPorts  = hosts.reduce((s, h) => s + h.ports.filter((p) => p.state === "open").length, 0);
    const riskCounts  = Object.fromEntries(RISK_ORDER.map((r) => [r, 0])) as Record<string, number>;
    let topRisk = "clean";

    for (const h of hosts) {
      const r = hostRiskLevel(h, findings);
      riskCounts[r]++;
      if (RISK_ORDER.indexOf(r as typeof RISK_ORDER[number]) < RISK_ORDER.indexOf(topRisk as typeof RISK_ORDER[number])) {
        topRisk = r;
      }
    }

    // Simple weighted score 0–100
    const score = Math.min(100, Math.round(
      (riskCounts.critical * 20 + riskCounts.high * 10 + riskCounts.medium * 5 + riskCounts.low * 2) /
      Math.max(hosts.length, 1) * 10
    ));

    return { totalPorts, riskCounts, topRisk, score };
  }, [hosts]);

  const topCol = RISK_COLOR[stats.topRisk as keyof typeof RISK_COLOR] ?? "var(--accent)";

  return (
    <div style={{
      margin: "1rem 1rem 0",
      background: "var(--bg-surface)",
      border: `1px solid var(--border)`,
      borderLeft: `2px solid ${topCol}`,
      padding: "8px 10px",
    }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
        <span style={{ fontSize: "9px", letterSpacing: "0.14em", color: "var(--text-dim)" }}>◈ ATTACK SURFACE</span>
        <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
        <span style={{
          fontSize: "9px", letterSpacing: "0.1em", padding: "1px 5px",
          color: topCol, border: `1px solid ${topCol}`,
        }}>
          {stats.topRisk.toUpperCase()}
        </span>
        <button
          onClick={onPrint}
          title="Print / save report as PDF"
          style={{
            fontSize: "9px", padding: "1px 6px", letterSpacing: "0.1em",
            color: "var(--accent2)", border: "1px solid var(--accent2)",
            background: "transparent",
          }}
        >
          ⎙ REPORT
        </button>
      </div>

      {/* Metrics row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "6px" }}>
        {[
          { label: "HOSTS",     value: String(hosts.length)     },
          { label: "OPEN PORTS",value: String(stats.totalPorts) },
          { label: "SCORE",     value: `${stats.score}/100`     },
          { label: "SCRIPTS",   value: String(hosts.reduce((s, h) => s + (h.script_results?.length ?? 0), 0)) },
        ].map(({ label, value }) => (
          <div key={label} style={{ textAlign: "center" as const }}>
            <div style={{ fontSize: "14px", fontFamily: "monospace", color: "var(--text-hi)", fontWeight: 700 }}>
              {value}
            </div>
            <div style={{ fontSize: "8px", color: "var(--text-dim)", letterSpacing: "0.1em" }}>
              {label}
            </div>
          </div>
        ))}
      </div>

      {/* Risk distribution bar */}
      <div style={{ marginTop: "7px", display: "flex", gap: "3px", alignItems: "center" }}>
        {RISK_ORDER.map((r) => {
          const count = stats.riskCounts[r] ?? 0;
          if (count === 0) return null;
          return (
            <div key={r} title={`${count} ${r}`} style={{
              flex: count,
              height: "4px",
              background: RISK_COLOR[r as keyof typeof RISK_COLOR],
              borderRadius: "2px",
              minWidth: "6px",
            }} />
          );
        })}
        <span style={{ fontSize: "8px", color: "var(--text-dim)", marginLeft: "4px", letterSpacing: "0.08em", flexShrink: 0 }}>
          {RISK_ORDER.map((r) => stats.riskCounts[r] > 0 ? `${r[0].toUpperCase()}:${stats.riskCounts[r]}` : null).filter(Boolean).join(" ")}
        </span>
      </div>
    </div>
  );
}
