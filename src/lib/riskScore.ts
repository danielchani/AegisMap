import { getAdvisory } from "../data/cveHints";
import type { HostResult, PentestFinding } from "../types";

export type RiskLevel = "clean" | "low" | "medium" | "high" | "critical";

const SEVERITY_SCORE: Record<string, number> = {
  info: 1, low: 2, medium: 3, high: 4, critical: 5,
};

export function hostRiskLevel(host: HostResult, findings?: PentestFinding[]): RiskLevel {
  let max = 0;
  for (const p of host.ports.filter((p) => p.state === "open")) {
    const adv = getAdvisory(p.port, p.service);
    if (adv) max = Math.max(max, SEVERITY_SCORE[adv.severity] ?? 0);
  }
  if (findings) {
    for (const f of findings) {
      if (
        f.affectedHosts.includes(host.address) &&
        f.status !== "false_positive" &&
        f.status !== "remediated"
      ) {
        max = Math.max(max, SEVERITY_SCORE[f.severity] ?? 0);
      }
    }
  }
  if (max >= 5) return "critical";
  if (max >= 4) return "high";
  if (max >= 3) return "medium";
  if (max >= 2) return "low";
  return "clean";
}

export const RISK_COLOR: Record<RiskLevel, string> = {
  clean:    "#4ade80",
  low:      "#a3e635",
  medium:   "#fb923c",
  high:     "#f87171",
  critical: "#e11d48",
};

export const RISK_LABEL: Record<RiskLevel, string> = {
  clean:    "CLEAN",
  low:      "LOW",
  medium:   "MEDIUM",
  high:     "HIGH",
  critical: "CRITICAL",
};
