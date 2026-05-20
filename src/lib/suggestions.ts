/**
 * Rule-based scan strategy suggestion engine.
 *
 * Pure function: (host, confidence) → ScanSuggestion[]
 * No side effects, no network calls, fully testable.
 *
 * Wording rules (enforced by design):
 *  - Never use "vulnerability" or "confirmed" for unverified items.
 *  - Use "consider", "inspect", "review", "verify" — not "exploit" or "attack".
 *  - Always show a brief rationale so the analyst understands why.
 */

import type { HostResult, ScanProfile } from "../types";
import type { FingerprintConfidence } from "./fingerprint";
import { getVersionAdvisory } from "../data/knownVersions";
import { hostRiskLevel } from "./riskScore";
import { WEB_PORTS, TLS_PORTS } from "./ports";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ScanSuggestion {
  id: string;
  priority: "high" | "medium" | "low";
  /** Short, action-oriented title (≤70 chars). Never uses "vulnerability" for candidates. */
  title: string;
  /** One-sentence explanation of why this is suggested. */
  rationale: string;
  action?: SuggestionAction;
}

export type SuggestionAction =
  | { type: "rescan";        profile: ScanProfile; scripts?: string[] }
  | { type: "probe";         probeType: "http" | "tls" | "dns" }
  | { type: "navigate";      tab: "findings" | "audit" }
  | { type: "create_finding" };

// ── Core function ─────────────────────────────────────────────────────────────

/**
 * Generates up to 4 prioritised suggestions for a host.
 * Rules are deterministic and rely only on observable host data.
 */
export function generateHostSuggestions(
  host: HostResult,
  confidence: FingerprintConfidence,
): ScanSuggestion[] {
  const open = host.ports.filter((p) => p.state === "open");
  if (open.length === 0) return [];

  const hasWebPort = open.some(
    (p) => WEB_PORTS.has(p.port) || p.service.toLowerCase().includes("http"),
  );
  const hasTlsPort = open.some(
    (p) =>
      TLS_PORTS.has(p.port) ||
      p.service.toLowerCase().includes("https") ||
      p.service.toLowerCase().includes("ssl"),
  );
  const hasEolAdvisory = open.some(
    (p) => getVersionAdvisory(p.product, p.version)?.type === "eol",
  );
  const risk = hostRiskLevel(host);
  const hasNewPorts = (host.portsDiff?.added.length ?? 0) > 0;

  const all: ScanSuggestion[] = [];

  // ── HIGH priority ─────────────────────────────────────────────────────────

  if (confidence.breakdown.serviceDetection < 50) {
    all.push({
      id: "svc-detect",
      priority: "high",
      title: "Run service detection to identify versions",
      rationale:
        "Version data is missing for most open ports — needed to evaluate advisories accurately.",
      action: { type: "rescan", profile: "light_service_detection" },
    });
  }

  if (hasNewPorts) {
    all.push({
      id: "new-port",
      priority: "high",
      title: "New port appeared since last scan — review change",
      rationale:
        "A port not seen in the previous scan is now open. Consider documenting it as a finding.",
      action: { type: "navigate", tab: "findings" },
    });
  }

  if (risk === "critical" || risk === "high") {
    all.push({
      id: "cve-review",
      priority: "high",
      title: "High-risk advisories present — review findings",
      rationale:
        "CVE candidates or high-severity advisories detected on this host. Review and promote relevant items.",
      action: { type: "navigate", tab: "findings" },
    });
  }

  if (hasEolAdvisory) {
    all.push({
      id: "eol-finding",
      priority: "high",
      title: "End-of-life software detected — create a finding",
      rationale:
        "One or more services run end-of-life software. Document the risk for tracking and remediation.",
      action: { type: "create_finding" },
    });
  }

  // ── MEDIUM priority ───────────────────────────────────────────────────────

  if (hasWebPort && !host.httpProbes?.length) {
    all.push({
      id: "http-probe",
      priority: "medium",
      title: "HTTP probe not run on detected web port",
      rationale:
        "Web surface intelligence (headers, page title, security headers) has not been collected yet.",
      action: { type: "probe", probeType: "http" },
    });
  }

  if (hasTlsPort && !host.tlsProbes?.length) {
    all.push({
      id: "tls-probe",
      priority: "medium",
      title: "TLS probe not run — certificate chain unknown",
      rationale:
        "HTTPS port found but certificate validity, cipher suite, and expiry have not been checked.",
      action: { type: "probe", probeType: "tls" },
    });
  }

  if (confidence.breakdown.scriptEnrichment < 30) {
    all.push({
      id: "nse-scripts",
      priority: "medium",
      title: "NSE script enrichment is low — enable scripts",
      rationale:
        "Banner and service metadata is sparse. Enable banner + ssl-cert scripts for deeper enumeration.",
      action: {
        type: "rescan",
        profile: "light_service_detection",
        scripts: ["banner", "ssl-cert", "http-title"],
      },
    });
  }

  // ── LOW priority ──────────────────────────────────────────────────────────

  if (confidence.breakdown.osDetection === 0 && open.length >= 3) {
    all.push({
      id: "os-detect",
      priority: "low",
      title: "OS not detected — consider OS fingerprinting",
      rationale:
        "With 3+ open ports, OS detection has a reasonable chance of success (requires root/admin).",
      action: { type: "rescan", profile: "os_detect" },
    });
  }

  if (host.hostname && !host.dnsResults?.length) {
    all.push({
      id: "dns-query",
      priority: "low",
      title: "DNS identity not verified for this host",
      rationale:
        "Hostname is known but PTR/forward verification and DNS records have not been collected.",
      action: { type: "probe", probeType: "dns" },
    });
  }

  // ── Deduplicate + sort + limit ────────────────────────────────────────────

  const seen = new Set<string>();
  const unique = all.filter((s) => (seen.has(s.id) ? false : (seen.add(s.id), true)));
  const order = { high: 0, medium: 1, low: 2 } as const;
  unique.sort((a, b) => order[a.priority] - order[b.priority]);
  return unique.slice(0, 4);
}
