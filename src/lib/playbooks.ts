/**
 * Recon Playbook definitions for AegisMap.
 *
 * Playbooks are user-guided workflows. Every "active" step requires explicit
 * user approval before a scan or probe is launched. No step silently executes.
 *
 * Design rules:
 * - "passive" steps = analysis/review; auto-advance after display.
 * - "active"  steps = scan/probe; wait for user confirmation.
 * - condition() gates whether a step applies to a given host (skip if false).
 * - All scan actions use safe, fixed profiles — no arbitrary flag passthrough.
 */

import type { HostResult, ScanProfile } from "../types";
import { WEB_PORTS, TLS_PORTS } from "./ports";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface PlaybookStep {
  id: string;
  label: string;
  /** Displayed in the step card — explains what will happen and why. */
  description: string;
  type: "passive" | "active";
  /** What this step triggers if confirmed (active) or shown (passive). */
  action?: PlaybookStepAction;
  /**
   * Optional guard: step is skipped if this returns false for the current host.
   * E.g., skip HTTP probe if no web port exists.
   */
  condition?: (host: HostResult) => boolean;
}

export type PlaybookStepAction =
  | { type: "scan";   profile: ScanProfile; scripts?: string[] }
  | { type: "probe";  probeType: "http" | "tls" | "dns" }
  | { type: "review"; target: "advisories" | "findings" | "diff" };

export interface Playbook {
  id: string;
  name: string;
  /** One-line description shown in the launcher. */
  description: string;
  steps: PlaybookStep[];
}

export interface PlaybookRun {
  playbook: Playbook;
  hostAddress: string;
  currentStep: number;
  /** Steps skipped due to condition() returning false. */
  skippedSteps: Set<string>;
  status: "active" | "complete" | "cancelled";
}

// ── Port helpers ──────────────────────────────────────────────────────────────

function hasWebPort(host: HostResult): boolean {
  return host.ports.some(
    (p) => p.state === "open" && (WEB_PORTS.has(p.port) || p.service.toLowerCase().includes("http")),
  );
}

function hasTlsPort(host: HostResult): boolean {
  return host.ports.some(
    (p) =>
      p.state === "open" &&
      (TLS_PORTS.has(p.port) ||
       p.service.toLowerCase().includes("https") ||
       p.service.toLowerCase().includes("ssl")),
  );
}

// ── Playbook definitions ──────────────────────────────────────────────────────

export const PLAYBOOKS: Playbook[] = [

  // ── 1. External Host Review ─────────────────────────────────────────────────
  {
    id: "external-host-review",
    name: "External Host Review",
    description: "Guided surface scan + enrichment for an Internet-facing host.",
    steps: [
      {
        id: "review-ports",
        label: "Review current ports and advisories",
        description:
          "Inspect the open ports, service advisories, and CVE indicators already detected. " +
          "This step is passive — no scan is launched.",
        type: "passive",
        action: { type: "review", target: "advisories" },
      },
      {
        id: "service-detect",
        label: "Service detection",
        description:
          "Run Light Service Detection to collect version strings for all open ports. " +
          "Profile: SERVICE (-sV). No NSE scripts. No aggressive probing.",
        type: "active",
        action: { type: "scan", profile: "light_service_detection" },
      },
      {
        id: "http-probe",
        label: "HTTP surface probe",
        description:
          "Probe detected web ports for HTTP headers, page title, security headers " +
          "(HSTS, CSP, X-Frame-Options, etc.), and technology hints.",
        type: "active",
        action: { type: "probe", probeType: "http" },
        condition: hasWebPort,
      },
      {
        id: "tls-probe",
        label: "TLS certificate probe",
        description:
          "Inspect the TLS certificate chain, expiry date, cipher suite, and hostname " +
          "verification. Results reveal certificate issues without active exploitation.",
        type: "active",
        action: { type: "probe", probeType: "tls" },
        condition: hasTlsPort,
      },
      {
        id: "dns-query",
        label: "DNS identity check",
        description:
          "Query DNS records to verify the hostname, collect MX/NS/TXT records, " +
          "and check PTR forward-verification. Identifies CDN/proxy infrastructure.",
        type: "active",
        action: { type: "probe", probeType: "dns" },
        condition: (h) => !!h.hostname,
      },
      {
        id: "review-findings",
        label: "Review advisories and create findings",
        description:
          "Review any advisories surfaced during this playbook. " +
          "Promote items to Findings for tracking and reporting.",
        type: "passive",
        action: { type: "review", target: "findings" },
      },
    ],
  },

  // ── 2. Web-Facing Asset Review ──────────────────────────────────────────────
  {
    id: "web-asset-review",
    name: "Web-Facing Asset Review",
    description: "HTTP security header analysis and TLS certificate inspection.",
    steps: [
      {
        id: "check-fingerprint",
        label: "Review fingerprint confidence",
        description:
          "Check the current fingerprint confidence score. " +
          "Low service detection means advisory accuracy may be reduced.",
        type: "passive",
      },
      {
        id: "http-probe",
        label: "HTTP surface probe",
        description:
          "Probe web ports for security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, " +
          "Permissions-Policy), page title, redirect chain, and technology hints.",
        type: "active",
        action: { type: "probe", probeType: "http" },
        condition: hasWebPort,
      },
      {
        id: "tls-probe",
        label: "TLS certificate inspection",
        description:
          "Inspect certificate validity, expiry date, issuer, SAN entries, cipher strength, " +
          "and hostname verification. Weak ciphers and near-expiry certs are flagged.",
        type: "active",
        action: { type: "probe", probeType: "tls" },
        condition: hasTlsPort,
      },
      {
        id: "review-headers",
        label: "Review security header posture",
        description:
          "Review the HTTP probe results for missing security headers. " +
          "Consider creating findings for absent HSTS or missing CSP.",
        type: "passive",
        action: { type: "review", target: "findings" },
      },
    ],
  },

  // ── 3. High-Risk Host Follow-Up ─────────────────────────────────────────────
  {
    id: "high-risk-followup",
    name: "High-Risk Host Follow-Up",
    description: "CVE candidate verification and evidence collection for critical hosts.",
    steps: [
      {
        id: "review-candidates",
        label: "Review CVE candidates in Findings",
        description:
          "Open the Findings tab and review any CVE candidate items. " +
          "These are version-matched candidates — not confirmed issues.",
        type: "passive",
        action: { type: "review", target: "findings" },
      },
      {
        id: "confirm-versions",
        label: "Confirm service versions",
        description:
          "Run Service Detection to verify the version strings that matched CVE patterns. " +
          "Profile: SERVICE (-sV). Accurate versions improve advisory confidence.",
        type: "active",
        action: { type: "scan", profile: "light_service_detection" },
      },
      {
        id: "collect-banners",
        label: "Collect service banners",
        description:
          "Run banner grab + ssl-cert scripts to collect additional evidence. " +
          "This information can be attached as evidence to findings.",
        type: "active",
        action: { type: "scan", profile: "light_service_detection", scripts: ["banner", "ssl-cert"] },
      },
      {
        id: "promote-findings",
        label: "Promote candidates to Needs Review",
        description:
          "Update CVE candidate findings to 'needs_review' status for confirmed version matches. " +
          "Add technical notes and any relevant evidence excerpts.",
        type: "passive",
        action: { type: "review", target: "findings" },
      },
    ],
  },

  // ── 4. TLS / Identity Review ─────────────────────────────────────────────────
  {
    id: "tls-identity-review",
    name: "TLS / Identity Review",
    description: "Certificate inspection and DNS identity verification for HTTPS services.",
    steps: [
      {
        id: "tls-probe",
        label: "TLS certificate probe",
        description:
          "Perform a raw TLS handshake to capture the full certificate chain, cipher suite, " +
          "TLS version, and check for weak ciphers. No HTTP traffic sent.",
        type: "active",
        action: { type: "probe", probeType: "tls" },
        condition: hasTlsPort,
      },
      {
        id: "dns-verify",
        label: "DNS hostname verification",
        description:
          "Resolve DNS records and verify that PTR/forward A records match. " +
          "SAN mismatches, CDN interception, and shared hosting are revealed here.",
        type: "active",
        action: { type: "probe", probeType: "dns" },
      },
      {
        id: "review-cert",
        label: "Review certificate and DNS findings",
        description:
          "Check the results: cert expiry, self-signed status, CN/SAN mismatch, " +
          "and PTR forward-verification. Create findings for certificate issues.",
        type: "passive",
        action: { type: "review", target: "findings" },
      },
    ],
  },

  // ── 5. Baseline Comparison Review ────────────────────────────────────────────
  {
    id: "baseline-comparison",
    name: "Baseline Comparison Review",
    description: "Track changes against a previous session snapshot using Diff Mode.",
    steps: [
      {
        id: "load-diff",
        label: "Load a baseline session for comparison",
        description:
          "In the 3D scene, switch to DIFF mode and select a saved session as the baseline. " +
          "This reveals added, removed, and changed hosts visually.",
        type: "passive",
        action: { type: "review", target: "diff" },
      },
      {
        id: "review-changes",
        label: "Review changed and added hosts",
        description:
          "Inspect hosts marked as CHANGED or ADDED in the diff. " +
          "Use the INSPECT tab to see port additions and version changes per host.",
        type: "passive",
      },
      {
        id: "verify-new-ports",
        label: "Verify new ports on changed hosts",
        description:
          "Run Service Detection on hosts with newly opened ports to confirm service identity. " +
          "Profile: SERVICE (-sV). Scope check applies.",
        type: "active",
        action: { type: "scan", profile: "light_service_detection" },
      },
      {
        id: "create-diff-findings",
        label: "Document significant changes as findings",
        description:
          "Create findings for critical port additions or risk escalations. " +
          "Label them with the diff baseline date for audit trail completeness.",
        type: "passive",
        action: { type: "review", target: "findings" },
      },
    ],
  },
];

// ── Factory ───────────────────────────────────────────────────────────────────

export function createPlaybookRun(playbook: Playbook, hostAddress: string): PlaybookRun {
  return {
    playbook,
    hostAddress,
    currentStep: 0,
    skippedSteps: new Set(),
    status: "active",
  };
}

/**
 * Returns the effective step index for the current step after applying conditions.
 * Steps whose condition() returns false for the host are auto-skipped.
 */
export function resolveCurrentStep(
  run: PlaybookRun,
  host: HostResult,
): { step: PlaybookStep | null; isLastStep: boolean } {
  const { playbook, currentStep } = run;
  for (let i = currentStep; i < playbook.steps.length; i++) {
    const step = playbook.steps[i];
    if (!step.condition || step.condition(host)) {
      return { step, isLastStep: i === playbook.steps.length - 1 };
    }
  }
  return { step: null, isLastStep: true };
}
