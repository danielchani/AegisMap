/**
 * Invoke wrappers for the Findings & Evidence Tauri commands, plus
 * factory helpers for creating findings from existing advisory/CVE data.
 *
 * Accuracy rule: auto-generated findings NEVER start as confirmed.
 * - CVE candidate  → confidence: "candidate"
 * - Advisory match → confidence: "heuristic"
 * - Script result  → confidence: "observed"
 * - Manual         → confidence: "observed" (analyst sets it)
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  PentestFinding, EvidenceItem, FindingSeverity,
} from "../types";

// ── CRUD wrappers ─────────────────────────────────────────────────────────────

export async function createFinding(
  finding: Omit<PentestFinding, "id" | "evidenceIds" | "createdAt" | "updatedAt">,
): Promise<string> {
  return invoke<string>("create_finding", { finding });
}

export async function updateFinding(
  id: string,
  patch: Partial<Pick<PentestFinding,
    "title" | "severity" | "confidence" | "status" | "affectedHosts" | "affectedPorts"
    | "summary" | "technicalDetails" | "remediation" | "references">>,
): Promise<void> {
  return invoke("update_finding", { id, patch });
}

export async function deleteFinding(id: string): Promise<void> {
  return invoke("delete_finding", { id });
}

export async function listFindings(sessionId: string): Promise<PentestFinding[]> {
  try {
    return await invoke<PentestFinding[]>("list_findings", { sessionId });
  } catch { return []; }
}

export async function attachEvidence(
  evidence: Omit<EvidenceItem, "id" | "createdAt">,
): Promise<string> {
  return invoke<string>("attach_evidence", { evidence });
}

export async function deleteEvidence(id: string): Promise<void> {
  return invoke("delete_evidence", { id });
}

export async function listEvidence(findingId: string): Promise<EvidenceItem[]> {
  try {
    return await invoke<EvidenceItem[]>("list_evidence_for_finding", { findingId });
  } catch { return []; }
}

// ── Factory helpers ───────────────────────────────────────────────────────────

interface CveContext {
  sessionId: string;
  hostAddress: string;
  portRef: string;        // "443/tcp"
  cveId: string;
  cvss: number;
  summary: string;
  affectedVersions: string;
  product: string;
  detectedVersion: string;
}

/** Creates a finding from a CVE candidate match. confidence is always "candidate". */
export async function createFindingFromCve(ctx: CveContext): Promise<string> {
  const severity = cvssToSeverity(ctx.cvss);
  const findingId = await createFinding({
    sessionId:     ctx.sessionId,
    title:         `${ctx.cveId} — ${ctx.product}`,
    severity,
    confidence:    "candidate",   // enforced by Rust too; never auto-confirmed
    status:        "draft",
    affectedHosts: [ctx.hostAddress],
    affectedPorts: [ctx.portRef],
    summary:       `${ctx.product} ${ctx.detectedVersion} matched ${ctx.cveId}. ${ctx.summary}`,
    references:    [ctx.cveId],
    source:        "cve_candidate",
    sourceRef:     ctx.cveId,
  });

  // Auto-attach evidence snapshot
  await attachEvidence({
    findingId,
    sessionId:   ctx.sessionId,
    type:        "advisory_match",
    hostAddress: ctx.hostAddress,
    portRef:     ctx.portRef,
    excerpt:     `${ctx.cveId} — CVSS ${ctx.cvss} — affected: ${ctx.affectedVersions}`,
    rawData:     JSON.stringify({ cveId: ctx.cveId, cvss: ctx.cvss, affectedVersions: ctx.affectedVersions, detectedVersion: ctx.detectedVersion }),
  });

  return findingId;
}

interface AdvisoryContext {
  sessionId: string;
  hostAddress: string;
  portRef: string;
  product: string;
  version: string;
  advisoryType: "update" | "eol";
  message: string;
}

/** Creates a finding from a version/EOL advisory. confidence is always "heuristic". */
export async function createFindingFromAdvisory(ctx: AdvisoryContext): Promise<string> {
  const severity: FindingSeverity = ctx.advisoryType === "eol" ? "high" : "low";
  const title = ctx.advisoryType === "eol"
    ? `${ctx.product} ${ctx.version} — End of Life`
    : `${ctx.product} ${ctx.version} — Update Available`;

  const findingId = await createFinding({
    sessionId:     ctx.sessionId,
    title,
    severity,
    confidence:    "heuristic",   // version range match — not validated
    status:        "draft",
    affectedHosts: [ctx.hostAddress],
    affectedPorts: [ctx.portRef],
    summary:       ctx.message,
    source:        "version_advisory",
    sourceRef:     ctx.product,
  });

  await attachEvidence({
    findingId,
    sessionId:   ctx.sessionId,
    type:        "advisory_match",
    hostAddress: ctx.hostAddress,
    portRef:     ctx.portRef,
    excerpt:     `${ctx.advisoryType.toUpperCase()}: ${ctx.product} ${ctx.version} — ${ctx.message}`,
    rawData:     JSON.stringify({ product: ctx.product, version: ctx.version, advisoryType: ctx.advisoryType }),
  });

  return findingId;
}

interface ScriptContext {
  sessionId: string;
  hostAddress: string;
  portRef?: string;
  scriptId: string;
  scriptOutput: string;
}

/** Creates a finding from an NSE script result. confidence is "observed". */
export async function createFindingFromScript(ctx: ScriptContext): Promise<string> {
  const findingId = await createFinding({
    sessionId:     ctx.sessionId,
    title:         `${ctx.scriptId} output on ${ctx.hostAddress}`,
    severity:      "info",
    confidence:    "observed",
    status:        "draft",
    affectedHosts: [ctx.hostAddress],
    affectedPorts: ctx.portRef ? [ctx.portRef] : undefined,
    summary:       ctx.scriptOutput.slice(0, 500),
    source:        "script_result",
    sourceRef:     ctx.scriptId,
  });

  await attachEvidence({
    findingId,
    sessionId:   ctx.sessionId,
    type:        "script_output",
    hostAddress: ctx.hostAddress,
    portRef:     ctx.portRef,
    excerpt:     ctx.scriptOutput.slice(0, 300),
    rawData:     JSON.stringify({ scriptId: ctx.scriptId, output: ctx.scriptOutput }),
  });

  return findingId;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function cvssToSeverity(cvss: number): FindingSeverity {
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  if (cvss > 0)    return "low";
  return "info";
}

export { cvssToSeverity };
