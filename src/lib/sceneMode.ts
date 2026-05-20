/**
 * Visual mode helpers for the 3D scene.
 * Diff mode and Confidence mode visual encodings are pure functions over
 * data — all testable without a browser or canvas.
 */

import type { SessionDiffReport } from "./sessionDiff";

export type DiffState      = "added" | "removed" | "changed" | "unchanged" | "none";
export type ConfidenceTier = "high" | "medium" | "low";

// ── Diff helpers ──────────────────────────────────────────────────────────────

/**
 * Returns the diff classification for a host address given a diff report.
 * Returns "none" when the report is null or the address is not found.
 */
export function getDiffState(
  address: string,
  report: SessionDiffReport | null,
): DiffState {
  if (!report) return "none";
  return report.diffs.find((d) => d.address === address)?.type ?? "none";
}

export const DIFF_COLOR: Record<DiffState, string> = {
  added:     "#00ffcc",   // teal  — new in this scan
  changed:   "#fbbf24",   // amber — something changed
  unchanged: "#475569",   // slate — no change (de-emphasised)
  removed:   "#475569",   // slate — gone since baseline (ghost nodes)
  none:      "#00ffaa",   // fallback to accent
};

export function getDiffColor(state: DiffState): string {
  return DIFF_COLOR[state];
}

// ── Confidence helpers ────────────────────────────────────────────────────────

/** Maps a 0-100 overall confidence score to a three-tier label. */
export function getConfidenceTier(overall: number): ConfidenceTier {
  if (overall >= 75) return "high";
  if (overall >= 45) return "medium";
  return "low";
}

export const CONFIDENCE_COLOR: Record<ConfidenceTier, string> = {
  high:   "#4ade80",   // green  — well-enumerated
  medium: "#fbbf24",   // amber  — partially enumerated
  low:    "#f87171",   // red    — poorly understood
};

export function getConfidenceColor(tier: ConfidenceTier): string {
  return CONFIDENCE_COLOR[tier];
}

// ── Diff opacity ──────────────────────────────────────────────────────────────

/** Node opacity in diff mode — unchanged hosts are dimmed to draw focus to changes. */
export function getDiffOpacity(state: DiffState): number {
  return state === "unchanged" ? 0.28 : 1.0;
}

// ── Diff badge glyphs ─────────────────────────────────────────────────────────

export const DIFF_BADGE: Record<DiffState, string> = {
  added:     "⊕",
  changed:   "◆",
  removed:   "⊖",
  unchanged: "",
  none:      "",
};
