import { describe, it, expect } from "vitest";
import {
  getDiffState, getConfidenceTier,
  getDiffColor, getConfidenceColor,
  getDiffOpacity, DIFF_BADGE,
} from "./sceneMode";
import type { SessionDiffReport } from "./sessionDiff";

function makeReport(
  ...entries: Array<{ address: string; type: "added" | "removed" | "changed" | "unchanged" }>
): SessionDiffReport {
  return {
    baselineDate: "b", comparisonDate: "c",
    hostsAdded: 0, hostsRemoved: 0, hostsChanged: 0, hostsUnchanged: 0,
    totalPortsAdded: 0, totalPortsRemoved: 0,
    diffs: entries.map((e) => ({ ...e })),
  };
}

// ── getDiffState ───────────────────────────────────────────────────────────────

describe("getDiffState", () => {
  it("returns none when report is null", () => {
    expect(getDiffState("1.2.3.4", null)).toBe("none");
  });

  it("returns added for an added host", () => {
    expect(getDiffState("1.2.3.4", makeReport({ address: "1.2.3.4", type: "added" }))).toBe("added");
  });

  it("returns removed for a removed host", () => {
    expect(getDiffState("1.2.3.4", makeReport({ address: "1.2.3.4", type: "removed" }))).toBe("removed");
  });

  it("returns changed for a changed host", () => {
    expect(getDiffState("1.2.3.4", makeReport({ address: "1.2.3.4", type: "changed" }))).toBe("changed");
  });

  it("returns unchanged for an unchanged host", () => {
    expect(getDiffState("1.2.3.4", makeReport({ address: "1.2.3.4", type: "unchanged" }))).toBe("unchanged");
  });

  it("returns none for an address not in the report", () => {
    expect(getDiffState("9.9.9.9", makeReport({ address: "1.2.3.4", type: "added" }))).toBe("none");
  });

  it("handles multiple entries — returns the correct one", () => {
    const r = makeReport(
      { address: "1.1.1.1", type: "added" },
      { address: "2.2.2.2", type: "changed" },
    );
    expect(getDiffState("1.1.1.1", r)).toBe("added");
    expect(getDiffState("2.2.2.2", r)).toBe("changed");
  });
});

// ── getConfidenceTier ──────────────────────────────────────────────────────────

describe("getConfidenceTier", () => {
  it("returns high at exactly 75", () => {
    expect(getConfidenceTier(75)).toBe("high");
  });

  it("returns high above 75", () => {
    expect(getConfidenceTier(100)).toBe("high");
    expect(getConfidenceTier(80)).toBe("high");
  });

  it("returns medium at exactly 45", () => {
    expect(getConfidenceTier(45)).toBe("medium");
  });

  it("returns medium in 45–74 range", () => {
    expect(getConfidenceTier(60)).toBe("medium");
    expect(getConfidenceTier(74)).toBe("medium");
  });

  it("returns low below 45", () => {
    expect(getConfidenceTier(0)).toBe("low");
    expect(getConfidenceTier(44)).toBe("low");
    expect(getConfidenceTier(30)).toBe("low");
  });
});

// ── getDiffColor ───────────────────────────────────────────────────────────────

describe("getDiffColor", () => {
  it("returns teal for added", () => expect(getDiffColor("added")).toBe("#00ffcc"));
  it("returns amber for changed", () => expect(getDiffColor("changed")).toBe("#fbbf24"));
  it("returns slate for removed", () => expect(getDiffColor("removed")).toBe("#475569"));
  it("returns slate for unchanged", () => expect(getDiffColor("unchanged")).toBe("#475569"));
  it("returns a non-empty string for none (no throw)", () => {
    expect(getDiffColor("none").length).toBeGreaterThan(0);
  });
});

// ── getConfidenceColor ────────────────────────────────────────────────────────

describe("getConfidenceColor", () => {
  it("returns green for high", () => expect(getConfidenceColor("high")).toBe("#4ade80"));
  it("returns amber for medium", () => expect(getConfidenceColor("medium")).toBe("#fbbf24"));
  it("returns red-pink for low", () => expect(getConfidenceColor("low")).toBe("#f87171"));
});

// ── getDiffOpacity ────────────────────────────────────────────────────────────

describe("getDiffOpacity", () => {
  it("unchanged hosts are dimmed", () => {
    expect(getDiffOpacity("unchanged")).toBeLessThan(0.5);
  });

  it("added/changed hosts are fully opaque", () => {
    expect(getDiffOpacity("added")).toBe(1.0);
    expect(getDiffOpacity("changed")).toBe(1.0);
    expect(getDiffOpacity("removed")).toBe(1.0);
  });
});

// ── DIFF_BADGE ────────────────────────────────────────────────────────────────

describe("DIFF_BADGE", () => {
  it("added has a glyph", () => expect(DIFF_BADGE["added"].length).toBeGreaterThan(0));
  it("changed has a glyph", () => expect(DIFF_BADGE["changed"].length).toBeGreaterThan(0));
  it("removed has a glyph", () => expect(DIFF_BADGE["removed"].length).toBeGreaterThan(0));
  it("unchanged is empty", () => expect(DIFF_BADGE["unchanged"]).toBe(""));
});
