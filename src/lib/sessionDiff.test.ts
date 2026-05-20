import { describe, it, expect } from "vitest";
import { diffSessions } from "./sessionDiff";
import type { HostResult } from "../types";

function makeHost(address: string, ports: number[]): HostResult {
  return {
    address,
    status: "up",
    ports: ports.map((p) => ({ port: p, protocol: "tcp", state: "open", service: "" })),
  };
}

describe("diffSessions", () => {
  it("detects added hosts", () => {
    const baseline = [makeHost("10.0.0.1", [22, 80])];
    const comparison = [makeHost("10.0.0.1", [22, 80]), makeHost("10.0.0.2", [443])];
    const diff = diffSessions(baseline, comparison);
    expect(diff.hostsAdded).toBe(1);
    expect(diff.hostsRemoved).toBe(0);
    expect(diff.diffs.find((d) => d.address === "10.0.0.2")?.type).toBe("added");
  });

  it("detects removed hosts", () => {
    const baseline = [makeHost("10.0.0.1", [22]), makeHost("10.0.0.2", [80])];
    const comparison = [makeHost("10.0.0.1", [22])];
    const diff = diffSessions(baseline, comparison);
    expect(diff.hostsRemoved).toBe(1);
    expect(diff.diffs.find((d) => d.address === "10.0.0.2")?.type).toBe("removed");
  });

  it("detects changed hosts (new port)", () => {
    const baseline = [makeHost("10.0.0.1", [22])];
    const comparison = [makeHost("10.0.0.1", [22, 80])];
    const diff = diffSessions(baseline, comparison);
    expect(diff.hostsChanged).toBe(1);
    expect(diff.totalPortsAdded).toBe(1);
    const hostDiff = diff.diffs.find((d) => d.address === "10.0.0.1");
    expect(hostDiff?.type).toBe("changed");
    expect(hostDiff?.portChanges?.added).toHaveLength(1);
    expect(hostDiff?.portChanges?.added[0].port).toBe(80);
  });

  it("detects changed hosts (removed port)", () => {
    const baseline = [makeHost("10.0.0.1", [22, 80, 443])];
    const comparison = [makeHost("10.0.0.1", [22, 443])];
    const diff = diffSessions(baseline, comparison);
    expect(diff.hostsChanged).toBe(1);
    expect(diff.totalPortsRemoved).toBe(1);
  });

  it("marks unchanged hosts", () => {
    const baseline = [makeHost("10.0.0.1", [22, 80])];
    const comparison = [makeHost("10.0.0.1", [22, 80])];
    const diff = diffSessions(baseline, comparison);
    expect(diff.hostsUnchanged).toBe(1);
    expect(diff.hostsChanged).toBe(0);
  });

  it("handles empty baselines and comparisons", () => {
    const diff = diffSessions([], []);
    expect(diff.hostsAdded).toBe(0);
    expect(diff.hostsRemoved).toBe(0);
    expect(diff.diffs).toHaveLength(0);
  });

  it("handles complete replacement (all new hosts)", () => {
    const baseline = [makeHost("10.0.0.1", [22])];
    const comparison = [makeHost("10.0.0.2", [80])];
    const diff = diffSessions(baseline, comparison);
    expect(diff.hostsAdded).toBe(1);
    expect(diff.hostsRemoved).toBe(1);
  });

  it("sorts diffs: changed first, then added, removed, unchanged", () => {
    const baseline = [
      makeHost("10.0.0.1", [22]),       // will be changed
      makeHost("10.0.0.2", [80]),       // will be removed
      makeHost("10.0.0.3", [443]),      // will be unchanged
    ];
    const comparison = [
      makeHost("10.0.0.1", [22, 8080]), // changed
      makeHost("10.0.0.3", [443]),      // unchanged
      makeHost("10.0.0.4", [3306]),     // added
    ];
    const diff = diffSessions(baseline, comparison);
    expect(diff.diffs[0].type).toBe("changed");
    expect(diff.diffs[1].type).toBe("added");
    expect(diff.diffs[2].type).toBe("removed");
    expect(diff.diffs[3].type).toBe("unchanged");
  });
});
