/**
 * Cross-session diff engine — compare two session snapshots and produce
 * a detailed change report showing new/removed hosts, port changes, and
 * service version changes.
 */

import type { HostResult } from "../types";

export interface HostDiff {
  address: string;
  hostname?: string;
  type: "added" | "removed" | "changed" | "unchanged";
  portChanges?: {
    added: Array<{ port: number; protocol: string; service: string }>;
    removed: Array<{ port: number; protocol: string; service: string }>;
    versionChanged: Array<{
      port: number;
      protocol: string;
      service: string;
      oldVersion: string;
      newVersion: string;
    }>;
  };
  riskChange?: { old: string; new: string };
}

export interface SessionDiffReport {
  baselineDate: string;
  comparisonDate: string;
  hostsAdded: number;
  hostsRemoved: number;
  hostsChanged: number;
  hostsUnchanged: number;
  totalPortsAdded: number;
  totalPortsRemoved: number;
  diffs: HostDiff[];
}

export function diffSessions(
  baseline: HostResult[],
  comparison: HostResult[],
  baselineDate = "baseline",
  comparisonDate = "comparison",
): SessionDiffReport {
  const baseMap = new Map(baseline.map((h) => [h.address, h]));
  const compMap = new Map(comparison.map((h) => [h.address, h]));

  const diffs: HostDiff[] = [];
  let hostsAdded = 0;
  let hostsRemoved = 0;
  let hostsChanged = 0;
  let hostsUnchanged = 0;
  let totalPortsAdded = 0;
  let totalPortsRemoved = 0;

  // Check hosts in comparison (new or changed)
  for (const [addr, compHost] of compMap) {
    const baseHost = baseMap.get(addr);
    if (!baseHost) {
      hostsAdded++;
      const openPorts = compHost.ports.filter((p) => p.state === "open");
      totalPortsAdded += openPorts.length;
      diffs.push({
        address: addr,
        hostname: compHost.hostname,
        type: "added",
        portChanges: {
          added: openPorts.map((p) => ({
            port: p.port,
            protocol: p.protocol,
            service: p.service,
          })),
          removed: [],
          versionChanged: [],
        },
      });
      continue;
    }

    // Compare ports
    const basePorts = new Map(
      baseHost.ports.filter((p) => p.state === "open").map((p) => [`${p.port}/${p.protocol}`, p])
    );
    const compPorts = new Map(
      compHost.ports.filter((p) => p.state === "open").map((p) => [`${p.port}/${p.protocol}`, p])
    );

    const added: HostDiff["portChanges"] extends undefined ? never : NonNullable<HostDiff["portChanges"]>["added"] = [];
    const removed: typeof added = [];
    const versionChanged: NonNullable<HostDiff["portChanges"]>["versionChanged"] = [];

    for (const [key, port] of compPorts) {
      if (!basePorts.has(key)) {
        added.push({ port: port.port, protocol: port.protocol, service: port.service });
        totalPortsAdded++;
      } else {
        const basePort = basePorts.get(key)!;
        if (basePort.version !== port.version && (basePort.version || port.version)) {
          versionChanged.push({
            port: port.port,
            protocol: port.protocol,
            service: port.service,
            oldVersion: basePort.version ?? "unknown",
            newVersion: port.version ?? "unknown",
          });
        }
      }
    }

    for (const [key, port] of basePorts) {
      if (!compPorts.has(key)) {
        removed.push({ port: port.port, protocol: port.protocol, service: port.service });
        totalPortsRemoved++;
      }
    }

    if (added.length === 0 && removed.length === 0 && versionChanged.length === 0) {
      hostsUnchanged++;
      diffs.push({ address: addr, hostname: compHost.hostname, type: "unchanged" });
    } else {
      hostsChanged++;
      diffs.push({
        address: addr,
        hostname: compHost.hostname,
        type: "changed",
        portChanges: { added, removed, versionChanged },
      });
    }
  }

  // Check hosts only in baseline (removed)
  for (const [addr, baseHost] of baseMap) {
    if (!compMap.has(addr)) {
      hostsRemoved++;
      const openPorts = baseHost.ports.filter((p) => p.state === "open");
      totalPortsRemoved += openPorts.length;
      diffs.push({
        address: addr,
        hostname: baseHost.hostname,
        type: "removed",
        portChanges: {
          added: [],
          removed: openPorts.map((p) => ({
            port: p.port,
            protocol: p.protocol,
            service: p.service,
          })),
          versionChanged: [],
        },
      });
    }
  }

  // Sort: changed first, then added, then removed, then unchanged
  const order = { changed: 0, added: 1, removed: 2, unchanged: 3 };
  diffs.sort((a, b) => order[a.type] - order[b.type]);

  return {
    baselineDate,
    comparisonDate,
    hostsAdded,
    hostsRemoved,
    hostsChanged,
    hostsUnchanged,
    totalPortsAdded,
    totalPortsRemoved,
    diffs,
  };
}
