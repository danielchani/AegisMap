/**
 * Host/port merge logic — single source of truth.
 * Used by App.tsx for scan result merging and session loading.
 */
import type { HostResult, PortEntry } from "../types";

const MAX_PORT_HISTORY = 10;

/** Union two port arrays, keeping latest version info per port/protocol pair. */
export function mergePorts(old: PortEntry[], incoming: PortEntry[]): PortEntry[] {
  const map = new Map<string, PortEntry>();
  old.forEach((p) => map.set(`${p.port}/${p.protocol}`, p));
  incoming.forEach((p) => map.set(`${p.port}/${p.protocol}`, p));
  return Array.from(map.values()).sort((a, b) => a.port - b.port);
}

/** Merge an incoming host into an existing one, preserving notes/tags/workflow and computing port diff. */
export function mergeHost(existing: HostResult, incoming: HostResult): HostResult {
  const prevOpen = new Set(existing.ports.filter((p) => p.state === "open").map((p) => p.port));
  const nextOpen = new Set(incoming.ports.filter((p) => p.state === "open").map((p) => p.port));
  const openCount = nextOpen.size;
  const history = [
    ...(existing.portHistory ?? []),
    { ts: new Date().toISOString(), open: openCount },
  ].slice(-MAX_PORT_HISTORY);

  return {
    ...incoming,
    ports:          mergePorts(existing.ports, incoming.ports),
    scannedAt:      new Date().toISOString(),
    notes:          existing.notes,
    workflowStatus: existing.workflowStatus,
    tags:           existing.tags,
    portNotes:      existing.portNotes,
    portHistory:    history,
    portsDiff: {
      added:   [...nextOpen].filter((p) => !prevOpen.has(p)),
      removed: [...prevOpen].filter((p) => !nextOpen.has(p)),
    },
  };
}
