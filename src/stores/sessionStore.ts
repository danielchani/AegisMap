/**
 * Zustand store for session state — hosts, selections, scope, and persistence.
 * Durable storage is SQLite via Rust commands (get_active_session / save_active_session).
 * Scope ranges remain in localStorage (simple config, no history needed).
 */

import { invoke } from "@tauri-apps/api/core";
import { create } from "zustand";
import { subscribeWithSelector } from "zustand/middleware";
import { appendAudit } from "../lib/auditLog";
import type { HostResult, PortEntry, PortFamily, ScanReport } from "../types";

const SCOPE_KEY = "aegismap:scope";
const MAX_PORT_HISTORY = 10;

// ── Port/host merge logic ──────────────────────────────────────────────────────

function mergePorts(old: PortEntry[], incoming: PortEntry[]): PortEntry[] {
  const map = new Map<string, PortEntry>();
  old.forEach((p) => map.set(`${p.port}/${p.protocol}`, p));
  incoming.forEach((p) => map.set(`${p.port}/${p.protocol}`, p));
  return Array.from(map.values()).sort((a, b) => a.port - b.port);
}

function mergeHost(existing: HostResult, incoming: HostResult): HostResult {
  const prevOpen = new Set(existing.ports.filter((p) => p.state === "open").map((p) => p.port));
  const nextOpen = new Set(incoming.ports.filter((p) => p.state === "open").map((p) => p.port));
  const history = [
    ...(existing.portHistory ?? []),
    { ts: new Date().toISOString(), open: nextOpen.size },
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

// ── Scope (stays in localStorage) ─────────────────────────────────────────────

function loadInitialScope(): string[] {
  try { return JSON.parse(localStorage.getItem(SCOPE_KEY) ?? "[]"); } catch { return []; }
}

// ── Store ────────────────────────────────────────────────────────────────────────

interface SessionState {
  hosts: HostResult[];
  selectedAddr: string | null;
  latestReport: ScanReport | null;
  finalizationId: number;
  portFilter: PortFamily;
  authorizedRanges: string[];
  storageError: string | null;
  stdoutLines: string[];

  selectedHost: () => HostResult | null;
  displayReport: () => ScanReport | null;

  // Called once on app init — loads from SQLite
  loadFromDb: () => Promise<void>;

  mergeReport: (report: ScanReport) => void;
  updateHost: (address: string, patch: Partial<HostResult>) => void;
  removeHost: (address: string) => void;
  selectHost: (address: string | null) => void;
  setPortFilter: (filter: PortFamily) => void;
  setAuthorizedRanges: (ranges: string[]) => void;
  clearSession: () => void;
  loadSession: (hosts: HostResult[]) => void;
  appendStdout: (line: string) => void;
  clearStdout: () => void;
  persistToStorage: () => Promise<void>;
}

export const useSessionStore = create<SessionState>()(
  subscribeWithSelector((set, get) => ({
    hosts: [],          // empty on init; loadFromDb() populates from SQLite
    selectedAddr: null,
    latestReport: null,
    finalizationId: 0,
    portFilter: null,
    authorizedRanges: loadInitialScope(),
    storageError: null,
    stdoutLines: [],

    selectedHost: () => {
      const { hosts, selectedAddr } = get();
      return hosts.find((h) => h.address === selectedAddr) ?? null;
    },

    displayReport: () => {
      const { latestReport, hosts } = get();
      if (!latestReport && hosts.length === 0) return null;
      if (!latestReport) return null;
      return { ...latestReport, hosts };
    },

    // ── Async DB init ─────────────────────────────────────────────────────────

    loadFromDb: async () => {
      try {
        const hosts = await invoke<HostResult[]>("get_active_session");
        set({ hosts: hosts ?? [] });
      } catch (e) {
        set({ storageError: `Failed to load session: ${String(e)}` });
      }
    },

    // ── Mutations ─────────────────────────────────────────────────────────────

    mergeReport: (report) => {
      set((state) => {
        const map = new Map(state.hosts.map((h) => [h.address, h]));
        report.hosts.forEach((h) => {
          const existing = map.get(h.address);
          const stamped  = { ...h, scannedAt: new Date().toISOString() };
          map.set(h.address, existing ? mergeHost(existing, stamped) : stamped);
        });
        return {
          hosts: Array.from(map.values()),
          latestReport: report,
          finalizationId: state.finalizationId + 1,
        };
      });
      setTimeout(() => void get().persistToStorage(), 0);
    },

    updateHost: (address, patch) => {
      set((state) => ({
        hosts: state.hosts.map((h) => h.address === address ? { ...h, ...patch } : h),
      }));
      setTimeout(() => void get().persistToStorage(), 0);
    },

    removeHost: (address) => {
      set((state) => ({
        hosts: state.hosts.filter((h) => h.address !== address),
        selectedAddr: state.selectedAddr === address ? null : state.selectedAddr,
      }));
      void appendAudit("REMOVE_HOST", address);
      setTimeout(() => void get().persistToStorage(), 0);
    },

    selectHost: (address) => set({ selectedAddr: address }),

    setPortFilter: (filter) => set({ portFilter: filter }),

    setAuthorizedRanges: (ranges) => {
      set({ authorizedRanges: ranges });
      localStorage.setItem(SCOPE_KEY, JSON.stringify(ranges));
    },

    clearSession: () => {
      set({
        hosts: [], latestReport: null, selectedAddr: null,
        stdoutLines: [], portFilter: null,
      });
      void invoke("clear_active_session").catch(() => {/* non-critical */});
      void appendAudit("SESSION_CLEAR", "All session hosts cleared");
    },

    loadSession: (hosts) => {
      set((state) => {
        const map = new Map(state.hosts.map((h) => [h.address, h]));
        hosts.forEach((h) => {
          const ex = map.get(h.address);
          map.set(h.address, ex ? mergeHost(ex, h) : h);
        });
        return { hosts: Array.from(map.values()) };
      });
      void appendAudit("SESSION_LOAD", `Merged ${hosts.length} host(s) from saved session`);
      setTimeout(() => void get().persistToStorage(), 0);
    },

    appendStdout: (line) => set((state) => ({ stdoutLines: [...state.stdoutLines, line] })),
    clearStdout: () => set({ stdoutLines: [] }),

    persistToStorage: async () => {
      const { hosts } = get();
      try {
        await invoke("save_active_session", { hosts });
        set({ storageError: null });
      } catch (e) {
        set({ storageError: `Session persistence error: ${String(e)}` });
      }
    },
  }))
);
