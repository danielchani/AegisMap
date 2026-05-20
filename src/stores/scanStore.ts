/**
 * Zustand store for scan execution state.
 * Manages active scans, scan queue, progress, and console output.
 * Prepared for multi-scan support via scanId-keyed state.
 */

import { create } from "zustand";
import type { ScanProfile, ScanStatus } from "../types";

export interface ActiveScan {
  id: string;
  target: string;
  profile: ScanProfile;
  status: ScanStatus;
  progress: number | null;
  eta: number | null;
  errorMsg: string | null;
  logLines: string[];
  startedAt: string;
}

interface ScanState {
  /** Currently active scan (single for now; keyed map for future parallel) */
  activeScan: ActiveScan | null;
  /** Queue of targets waiting to scan */
  scanQueue: string[];
  /** Global status derived from active scan */
  status: ScanStatus;

  // Actions
  startScan: (target: string, profile: ScanProfile) => string;
  updateScanStatus: (status: ScanStatus) => void;
  updateProgress: (percent: number, eta: number | null) => void;
  appendLog: (line: string) => void;
  setError: (msg: string) => void;
  clearScan: () => void;
  enqueue: (target: string) => void;
  dequeue: () => string | undefined;
  clearQueue: () => void;
}

let scanCounter = 0;

export const useScanStore = create<ScanState>((set, get) => ({
  activeScan: null,
  scanQueue: [],
  status: "idle",

  startScan: (target, profile) => {
    const id = `scan-${++scanCounter}-${Date.now()}`;
    set({
      activeScan: {
        id,
        target,
        profile,
        status: "starting",
        progress: null,
        eta: null,
        errorMsg: null,
        logLines: [],
        startedAt: new Date().toISOString(),
      },
      status: "starting",
    });
    return id;
  },

  updateScanStatus: (status) => {
    set((state) => ({
      status,
      activeScan: state.activeScan ? { ...state.activeScan, status } : null,
    }));
  },

  updateProgress: (percent, eta) => {
    set((state) => ({
      activeScan: state.activeScan
        ? { ...state.activeScan, progress: percent, eta }
        : null,
    }));
  },

  appendLog: (line) => {
    set((state) => ({
      activeScan: state.activeScan
        ? { ...state.activeScan, logLines: [...state.activeScan.logLines, line] }
        : null,
    }));
  },

  setError: (msg) => {
    set((state) => ({
      activeScan: state.activeScan
        ? { ...state.activeScan, errorMsg: msg }
        : null,
    }));
  },

  clearScan: () => {
    set({ activeScan: null, status: "idle" });
  },

  enqueue: (target) => {
    set((state) => ({ scanQueue: [...state.scanQueue, target] }));
  },

  dequeue: () => {
    const { scanQueue } = get();
    if (scanQueue.length === 0) return undefined;
    const [next, ...rest] = scanQueue;
    set({ scanQueue: rest });
    return next;
  },

  clearQueue: () => {
    set({ scanQueue: [] });
  },
}));
