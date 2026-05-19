/**
 * Zustand store for UI state — panel dimensions, active tab, theme preferences.
 */

import { create } from "zustand";

export type PanelTab = "scan" | "results" | "inspect" | "audit" | "findings";

interface UIState {
  panelWidth: number;
  activeTab: PanelTab;
  show3DFilters: boolean;
  /** 3D scene filter: risk levels to show */
  visibleRiskLevels: Set<string>;
  /** High contrast mode for accessibility */
  highContrast: boolean;

  // Actions
  setPanelWidth: (width: number) => void;
  setActiveTab: (tab: PanelTab) => void;
  toggleTab: (tab: PanelTab) => void;
  setShow3DFilters: (show: boolean) => void;
  toggleRiskLevel: (level: string) => void;
  toggleHighContrast: () => void;
}

export const useUIStore = create<UIState>((set) => ({
  panelWidth: 380,
  activeTab: "scan",
  show3DFilters: false,
  visibleRiskLevels: new Set(["clean", "low", "medium", "high", "critical"]),
  highContrast: false,

  setPanelWidth: (width) => set({ panelWidth: Math.min(600, Math.max(280, width)) }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  toggleTab: (tab) => set((state) => ({
    activeTab: state.activeTab === tab ? "scan" : tab,
  })),

  setShow3DFilters: (show) => set({ show3DFilters: show }),

  toggleRiskLevel: (level) => set((state) => {
    const next = new Set(state.visibleRiskLevels);
    if (next.has(level)) next.delete(level);
    else next.add(level);
    return { visibleRiskLevels: next };
  }),

  toggleHighContrast: () => set((state) => ({ highContrast: !state.highContrast })),
}));
