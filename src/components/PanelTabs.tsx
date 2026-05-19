/**
 * Tabbed navigation for the left panel — reduces cognitive load by
 * organizing controls into logical groups instead of one long scroll.
 */

import type { PanelTab } from "../stores/uiStore";

interface Props {
  activeTab: PanelTab;
  onTabChange: (tab: PanelTab) => void;
  hostCount: number;
  hasSelection: boolean;
  findingCount?: number;
}

const TABS: Array<{ key: PanelTab; label: string; icon: string; hint: string }> = [
  { key: "scan",     label: "SCAN",     icon: "▶", hint: "Scanner controls" },
  { key: "results",  label: "HOSTS",    icon: "◉", hint: "Results table" },
  { key: "inspect",  label: "INSPECT",  icon: "⎔", hint: "Host inspector" },
  { key: "findings", label: "FINDINGS", icon: "⚑", hint: "Analyst findings" },
  { key: "audit",    label: "LOG",      icon: "☰", hint: "Audit log" },
];

export function PanelTabs({ activeTab, onTabChange, hostCount, hasSelection, findingCount = 0 }: Props) {
  return (
    <div style={{
      display: "flex",
      borderBottom: "1px solid var(--border)",
      background: "var(--bg-panel)",
      flexShrink: 0,
    }}>
      {TABS.map(({ key, label, icon, hint }) => {
        const active = activeTab === key;
        const disabled = (key === "results" && hostCount === 0) ||
                        (key === "inspect" && !hasSelection);
        return (
          <button
            key={key}
            onClick={() => !disabled && onTabChange(key)}
            title={hint}
            style={{
              flex: 1,
              padding: "8px 4px 6px",
              display: "flex",
              flexDirection: "column" as const,
              alignItems: "center",
              gap: "2px",
              fontSize: "8px",
              letterSpacing: "0.14em",
              color: disabled ? "var(--border-hi)"
                : active ? "var(--accent)"
                : "var(--text-dim)",
              background: active ? "var(--accent-dim)" : "transparent",
              borderBottom: active ? "2px solid var(--accent)" : "2px solid transparent",
              transition: "all 0.15s",
              cursor: disabled ? "default" : "pointer",
              opacity: disabled ? 0.4 : 1,
              position: "relative" as const,
            }}
          >
            <span style={{ fontSize: "12px" }}>{icon}</span>
            <span>{label}</span>
            {/* Badges */}
            {key === "findings" && findingCount > 0 && (
              <span style={{ position: "absolute", top: "3px", right: "3px", fontSize: "7px", padding: "0 3px", color: "#f87171", border: "1px solid #f87171", lineHeight: "1.4" }}>
                {findingCount}
              </span>
            )}
            {key === "results" && hostCount > 0 && (
              <span style={{
                position: "absolute",
                top: "3px",
                right: "8px",
                fontSize: "7px",
                padding: "0 3px",
                color: "var(--accent)",
                border: "1px solid var(--accent)",
                lineHeight: "1.4",
              }}>
                {hostCount}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
