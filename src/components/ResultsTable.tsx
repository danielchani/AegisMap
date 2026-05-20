import { useMemo, useState } from "react";
import { SLabel } from "./ui/SLabel";
import { formatScanAge, useNow } from "../hooks/useScanAge";
import { hostRiskLevel, RISK_COLOR, RISK_LABEL } from "../lib/riskScore";
import type { HostResult, PentestFinding, ScanReport } from "../types";

interface Props {
  report: ScanReport;
  selectedAddress: string | null;
  onSelect: (host: HostResult | null) => void;
  onRemoveHost: (address: string) => void;
  findings?: PentestFinding[];
}

type SortKey = "address" | "open" | "scanned" | "risk";

const RISK_RANK: Record<string, number> = { clean: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function ResultsTable({ report, selectedAddress, onSelect, onRemoveHost, findings }: Props) {
  const [hoveredAddr, setHoveredAddr] = useState<string | null>(null);
  const [search,   setSearch]   = useState("");
  const [sortKey,  setSortKey]  = useState<SortKey | null>(null);
  const [sortDir,  setSortDir]  = useState<1 | -1>(1);
  const now = useNow();

  const openCount = (h: HostResult) => h.ports.filter((p) => p.state === "open").length;

  function handleSort(key: SortKey) {
    if (sortKey === key) setSortDir((d) => (d === 1 ? -1 : 1));
    else { setSortKey(key); setSortDir(1); }
  }

  const displayed = useMemo(() => {
    const q = search.toLowerCase();
    let list = report.hosts.filter((h) =>
      !q ||
      h.address.includes(q) ||
      h.hostname?.toLowerCase().includes(q) ||
      h.ports.some((p) => p.service?.toLowerCase().includes(q))
    );
    if (sortKey) {
      list = [...list].sort((a, b) => {
        let diff = 0;
        if (sortKey === "address") diff = a.address.localeCompare(b.address);
        else if (sortKey === "open") diff = openCount(a) - openCount(b);
        else if (sortKey === "scanned") diff = (a.scannedAt ?? "").localeCompare(b.scannedAt ?? "");
        else if (sortKey === "risk") diff = RISK_RANK[hostRiskLevel(a, findings)] - RISK_RANK[hostRiskLevel(b, findings)];
        return diff * sortDir;
      });
    }
    return list;
  }, [report.hosts, search, sortKey, sortDir]);

  function SortArrow({ k }: { k: SortKey }) {
    if (sortKey !== k) return <span style={{ opacity: 0.2 }}> ↕</span>;
    return <span style={{ color: "var(--accent)" }}>{sortDir === 1 ? " ↑" : " ↓"}</span>;
  }

  function ColHeader({ k, children }: { k: SortKey; children: React.ReactNode }) {
    return (
      <span
        onClick={() => handleSort(k)}
        style={{ cursor: "pointer", userSelect: "none" }}
        title={`Sort by ${k}`}
      >
        {children}<SortArrow k={k} />
      </span>
    );
  }

  return (
    <div>
      <SLabel>
        SESSION HOSTS
        <span style={{ fontSize: "9px", color: "var(--text-hi)", letterSpacing: "0.05em" }}>
          {report.hosts.length} host{report.hosts.length !== 1 ? "s" : ""}
          {report.elapsedSeconds != null && ` · last ${report.elapsedSeconds.toFixed(2)}s`}
        </span>
      </SLabel>

      {/* Search */}
      <div style={{ marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search address, hostname, service…"
          style={{
            flex: 1, padding: "4px 8px", fontSize: "10px",
            background: "var(--bg-input)", color: "var(--text-hi)",
            border: "1px solid var(--border)", letterSpacing: "0.02em",
          }}
        />
        {search && (
          <button onClick={() => setSearch("")} style={{
            fontSize: "10px", color: "var(--text-dim)",
            background: "transparent", border: "none", cursor: "pointer",
          }}>
            ✕
          </button>
        )}
      </div>

      <div style={{ border: "1px solid var(--border)" }}>
        {/* Header */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 72px 44px 34px 52px 36px 60px 18px",
          padding: "4px 8px",
          fontSize: "9px", letterSpacing: "0.1em", color: "var(--text-dim)",
          borderBottom: "1px solid var(--border)",
        }}>
          <ColHeader k="address">ADDR</ColHeader>
          <span>HOSTNAME</span>
          <span>STATE</span>
          <ColHeader k="open">OPEN</ColHeader>
          <ColHeader k="scanned">AGE</ColHeader>
          <ColHeader k="risk">RISK</ColHeader>
          <span>TAGS</span>
          <span />
        </div>

        {displayed.length === 0 && (
          <div style={{ padding: "10px 8px", fontSize: "10px", color: "var(--text-dim)" }}>
            No hosts match "{search}".
          </div>
        )}

        {displayed.map((host) => {
          const selected = host.address === selectedAddress;
          const hovered  = hoveredAddr === host.address;
          const up       = host.status === "up";
          const risk     = hostRiskLevel(host, findings);
          const { label: ageLabel, isStale } = formatScanAge(host.scannedAt, now);

          return (
            <div
              key={host.address}
              onClick={() => onSelect(selected ? null : host)}
              onMouseEnter={() => setHoveredAddr(host.address)}
              onMouseLeave={() => setHoveredAddr(null)}
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 72px 44px 34px 52px 36px 60px 18px",
                padding: "6px 8px",
                fontSize: "11px", cursor: "pointer", alignItems: "center",
                background: selected ? "rgba(0,255,170,0.06)" : hovered ? "rgba(255,255,255,0.02)" : "transparent",
                borderBottom: "1px solid var(--border)",
                borderLeft: selected ? "2px solid var(--accent)" : "2px solid transparent",
                transition: "background 0.12s",
              }}
            >
              <span style={{ fontFamily: "monospace", color: "var(--text-hi)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {host.address}
              </span>
              <span style={{ color: "var(--text-dim)", fontSize: "10px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {host.hostname ?? "—"}
              </span>
              <span style={{ color: up ? "var(--success)" : "var(--danger)", fontSize: "9px", letterSpacing: "0.1em" }}>
                {host.status.toUpperCase()}
              </span>
              <span style={{ textAlign: "right", color: "var(--accent)", fontFamily: "monospace" }}>
                {openCount(host)}
              </span>
              <span style={{ textAlign: "right", fontSize: "9px", color: isStale ? "var(--warning)" : "var(--text-dim)" }} title={host.scannedAt}>
                {ageLabel}
              </span>
              {/* Risk badge */}
              <span style={{
                fontSize: "7px", letterSpacing: "0.08em", padding: "1px 3px",
                color: RISK_COLOR[risk],
                border: risk !== "clean" ? `1px solid ${RISK_COLOR[risk]}44` : "1px solid transparent",
                textAlign: "center",
              }}>
                {RISK_LABEL[risk]}
              </span>
              {/* Tags */}
              <div style={{ display: "flex", gap: "2px", flexWrap: "wrap", overflow: "hidden" }}>
                {(host.tags ?? []).slice(0, 2).map((tag) => (
                  <span key={tag} style={{ fontSize: "7px", padding: "0 3px", color: "var(--accent2)", border: "1px solid rgba(56,189,248,0.35)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "52px" }}>{tag}</span>
                ))}
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); onRemoveHost(host.address); }}
                title="Remove host"
                style={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  width: "16px", height: "16px", fontSize: "11px",
                  color: hovered ? "var(--danger)" : "var(--text-dim)",
                  background: "transparent",
                  border: hovered ? "1px solid var(--danger)" : "1px solid transparent",
                  borderRadius: "2px", opacity: hovered ? 1 : 0.3, transition: "all 0.15s",
                }}
              >
                ×
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
