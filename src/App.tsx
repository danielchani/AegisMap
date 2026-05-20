import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import html2canvas from "html2canvas";
import { invoke } from "@tauri-apps/api/core";
import { NmapStatusBar } from "./components/NmapStatusBar";
import { PanelTabs } from "./components/PanelTabs";
import { ScannerPanel } from "./components/ScannerPanel";
import { SceneFilters } from "./components/SceneFilters";
import { SessionManager } from "./components/SessionManager";
import { PrintReport } from "./components/PrintReport";
import { ScanScene } from "./components/visualization/ScanScene";
import { useProvisionalHosts } from "./hooks/useProvisionalHosts";
import { appendAudit } from "./lib/auditLog";
import { listFindings } from "./lib/findings";
import { calculateConfidence } from "./lib/fingerprint";
import { diffSessions } from "./lib/sessionDiff";
import { mergeHost } from "./lib/mergeHosts";
import type { HostResult, PentestFinding, PortFamily, ScanReport, ScanStatus, SceneMode } from "./types";
import type { SessionDiffReport } from "./lib/sessionDiff";
import type { PanelTab } from "./stores/uiStore";
import "./App.css";

// ── Scope config key (stays in localStorage; no history needed) ──────────────
const SCOPE_KEY = "aegismap:scope";

// ── App ────────────────────────────────────────────────────────────────────────

export default function App() {
  const [status,          setStatus]          = useState<ScanStatus>("idle");
  const [latestReport,    setLatestReport]     = useState<ScanReport | null>(null);
  const [sessionHosts,    setSessionHosts]     = useState<HostResult[]>([]);
  const [finalizationId,  setFinalizationId]   = useState(0);
  const [selectedAddr,    setSelectedAddr]     = useState<string | null>(null);
  const [stdoutLines,     setStdoutLines]      = useState<string[]>([]);
  const [portFilter,      setPortFilter]       = useState<PortFamily>(null);
  const [panelWidth,      setPanelWidth]       = useState(380);
  const [authorizedRanges, setAuthorizedRanges] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(SCOPE_KEY) ?? "[]"); } catch { return []; }
  });
  const [storageError, setStorageError] = useState<string | null>(null);
  const [findings,     setFindings]     = useState<PentestFinding[]>([]);

  // ── Scene mode state (diff + confidence) ────────────────────────────────────
  const [sceneMode,        setSceneMode]        = useState<SceneMode>("network");
  const [diffBaseline,     setDiffBaseline]     = useState<HostResult[] | null>(null);
  const [diffBaselineName, setDiffBaselineName] = useState<string>("");
  const [visibleDiffStates, setVisibleDiffStates] = useState<Set<string>>(
    new Set(["added", "removed", "changed", "unchanged"]),
  );

  const diffReport = useMemo<SessionDiffReport | null>(
    () => (diffBaseline ? diffSessions(diffBaseline, sessionHosts) : null),
    [diffBaseline, sessionHosts],
  );

  const diffRemovedHosts = useMemo<HostResult[]>(() => {
    if (!diffReport || !diffBaseline) return [];
    const removed = new Set(diffReport.diffs.filter((d) => d.type === "removed").map((d) => d.address));
    return diffBaseline.filter((h) => removed.has(h.address));
  }, [diffReport, diffBaseline]);

  const confidenceMap = useMemo<Map<string, number>>(() => {
    const m = new Map<string, number>();
    sessionHosts.forEach((h) => m.set(h.address, calculateConfidence(h).overall));
    return m;
  }, [sessionHosts]);

  // ── New UI state ─────────────────────────────────────────────────────────────
  const [activeTab,        setActiveTab]        = useState<PanelTab>("scan");
  const [highContrast,     setHighContrast]     = useState(false);
  const [showLabels,       setShowLabels]       = useState(true);
  const [showConnections,  setShowConnections]  = useState(true);
  const [visibleRiskLevels, setVisibleRiskLevels] = useState<Set<string>>(
    new Set(["clean", "low", "medium", "high", "critical"])
  );

  const dragging   = useRef(false);
  const dragStart  = useRef(0);
  const widthStart = useRef(380);
  const canvasRef  = useRef<HTMLDivElement>(null);

  const provisionalHosts = useProvisionalHosts(stdoutLines);

  // ── High contrast toggle ────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.classList.toggle("high-contrast", highContrast);
  }, [highContrast]);

  // ── DB init + legacy migration ────────────────────────────────────────────────

  useEffect(() => {
    void (async () => {
      // One-shot migration: if SQLite is empty and localStorage has old data, migrate.
      const needsMigration = await invoke<boolean>("check_migration_needed").catch(() => false);
      if (needsMigration) {
        const ls = localStorage.getItem("aegismap:session");
        const lsSaved = localStorage.getItem("aegismap:saved-sessions");
        const lsAudit = localStorage.getItem("aegismap:audit");
        if (ls || lsSaved || lsAudit) {
          try {
            await invoke("migrate_from_legacy", {
              data: {
                activeSession:  ls      ? JSON.parse(ls)      : null,
                namedSessions:  lsSaved ? JSON.parse(lsSaved) : null,
                auditEntries:   lsAudit ? JSON.parse(lsAudit) : null,
              },
            });
            // Clear legacy keys only after successful migration
            localStorage.removeItem("aegismap:session");
            localStorage.removeItem("aegismap:saved-sessions");
            localStorage.removeItem("aegismap:audit");
          } catch (err) { console.error("[AegisMap] Legacy migration failed:", err); }
        }
      }

      // Load active session from SQLite into local state
      const hosts = await invoke<HostResult[]>("get_active_session").catch(() => []);
      if (Array.isArray(hosts) && hosts.length > 0) setSessionHosts(hosts);

      // Load findings for the active session
      const loadedFindings = await listFindings("active").catch(() => []);
      if (loadedFindings.length > 0) setFindings(loadedFindings);

      // Dismiss splash screen
      const splash = document.getElementById("aegis-splash");
      if (splash) {
        splash.classList.add("fade-out");
        setTimeout(() => splash.remove(), 500);
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Persist active session to SQLite whenever it changes (debounced via setTimeout).
  useEffect(() => {
    const t = setTimeout(() => {
      void invoke("save_active_session", { hosts: sessionHosts }).catch((err) => {
        console.error("[AegisMap] Session persist failed:", err);
        setStorageError("Session could not be saved — changes may not persist across restarts.");
      });
    }, 200);
    return () => clearTimeout(t);
  }, [sessionHosts]);

  useEffect(() => {
    localStorage.setItem(SCOPE_KEY, JSON.stringify(authorizedRanges));
  }, [authorizedRanges]);

  // ── Resizable panel ──────────────────────────────────────────────────────────

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragging.current) return;
      setPanelWidth(Math.min(600, Math.max(280, widthStart.current + e.clientX - dragStart.current)));
    };
    const onUp = () => { dragging.current = false; };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
  }, []);

  function startDrag(e: React.MouseEvent) {
    dragging.current = true; dragStart.current = e.clientX; widthStart.current = panelWidth; e.preventDefault();
  }

  // ── Keyboard shortcuts ────────────────────────────────────────────────────────

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const inInput = ["INPUT", "TEXTAREA"].includes((document.activeElement as HTMLElement)?.tagName ?? "");
      if (e.key === "Escape") setSelectedAddr(null);
      if ((e.ctrlKey || e.metaKey) && e.key === "k") { e.preventDefault(); (document.querySelector("#scan-target") as HTMLInputElement | null)?.focus(); }
      if ((e.ctrlKey || e.metaKey) && e.key === "e") { e.preventDefault(); window.dispatchEvent(new CustomEvent("aegismap:export")); }
      if ((e.ctrlKey || e.metaKey) && e.key === "p") { e.preventDefault(); handlePrint(); }
      if (!inInput && e.key === "Delete" && selectedAddr) handleRemoveHost(selectedAddr);
      // Tab switching: Ctrl+1-5
      if ((e.ctrlKey || e.metaKey) && e.key >= "1" && e.key <= "5") {
        e.preventDefault();
        const tabs: PanelTab[] = ["scan", "results", "inspect", "findings", "audit"];
        setActiveTab(tabs[parseInt(e.key) - 1]);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedAddr]);

  // ── Auto-switch to inspect tab when selecting a host ─────────────────────────
  useEffect(() => {
    if (selectedAddr && activeTab !== "inspect") setActiveTab("inspect");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedAddr]);

  // ── Screenshot ──────────────────────────────────────────────────────────────

  function handleScreenshot() {
    const container = document.getElementById("scan-canvas");
    if (!container) { console.warn("AegisMap: scan-canvas not found"); return; }

    html2canvas(container, {
      useCORS:         true,
      allowTaint:      true,
      scale:           window.devicePixelRatio || 1,
      logging:         false,
      backgroundColor: "#020b18",
    }).then((offscreen) => {
      offscreen.toBlob((blob) => {
        if (!blob) { console.warn("AegisMap: toBlob returned null"); return; }
        const url = URL.createObjectURL(blob);
        const a   = document.createElement("a");
        a.href     = url;
        a.download = `aegismap-${Date.now()}.png`;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 150);
        void appendAudit("SCREENSHOT", "3D scene captured as PNG");
      }, "image/png", 1.0);
    }).catch((err) => console.error("AegisMap: screenshot failed", err));
  }

  // ── Print ────────────────────────────────────────────────────────────────────

  function handlePrint() {
    void appendAudit("PRINT", `Report printed for ${sessionHosts.length} host(s)`);
    window.print();
  }

  // ── Derived state ─────────────────────────────────────────────────────────────

  const selectedHost = useMemo(() => sessionHosts.find((h) => h.address === selectedAddr) ?? null, [sessionHosts, selectedAddr]);

  const displayReport = useMemo<ScanReport | null>(() => {
    if (sessionHosts.length === 0 && !latestReport) return null;
    // When hosts exist but no scan has been run yet (e.g. loaded session,
    // app restart with persisted data), synthesize a minimal report wrapper
    // so the 3D scene, results table, and print report all render correctly.
    const base = latestReport ?? {
      target: "session",
      profile: "quick_common_ports" as ScanReport["profile"],
      hosts: [],
    };
    return { ...base, hosts: sessionHosts };
  }, [latestReport, sessionHosts]);

  // ── Handlers ─────────────────────────────────────────────────────────────────

  const handleSelectHost = useCallback((h: HostResult | null) => setSelectedAddr(h?.address ?? null), []);

  const handleReportChange = useCallback((r: ScanReport | null) => {
    if (!r) return;
    setLatestReport(r);
    setFinalizationId((n) => n + 1);
    setSessionHosts((prev) => {
      const map = new Map(prev.map((h) => [h.address, h]));
      r.hosts.forEach((h) => {
        const existing = map.get(h.address);
        const stamped  = { ...h, scannedAt: new Date().toISOString() };
        map.set(h.address, existing ? mergeHost(existing, stamped) : stamped);
      });
      return Array.from(map.values());
    });
    // Auto-switch to results tab after scan
    setActiveTab("results");
  }, []);

  const handleUpdateHost = useCallback((address: string, patch: Partial<HostResult>) => {
    setSessionHosts((prev) => prev.map((h) => h.address === address ? { ...h, ...patch } : h));
  }, []);

  const handleRemoveHost = useCallback((address: string) => {
    setSessionHosts((prev) => prev.filter((h) => h.address !== address));
    setSelectedAddr((prev) => (prev === address ? null : prev));
    void appendAudit("REMOVE_HOST", address);
  }, []);

  const handleScanStart = useCallback(() => { setStdoutLines([]); setActiveTab("scan"); }, []);

  const handleClearSession = useCallback(() => {
    setSessionHosts([]); setLatestReport(null); setSelectedAddr(null); setStdoutLines([]); setPortFilter(null);
    setActiveTab("scan");
    void appendAudit("SESSION_CLEAR", "All session hosts cleared");
  }, []);

  const handleStdoutLine = useCallback((line: string) => setStdoutLines((p) => [...p, line]), []);

  const handleLoadSession = useCallback((hosts: HostResult[]) => {
    setSessionHosts((prev) => {
      const map = new Map(prev.map((h) => [h.address, h]));
      hosts.forEach((h) => { const ex = map.get(h.address); map.set(h.address, ex ? mergeHost(ex, h) : h); });
      return Array.from(map.values());
    });
    setActiveTab("results");
    void appendAudit("SESSION_LOAD", `Merged ${hosts.length} host(s) from saved session`);
  }, []);

  function handleScanStarted(target: string, profile: string, scopeWarned: boolean) {
    const extra = scopeWarned ? " [out-of-scope override]" : "";
    void appendAudit("SCAN_START", `${target} · ${profile}${extra}`);
  }

  function handleScanComplete(target: string, hostCount: number) {
    void appendAudit("SCAN_COMPLETE", `${target} → ${hostCount} host(s)`);
  }

  const handleToggleRiskLevel = useCallback((level: string) => {
    setVisibleRiskLevels((prev) => {
      const next = new Set(prev);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  }, []);

  const handleLoadDiffBaseline = useCallback(async (id: string, name: string) => {
    try {
      const hosts = await invoke<HostResult[]>("load_named_session", { id });
      setDiffBaseline(hosts);
      setDiffBaselineName(name);
    } catch (err) { console.error("[AegisMap] Failed to load diff baseline:", err); }
  }, []);

  const handleToggleDiffState = useCallback((state: string) => {
    setVisibleDiffStates((prev) => {
      const next = new Set(prev);
      if (next.has(state)) next.delete(state);
      else next.add(state);
      return next;
    });
  }, []);

  const handleSceneModeChange = useCallback((mode: SceneMode) => {
    setSceneMode(mode);
    if (mode !== "diff") {
      setDiffBaseline(null);
      setDiffBaselineName("");
    }
  }, []);

  return (
    <div className="hud-panel" style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden", background: "var(--bg)" }}>

      {/* Accessibility: skip-to-content link */}
      <a href="#scan-canvas" className="sr-only" tabIndex={0}>Skip to 3D view</a>

      {/* Header */}
      <header className="no-print" style={{
        display: "flex", alignItems: "center", gap: "1rem",
        padding: "0 1rem", height: "44px", flexShrink: 0,
        background: "var(--bg-panel)", borderBottom: "1px solid var(--border)", position: "relative",
      }}>
        <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: "1px", background: "linear-gradient(90deg, var(--accent) 0%, transparent 60%)", opacity: 0.4 }} />
        <div className="bracketed" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "2px 6px" }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <polygon points="12,2 22,20 2,20" fill="none" stroke="#00ffaa" strokeWidth="1.5" opacity="0.9" />
            <circle cx="12" cy="14" r="2.5" fill="#00ffaa" />
          </svg>
          <span className="neon" style={{ fontWeight: 700, fontSize: "12px", letterSpacing: "0.18em", color: "var(--accent)" }}>AEGISMAP</span>
          <span className="blink" style={{ color: "var(--accent)", fontSize: "12px" }} aria-hidden="true">_</span>
        </div>
        <div style={{ width: "1px", height: "18px", background: "var(--border-hi)" }} />
        <NmapStatusBar />
        <div style={{ flex: 1 }} />

        {/* High contrast toggle */}
        <button
          onClick={() => setHighContrast((v) => !v)}
          title={highContrast ? "Switch to standard theme" : "Switch to high contrast (accessibility)"}
          aria-label="Toggle high contrast mode"
          style={{
            fontSize: "9px", padding: "2px 6px", letterSpacing: "0.1em",
            color: highContrast ? "var(--accent)" : "var(--text-dim)",
            border: `1px solid ${highContrast ? "var(--accent)" : "var(--border)"}`,
            background: highContrast ? "var(--accent-dim)" : "transparent",
          }}
        >
          HC
        </button>

        {sessionHosts.length > 0 && (
          <div style={{ fontSize: "9px", letterSpacing: "0.1em", color: "var(--accent)", border: "1px solid var(--accent)", padding: "2px 6px", opacity: 0.7 }}>
            {sessionHosts.length} HOST{sessionHosts.length !== 1 ? "S" : ""}
          </div>
        )}
        <SessionManager currentHosts={sessionHosts} onLoad={handleLoadSession} onNewSession={handleClearSession} />
        <div style={{ fontSize: "9px", color: "var(--text-dim)", letterSpacing: "0.12em", display: "flex", alignItems: "center", gap: "6px" }}>
          <span style={{ color: "var(--border-hi)" }}>◈</span>NETWORK RECON v0.1
        </div>
      </header>

      {/* Storage error banner */}
      {storageError && (
        <div style={{ background: "rgba(251,191,36,0.1)", borderBottom: "1px solid var(--warning)", padding: "3px 1rem", fontSize: "9px", color: "var(--warning)", letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: "6px" }}>
          <span>⚠</span>{storageError}
          <button onClick={() => setStorageError(null)} style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--warning)", cursor: "pointer", fontSize: "11px" }}>×</button>
        </div>
      )}

      {/* Main split */}
      <main style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        <div className="hud-panel no-print" style={{ width: `${panelWidth}px`, flexShrink: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
          {/* Tab navigation */}
          <PanelTabs
            activeTab={activeTab}
            onTabChange={setActiveTab}
            hostCount={sessionHosts.length}
            hasSelection={!!selectedHost}
            findingCount={findings.length}
          />

          {/* Tab content */}
          <div style={{ flex: 1, overflowY: "auto" }}>
            <ScannerPanel
              status={status}
              report={displayReport}
              sessionHostCount={sessionHosts.length}
              selectedHost={selectedHost}
              portFilter={portFilter}
              authorizedRanges={authorizedRanges}
              activeTab={activeTab}
              onStatusChange={setStatus}
              onReportChange={handleReportChange}
              onSelectHost={handleSelectHost}
              onRemoveHost={handleRemoveHost}
              onUpdateHost={handleUpdateHost}
              onSetPortFilter={setPortFilter}
              onSetAuthorizedRanges={setAuthorizedRanges}
              onStdoutLine={handleStdoutLine}
              onScanStart={handleScanStart}
              onClearSession={handleClearSession}
              onPrint={handlePrint}
              onScanStarted={handleScanStarted}
              onScanComplete={handleScanComplete}
              findings={findings}
              sessionId="active"
              onFindingsChange={setFindings}
            />
          </div>

          {/* Keyboard hints footer */}
          <div className="no-print" style={{ padding: "4px 10px", fontSize: "7px", color: "var(--text-dim)", letterSpacing: "0.08em", borderTop: "1px solid var(--border)", flexShrink: 0 }}>
            Ctrl+K target · Ctrl+1-5 tabs · Ctrl+E export · Ctrl+P pdf · Esc deselect · Del remove
          </div>
        </div>

        <div onMouseDown={startDrag} className="no-print" style={{
          width: "4px", flexShrink: 0, background: "var(--border)", cursor: "col-resize", transition: "background 0.15s",
        }}
          onMouseEnter={(e) => (e.currentTarget.style.background = "var(--accent)")}
          onMouseLeave={(e) => (e.currentTarget.style.background = "var(--border)")}
        />

        <div ref={canvasRef} id="scan-canvas" style={{ flex: 1, position: "relative", background: "var(--bg)" }}>
          {/* 3D scene filter controls */}
          <SceneFilters
            visibleRiskLevels={visibleRiskLevels}
            onToggleRiskLevel={handleToggleRiskLevel}
            showLabels={showLabels}
            onToggleLabels={() => setShowLabels((v) => !v)}
            showConnections={showConnections}
            onToggleConnections={() => setShowConnections((v) => !v)}
            hostCount={sessionHosts.length}
            sceneMode={sceneMode}
            onSceneModeChange={handleSceneModeChange}
            diffReport={diffReport}
            diffBaselineName={diffBaselineName}
            onLoadDiffBaseline={handleLoadDiffBaseline}
            visibleDiffStates={visibleDiffStates}
            onToggleDiffState={handleToggleDiffState}
            confidenceMap={confidenceMap}
          />

          {/* Screenshot button */}
          <button
            onClick={handleScreenshot}
            title="Save 3D view as PNG (Ctrl+P for PDF report)"
            aria-label="Take screenshot of 3D scene"
            className="no-print"
            style={{
              position: "absolute", top: "10px", right: "10px", zIndex: 10,
              fontSize: "11px", padding: "4px 8px",
              background: "rgba(2,11,24,0.8)", color: "var(--text-dim)",
              border: "1px solid var(--border)", cursor: "pointer",
              transition: "all 0.15s",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--accent)"; e.currentTarget.style.borderColor = "var(--accent)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-dim)"; e.currentTarget.style.borderColor = "var(--border)"; }}
          >
            ⎙
          </button>
          <ScanScene
            status={status}
            report={displayReport}
            finalizationId={finalizationId}
            provisionalHosts={provisionalHosts}
            selectedHost={selectedHost}
            portFilter={portFilter}
            onSelectHost={handleSelectHost}
            showLabels={showLabels}
            showConnections={showConnections}
            visibleRiskLevels={visibleRiskLevels}
            sceneMode={sceneMode}
            diffReport={diffReport}
            diffRemovedHosts={diffRemovedHosts}
            visibleDiffStates={visibleDiffStates}
            confidenceMap={confidenceMap}
            findings={findings}
          />
        </div>
      </main>

      {/* Hidden print report — activated by window.print() */}
      {displayReport && (
        <PrintReport report={displayReport} sessionHosts={sessionHosts} findings={findings} />
      )}
    </div>
  );
}
