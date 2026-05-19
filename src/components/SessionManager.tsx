import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import type { HostResult } from "../types";

// Session listing as returned by the DB (no hosts array — loaded on demand)
interface ListedSession {
  id: string;
  name: string;
  savedAt: string;
  hostCount: number;
}

interface Props {
  currentHosts: HostResult[];
  onLoad: (hosts: HostResult[]) => void;
}

export function SessionManager({ currentHosts, onLoad }: Props) {
  const [open,          setOpen]          = useState(false);
  const [saved,         setSaved]         = useState<ListedSession[]>([]);
  const [showNameInput, setShowNameInput] = useState(false);
  const [nameValue,     setNameValue]     = useState("");
  const [confirmLoad,   setConfirmLoad]   = useState<ListedSession | null>(null);
  const [loading,       setLoading]       = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);

  // Load session list from SQLite on mount and when panel opens
  const refreshList = () => {
    invoke<ListedSession[]>("list_named_sessions")
      .then(setSaved)
      .catch(() => setSaved([]));
  };

  useEffect(() => { refreshList(); }, []);
  useEffect(() => { if (open) refreshList(); }, [open]);

  async function handleSaveConfirm() {
    const name = nameValue.trim();
    if (!name) return;
    setLoading(true);
    try {
      await invoke("save_named_session", { name, hosts: currentHosts });
      await refreshList();
    } catch { /* silently ignored */ } finally {
      setLoading(false);
      setShowNameInput(false);
      setNameValue("");
    }
  }

  async function handleLoadConfirm() {
    if (!confirmLoad) return;
    setLoading(true);
    try {
      const hosts = await invoke<HostResult[]>("load_named_session", { id: confirmLoad.id });
      onLoad(hosts);
    } catch { /* silently ignored */ } finally {
      setLoading(false);
      setConfirmLoad(null);
      setOpen(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await invoke("delete_named_session", { id });
      setSaved((prev) => prev.filter((s) => s.id !== id));
    } catch { /* silently ignored */ }
  }

  function getDropdownStyle(): React.CSSProperties {
    const rect = btnRef.current?.getBoundingClientRect();
    return {
      position: "fixed",
      top:   rect ? rect.bottom + 4 : 52,
      right: rect ? window.innerWidth - rect.right : 16,
      width: "280px",
      zIndex: 9999,
      background: "var(--bg-panel)",
      border: "1px solid var(--border-hi)",
      boxShadow: "0 8px 32px rgba(0,0,0,0.75), 0 0 0 1px rgba(0,255,170,0.06)",
    };
  }

  return (
    <div style={{ position: "relative" }}>
      <button
        ref={btnRef}
        onClick={() => setOpen((o) => !o)}
        style={{
          fontSize: "9px", letterSpacing: "0.12em", padding: "3px 8px",
          color:      open ? "var(--accent)" : "var(--text-dim)",
          border:     `1px solid ${open ? "var(--accent)" : "var(--border)"}`,
          background: open ? "var(--accent-dim)" : "transparent",
          transition: "all 0.15s",
        }}
        title="Manage saved sessions"
      >
        ◈ SESSIONS {saved.length > 0 && `(${saved.length})`}
      </button>

      {open && createPortal(
        <>
          <div
            onClick={() => { setOpen(false); setShowNameInput(false); setConfirmLoad(null); }}
            style={{ position: "fixed", inset: 0, zIndex: 9998 }}
          />

          <div style={getDropdownStyle()}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "7px 10px", borderBottom: "1px solid var(--border)", fontSize: "9px", letterSpacing: "0.14em", color: "var(--text-dim)" }}>
              <span>◈ SAVED SESSIONS</span>
              {currentHosts.length > 0 && !showNameInput && (
                <button
                  onClick={(e) => { e.stopPropagation(); setNameValue(`Session ${new Date().toLocaleDateString()}`); setShowNameInput(true); }}
                  style={{ fontSize: "9px", padding: "2px 6px", color: "var(--accent)", border: "1px solid var(--accent)", background: "transparent", letterSpacing: "0.1em", cursor: "pointer" }}
                >
                  + SAVE CURRENT
                </button>
              )}
            </div>

            {/* Name input */}
            {showNameInput && (
              <div onClick={(e) => e.stopPropagation()} style={{ padding: "8px 10px", borderBottom: "1px solid var(--border)", display: "flex", flexDirection: "column", gap: "5px" }}>
                <div style={{ fontSize: "9px", color: "var(--text-dim)", letterSpacing: "0.1em" }}>SESSION NAME</div>
                <input
                  autoFocus
                  value={nameValue}
                  onChange={(e) => setNameValue(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") void handleSaveConfirm(); if (e.key === "Escape") setShowNameInput(false); }}
                  style={{ width: "100%", padding: "4px 8px", fontSize: "11px", background: "var(--bg-input)", color: "var(--text-hi)", border: "1px solid var(--accent)", outline: "none" }}
                />
                <div style={{ display: "flex", gap: "4px" }}>
                  <button onClick={() => void handleSaveConfirm()} disabled={!nameValue.trim() || loading} style={{ flex: 1, padding: "3px 0", fontSize: "9px", color: "var(--accent)", border: "1px solid var(--accent)", background: "transparent", cursor: "pointer", letterSpacing: "0.1em" }}>
                    {loading ? "…" : "SAVE"}
                  </button>
                  <button onClick={() => setShowNameInput(false)} style={{ flex: 1, padding: "3px 0", fontSize: "9px", color: "var(--text-dim)", border: "1px solid var(--border)", background: "transparent", cursor: "pointer" }}>CANCEL</button>
                </div>
              </div>
            )}

            {/* Load confirm */}
            {confirmLoad && (
              <div onClick={(e) => e.stopPropagation()} style={{ padding: "8px 10px", borderBottom: "1px solid var(--border)", background: "rgba(56,189,248,0.05)" }}>
                <div style={{ fontSize: "9px", color: "var(--text-hi)", marginBottom: "6px" }}>
                  Merge <strong>{confirmLoad.hostCount}</strong> host(s) from <em>"{confirmLoad.name}"</em> into current session?
                </div>
                <div style={{ display: "flex", gap: "4px" }}>
                  <button onClick={() => void handleLoadConfirm()} disabled={loading} style={{ flex: 1, padding: "3px 0", fontSize: "9px", color: "var(--accent2)", border: "1px solid var(--accent2)", background: "transparent", cursor: "pointer", letterSpacing: "0.1em" }}>
                    {loading ? "…" : "MERGE"}
                  </button>
                  <button onClick={() => setConfirmLoad(null)} style={{ flex: 1, padding: "3px 0", fontSize: "9px", color: "var(--text-dim)", border: "1px solid var(--border)", background: "transparent", cursor: "pointer" }}>CANCEL</button>
                </div>
              </div>
            )}

            {/* Session list */}
            {saved.length === 0 ? (
              <div style={{ padding: "12px 10px", fontSize: "10px", color: "var(--text-dim)" }}>
                No saved sessions yet. Run a scan and click + SAVE CURRENT.
              </div>
            ) : (
              <div style={{ maxHeight: "320px", overflowY: "auto" }}>
                {saved.map((s) => (
                  <div key={s.id} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "7px 10px", borderBottom: "1px solid var(--border)", fontSize: "11px" }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: "var(--text-hi)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.name}</div>
                      <div style={{ fontSize: "9px", color: "var(--text-dim)", marginTop: "1px" }}>
                        {s.hostCount} host{s.hostCount !== 1 ? "s" : ""} · {new Date(s.savedAt).toLocaleDateString()}
                      </div>
                    </div>
                    <button onClick={() => setConfirmLoad(s)} title="Merge into current session" style={{ fontSize: "9px", padding: "2px 5px", color: "var(--accent2)", border: "1px solid var(--accent2)", background: "transparent", cursor: "pointer" }}>LOAD</button>
                    <button onClick={() => void handleDelete(s.id)} title="Delete this session" style={{ fontSize: "11px", padding: "1px 5px", color: "var(--danger)", border: "1px solid transparent", background: "transparent", cursor: "pointer" }}>×</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>,
        document.body
      )}
    </div>
  );
}
