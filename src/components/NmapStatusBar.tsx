import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { NmapStatus } from "../types";

export function NmapStatusBar() {
  const [status, setStatus] = useState<NmapStatus | null>(null);

  useEffect(() => {
    invoke<NmapStatus>("detect_nmap")
      .then(setStatus)
      .catch(() => setStatus({ installed: false, error: "invoke failed" }));
  }, []);

  const dotStyle = (color: string, pulse = false): React.CSSProperties => ({
    width: "6px",
    height: "6px",
    borderRadius: "50%",
    background: color,
    boxShadow: `0 0 5px ${color}`,
    flexShrink: 0,
    animation: pulse ? "nmapPulse 2s ease-in-out infinite" : "none",
  });

  if (!status) {
    return (
      <span style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "11px", color: "var(--text-dim)" }}>
        <span style={dotStyle("#334155")} />
        CHECKING…
      </span>
    );
  }

  if (status.installed) {
    return (
      <>
        {/* nmapPulse keyframe is defined in App.css */}
        <span style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "11px", color: "var(--accent)" }}>
          <span style={dotStyle("var(--accent)", true)} />
          NMAP {status.version}
        </span>
      </>
    );
  }

  return (
    <span style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "11px", color: "var(--danger)" }}
      title={status.error}>
      <span style={dotStyle("var(--danger)")} />
      NMAP NOT FOUND
    </span>
  );
}
