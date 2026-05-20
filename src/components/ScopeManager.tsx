import { useState } from "react";
import { validateScopeRange } from "../lib/scopeUtils";

interface Props {
  ranges: string[];
  onChange: (ranges: string[]) => void;
}

export function ScopeManager({ ranges, onChange }: Props) {
  const [input, setInput]   = useState("");
  const [error, setError]   = useState<string | null>(null);
  const [open,  setOpen]    = useState(false);

  function handleAdd() {
    const err = validateScopeRange(input);
    if (err) { setError(err); return; }
    onChange([...ranges, input.trim()]);
    setInput("");
    setError(null);
  }

  function handleRemove(r: string) {
    onChange(ranges.filter((x) => x !== r));
  }

  return (
    <div>
      {/* Toggle header */}
      <div
        onClick={() => setOpen((o) => !o)}
        style={{
          display: "flex", alignItems: "center", gap: "8px", cursor: "pointer",
          fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)",
          marginBottom: open ? "7px" : 0,
        }}
      >
        <span style={{ color: "var(--accent)", opacity: 0.5 }}>◈</span>
        ENGAGEMENT SCOPE
        {ranges.length > 0 && (
          <span style={{ color: "var(--success)", marginLeft: "2px" }}>
            ({ranges.length} range{ranges.length !== 1 ? "s" : ""})
          </span>
        )}
        <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
        <span style={{ fontSize: "8px" }}>{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
          <div style={{ fontSize: "9px", color: "var(--text-dim)", lineHeight: "1.4" }}>
            Define authorised IP ranges. Targets outside scope show a warning before scanning.
          </div>

          {/* Existing ranges */}
          {ranges.map((r) => (
            <div key={r} style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{
                flex: 1, fontFamily: "monospace", fontSize: "10px",
                color: "var(--success)", padding: "2px 6px",
                background: "rgba(74,222,128,0.06)", border: "1px solid rgba(74,222,128,0.2)",
              }}>
                ✓ {r}
              </span>
              <button
                onClick={() => handleRemove(r)}
                style={{ fontSize: "10px", color: "var(--danger)", background: "transparent", border: "none" }}
              >
                ×
              </button>
            </div>
          ))}

          {/* Add range input */}
          <div style={{ display: "flex", gap: "5px" }}>
            <input
              value={input}
              onChange={(e) => { setInput(e.target.value); setError(null); }}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              placeholder="192.168.1.0/24 or 10.0.0.1"
              style={{
                flex: 1, padding: "4px 8px", fontSize: "10px",
                background: "var(--bg-input)", color: "var(--text-hi)",
                border: `1px solid ${error ? "var(--danger)" : "var(--border)"}`,
              }}
            />
            <button
              onClick={handleAdd}
              style={{
                padding: "3px 8px", fontSize: "9px", letterSpacing: "0.1em",
                color: "var(--accent)", border: "1px solid var(--accent)",
                background: "transparent",
              }}
            >
              ADD
            </button>
          </div>
          {error && <div style={{ fontSize: "9px", color: "var(--danger)" }}>{error}</div>}
        </div>
      )}
    </div>
  );
}
