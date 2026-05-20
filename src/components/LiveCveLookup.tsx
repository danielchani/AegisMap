/**
 * LiveCveLookup — per-host opt-in CVE lookup against the NVD API v2.
 *
 * Security contract (enforced in Rust backend):
 *   - Product names validated before URL construction (no shell metacharacters)
 *   - HTTPS only; max 2 MB response body; max 20 results
 *   - CVE IDs validated to CVE-NNNN-N+ pattern; CVSS scores clamped to 0–10
 *   - Reference URLs HTTPS-only, max 10 per entry
 *   - Rate-limited server-side (6.5 s without API key, 700 ms with key)
 *   - Results cached 24 h in SQLite; never fetched automatically
 *   - All created findings start as confidence: "candidate" — never auto-confirmed
 */

import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { createFindingFromLiveCve } from "../lib/findings";
import type { CveFetchResult, HostResult, LiveCveEntry } from "../types";
import { SLabel } from "./ui/SLabel";

// ── Helpers ───────────────────────────────────────────────────────────────────

const ACTIVE_SESSION_ID = "active";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "var(--danger)",
  HIGH:     "#f97316",
  MEDIUM:   "var(--warning)",
  LOW:      "#22c55e",
  NONE:     "var(--text-dim)",
};

function severityColor(sev?: string): string {
  return SEVERITY_COLOR[sev?.toUpperCase() ?? ""] ?? "var(--text-dim)";
}

function cvssColor(score?: number): string {
  if (score === undefined) return "var(--text-dim)";
  if (score >= 9.0) return "var(--danger)";
  if (score >= 7.0) return "#f97316";
  if (score >= 4.0) return "var(--warning)";
  return "#22c55e";
}

/** Extracts unique (product, version, portRef) triplets from open ports. */
function extractProducts(host: HostResult): { product: string; version?: string; portRef: string }[] {
  const seen = new Set<string>();
  const results: { product: string; version?: string; portRef: string }[] = [];
  for (const p of host.ports) {
    if (p.state !== "open" || !p.product?.trim()) continue;
    const key = p.product.trim().toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    results.push({ product: p.product.trim(), version: p.version?.trim(), portRef: `${p.port}/${p.protocol}` });
  }
  return results;
}

function cacheAge(fetchedAt: string): string {
  const diff = Date.now() - new Date(fetchedAt).getTime();
  const h = Math.floor(diff / 3_600_000);
  if (h >= 1) return `${h}h ago`;
  const m = Math.floor(diff / 60_000);
  if (m >= 1) return `${m}m ago`;
  return "just now";
}

// ── Rate-limit countdown ──────────────────────────────────────────────────────

function useCountdown(initialMs: number): number {
  const [ms, setMs] = useState(initialMs);
  const ref = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    setMs(initialMs);
    if (ref.current) clearInterval(ref.current);
    if (initialMs <= 0) return;
    ref.current = setInterval(() => {
      setMs((prev) => {
        const next = prev - 200;
        if (next <= 0 && ref.current) { clearInterval(ref.current); return 0; }
        return next;
      });
    }, 200);
    return () => { if (ref.current) clearInterval(ref.current); };
  }, [initialMs]);
  return ms;
}

// ── CVE card ──────────────────────────────────────────────────────────────────

function CveCard({
  entry, hostAddress, portRef, detectedProduct, detectedVersion, onFindingCreated,
}: {
  entry: LiveCveEntry;
  hostAddress: string;
  portRef: string;
  detectedProduct: string;
  detectedVersion?: string;
  onFindingCreated?: () => void;
}) {
  const [creating, setCreating] = useState(false);
  const [created,  setCreated]  = useState(false);

  const score   = entry.cvssV3Score ?? entry.cvssV2Score;
  const scoreLabel = score !== undefined ? score.toFixed(1) : "—";
  const sev     = entry.cvssV3Severity;
  const scColor = cvssColor(score);
  const svColor = severityColor(sev);

  async function handleCreate() {
    setCreating(true);
    try {
      await createFindingFromLiveCve({
        sessionId: ACTIVE_SESSION_ID,
        hostAddress,
        portRef,
        entry,
        detectedProduct,
        detectedVersion,
      });
      setCreated(true);
      onFindingCreated?.();
    } catch (err) {
      console.error("[AegisMap] createFindingFromLiveCve failed:", err);
    } finally {
      setCreating(false);
    }
  }

  return (
    <div style={{
      padding: "7px 10px", marginBottom: "4px",
      border: "1px solid var(--border)",
      borderLeft: `2px solid ${scColor}`,
      background: "rgba(0,0,0,0.15)", fontSize: "10px",
    }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap", marginBottom: "4px" }}>
        <span style={{ fontFamily: "monospace", fontWeight: 700, color: "var(--accent)", fontSize: "11px" }}>
          {entry.cveId}
        </span>
        {score !== undefined && (
          <span style={{ fontWeight: 700, color: scColor, fontSize: "11px" }}>
            {scoreLabel}
          </span>
        )}
        {sev && (
          <span style={{
            fontSize: "7px", padding: "0 4px", letterSpacing: "0.08em",
            color: svColor, border: `1px solid ${svColor}`,
          }}>
            {sev}
          </span>
        )}
        <span style={{ fontSize: "8px", color: "var(--text-dim)", marginLeft: "auto" }}>
          {entry.published.slice(0, 10)}
        </span>
        {!created ? (
          <button
            onClick={() => void handleCreate()}
            disabled={creating}
            title="Create finding (candidate confidence)"
            style={{
              fontSize: "7px", padding: "0 5px", letterSpacing: "0.06em",
              color: creating ? "var(--text-dim)" : "var(--accent2)",
              border: `1px solid ${creating ? "var(--border)" : "var(--accent2)"}`,
              background: "transparent", cursor: creating ? "default" : "pointer",
            }}
          >
            {creating ? "…" : "+F"}
          </button>
        ) : (
          <span style={{ fontSize: "7px", color: "var(--success)", letterSpacing: "0.06em" }}>
            ✓ FINDING
          </span>
        )}
      </div>

      {/* Description */}
      {entry.description && (
        <p style={{
          margin: "0 0 4px", color: "var(--text)", lineHeight: 1.5,
          display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical",
          overflow: "hidden",
        }}>
          {entry.description}
        </p>
      )}

      {/* References */}
      {entry.references.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
          {entry.references.slice(0, 3).map((url, i) => (
            <span
              key={i}
              title={url}
              style={{
                fontSize: "8px", color: "var(--accent2)", letterSpacing: "0.04em",
                maxWidth: "220px", overflow: "hidden", textOverflow: "ellipsis",
                whiteSpace: "nowrap", cursor: "default",
              }}
            >
              ↗ {new URL(url).hostname}
            </span>
          ))}
          {entry.references.length > 3 && (
            <span style={{ fontSize: "8px", color: "var(--text-dim)" }}>
              +{entry.references.length - 3} more
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ── ProductRow ────────────────────────────────────────────────────────────────

type FetchState =
  | { status: "idle" }
  | { status: "fetching" }
  | { status: "loaded"; result: CveFetchResult; expanded: boolean }
  | { status: "error"; message: string; waitMs: number };

function ProductRow({
  product, version, portRef, host, rateMsRef, onFindingCreated,
}: {
  product: string;
  version?: string;
  portRef: string;
  host: HostResult;
  rateMsRef: React.MutableRefObject<number>;
  onFindingCreated?: () => void;
}) {
  const [state, setState] = useState<FetchState>({ status: "idle" });
  const countdownMs = useCountdown(state.status === "error" ? state.waitMs : 0);

  async function handleFetch() {
    setState({ status: "fetching" });
    try {
      const result = await invoke<CveFetchResult>("fetch_live_cves", {
        product,
        version: version ?? null,
      });
      setState({ status: "loaded", result, expanded: true });
    } catch (err) {
      const msg = typeof err === "string" ? err : String((err as { message?: string }).message ?? err);
      // Backend encodes rate limit wait as "RATE_LIMIT:<ms>"
      const rlMatch = msg.match(/RATE_LIMIT:(\d+)/);
      if (rlMatch) {
        const waitMs = Math.min(parseInt(rlMatch[1], 10), 7000);
        rateMsRef.current = waitMs;
        setState({ status: "error", message: "Rate limited by NVD API", waitMs });
      } else {
        setState({ status: "error", message: msg, waitMs: 0 });
      }
    }
  }

  const busy = state.status === "fetching";
  const readyAfterMs = state.status === "error" && state.waitMs > 0 ? countdownMs : 0;

  return (
    <div style={{ marginBottom: "6px" }}>
      {/* Trigger row */}
      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
        <span style={{ fontSize: "10px", color: "var(--text-hi)", fontFamily: "monospace", flex: 1 }}>
          {product}
          {version && <span style={{ color: "var(--text-dim)", marginLeft: "4px" }}>{version}</span>}
          <span style={{ color: "var(--text-dim)", marginLeft: "4px", fontSize: "9px" }}>:{portRef}</span>
        </span>

        {state.status === "loaded" && (
          <span style={{ fontSize: "9px", color: "var(--text-dim)" }}>
            {state.result.entries.length} CVE{state.result.entries.length !== 1 ? "s" : ""}
            {state.result.fromCache && ` · cached ${cacheAge(state.result.fetchedAt)}`}
            {state.result.totalAvailable > state.result.entries.length &&
              ` (of ${state.result.totalAvailable})`}
          </span>
        )}

        {readyAfterMs > 0 ? (
          <span style={{ fontSize: "8px", color: "var(--warning)" }}>
            wait {(readyAfterMs / 1000).toFixed(1)}s
          </span>
        ) : (
          <button
            onClick={() => void handleFetch()}
            disabled={busy}
            style={{
              padding: "2px 8px", fontSize: "8px", letterSpacing: "0.08em",
              color: busy ? "var(--text-dim)" : "var(--accent)",
              border: `1px solid ${busy ? "var(--border)" : "var(--accent)"}`,
              background: busy ? "transparent" : "var(--accent-dim)",
              cursor: busy ? "default" : "pointer", transition: "all 0.12s",
            }}
          >
            {busy ? "FETCHING…" : state.status === "loaded" ? "↺ REFRESH" : "FETCH CVEs"}
          </button>
        )}

        {state.status === "loaded" && state.result.entries.length > 0 && (
          <button
            onClick={() => setState((s) => s.status === "loaded"
              ? { ...s, expanded: !s.expanded } : s)}
            style={{
              padding: "2px 6px", fontSize: "8px",
              color: "var(--text-dim)", border: "1px solid var(--border)",
              background: "transparent", cursor: "pointer",
            }}
          >
            {state.status === "loaded" && state.expanded ? "▲" : "▼"}
          </button>
        )}
      </div>

      {/* Error */}
      {state.status === "error" && state.waitMs === 0 && (
        <div style={{ fontSize: "9px", color: "var(--danger)", marginTop: "3px" }}>
          ✗ {state.message}
        </div>
      )}

      {/* CVE list */}
      {state.status === "loaded" && state.expanded && (
        state.result.entries.length === 0 ? (
          <div style={{ fontSize: "9px", color: "var(--text-dim)", marginTop: "4px" }}>
            No CVEs found for "{product}" on NVD.
          </div>
        ) : (
          <div style={{ marginTop: "6px" }}>
            {state.result.entries.map((entry) => (
              <CveCard
                key={entry.cveId}
                entry={entry}
                hostAddress={host.address}
                portRef={portRef}
                detectedProduct={product}
                detectedVersion={version}
                onFindingCreated={onFindingCreated}
              />
            ))}
          </div>
        )
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props {
  host: HostResult;
  onFindingCreated?: () => void;
}

export function LiveCveLookup({ host, onFindingCreated }: Props) {
  const products = extractProducts(host);
  const [apiKeyConfigured, setApiKeyConfigured] = useState(false);
  const [showSettings,     setShowSettings]     = useState(false);
  const [apiKeyInput,      setApiKeyInput]       = useState("");
  const [savingKey,        setSavingKey]         = useState(false);
  const rateMsRef = useRef(0);

  useEffect(() => {
    void invoke<boolean>("get_nvd_api_key_status")
      .then((has) => setApiKeyConfigured(has))
      .catch(() => { /* non-critical */ });
  }, []);

  if (products.length === 0) return null;

  async function handleSaveKey() {
    setSavingKey(true);
    try {
      await invoke("set_nvd_api_key", { key: apiKeyInput.trim() || null });
      const has = await invoke<boolean>("get_nvd_api_key_status");
      setApiKeyConfigured(has);
      setShowSettings(false);
      setApiKeyInput("");
    } catch (err) {
      console.error("[AegisMap] set_nvd_api_key failed:", err);
    } finally {
      setSavingKey(false);
    }
  }

  async function handleClearKey() {
    try {
      await invoke("set_nvd_api_key", { key: null });
      setApiKeyConfigured(false);
      setShowSettings(false);
    } catch (err) {
      console.error("[AegisMap] clear nvd_api_key failed:", err);
    }
  }

  return (
    <div style={{ marginTop: "8px" }}>
      <SLabel>
        LIVE CVE LOOKUP
        <span style={{ fontSize: "8px", fontWeight: 400, opacity: 0.6, marginLeft: "4px" }}>(opt-in · NVD API v2)</span>
        {apiKeyConfigured && (
          <span style={{ fontSize: "7px", padding: "0 4px", color: "var(--success)", border: "1px solid var(--success)", marginLeft: "4px" }}>
            KEY SET
          </span>
        )}
        <button
          onClick={() => setShowSettings((v) => !v)}
          title="Configure NVD API key (optional — raises rate limit from 5 to 50 req/30s)"
          style={{
            fontSize: "8px", padding: "1px 5px",
            color: "var(--text-dim)", border: "1px solid var(--border)",
            background: "transparent", cursor: "pointer",
          }}
        >
          ⚙
        </button>
      </SLabel>

      {/* API key settings panel */}
      {showSettings && (
        <div style={{
          marginTop: "5px", padding: "7px 10px",
          background: "rgba(0,0,0,0.25)", border: "1px solid var(--border)",
          fontSize: "9px",
        }}>
          <div style={{ color: "var(--text-dim)", marginBottom: "5px", lineHeight: 1.4 }}>
            NVD API key is optional. Without one, rate limit is 5 req/30 s.
            With a key, 50 req/30 s. Keys are free at{" "}
            <span style={{ color: "var(--accent2)" }}>nvd.nist.gov/developers/request-an-api-key</span>
          </div>
          <div style={{ display: "flex", gap: "4px" }}>
            <input
              type="password"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              placeholder={apiKeyConfigured ? "Enter new key to replace…" : "Paste NVD API key…"}
              style={{
                flex: 1, padding: "3px 7px", fontSize: "9px",
                background: "var(--bg-input)", color: "var(--text-hi)",
                border: "1px solid var(--border)", outline: "none",
              }}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
              onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
            />
            <button
              onClick={() => void handleSaveKey()}
              disabled={savingKey || !apiKeyInput.trim()}
              style={{
                padding: "3px 8px", fontSize: "8px",
                color: "var(--accent)", border: "1px solid var(--accent)",
                background: "transparent", cursor: "pointer",
              }}
            >
              SAVE
            </button>
            {apiKeyConfigured && (
              <button
                onClick={() => void handleClearKey()}
                style={{
                  padding: "3px 8px", fontSize: "8px",
                  color: "var(--danger)", border: "1px solid var(--danger)",
                  background: "transparent", cursor: "pointer",
                }}
              >
                CLEAR
              </button>
            )}
          </div>
        </div>
      )}

      {/* Per-product fetch rows */}
      <div style={{ marginTop: "6px" }}>
        {products.map(({ product, version, portRef }) => (
          <ProductRow
            key={product.toLowerCase()}
            product={product}
            version={version}
            portRef={portRef}
            host={host}
            rateMsRef={rateMsRef}
            onFindingCreated={onFindingCreated}
          />
        ))}
      </div>
    </div>
  );
}
