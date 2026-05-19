/**
 * Append-only audit log with SHA-256 chained integrity.
 *
 * Each entry includes the SHA-256 digest of the previous entry's hash,
 * forming a sequential chain. Modifications, insertions, or deletions that
 * break the chain are detected by verifyAuditChain().
 *
 * Security model: this is a local, keyless integrity chain. It detects
 * accidental corruption and unsophisticated tampering. It does NOT protect
 * against a determined actor with direct localStorage access who can
 * recompute the chain — the verification algorithm is open source.
 * Suitable for audit trail purposes, not forensic-grade evidence.
 */

const AUDIT_KEY = "aegismap:audit";
const MAX_ENTRIES = 500;
const CHAIN_VERSION = 2;

/** Domain separator prepended to each hash input. */
const CHAIN_PREFIX = "aegismap-audit-chain-v2";

/** Sentinel previous-hash for the first entry in a chain. */
const CHAIN_GENESIS =
  "0000000000000000000000000000000000000000000000000000000000000000";

export interface AuditEntry {
  timestamp: string;
  action: string;
  details: string;
  /** SHA-256 chain digest (64 lowercase hex chars). */
  hash: string;
}

interface AuditLogStore {
  version: number;
  entries: AuditEntry[];
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────

/** Returns the SHA-256 digest of `input` as 64 lowercase hex chars. */
async function chainHash(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function computeEntryHash(
  prevHash: string,
  timestamp: string,
  action: string,
  details: string,
): Promise<string> {
  return chainHash(`${CHAIN_PREFIX}:${prevHash}:${timestamp}:${action}:${details}`);
}

// ── Storage helpers ────────────────────────────────────────────────────────────

function loadStore(): AuditLogStore {
  try {
    const raw = localStorage.getItem(AUDIT_KEY);
    if (!raw) return { version: CHAIN_VERSION, entries: [] };
    const parsed: unknown = JSON.parse(raw);
    // v1 format is a plain AuditEntry[]; v2 is { version, entries }.
    if (Array.isArray(parsed)) {
      return { version: 1, entries: parsed as AuditEntry[] };
    }
    return parsed as AuditLogStore;
  } catch {
    return { version: CHAIN_VERSION, entries: [] };
  }
}

function saveStore(entries: AuditEntry[]): void {
  const store: AuditLogStore = { version: CHAIN_VERSION, entries };
  localStorage.setItem(AUDIT_KEY, JSON.stringify(store));
}

/**
 * Re-signs every entry with SHA-256, preserving all original field values.
 * Used to migrate v1 (djb2) logs to v2 (SHA-256) transparently.
 */
async function resignChain(entries: AuditEntry[]): Promise<AuditEntry[]> {
  const result: AuditEntry[] = [];
  let prevHash = CHAIN_GENESIS;
  for (const entry of entries) {
    const hash = await computeEntryHash(
      prevHash, entry.timestamp, entry.action, entry.details,
    );
    result.push({ ...entry, hash });
    prevHash = hash;
  }
  return result;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Appends an audit entry. Async because SHA-256 is used for chain integrity.
 * Call sites should use `void appendAudit(...)` (fire-and-forget) — the audit
 * log is non-critical and must not block UI operations.
 */
export async function appendAudit(action: string, details: string): Promise<void> {
  try {
    const store = loadStore();
    let entries = store.entries;

    // Transparently migrate v1 entries before appending a new one.
    if (store.version < CHAIN_VERSION && entries.length > 0) {
      entries = await resignChain(entries);
    }

    const prevHash = entries.length > 0
      ? entries[entries.length - 1].hash
      : CHAIN_GENESIS;
    const timestamp = new Date().toISOString();
    const hash = await computeEntryHash(prevHash, timestamp, action, details);

    entries.push({ timestamp, action, details, hash });
    if (entries.length > MAX_ENTRIES) {
      entries.splice(0, entries.length - MAX_ENTRIES);
    }
    saveStore(entries);
  } catch {
    /* storage unavailable — silently ignored */
  }
}

/** Returns all stored audit entries (most recent last). Synchronous. */
export function loadAudit(): AuditEntry[] {
  return loadStore().entries;
}

/** Removes all audit entries from storage. */
export function clearAudit(): void {
  localStorage.removeItem(AUDIT_KEY);
}

/**
 * Verifies the SHA-256 integrity chain.
 *
 * If the stored log is in the old v1 (djb2) format, it is automatically
 * re-signed with SHA-256 and saved — `migrated: true` is set in the result
 * so callers can show a one-time upgrade notice.
 *
 * Returns:
 *   { valid: true }               — chain is intact
 *   { valid: false, brokenAt: N } — chain broken at entry index N
 *   { migrated: true }            — log was silently upgraded from v1 to v2
 */
export async function verifyAuditChain(
  log?: AuditEntry[],
): Promise<{ valid: boolean; brokenAt?: number; migrated?: boolean }> {
  let entries = log ?? loadAudit();
  let migrated = false;

  // Auto-migrate v1 logs when verifying directly from storage.
  if (!log) {
    const store = loadStore();
    if (store.version < CHAIN_VERSION && store.entries.length > 0) {
      entries = await resignChain(store.entries);
      saveStore(entries);
      migrated = true;
    }
  }

  if (entries.length === 0) return { valid: true, migrated };

  for (let i = 0; i < entries.length; i++) {
    const prevHash = i === 0 ? CHAIN_GENESIS : entries[i - 1].hash;
    const expected = await computeEntryHash(
      prevHash, entries[i].timestamp, entries[i].action, entries[i].details,
    );
    if (entries[i].hash !== expected) {
      return { valid: false, brokenAt: i, migrated };
    }
  }
  return { valid: true, migrated };
}
