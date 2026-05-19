/**
 * Append-only audit log — SQLite-backed via Rust backend.
 *
 * The SHA-256 chain hash is computed in Rust (db_audit.rs) using the same
 * "aegismap-audit-chain-v2:" prefix as the previous localStorage implementation,
 * so entries migrated from localStorage verify correctly.
 *
 * All functions are async. Call sites should use `void appendAudit(...)` for
 * fire-and-forget logging (non-critical path).
 */

import { invoke } from "@tauri-apps/api/core";

export interface AuditEntry {
  timestamp: string;
  action: string;
  details: string;
  hash: string; // 64-char SHA-256 hex
}

/**
 * Appends an audit entry. Fire-and-forget at call sites:
 *   `void appendAudit("ACTION", "details")`
 */
export async function appendAudit(action: string, details: string): Promise<void> {
  try {
    await invoke("append_audit_entry", { action, details });
  } catch {
    /* non-critical — silently ignored */
  }
}

/**
 * Loads audit entries from SQLite, oldest first.
 * Pass `limit` to get the most recent N entries.
 */
export async function loadAudit(limit?: number): Promise<AuditEntry[]> {
  try {
    return await invoke<AuditEntry[]>("load_audit_entries", {
      limit: limit ?? null,
    });
  } catch {
    return [];
  }
}

/** Removes all audit entries. */
export async function clearAudit(): Promise<void> {
  try {
    await invoke("clear_audit_log");
  } catch {
    /* non-critical */
  }
}

/**
 * Verifies the SHA-256 chain. Returns `{ valid, brokenAt? }`.
 * Compatible with the previous localStorage-based API shape.
 */
export async function verifyAuditChain(): Promise<{
  valid: boolean;
  brokenAt?: number;
  migrated?: boolean;
}> {
  try {
    const result = await invoke<{ valid: boolean; brokenAt?: number }>(
      "verify_audit_chain",
    );
    return { valid: result.valid, brokenAt: result.brokenAt };
  } catch {
    return { valid: false };
  }
}
