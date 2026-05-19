/**
 * Tests for auditLog.ts wrapper functions.
 * Since the implementation delegates to Rust via invoke(), we mock invoke()
 * and verify the wrappers call the right commands with the right arguments.
 * The actual SHA-256 chain logic is tested in Rust (db_audit.rs tests).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { appendAudit, loadAudit, clearAudit, verifyAuditChain } from "./auditLog";

// Mock Tauri's invoke
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
const mockInvoke = vi.mocked(invoke);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("appendAudit", () => {
  it("calls append_audit_entry with action and details", async () => {
    mockInvoke.mockResolvedValueOnce(undefined);
    await appendAudit("TEST", "detail");
    expect(mockInvoke).toHaveBeenCalledWith("append_audit_entry", { action: "TEST", details: "detail" });
  });

  it("silently ignores errors (non-critical path)", async () => {
    mockInvoke.mockRejectedValueOnce(new Error("DB error"));
    await expect(appendAudit("X", "y")).resolves.toBeUndefined();
  });
});

describe("loadAudit", () => {
  it("calls load_audit_entries with null limit when unspecified", async () => {
    mockInvoke.mockResolvedValueOnce([]);
    await loadAudit();
    expect(mockInvoke).toHaveBeenCalledWith("load_audit_entries", { limit: null });
  });

  it("calls load_audit_entries with provided limit", async () => {
    mockInvoke.mockResolvedValueOnce([]);
    await loadAudit(50);
    expect(mockInvoke).toHaveBeenCalledWith("load_audit_entries", { limit: 50 });
  });

  it("returns entries from backend", async () => {
    const entries = [
      { timestamp: "2024-01-01T00:00:00Z", action: "SCAN_START", details: "10.0.0.1", hash: "a".repeat(64) },
    ];
    mockInvoke.mockResolvedValueOnce(entries);
    const result = await loadAudit();
    expect(result).toEqual(entries);
  });

  it("returns empty array on error", async () => {
    mockInvoke.mockRejectedValueOnce(new Error("error"));
    expect(await loadAudit()).toEqual([]);
  });
});

describe("clearAudit", () => {
  it("calls clear_audit_log", async () => {
    mockInvoke.mockResolvedValueOnce(undefined);
    await clearAudit();
    expect(mockInvoke).toHaveBeenCalledWith("clear_audit_log");
  });

  it("silently ignores errors", async () => {
    mockInvoke.mockRejectedValueOnce(new Error("error"));
    await expect(clearAudit()).resolves.toBeUndefined();
  });
});

describe("verifyAuditChain", () => {
  it("calls verify_audit_chain and returns valid result", async () => {
    mockInvoke.mockResolvedValueOnce({ valid: true, brokenAt: undefined });
    const result = await verifyAuditChain();
    expect(mockInvoke).toHaveBeenCalledWith("verify_audit_chain");
    expect(result.valid).toBe(true);
  });

  it("returns broken chain info", async () => {
    mockInvoke.mockResolvedValueOnce({ valid: false, brokenAt: 3 });
    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(3);
  });

  it("returns invalid on error", async () => {
    mockInvoke.mockRejectedValueOnce(new Error("error"));
    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
  });
});
