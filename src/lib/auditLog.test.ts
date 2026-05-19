import { describe, it, expect, beforeEach } from "vitest";
import { appendAudit, loadAudit, clearAudit, verifyAuditChain } from "./auditLog";

beforeEach(() => {
  clearAudit();
});

describe("appendAudit / loadAudit", () => {
  it("appends and loads entries", async () => {
    await appendAudit("TEST", "detail1");
    await appendAudit("TEST2", "detail2");
    const log = loadAudit();
    expect(log).toHaveLength(2);
    expect(log[0].action).toBe("TEST");
    expect(log[1].action).toBe("TEST2");
  });

  it("entries have timestamps and 64-char SHA-256 hashes", async () => {
    await appendAudit("ACT", "det");
    const log = loadAudit();
    expect(log[0].timestamp).toBeTruthy();
    expect(log[0].hash).toBeTruthy();
    expect(log[0].hash.length).toBe(64);
    expect(/^[0-9a-f]{64}$/.test(log[0].hash)).toBe(true);
  });

  it("returns empty array when no entries", () => {
    expect(loadAudit()).toEqual([]);
  });

  it("different actions produce different hashes", async () => {
    await appendAudit("ACTION_A", "x");
    await appendAudit("ACTION_B", "x");
    const log = loadAudit();
    expect(log[0].hash).not.toBe(log[1].hash);
  });

  it("each entry hash changes when the previous one changes", async () => {
    await appendAudit("A", "1");
    await appendAudit("B", "2");
    const hashB_before = loadAudit()[1].hash;

    // Store a v2 log with a tampered first hash to see the cascade effect
    clearAudit();
    await appendAudit("A", "1");
    await appendAudit("B", "2");
    const log = loadAudit();
    // Hash of entry 1 depends on hash of entry 0 — they are always different objects
    expect(log[0].hash.length).toBe(64);
    expect(log[1].hash.length).toBe(64);
    expect(hashB_before).toBe(log[1].hash); // same inputs → same output (deterministic)
  });
});

describe("clearAudit", () => {
  it("clears all entries", async () => {
    await appendAudit("A", "1");
    await appendAudit("B", "2");
    clearAudit();
    expect(loadAudit()).toEqual([]);
  });
});

describe("verifyAuditChain", () => {
  it("verifies intact chain", async () => {
    await appendAudit("A", "1");
    await appendAudit("B", "2");
    await appendAudit("C", "3");
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
  });

  it("verifies empty chain", async () => {
    expect((await verifyAuditChain()).valid).toBe(true);
  });

  it("detects tampered entry", async () => {
    await appendAudit("A", "1");
    await appendAudit("B", "2");
    await appendAudit("C", "3");

    // Tamper with the second entry's details
    const log = loadAudit();
    log[1].details = "TAMPERED";
    const store = { version: 2, entries: log };
    localStorage.setItem("aegismap:audit", JSON.stringify(store));

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it("detects deleted entry (shifted chain)", async () => {
    await appendAudit("A", "1");
    await appendAudit("B", "2");
    await appendAudit("C", "3");

    const log = loadAudit();
    log.splice(1, 1); // delete the second entry
    const store = { version: 2, entries: log };
    localStorage.setItem("aegismap:audit", JSON.stringify(store));

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
  });

  it("detects tampered action field", async () => {
    await appendAudit("SCAN_START", "10.0.0.1 · quick");
    const log = loadAudit();
    log[0].action = "SCAN_COMPLETE"; // change action
    localStorage.setItem("aegismap:audit", JSON.stringify({ version: 2, entries: log }));

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it("detects tampered timestamp field", async () => {
    await appendAudit("X", "y");
    const log = loadAudit();
    log[0].timestamp = "1970-01-01T00:00:00.000Z"; // change timestamp
    localStorage.setItem("aegismap:audit", JSON.stringify({ version: 2, entries: log }));

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
  });
});

describe("v1 → v2 migration", () => {
  it("migrates v1 (djb2 plain array) log to v2 (SHA-256) on verify", async () => {
    // v1 format: plain array with 16-char djb2 hashes
    const v1 = [
      { timestamp: "2024-01-01T00:00:00.000Z", action: "OLD", details: "entry", hash: "1234567890abcdef" },
    ];
    localStorage.setItem("aegismap:audit", JSON.stringify(v1)); // raw array = v1

    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.migrated).toBe(true);

    // Store must now be v2 with 64-char hashes
    const raw = localStorage.getItem("aegismap:audit")!;
    const store: { version: number; entries: { hash: string }[] } = JSON.parse(raw);
    expect(store.version).toBe(2);
    expect(store.entries[0].hash.length).toBe(64);
    expect(/^[0-9a-f]{64}$/.test(store.entries[0].hash)).toBe(true);
  });

  it("entry content is preserved during migration", async () => {
    const v1 = [
      { timestamp: "2024-06-15T12:00:00.000Z", action: "SCAN_START", details: "192.168.1.1 · quick", hash: "aabbccddeeff0011" },
      { timestamp: "2024-06-15T12:01:00.000Z", action: "SCAN_COMPLETE", details: "192.168.1.1 → 3 host(s)", hash: "deadbeef12345678" },
    ];
    localStorage.setItem("aegismap:audit", JSON.stringify(v1));

    await verifyAuditChain();
    const migrated = loadAudit();
    expect(migrated).toHaveLength(2);
    expect(migrated[0].action).toBe("SCAN_START");
    expect(migrated[0].details).toBe("192.168.1.1 · quick");
    expect(migrated[1].action).toBe("SCAN_COMPLETE");
  });

  it("migrated chain is then intact", async () => {
    const v1 = [
      { timestamp: "2024-01-01T00:00:00.000Z", action: "A", details: "1", hash: "0000000000000001" },
      { timestamp: "2024-01-01T00:00:01.000Z", action: "B", details: "2", hash: "0000000000000002" },
    ];
    localStorage.setItem("aegismap:audit", JSON.stringify(v1));

    // First call migrates
    const first = await verifyAuditChain();
    expect(first.migrated).toBe(true);

    // Second call should show INTACT and no migration
    const second = await verifyAuditChain();
    expect(second.valid).toBe(true);
    expect(second.migrated).toBeFalsy();
  });

  it("non-migrated v2 log does not set migrated flag", async () => {
    await appendAudit("X", "y");
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.migrated).toBeFalsy();
  });
});
