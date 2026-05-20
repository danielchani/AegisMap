import { describe, it, expect } from "vitest";
import { lookupCVEs, hostCVESummary } from "./cveDatabase";

describe("lookupCVEs", () => {
  it("returns empty for unknown product", () => {
    expect(lookupCVEs("UnknownProduct", "1.0")).toEqual([]);
  });

  it("returns empty for no product/version", () => {
    expect(lookupCVEs(undefined, undefined)).toEqual([]);
    expect(lookupCVEs("OpenSSH", undefined)).toEqual([]);
  });

  it("finds CVEs for vulnerable OpenSSH version", () => {
    const cves = lookupCVEs("OpenSSH", "8.9");
    expect(cves.length).toBeGreaterThan(0);
    expect(cves.some((c) => c.id === "CVE-2024-6387")).toBe(true);
  });

  it("finds CVEs for vulnerable Apache version", () => {
    const cves = lookupCVEs("Apache", "2.4.49");
    expect(cves.length).toBeGreaterThan(0);
    expect(cves.some((c) => c.id === "CVE-2021-41773")).toBe(true);
  });

  it("returns CVEs sorted by CVSS (highest first)", () => {
    const cves = lookupCVEs("OpenSSH", "8.5");
    if (cves.length >= 2) {
      expect(cves[0].cvss).toBeGreaterThanOrEqual(cves[1].cvss);
    }
  });

  it("matches product aliases case-insensitively", () => {
    const cves = lookupCVEs("openssh", "8.9");
    expect(cves.length).toBeGreaterThan(0);
  });

  it("finds nginx CVEs", () => {
    const cves = lookupCVEs("nginx", "1.18.0");
    expect(cves.length).toBeGreaterThan(0);
  });

  it("finds Redis CVEs", () => {
    const cves = lookupCVEs("Redis", "7.0.10");
    expect(cves.length).toBeGreaterThan(0);
  });
});

describe("hostCVESummary", () => {
  it("returns zero totals for host with no vulnerable services", () => {
    const result = hostCVESummary([
      { product: "UnknownApp", version: "1.0", state: "open" },
    ]);
    expect(result.total).toBe(0);
    expect(result.topCVE).toBeNull();
  });

  it("counts CVEs across multiple ports", () => {
    const result = hostCVESummary([
      { product: "OpenSSH", version: "8.5", state: "open" },
      { product: "nginx", version: "1.18.0", state: "open" },
    ]);
    expect(result.total).toBeGreaterThan(0);
    expect(result.topCVE).not.toBeNull();
  });

  it("ignores closed ports", () => {
    const result = hostCVESummary([
      { product: "OpenSSH", version: "8.5", state: "closed" },
    ]);
    expect(result.total).toBe(0);
  });
});
