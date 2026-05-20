import { describe, it, expect } from "vitest";
import { generateHostSuggestions } from "./suggestions";
import type { HostResult } from "../types";
import type { FingerprintConfidence } from "./fingerprint";

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeConf(overrides: Partial<FingerprintConfidence["breakdown"]> = {}): FingerprintConfidence {
  return {
    overall: 60,
    breakdown: {
      serviceDetection: 80,
      osDetection: 50,
      scriptEnrichment: 60,
      bannerGrab: 70,
      httpEnrichment: 0,
      tlsEnrichment: 0,
      dnsEnrichment: 0,
      ...overrides,
    },
    suggestions: [],
  };
}

function makeHost(overrides: Partial<HostResult> = {}): HostResult {
  return {
    address: "192.168.1.5",
    status: "up",
    ports: [
      { port: 22,  protocol: "tcp", state: "open", service: "ssh",  product: "OpenSSH", version: "8.9" },
      { port: 80,  protocol: "tcp", state: "open", service: "http", product: "nginx",   version: "1.26" },
      { port: 443, protocol: "tcp", state: "open", service: "https",product: "nginx",   version: "1.26" },
    ],
    ...overrides,
  };
}

// ── generateHostSuggestions ───────────────────────────────────────────────────

describe("generateHostSuggestions", () => {

  it("returns empty array when host has no open ports", () => {
    const host = makeHost({ ports: [] });
    expect(generateHostSuggestions(host, makeConf())).toHaveLength(0);
  });

  it("suggests HTTP probe when web port open and no httpProbes", () => {
    const host = makeHost({ httpProbes: undefined });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "http-probe")).toBe(true);
  });

  it("does NOT suggest HTTP probe when httpProbes already exist", () => {
    const host = makeHost({
      httpProbes: [
        { url: "http://x/", finalUrl: "http://x/", responseTimeMs: 50,
          securityHeaders: {}, technologyHints: [], probedAt: "2024-01-01T00:00:00Z" },
      ],
    });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "http-probe")).toBe(false);
  });

  it("suggests TLS probe when TLS port open and no tlsProbes", () => {
    const host = makeHost({ tlsProbes: undefined });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "tls-probe")).toBe(true);
  });

  it("does NOT suggest TLS probe when tlsProbes already exist", () => {
    const host = makeHost({
      tlsProbes: [
        { address: "192.168.1.5", port: 443, cipherIsWeak: false,
          certificateChain: [], connectionTimeMs: 10, probedAt: "2024-01-01T00:00:00Z" },
      ],
    });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "tls-probe")).toBe(false);
  });

  it("suggests DNS query when hostname present and no dnsResults", () => {
    const host = makeHost({ hostname: "host.example.com", dnsResults: undefined });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "dns-query")).toBe(true);
  });

  it("does NOT suggest DNS query when no hostname", () => {
    const host = makeHost({ hostname: undefined, dnsResults: undefined });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "dns-query")).toBe(false);
  });

  it("suggests service detection when serviceDetection < 50", () => {
    const suggestions = generateHostSuggestions(makeHost(), makeConf({ serviceDetection: 30 }));
    expect(suggestions.some((s) => s.id === "svc-detect")).toBe(true);
  });

  it("does NOT suggest service detection when serviceDetection >= 50", () => {
    const suggestions = generateHostSuggestions(makeHost(), makeConf({ serviceDetection: 75 }));
    expect(suggestions.some((s) => s.id === "svc-detect")).toBe(false);
  });

  it("suggests new-port review when portsDiff has added ports", () => {
    const host = makeHost({ portsDiff: { added: [8080], removed: [] } });
    const suggestions = generateHostSuggestions(host, makeConf());
    expect(suggestions.some((s) => s.id === "new-port")).toBe(true);
  });

  it("suggests finding review for high-risk host (SMB port)", () => {
    // Port 445 triggers a critical advisory
    const host = makeHost({
      ports: [
        { port: 445, protocol: "tcp", state: "open", service: "microsoft-ds" },
      ],
    });
    const suggestions = generateHostSuggestions(host, makeConf({ serviceDetection: 80 }));
    expect(suggestions.some((s) => s.id === "cve-review")).toBe(true);
  });

  it("returns at most 4 suggestions", () => {
    // Create a host with many trigger conditions
    const host = makeHost({
      hostname: "host.example.com",
      portsDiff: { added: [8080], removed: [] },
      ports: [
        { port: 445, protocol: "tcp", state: "open", service: "microsoft-ds" },
        { port: 80,  protocol: "tcp", state: "open", service: "http" },
        { port: 443, protocol: "tcp", state: "open", service: "https" },
        { port: 22,  protocol: "tcp", state: "open", service: "ssh" },
      ],
    });
    const suggestions = generateHostSuggestions(host, makeConf({ serviceDetection: 10, scriptEnrichment: 5, osDetection: 0 }));
    expect(suggestions.length).toBeLessThanOrEqual(4);
  });

  it("sorts suggestions high → medium → low", () => {
    const host = makeHost({ hostname: "host.example.com" }); // triggers dns-query (low)
    const suggestions = generateHostSuggestions(
      host,
      makeConf({ serviceDetection: 20 }), // triggers svc-detect (high)
    );
    const priorities = suggestions.map((s) => s.priority);
    // High should come before low
    const firstLow  = priorities.indexOf("low");
    const lastHigh  = priorities.lastIndexOf("high");
    if (firstLow !== -1 && lastHigh !== -1) {
      expect(lastHigh).toBeLessThan(firstLow);
    }
  });

  it("suggestion titles never contain the word 'vulnerability' or 'confirmed'", () => {
    const host = makeHost({
      ports: [{ port: 445, protocol: "tcp", state: "open", service: "microsoft-ds" }],
      hostname: "host.example.com",
    });
    const suggestions = generateHostSuggestions(host, makeConf({ serviceDetection: 20 }));
    for (const s of suggestions) {
      expect(s.title.toLowerCase()).not.toContain("vulnerability");
      expect(s.title.toLowerCase()).not.toContain("confirmed");
      expect(s.rationale.toLowerCase()).not.toContain("confirmed vulnerability");
    }
  });

  it("suggestions with actions have valid action types", () => {
    const host = makeHost();
    const suggestions = generateHostSuggestions(host, makeConf({ serviceDetection: 20 }));
    const validTypes = ["rescan", "probe", "navigate", "create_finding"];
    for (const s of suggestions) {
      if (s.action) {
        expect(validTypes).toContain(s.action.type);
      }
    }
  });

  it("returns no HIGH suggestions when host is well-enumerated with no advisories", () => {
    // No product/version → getVersionAdvisory returns null; port 22 has no CVE advisory
    const host = makeHost({
      hostname: undefined,
      portsDiff: undefined,
      httpProbes: [{ url: "x", finalUrl: "x", responseTimeMs: 10, securityHeaders: {}, technologyHints: [], probedAt: "2024-01-01T00:00:00Z" }],
      tlsProbes:  [{ address: "192.168.1.5", port: 443, cipherIsWeak: false, certificateChain: [], connectionTimeMs: 10, probedAt: "2024-01-01T00:00:00Z" }],
      dnsResults: [{ address: "192.168.1.5", ptrRecords: [], aRecords: [], aaaaRecords: [], cnameChain: [], mxRecords: [], nsRecords: [], txtRecords: [], queriedAt: "2024-01-01T00:00:00Z" }],
      ports: [
        // No product/version → no advisory triggered; no EOL suggestion
        { port: 22, protocol: "tcp", state: "open", service: "ssh" },
      ],
    });
    const conf = makeConf({ serviceDetection: 90, osDetection: 50, scriptEnrichment: 80, bannerGrab: 85 });
    const suggestions = generateHostSuggestions(host, conf);
    // High confidence, all probes done, no advisories, no new ports → no HIGH suggestions
    const highSuggestions = suggestions.filter((s) => s.priority === "high");
    expect(highSuggestions).toHaveLength(0);
  });
});
