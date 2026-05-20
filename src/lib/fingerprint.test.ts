import { describe, it, expect } from "vitest";
import { calculateConfidence, extractIdentity } from "./fingerprint";
import type { HostResult } from "../types";

function makeHost(overrides: Partial<HostResult> = {}): HostResult {
  return {
    address: "192.168.1.1",
    status: "up",
    ports: [
      { port: 22, protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "8.9" },
      { port: 80, protocol: "tcp", state: "open", service: "http", product: "nginx", version: "1.22" },
      { port: 443, protocol: "tcp", state: "open", service: "https", product: "nginx", version: "1.22" },
    ],
    ...overrides,
  };
}

describe("calculateConfidence", () => {
  it("returns 0 for host with no open ports", () => {
    const result = calculateConfidence(makeHost({ ports: [] }));
    expect(result.overall).toBe(0);
    expect(result.suggestions.length).toBeGreaterThan(0);
  });

  it("returns higher confidence for well-detected host", () => {
    const well = calculateConfidence(makeHost({
      hostname: "web.example.com",
      script_results: [
        { id: "ssl-cert", output: "Subject: CN=example.com" },
        { id: "http-title", output: "title: Welcome" },
        { id: "banner", output: "22/tcp: SSH-2.0-OpenSSH_8.9" },
      ],
    }));
    const bare = calculateConfidence(makeHost({
      ports: [
        { port: 22, protocol: "tcp", state: "open", service: "unknown" },
      ],
    }));
    expect(well.overall).toBeGreaterThan(bare.overall);
  });

  it("provides meaningful suggestions", () => {
    const result = calculateConfidence(makeHost({
      ports: [{ port: 22, protocol: "tcp", state: "open", service: "unknown" }],
    }));
    expect(result.suggestions.length).toBeGreaterThan(0);
    expect(result.suggestions.some((s) => s.includes("SERVICE") || s.includes("banner") || s.includes("NSE"))).toBe(true);
  });

  it("breakdown scores are between 0-100", () => {
    const result = calculateConfidence(makeHost());
    expect(result.breakdown.serviceDetection).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.serviceDetection).toBeLessThanOrEqual(100);
    expect(result.breakdown.bannerGrab).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.bannerGrab).toBeLessThanOrEqual(100);
  });

  it("enrichment bonus is 0 when no probes have been run", () => {
    const result = calculateConfidence(makeHost());
    expect(result.breakdown.httpEnrichment).toBe(0);
    expect(result.breakdown.tlsEnrichment).toBe(0);
    expect(result.breakdown.dnsEnrichment).toBe(0);
  });

  it("http probe adds +5 enrichment bonus", () => {
    const without = calculateConfidence(makeHost());
    const with_http = calculateConfidence(makeHost({
      httpProbes: [{ url: "http://192.168.1.1:80/", finalUrl: "http://192.168.1.1:80/", responseTimeMs: 50, securityHeaders: {}, technologyHints: [], probedAt: "2024-01-01T00:00:00Z" }],
    }));
    expect(with_http.breakdown.httpEnrichment).toBe(5);
    expect(with_http.overall).toBe(Math.min(100, without.overall + 5));
  });

  it("all three probes add +15 total enrichment bonus", () => {
    const with_all = calculateConfidence(makeHost({
      httpProbes: [{ url: "http://x/", finalUrl: "http://x/", responseTimeMs: 10, securityHeaders: {}, technologyHints: [], probedAt: "2024-01-01T00:00:00Z" }],
      tlsProbes:  [{ address: "192.168.1.1", port: 443, cipherIsWeak: false, certificateChain: [], connectionTimeMs: 10, probedAt: "2024-01-01T00:00:00Z" }],
      dnsResults: [{ address: "192.168.1.1", ptrRecords: [], aRecords: [], aaaaRecords: [], cnameChain: [], mxRecords: [], nsRecords: [], txtRecords: [], queriedAt: "2024-01-01T00:00:00Z" }],
    }));
    expect(with_all.breakdown.httpEnrichment).toBe(5);
    expect(with_all.breakdown.tlsEnrichment).toBe(5);
    expect(with_all.breakdown.dnsEnrichment).toBe(5);
  });

  it("enrichment suggestions appear for unrun probes on relevant ports", () => {
    const result = calculateConfidence(makeHost({ hostname: "web.example.com" }));
    // Has port 443 (TLS) and port 80/443 (HTTP) — should suggest both + DNS (has hostname)
    expect(result.suggestions.some((s) => s.includes("HTTP probe"))).toBe(true);
    expect(result.suggestions.some((s) => s.includes("TLS probe"))).toBe(true);
    expect(result.suggestions.some((s) => s.includes("DNS query"))).toBe(true);
  });
});

describe("extractIdentity", () => {
  it("extracts hostname", () => {
    const identity = extractIdentity(makeHost({ hostname: "web.example.com" }));
    expect(identity.probableHostnames).toContain("web.example.com");
  });

  it("extracts tech stack from port products", () => {
    const identity = extractIdentity(makeHost());
    expect(identity.techStack).toContain("OpenSSH 8.9");
    expect(identity.techStack).toContain("nginx 1.22");
  });

  it("extracts SSL cert info from script results", () => {
    const identity = extractIdentity(makeHost({
      script_results: [{
        id: "ssl-cert",
        output: "Subject: CN=example.com/O=Example Inc\nIssuer: CN=Let's Encrypt\nSubject Alternative Name: DNS:example.com, DNS:www.example.com",
      }],
    }));
    expect(identity.sslInfo).toBeDefined();
    expect(identity.probableHostnames).toContain("example.com");
    expect(identity.probableHostnames).toContain("www.example.com");
    expect(identity.organization).toBe("Example Inc");
  });

  it("returns empty identity for bare host", () => {
    const identity = extractIdentity(makeHost({
      ports: [{ port: 22, protocol: "tcp", state: "open", service: "" }],
      script_results: [],
    }));
    expect(identity.techStack).toHaveLength(0);
    expect(identity.banners).toHaveLength(0);
  });
});
