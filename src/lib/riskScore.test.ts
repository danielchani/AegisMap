import { describe, it, expect } from "vitest";
import { hostRiskLevel, RISK_COLOR, RISK_LABEL } from "./riskScore";
import type { HostResult } from "../types";

function makeHost(ports: Array<{ port: number; state: string; service?: string }>): HostResult {
  return {
    address: "192.168.1.1",
    status: "up",
    ports: ports.map((p) => ({
      port: p.port,
      protocol: "tcp",
      state: p.state,
      service: p.service ?? "",
    })),
  };
}

describe("hostRiskLevel", () => {
  it("returns 'clean' for host with no open ports", () => {
    expect(hostRiskLevel(makeHost([]))).toBe("clean");
  });

  it("returns 'clean' for host with no advisory-matching ports", () => {
    expect(hostRiskLevel(makeHost([{ port: 8080, state: "open" }]))).toBe("clean");
  });

  it("returns 'medium' for host with FTP (port 21)", () => {
    expect(hostRiskLevel(makeHost([{ port: 21, state: "open" }]))).toBe("medium");
  });

  it("returns 'high' for host with Telnet (port 23)", () => {
    expect(hostRiskLevel(makeHost([{ port: 23, state: "open" }]))).toBe("high");
  });

  it("returns 'high' for host with Redis (port 6379)", () => {
    expect(hostRiskLevel(makeHost([{ port: 6379, state: "open" }]))).toBe("high");
  });

  it("ignores closed ports", () => {
    expect(hostRiskLevel(makeHost([{ port: 23, state: "closed" }]))).toBe("clean");
  });

  it("uses highest severity when multiple ports open", () => {
    const host = makeHost([
      { port: 80, state: "open" },   // no advisory → clean
      { port: 21, state: "open" },   // medium
      { port: 23, state: "open" },   // high
    ]);
    expect(hostRiskLevel(host)).toBe("high");
  });

  it("falls back to service-based advisory", () => {
    const host = makeHost([{ port: 9999, state: "open", service: "telnet" }]);
    expect(hostRiskLevel(host)).toBe("high");
  });
});

describe("RISK_COLOR / RISK_LABEL", () => {
  it("has colors for all risk levels", () => {
    expect(RISK_COLOR.clean).toBeDefined();
    expect(RISK_COLOR.low).toBeDefined();
    expect(RISK_COLOR.medium).toBeDefined();
    expect(RISK_COLOR.high).toBeDefined();
    expect(RISK_COLOR.critical).toBeDefined();
  });

  it("has labels for all risk levels", () => {
    expect(RISK_LABEL.clean).toBe("CLEAN");
    expect(RISK_LABEL.critical).toBe("CRITICAL");
  });
});
