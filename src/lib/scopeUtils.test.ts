import { describe, it, expect } from "vitest";
import { isInScope, validateScopeRange } from "./scopeUtils";

describe("isInScope", () => {
  it("returns true when no ranges defined (open scope)", () => {
    expect(isInScope("192.168.1.1", [])).toBe(true);
  });

  it("matches exact IP", () => {
    expect(isInScope("10.0.0.1", ["10.0.0.1"])).toBe(true);
  });

  it("rejects IP outside exact match", () => {
    expect(isInScope("10.0.0.2", ["10.0.0.1"])).toBe(false);
  });

  it("matches IP within /24 CIDR", () => {
    expect(isInScope("192.168.1.50", ["192.168.1.0/24"])).toBe(true);
  });

  it("rejects IP outside /24 CIDR", () => {
    expect(isInScope("192.168.2.1", ["192.168.1.0/24"])).toBe(false);
  });

  it("matches IP within /16 CIDR", () => {
    expect(isInScope("10.0.5.100", ["10.0.0.0/16"])).toBe(true);
  });

  it("handles multiple ranges (OR logic)", () => {
    expect(isInScope("172.16.0.5", ["10.0.0.0/8", "172.16.0.0/16"])).toBe(true);
    expect(isInScope("192.168.1.1", ["10.0.0.0/8", "172.16.0.0/16"])).toBe(false);
  });

  it("extracts IP from parenthesized target", () => {
    expect(isInScope("host (10.0.0.1)", ["10.0.0.0/24"])).toBe(true);
  });

  it("handles /32 CIDR (exact match)", () => {
    expect(isInScope("10.0.0.1", ["10.0.0.1/32"])).toBe(true);
    expect(isInScope("10.0.0.2", ["10.0.0.1/32"])).toBe(false);
  });
});

describe("validateScopeRange", () => {
  it("accepts valid CIDR", () => {
    expect(validateScopeRange("192.168.1.0/24")).toBeNull();
  });

  it("accepts exact IP", () => {
    expect(validateScopeRange("10.0.0.1")).toBeNull();
  });

  it("rejects empty string", () => {
    expect(validateScopeRange("")).not.toBeNull();
  });

  it("rejects special characters", () => {
    expect(validateScopeRange("10.0.0.1; rm -rf /")).not.toBeNull();
  });
});
