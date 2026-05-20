import { describe, it, expect } from "vitest";
import { PLAYBOOKS, createPlaybookRun, resolveCurrentStep } from "./playbooks";
import type { HostResult } from "../types";

function makeHost(overrides: Partial<HostResult> = {}): HostResult {
  return {
    address: "10.0.0.1",
    status: "up",
    ports: [
      { port: 80,  protocol: "tcp", state: "open", service: "http" },
      { port: 443, protocol: "tcp", state: "open", service: "https" },
      { port: 22,  protocol: "tcp", state: "open", service: "ssh" },
    ],
    ...overrides,
  };
}

// ── PLAYBOOKS array ───────────────────────────────────────────────────────────

describe("PLAYBOOKS", () => {
  it("contains exactly 5 playbooks", () => {
    expect(PLAYBOOKS).toHaveLength(5);
  });

  it("each playbook has id, name, description, and steps", () => {
    for (const pb of PLAYBOOKS) {
      expect(typeof pb.id).toBe("string");
      expect(pb.id.length).toBeGreaterThan(0);
      expect(typeof pb.name).toBe("string");
      expect(pb.name.length).toBeGreaterThan(0);
      expect(typeof pb.description).toBe("string");
      expect(Array.isArray(pb.steps)).toBe(true);
      expect(pb.steps.length).toBeGreaterThan(0);
    }
  });

  it("every step has id, label, description, and type 'passive' | 'active'", () => {
    for (const pb of PLAYBOOKS) {
      for (const step of pb.steps) {
        expect(typeof step.id).toBe("string");
        expect(typeof step.label).toBe("string");
        expect(typeof step.description).toBe("string");
        expect(["passive", "active"]).toContain(step.type);
      }
    }
  });

  it("every active step has an action", () => {
    for (const pb of PLAYBOOKS) {
      for (const step of pb.steps) {
        if (step.type === "active") {
          expect(step.action).toBeDefined();
        }
      }
    }
  });

  it("no step has type outside passive/active", () => {
    for (const pb of PLAYBOOKS) {
      for (const step of pb.steps) {
        expect(step.type === "passive" || step.type === "active").toBe(true);
      }
    }
  });

  it("External Host Review has at least 4 steps", () => {
    const pb = PLAYBOOKS.find((p) => p.id === "external-host-review");
    expect(pb).toBeDefined();
    expect(pb!.steps.length).toBeGreaterThanOrEqual(4);
  });

  it("playbook IDs are unique", () => {
    const ids = PLAYBOOKS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("step IDs are unique within each playbook", () => {
    for (const pb of PLAYBOOKS) {
      const ids = pb.steps.map((s) => s.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });
});

// ── createPlaybookRun ─────────────────────────────────────────────────────────

describe("createPlaybookRun", () => {
  it("creates a run at step 0 with active status", () => {
    const pb = PLAYBOOKS[0];
    const run = createPlaybookRun(pb, "10.0.0.1");
    expect(run.currentStep).toBe(0);
    expect(run.status).toBe("active");
    expect(run.hostAddress).toBe("10.0.0.1");
    expect(run.playbook.id).toBe(pb.id);
  });

  it("initialises skippedSteps as empty set", () => {
    const run = createPlaybookRun(PLAYBOOKS[0], "10.0.0.2");
    expect(run.skippedSteps.size).toBe(0);
  });
});

// ── resolveCurrentStep ────────────────────────────────────────────────────────

describe("resolveCurrentStep", () => {
  it("returns the step at currentStep when condition is absent", () => {
    const pb = PLAYBOOKS[0]; // external-host-review; step 0 is passive (no condition)
    const run = createPlaybookRun(pb, "10.0.0.1");
    const { step } = resolveCurrentStep(run, makeHost());
    expect(step).not.toBeNull();
    expect(step!.id).toBe(pb.steps[0].id);
  });

  it("skips steps whose condition returns false", () => {
    const pb = PLAYBOOKS[0]; // external-host-review
    // Start from step that has a condition (http-probe, step idx=2)
    const run = createPlaybookRun(pb, "10.0.0.1");
    run.currentStep = 2; // http-probe step (condition: hasWebPort)
    // Host with no web port — condition should return false, skip to next
    const noWebHost = makeHost({ ports: [{ port: 22, protocol: "tcp", state: "open", service: "ssh" }] });
    const { step } = resolveCurrentStep(run, noWebHost);
    // Should skip http-probe (idx 2) and tls-probe (idx 3, hasTlsPort also false) and dns-query (idx 4, no hostname)
    // Should land on review-findings (idx 5) which has no condition
    expect(step?.id).toBe("review-findings");
  });

  it("returns null when all remaining steps are gated out", () => {
    const pb = PLAYBOOKS[0];
    const run = createPlaybookRun(pb, "10.0.0.1");
    run.currentStep = pb.steps.length; // past last step
    const { step } = resolveCurrentStep(run, makeHost());
    expect(step).toBeNull();
  });

  it("isLastStep is true when current step is the final step", () => {
    const pb = PLAYBOOKS[0];
    const run = createPlaybookRun(pb, "10.0.0.1");
    run.currentStep = pb.steps.length - 1; // last step
    const host = makeHost({ hostname: "x.com" }); // ensure conditions pass
    // Run to last step
    const { isLastStep } = resolveCurrentStep(run, host);
    // isLastStep is relative to the resolved step's index
    // The passive review-findings step is always last (no condition)
    expect(isLastStep).toBe(true);
  });
});
