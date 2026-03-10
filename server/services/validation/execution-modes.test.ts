import { describe, it, expect } from "vitest";
import { validateOperation } from "./execution-modes";

describe("validateOperation", () => {
  // ── Safe mode ────────────────────────────────────────────────────
  describe("safe mode", () => {
    it("allows banner grabbing", () => {
      const result = validateOperation("safe", "bannerGrabbing");
      expect(result.allowed).toBe(true);
    });

    it("blocks payload injection", () => {
      const result = validateOperation("safe", "payloadInjection");
      expect(result.allowed).toBe(false);
    });

    it("blocks exploit execution", () => {
      const result = validateOperation("safe", "exploitExecution");
      expect(result.allowed).toBe(false);
    });

    it("blocks data exfiltration", () => {
      const result = validateOperation("safe", "dataExfiltration");
      expect(result.allowed).toBe(false);
    });
  });

  // ── Simulation mode ──────────────────────────────────────────────
  describe("simulation mode", () => {
    it("allows payload injection", () => {
      const result = validateOperation("simulation", "payloadInjection");
      expect(result.allowed).toBe(true);
    });

    it("blocks exploit execution", () => {
      const result = validateOperation("simulation", "exploitExecution");
      expect(result.allowed).toBe(false);
    });

    it("blocks .gov targets", () => {
      const result = validateOperation("simulation", "payloadInjection", "test.gov");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("blocked pattern");
    });

    it("blocks .mil targets", () => {
      const result = validateOperation("simulation", "payloadInjection", "test.mil");
      expect(result.allowed).toBe(false);
    });
  });

  // ── Live mode ────────────────────────────────────────────────────
  describe("live mode", () => {
    it("requires approval for all operations", () => {
      const result = validateOperation("live", "payloadInjection");
      expect(result.requiresApproval).toBe(true);
    });

    it("exploit execution needs CISO approval", () => {
      const result = validateOperation("live", "exploitExecution");
      expect(result.requiredApprovalLevel).toBe("ciso");
    });

    it("data exfiltration needs security_lead approval", () => {
      const result = validateOperation("live", "dataExfiltration");
      expect(result.requiredApprovalLevel).toBe("security_lead");
    });
  });
});
