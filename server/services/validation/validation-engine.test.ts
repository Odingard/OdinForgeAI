import { describe, it, expect } from "vitest";
import { ValidationEngine, createValidationEngine } from "./validation-engine";

describe("ValidationEngine", () => {
  describe("config management", () => {
    it("uses default config when none provided", () => {
      const engine = new ValidationEngine();
      const config = engine.getConfig();

      expect(config.maxPayloadsPerTest).toBe(10);
      expect(config.timeoutMs).toBe(10000);
      expect(config.captureEvidence).toBe(true);
      expect(config.safeMode).toBe(true);
      expect(config.executionMode).toBe("safe");
      expect(config.tenantId).toBe("default");
      expect(config.detectedWaf).toBeNull();
      expect(config.useResponseDiffing).toBe(true);
    });

    it("merges user config with defaults", () => {
      const engine = new ValidationEngine({
        maxPayloadsPerTest: 5,
        timeoutMs: 5000,
        executionMode: "simulation",
      });
      const config = engine.getConfig();

      expect(config.maxPayloadsPerTest).toBe(5);
      expect(config.timeoutMs).toBe(5000);
      expect(config.executionMode).toBe("simulation");
      // Defaults still present
      expect(config.captureEvidence).toBe(true);
      expect(config.safeMode).toBe(true);
    });

    it("setConfig updates config partially", () => {
      const engine = new ValidationEngine();
      engine.setConfig({ maxPayloadsPerTest: 3 });
      const config = engine.getConfig();

      expect(config.maxPayloadsPerTest).toBe(3);
      expect(config.timeoutMs).toBe(10000); // unchanged
    });
  });

  describe("createValidationEngine factory", () => {
    it("creates engine with custom config", () => {
      const engine = createValidationEngine({ safeMode: false, executionMode: "live" });
      const config = engine.getConfig();

      expect(config.safeMode).toBe(false);
      expect(config.executionMode).toBe("live");
    });
  });
});
