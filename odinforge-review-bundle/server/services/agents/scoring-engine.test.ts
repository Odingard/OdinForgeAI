import { describe, it, expect } from "vitest";
import { generateDeterministicScore, type ScoringContext } from "./scoring-engine";

function baseContext(overrides: Partial<ScoringContext> = {}): ScoringContext {
  return {
    assetId: "test-asset",
    exposureType: "SQL Injection",
    priority: "high",
    description: "Test vulnerability",
    exploitable: false,
    ...overrides,
  };
}

describe("generateDeterministicScore", () => {
  // ── Core formula ─────────────────────────────────────────────────
  describe("weighted combination", () => {
    it("uses 45/35/20 weights when EPSS + CVSS + agent all present", () => {
      const ctx = baseContext({
        epssScore: 0.5, // 50 * 0.45 = 22.5
        cvssData: { version: "3.1", vectorString: "test", baseScore: 7.0, severity: "high", metrics: {} as any, networkExposure: "internet", authRequired: "none" }, // 70 * 0.35 = 24.5
        exploitable: true, // 100 * 0.20 = 20
      });
      const result = generateDeterministicScore(ctx);
      // 22.5 + 24.5 + 20 = 67, plus high count boost
      expect(result.exploitability.score).toBeGreaterThanOrEqual(65);
      expect(result.exploitability.score).toBeLessThanOrEqual(75);
    });

    it("redistributes CVSS weight to EPSS when CVSS absent", () => {
      const ctx = baseContext({ epssScore: 0.8, exploitable: true });
      const result = generateDeterministicScore(ctx);
      // 80 * 0.65 + 100 * 0.35 = 52 + 35 = 87
      expect(result.exploitability.score).toBeGreaterThanOrEqual(85);
    });

    it("redistributes EPSS weight to CVSS when EPSS absent", () => {
      const ctx = baseContext({
        cvssData: { version: "3.1", vectorString: "test", baseScore: 9.8, severity: "critical", metrics: {} as any, networkExposure: "internet", authRequired: "none" },
        exploitable: true,
      });
      const result = generateDeterministicScore(ctx);
      // 98 * 0.70 + 100 * 0.30 = 68.6 + 30 = 98.6
      expect(result.exploitability.score).toBeGreaterThanOrEqual(95);
    });

    it("uses heuristic when no external data, exploitable", () => {
      const result = generateDeterministicScore(baseContext({ exploitable: true }));
      expect(result.exploitability.score).toBeGreaterThanOrEqual(70);
    });

    it("uses heuristic when no external data, not exploitable", () => {
      const result = generateDeterministicScore(baseContext({ exploitable: false }));
      expect(result.exploitability.score).toBeGreaterThanOrEqual(25);
      expect(result.exploitability.score).toBeLessThanOrEqual(35);
    });
  });

  // ── KEV override ─────────────────────────────────────────────────
  describe("KEV override", () => {
    it("floors exploitability at 85 when KEV listed", () => {
      const ctx = baseContext({ isKevListed: true, exploitable: false });
      const result = generateDeterministicScore(ctx);
      expect(result.exploitability.score).toBeGreaterThanOrEqual(85);
    });

    it("floors business score at 70 when KEV listed", () => {
      const ctx = baseContext({ isKevListed: true, priority: "low", exploitable: false });
      const result = generateDeterministicScore(ctx);
      expect(result.businessImpact.score).toBeGreaterThanOrEqual(70);
    });

    it("applies ransomware +10 amplifier", () => {
      const ctx1 = baseContext({ isKevListed: true, kevRansomwareUse: false });
      const ctx2 = baseContext({ isKevListed: true, kevRansomwareUse: true });
      const r1 = generateDeterministicScore(ctx1);
      const r2 = generateDeterministicScore(ctx2);
      expect(r2.exploitability.score).toBeGreaterThanOrEqual(r1.exploitability.score);
    });

    it("caps at 100 with ransomware amplifier", () => {
      const ctx = baseContext({
        isKevListed: true, kevRansomwareUse: true,
        epssScore: 0.99, exploitable: true,
        cvssData: { version: "3.1", vectorString: "test", baseScore: 10.0, severity: "critical", metrics: {} as any, networkExposure: "internet", authRequired: "none" },
      });
      const result = generateDeterministicScore(ctx);
      expect(result.exploitability.score).toBeLessThanOrEqual(100);
    });
  });

  // ── Maturity classification ──────────────────────────────────────
  describe("maturity", () => {
    it("KEV listed → in_the_wild", () => {
      const result = generateDeterministicScore(baseContext({ isKevListed: true }));
      expect(result.exploitability.factors.exploitMaturity.availability).toBe("in_the_wild");
    });

    it("EPSS >= 0.5 → weaponized", () => {
      const result = generateDeterministicScore(baseContext({ epssScore: 0.6 }));
      expect(result.exploitability.factors.exploitMaturity.availability).toBe("weaponized");
    });

    it("EPSS >= 0.1 → poc", () => {
      const result = generateDeterministicScore(baseContext({ epssScore: 0.15 }));
      expect(result.exploitability.factors.exploitMaturity.availability).toBe("poc");
    });

    it("exploitable with no EPSS → poc, advanced", () => {
      const result = generateDeterministicScore(baseContext({ exploitable: true }));
      expect(result.exploitability.factors.exploitMaturity.availability).toBe("poc");
      expect(result.exploitability.factors.exploitMaturity.skillRequired).toBe("advanced");
    });

    it("not exploitable, no external data → theoretical", () => {
      const result = generateDeterministicScore(baseContext());
      expect(result.exploitability.factors.exploitMaturity.availability).toBe("theoretical");
    });
  });

  // ── Confidence tracking ──────────────────────────────────────────
  describe("confidence", () => {
    it("accumulates from all data sources", () => {
      const ctx = baseContext({
        epssScore: 0.5,
        cvssData: { version: "3.1", vectorString: "test", baseScore: 7.0, severity: "high", metrics: {} as any, networkExposure: "internet", authRequired: "none" },
        isKevListed: true,
        exploitable: true,
        attackPath: [{ step: "test", severity: "critical", description: "test", confidence: 90 } as any],
      });
      const result = generateDeterministicScore(ctx);
      // EPSS(30) + CVSS(25) + KEV(15) + exploitable(20) + findings(10) = 100
      expect(result.exploitability.confidence).toBe(100);
    });

    it("is 0 when no external data and not exploitable", () => {
      const result = generateDeterministicScore(baseContext());
      expect(result.exploitability.confidence).toBe(0);
    });
  });

  // ── Risk level thresholds ────────────────────────────────────────
  describe("risk levels", () => {
    it("score >= 90 → emergency", () => {
      const ctx = baseContext({
        isKevListed: true, kevRansomwareUse: true,
        epssScore: 0.99, exploitable: true, priority: "critical",
        cvssData: { version: "3.1", vectorString: "test", baseScore: 10.0, severity: "critical", metrics: {} as any, networkExposure: "internet", authRequired: "none" },
      });
      const result = generateDeterministicScore(ctx);
      expect(result.riskRank.riskLevel).toBe("emergency");
    });

    it("low score → low or medium", () => {
      const result = generateDeterministicScore(baseContext({ priority: "low" }));
      expect(["low", "medium"]).toContain(result.riskRank.riskLevel);
    });
  });

  // ── Methodology string ───────────────────────────────────────────
  describe("methodology", () => {
    it("includes OdinForge Deterministic v3.0", () => {
      const result = generateDeterministicScore(baseContext());
      expect(result.methodology).toContain("OdinForge Deterministic v3.0");
    });

    it("includes EPSS percentage when present", () => {
      const result = generateDeterministicScore(baseContext({ epssScore: 0.972 }));
      expect(result.methodology).toContain("EPSS 97.2%");
    });

    it("includes CISA KEV when listed", () => {
      const result = generateDeterministicScore(baseContext({ isKevListed: true }));
      expect(result.methodology).toContain("CISA KEV");
    });

    it("includes [Ransomware] when applicable", () => {
      const result = generateDeterministicScore(baseContext({ kevRansomwareUse: true }));
      expect(result.methodology).toContain("[Ransomware]");
    });
  });

  // ── Asset criticality ────────────────────────────────────────────
  describe("asset criticality", () => {
    it("critical asset amplifies business score", () => {
      const base = baseContext({ exploitable: true, priority: "high" });
      const critical = baseContext({ exploitable: true, priority: "high", assetCriticality: "critical" });
      const rBase = generateDeterministicScore(base);
      const rCritical = generateDeterministicScore(critical);
      expect(rCritical.businessImpact.score).toBeGreaterThanOrEqual(rBase.businessImpact.score);
    });

    it("low asset reduces business score", () => {
      const base = baseContext({ exploitable: true, priority: "high" });
      const low = baseContext({ exploitable: true, priority: "high", assetCriticality: "low" });
      const rBase = generateDeterministicScore(base);
      const rLow = generateDeterministicScore(low);
      expect(rLow.businessImpact.score).toBeLessThanOrEqual(rBase.businessImpact.score);
    });
  });

  // ── Output structure ─────────────────────────────────────────────
  it("returns all required fields", () => {
    const result = generateDeterministicScore(baseContext());
    expect(result).toHaveProperty("exploitability.score");
    expect(result).toHaveProperty("exploitability.confidence");
    expect(result).toHaveProperty("businessImpact.score");
    expect(result).toHaveProperty("exploitability.factors.exploitMaturity.availability");
    expect(result).toHaveProperty("exploitability.factors.exploitMaturity.skillRequired");
    expect(result).toHaveProperty("riskRank.riskLevel");
    expect(result).toHaveProperty("methodology");
    expect(result).toHaveProperty("riskRank.overallScore");
    expect(result).toHaveProperty("riskRank.recommendation.timeframe");
  });
});
