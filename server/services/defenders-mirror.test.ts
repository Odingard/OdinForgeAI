import { describe, it, expect } from "vitest";
import { DefendersMirror, AttackEvidence, DetectionRuleSet } from "./defenders-mirror";

function makeEvidence(overrides: Partial<AttackEvidence> = {}): AttackEvidence {
  return {
    id: "ev-001",
    engagementId: "eng-abc",
    phase: "application_compromise",
    techniqueCategory: "sqli",
    targetUrl: "https://target.example.com/login",
    success: true,
    ...overrides,
  };
}

describe("DefendersMirror", () => {
  it("generates Sigma YAML containing SQLi indicators for sqli evidence", () => {
    const mirror = new DefendersMirror();
    const rules = mirror.generateFromEvidence(makeEvidence({ techniqueCategory: "sqli" }));
    expect(rules.sigmaRule).toContain("UNION SELECT");
    expect(rules.sigmaRule).toContain("1=1");
  });

  it("generates YARA rule with IPC$ string for smb_pivot evidence", () => {
    const mirror = new DefendersMirror();
    const rules = mirror.generateFromEvidence(
      makeEvidence({ techniqueCategory: "smb_pivot", networkProtocol: "smb" })
    );
    expect(rules.yaraRule).toContain("IPC$");
  });

  it("falls back to generic rules for unknown technique categories", () => {
    const mirror = new DefendersMirror();
    const rules = mirror.generateFromEvidence(
      makeEvidence({ techniqueCategory: "zero_day_custom" })
    );
    // Generic sigma uses cs-uri and cs-method
    expect(rules.sigmaRule).toContain("cs-uri");
    // Generic YARA uses the target URL as a string
    expect(rules.yaraRule).toContain("target.example.com");
  });

  it("maps sqli to T1190 and smb_pivot to T1021.002", () => {
    const mirror = new DefendersMirror();
    const sqliRules = mirror.generateFromEvidence(makeEvidence({ techniqueCategory: "sqli" }));
    expect(sqliRules.mitreAttackId).toBe("T1190");

    const smbRules = mirror.generateFromEvidence(
      makeEvidence({ id: "ev-002", techniqueCategory: "smb_pivot" })
    );
    expect(smbRules.mitreAttackId).toBe("T1021.002");
  });

  it("produces rule sets with all required fields", () => {
    const mirror = new DefendersMirror();
    const rules = mirror.generateFromEvidence(makeEvidence());

    expect(rules.id).toBeDefined();
    expect(typeof rules.id).toBe("string");
    expect(rules.sigmaRule.length).toBeGreaterThan(0);
    expect(rules.yaraRule.length).toBeGreaterThan(0);
    expect(rules.splunkSPL.length).toBeGreaterThan(0);
    expect(rules.mitreAttackId.length).toBeGreaterThan(0);
    expect(rules.engagementId).toBe("eng-abc");
    expect(rules.attackEvidenceRef).toBe("ev-001");
    expect(rules.generatedAt).toBeDefined();
  });

  it("generates a batch of 5 evidence items into 5 rule sets", () => {
    const mirror = new DefendersMirror();
    const evidenceList: AttackEvidence[] = [
      makeEvidence({ id: "ev-1", techniqueCategory: "sqli" }),
      makeEvidence({ id: "ev-2", techniqueCategory: "xss" }),
      makeEvidence({ id: "ev-3", techniqueCategory: "ssrf" }),
      makeEvidence({ id: "ev-4", techniqueCategory: "cmdi" }),
      makeEvidence({ id: "ev-5", techniqueCategory: "ssti" }),
    ];

    const ruleSets = mirror.generateBatch(evidenceList);
    expect(ruleSets).toHaveLength(5);
    for (const rs of ruleSets) {
      expect(rs.sigmaRule).toBeDefined();
      expect(rs.yaraRule).toBeDefined();
      expect(rs.splunkSPL).toBeDefined();
    }
  });

  it("filters rules by engagement ID via getRulesForEngagement", () => {
    const mirror = new DefendersMirror();
    mirror.generateFromEvidence(makeEvidence({ id: "ev-a", engagementId: "eng-111" }));
    mirror.generateFromEvidence(makeEvidence({ id: "ev-b", engagementId: "eng-222" }));
    mirror.generateFromEvidence(makeEvidence({ id: "ev-c", engagementId: "eng-111" }));

    const filtered = mirror.getRulesForEngagement("eng-111");
    expect(filtered).toHaveLength(2);
    expect(filtered.every(r => r.engagementId === "eng-111")).toBe(true);

    const all = mirror.getRules();
    expect(all).toHaveLength(3);
  });

  it("returns empty array when filtering for nonexistent engagement", () => {
    const mirror = new DefendersMirror();
    mirror.generateFromEvidence(makeEvidence({ engagementId: "eng-only" }));
    expect(mirror.getRulesForEngagement("eng-nope")).toHaveLength(0);
  });
});
