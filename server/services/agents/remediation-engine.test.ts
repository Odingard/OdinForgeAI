import { describe, it, expect } from "vitest";
import {
  generateFixProposal,
  type FixProposalInput,
} from "./remediation-engine";

function makeInput(overrides: Partial<FixProposalInput> = {}): FixProposalInput {
  return {
    findingId: "f-001",
    severity: "high",
    title: "SQL Injection in /api/users",
    description: "SQL injection via user_id parameter",
    technique: "sqli",
    evidenceQuality: "proven",
    targetUrl: "https://example.com/api/users?id=1",
    requestPayload: "1 OR 1=1",
    responseBody: "syntax error near OR",
    ...overrides,
  };
}

describe("generateFixProposal", () => {
  it("generates a fix proposal for PROVEN finding", () => {
    const proposal = generateFixProposal(makeInput(), "chain-001");
    expect(proposal.id).toMatch(/^fix-/);
    expect(proposal.findingId).toBe("f-001");
    expect(proposal.chainId).toBe("chain-001");
    expect(proposal.type).toBe("waf_rule");
    expect(proposal.priority).toBe("high");
    expect(proposal.evidenceQuality).toBe("proven");
    expect(proposal.verificationPayload).not.toBeNull();
    expect(proposal.verificationPayload!.expectedVulnIndicators.length).toBeGreaterThan(0);
  });

  it("generates a fix proposal for CORROBORATED finding", () => {
    const proposal = generateFixProposal(
      makeInput({ evidenceQuality: "corroborated" }),
      "chain-002",
    );
    expect(proposal.evidenceQuality).toBe("corroborated");
    expect(proposal.id).toMatch(/^fix-/);
  });

  it("throws for INFERRED finding", () => {
    expect(() =>
      generateFixProposal(
        makeInput({ evidenceQuality: "inferred" as any }),
        "chain-003",
      )
    ).toThrow("Cannot generate fix proposal for inferred finding");
  });

  it("throws for UNVERIFIABLE finding", () => {
    expect(() =>
      generateFixProposal(
        makeInput({ evidenceQuality: "unverifiable" as any }),
        "chain-004",
      )
    ).toThrow("Cannot generate fix proposal for unverifiable finding");
  });

  it("generates IAM policy fix for IAM-related finding", () => {
    const proposal = generateFixProposal(
      makeInput({
        title: "IAM Privilege Escalation via CreateUser",
        technique: "iam_escalation",
      }),
      "chain-005",
    );
    expect(proposal.type).toBe("iam_policy");
    expect(proposal.content).toContain("iam:CreateUser");
  });

  it("generates WAF rule for XSS finding", () => {
    const proposal = generateFixProposal(
      makeInput({
        title: "Reflected XSS in search endpoint",
        technique: "xss",
      }),
      "chain-006",
    );
    expect(proposal.type).toBe("waf_rule");
    expect(proposal.content).toContain("detectXSS");
  });

  it("returns null verification payload when no targetUrl", () => {
    const proposal = generateFixProposal(
      makeInput({ targetUrl: undefined, requestPayload: undefined }),
      "chain-007",
    );
    expect(proposal.verificationPayload).toBeNull();
  });

  it("maps severity to priority correctly", () => {
    const critical = generateFixProposal(
      makeInput({ severity: "critical" }),
      "chain-008",
    );
    expect(critical.priority).toBe("critical");

    const medium = generateFixProposal(
      makeInput({ severity: "medium" }),
      "chain-009",
    );
    expect(medium.priority).toBe("medium");
  });
});
