/**
 * governance-live-mode.test.ts
 *
 * Tests for the live mode approval gate fix — requireAuthorizationForLive=false
 * must allow breach chains through without a manual approval step.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { validateOperation } from "../validation/execution-modes";
import { GovernanceEnforcementService } from "./governance-enforcement";
import type { OrganizationGovernance } from "@shared/schema";

// ─── validateOperation (pure) — approval gate behavior ───────────────────────

describe("validateOperation — live mode approval gate", () => {
  it("returns requiresApproval=true for exploitExecution in live mode", () => {
    const result = validateOperation("live", "exploitExecution");
    expect(result.allowed).toBe(false);
    expect(result.requiresApproval).toBe(true);
  });

  it("returns ciso approval level for exploitExecution", () => {
    const result = validateOperation("live", "exploitExecution");
    expect(result.requiredApprovalLevel).toBe("ciso");
  });

  it("returns security_lead approval level for dataExfiltration", () => {
    const result = validateOperation("live", "dataExfiltration");
    expect(result.requiresApproval).toBe(true);
    expect(result.requiredApprovalLevel).toBe("security_lead");
  });

  it("simulation mode — credentialTesting is allowed without approval", () => {
    const result = validateOperation("simulation", "credentialTesting");
    expect(result.allowed).toBe(true);
    expect(result.requiresApproval).toBeFalsy();
  });

  it("safe mode — portScanning is allowed without approval", () => {
    const result = validateOperation("safe", "portScanning");
    expect(result.allowed).toBe(true);
    expect(result.requiresApproval).toBeFalsy();
  });

  it(".gov targets are blocked regardless of mode", () => {
    const result = validateOperation("live", "exploitExecution", "target.gov");
    expect(result.allowed).toBe(false);
  });
});

// ─── GovernanceEnforcementService.checkExecutionMode (real class, mocked DB) ──

function makeGovernance(overrides: Partial<OrganizationGovernance> = {}): OrganizationGovernance {
  return {
    id: "gov-001",
    organizationId: "org-test",
    executionMode: "live",
    killSwitchActive: false,
    killSwitchActivatedAt: null,
    killSwitchActivatedBy: null,
    rateLimitPerHour: 100,
    rateLimitPerDay: 1000,
    concurrentEvaluationsLimit: 5,
    currentConcurrentEvaluations: 0,
    allowedTargetPatterns: [],
    blockedTargetPatterns: [],
    allowedNetworkRanges: [],
    requireAuthorizationForLive: true,
    autoKillOnCritical: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

describe("GovernanceEnforcementService.checkExecutionMode", () => {
  let service: GovernanceEnforcementService;

  beforeEach(() => {
    service = new GovernanceEnforcementService();
  });

  it("blocks exploitExecution in live mode when requireAuthorizationForLive=true", async () => {
    vi.spyOn(service as any, "getGovernance").mockResolvedValue(
      makeGovernance({ executionMode: "live", requireAuthorizationForLive: true })
    );
    const result = await service.checkExecutionMode("org-test", "exploitExecution");
    expect(result.allowed).toBe(false);
    expect(result.requiresApproval).toBe(true);
  });

  it("allows exploitExecution in live mode when requireAuthorizationForLive=false", async () => {
    vi.spyOn(service as any, "getGovernance").mockResolvedValue(
      makeGovernance({ executionMode: "live", requireAuthorizationForLive: false })
    );
    const result = await service.checkExecutionMode("org-test", "exploitExecution");
    expect(result.allowed).toBe(true);
  });

  it("allows when no governance record exists (defaults to open)", async () => {
    vi.spyOn(service as any, "getGovernance").mockResolvedValue(undefined);
    const result = await service.checkExecutionMode("org-test", "exploitExecution");
    expect(result.allowed).toBe(true);
  });

  it("blocks in safe mode for exploitExecution regardless of requireAuthorizationForLive", async () => {
    vi.spyOn(service as any, "getGovernance").mockResolvedValue(
      makeGovernance({ executionMode: "safe", requireAuthorizationForLive: false })
    );
    const result = await service.checkExecutionMode("org-test", "exploitExecution");
    expect(result.allowed).toBe(false);
    // Not an approval issue — the operation isn't allowed in safe mode at all
    expect(result.requiresApproval).toBeFalsy();
  });

  it("allows portScanning in safe mode", async () => {
    vi.spyOn(service as any, "getGovernance").mockResolvedValue(
      makeGovernance({ executionMode: "safe", requireAuthorizationForLive: true })
    );
    const result = await service.checkExecutionMode("org-test", "portScanning");
    expect(result.allowed).toBe(true);
  });

  it("allows credentialTesting in simulation mode", async () => {
    vi.spyOn(service as any, "getGovernance").mockResolvedValue(
      makeGovernance({ executionMode: "simulation", requireAuthorizationForLive: true })
    );
    const result = await service.checkExecutionMode("org-test", "credentialTesting");
    expect(result.allowed).toBe(true);
  });
});
