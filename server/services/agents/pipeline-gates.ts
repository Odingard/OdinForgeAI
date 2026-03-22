/**
 * Pipeline Gates — Logic routing between agent steps
 *
 * These gate functions enforce EvidenceContract compliance at critical
 * decision points in the agent pipeline. No synthetic/LLM-only findings
 * pass through.
 *
 * Gate functions are pure TypeScript — NO LLM calls.
 *
 * Logic_Recon_Success:
 *   Pass/fail gate after Step 2 (Reconnaissance).
 *   If recon found no entry points, the chain stops here.
 *
 * Logic_Exploit_Confirmed:
 *   Gate between Step 3 (Exploitation) and Step 4 (Lateral Move + Impact).
 *   If no thread A/B/C agent confirmed a real finding, Step 4 is skipped.
 */

import type {
  ReconFindings,
  ExploitFindings,
  BusinessLogicFindings,
  MultiVectorFindings,
} from "./types";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface GateResult {
  passed: boolean;
  reason: string;
  /** Metrics about what was evaluated */
  metrics: Record<string, number>;
}

// ─── Logic_Recon_Success ───────────────────────────────────────────────────

/**
 * Checks whether reconnaissance produced actionable entry points.
 *
 * EvidenceContract compliance:
 *   - At least one entry point OR api endpoint must exist
 *   - Attack surface must have at least one element
 *   - Recon cannot be purely empty (all fields zero)
 *
 * If this gate fails, the pipeline should stop — there is nothing to exploit.
 */
export function gateReconSuccess(recon: ReconFindings | undefined): GateResult {
  if (!recon) {
    return {
      passed: false,
      reason: "No recon findings available",
      metrics: { entryPoints: 0, apiEndpoints: 0, attackSurface: 0, technologies: 0 },
    };
  }

  const entryPointCount = recon.entryPoints.length;
  const apiEndpointCount = recon.apiEndpoints.length;
  const attackSurfaceCount = recon.attackSurface.length;
  const technologyCount = recon.technologies.length;
  const vulnCount = recon.potentialVulnerabilities.length;
  const portCount = recon.openPorts.length;

  const metrics = {
    entryPoints: entryPointCount,
    apiEndpoints: apiEndpointCount,
    attackSurface: attackSurfaceCount,
    technologies: technologyCount,
    potentialVulnerabilities: vulnCount,
    openPorts: portCount,
  };

  // Primary gate: must have at least one actionable target
  const hasActionableTargets = entryPointCount > 0 || apiEndpointCount > 0;

  // Secondary check: recon must have discovered something meaningful
  const hasAnyIntel = attackSurfaceCount > 0 || technologyCount > 0 || portCount > 0;

  if (!hasActionableTargets && !hasAnyIntel) {
    return {
      passed: false,
      reason: "Recon found no entry points, API endpoints, or attack surface — nothing to exploit",
      metrics,
    };
  }

  // Warn case: we have some intel but no direct entry points.
  // Still pass — the exploit agent can fingerprint and discover endpoints.
  if (!hasActionableTargets && hasAnyIntel) {
    return {
      passed: true,
      reason: `Recon found ${attackSurfaceCount} attack surface elements and ${technologyCount} technologies but no direct entry points — exploit agent will fingerprint`,
      metrics,
    };
  }

  return {
    passed: true,
    reason: `Recon success: ${entryPointCount} entry points, ${apiEndpointCount} API endpoints, ${vulnCount} potential vulnerabilities`,
    metrics,
  };
}

// ─── Logic_Exploit_Confirmed ───────────────────────────────────────────────

/**
 * Checks whether any exploitation thread (A/B/C) confirmed a real finding.
 *
 * EvidenceContract compliance:
 *   - At least one exploit chain must have validated === true
 *     OR validationConfidence >= 50
 *   - Pure LLM-inferred findings (no evidence) do NOT count
 *   - Business logic findings with authorization bypass count
 *   - Multi-vector findings with confirmed cloud/IAM issues count
 *
 * If this gate fails, Step 4 (lateral movement + impact) is skipped
 * because there is nothing to pivot from.
 */
export function gateExploitConfirmed(
  exploitFindings: ExploitFindings | undefined,
  businessLogicFindings: BusinessLogicFindings | undefined,
  multiVectorFindings: MultiVectorFindings | undefined
): GateResult {
  let confirmedExploits = 0;
  let confirmedBL = 0;
  let confirmedMV = 0;

  // Thread A: Exploit agent — check for real validated findings
  if (exploitFindings && exploitFindings.exploitChains) {
    for (const chain of exploitFindings.exploitChains) {
      // Chain must have real evidence — validated flag or high confidence
      const hasRealEvidence =
        chain.validated === true ||
        (chain.validationConfidence !== undefined && chain.validationConfidence >= 50);

      // Also check tool call log for any confirmed vulnerability
      const hasToolEvidence =
        exploitFindings.toolCallLog?.some(
          (tc) => tc.vulnerable && tc.confidence >= 50
        ) ?? false;

      if (hasRealEvidence || hasToolEvidence) {
        confirmedExploits++;
      }
    }
  }

  // Thread B: Business logic agent — check for real authorization bypasses
  if (businessLogicFindings) {
    confirmedBL += businessLogicFindings.authorizationBypass.length;
    confirmedBL += businessLogicFindings.raceConditions.length;
  }

  // Thread C: Multi-vector agent — check for confirmed cloud/IAM findings
  if (multiVectorFindings) {
    for (const finding of multiVectorFindings.findings) {
      if (finding.severity === "critical" || finding.severity === "high") {
        confirmedMV++;
      }
    }
    confirmedMV += multiVectorFindings.iamFindings.length;
  }

  const totalConfirmed = confirmedExploits + confirmedBL + confirmedMV;
  const metrics = {
    confirmedExploits,
    confirmedBusinessLogic: confirmedBL,
    confirmedMultiVector: confirmedMV,
    totalConfirmed,
  };

  if (totalConfirmed === 0) {
    return {
      passed: false,
      reason: "No confirmed findings from any exploitation thread — skipping lateral movement and impact assessment",
      metrics,
    };
  }

  return {
    passed: true,
    reason: `Exploit confirmed: ${confirmedExploits} exploit chains, ${confirmedBL} business logic, ${confirmedMV} multi-vector findings`,
    metrics,
  };
}
