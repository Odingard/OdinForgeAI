// =============================================================================
// Intelligence Engine — HTTP Client
// Calls the Intelligence Engine sidecar (port 8001) from OdinForge.
//
// Called as a post-evaluation hook after AEV evaluation completes.
// Non-blocking — OdinForge continues without intelligence output on failure.
// =============================================================================

import { eq } from "drizzle-orm";
import { db } from "../db";
import {
  aevResults,
  vulnerabilityImports,
  type VulnerabilityImport,
  type Evaluation,
  type Result,
} from "@shared/schema";
import type {
  IntelligenceRequest,
  IntelligenceResponse,
  FindingInput,
  BreachChainInput,
} from "../types/intelligence.types";

const INTELLIGENCE_URL = process.env.INTELLIGENCE_SERVICE_URL ?? "http://intelligence:8001";
const INTELLIGENCE_SECRET = process.env.INTELLIGENCE_INTERNAL_SECRET ?? "";

/**
 * Call the Intelligence Engine's /analyze endpoint.
 * Returns null on any failure — caller should continue without intelligence output.
 */
export async function callIntelligenceEngine(
  request: IntelligenceRequest,
): Promise<IntelligenceResponse | null> {
  if (!INTELLIGENCE_SECRET) {
    console.warn("[Intelligence] No INTELLIGENCE_INTERNAL_SECRET configured — skipping");
    return null;
  }

  try {
    const res = await fetch(`${INTELLIGENCE_URL}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": INTELLIGENCE_SECRET,
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) {
      console.error("[Intelligence] HTTP error:", res.status, await res.text().catch(() => ""));
      return null;
    }

    return (await res.json()) as IntelligenceResponse;
  } catch (err) {
    console.error("[Intelligence] Call failed:", (err as Error).message);
    return null;
  }
}

/**
 * Build an IntelligenceRequest from a completed AEV evaluation.
 * Fetches vulnerability imports for the asset and maps them to FindingInput[].
 */
export async function buildIntelligenceRequest(
  evaluation: Evaluation,
  result: Result,
  organizationId: string,
  entityId?: string,
): Promise<IntelligenceRequest> {
  // Fetch vulnerability imports for the asset
  const vulns: VulnerabilityImport[] = evaluation.assetId
    ? await db
        .select()
        .from(vulnerabilityImports)
        .where(eq(vulnerabilityImports.organizationId, organizationId))
    : [];

  const findings: FindingInput[] = vulns.map((v) => ({
    id: v.id,
    source_product: "odinforge",
    title: v.cveId ?? `Vulnerability on ${v.affectedHost}`,
    category: "vulnerable_software",
    severity: (v.severity as FindingInput["severity"]) ?? "medium",
    cve_id: v.cveId ?? undefined,
    cvss_score: v.cvssScore ? Number(v.cvssScore) : undefined,
    epss_score: v.epssScore ? Number(v.epssScore) : undefined,
    is_kev_listed: v.isKevListed ?? false,
    evidence: {},
  }));

  // Build breach chain input from attack graph if present
  const breachChains: BreachChainInput[] = [];
  const attackGraph = result.attackGraph as Record<string, unknown> | null;
  if (attackGraph) {
    const nodes = (attackGraph.nodes as Array<Record<string, unknown>>) ?? [];
    const criticalPaths = (attackGraph.criticalPaths as string[][]) ?? [];
    breachChains.push({
      chain_id: result.id,
      steps: criticalPaths[0] ?? [],
      techniques: nodes
        .map((n) => n.technique as string)
        .filter(Boolean),
      confirmed: result.exploitable ?? false,
      cvss_max: result.score ? Number(result.score) : undefined,
    });
  }

  return {
    request_id: crypto.randomUUID(),
    organization_id: organizationId,
    entity_id: entityId,
    source_product: "odinforge",
    target_domain: (evaluation as Record<string, unknown>).targetDomain as string | undefined,
    mode: "full",
    tone: "technical",
    findings,
    breach_chains: breachChains.length > 0 ? breachChains : undefined,
  };
}

/**
 * Post-evaluation hook: call intelligence engine and persist narrative to aev_results.
 * Non-blocking — errors are logged but never propagate.
 */
export async function runPostEvaluationIntelligence(
  evaluation: Evaluation,
  result: Result,
  organizationId: string,
  entityId?: string,
): Promise<void> {
  try {
    const request = await buildIntelligenceRequest(evaluation, result, organizationId, entityId);
    const intelligence = await callIntelligenceEngine(request);

    if (!intelligence) return;

    // Persist narrative + calibrated score back to aev_results.intelligentScore
    // intelligentScore has mixed shapes in DB — use type assertion for the extended fields
    const existingScore = (result.intelligentScore as Record<string, unknown>) ?? {};

    const updatedScore = {
      ...existingScore,
      executiveSummary: intelligence.narrative?.executive_summary,
      riskHeadline: intelligence.narrative?.risk_headline,
      keyFindingsNarrative: intelligence.narrative?.key_findings_narrative,
      remediationSteps: intelligence.narrative?.remediation_steps,
      generatedBy: intelligence.narrative?.generated_by,
      groundedClaims: intelligence.narrative?.grounded_claims,
      calibratedScore: intelligence.statistical?.calibrated_score,
      calibrationDelta: intelligence.statistical?.calibration_delta,
      intelligenceTimingMs: intelligence.total_ms,
    } as any;

    await db
      .update(aevResults)
      .set({ intelligentScore: updatedScore })
      .where(eq(aevResults.id, result.id));

    console.log(
      "[Intelligence] Persisted narrative for evaluation %s (score=%.1f, %dms)",
      result.evaluationId,
      intelligence.deterministic.composite_score,
      intelligence.total_ms,
    );
  } catch (err) {
    console.error("[Intelligence] Post-evaluation hook failed:", (err as Error).message);
  }
}
