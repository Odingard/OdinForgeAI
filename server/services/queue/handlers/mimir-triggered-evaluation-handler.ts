// =============================================================================
// Task 03 — Handler: mimir_triggered_evaluation
//
// Handles jobs enqueued by the Redis Stream consumer when a Mimir assessment
// completes with grade C, D, or F.
//
// Flow:
//   1. Idempotency check — don't run twice for same Mimir assessment
//   2. Resolve or create a discovered_asset for the target domain
//   3. Create aev_evaluation record
//   4. Register cross-product link in entity_graph.assessments
//   5. Enqueue standard "evaluation" job via existing orchestrator
// =============================================================================

import { Job } from "bullmq";
import { randomUUID } from "crypto";
import { eq, and, sql } from "drizzle-orm";
import { db } from "../../../db";
import { storage } from "../../../storage";
import { setTenantContext } from "../../rls-setup";
import { queueService } from "../queue-service";
import {
  egAssessments,
  discoveredAssets,
} from "@shared/schema";
import type {
  MimirTriggeredEvaluationJobData,
  JobResult,
} from "../job-types";


// =============================================================================
// IDEMPOTENCY — check entity_graph.assessments for existing exploit_validation
// =============================================================================

async function isAlreadyTriggered(
  mimirAssessmentId: string,
  organizationId: string,
): Promise<boolean> {
  const existing = await db
    .select({ id: egAssessments.id })
    .from(egAssessments)
    .where(
      and(
        eq(egAssessments.assessmentType, "exploit_validation"),
        eq(egAssessments.sourceProduct, "odinforge"),
        sql`${egAssessments.summary}->>'mimir_assessment_id' = ${mimirAssessmentId}`,
      ),
    )
    .limit(1);

  return existing.length > 0;
}


// =============================================================================
// ASSET RESOLUTION — find or create discovered_asset for target domain
// =============================================================================

async function resolveOrCreateAsset(
  targetDomain: string,
  organizationId: string,
): Promise<string> {
  // Look up existing asset by hostname
  const existing = await db
    .select({ id: discoveredAssets.id })
    .from(discoveredAssets)
    .where(
      and(
        eq(discoveredAssets.organizationId, organizationId),
        sql`(
          ${discoveredAssets.hostname} = ${targetDomain}
          OR ${discoveredAssets.assetIdentifier} = ${targetDomain}
        )`,
      ),
    )
    .limit(1);

  if (existing.length > 0) {
    return existing[0].id;
  }

  // Create stub asset — will be enriched during evaluation
  const asset = await storage.createDiscoveredAsset({
    organizationId,
    assetIdentifier: targetDomain,
    assetType: "web_application",
    hostname: targetDomain,
    environment: "production",
    criticality: "high",
    discoverySource: "mimir_triggered",
  });

  return asset.id;
}


// =============================================================================
// MAIN HANDLER
// =============================================================================

export async function handleMimirTriggeredEvaluation(
  job: Job<MimirTriggeredEvaluationJobData>,
): Promise<JobResult> {
  const start = Date.now();
  const {
    mimir_assessment_id,
    mimir_event_id,
    stream_event_id,
    target_domain,
    entity_id,
    risk_grade,
    risk_score,
    kev_count,
    critical_count,
    top_risk_findings,
    industry,
    company_name,
    tenantId,
    organizationId,
    userId,
    execution_mode,
  } = job.data;

  const logPrefix = `[MimirTriggered] domain=${target_domain} grade=${risk_grade}`;

  try {
    // Set RLS context for this background job
    await setTenantContext(organizationId);

    // 1. Idempotency check
    const alreadyRan = await isAlreadyTriggered(mimir_assessment_id, organizationId);
    if (alreadyRan) {
      console.log(`${logPrefix} — already triggered, skipping`);
      return {
        success: true,
        data: { skipped: true, reason: "already_triggered" },
        duration: Date.now() - start,
      };
    }

    // 2. Resolve or create asset
    const assetId = await resolveOrCreateAsset(target_domain, organizationId);

    // 3. Build exposure data from top Mimir findings
    const topFinding = top_risk_findings[0];
    const description = topFinding
      ? `Mimir-identified: ${topFinding.title} (grade ${risk_grade}, score ${risk_score})`
      : `Mimir grade ${risk_grade} — automated validation (score ${risk_score})`;

    const exposureType = topFinding?.category ?? "web_application";

    // Map "aggressive" → "live" for OdinForge execution modes (safe | simulation | live)
    const odinforgeMode = execution_mode === "aggressive" ? "live" : "safe";

    // 4. Create aev_evaluation via storage (follows existing ID pattern)
    const evaluation = await storage.createEvaluation({
      organizationId,
      assetId,
      exposureType,
      priority: kev_count > 0 || risk_grade === "F" ? "critical" : "high",
      description,
      executionMode: odinforgeMode,
      status: "pending",
    });

    // 5. Register cross-product link in entity_graph.assessments
    // Uses a fresh UUID for source_id (entity_graph columns are UUID type)
    const egSourceId = randomUUID();
    try {
      await db.execute(
        sql`
          INSERT INTO entity_graph.assessments (
            id, organization_id, entity_id, assessment_type, source_product,
            source_id, source_table, status, summary
          ) VALUES (
            gen_random_uuid(),
            ${organizationId}::uuid,
            ${entity_id}::uuid,
            'exploit_validation',
            'odinforge',
            ${egSourceId}::uuid,
            'aev_evaluations',
            'pending',
            ${JSON.stringify({
              mimir_assessment_id,
              mimir_event_id,
              risk_grade,
              risk_score,
              evaluation_id: evaluation.id,
              triggered_by: "mimir_stream",
            })}::jsonb
          )
          ON CONFLICT (source_product, source_table, source_id) DO NOTHING
        `,
      );
    } catch (egErr) {
      // Entity graph write is best-effort — don't fail the whole job
      console.warn(`${logPrefix} — entity graph write failed:`, (egErr as Error).message);
    }

    // 6. Build exposure data for the standard evaluation job
    const exposureData = topFinding
      ? {
          exposureType: topFinding.category,
          priority: topFinding.severity === "critical" ? "critical" : "high",
          description: `Mimir-identified: ${topFinding.title}`,
          mimirFindings: top_risk_findings.map(f => ({
            id: f.finding_id,
            title: f.title,
            severity: f.severity,
            cve_id: f.cve_id,
            is_kev: f.is_kev_listed,
          })),
        }
      : {
          exposureType: "web_application",
          priority: "high",
          description: `Mimir grade ${risk_grade} — automated validation`,
        };

    // 7. Enqueue standard evaluation job via existing pipeline
    const bullJobId = await queueService.addJob("evaluation", {
      type: "evaluation",
      tenantId,
      organizationId,
      userId,
      evaluationId: evaluation.id,
      executionMode: odinforgeMode as "safe" | "simulation" | "live",
      assetId,
      exposureData,
      correlationId: mimir_event_id,
    });

    console.log(
      `${logPrefix} — enqueued evaluation ${evaluation.id} `
      + `(mode=${odinforgeMode} bull_job=${bullJobId})`,
    );

    return {
      success: true,
      data: {
        evaluation_id: evaluation.id,
        bull_job_id: bullJobId,
        asset_id: assetId,
        execution_mode: odinforgeMode,
        findings_count: top_risk_findings.length,
      },
      duration: Date.now() - start,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`${logPrefix} — handler error:`, message);

    return {
      success: false,
      error: message,
      duration: Date.now() - start,
    };
  }
}
