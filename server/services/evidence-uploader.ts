/**
 * Evidence Uploader — stores evidence artifact bundles.
 *
 * Strategy:
 * 1. Serialize tool call evidence + analysis artifacts to JSON
 * 2. Store each artifact via EvidenceStorageService (DB-backed)
 * 3. Store the full bundle JSON as a "bundle" artifact with storage_key reference
 *
 * Reliability:
 * - In dev/benchmark mode (NODE_ENV !== "production" || BENCHMARK_MODE=1): awaited by caller
 * - In production: fire-and-forget, failures logged with evaluationId
 */

import { randomUUID } from "crypto";
import type { EvidenceArtifact } from "@shared/schema";

/** True when uploads should be awaited (dev, test, benchmark runs). */
export const EVIDENCE_UPLOAD_SYNC =
  process.env.NODE_ENV !== "production" || process.env.BENCHMARK_MODE === "1";

/**
 * Persist evidence artifacts to the DB via the evidence storage service.
 * Each artifact becomes a `validation_evidence_artifacts` row.
 * Returns { stored, failed } counts for telemetry.
 */
export async function uploadAndLinkEvidence(
  evaluationId: string,
  organizationId: string,
  artifacts: EvidenceArtifact[]
): Promise<{ stored: number; failed: number }> {
  if (artifacts.length === 0) return { stored: 0, failed: 0 };

  let stored = 0;
  let failed = 0;

  try {
    const { EvidenceStorageService } = await import("./validation/evidence-storage-service");
    const evidenceStore = new EvidenceStorageService();

    // Store each artifact as a DB row
    for (const artifact of artifacts) {
      try {
        await evidenceStore.storeEvidence({
          tenantId: organizationId,
          organizationId,
          evaluationId,
          evidenceType: artifact.type || "request_response",
          verdict: "theoretical",
          validationMethod: "agent_based",
          observedBehavior: artifact.description || "",
          targetUrl: (artifact.data as any)?.request?.url || undefined,
          storageKey: `evidence/${organizationId}/${evaluationId}/${artifact.id}`,
        });
        stored++;
      } catch (e) {
        failed++;
        console.warn(`[EvidenceUploader] Artifact ${artifact.id} failed for eval=${evaluationId}:`, (e as Error).message);
      }
    }

    // Store a summary bundle artifact
    const bundleJson = JSON.stringify({
      evaluationId,
      organizationId,
      exportedAt: new Date().toISOString(),
      artifactCount: artifacts.length,
      artifacts,
    });

    const bundleKey = `evidence/${organizationId}/${evaluationId}/bundle-${randomUUID()}.json`;

    // Try MinIO/S3 upload first, fall back to DB-only base64 storage
    let objectStorageUrl: string | undefined;
    try {
      const { StorageService } = await import("./storage");
      const storageService = new StorageService();
      objectStorageUrl = await storageService.uploadFile(
        bundleKey, Buffer.from(bundleJson), "application/json"
      );
    } catch {
      // MinIO/S3 not configured or unavailable — fall through to DB storage
    }

    await evidenceStore.storeEvidence({
      tenantId: organizationId,
      organizationId,
      evaluationId,
      evidenceType: "evidence_bundle",
      verdict: "theoretical",
      validationMethod: "agent_based",
      observedBehavior: `Evidence bundle: ${artifacts.length} artifacts`,
      storageKey: bundleKey,
      objectStorageUrl,
      rawDataBase64: objectStorageUrl
        ? undefined
        : Buffer.from(bundleJson).toString("base64").slice(0, 500 * 1024),
    });
    stored++;

    console.log(`[EvidenceUploader] eval=${evaluationId}: ${stored} stored, ${failed} failed`);
  } catch (e) {
    failed++;
    console.warn(`[EvidenceUploader] Bundle failed for eval=${evaluationId}:`, (e as Error).message);
  }

  return { stored, failed };
}
