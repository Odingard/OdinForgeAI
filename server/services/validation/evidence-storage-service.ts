import type { ValidationEvidenceArtifact, InsertValidationEvidenceArtifact, ValidationVerdict } from "@shared/schema";
import { storage } from "../../storage";

const DEFAULT_RETENTION_DAYS = 90;
const MAX_ARTIFACTS_PER_EVALUATION = 100;
const MAX_ARTIFACT_SIZE_BYTES = 500 * 1024;

export interface EvidenceQuery {
  organizationId: string;
  evaluationId?: string;
  findingId?: string;
  scanId?: string;
  validationId?: string;
  verdict?: ValidationVerdict;
  vulnerabilityType?: string;
  limit?: number;
  offset?: number;
}

export interface EvidenceSummary {
  totalArtifacts: number;
  confirmedCount: number;
  likelyCount: number;
  theoreticalCount: number;
  falsePositiveCount: number;
  errorCount: number;
  totalSizeBytes: number;
  oldestArtifact?: Date;
  newestArtifact?: Date;
}

export class EvidenceStorageService {
  private retentionDays: number;
  private maxArtifactsPerEvaluation: number;
  private maxArtifactSizeBytes: number;

  constructor(options?: {
    retentionDays?: number;
    maxArtifactsPerEvaluation?: number;
    maxArtifactSizeBytes?: number;
  }) {
    this.retentionDays = options?.retentionDays || DEFAULT_RETENTION_DAYS;
    this.maxArtifactsPerEvaluation = options?.maxArtifactsPerEvaluation || MAX_ARTIFACTS_PER_EVALUATION;
    this.maxArtifactSizeBytes = options?.maxArtifactSizeBytes || MAX_ARTIFACT_SIZE_BYTES;
  }

  async storeEvidence(data: InsertValidationEvidenceArtifact): Promise<ValidationEvidenceArtifact> {
    if (data.artifactSizeBytes && data.artifactSizeBytes > this.maxArtifactSizeBytes) {
      data = this.truncateArtifact(data);
    }

    if (data.evaluationId) {
      await this.enforceEvaluationLimit(data.evaluationId, data.organizationId);
    }

    return storage.createValidationEvidenceArtifact(data);
  }

  async getEvidence(id: string): Promise<ValidationEvidenceArtifact | undefined> {
    return storage.getValidationEvidenceArtifact(id);
  }

  async queryEvidence(query: EvidenceQuery): Promise<ValidationEvidenceArtifact[]> {
    const organizationId = query.organizationId;
    if (query.evaluationId) {
      return storage.getValidationEvidenceArtifactsByEvaluationId(query.evaluationId, organizationId);
    }
    if (query.findingId) {
      return storage.getValidationEvidenceArtifactsByFindingId(query.findingId, organizationId);
    }
    if (query.scanId) {
      return storage.getValidationEvidenceArtifactsByScanId(query.scanId, organizationId);
    }
    return storage.getValidationEvidenceArtifacts(organizationId, query.limit);
  }

  async getEvidenceForEvaluation(evaluationId: string, organizationId?: string): Promise<ValidationEvidenceArtifact[]> {
    return storage.getValidationEvidenceArtifactsByEvaluationId(evaluationId, organizationId || "");
  }

  async getEvidenceForFinding(findingId: string, organizationId?: string): Promise<ValidationEvidenceArtifact[]> {
    return storage.getValidationEvidenceArtifactsByFindingId(findingId, organizationId || "");
  }

  async getSummary(organizationId: string): Promise<EvidenceSummary> {
    const artifacts = await storage.getValidationEvidenceArtifacts(organizationId);

    const summary: EvidenceSummary = {
      totalArtifacts: artifacts.length,
      confirmedCount: 0,
      likelyCount: 0,
      theoreticalCount: 0,
      falsePositiveCount: 0,
      errorCount: 0,
      totalSizeBytes: 0,
    };

    for (const artifact of artifacts) {
      switch (artifact.verdict) {
        case "confirmed":
          summary.confirmedCount++;
          break;
        case "likely":
          summary.likelyCount++;
          break;
        case "theoretical":
          summary.theoreticalCount++;
          break;
        case "false_positive":
          summary.falsePositiveCount++;
          break;
        case "error":
          summary.errorCount++;
          break;
      }

      if (artifact.artifactSizeBytes) {
        summary.totalSizeBytes += artifact.artifactSizeBytes;
      }

      const capturedAt = artifact.capturedAt ? new Date(artifact.capturedAt) : null;
      if (capturedAt) {
        if (!summary.oldestArtifact || capturedAt < summary.oldestArtifact) {
          summary.oldestArtifact = capturedAt;
        }
        if (!summary.newestArtifact || capturedAt > summary.newestArtifact) {
          summary.newestArtifact = capturedAt;
        }
      }
    }

    return summary;
  }

  async cleanupOldArtifacts(): Promise<{ deletedCount: number }> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.retentionDays);

    const deletedCount = await storage.deleteOldValidationEvidenceArtifacts(cutoffDate);
    console.log(`[EvidenceStorage] Cleaned up ${deletedCount} artifacts older than ${this.retentionDays} days`);

    return { deletedCount };
  }

  async deleteEvidence(id: string): Promise<void> {
    await storage.deleteValidationEvidenceArtifact(id);
  }

  async updateVerdict(id: string, verdict: ValidationVerdict, confidenceScore?: number): Promise<void> {
    const updates: Partial<ValidationEvidenceArtifact> = { verdict };
    if (confidenceScore !== undefined) {
      updates.confidenceScore = confidenceScore;
    }
    await storage.updateValidationEvidenceArtifact(id, updates);
  }

  private truncateArtifact(data: InsertValidationEvidenceArtifact): InsertValidationEvidenceArtifact {
    const truncated = { ...data };

    if (truncated.httpResponse) {
      const responseBody = truncated.httpResponse.body;
      if (typeof responseBody === "string" && responseBody.length > 50000) {
        truncated.httpResponse = {
          ...truncated.httpResponse,
          body: responseBody.slice(0, 50000) + "...[truncated]",
          bodyTruncated: true,
        };
      }
    }

    if (truncated.httpRequest) {
      const requestBody = truncated.httpRequest.body;
      if (typeof requestBody === "string" && requestBody.length > 10000) {
        truncated.httpRequest = {
          ...truncated.httpRequest,
          body: requestBody.slice(0, 10000) + "...[truncated]",
        };
      }
    }

    if (truncated.rawDataBase64 && truncated.rawDataBase64.length > 100000) {
      truncated.rawDataBase64 = undefined;
    }

    return truncated;
  }

  private async enforceEvaluationLimit(evaluationId: string, organizationId: string): Promise<void> {
    const existing = await storage.getValidationEvidenceArtifactsByEvaluationId(evaluationId, organizationId);

    if (existing.length >= this.maxArtifactsPerEvaluation) {
      const toDelete = existing
        .filter(a => a.verdict === "theoretical" || a.verdict === "false_positive")
        .sort((a, b) => {
          const aTime = a.capturedAt ? new Date(a.capturedAt).getTime() : 0;
          const bTime = b.capturedAt ? new Date(b.capturedAt).getTime() : 0;
          return aTime - bTime;
        })
        .slice(0, 10);

      for (const artifact of toDelete) {
        await storage.deleteValidationEvidenceArtifact(artifact.id);
      }

      console.log(`[EvidenceStorage] Removed ${toDelete.length} old artifacts to stay within limit for evaluation ${evaluationId}`);
    }
  }
}

export const evidenceStorageService = new EvidenceStorageService();
