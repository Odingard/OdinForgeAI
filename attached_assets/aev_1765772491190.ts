import axios from "axios";
import { logger } from "../logger";
import { websocket } from "./websocket";
import { kafka, KafkaEvent, TOPICS } from "./kafka";
import { nanoid } from "nanoid";
import { 
  createAevResult, 
  getAevResults, 
  getAevResultByEvaluationId,
  updateAevResult,
} from "../storage/security";

const AEV_SERVICE_URL = process.env.AEV_SERVICE_URL || "http://localhost:8000";
const AEV_SERVICE_SECRET = process.env.AEV_SERVICE_SECRET || "";
const AEV_TIMEOUT_MS = (() => {
  const timeout = parseInt(process.env.AEV_TIMEOUT_MS || "120000", 10);
  return isNaN(timeout) || timeout <= 0 ? 120000 : timeout;
})();

export interface ExposureInput {
  assetId: string;
  exposureType: "cve" | "misconfiguration" | "behavior" | "network" | "custom";
  description: string;
  data: Record<string, any>;
  organizationId: string;
  module?: "posture" | "spear" | "sentinel" | "vulnmgmt";
  priority?: "low" | "medium" | "high" | "critical";
}

export interface SimulationResult {
  evaluationId: string;
  exploitable: boolean;
  confidence: number;
  attackPath: string[];
  impact: string;
  recommendedFix: string;
  score: number;
  status: "pending" | "in_progress" | "completed" | "failed";
  error?: string;
  duration?: number;
  completedAt?: string;
}

interface AEVEvaluation {
  id: string;
  input: ExposureInput;
  status: "pending" | "in_progress" | "completed" | "failed";
  result?: SimulationResult;
  createdAt: Date;
  updatedAt: Date;
}

class AEVService {
  private evaluations: Map<string, AEVEvaluation> = new Map();
  private enabled: boolean = false;

  constructor() {
    this.enabled = !!process.env.AEV_SERVICE_URL;
    if (this.enabled) {
      logger.info({ url: AEV_SERVICE_URL, timeout: AEV_TIMEOUT_MS }, "✅ AEV Service initialized");
    } else {
      logger.info("⚠️ AEV Service URL not configured, running in mock mode");
    }
  }

  startEvaluation(input: ExposureInput, providedEvaluationId?: string): string {
    const evaluationId = providedEvaluationId || `aev-${nanoid()}`;
    
    if (!this.evaluations.has(evaluationId)) {
      const evaluation: AEVEvaluation = {
        id: evaluationId,
        input,
        status: "pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.evaluations.set(evaluationId, evaluation);
    }
    return evaluationId;
  }

  async evaluate(input: ExposureInput, existingEvaluationId?: string): Promise<SimulationResult> {
    const evaluationId = existingEvaluationId || this.startEvaluation(input);
    const startTime = Date.now();

    let evaluation = this.evaluations.get(evaluationId);
    if (!evaluation) {
      evaluation = {
        id: evaluationId,
        input,
        status: "pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.evaluations.set(evaluationId, evaluation);
    }

    try {
      this.updateProgress(evaluationId, input.organizationId, 0, "Initializing evaluation...");
      evaluation.status = "in_progress";
      evaluation.updatedAt = new Date();

      if (!this.enabled) {
        return await this.mockEvaluate(evaluationId, input);
      }

      this.updateProgress(evaluationId, input.organizationId, 20, "Connecting to AEV engine...");

      const response = await axios.post(
        `${AEV_SERVICE_URL}/aev/evaluate`,
        {
          asset_id: input.assetId,
          exposure_type: input.exposureType,
          description: input.description,
          data: input.data,
        },
        {
          headers: {
            "Content-Type": "application/json",
            ...(AEV_SERVICE_SECRET && { "X-AI-Service-Secret": AEV_SERVICE_SECRET }),
          },
          timeout: AEV_TIMEOUT_MS,
        }
      );

      this.updateProgress(evaluationId, input.organizationId, 80, "Processing results...");

      const result: SimulationResult = {
        evaluationId,
        exploitable: response.data.exploitable,
        confidence: response.data.confidence,
        attackPath: response.data.attack_path,
        impact: response.data.impact,
        recommendedFix: response.data.recommended_fix,
        score: response.data.score,
        status: "completed",
        duration: Date.now() - startTime,
        completedAt: new Date().toISOString(),
      };

      evaluation.status = "completed";
      evaluation.result = result;
      evaluation.updatedAt = new Date();

      await this.persistResult(input, result);

      this.notifyComplete(evaluationId, input.organizationId, result);

      await this.emitKafkaEvent("aev.completed", input.organizationId, {
        evaluationId,
        assetId: input.assetId,
        exposureType: input.exposureType,
        result,
      });

      logger.info({
        evaluationId,
        assetId: input.assetId,
        exploitable: result.exploitable,
        score: result.score,
        duration: result.duration,
      }, "AEV evaluation completed");

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      
      evaluation.status = "failed";
      evaluation.updatedAt = new Date();

      const result: SimulationResult = {
        evaluationId,
        exploitable: false,
        confidence: 0,
        attackPath: [],
        impact: "Unable to determine",
        recommendedFix: "Manual review required",
        score: 0,
        status: "failed",
        error: errorMessage,
        duration: Date.now() - startTime,
      };

      evaluation.result = result;

      await this.persistResult(input, result);

      this.notifyComplete(evaluationId, input.organizationId, result);

      logger.error({
        evaluationId,
        assetId: input.assetId,
        error: errorMessage,
      }, "AEV evaluation failed");

      return result;
    }
  }

  private async mockEvaluate(evaluationId: string, input: ExposureInput): Promise<SimulationResult> {
    const stages = [
      { 
        progress: 15, 
        stageNumber: 1,
        stageName: "Analyzing Exposure",
        message: "Parsing vulnerability characteristics...",
      },
      { 
        progress: 25, 
        stageNumber: 1,
        stageName: "Analyzing Exposure",
        message: "Mapping attack surface and entry points...",
      },
      { 
        progress: 35, 
        stageNumber: 2,
        stageName: "Simulating Exploit Chain",
        message: "Testing potential attack vectors...",
      },
      { 
        progress: 50, 
        stageNumber: 2,
        stageName: "Simulating Exploit Chain",
        message: "Validating exploit chain feasibility...",
      },
      { 
        progress: 60, 
        stageNumber: 3,
        stageName: "Impact Assessment",
        message: "Calculating blast radius and damage potential...",
      },
      { 
        progress: 75, 
        stageNumber: 3,
        stageName: "Impact Assessment",
        message: "Evaluating data exposure risk...",
      },
      { 
        progress: 85, 
        stageNumber: 4,
        stageName: "Recommendations",
        message: "Generating remediation strategies...",
      },
      { 
        progress: 95, 
        stageNumber: 4,
        stageName: "Recommendations",
        message: "Compiling mitigation playbook...",
      },
    ];

    for (const stage of stages) {
      await new Promise((resolve) => setTimeout(resolve, 400 + Math.random() * 300));
      this.updateProgress(
        evaluationId, 
        input.organizationId, 
        stage.progress, 
        stage.message,
        stage.stageNumber,
        stage.stageName
      );
    }

    const isExploitable = Math.random() > 0.5;
    const confidence = 0.7 + Math.random() * 0.25;
    const score = isExploitable ? 60 + Math.random() * 40 : 10 + Math.random() * 30;

    const result: SimulationResult = {
      evaluationId,
      exploitable: isExploitable,
      confidence: Math.round(confidence * 100) / 100,
      attackPath: isExploitable
        ? [
            "Initial access via network service",
            "Privilege escalation through misconfiguration",
            "Data exfiltration attempt",
          ]
        : [],
      impact: isExploitable
        ? input.priority === "critical"
          ? "Critical system compromise possible"
          : "Moderate impact on affected systems"
        : "Limited exposure, low risk",
      recommendedFix: isExploitable
        ? `Apply security patch for ${input.exposureType}. Review access controls and network segmentation.`
        : "No immediate action required. Monitor for changes.",
      score: Math.round(score * 10) / 10,
      status: "completed",
      duration: 2000 + Math.random() * 1000,
      completedAt: new Date().toISOString(),
    };

    const evaluation = this.evaluations.get(evaluationId);
    if (evaluation) {
      evaluation.status = "completed";
      evaluation.result = result;
      evaluation.updatedAt = new Date();
    }

    await this.persistResult(input, result);

    this.notifyComplete(evaluationId, input.organizationId, result);

    return result;
  }

  private async persistResult(input: ExposureInput, result: SimulationResult): Promise<void> {
    try {
      await createAevResult({
        organizationId: input.organizationId,
        evaluationId: result.evaluationId,
        exploitable: result.exploitable,
        confidence: Math.round(result.confidence * 100),
        score: Math.round(result.score),
        attackPath: result.attackPath,
        impact: result.impact,
        impactCategory: input.exposureType === "cve" ? "confidentiality" : "integrity",
        recommendedFix: result.recommendedFix,
        exploitComplexity: result.exploitable ? "medium" : "high",
        privilegesRequired: result.exploitable ? "low" : "none",
        userInteraction: "none",
        scope: "unchanged",
        status: result.status,
        errorMessage: result.error,
        duration: result.duration,
        metadata: {
          assetId: input.assetId,
          exposureType: input.exposureType,
          module: input.module,
          priority: input.priority,
          description: input.description,
        },
      });

      logger.info({ evaluationId: result.evaluationId }, "AEV result persisted to database");
    } catch (error) {
      logger.error({ error, evaluationId: result.evaluationId }, "Failed to persist AEV result to database");
    }
  }

  private updateProgress(
    evaluationId: string,
    organizationId: string,
    progress: number,
    stage: string,
    currentStage?: number,
    stageName?: string
  ): void {
    websocket.notifyAEVProgress(organizationId, {
      evaluationId,
      progress,
      stage,
      currentStage,
      stageName,
    });
  }

  private notifyComplete(
    evaluationId: string,
    organizationId: string,
    result: SimulationResult
  ): void {
    websocket.notifyAEVComplete(organizationId, {
      evaluationId,
      exploitable: result.exploitable,
      confidence: result.confidence,
      score: result.score,
      status: result.status,
      error: result.error,
    });
  }

  private async emitKafkaEvent(
    eventType: string,
    organizationId: string,
    payload: Record<string, any>
  ): Promise<void> {
    if (!kafka.isConnected()) return;

    const event: KafkaEvent = {
      eventId: nanoid(),
      eventType,
      organizationId,
      payload,
      timestamp: new Date().toISOString(),
      source: "aev-service",
      version: "1.0",
    };

    await kafka.publishEvent(TOPICS.SECURITY_EVENTS, event);
  }

  getEvaluation(evaluationId: string): AEVEvaluation | undefined {
    return this.evaluations.get(evaluationId);
  }

  getEvaluationsByOrganization(organizationId: string): AEVEvaluation[] {
    return Array.from(this.evaluations.values())
      .filter((e) => e.input.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getPersistedResults(
    organizationId: string, 
    filters: { taskId?: string; exploitable?: boolean; status?: string } = {},
    pagination = { limit: 50, offset: 0 }
  ) {
    return await getAevResults(organizationId, filters, pagination, { sortBy: "evaluatedAt", sortOrder: "desc" });
  }

  async getPersistedResultByEvaluationId(organizationId: string, evaluationId: string) {
    return await getAevResultByEvaluationId(organizationId, evaluationId);
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  getStats(): { enabled: boolean; totalEvaluations: number; pendingCount: number } {
    const evaluations = Array.from(this.evaluations.values());
    return {
      enabled: this.enabled,
      totalEvaluations: evaluations.length,
      pendingCount: evaluations.filter((e) => e.status === "in_progress" || e.status === "pending").length,
    };
  }
}

export const aevService = new AEVService();
