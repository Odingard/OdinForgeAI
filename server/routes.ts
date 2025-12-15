import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertEvaluationSchema } from "@shared/schema";
import { runAgentOrchestrator } from "./services/agents";
import { wsService } from "./services/websocket";
import { randomUUID } from "crypto";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  wsService.initialize(httpServer);

  app.post("/api/aev/evaluate", async (req, res) => {
    try {
      const parsed = insertEvaluationSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error });
      }

      const evaluation = await storage.createEvaluation(parsed.data);
      
      res.json({ evaluationId: evaluation.id, assetId: evaluation.assetId, status: "started" });

      runEvaluation(evaluation.id, parsed.data);
    } catch (error) {
      console.error("Error starting evaluation:", error);
      res.status(500).json({ error: "Failed to start evaluation" });
    }
  });

  app.get("/api/aev/evaluations", async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const evaluations = await storage.getEvaluations(organizationId);
      
      const evaluationsWithResults = await Promise.all(
        evaluations.map(async (evaluation) => {
          const result = await storage.getResultByEvaluationId(evaluation.id);
          return {
            ...evaluation,
            exploitable: result?.exploitable,
            score: result?.score,
            confidence: result?.confidence ? result.confidence / 100 : undefined,
            intelligentScore: result?.intelligentScore,
          };
        })
      );
      
      res.json(evaluationsWithResults);
    } catch (error) {
      console.error("Error fetching evaluations:", error);
      res.status(500).json({ error: "Failed to fetch evaluations" });
    }
  });

  app.get("/api/aev/evaluations/:id", async (req, res) => {
    try {
      const evaluation = await storage.getEvaluation(req.params.id);
      if (!evaluation) {
        return res.status(404).json({ error: "Evaluation not found" });
      }

      const result = await storage.getResultByEvaluationId(evaluation.id);
      
      res.json({
        ...evaluation,
        exploitable: result?.exploitable,
        score: result?.score,
        confidence: result?.confidence ? result.confidence / 100 : undefined,
        attackPath: result?.attackPath,
        attackGraph: result?.attackGraph,
        businessLogicFindings: result?.businessLogicFindings,
        multiVectorFindings: result?.multiVectorFindings,
        workflowAnalysis: result?.workflowAnalysis,
        recommendations: result?.recommendations,
        impact: result?.impact,
        evidenceArtifacts: result?.evidenceArtifacts,
        intelligentScore: result?.intelligentScore,
        remediationGuidance: result?.remediationGuidance,
        duration: result?.duration,
      });
    } catch (error) {
      console.error("Error fetching evaluation:", error);
      res.status(500).json({ error: "Failed to fetch evaluation" });
    }
  });

  app.delete("/api/aev/evaluations/:id", async (req, res) => {
    try {
      const evaluationId = req.params.id;
      const evaluation = await storage.getEvaluation(evaluationId);
      
      if (!evaluation) {
        return res.status(404).json({ error: "Evaluation not found" });
      }

      await storage.deleteResult(evaluationId);
      await storage.deleteEvaluation(evaluationId);
      
      res.json({ success: true, message: "Evaluation deleted successfully" });
    } catch (error) {
      console.error("Error deleting evaluation:", error);
      res.status(500).json({ error: "Failed to delete evaluation" });
    }
  });

  app.get("/api/aev/stats", async (req, res) => {
    try {
      const evaluations = await storage.getEvaluations();
      const resultsPromises = evaluations.map(e => storage.getResultByEvaluationId(e.id));
      const results = await Promise.all(resultsPromises);
      
      const completedResults = results.filter(r => r !== undefined);
      const exploitableCount = completedResults.filter(r => r?.exploitable).length;
      const safeCount = completedResults.filter(r => r && !r.exploitable).length;
      
      const avgConfidence = completedResults.length > 0
        ? Math.round(completedResults.reduce((sum, r) => sum + (r?.confidence || 0), 0) / completedResults.length)
        : 0;

      res.json({
        total: evaluations.length,
        active: evaluations.filter(e => e.status === "pending" || e.status === "in_progress").length,
        completed: evaluations.filter(e => e.status === "completed").length,
        exploitable: exploitableCount,
        safe: safeCount,
        avgConfidence,
      });
    } catch (error) {
      console.error("Error fetching stats:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  return httpServer;
}

async function runEvaluation(evaluationId: string, data: {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
}) {
  const startTime = Date.now();
  
  try {
    await storage.updateEvaluationStatus(evaluationId, "in_progress");

    const result = await runAgentOrchestrator(
      data.assetId,
      data.exposureType,
      data.priority,
      data.description,
      evaluationId,
      (agentName, stage, progress, message) => {
        wsService.sendProgress(evaluationId, agentName, stage, progress, message);
      }
    );

    const duration = Date.now() - startTime;

    await storage.createResult({
      id: `res-${randomUUID().slice(0, 8)}`,
      evaluationId,
      exploitable: result.exploitable,
      confidence: result.confidence,
      score: result.score,
      attackPath: result.attackPath,
      attackGraph: result.attackGraph,
      businessLogicFindings: result.businessLogicFindings,
      multiVectorFindings: result.multiVectorFindings,
      workflowAnalysis: result.workflowAnalysis,
      impact: result.impact,
      recommendations: result.recommendations,
      evidenceArtifacts: result.evidenceArtifacts,
      intelligentScore: result.intelligentScore,
      remediationGuidance: result.remediationGuidance,
      duration,
    });

    await storage.updateEvaluationStatus(evaluationId, "completed");
    wsService.sendComplete(evaluationId, true);
  } catch (error) {
    console.error("Evaluation failed:", error);
    await storage.updateEvaluationStatus(evaluationId, "failed");
    wsService.sendComplete(evaluationId, false, String(error));
  }
}
