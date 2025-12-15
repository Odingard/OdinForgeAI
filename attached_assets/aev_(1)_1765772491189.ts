import { Hono } from "hono";
import { z } from "zod";
import { aevService, ExposureInput } from "../services/aev";
import { logger } from "../logger";
import { AuthContext } from "../middleware/auth";
import { createAuditLog, getClientInfo } from "../services/audit";

const aevRouter = new Hono<{ Variables: { auth: AuthContext } }>();

const EvaluateSchema = z.object({
  assetId: z.string().min(1, "Asset ID is required"),
  exposureType: z.enum(["cve", "misconfiguration", "behavior", "network", "custom"]),
  description: z.string().min(1, "Description is required"),
  data: z.record(z.string(), z.any()).default({}),
  module: z.enum(["posture", "spear", "sentinel", "vulnmgmt"]).optional(),
  priority: z.enum(["low", "medium", "high", "critical"]).optional().default("medium"),
  evaluationId: z.string().optional(),
});

aevRouter.post("/evaluate", async (c) => {
  const auth = c.get("auth") as AuthContext;
  const clientInfo = getClientInfo(c);

  try {
    const body = await c.req.json();
    const parsed = EvaluateSchema.safeParse(body);

    if (!parsed.success) {
      return c.json(
        { error: "Validation failed", details: parsed.error.flatten() },
        400
      );
    }

    const input: ExposureInput = {
      ...parsed.data,
      organizationId: auth.organizationId,
    };

    logger.info({
      assetId: input.assetId,
      exposureType: input.exposureType,
      module: input.module,
      organizationId: auth.organizationId,
      userId: auth.userId,
    }, "Starting AEV evaluation");

    const evaluationId = aevService.startEvaluation(input, parsed.data.evaluationId);

    aevService.evaluate(input, evaluationId).then(async (result) => {
      await createAuditLog({
        organizationId: auth.organizationId,
        eventType: "security.aev",
        action: "evaluate",
        actor: auth.userId || "system",
        resource: "aev_evaluation",
        resourceId: result.evaluationId,
        details: { 
          assetId: input.assetId, 
          exposureType: input.exposureType,
          module: input.module,
          priority: input.priority,
        },
        status: "success",
        ...clientInfo,
      });
    }).catch(async (error) => {
      await createAuditLog({
        organizationId: auth.organizationId,
        eventType: "security.aev",
        action: "evaluate",
        actor: auth.userId || "system",
        resource: "aev_evaluation",
        resourceId: evaluationId,
        status: "failure",
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        ...clientInfo,
      });
      logger.error({ error: error instanceof Error ? error.message : "Unknown error" }, "AEV evaluation failed");
    });

    return c.json({ 
      evaluationId,
      status: "started",
      message: "Evaluation started. Subscribe to WebSocket for real-time progress.",
    });
  } catch (error) {
    await createAuditLog({
      organizationId: auth.organizationId,
      eventType: "security.aev",
      action: "evaluate",
      actor: auth.userId || "system",
      resource: "aev_evaluation",
      status: "failure",
      errorMessage: error instanceof Error ? error.message : "Unknown error",
      ...clientInfo,
    });
    
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    logger.error({ error: errorMessage }, "AEV evaluation request failed");
    return c.json({ error: "Evaluation failed", details: errorMessage }, 500);
  }
});

aevRouter.get("/evaluations", async (c) => {
  const auth = c.get("auth") as AuthContext;

  try {
    const evaluations = aevService.getEvaluationsByOrganization(auth.organizationId);

    return c.json({
      evaluations: evaluations.map((e) => ({
        id: e.id,
        assetId: e.input.assetId,
        exposureType: e.input.exposureType,
        module: e.input.module,
        priority: e.input.priority,
        status: e.status,
        result: e.result
          ? {
              exploitable: e.result.exploitable,
              confidence: e.result.confidence,
              score: e.result.score,
              status: e.result.status,
            }
          : null,
        createdAt: e.createdAt.toISOString(),
        updatedAt: e.updatedAt.toISOString(),
      })),
      total: evaluations.length,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    logger.error({ error: errorMessage }, "Failed to fetch evaluations");
    return c.json({ error: "Failed to fetch evaluations" }, 500);
  }
});

aevRouter.get("/evaluations/:id", async (c) => {
  const auth = c.get("auth") as AuthContext;
  const evaluationId = c.req.param("id");

  try {
    const evaluation = aevService.getEvaluation(evaluationId);

    if (!evaluation) {
      return c.json({ error: "Evaluation not found" }, 404);
    }

    if (evaluation.input.organizationId !== auth.organizationId) {
      return c.json({ error: "Access denied" }, 403);
    }

    return c.json({
      id: evaluation.id,
      input: {
        assetId: evaluation.input.assetId,
        exposureType: evaluation.input.exposureType,
        description: evaluation.input.description,
        module: evaluation.input.module,
        priority: evaluation.input.priority,
      },
      status: evaluation.status,
      result: evaluation.result,
      createdAt: evaluation.createdAt.toISOString(),
      updatedAt: evaluation.updatedAt.toISOString(),
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    logger.error({ error: errorMessage, evaluationId }, "Failed to fetch evaluation");
    return c.json({ error: "Failed to fetch evaluation" }, 500);
  }
});

aevRouter.get("/stats", async (c) => {
  const stats = aevService.getStats();
  return c.json(stats);
});

aevRouter.get("/results", async (c) => {
  const auth = c.get("auth") as AuthContext;

  try {
    const { 
      exploitable, 
      status, 
      taskId,
      limit = "50",
      offset = "0",
    } = c.req.query();

    const filters: { taskId?: string; exploitable?: boolean; status?: string } = {};
    if (taskId) filters.taskId = taskId;
    if (exploitable !== undefined) filters.exploitable = exploitable === "true";
    if (status) filters.status = status;

    const result = await aevService.getPersistedResults(
      auth.organizationId,
      filters,
      { limit: parseInt(limit), offset: parseInt(offset) }
    );

    return c.json(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    logger.error({ error: errorMessage }, "Failed to fetch persisted AEV results");
    return c.json({ error: "Failed to fetch AEV results" }, 500);
  }
});

aevRouter.get("/results/:evaluationId", async (c) => {
  const auth = c.get("auth") as AuthContext;
  const evaluationId = c.req.param("evaluationId");

  try {
    const result = await aevService.getPersistedResultByEvaluationId(auth.organizationId, evaluationId);

    if (!result) {
      return c.json({ error: "AEV result not found" }, 404);
    }

    return c.json(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    logger.error({ error: errorMessage, evaluationId }, "Failed to fetch persisted AEV result");
    return c.json({ error: "Failed to fetch AEV result" }, 500);
  }
});

aevRouter.post("/batch-evaluate", async (c) => {
  const auth = c.get("auth") as AuthContext;
  const clientInfo = getClientInfo(c);

  try {
    const body = await c.req.json();

    if (!Array.isArray(body.exposures)) {
      return c.json({ error: "exposures must be an array" }, 400);
    }

    if (body.exposures.length > 10) {
      return c.json({ error: "Maximum 10 exposures per batch" }, 400);
    }

    const evaluationIds: string[] = [];
    const errors: { index: number; error: string }[] = [];

    for (let i = 0; i < body.exposures.length; i++) {
      const exposure = body.exposures[i];
      const parsed = EvaluateSchema.safeParse(exposure);

      if (!parsed.success) {
        errors.push({ index: i, error: parsed.error.message });
        continue;
      }

      const input: ExposureInput = {
        ...parsed.data,
        organizationId: auth.organizationId,
      };

      const evaluationId = aevService.startEvaluation(input, parsed.data.evaluationId);
      
      aevService.evaluate(input, evaluationId).then((result) => {
        logger.info({ evaluationId: result.evaluationId }, "Batch evaluation completed");
      });

      evaluationIds.push(evaluationId);
    }

    await createAuditLog({
      organizationId: auth.organizationId,
      eventType: "security.aev",
      action: "evaluate",
      actor: auth.userId || "system",
      resource: "aev_batch_evaluation",
      details: { 
        batchSize: body.exposures.length,
        successCount: evaluationIds.length,
        errorCount: errors.length,
      },
      status: "success",
      ...clientInfo,
    });

    return c.json({
      message: "Batch evaluation started",
      evaluations: evaluationIds.length,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    await createAuditLog({
      organizationId: auth.organizationId,
      eventType: "security.aev",
      action: "evaluate",
      actor: auth.userId || "system",
      resource: "aev_batch_evaluation",
      status: "failure",
      errorMessage: error instanceof Error ? error.message : "Unknown error",
      ...clientInfo,
    });
    
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    logger.error({ error: errorMessage }, "Batch evaluation request failed");
    return c.json({ error: "Batch evaluation failed" }, 500);
  }
});

export { aevRouter };
