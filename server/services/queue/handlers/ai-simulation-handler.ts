import { Job } from "bullmq";
import { storage } from "../../../storage";
import { runAISimulation, type AISimulationResult } from "../../agents/ai-simulation";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import { setTenantContext, clearTenantContext } from "../../rls-setup";
import {
  AiSimulationJobData,
  JobResult,
  JobProgress,
} from "../job-types";

interface AISimulationJob {
  id?: string;
  data: AiSimulationJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitSimulationProgress(
  tenantId: string,
  organizationId: string,
  simulationId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "ai_simulation_started") {
    console.log(`[AISimulation] ${simulationId}: Started ${event.scenario} simulation`);
  } else if (type === "ai_simulation_round") {
    console.log(`[AISimulation] ${simulationId}: Round ${event.round}/${event.totalRounds} - ${event.phase}`);
  } else if (type === "ai_simulation_completed") {
    console.log(`[AISimulation] ${simulationId}: Completed after ${event.rounds} rounds - ${event.winner}`);
  } else if (type === "ai_simulation_failed") {
    console.log(`[AISimulation] ${simulationId}: Failed - ${event.error}`);
  }

  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `simulation:${tenantId}:${organizationId}:${simulationId}`;
    
    if (type === "ai_simulation_round") {
      wsService.broadcastToChannel(channel, {
        type: "simulation_progress",
        simulationId,
        round: event.round,
        phase: event.phase,
        message: event.message,
      });
    } else if (type === "ai_simulation_completed") {
      wsService.broadcastToChannel(channel, {
        type: "simulation_progress",
        simulationId,
        round: event.rounds,
        phase: "analysis",
        message: `Simulation complete: ${event.winner} wins`,
      });
    }
  } catch {
  }
}

export async function handleAISimulationJob(
  job: Job<AiSimulationJobData> | AISimulationJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { simulationId, scenario, rounds = 3, tenantId, organizationId } = job.data;
  const jobId = job.id || simulationId;

  console.log(`[AISimulation] Starting ${scenario} simulation with ${rounds} rounds`);

  await setTenantContext(organizationId);

  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "ai_simulation",
    scenario
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[AISimulation] Blocked by governance: ${governanceCheck.reason}`);
    
    emitSimulationProgress(tenantId, organizationId, simulationId, {
      type: "ai_simulation_failed",
      error: `Operation blocked by governance controls: ${governanceCheck.reason}`,
    });
    
    try {
      await storage.updateAiSimulation(simulationId, { 
        status: "failed",
        results: { error: governanceCheck.reason, blockedByGovernance: true } as any
      });
    } catch {}
    
    return {
      success: false,
      error: governanceCheck.reason,
      metadata: {
        blockedByGovernance: true,
        reason: governanceCheck.reason,
      },
    };
  }

  await governanceEnforcement.logOperationStarted(organizationId, "ai_simulation", scenario);

  emitSimulationProgress(tenantId, organizationId, simulationId, {
    type: "ai_simulation_started",
    scenario,
    rounds,
  });

  try {
    let simulation = await storage.getAiSimulation(simulationId);
    
    if (!simulation) {
      simulation = await storage.createAiSimulation({
        organizationId,
        name: scenario,
        attackScenario: scenario,
        targetSystem: "default",
        status: "running",
      });
    } else {
      await storage.updateAiSimulation(simulationId, { status: "running" });
    }

    await job.updateProgress?.({
      percent: 10,
      stage: "initializing",
      message: "Initializing AI agents...",
    } as JobProgress);

    const onProgress = (phase: string, round: number, progress: number, message: string) => {
      job.updateProgress?.({
        percent: Math.min(99, progress),
        stage: phase,
        message: `Round ${round}: ${message}`,
      } as JobProgress);

      emitSimulationProgress(tenantId, organizationId, simulationId, {
        type: "ai_simulation_round",
        round,
        totalRounds: rounds,
        phase,
        message,
      });
    };

    const result: AISimulationResult = await runAISimulation(
      `asset-${simulationId}`,
      scenario,
      "high",
      `AI vs AI purple team simulation: ${scenario}`,
      `eval-${simulationId}`,
      rounds,
      onProgress
    );

    await storage.updateAiSimulation(simulationId, {
      status: "completed",
      results: {
        rounds: result.rounds || [],
        summary: result.executiveSummary || "Simulation completed",
        winner: result.winner,
        finalAttackScore: result.finalAttackScore,
        finalDefenseScore: result.finalDefenseScore,
        recommendations: result.recommendations || [],
      },
    });

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Simulation complete",
    } as JobProgress);

    emitSimulationProgress(tenantId, organizationId, simulationId, {
      type: "ai_simulation_completed",
      rounds: result.totalRounds,
      winner: result.winner,
      finalAttackScore: result.finalAttackScore,
      finalDefenseScore: result.finalDefenseScore,
      recommendationCount: result.recommendations?.length || 0,
    });

    return {
      success: true,
      data: {
        simulationId,
        scenario,
        rounds: result.totalRounds,
        winner: result.winner,
        finalAttackScore: result.finalAttackScore,
        finalDefenseScore: result.finalDefenseScore,
        recommendations: result.recommendations,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[AISimulation] Simulation failed:`, errorMessage);

    await storage.updateAiSimulation(simulationId, { status: "failed" }).catch(() => {});

    emitSimulationProgress(tenantId, organizationId, simulationId, {
      type: "ai_simulation_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  } finally {
    await clearTenantContext().catch((err) => console.error("[RLS] Failed to clear context:", err));
  }
}
