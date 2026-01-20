import cron from "node-cron";
import { db } from "../db";
import { cloudAssets, endpointAgents, agentDeploymentJobs, aevEvaluations, aevResults, discoveredAssets } from "@shared/schema";
import { eq, sql, notInArray, and, isNotNull, inArray } from "drizzle-orm";

let reconciliationTask: ReturnType<typeof cron.schedule> | null = null;

export interface ReconciliationResult {
  orphanedCloudAssetAgents: number;
  orphanedDeploymentJobs: number;
  orphanedEvaluations: number;
  orphanedResults: number;
  totalCleaned: number;
  timestamp: Date;
}

async function cleanOrphanedAgentReferences(): Promise<number> {
  const validAgentIds = await db
    .select({ id: endpointAgents.id })
    .from(endpointAgents);
  
  const validIds = validAgentIds.map(a => a.id);
  
  const orphanedAssets = await db
    .select({ id: cloudAssets.id })
    .from(cloudAssets)
    .where(isNotNull(cloudAssets.agentId));
  
  let affectedCount = 0;
  
  if (validIds.length === 0) {
    if (orphanedAssets.length > 0) {
      await db
        .update(cloudAssets)
        .set({
          agentId: null,
          agentInstalled: false,
          agentDeploymentStatus: null,
          agentDeploymentError: null,
          lastAgentDeploymentAttempt: null,
          updatedAt: new Date()
        })
        .where(isNotNull(cloudAssets.agentId));
      
      affectedCount = orphanedAssets.length;
    }
  } else {
    const orphanedWithInvalidAgent = await db
      .select({ id: cloudAssets.id })
      .from(cloudAssets)
      .where(
        and(
          isNotNull(cloudAssets.agentId),
          notInArray(cloudAssets.agentId, validIds)
        )
      );
    
    if (orphanedWithInvalidAgent.length > 0) {
      await db
        .update(cloudAssets)
        .set({
          agentId: null,
          agentInstalled: false,
          agentDeploymentStatus: null,
          agentDeploymentError: null,
          lastAgentDeploymentAttempt: null,
          updatedAt: new Date()
        })
        .where(
          and(
            isNotNull(cloudAssets.agentId),
            notInArray(cloudAssets.agentId, validIds)
          )
        );
      
      affectedCount = orphanedWithInvalidAgent.length;
    }
  }
  
  return affectedCount;
}

async function cleanOrphanedDeploymentJobs(): Promise<number> {
  const validAssetIds = await db
    .select({ id: cloudAssets.id })
    .from(cloudAssets);
  
  const validIds = validAssetIds.map(a => a.id);
  
  if (validIds.length === 0) {
    const allJobs = await db
      .select({ id: agentDeploymentJobs.id })
      .from(agentDeploymentJobs);
    
    if (allJobs.length > 0) {
      await db.delete(agentDeploymentJobs);
      return allJobs.length;
    }
    return 0;
  }
  
  const orphanedJobs = await db
    .select({ id: agentDeploymentJobs.id })
    .from(agentDeploymentJobs)
    .where(notInArray(agentDeploymentJobs.cloudAssetId, validIds));
  
  if (orphanedJobs.length > 0) {
    const orphanedIds = orphanedJobs.map(j => j.id);
    await db
      .delete(agentDeploymentJobs)
      .where(inArray(agentDeploymentJobs.id, orphanedIds));
    
    return orphanedJobs.length;
  }
  
  return 0;
}

async function cleanOrphanedEvaluations(): Promise<number> {
  const [cloudAssetIds, discoveredAssetIds] = await Promise.all([
    db.select({ id: cloudAssets.id }).from(cloudAssets),
    db.select({ id: discoveredAssets.id }).from(discoveredAssets)
  ]);
  
  const allValidAssetIds = [
    ...cloudAssetIds.map(a => a.id),
    ...discoveredAssetIds.map(a => a.id)
  ];
  
  if (allValidAssetIds.length === 0) {
    const allEvals = await db
      .select({ id: aevEvaluations.id })
      .from(aevEvaluations)
      .where(isNotNull(aevEvaluations.assetId));
    
    if (allEvals.length > 0) {
      await db
        .delete(aevEvaluations)
        .where(isNotNull(aevEvaluations.assetId));
      return allEvals.length;
    }
    return 0;
  }
  
  const orphanedEvals = await db
    .select({ id: aevEvaluations.id })
    .from(aevEvaluations)
    .where(
      and(
        isNotNull(aevEvaluations.assetId),
        notInArray(aevEvaluations.assetId, allValidAssetIds)
      )
    );
  
  if (orphanedEvals.length > 0) {
    const orphanedIds = orphanedEvals.map(e => e.id);
    await db
      .delete(aevEvaluations)
      .where(inArray(aevEvaluations.id, orphanedIds));
    
    return orphanedEvals.length;
  }
  
  return 0;
}

async function cleanOrphanedResults(): Promise<number> {
  const validEvalIds = await db
    .select({ id: aevEvaluations.id })
    .from(aevEvaluations);
  
  const validIds = validEvalIds.map(e => e.id);
  
  if (validIds.length === 0) {
    const allResults = await db
      .select({ id: aevResults.id })
      .from(aevResults);
    
    if (allResults.length > 0) {
      await db.delete(aevResults);
      return allResults.length;
    }
    return 0;
  }
  
  const orphanedResults = await db
    .select({ id: aevResults.id })
    .from(aevResults)
    .where(notInArray(aevResults.evaluationId, validIds));
  
  if (orphanedResults.length > 0) {
    const orphanedIds = orphanedResults.map(r => r.id);
    await db
      .delete(aevResults)
      .where(inArray(aevResults.id, orphanedIds));
    
    return orphanedResults.length;
  }
  
  return 0;
}

export async function runReconciliation(): Promise<ReconciliationResult> {
  console.log("[Data Reconciliation] Starting data cleanup...");
  
  const orphanedAgents = await cleanOrphanedAgentReferences();
  const orphanedJobs = await cleanOrphanedDeploymentJobs();
  const orphanedEvals = await cleanOrphanedEvaluations();
  const orphanedResults = await cleanOrphanedResults();
  
  const result: ReconciliationResult = {
    orphanedCloudAssetAgents: orphanedAgents,
    orphanedDeploymentJobs: orphanedJobs,
    orphanedEvaluations: orphanedEvals,
    orphanedResults: orphanedResults,
    totalCleaned: orphanedAgents + orphanedJobs + orphanedEvals + orphanedResults,
    timestamp: new Date()
  };
  
  if (result.totalCleaned > 0) {
    console.log(`[Data Reconciliation] Cleaned ${result.totalCleaned} orphaned records:`, {
      cloudAssetAgents: orphanedAgents,
      deploymentJobs: orphanedJobs,
      evaluations: orphanedEvals,
      results: orphanedResults
    });
  } else {
    console.log("[Data Reconciliation] No orphaned records found");
  }
  
  return result;
}

export function startReconciliationScheduler(): void {
  if (reconciliationTask) {
    console.log("[Data Reconciliation] Scheduler already running");
    return;
  }
  
  reconciliationTask = cron.schedule("0 3 * * *", async () => {
    try {
      await runReconciliation();
    } catch (error) {
      console.error("[Data Reconciliation] Scheduled cleanup failed:", error);
    }
  });
  
  console.log("[Data Reconciliation] Scheduler started - runs daily at 3:00 AM");
}

export function stopReconciliationScheduler(): void {
  if (reconciliationTask) {
    reconciliationTask.stop();
    reconciliationTask = null;
    console.log("[Data Reconciliation] Scheduler stopped");
  }
}
