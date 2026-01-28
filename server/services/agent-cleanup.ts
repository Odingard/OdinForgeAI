import { storage } from "../storage";
import { db } from "../db";
import { endpointAgents, agentDeploymentJobs, agentRegistrationTokens } from "@shared/schema";
import { eq, and, lt, isNull, or, sql } from "drizzle-orm";
import { setTenantContext, clearTenantContext } from "./rls-setup";

export interface StaleAgent {
  id: string;
  agentName: string;
  hostname: string | null;
  platform: string | null;
  status: string | null;
  lastHeartbeat: Date | null;
  createdAt: Date;
  registeredAt: Date | null;
  reason: string;
}

export interface StaleDeploymentJob {
  id: string;
  cloudAssetId: string;
  status: string | null;
  deploymentMethod: string;
  createdAt: Date;
  updatedAt: Date;
  errorMessage: string | null;
  reason: string;
}

export interface CleanupResult {
  success: boolean;
  deletedAgents: number;
  deletedDeploymentJobs: number;
  deletedTokens: number;
  errors: string[];
}

export interface StaleResourcesSummary {
  staleAgents: StaleAgent[];
  staleDeploymentJobs: StaleDeploymentJob[];
  expiredTokens: number;
}

const STALE_THRESHOLDS = {
  AGENT_NEVER_CHECKED_IN_HOURS: 24,
  AGENT_NO_HEARTBEAT_HOURS: 72,
  DEPLOYMENT_STUCK_HOURS: 2,
  TOKEN_EXPIRED_HOURS: 1,
};

export const agentCleanupService = {
  async getStaleResources(organizationId: string): Promise<StaleResourcesSummary> {
    await setTenantContext(organizationId);
    try {
      const now = new Date();
      
      const neverCheckedInCutoff = new Date(now.getTime() - STALE_THRESHOLDS.AGENT_NEVER_CHECKED_IN_HOURS * 60 * 60 * 1000);
      const noHeartbeatCutoff = new Date(now.getTime() - STALE_THRESHOLDS.AGENT_NO_HEARTBEAT_HOURS * 60 * 60 * 1000);
      const deploymentStuckCutoff = new Date(now.getTime() - STALE_THRESHOLDS.DEPLOYMENT_STUCK_HOURS * 60 * 60 * 1000);
      // 1-hour grace period after token expiry before counting as "stale"
      const tokenExpiredCutoff = new Date(now.getTime() - STALE_THRESHOLDS.TOKEN_EXPIRED_HOURS * 60 * 60 * 1000);

      const staleAgents: StaleAgent[] = [];
      const staleDeploymentJobs: StaleDeploymentJob[] = [];

      const agents = await db
        .select()
        .from(endpointAgents)
        .where(eq(endpointAgents.organizationId, organizationId));

      for (const agent of agents) {
        if (agent.lastHeartbeat === null && agent.createdAt && agent.createdAt < neverCheckedInCutoff) {
          staleAgents.push({
            id: agent.id,
            agentName: agent.agentName,
            hostname: agent.hostname,
            platform: agent.platform,
            status: agent.status,
            lastHeartbeat: agent.lastHeartbeat,
            createdAt: agent.createdAt,
            registeredAt: agent.registeredAt,
            reason: `Never checked in (created ${Math.round((now.getTime() - agent.createdAt.getTime()) / 3600000)}h ago)`,
          });
        } else if (agent.lastHeartbeat && agent.lastHeartbeat < noHeartbeatCutoff) {
          staleAgents.push({
            id: agent.id,
            agentName: agent.agentName,
            hostname: agent.hostname,
            platform: agent.platform,
            status: agent.status,
            lastHeartbeat: agent.lastHeartbeat,
            createdAt: agent.createdAt!,
            registeredAt: agent.registeredAt,
            reason: `No heartbeat for ${Math.round((now.getTime() - agent.lastHeartbeat.getTime()) / 3600000)}h`,
          });
        }
      }

      const deploymentJobs = await db
        .select()
        .from(agentDeploymentJobs)
        .where(
          and(
            eq(agentDeploymentJobs.organizationId, organizationId),
            or(
              eq(agentDeploymentJobs.status, "pending"),
              eq(agentDeploymentJobs.status, "in_progress")
            )
          )
        );

      for (const job of deploymentJobs) {
        if (job.createdAt && job.createdAt < deploymentStuckCutoff) {
          staleDeploymentJobs.push({
            id: job.id,
            cloudAssetId: job.cloudAssetId,
            status: job.status,
            deploymentMethod: job.deploymentMethod,
            createdAt: job.createdAt,
            updatedAt: job.updatedAt!,
            errorMessage: job.errorMessage,
            reason: `Stuck in ${job.status} for ${Math.round((now.getTime() - job.createdAt.getTime()) / 3600000)}h`,
          });
        }
      }

      const expiredTokensResult = await db
        .select({ count: sql<number>`count(*)` })
        .from(agentRegistrationTokens)
        .where(
          and(
            eq(agentRegistrationTokens.organizationId, organizationId),
            lt(agentRegistrationTokens.expiresAt, tokenExpiredCutoff)
          )
        );
      
      const expiredTokens = expiredTokensResult[0]?.count || 0;

      return {
        staleAgents,
        staleDeploymentJobs,
        expiredTokens: Number(expiredTokens),
      };
    } finally {
      await clearTenantContext();
    }
  },

  async cleanupStaleResources(
    organizationId: string,
    options: {
      cleanAgents?: boolean;
      cleanDeploymentJobs?: boolean;
      cleanExpiredTokens?: boolean;
      agentIds?: string[];
      deploymentJobIds?: string[];
    } = {}
  ): Promise<CleanupResult> {
    const {
      cleanAgents = true,
      cleanDeploymentJobs = true,
      cleanExpiredTokens = true,
      agentIds,
      deploymentJobIds,
    } = options;

    const result: CleanupResult = {
      success: true,
      deletedAgents: 0,
      deletedDeploymentJobs: 0,
      deletedTokens: 0,
      errors: [],
    };

    await setTenantContext(organizationId);
    try {
      if (cleanAgents) {
        if (agentIds && agentIds.length > 0) {
          for (const agentId of agentIds) {
            try {
              await db
                .delete(endpointAgents)
                .where(
                  and(
                    eq(endpointAgents.id, agentId),
                    eq(endpointAgents.organizationId, organizationId)
                  )
                );
              result.deletedAgents++;
              console.log(`[AgentCleanup] Deleted agent ${agentId}`);
            } catch (err: any) {
              result.errors.push(`Failed to delete agent ${agentId}: ${err.message}`);
            }
          }
        } else {
          const staleData = await this.getStaleResources(organizationId);
          for (const agent of staleData.staleAgents) {
            try {
              await db
                .delete(endpointAgents)
                .where(
                  and(
                    eq(endpointAgents.id, agent.id),
                    eq(endpointAgents.organizationId, organizationId)
                  )
                );
              result.deletedAgents++;
              console.log(`[AgentCleanup] Deleted stale agent ${agent.id}: ${agent.reason}`);
            } catch (err: any) {
              result.errors.push(`Failed to delete agent ${agent.id}: ${err.message}`);
            }
          }
        }
      }

      if (cleanDeploymentJobs) {
        if (deploymentJobIds && deploymentJobIds.length > 0) {
          for (const jobId of deploymentJobIds) {
            try {
              await db
                .delete(agentDeploymentJobs)
                .where(
                  and(
                    eq(agentDeploymentJobs.id, jobId),
                    eq(agentDeploymentJobs.organizationId, organizationId)
                  )
                );
              result.deletedDeploymentJobs++;
              console.log(`[AgentCleanup] Deleted deployment job ${jobId}`);
            } catch (err: any) {
              result.errors.push(`Failed to delete deployment job ${jobId}: ${err.message}`);
            }
          }
        } else {
          const staleData = await this.getStaleResources(organizationId);
          for (const job of staleData.staleDeploymentJobs) {
            try {
              await db
                .delete(agentDeploymentJobs)
                .where(
                  and(
                    eq(agentDeploymentJobs.id, job.id),
                    eq(agentDeploymentJobs.organizationId, organizationId)
                  )
                );
              result.deletedDeploymentJobs++;
              console.log(`[AgentCleanup] Deleted stale deployment job ${job.id}: ${job.reason}`);
            } catch (err: any) {
              result.errors.push(`Failed to delete deployment job ${job.id}: ${err.message}`);
            }
          }
        }
      }

      if (cleanExpiredTokens) {
        try {
          // Use the same 1-hour grace period threshold as getStaleResources
          const tokenExpiredCutoff = new Date(Date.now() - STALE_THRESHOLDS.TOKEN_EXPIRED_HOURS * 60 * 60 * 1000);
          const deleteResult = await db
            .delete(agentRegistrationTokens)
            .where(
              and(
                eq(agentRegistrationTokens.organizationId, organizationId),
                lt(agentRegistrationTokens.expiresAt, tokenExpiredCutoff)
              )
            )
            .returning({ id: agentRegistrationTokens.id });
          
          result.deletedTokens = deleteResult.length;
          console.log(`[AgentCleanup] Deleted ${result.deletedTokens} expired registration tokens`);
        } catch (err: any) {
          result.errors.push(`Failed to delete expired tokens: ${err.message}`);
        }
      }

      if (result.errors.length > 0) {
        result.success = false;
      }

      console.log(`[AgentCleanup] Cleanup complete: ${result.deletedAgents} agents, ${result.deletedDeploymentJobs} deployment jobs, ${result.deletedTokens} tokens deleted`);
      
      return result;
    } catch (error: any) {
      console.error(`[AgentCleanup] Cleanup failed:`, error);
      return {
        success: false,
        deletedAgents: result.deletedAgents,
        deletedDeploymentJobs: result.deletedDeploymentJobs,
        deletedTokens: result.deletedTokens,
        errors: [...result.errors, error.message],
      };
    } finally {
      await clearTenantContext();
    }
  },

  async deleteAgent(organizationId: string, agentId: string): Promise<{ success: boolean; error?: string }> {
    await setTenantContext(organizationId);
    try {
      const deleteResult = await db
        .delete(endpointAgents)
        .where(
          and(
            eq(endpointAgents.id, agentId),
            eq(endpointAgents.organizationId, organizationId)
          )
        )
        .returning({ id: endpointAgents.id });
      
      if (deleteResult.length === 0) {
        return { success: false, error: "Agent not found or already deleted" };
      }
      
      console.log(`[AgentCleanup] Deleted agent ${agentId}`);
      return { success: true };
    } catch (error: any) {
      console.error(`[AgentCleanup] Failed to delete agent ${agentId}:`, error);
      return { success: false, error: error.message };
    } finally {
      await clearTenantContext();
    }
  },

  async retryDeployment(organizationId: string, deploymentJobId: string): Promise<{ success: boolean; error?: string }> {
    await setTenantContext(organizationId);
    try {
      const updateResult = await db
        .update(agentDeploymentJobs)
        .set({
          status: "pending",
          errorMessage: null,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(agentDeploymentJobs.id, deploymentJobId),
            eq(agentDeploymentJobs.organizationId, organizationId)
          )
        )
        .returning({ id: agentDeploymentJobs.id });
      
      if (updateResult.length === 0) {
        return { success: false, error: "Deployment job not found" };
      }
      
      console.log(`[AgentCleanup] Reset deployment job ${deploymentJobId} to pending for retry`);
      return { success: true };
    } catch (error: any) {
      console.error(`[AgentCleanup] Failed to retry deployment job ${deploymentJobId}:`, error);
      return { success: false, error: error.message };
    } finally {
      await clearTenantContext();
    }
  },
};
