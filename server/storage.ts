import { 
  type User, 
  type InsertUser, 
  type Evaluation, 
  type InsertEvaluation,
  type Result,
  type InsertResult,
  type Report,
  type InsertReport,
  type ReportNarrative,
  type InsertReportNarrative,
  type BatchJob,
  type InsertBatchJob,
  type ScheduledScan,
  type InsertScheduledScan,
  type OrganizationGovernance,
  type InsertOrganizationGovernance,
  type AuthorizationLog,
  type InsertAuthorizationLog,
  type ScopeRule,
  type InsertScopeRule,
  type AiAdversaryProfile,
  type InsertAiAdversaryProfile,
  type AttackPrediction,
  type InsertAttackPrediction,
  type DefensivePostureScore,
  type InsertDefensivePostureScore,
  type PurpleTeamFinding,
  type InsertPurpleTeamFinding,
  type AiSimulation,
  type InsertAiSimulation,
  type DiscoveredAsset,
  type InsertDiscoveredAsset,
  type VulnerabilityImport,
  type InsertVulnerabilityImport,
  type ImportJob,
  type InsertImportJob,
  type CloudConnection,
  type InsertCloudConnection,
  type EndpointAgent,
  type InsertEndpointAgent,
  type AgentTelemetry,
  type InsertAgentTelemetry,
  type AgentFinding,
  type InsertAgentFinding,
  type AgentCommand,
  type InsertAgentCommand,
  type UIRole,
  type InsertUIRole,
  type UIUser,
  type InsertUIUser,
  type UIRefreshToken,
  type InsertUIRefreshToken,
  type FullAssessment,
  type InsertFullAssessment,
  type SystemRoleId,
  systemRoleIds,
  uiRoles,
  users,
  aevEvaluations,
  aevResults,
  reports,
  reportNarratives,
  batchJobs,
  scheduledScans,
  evaluationHistory,
  organizationGovernance,
  authorizationLogs,
  scopeRules,
  aiAdversaryProfiles,
  attackPredictions,
  defensivePostureScores,
  purpleTeamFindings,
  aiSimulations,
  discoveredAssets,
  vulnerabilityImports,
  importJobs,
  cloudConnections,
  cloudCredentials,
  cloudDiscoveryJobs,
  cloudAssets,
  agentDeploymentJobs,
  endpointAgents,
  agentTelemetry,
  agentFindings,
  agentCommands,
  uiUsers,
  type CloudCredential,
  type InsertCloudCredential,
  type CloudDiscoveryJob,
  type InsertCloudDiscoveryJob,
  type CloudAsset,
  type InsertCloudAsset,
  type AgentDeploymentJob,
  type InsertAgentDeploymentJob,
  uiRefreshTokens,
  fullAssessments,
} from "@shared/schema";
import { randomUUID } from "crypto";
import { db } from "./db";
import { eq, desc, and, gte, lte, sql } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getAllUsers(organizationId?: string): Promise<User[]>;
  updateUser(id: string, updates: Partial<User>): Promise<void>;
  deleteUser(id: string): Promise<void>;
  
  // AEV Evaluation operations
  createEvaluation(data: InsertEvaluation): Promise<Evaluation>;
  getEvaluation(id: string): Promise<Evaluation | undefined>;
  getEvaluations(organizationId?: string): Promise<Evaluation[]>;
  getEvaluationsByDateRange(from: Date, to: Date, organizationId?: string): Promise<Evaluation[]>;
  updateEvaluationStatus(id: string, status: string, executionMode?: string): Promise<void>;
  
  // AEV Result operations
  createResult(data: InsertResult & { id: string }): Promise<Result>;
  getResultByEvaluationId(evaluationId: string): Promise<Result | undefined>;
  getResultsByEvaluationIds(evaluationIds: string[]): Promise<Result[]>;
  
  // Delete operations
  deleteEvaluation(id: string): Promise<void>;
  deleteResult(evaluationId: string): Promise<void>;
  
  // Report operations
  createReport(data: InsertReport): Promise<Report>;
  getReport(id: string): Promise<Report | undefined>;
  getReports(organizationId?: string): Promise<Report[]>;
  updateReport(id: string, updates: Partial<Report>): Promise<void>;
  deleteReport(id: string): Promise<void>;
  
  // Report Narrative operations (V2)
  createReportNarrative(data: InsertReportNarrative & { id: string }): Promise<ReportNarrative>;
  getReportNarrative(id: string): Promise<ReportNarrative | undefined>;
  getReportNarrativeByEvaluationId(evaluationId: string): Promise<ReportNarrative | undefined>;
  getReportNarratives(organizationId?: string): Promise<ReportNarrative[]>;
  
  // Batch Job operations
  createBatchJob(data: InsertBatchJob): Promise<BatchJob>;
  getBatchJob(id: string): Promise<BatchJob | undefined>;
  getBatchJobs(organizationId?: string): Promise<BatchJob[]>;
  updateBatchJob(id: string, updates: Partial<BatchJob>): Promise<void>;
  deleteBatchJob(id: string): Promise<void>;
  
  // Scheduled Scan operations
  createScheduledScan(data: InsertScheduledScan): Promise<ScheduledScan>;
  getScheduledScan(id: string): Promise<ScheduledScan | undefined>;
  getScheduledScans(organizationId?: string): Promise<ScheduledScan[]>;
  updateScheduledScan(id: string, updates: Partial<ScheduledScan>): Promise<void>;
  deleteScheduledScan(id: string): Promise<void>;
  
  // Full Assessment operations
  createFullAssessment(data: InsertFullAssessment): Promise<FullAssessment>;
  getFullAssessment(id: string): Promise<FullAssessment | undefined>;
  getFullAssessments(organizationId?: string): Promise<FullAssessment[]>;
  updateFullAssessment(id: string, updates: Partial<FullAssessment>): Promise<void>;
  deleteFullAssessment(id: string): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const [user] = await db.insert(users).values({ ...insertUser, id }).returning();
    return user;
  }

  async getAllUsers(organizationId?: string): Promise<User[]> {
    return db.select().from(users).orderBy(desc(users.createdAt));
  }

  async updateUser(id: string, updates: Partial<User>): Promise<void> {
    await db.update(users).set(updates).where(eq(users.id, id));
  }

  async deleteUser(id: string): Promise<void> {
    await db.delete(users).where(eq(users.id, id));
  }

  // AEV Evaluation operations
  async createEvaluation(data: InsertEvaluation): Promise<Evaluation> {
    const id = `aev-${randomUUID().slice(0, 8)}`;
    const [evaluation] = await db
      .insert(aevEvaluations)
      .values({ ...data, id })
      .returning();
    return evaluation;
  }

  async getEvaluation(id: string): Promise<Evaluation | undefined> {
    const [evaluation] = await db
      .select()
      .from(aevEvaluations)
      .where(eq(aevEvaluations.id, id));
    return evaluation;
  }

  async getEvaluations(organizationId?: string): Promise<Evaluation[]> {
    if (organizationId) {
      return db
        .select()
        .from(aevEvaluations)
        .where(eq(aevEvaluations.organizationId, organizationId))
        .orderBy(desc(aevEvaluations.createdAt));
    }
    return db.select().from(aevEvaluations).orderBy(desc(aevEvaluations.createdAt));
  }

  async updateEvaluationStatus(id: string, status: string, executionMode?: string): Promise<void> {
    const updates: Record<string, any> = { status, updatedAt: new Date() };
    if (executionMode) {
      updates.executionMode = executionMode;
    }
    await db
      .update(aevEvaluations)
      .set(updates)
      .where(eq(aevEvaluations.id, id));
  }

  // AEV Result operations
  async createResult(data: InsertResult & { id: string }): Promise<Result> {
    const [result] = await db
      .insert(aevResults)
      .values({ 
        ...data, 
        completedAt: new Date() 
      } as typeof aevResults.$inferInsert)
      .returning();
    return result;
  }

  async getResultByEvaluationId(evaluationId: string): Promise<Result | undefined> {
    const [result] = await db
      .select()
      .from(aevResults)
      .where(eq(aevResults.evaluationId, evaluationId));
    return result;
  }

  async deleteEvaluation(id: string): Promise<void> {
    await db.delete(aevEvaluations).where(eq(aevEvaluations.id, id));
  }

  async deleteResult(evaluationId: string): Promise<void> {
    await db.delete(aevResults).where(eq(aevResults.evaluationId, evaluationId));
  }

  async getEvaluationsByDateRange(from: Date, to: Date, organizationId?: string): Promise<Evaluation[]> {
    if (organizationId) {
      return db
        .select()
        .from(aevEvaluations)
        .where(and(
          eq(aevEvaluations.organizationId, organizationId),
          gte(aevEvaluations.createdAt, from),
          lte(aevEvaluations.createdAt, to)
        ))
        .orderBy(desc(aevEvaluations.createdAt));
    }
    return db
      .select()
      .from(aevEvaluations)
      .where(and(
        gte(aevEvaluations.createdAt, from),
        lte(aevEvaluations.createdAt, to)
      ))
      .orderBy(desc(aevEvaluations.createdAt));
  }

  async getResultsByEvaluationIds(evaluationIds: string[]): Promise<Result[]> {
    if (evaluationIds.length === 0) return [];
    const results = await Promise.all(
      evaluationIds.map(id => this.getResultByEvaluationId(id))
    );
    return results.filter((r): r is Result => r !== undefined);
  }

  // Report operations
  async createReport(data: InsertReport): Promise<Report> {
    const id = `rpt-${randomUUID().slice(0, 8)}`;
    const [report] = await db
      .insert(reports)
      .values({ ...data, id } as typeof reports.$inferInsert)
      .returning();
    return report;
  }

  async getReport(id: string): Promise<Report | undefined> {
    const [report] = await db
      .select()
      .from(reports)
      .where(eq(reports.id, id));
    return report;
  }

  async getReports(organizationId?: string): Promise<Report[]> {
    if (organizationId) {
      return db
        .select()
        .from(reports)
        .where(eq(reports.organizationId, organizationId))
        .orderBy(desc(reports.createdAt));
    }
    return db.select().from(reports).orderBy(desc(reports.createdAt));
  }

  async updateReport(id: string, updates: Partial<Report>): Promise<void> {
    await db
      .update(reports)
      .set(updates)
      .where(eq(reports.id, id));
  }

  async deleteReport(id: string): Promise<void> {
    await db.delete(reports).where(eq(reports.id, id));
  }

  // Report Narrative operations (V2)
  async createReportNarrative(data: InsertReportNarrative & { id: string }): Promise<ReportNarrative> {
    const [narrative] = await db
      .insert(reportNarratives)
      .values(data as typeof reportNarratives.$inferInsert)
      .returning();
    return narrative;
  }

  async getReportNarrative(id: string): Promise<ReportNarrative | undefined> {
    const [narrative] = await db
      .select()
      .from(reportNarratives)
      .where(eq(reportNarratives.id, id));
    return narrative;
  }

  async getReportNarrativeByEvaluationId(evaluationId: string): Promise<ReportNarrative | undefined> {
    const [narrative] = await db
      .select()
      .from(reportNarratives)
      .where(eq(reportNarratives.evaluationId, evaluationId))
      .orderBy(desc(reportNarratives.createdAt))
      .limit(1);
    return narrative;
  }

  async getReportNarratives(organizationId?: string): Promise<ReportNarrative[]> {
    if (organizationId) {
      return db
        .select()
        .from(reportNarratives)
        .where(eq(reportNarratives.organizationId, organizationId))
        .orderBy(desc(reportNarratives.createdAt));
    }
    return db.select().from(reportNarratives).orderBy(desc(reportNarratives.createdAt));
  }

  // Batch Job operations
  async createBatchJob(data: InsertBatchJob & { totalEvaluations: number }): Promise<BatchJob> {
    const id = `batch-${randomUUID().slice(0, 8)}`;
    const [job] = await db
      .insert(batchJobs)
      .values({ ...data, id } as typeof batchJobs.$inferInsert)
      .returning();
    return job;
  }

  async getBatchJob(id: string): Promise<BatchJob | undefined> {
    const [job] = await db
      .select()
      .from(batchJobs)
      .where(eq(batchJobs.id, id));
    return job;
  }

  async getBatchJobs(organizationId?: string): Promise<BatchJob[]> {
    if (organizationId) {
      return db
        .select()
        .from(batchJobs)
        .where(eq(batchJobs.organizationId, organizationId))
        .orderBy(desc(batchJobs.createdAt));
    }
    return db.select().from(batchJobs).orderBy(desc(batchJobs.createdAt));
  }

  async updateBatchJob(id: string, updates: Partial<BatchJob>): Promise<void> {
    await db
      .update(batchJobs)
      .set(updates)
      .where(eq(batchJobs.id, id));
  }

  async deleteBatchJob(id: string): Promise<void> {
    await db.delete(batchJobs).where(eq(batchJobs.id, id));
  }

  // Scheduled Scan operations
  async createScheduledScan(data: InsertScheduledScan): Promise<ScheduledScan> {
    const id = `sched-${randomUUID().slice(0, 8)}`;
    const [scan] = await db
      .insert(scheduledScans)
      .values({ ...data, id } as typeof scheduledScans.$inferInsert)
      .returning();
    return scan;
  }

  async getScheduledScan(id: string): Promise<ScheduledScan | undefined> {
    const [scan] = await db
      .select()
      .from(scheduledScans)
      .where(eq(scheduledScans.id, id));
    return scan;
  }

  async getScheduledScans(organizationId?: string): Promise<ScheduledScan[]> {
    if (organizationId) {
      return db
        .select()
        .from(scheduledScans)
        .where(eq(scheduledScans.organizationId, organizationId))
        .orderBy(desc(scheduledScans.createdAt));
    }
    return db.select().from(scheduledScans).orderBy(desc(scheduledScans.createdAt));
  }

  async updateScheduledScan(id: string, updates: Partial<ScheduledScan>): Promise<void> {
    await db
      .update(scheduledScans)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(scheduledScans.id, id));
  }

  async deleteScheduledScan(id: string): Promise<void> {
    await db.delete(scheduledScans).where(eq(scheduledScans.id, id));
  }

  // ========== GOVERNANCE OPERATIONS ==========
  
  async getOrganizationGovernance(organizationId: string): Promise<OrganizationGovernance | undefined> {
    const [governance] = await db
      .select()
      .from(organizationGovernance)
      .where(eq(organizationGovernance.organizationId, organizationId));
    return governance;
  }

  async createOrganizationGovernance(data: InsertOrganizationGovernance): Promise<OrganizationGovernance> {
    const id = `gov-${randomUUID().slice(0, 8)}`;
    const [governance] = await db
      .insert(organizationGovernance)
      .values({ ...data, id } as typeof organizationGovernance.$inferInsert)
      .returning();
    return governance;
  }

  async updateOrganizationGovernance(organizationId: string, updates: Partial<OrganizationGovernance>): Promise<void> {
    await db
      .update(organizationGovernance)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(organizationGovernance.organizationId, organizationId));
  }

  async activateKillSwitch(organizationId: string, activatedBy: string): Promise<void> {
    await db
      .update(organizationGovernance)
      .set({ 
        killSwitchActive: true, 
        killSwitchActivatedAt: new Date(),
        killSwitchActivatedBy: activatedBy,
        updatedAt: new Date()
      })
      .where(eq(organizationGovernance.organizationId, organizationId));
  }

  async deactivateKillSwitch(organizationId: string): Promise<void> {
    await db
      .update(organizationGovernance)
      .set({ 
        killSwitchActive: false,
        killSwitchActivatedAt: null,
        killSwitchActivatedBy: null,
        updatedAt: new Date()
      })
      .where(eq(organizationGovernance.organizationId, organizationId));
  }

  // Authorization Log operations
  async createAuthorizationLog(data: InsertAuthorizationLog): Promise<AuthorizationLog> {
    const id = `log-${randomUUID().slice(0, 8)}`;
    const [log] = await db
      .insert(authorizationLogs)
      .values({ ...data, id } as typeof authorizationLogs.$inferInsert)
      .returning();
    return log;
  }

  async getAuthorizationLogs(organizationId: string, limit = 100): Promise<AuthorizationLog[]> {
    return db
      .select()
      .from(authorizationLogs)
      .where(eq(authorizationLogs.organizationId, organizationId))
      .orderBy(desc(authorizationLogs.createdAt))
      .limit(limit);
  }

  // Scope Rule operations
  async createScopeRule(data: InsertScopeRule): Promise<ScopeRule> {
    const id = `rule-${randomUUID().slice(0, 8)}`;
    const [rule] = await db
      .insert(scopeRules)
      .values({ ...data, id } as typeof scopeRules.$inferInsert)
      .returning();
    return rule;
  }

  async getScopeRules(organizationId: string): Promise<ScopeRule[]> {
    return db
      .select()
      .from(scopeRules)
      .where(eq(scopeRules.organizationId, organizationId))
      .orderBy(desc(scopeRules.priority));
  }

  async updateScopeRule(id: string, updates: Partial<ScopeRule>): Promise<void> {
    await db.update(scopeRules).set(updates).where(eq(scopeRules.id, id));
  }

  async deleteScopeRule(id: string): Promise<void> {
    await db.delete(scopeRules).where(eq(scopeRules.id, id));
  }

  // ========== ADVANCED AI OPERATIONS ==========

  // Adversary Profile operations
  async getAdversaryProfiles(): Promise<AiAdversaryProfile[]> {
    return db.select().from(aiAdversaryProfiles).orderBy(aiAdversaryProfiles.name);
  }

  async getAdversaryProfile(id: string): Promise<AiAdversaryProfile | undefined> {
    const [profile] = await db
      .select()
      .from(aiAdversaryProfiles)
      .where(eq(aiAdversaryProfiles.id, id));
    return profile;
  }

  async createAdversaryProfile(data: InsertAiAdversaryProfile): Promise<AiAdversaryProfile> {
    const id = `adv-${randomUUID().slice(0, 8)}`;
    const [profile] = await db
      .insert(aiAdversaryProfiles)
      .values({ ...data, id } as typeof aiAdversaryProfiles.$inferInsert)
      .returning();
    return profile;
  }

  // Attack Prediction operations
  async createAttackPrediction(data: InsertAttackPrediction): Promise<AttackPrediction> {
    const id = `pred-${randomUUID().slice(0, 8)}`;
    const [prediction] = await db
      .insert(attackPredictions)
      .values({ ...data, id } as typeof attackPredictions.$inferInsert)
      .returning();
    return prediction;
  }

  async getAttackPredictions(organizationId: string): Promise<AttackPrediction[]> {
    return db
      .select()
      .from(attackPredictions)
      .where(eq(attackPredictions.organizationId, organizationId))
      .orderBy(desc(attackPredictions.createdAt));
  }

  // Defensive Posture operations
  async createDefensivePostureScore(data: InsertDefensivePostureScore): Promise<DefensivePostureScore> {
    const id = `posture-${randomUUID().slice(0, 8)}`;
    const [score] = await db
      .insert(defensivePostureScores)
      .values({ ...data, id } as typeof defensivePostureScores.$inferInsert)
      .returning();
    return score;
  }

  async getLatestDefensivePosture(organizationId: string): Promise<DefensivePostureScore | undefined> {
    const [score] = await db
      .select()
      .from(defensivePostureScores)
      .where(eq(defensivePostureScores.organizationId, organizationId))
      .orderBy(desc(defensivePostureScores.calculatedAt))
      .limit(1);
    return score;
  }

  async getDefensivePostureHistory(organizationId: string, limit = 30): Promise<DefensivePostureScore[]> {
    return db
      .select()
      .from(defensivePostureScores)
      .where(eq(defensivePostureScores.organizationId, organizationId))
      .orderBy(desc(defensivePostureScores.calculatedAt))
      .limit(limit);
  }

  // Purple Team Finding operations
  async createPurpleTeamFinding(data: InsertPurpleTeamFinding): Promise<PurpleTeamFinding> {
    const id = `purple-${randomUUID().slice(0, 8)}`;
    const [finding] = await db
      .insert(purpleTeamFindings)
      .values({ ...data, id } as typeof purpleTeamFindings.$inferInsert)
      .returning();
    return finding;
  }

  async getPurpleTeamFindings(organizationId: string): Promise<PurpleTeamFinding[]> {
    return db
      .select()
      .from(purpleTeamFindings)
      .where(eq(purpleTeamFindings.organizationId, organizationId))
      .orderBy(desc(purpleTeamFindings.createdAt));
  }

  async updatePurpleTeamFinding(id: string, updates: Partial<PurpleTeamFinding>): Promise<void> {
    await db.update(purpleTeamFindings).set(updates).where(eq(purpleTeamFindings.id, id));
  }

  // AI Simulation operations
  async createAiSimulation(data: InsertAiSimulation): Promise<AiSimulation> {
    const id = `sim-${randomUUID().slice(0, 8)}`;
    const [simulation] = await db
      .insert(aiSimulations)
      .values({ ...data, id } as typeof aiSimulations.$inferInsert)
      .returning();
    return simulation;
  }

  async getAiSimulation(id: string): Promise<AiSimulation | undefined> {
    const [simulation] = await db
      .select()
      .from(aiSimulations)
      .where(eq(aiSimulations.id, id));
    return simulation;
  }

  async getAiSimulations(organizationId: string): Promise<AiSimulation[]> {
    return db
      .select()
      .from(aiSimulations)
      .where(eq(aiSimulations.organizationId, organizationId))
      .orderBy(desc(aiSimulations.createdAt));
  }

  async updateAiSimulation(id: string, updates: Partial<AiSimulation>): Promise<void> {
    await db.update(aiSimulations).set(updates).where(eq(aiSimulations.id, id));
  }

  async deleteAiSimulation(id: string): Promise<void> {
    await db.delete(aiSimulations).where(eq(aiSimulations.id, id));
  }

  async getAllAiSimulations(): Promise<AiSimulation[]> {
    return db
      .select()
      .from(aiSimulations)
      .orderBy(desc(aiSimulations.createdAt));
  }

  // ============================================
  // INFRASTRUCTURE DATA INGESTION OPERATIONS
  // ============================================

  // Discovered Asset operations
  async createDiscoveredAsset(data: InsertDiscoveredAsset): Promise<DiscoveredAsset> {
    const id = `asset-${randomUUID().slice(0, 8)}`;
    const [asset] = await db
      .insert(discoveredAssets)
      .values({ ...data, id } as typeof discoveredAssets.$inferInsert)
      .returning();
    return asset;
  }

  async createDiscoveredAssets(assets: InsertDiscoveredAsset[]): Promise<DiscoveredAsset[]> {
    if (assets.length === 0) return [];
    const assetsWithIds = assets.map(a => ({
      ...a,
      id: `asset-${randomUUID().slice(0, 8)}`,
    }));
    return db
      .insert(discoveredAssets)
      .values(assetsWithIds as Array<typeof discoveredAssets.$inferInsert>)
      .returning();
  }

  async getDiscoveredAsset(id: string): Promise<DiscoveredAsset | undefined> {
    const [asset] = await db
      .select()
      .from(discoveredAssets)
      .where(eq(discoveredAssets.id, id));
    return asset;
  }

  async getDiscoveredAssets(organizationId?: string): Promise<DiscoveredAsset[]> {
    if (organizationId) {
      return db
        .select()
        .from(discoveredAssets)
        .where(eq(discoveredAssets.organizationId, organizationId))
        .orderBy(desc(discoveredAssets.createdAt));
    }
    return db.select().from(discoveredAssets).orderBy(desc(discoveredAssets.createdAt));
  }

  async getDiscoveredAssetByIdentifier(assetIdentifier: string, organizationId?: string): Promise<DiscoveredAsset | undefined> {
    const conditions = organizationId 
      ? and(eq(discoveredAssets.assetIdentifier, assetIdentifier), eq(discoveredAssets.organizationId, organizationId))
      : eq(discoveredAssets.assetIdentifier, assetIdentifier);
    const [asset] = await db.select().from(discoveredAssets).where(conditions);
    return asset;
  }

  async updateDiscoveredAsset(id: string, updates: Partial<DiscoveredAsset>): Promise<void> {
    await db.update(discoveredAssets).set({ ...updates, updatedAt: new Date() }).where(eq(discoveredAssets.id, id));
  }

  async deleteDiscoveredAsset(id: string): Promise<void> {
    await db.delete(discoveredAssets).where(eq(discoveredAssets.id, id));
  }

  // Vulnerability Import operations
  async createVulnerabilityImport(data: InsertVulnerabilityImport): Promise<VulnerabilityImport> {
    const id = `vuln-${randomUUID().slice(0, 8)}`;
    const [vuln] = await db
      .insert(vulnerabilityImports)
      .values({ ...data, id } as typeof vulnerabilityImports.$inferInsert)
      .returning();
    return vuln;
  }

  async createVulnerabilityImports(vulns: InsertVulnerabilityImport[]): Promise<VulnerabilityImport[]> {
    if (vulns.length === 0) return [];
    const vulnsWithIds = vulns.map(v => ({
      ...v,
      id: `vuln-${randomUUID().slice(0, 8)}`,
    }));
    return db
      .insert(vulnerabilityImports)
      .values(vulnsWithIds as Array<typeof vulnerabilityImports.$inferInsert>)
      .returning();
  }

  async getVulnerabilityImport(id: string): Promise<VulnerabilityImport | undefined> {
    const [vuln] = await db
      .select()
      .from(vulnerabilityImports)
      .where(eq(vulnerabilityImports.id, id));
    return vuln;
  }

  async getVulnerabilityImports(organizationId?: string): Promise<VulnerabilityImport[]> {
    if (organizationId) {
      return db
        .select()
        .from(vulnerabilityImports)
        .where(eq(vulnerabilityImports.organizationId, organizationId))
        .orderBy(desc(vulnerabilityImports.createdAt));
    }
    return db.select().from(vulnerabilityImports).orderBy(desc(vulnerabilityImports.createdAt));
  }

  async getVulnerabilityImportsByJobId(importJobId: string): Promise<VulnerabilityImport[]> {
    return db
      .select()
      .from(vulnerabilityImports)
      .where(eq(vulnerabilityImports.importJobId, importJobId))
      .orderBy(desc(vulnerabilityImports.createdAt));
  }

  async getVulnerabilityImportsByAssetId(assetId: string): Promise<VulnerabilityImport[]> {
    return db
      .select()
      .from(vulnerabilityImports)
      .where(eq(vulnerabilityImports.assetId, assetId))
      .orderBy(desc(vulnerabilityImports.createdAt));
  }

  async updateVulnerabilityImport(id: string, updates: Partial<VulnerabilityImport>): Promise<void> {
    await db.update(vulnerabilityImports).set({ ...updates, updatedAt: new Date() }).where(eq(vulnerabilityImports.id, id));
  }

  async deleteVulnerabilityImport(id: string): Promise<void> {
    await db.delete(vulnerabilityImports).where(eq(vulnerabilityImports.id, id));
  }

  // Import Job operations
  async createImportJob(data: InsertImportJob): Promise<ImportJob> {
    const id = `import-${randomUUID().slice(0, 8)}`;
    const [job] = await db
      .insert(importJobs)
      .values({ ...data, id } as typeof importJobs.$inferInsert)
      .returning();
    return job;
  }

  async getImportJob(id: string): Promise<ImportJob | undefined> {
    const [job] = await db
      .select()
      .from(importJobs)
      .where(eq(importJobs.id, id));
    return job;
  }

  async getImportJobs(organizationId?: string): Promise<ImportJob[]> {
    if (organizationId) {
      return db
        .select()
        .from(importJobs)
        .where(eq(importJobs.organizationId, organizationId))
        .orderBy(desc(importJobs.createdAt));
    }
    return db.select().from(importJobs).orderBy(desc(importJobs.createdAt));
  }

  async updateImportJob(id: string, updates: Partial<ImportJob>): Promise<void> {
    await db.update(importJobs).set(updates).where(eq(importJobs.id, id));
  }

  async deleteImportJob(id: string): Promise<void> {
    await db.delete(vulnerabilityImports).where(eq(vulnerabilityImports.importJobId, id));
    await db.delete(importJobs).where(eq(importJobs.id, id));
  }

  // Cloud Connection operations
  async createCloudConnection(data: InsertCloudConnection): Promise<CloudConnection> {
    const id = `cloud-${randomUUID().slice(0, 8)}`;
    const [connection] = await db
      .insert(cloudConnections)
      .values({ ...data, id } as typeof cloudConnections.$inferInsert)
      .returning();
    return connection;
  }

  async getCloudConnection(id: string): Promise<CloudConnection | undefined> {
    const [connection] = await db
      .select()
      .from(cloudConnections)
      .where(eq(cloudConnections.id, id));
    return connection;
  }

  async getCloudConnections(organizationId?: string): Promise<CloudConnection[]> {
    if (organizationId) {
      return db
        .select()
        .from(cloudConnections)
        .where(eq(cloudConnections.organizationId, organizationId))
        .orderBy(desc(cloudConnections.createdAt));
    }
    return db.select().from(cloudConnections).orderBy(desc(cloudConnections.createdAt));
  }

  async updateCloudConnection(id: string, updates: Partial<CloudConnection>): Promise<void> {
    await db.update(cloudConnections).set({ ...updates, updatedAt: new Date() }).where(eq(cloudConnections.id, id));
  }

  async deleteCloudConnection(id: string): Promise<void> {
    await db.delete(agentDeploymentJobs).where(eq(agentDeploymentJobs.connectionId, id));
    await db.delete(cloudAssets).where(eq(cloudAssets.connectionId, id));
    await db.delete(cloudDiscoveryJobs).where(eq(cloudDiscoveryJobs.connectionId, id));
    await db.delete(cloudCredentials).where(eq(cloudCredentials.connectionId, id));
    await db.delete(cloudConnections).where(eq(cloudConnections.id, id));
  }

  // Cloud Credential operations
  async createCloudCredential(data: InsertCloudCredential): Promise<CloudCredential> {
    const id = `cred-${randomUUID().slice(0, 8)}`;
    const [credential] = await db
      .insert(cloudCredentials)
      .values({ ...data, id } as typeof cloudCredentials.$inferInsert)
      .returning();
    return credential;
  }

  async getCloudCredentialByConnectionId(connectionId: string): Promise<CloudCredential | undefined> {
    const [credential] = await db
      .select()
      .from(cloudCredentials)
      .where(eq(cloudCredentials.connectionId, connectionId));
    return credential;
  }

  async updateCloudCredential(id: string, updates: Partial<CloudCredential>): Promise<void> {
    await db.update(cloudCredentials).set({ ...updates, updatedAt: new Date() }).where(eq(cloudCredentials.id, id));
  }

  // Cloud Discovery Job operations
  async createCloudDiscoveryJob(data: InsertCloudDiscoveryJob): Promise<CloudDiscoveryJob> {
    const id = `disc-${randomUUID().slice(0, 8)}`;
    const [job] = await db
      .insert(cloudDiscoveryJobs)
      .values({ ...data, id } as typeof cloudDiscoveryJobs.$inferInsert)
      .returning();
    return job;
  }

  async getCloudDiscoveryJob(id: string): Promise<CloudDiscoveryJob | undefined> {
    const [job] = await db
      .select()
      .from(cloudDiscoveryJobs)
      .where(eq(cloudDiscoveryJobs.id, id));
    return job;
  }

  async getCloudDiscoveryJobs(connectionId: string): Promise<CloudDiscoveryJob[]> {
    return db
      .select()
      .from(cloudDiscoveryJobs)
      .where(eq(cloudDiscoveryJobs.connectionId, connectionId))
      .orderBy(desc(cloudDiscoveryJobs.createdAt));
  }

  async updateCloudDiscoveryJob(id: string, updates: Partial<CloudDiscoveryJob>): Promise<void> {
    await db.update(cloudDiscoveryJobs).set(updates).where(eq(cloudDiscoveryJobs.id, id));
  }

  // Cloud Asset operations
  async createCloudAsset(data: InsertCloudAsset): Promise<CloudAsset> {
    const id = `casset-${randomUUID().slice(0, 8)}`;
    const [asset] = await db
      .insert(cloudAssets)
      .values({ ...data, id } as typeof cloudAssets.$inferInsert)
      .returning();
    return asset;
  }

  async getCloudAsset(id: string): Promise<CloudAsset | undefined> {
    const [asset] = await db
      .select()
      .from(cloudAssets)
      .where(eq(cloudAssets.id, id));
    return asset;
  }

  async getCloudAssetByProviderId(connectionId: string, providerResourceId: string): Promise<CloudAsset | undefined> {
    const [asset] = await db
      .select()
      .from(cloudAssets)
      .where(and(
        eq(cloudAssets.connectionId, connectionId),
        eq(cloudAssets.providerResourceId, providerResourceId)
      ));
    return asset;
  }

  async getCloudAssetsByConnection(connectionId: string): Promise<CloudAsset[]> {
    return db
      .select()
      .from(cloudAssets)
      .where(eq(cloudAssets.connectionId, connectionId))
      .orderBy(desc(cloudAssets.lastSeenAt));
  }

  async getCloudAssets(organizationId?: string): Promise<CloudAsset[]> {
    if (organizationId) {
      return db
        .select()
        .from(cloudAssets)
        .where(eq(cloudAssets.organizationId, organizationId))
        .orderBy(desc(cloudAssets.lastSeenAt));
    }
    return db.select().from(cloudAssets).orderBy(desc(cloudAssets.lastSeenAt));
  }

  async updateCloudAsset(id: string, updates: Partial<CloudAsset>): Promise<void> {
    await db.update(cloudAssets).set({ ...updates, updatedAt: new Date() }).where(eq(cloudAssets.id, id));
  }

  // Agent Deployment Job operations
  async createAgentDeploymentJob(data: InsertAgentDeploymentJob): Promise<AgentDeploymentJob> {
    const id = `deploy-${randomUUID().slice(0, 8)}`;
    const [job] = await db
      .insert(agentDeploymentJobs)
      .values({ ...data, id } as typeof agentDeploymentJobs.$inferInsert)
      .returning();
    return job;
  }

  async getAgentDeploymentJob(id: string): Promise<AgentDeploymentJob | undefined> {
    const [job] = await db
      .select()
      .from(agentDeploymentJobs)
      .where(eq(agentDeploymentJobs.id, id));
    return job;
  }

  async getAgentDeploymentJobs(connectionId: string): Promise<AgentDeploymentJob[]> {
    return db
      .select()
      .from(agentDeploymentJobs)
      .where(eq(agentDeploymentJobs.connectionId, connectionId))
      .orderBy(desc(agentDeploymentJobs.createdAt));
  }

  async updateAgentDeploymentJob(id: string, updates: Partial<AgentDeploymentJob>): Promise<void> {
    await db.update(agentDeploymentJobs).set({ ...updates, updatedAt: new Date() }).where(eq(agentDeploymentJobs.id, id));
  }

  // Get asset and vulnerability counts for dashboard
  async getInfrastructureStats(organizationId?: string): Promise<{
    totalAssets: number;
    totalVulnerabilities: number;
    criticalVulns: number;
    highVulns: number;
    pendingImports: number;
    cloudConnections: number;
  }> {
    const orgFilter = organizationId ? eq(discoveredAssets.organizationId, organizationId) : sql`1=1`;
    const vulnOrgFilter = organizationId ? eq(vulnerabilityImports.organizationId, organizationId) : sql`1=1`;
    
    const [assetCount] = await db.select({ count: sql<number>`count(*)::int` }).from(discoveredAssets).where(orgFilter);
    const [vulnCount] = await db.select({ count: sql<number>`count(*)::int` }).from(vulnerabilityImports).where(vulnOrgFilter);
    const [criticalCount] = await db.select({ count: sql<number>`count(*)::int` }).from(vulnerabilityImports).where(and(vulnOrgFilter, eq(vulnerabilityImports.severity, "critical")));
    const [highCount] = await db.select({ count: sql<number>`count(*)::int` }).from(vulnerabilityImports).where(and(vulnOrgFilter, eq(vulnerabilityImports.severity, "high")));
    const [pendingCount] = await db.select({ count: sql<number>`count(*)::int` }).from(importJobs).where(eq(importJobs.status, "pending"));
    const [cloudCount] = await db.select({ count: sql<number>`count(*)::int` }).from(cloudConnections).where(eq(cloudConnections.status, "connected"));

    return {
      totalAssets: assetCount?.count || 0,
      totalVulnerabilities: vulnCount?.count || 0,
      criticalVulns: criticalCount?.count || 0,
      highVulns: highCount?.count || 0,
      pendingImports: pendingCount?.count || 0,
      cloudConnections: cloudCount?.count || 0,
    };
  }

  // ========== ENDPOINT AGENT OPERATIONS ==========
  
  // Endpoint Agent operations
  async createEndpointAgent(data: InsertEndpointAgent): Promise<EndpointAgent> {
    const id = `agent-${randomUUID().slice(0, 8)}`;
    const [agent] = await db
      .insert(endpointAgents)
      .values({ ...data, id } as typeof endpointAgents.$inferInsert)
      .returning();
    return agent;
  }

  async getEndpointAgent(id: string): Promise<EndpointAgent | undefined> {
    const [agent] = await db
      .select()
      .from(endpointAgents)
      .where(eq(endpointAgents.id, id));
    return agent;
  }

  async getEndpointAgentByApiKey(apiKey: string): Promise<EndpointAgent | undefined> {
    const [agent] = await db
      .select()
      .from(endpointAgents)
      .where(eq(endpointAgents.apiKey, apiKey));
    return agent;
  }

  async getEndpointAgents(organizationId?: string): Promise<EndpointAgent[]> {
    if (organizationId) {
      return db
        .select()
        .from(endpointAgents)
        .where(eq(endpointAgents.organizationId, organizationId))
        .orderBy(desc(endpointAgents.registeredAt));
    }
    return db.select().from(endpointAgents).orderBy(desc(endpointAgents.registeredAt));
  }

  async updateEndpointAgent(id: string, updates: Partial<EndpointAgent>): Promise<void> {
    await db.update(endpointAgents).set({ ...updates, updatedAt: new Date() }).where(eq(endpointAgents.id, id));
  }

  async deleteEndpointAgent(id: string): Promise<void> {
    await db.delete(agentFindings).where(eq(agentFindings.agentId, id));
    await db.delete(agentTelemetry).where(eq(agentTelemetry.agentId, id));
    await db.delete(endpointAgents).where(eq(endpointAgents.id, id));
  }

  async updateAgentHeartbeat(id: string): Promise<void> {
    await db.update(endpointAgents).set({ 
      lastHeartbeat: new Date(),
      status: "online",
      updatedAt: new Date()
    }).where(eq(endpointAgents.id, id));
  }

  // Agent Telemetry operations
  async createAgentTelemetry(data: InsertAgentTelemetry): Promise<AgentTelemetry> {
    const id = `tel-${randomUUID().slice(0, 8)}`;
    const [telemetry] = await db
      .insert(agentTelemetry)
      .values({ ...data, id } as typeof agentTelemetry.$inferInsert)
      .returning();
    
    await db.update(endpointAgents).set({ 
      lastTelemetry: new Date(),
      status: "online",
      updatedAt: new Date()
    }).where(eq(endpointAgents.id, data.agentId));
    
    return telemetry;
  }

  async getAgentTelemetry(agentId: string, limit: number = 100): Promise<AgentTelemetry[]> {
    return db
      .select()
      .from(agentTelemetry)
      .where(eq(agentTelemetry.agentId, agentId))
      .orderBy(desc(agentTelemetry.collectedAt))
      .limit(limit);
  }

  async getLatestAgentTelemetry(agentId: string): Promise<AgentTelemetry | undefined> {
    const [telemetry] = await db
      .select()
      .from(agentTelemetry)
      .where(eq(agentTelemetry.agentId, agentId))
      .orderBy(desc(agentTelemetry.collectedAt))
      .limit(1);
    return telemetry;
  }

  // Agent Finding operations
  async createAgentFinding(data: InsertAgentFinding): Promise<AgentFinding> {
    const id = `finding-${randomUUID().slice(0, 8)}`;
    const [finding] = await db
      .insert(agentFindings)
      .values({ ...data, id } as typeof agentFindings.$inferInsert)
      .returning();
    return finding;
  }

  async getAgentFinding(id: string): Promise<AgentFinding | undefined> {
    const [finding] = await db
      .select()
      .from(agentFindings)
      .where(eq(agentFindings.id, id));
    return finding;
  }

  async getAgentFindings(agentId?: string, organizationId?: string): Promise<AgentFinding[]> {
    if (agentId) {
      return db
        .select()
        .from(agentFindings)
        .where(eq(agentFindings.agentId, agentId))
        .orderBy(desc(agentFindings.detectedAt));
    }
    if (organizationId) {
      return db
        .select()
        .from(agentFindings)
        .where(eq(agentFindings.organizationId, organizationId))
        .orderBy(desc(agentFindings.detectedAt));
    }
    return db.select().from(agentFindings).orderBy(desc(agentFindings.detectedAt));
  }

  async getUnprocessedFindings(organizationId?: string): Promise<AgentFinding[]> {
    const baseQuery = db
      .select()
      .from(agentFindings)
      .where(and(
        eq(agentFindings.autoEvaluationTriggered, false),
        eq(agentFindings.status, "new")
      ))
      .orderBy(desc(agentFindings.detectedAt));
    return baseQuery;
  }

  async updateAgentFinding(id: string, updates: Partial<AgentFinding>): Promise<void> {
    await db.update(agentFindings).set({ ...updates, updatedAt: new Date() }).where(eq(agentFindings.id, id));
  }

  async deleteAgentFinding(id: string): Promise<void> {
    await db.delete(agentFindings).where(eq(agentFindings.id, id));
  }

  // Agent stats for dashboard
  async getAgentStats(organizationId?: string): Promise<{
    totalAgents: number;
    onlineAgents: number;
    offlineAgents: number;
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    newFindings: number;
  }> {
    const orgFilter = organizationId ? eq(endpointAgents.organizationId, organizationId) : sql`1=1`;
    const findingOrgFilter = organizationId ? eq(agentFindings.organizationId, organizationId) : sql`1=1`;
    
    const [totalAgents] = await db.select({ count: sql<number>`count(*)::int` }).from(endpointAgents).where(orgFilter);
    const [onlineAgents] = await db.select({ count: sql<number>`count(*)::int` }).from(endpointAgents).where(and(orgFilter, eq(endpointAgents.status, "online")));
    const [offlineAgents] = await db.select({ count: sql<number>`count(*)::int` }).from(endpointAgents).where(and(orgFilter, eq(endpointAgents.status, "offline")));
    const [totalFindings] = await db.select({ count: sql<number>`count(*)::int` }).from(agentFindings).where(findingOrgFilter);
    const [criticalFindings] = await db.select({ count: sql<number>`count(*)::int` }).from(agentFindings).where(and(findingOrgFilter, eq(agentFindings.severity, "critical")));
    const [highFindings] = await db.select({ count: sql<number>`count(*)::int` }).from(agentFindings).where(and(findingOrgFilter, eq(agentFindings.severity, "high")));
    const [newFindings] = await db.select({ count: sql<number>`count(*)::int` }).from(agentFindings).where(and(findingOrgFilter, eq(agentFindings.status, "new")));

    return {
      totalAgents: totalAgents?.count || 0,
      onlineAgents: onlineAgents?.count || 0,
      offlineAgents: offlineAgents?.count || 0,
      totalFindings: totalFindings?.count || 0,
      criticalFindings: criticalFindings?.count || 0,
      highFindings: highFindings?.count || 0,
      newFindings: newFindings?.count || 0,
    };
  }

  // Agent Command operations
  async createAgentCommand(data: InsertAgentCommand): Promise<AgentCommand> {
    const id = `cmd-${randomUUID().slice(0, 8)}`;
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // Expires in 10 minutes
    const [command] = await db
      .insert(agentCommands)
      .values({ ...data, id, expiresAt } as typeof agentCommands.$inferInsert)
      .returning();
    return command;
  }

  async getAgentCommand(id: string): Promise<AgentCommand | undefined> {
    const [command] = await db
      .select()
      .from(agentCommands)
      .where(eq(agentCommands.id, id));
    return command;
  }

  async getPendingAgentCommands(agentId: string): Promise<AgentCommand[]> {
    return db
      .select()
      .from(agentCommands)
      .where(and(
        eq(agentCommands.agentId, agentId),
        eq(agentCommands.status, "pending")
      ))
      .orderBy(desc(agentCommands.createdAt));
  }

  async updateAgentCommand(id: string, updates: Partial<AgentCommand>): Promise<void> {
    await db.update(agentCommands).set(updates).where(eq(agentCommands.id, id));
  }

  async acknowledgeAgentCommand(id: string): Promise<void> {
    await db.update(agentCommands).set({ 
      status: "acknowledged", 
      acknowledgedAt: new Date() 
    }).where(eq(agentCommands.id, id));
  }

  async completeAgentCommand(id: string, result?: Record<string, any>, errorMessage?: string): Promise<void> {
    await db.update(agentCommands).set({ 
      status: errorMessage ? "failed" : "executed", 
      executedAt: new Date(),
      result: result || null,
      errorMessage: errorMessage || null
    }).where(eq(agentCommands.id, id));
  }

  async expireOldCommands(): Promise<number> {
    const result = await db.update(agentCommands)
      .set({ status: "expired" })
      .where(and(
        eq(agentCommands.status, "pending"),
        lte(agentCommands.expiresAt, new Date())
      ))
      .returning();
    return result.length;
  }

  // ========== UI Role Operations ==========

  async createUIRole(data: InsertUIRole): Promise<UIRole> {
    const [role] = await db.insert(uiRoles).values(data).returning();
    return role;
  }

  async upsertUIRole(data: InsertUIRole): Promise<UIRole> {
    const existing = await this.getUIRole(data.id);
    if (existing) {
      if (existing.isSystemRole) {
        // System roles can only be seeded/refreshed by internal seedSystemRoles function
        // which always passes the same immutable config. External callers cannot modify.
        // Only update if this is the initial seed (internal call with isSystemRole: true)
        if (data.isSystemRole === true) {
          await db.update(uiRoles)
            .set({ ...data, updatedAt: new Date() })
            .where(eq(uiRoles.id, data.id));
          const [updated] = await db.select().from(uiRoles).where(eq(uiRoles.id, data.id));
          return updated;
        }
        // Reject external attempts to modify system roles
        return existing;
      }
      await db.update(uiRoles)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(uiRoles.id, data.id));
      const [updated] = await db.select().from(uiRoles).where(eq(uiRoles.id, data.id));
      return updated;
    }
    return this.createUIRole(data);
  }

  async getUIRole(id: string): Promise<UIRole | undefined> {
    const [role] = await db.select().from(uiRoles).where(eq(uiRoles.id, id));
    return role;
  }

  async getUIRoles(): Promise<UIRole[]> {
    return db.select().from(uiRoles).orderBy(uiRoles.hierarchyLevel);
  }

  async deleteUIRole(id: string): Promise<{ success: boolean; error?: string }> {
    const role = await this.getUIRole(id);
    if (!role) {
      return { success: false, error: "Role not found" };
    }
    if (role.isSystemRole) {
      return { success: false, error: "Cannot delete system roles" };
    }
    await db.delete(uiRoles).where(eq(uiRoles.id, id));
    return { success: true };
  }

  isSystemRoleId(id: string): boolean {
    return systemRoleIds.includes(id as SystemRoleId);
  }

  // ========== UI User Operations ==========
  
  async createUIUser(data: InsertUIUser): Promise<UIUser> {
    const id = `uiuser-${randomUUID().slice(0, 8)}`;
    const [user] = await db.insert(uiUsers).values({ ...data, id }).returning();
    return user;
  }

  async getUIUser(id: string): Promise<UIUser | undefined> {
    const [user] = await db.select().from(uiUsers).where(eq(uiUsers.id, id));
    return user;
  }

  async getUIUserByEmail(email: string, tenantId: string): Promise<UIUser | undefined> {
    const [user] = await db
      .select()
      .from(uiUsers)
      .where(and(eq(uiUsers.email, email), eq(uiUsers.tenantId, tenantId)));
    return user;
  }

  async getUIUsers(tenantId?: string): Promise<UIUser[]> {
    if (tenantId) {
      return db.select().from(uiUsers).where(eq(uiUsers.tenantId, tenantId)).orderBy(desc(uiUsers.createdAt));
    }
    return db.select().from(uiUsers).orderBy(desc(uiUsers.createdAt));
  }

  async updateUIUser(id: string, updates: Partial<UIUser>): Promise<void> {
    await db.update(uiUsers).set({ ...updates, updatedAt: new Date() }).where(eq(uiUsers.id, id));
  }

  async deleteUIUser(id: string): Promise<void> {
    await db.delete(uiUsers).where(eq(uiUsers.id, id));
  }

  async incrementUIUserTokenVersion(id: string): Promise<number> {
    const [result] = await db
      .update(uiUsers)
      .set({ 
        tokenVersion: sql`${uiUsers.tokenVersion} + 1`,
        updatedAt: new Date() 
      })
      .where(eq(uiUsers.id, id))
      .returning({ tokenVersion: uiUsers.tokenVersion });
    return result?.tokenVersion || 0;
  }

  async recordLoginAttempt(id: string, success: boolean): Promise<void> {
    if (success) {
      await db.update(uiUsers).set({
        failedLoginAttempts: 0,
        lastLoginAt: new Date(),
        lockedUntil: null,
        updatedAt: new Date(),
      }).where(eq(uiUsers.id, id));
    } else {
      const [user] = await db.select().from(uiUsers).where(eq(uiUsers.id, id));
      if (user) {
        const newAttempts = (user.failedLoginAttempts || 0) + 1;
        const updates: Partial<UIUser> = {
          failedLoginAttempts: newAttempts,
          updatedAt: new Date(),
        };
        if (newAttempts >= 5) {
          updates.status = "locked";
          updates.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 min lockout
        }
        await db.update(uiUsers).set(updates).where(eq(uiUsers.id, id));
      }
    }
  }

  // ========== UI Refresh Token Operations ==========

  async createUIRefreshToken(data: InsertUIRefreshToken): Promise<UIRefreshToken> {
    const id = `rt-${randomUUID().slice(0, 8)}`;
    const [token] = await db.insert(uiRefreshTokens).values({ ...data, id }).returning();
    return token;
  }

  async getUIRefreshToken(id: string): Promise<UIRefreshToken | undefined> {
    const [token] = await db.select().from(uiRefreshTokens).where(eq(uiRefreshTokens.id, id));
    return token;
  }

  async getUIRefreshTokenByHash(tokenHash: string): Promise<UIRefreshToken | undefined> {
    const [token] = await db
      .select()
      .from(uiRefreshTokens)
      .where(eq(uiRefreshTokens.tokenHash, tokenHash));
    return token;
  }

  async updateUIRefreshTokenLastUsed(id: string): Promise<void> {
    await db.update(uiRefreshTokens).set({ lastUsedAt: new Date() }).where(eq(uiRefreshTokens.id, id));
  }

  async revokeUIRefreshToken(id: string, reason: string): Promise<void> {
    await db.update(uiRefreshTokens).set({
      revokedAt: new Date(),
      revokedReason: reason,
    }).where(eq(uiRefreshTokens.id, id));
  }

  async revokeAllUIRefreshTokensForUser(userId: string): Promise<void> {
    await db.update(uiRefreshTokens).set({
      revokedAt: new Date(),
      revokedReason: "logout_all",
    }).where(eq(uiRefreshTokens.userId, userId));
  }

  async cleanupExpiredUIRefreshTokens(): Promise<number> {
    const result = await db.delete(uiRefreshTokens).where(
      lte(uiRefreshTokens.expiresAt, new Date())
    );
    return result.rowCount || 0;
  }

  // ========== Full Assessment Operations ==========

  async createFullAssessment(data: InsertFullAssessment): Promise<FullAssessment> {
    const id = `fa-${randomUUID().slice(0, 8)}`;
    const [assessment] = await db
      .insert(fullAssessments)
      .values({ ...data, id, startedAt: new Date() })
      .returning();
    return assessment;
  }

  async getFullAssessment(id: string): Promise<FullAssessment | undefined> {
    const [assessment] = await db
      .select()
      .from(fullAssessments)
      .where(eq(fullAssessments.id, id));
    return assessment;
  }

  async getFullAssessments(organizationId?: string): Promise<FullAssessment[]> {
    if (organizationId) {
      return db
        .select()
        .from(fullAssessments)
        .where(eq(fullAssessments.organizationId, organizationId))
        .orderBy(desc(fullAssessments.createdAt));
    }
    return db.select().from(fullAssessments).orderBy(desc(fullAssessments.createdAt));
  }

  async updateFullAssessment(id: string, updates: Partial<FullAssessment>): Promise<void> {
    await db
      .update(fullAssessments)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(fullAssessments.id, id));
  }

  async deleteFullAssessment(id: string): Promise<void> {
    await db.delete(fullAssessments).where(eq(fullAssessments.id, id));
  }
}

export const storage = new DatabaseStorage();
