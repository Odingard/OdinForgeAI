import { 
  type User, 
  type InsertUser, 
  type Evaluation, 
  type InsertEvaluation,
  type Result,
  type InsertResult,
  type Report,
  type InsertReport,
  type BatchJob,
  type InsertBatchJob,
  type ScheduledScan,
  type InsertScheduledScan,
  users,
  aevEvaluations,
  aevResults,
  reports,
  batchJobs,
  scheduledScans,
  evaluationHistory,
} from "@shared/schema";
import { randomUUID } from "crypto";
import { db } from "./db";
import { eq, desc, and, gte, lte, sql } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // AEV Evaluation operations
  createEvaluation(data: InsertEvaluation): Promise<Evaluation>;
  getEvaluation(id: string): Promise<Evaluation | undefined>;
  getEvaluations(organizationId?: string): Promise<Evaluation[]>;
  getEvaluationsByDateRange(from: Date, to: Date, organizationId?: string): Promise<Evaluation[]>;
  updateEvaluationStatus(id: string, status: string): Promise<void>;
  
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

  async updateEvaluationStatus(id: string, status: string): Promise<void> {
    await db
      .update(aevEvaluations)
      .set({ status, updatedAt: new Date() })
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
}

export const storage = new DatabaseStorage();
