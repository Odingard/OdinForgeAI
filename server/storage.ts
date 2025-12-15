import { 
  type User, 
  type InsertUser, 
  type Evaluation, 
  type InsertEvaluation,
  type Result,
  type InsertResult,
  users,
  aevEvaluations,
  aevResults
} from "@shared/schema";
import { randomUUID } from "crypto";
import { db } from "./db";
import { eq, desc } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // AEV Evaluation operations
  createEvaluation(data: InsertEvaluation): Promise<Evaluation>;
  getEvaluation(id: string): Promise<Evaluation | undefined>;
  getEvaluations(organizationId?: string): Promise<Evaluation[]>;
  updateEvaluationStatus(id: string, status: string): Promise<void>;
  
  // AEV Result operations
  createResult(data: InsertResult & { id: string }): Promise<Result>;
  getResultByEvaluationId(evaluationId: string): Promise<Result | undefined>;
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
      .values({ ...data, completedAt: new Date() })
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
}

export const storage = new DatabaseStorage();
