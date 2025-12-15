import { sql } from "drizzle-orm";
import { pgTable, text, varchar, boolean, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// AEV Evaluations table
export const aevEvaluations = pgTable("aev_evaluations", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  assetId: varchar("asset_id").notNull(),
  exposureType: varchar("exposure_type").notNull(), // cve, misconfiguration, behavior, network, business_logic, api_abuse
  priority: varchar("priority").notNull().default("medium"), // critical, high, medium, low
  description: text("description").notNull(),
  status: varchar("status").notNull().default("pending"), // pending, in_progress, completed, failed
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Attack path step type
export const attackPathStepSchema = z.object({
  id: z.number(),
  title: z.string(),
  description: z.string(),
  technique: z.string().optional(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  discoveredBy: z.enum(["recon", "exploit", "lateral", "business-logic", "impact"]).optional(),
});

// Recommendation type
export const recommendationSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  priority: z.enum(["critical", "high", "medium", "low"]),
  type: z.enum(["remediation", "compensating", "preventive"]),
});

export type AttackPathStep = z.infer<typeof attackPathStepSchema>;
export type Recommendation = z.infer<typeof recommendationSchema>;

// MITRE ATT&CK Kill Chain Tactics
export const killChainTactics = [
  "reconnaissance",
  "resource-development", 
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact"
] as const;

export type KillChainTactic = typeof killChainTactics[number];

// Attack Graph Node - represents a state/position in the attack
export const attackNodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  description: z.string(),
  nodeType: z.enum(["entry", "pivot", "objective", "dead-end"]),
  tactic: z.enum(killChainTactics),
  compromiseLevel: z.enum(["none", "limited", "user", "admin", "system"]),
  assets: z.array(z.string()).optional(),
  discoveredBy: z.enum(["recon", "exploit", "lateral", "business-logic", "impact"]).optional(),
});

// Attack Graph Edge - represents a technique/transition between nodes
export const attackEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  technique: z.string(),
  techniqueId: z.string().optional(),
  description: z.string(),
  successProbability: z.number().min(0).max(100),
  complexity: z.enum(["trivial", "low", "medium", "high", "expert"]),
  timeEstimate: z.number(),
  prerequisites: z.array(z.string()).optional(),
  alternatives: z.array(z.string()).optional(),
  edgeType: z.enum(["primary", "alternative", "fallback"]),
  discoveredBy: z.enum(["recon", "exploit", "lateral", "business-logic", "impact"]).optional(),
});

// Complete Attack Graph structure
export const attackGraphSchema = z.object({
  nodes: z.array(attackNodeSchema),
  edges: z.array(attackEdgeSchema),
  entryNodeId: z.string(),
  objectiveNodeIds: z.array(z.string()),
  criticalPath: z.array(z.string()),
  alternativePaths: z.array(z.array(z.string())).optional(),
  killChainCoverage: z.array(z.enum(killChainTactics)),
  complexityScore: z.number().min(0).max(100),
  timeToCompromise: z.object({
    minimum: z.number(),
    expected: z.number(),
    maximum: z.number(),
    unit: z.enum(["minutes", "hours", "days"]),
  }),
  chainedExploits: z.array(z.object({
    name: z.string(),
    techniques: z.array(z.string()),
    combinedImpact: z.string(),
  })).optional(),
});

export type AttackNode = z.infer<typeof attackNodeSchema>;
export type AttackEdge = z.infer<typeof attackEdgeSchema>;
export type AttackGraph = z.infer<typeof attackGraphSchema>;

// AEV Results table
export const aevResults = pgTable("aev_results", {
  id: varchar("id").primaryKey(),
  evaluationId: varchar("evaluation_id").notNull(),
  exploitable: boolean("exploitable").notNull(),
  confidence: integer("confidence").notNull(), // 0-100
  score: integer("score").notNull(), // 0-100
  attackPath: jsonb("attack_path").$type<AttackPathStep[]>(),
  attackGraph: jsonb("attack_graph").$type<AttackGraph>(),
  impact: text("impact"),
  recommendations: jsonb("recommendations").$type<Recommendation[]>(),
  duration: integer("duration"), // milliseconds
  completedAt: timestamp("completed_at"),
});

export const insertEvaluationSchema = createInsertSchema(aevEvaluations).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertResultSchema = createInsertSchema(aevResults).omit({
  id: true,
  completedAt: true,
});

export type InsertEvaluation = z.infer<typeof insertEvaluationSchema>;
export type Evaluation = typeof aevEvaluations.$inferSelect;
export type InsertResult = z.infer<typeof insertResultSchema>;
export type Result = typeof aevResults.$inferSelect;
