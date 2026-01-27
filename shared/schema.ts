import { sql } from "drizzle-orm";
import { pgTable, text, varchar, boolean, integer, timestamp, jsonb, customType } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Custom type for pgvector embeddings
const vector = customType<{ data: number[]; driverData: string }>({
  dataType() {
    return "vector(1536)";
  },
  toDriver(value: number[]): string {
    return `[${value.join(",")}]`;
  },
  fromDriver(value: string): number[] {
    // Parse "[0.1,0.2,...]" format
    return JSON.parse(value.replace(/^\[/, "[").replace(/\]$/, "]"));
  },
});

// ============================================================================
// OdinForge Role-Based Access Control (RBAC)
// Comprehensive 9-role model with granular permissions
// ============================================================================

// Platform Roles (System-Level) - Not customer assignable
export const platformRoles = ["platform_super_admin"] as const;
export type PlatformRole = typeof platformRoles[number];

// Organization Roles (Customer-Facing)
export const organizationRoles = [
  "organization_owner",      // Business & security ownership
  "security_administrator",  // Operational control
  "security_engineer",       // Hands-on technical work
  "security_analyst",        // Investigation & triage (read-only)
  "executive_viewer",        // Business risk visibility only
] as const;
export type OrganizationRole = typeof organizationRoles[number];

// Specialized Roles (Optional per tenant)
export const specializedRoles = [
  "compliance_officer",      // GRC, audit teams
  "automation_account",      // CI/CD pipelines, SOAR tools (API-only)
] as const;
export type SpecializedRole = typeof specializedRoles[number];

// Non-User Roles (System identities)
export const systemRoles = ["endpoint_agent"] as const;
export type SystemRole = typeof systemRoles[number];

// Combined user roles (all assignable roles)
export const userRoles = [
  ...platformRoles,
  ...organizationRoles,
  ...specializedRoles,
] as const;
export type UserRole = typeof userRoles[number];

// All roles including system
export const allRoles = [...userRoles, ...systemRoles] as const;
export type AllRole = typeof allRoles[number];

// Execution modes for evaluations
export const executionModes = ["safe", "simulation", "live"] as const;
export type ExecutionMode = typeof executionModes[number];

// Granular permissions for each module
export const permissions = [
  // Evaluations
  "evaluations:read",
  "evaluations:create",
  "evaluations:execute_safe",       // Run in safe mode
  "evaluations:execute_simulation", // Run in simulation mode
  "evaluations:execute_live",       // Run in live mode (requires approval)
  "evaluations:approve_live",       // Approve live execution
  "evaluations:delete",
  "evaluations:archive",
  
  // Assets
  "assets:read",
  "assets:create",
  "assets:update",
  "assets:delete",
  
  // Reports
  "reports:read",
  "reports:read_executive",         // Executive summaries only
  "reports:generate",
  "reports:export",
  "reports:delete",
  
  // Agents
  "agents:read",
  "agents:register",
  "agents:manage",
  "agents:revoke",
  "agents:delete",
  
  // Evidence & Findings
  "evidence:read",
  "evidence:read_sanitized",        // No raw exploit details
  "findings:read",
  "findings:triage",
  
  // Simulations
  "simulations:read",
  "simulations:run",
  "simulations:delete",
  
  // Governance & Audit
  "governance:read",
  "governance:manage",
  "audit:read",
  "audit:read_global",              // Cross-tenant audit (platform admin only)
  
  // Organization Management
  "org:read",
  "org:manage_settings",
  "org:manage_users",
  "org:assign_roles",
  
  // Platform Administration (Super Admin only)
  "platform:emergency_access",
  "platform:feature_flags",
  "platform:rate_limits",
  "platform:cross_tenant_access",
  
  // API Access
  "api:read",
  "api:write",
] as const;
export type Permission = typeof permissions[number];

// Role metadata for UI display and restrictions
export interface RoleMetadata {
  displayName: string;
  description: string;
  category: "platform" | "organization" | "specialized" | "system";
  requiresMFA: boolean;
  uiAccess: boolean;           // Can access web UI
  apiOnly: boolean;            // API-only access
  customerAssignable: boolean; // Can customers assign this role?
}

export const roleMetadata: Record<AllRole, RoleMetadata> = {
  platform_super_admin: {
    displayName: "Platform Super Admin",
    description: "Full platform operations & emergency control",
    category: "platform",
    requiresMFA: true,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: false,
  },
  organization_owner: {
    displayName: "Organization Owner",
    description: "Business & security ownership of organization",
    category: "organization",
    requiresMFA: true,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: true,
  },
  security_administrator: {
    displayName: "Security Administrator",
    description: "Operational control over security assessments",
    category: "organization",
    requiresMFA: false,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: true,
  },
  security_engineer: {
    displayName: "Security Engineer",
    description: "Hands-on technical security work",
    category: "organization",
    requiresMFA: false,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: true,
  },
  security_analyst: {
    displayName: "Security Analyst",
    description: "Investigation & triage of findings",
    category: "organization",
    requiresMFA: false,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: true,
  },
  executive_viewer: {
    displayName: "Executive Viewer",
    description: "Business risk visibility for leadership",
    category: "organization",
    requiresMFA: false,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: true,
  },
  compliance_officer: {
    displayName: "Compliance Officer",
    description: "GRC and audit oversight",
    category: "specialized",
    requiresMFA: false,
    uiAccess: true,
    apiOnly: false,
    customerAssignable: true,
  },
  automation_account: {
    displayName: "Automation Account",
    description: "CI/CD and SOAR integration",
    category: "specialized",
    requiresMFA: false,
    uiAccess: false,
    apiOnly: true,
    customerAssignable: true,
  },
  endpoint_agent: {
    displayName: "Endpoint Agent",
    description: "System identity for deployed agents",
    category: "system",
    requiresMFA: false,
    uiAccess: false,
    apiOnly: true,
    customerAssignable: false,
  },
};

// Role-permission mapping
export const rolePermissions: Record<UserRole, Permission[]> = {
  // Platform Super Admin - Full access
  platform_super_admin: [...permissions],
  
  // Organization Owner - Business & security ownership
  organization_owner: [
    "evaluations:read",
    "evaluations:create",
    "evaluations:execute_safe",
    "evaluations:execute_simulation",
    "evaluations:approve_live",
    "evaluations:delete",
    "evaluations:archive",
    "assets:read",
    "assets:create",
    "assets:update",
    "assets:delete",
    "reports:read",
    "reports:read_executive",
    "reports:generate",
    "reports:export",
    "reports:delete",
    "agents:read",
    "agents:register",
    "agents:manage",
    "agents:delete",
    "evidence:read",
    "findings:read",
    "findings:triage",
    "simulations:read",
    "simulations:run",
    "simulations:delete",
    "governance:read",
    "audit:read",
    "org:read",
    "org:manage_settings",
    "org:manage_users",
    "org:assign_roles",
    "api:read",
    "api:write",
  ],
  
  // Security Administrator - Operational control
  security_administrator: [
    "evaluations:read",
    "evaluations:create",
    "evaluations:execute_safe",
    "evaluations:execute_simulation",
    "evaluations:execute_live",
    "evaluations:archive",
    "evaluations:delete",
    "assets:read",
    "assets:create",
    "assets:update",
    "assets:delete",
    "reports:read",
    "reports:generate",
    "reports:export",
    "reports:delete",
    "agents:read",
    "agents:register",
    "agents:manage",
    "agents:delete",
    "evidence:read",
    "findings:read",
    "findings:triage",
    "simulations:read",
    "simulations:run",
    "simulations:delete",
    "governance:read",
    "governance:manage",
    "audit:read",
    "org:read",
    "api:read",
    "api:write",
  ],
  
  // Security Engineer - Technical work
  security_engineer: [
    "evaluations:read",
    "evaluations:create",
    "evaluations:execute_safe",
    "evaluations:execute_simulation",
    "assets:read",
    "assets:create",
    "reports:read",
    "reports:generate",
    "reports:export",
    "agents:read",
    "agents:register",
    "evidence:read",
    "findings:read",
    "simulations:read",
    "simulations:run",
    "simulations:delete",
    "governance:read",
    "api:read",
  ],
  
  // Security Analyst - Investigation & triage (read-heavy)
  security_analyst: [
    "evaluations:read",
    "assets:read",
    "reports:read",
    "reports:export",
    "agents:read",
    "evidence:read",
    "findings:read",
    "simulations:read",
    "governance:read",
    "api:read",
  ],
  
  // Executive Viewer - Business risk visibility (sanitized view)
  executive_viewer: [
    "evaluations:read",
    "assets:read",
    "reports:read",
    "reports:read_executive",
    "evidence:read_sanitized",
    "findings:read",
    "governance:read",
  ],
  
  // Compliance Officer - GRC oversight
  compliance_officer: [
    "evaluations:read",
    "assets:read",
    "reports:read",
    "reports:export",
    "evidence:read",
    "findings:read",
    "governance:read",
    "audit:read",
    "api:read",
  ],
  
  // Automation Account - API-only, scoped
  automation_account: [
    "evaluations:read",
    "evaluations:create",
    "evaluations:execute_safe",
    "evaluations:execute_simulation",
    "assets:read",
    "reports:read",
    "findings:read",
    "api:read",
    "api:write",
  ],
};

// Helper to check if role can execute in a specific mode
export function canExecuteMode(role: UserRole, mode: ExecutionMode): boolean {
  const perms = rolePermissions[role] || [];
  switch (mode) {
    case "safe":
      return perms.includes("evaluations:execute_safe");
    case "simulation":
      return perms.includes("evaluations:execute_simulation");
    case "live":
      return perms.includes("evaluations:execute_live");
    default:
      return false;
  }
}

// Helper to check if role needs sanitized evidence view
export function needsSanitizedView(role: UserRole): boolean {
  const perms = rolePermissions[role] || [];
  return perms.includes("evidence:read_sanitized") && !perms.includes("evidence:read");
}

// Helper to check if role is API-only
export function isApiOnlyRole(role: AllRole): boolean {
  return roleMetadata[role]?.apiOnly ?? false;
}

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  role: varchar("role").notNull().default("viewer"), // admin, analyst, viewer
  displayName: text("display_name"),
  email: text("email"),
  createdAt: timestamp("created_at").defaultNow(),
  lastLoginAt: timestamp("last_login_at"),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  role: true,
  displayName: true,
  email: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// ============================================================================
// MULTI-TENANT ISOLATION
// Core tenant management for organization separation
// ============================================================================

export const tenantStatuses = [
  "active",
  "suspended",
  "trial",
  "pending_verification",
  "deleted",
] as const;
export type TenantStatus = typeof tenantStatuses[number];

export const tenantTiers = [
  "free",
  "starter",
  "professional",
  "enterprise",
  "unlimited",
] as const;
export type TenantTier = typeof tenantTiers[number];

export const tenants = pgTable("tenants", {
  id: varchar("id").primaryKey(),
  
  // Tenant identification
  name: varchar("name").notNull(),
  slug: varchar("slug").notNull().unique(), // URL-safe identifier
  
  // Status and tier
  status: varchar("status").notNull().default("active"), // One of tenantStatuses
  tier: varchar("tier").notNull().default("starter"), // One of tenantTiers
  
  // Trial management
  trialEndsAt: timestamp("trial_ends_at"),
  
  // Feature limits (based on tier)
  maxUsers: integer("max_users").default(5),
  maxAgents: integer("max_agents").default(10),
  maxEvaluationsPerDay: integer("max_evaluations_per_day").default(100),
  maxConcurrentScans: integer("max_concurrent_scans").default(3),
  
  // Feature flags (tenant-specific overrides)
  features: jsonb("features").$type<{
    liveScanning?: boolean;
    cloudIntegration?: boolean;
    apiAccess?: boolean;
    customReports?: boolean;
    aiSimulations?: boolean;
    externalRecon?: boolean;
    complianceFrameworks?: string[];
  }>().default({}),
  
  // Security settings
  allowedIpRanges: jsonb("allowed_ip_ranges").$type<string[]>().default([]),
  enforceIpAllowlist: boolean("enforce_ip_allowlist").default(false),
  
  // Metadata
  billingEmail: varchar("billing_email"),
  technicalContact: varchar("technical_contact"),
  industry: varchar("industry"),
  
  // Parent tenant for hierarchical multi-tenancy
  parentTenantId: varchar("parent_tenant_id"),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  deletedAt: timestamp("deleted_at"),
});

export const insertTenantSchema = createInsertSchema(tenants).omit({
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
});

export type InsertTenant = z.infer<typeof insertTenantSchema>;
export type Tenant = typeof tenants.$inferSelect;

// Tenant context passed through request pipeline
export interface TenantContext {
  tenantId: string;
  organizationId: string;
  userId?: string;
  userRole?: UserRole;
  tier: TenantTier;
  features: Tenant["features"];
}

// Exposure Types - Multi-Vector Coverage
export const exposureTypes = [
  "cve",                    // CVE exploitation (safe mode)
  "misconfiguration",       // General misconfigurations
  "behavioral_anomaly",     // Behavioral anomalies
  "network_vulnerability",  // Network pivoting
  "cloud_misconfiguration", // Cloud misconfiguration chaining (AWS/GCP/Azure)
  "iam_abuse",              // IAM abuse paths
  "saas_permission",        // SaaS permission abuse
  "shadow_admin",           // Shadow admin discovery
  "api_sequence_abuse",     // API sequence/workflow abuse
  "payment_flow",           // Payment flow vulnerabilities
  "subscription_bypass",    // Subscription & billing bypass
  "state_machine",          // State machine violations
  "privilege_boundary",     // Privilege boundary violations
  "workflow_desync",        // Workflow desynchronization
  "order_lifecycle",        // Order lifecycle abuse
  "app_logic",              // Application logic flaws (IDOR/BOLA, mass assignment, rate limiting)
] as const;

// App Logic Exposure Data - Structured input for deterministic IDOR/BOLA/auth analysis
export interface AppLogicExposureData {
  endpoint?: string;              // e.g., "/api/users/{id}"
  method?: string;                // GET, POST, PUT, DELETE, PATCH
  authRequired?: boolean;         // Is authentication required?
  roleRequired?: string;          // e.g., "admin", "user", null
  pathParams?: string[];          // e.g., ["id", "userId"]
  objectIdParam?: string;         // Which param is the object ID? e.g., "id"
  ownershipEnforced?: boolean | null; // true=enforced, false=not enforced, null=unknown
  rateLimit?: "none" | "weak" | "strong" | null;
  sensitiveFields?: string[];     // Fields that could be mass-assigned, e.g., ["role", "isAdmin"]
  acceptsUserInput?: boolean;     // Does the endpoint accept user input in body?
}

export type ExposureType = typeof exposureTypes[number];

// Business Logic Vulnerability Categories
export const businessLogicCategories = [
  "payment_bypass",         // Skipping payment steps
  "subscription_abuse",     // Free tier abuse, trial extension
  "order_manipulation",     // Price manipulation, quantity abuse
  "state_transition",       // Invalid state jumps
  "privilege_escalation",   // Horizontal/vertical escalation
  "workflow_bypass",        // Skipping required steps
  "race_condition",         // TOCTOU, double-spend
  "parameter_tampering",    // Hidden field manipulation
  "session_abuse",          // Session fixation, replay
  "logic_flaw",             // General logic flaws
] as const;

export type BusinessLogicCategory = typeof businessLogicCategories[number];

// Cloud/IAM Vector Types
export const cloudVectorTypes = [
  "s3_public_bucket",
  "iam_role_chaining",
  "cross_account_access",
  "metadata_service_abuse",
  "lambda_privilege_escalation",
  "storage_account_exposure",
  "service_account_abuse",
  "federation_bypass",
  "permission_boundary_bypass",
  "resource_policy_abuse",
] as const;

export type CloudVectorType = typeof cloudVectorTypes[number];

// AEV Evaluations table
export const aevEvaluations = pgTable("aev_evaluations", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  assetId: varchar("asset_id").notNull(),
  exposureType: varchar("exposure_type").notNull(), // One of exposureTypes
  priority: varchar("priority").notNull().default("medium"), // critical, high, medium, low
  description: text("description").notNull(),
  adversaryProfile: varchar("adversary_profile"), // One of adversaryProfiles (optional)
  executionMode: varchar("execution_mode").default("safe"), // safe, live, simulation - tracks which governance mode was used
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

// Business Logic Vulnerability Finding
export const businessLogicFindingSchema = z.object({
  id: z.string(),
  category: z.enum(businessLogicCategories),
  title: z.string(),
  description: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  intendedWorkflow: z.array(z.string()),
  actualWorkflow: z.array(z.string()),
  stateViolations: z.array(z.object({
    fromState: z.string(),
    toState: z.string(),
    expectedTransitions: z.array(z.string()),
    actualTransition: z.string(),
    isViolation: z.boolean(),
  })).optional(),
  exploitSteps: z.array(z.string()),
  impact: z.string(),
  businessImpact: z.object({
    financialLoss: z.string().optional(),
    dataExposure: z.string().optional(),
    reputationalDamage: z.string().optional(),
    complianceViolation: z.string().optional(),
  }).optional(),
  validatedExploit: z.boolean(),
  proofOfConcept: z.string().optional(),
});

export type BusinessLogicFinding = z.infer<typeof businessLogicFindingSchema>;

// Workflow State Machine representation
export const workflowStateMachineSchema = z.object({
  name: z.string(),
  states: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.enum(["initial", "intermediate", "terminal", "error"]),
    requiredAuth: z.enum(["none", "user", "admin", "system"]).optional(),
  })),
  transitions: z.array(z.object({
    id: z.string(),
    from: z.string(),
    to: z.string(),
    trigger: z.string(),
    guard: z.string().optional(),
    isSecurityCritical: z.boolean().optional(),
  })),
  securityBoundaries: z.array(z.object({
    name: z.string(),
    statesWithin: z.array(z.string()),
    requiredPrivilege: z.string(),
  })).optional(),
});

export type WorkflowStateMachine = z.infer<typeof workflowStateMachineSchema>;

// Multi-Vector Analysis Finding
export const multiVectorFindingSchema = z.object({
  id: z.string(),
  vectorType: z.enum([...exposureTypes]),
  cloudVector: z.enum([...cloudVectorTypes]).optional(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  affectedResources: z.array(z.string()),
  chainableWith: z.array(z.string()).optional(),
  exploitPath: z.array(z.object({
    step: z.number(),
    action: z.string(),
    target: z.string(),
    technique: z.string().optional(),
  })),
  iamContext: z.object({
    principal: z.string().optional(),
    assumableRoles: z.array(z.string()).optional(),
    effectivePermissions: z.array(z.string()).optional(),
    privilegeEscalationPath: z.string().optional(),
  }).optional(),
  cloudContext: z.object({
    provider: z.enum(["aws", "gcp", "azure", "multi-cloud"]).optional(),
    region: z.string().optional(),
    service: z.string().optional(),
    resourceArn: z.string().optional(),
  }).optional(),
  saasContext: z.object({
    platform: z.string().optional(),
    permissionLevel: z.string().optional(),
    shadowAdminIndicators: z.array(z.string()).optional(),
  }).optional(),
});

export type MultiVectorFinding = z.infer<typeof multiVectorFindingSchema>;

// Evidence Artifact Types
export const evidenceArtifactTypes = [
  "request_response",     // HTTP request/response pair
  "execution_trace",      // Step-by-step execution log
  "log_capture",          // System/application logs
  "screenshot",           // Safe screenshot capture
  "configuration_dump",   // Config state at time of exploit
  "data_sample",          // Sanitized data samples
  "network_capture",      // Network traffic summary
  "timeline_event",       // Timestamped event
] as const;

export type EvidenceArtifactType = typeof evidenceArtifactTypes[number];

// Evidence Artifact Schema - proof of exploit
export const evidenceArtifactSchema = z.object({
  id: z.string(),
  type: z.enum(evidenceArtifactTypes),
  timestamp: z.string(),
  title: z.string(),
  description: z.string(),
  data: z.object({
    request: z.object({
      method: z.string(),
      url: z.string(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
    }).optional(),
    response: z.object({
      statusCode: z.number(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
      timing: z.number().optional(),
    }).optional(),
    logs: z.array(z.object({
      timestamp: z.string(),
      level: z.enum(["debug", "info", "warn", "error"]),
      message: z.string(),
      source: z.string().optional(),
    })).optional(),
    screenshot: z.object({
      base64: z.string().optional(),
      url: z.string().optional(),
      caption: z.string(),
    }).optional(),
    trace: z.array(z.object({
      step: z.number(),
      action: z.string(),
      result: z.string(),
      duration: z.number().optional(),
    })).optional(),
  }),
  tags: z.array(z.string()).optional(),
  attackStepId: z.number().optional(),
  findingId: z.string().optional(),
  isSanitized: z.boolean().default(true),
});

export type EvidenceArtifact = z.infer<typeof evidenceArtifactSchema>;

// Evidence Packet - collection of artifacts for sharing
export const evidencePacketSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  createdAt: z.string(),
  title: z.string(),
  summary: z.string(),
  artifacts: z.array(evidenceArtifactSchema),
  timeline: z.array(z.object({
    timestamp: z.string(),
    event: z.string(),
    artifactId: z.string().optional(),
  })),
  executiveSummary: z.string().optional(),
  replayInstructions: z.string().optional(),
  metadata: z.object({
    evaluationType: z.string(),
    assetId: z.string(),
    totalArtifacts: z.number(),
    criticalFindings: z.number(),
  }),
});

export type EvidencePacket = z.infer<typeof evidencePacketSchema>;

// Compliance Frameworks
export const complianceFrameworks = [
  "pci_dss",    // Payment Card Industry
  "hipaa",      // Healthcare
  "sox",        // Financial reporting
  "gdpr",       // EU data protection
  "ccpa",       // California privacy
  "iso27001",   // Information security
  "nist",       // NIST Cybersecurity Framework
  "soc2",       // Service Organization Control
] as const;

export type ComplianceFramework = typeof complianceFrameworks[number];

// Exploitability Score Schema - contextual risk assessment
export const exploitabilityScoreSchema = z.object({
  score: z.number().min(0).max(100),
  confidence: z.number().min(0).max(100),
  factors: z.object({
    attackComplexity: z.object({
      level: z.enum(["trivial", "low", "medium", "high", "expert"]),
      score: z.number().min(0).max(100),
      rationale: z.string(),
    }),
    authenticationRequired: z.object({
      level: z.enum(["none", "single", "multi-factor", "privileged"]),
      score: z.number().min(0).max(100),
      rationale: z.string(),
    }),
    environmentalContext: z.object({
      networkExposure: z.enum(["internet", "dmz", "internal", "isolated"]),
      patchLevel: z.enum(["current", "behind", "significantly_behind", "eol"]),
      compensatingControls: z.array(z.string()),
      score: z.number().min(0).max(100),
    }),
    detectionLikelihood: z.object({
      level: z.enum(["unlikely", "possible", "likely", "certain"]),
      monitoringCoverage: z.number().min(0).max(100),
      evasionDifficulty: z.enum(["trivial", "moderate", "difficult", "near_impossible"]),
      score: z.number().min(0).max(100),
    }),
    exploitMaturity: z.object({
      availability: z.enum(["theoretical", "poc", "weaponized", "in_the_wild"]),
      skillRequired: z.enum(["script_kiddie", "intermediate", "advanced", "nation_state"]),
      score: z.number().min(0).max(100),
    }),
  }),
});

export type ExploitabilityScore = z.infer<typeof exploitabilityScoreSchema>;

// Business Impact Score Schema
export const businessImpactScoreSchema = z.object({
  score: z.number().min(0).max(100),
  riskLabel: z.enum(["minimal", "low", "moderate", "significant", "severe", "catastrophic"]),
  factors: z.object({
    dataSensitivity: z.object({
      classification: z.enum(["public", "internal", "confidential", "restricted", "top_secret"]),
      dataTypes: z.array(z.enum(["pii", "phi", "pci", "credentials", "trade_secrets", "financial", "customer_data"])),
      recordsAtRisk: z.string(),
      score: z.number().min(0).max(100),
    }),
    financialExposure: z.object({
      directLoss: z.object({
        min: z.number(),
        max: z.number(),
        currency: z.string().default("USD"),
      }),
      regulatoryFines: z.object({
        potential: z.number(),
        frameworks: z.array(z.string()),
      }),
      remediationCost: z.number(),
      businessDisruptionCost: z.number(),
      score: z.number().min(0).max(100),
    }),
    complianceImpact: z.object({
      affectedFrameworks: z.array(z.enum(complianceFrameworks)),
      violations: z.array(z.object({
        framework: z.string(),
        requirement: z.string(),
        severity: z.enum(["minor", "major", "critical"]),
      })),
      auditImplications: z.string().optional(),
      score: z.number().min(0).max(100),
    }),
    blastRadius: z.object({
      affectedSystems: z.number(),
      affectedUsers: z.string(),
      downstreamDependencies: z.array(z.string()),
      propagationRisk: z.enum(["contained", "limited", "spreading", "uncontained"]),
      score: z.number().min(0).max(100),
    }),
    reputationalRisk: z.object({
      customerTrust: z.enum(["minimal", "moderate", "significant", "severe"]),
      mediaExposure: z.enum(["unlikely", "possible", "likely", "certain"]),
      competitiveAdvantage: z.enum(["none", "minor", "moderate", "major"]),
      score: z.number().min(0).max(100),
    }),
  }),
});

export type BusinessImpactScore = z.infer<typeof businessImpactScoreSchema>;

// Combined Risk Rank Schema
export const riskRankSchema = z.object({
  overallScore: z.number().min(0).max(100),
  riskLevel: z.enum(["info", "low", "medium", "high", "critical", "emergency"]),
  executiveLabel: z.string(),
  fixPriority: z.number().min(1).max(100),
  recommendation: z.object({
    action: z.string(),
    timeframe: z.enum(["immediate", "24_hours", "7_days", "30_days", "90_days", "acceptable_risk"]),
    justification: z.string(),
  }),
  comparison: z.object({
    cvssEquivalent: z.number().optional(),
    industryPercentile: z.number().optional(),
    organizationPercentile: z.number().optional(),
  }).optional(),
  trendIndicator: z.enum(["improving", "stable", "degrading", "new"]).optional(),
});

export type RiskRank = z.infer<typeof riskRankSchema>;

// Complete Intelligent Score combining all factors
export const intelligentScoreSchema = z.object({
  exploitability: exploitabilityScoreSchema,
  businessImpact: businessImpactScoreSchema,
  riskRank: riskRankSchema,
  calculatedAt: z.string(),
  methodology: z.string().optional(),
  overrides: z.array(z.object({
    field: z.string(),
    originalValue: z.any(),
    overrideValue: z.any(),
    reason: z.string(),
    overriddenBy: z.string(),
    timestamp: z.string(),
  })).optional(),
});

export type IntelligentScore = z.infer<typeof intelligentScoreSchema>;

// Remediation Types
export const remediationTypes = [
  "code_fix",           // Code-level patches
  "config_change",      // Configuration updates
  "waf_rule",           // WAF/firewall rules
  "iam_policy",         // IAM policy changes
  "network_control",    // Network segmentation/controls
  "detection_rule",     // SIEM/detection signatures
  "compensating",       // Compensating controls
] as const;

export type RemediationType = typeof remediationTypes[number];

// Code Fix Schema
export const codeFixSchema = z.object({
  id: z.string(),
  title: z.string(),
  language: z.string(),
  filePath: z.string().optional(),
  vulnerability: z.string(),
  beforeCode: z.string(),
  afterCode: z.string(),
  explanation: z.string(),
  complexity: z.enum(["trivial", "low", "medium", "high"]),
  testingNotes: z.string().optional(),
});

export type CodeFix = z.infer<typeof codeFixSchema>;

// WAF Rule Schema
export const wafRuleSchema = z.object({
  id: z.string(),
  title: z.string(),
  platform: z.enum(["cloudflare", "aws_waf", "azure_waf", "modsecurity", "nginx", "generic"]),
  ruleType: z.enum(["block", "rate_limit", "challenge", "log"]),
  condition: z.string(),
  action: z.string(),
  priority: z.number(),
  description: z.string(),
  falsePositiveRisk: z.enum(["low", "medium", "high"]),
  rawConfig: z.string(),
});

export type WafRule = z.infer<typeof wafRuleSchema>;

// IAM Policy Schema
export const iamPolicySchema = z.object({
  id: z.string(),
  title: z.string(),
  platform: z.enum(["aws", "gcp", "azure", "okta", "generic"]),
  policyType: z.enum(["deny", "allow", "boundary", "scp"]),
  currentState: z.string(),
  recommendedState: z.string(),
  affectedPrincipals: z.array(z.string()),
  riskReduction: z.number().min(0).max(100),
  implementationSteps: z.array(z.string()),
  rollbackPlan: z.string().optional(),
  rawPolicy: z.string(),
});

export type IamPolicy = z.infer<typeof iamPolicySchema>;

// Network Control Schema
export const networkControlSchema = z.object({
  id: z.string(),
  title: z.string(),
  controlType: z.enum(["firewall", "segmentation", "acl", "vpn", "proxy"]),
  sourceZone: z.string(),
  destinationZone: z.string(),
  protocol: z.string(),
  ports: z.array(z.string()),
  action: z.enum(["allow", "deny", "log", "quarantine"]),
  description: z.string(),
  implementationGuide: z.string(),
});

export type NetworkControl = z.infer<typeof networkControlSchema>;

// Detection Rule Schema
export const detectionRuleSchema = z.object({
  id: z.string(),
  title: z.string(),
  platform: z.enum(["splunk", "elastic", "sentinel", "sigma", "yara", "snort", "generic"]),
  ruleType: z.enum(["correlation", "threshold", "anomaly", "signature"]),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  description: z.string(),
  logic: z.string(),
  rawRule: z.string(),
  dataSource: z.array(z.string()),
  mitreTechniques: z.array(z.string()).optional(),
  falsePositiveGuidance: z.string().optional(),
  responsePlaybook: z.string().optional(),
});

export type DetectionRule = z.infer<typeof detectionRuleSchema>;

// Compensating Control Schema
export const compensatingControlSchema = z.object({
  id: z.string(),
  title: z.string(),
  controlType: z.enum(["monitoring", "alerting", "access_review", "encryption", "backup", "training"]),
  description: z.string(),
  rationale: z.string(),
  implementationGuide: z.string(),
  effectiveness: z.number().min(0).max(100),
  duration: z.enum(["temporary", "permanent"]),
  reviewDate: z.string().optional(),
  dependencies: z.array(z.string()).optional(),
});

export type CompensatingControl = z.infer<typeof compensatingControlSchema>;

// Complete Remediation Guidance
export const remediationGuidanceSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  generatedAt: z.string(),
  summary: z.string(),
  executiveSummary: z.string(),
  codeFixes: z.array(codeFixSchema).optional(),
  wafRules: z.array(wafRuleSchema).optional(),
  iamPolicies: z.array(iamPolicySchema).optional(),
  networkControls: z.array(networkControlSchema).optional(),
  detectionRules: z.array(detectionRuleSchema).optional(),
  compensatingControls: z.array(compensatingControlSchema).optional(),
  prioritizedActions: z.array(z.object({
    order: z.number(),
    action: z.string(),
    type: z.enum(remediationTypes),
    timeEstimate: z.string(),
    riskReduction: z.number().min(0).max(100),
    effort: z.enum(["low", "medium", "high"]),
  })),
  totalRiskReduction: z.number().min(0).max(100),
  estimatedImplementationTime: z.string(),
});

export type RemediationGuidance = z.infer<typeof remediationGuidanceSchema>;

// AEV Results table
export const aevResults = pgTable("aev_results", {
  id: varchar("id").primaryKey(),
  evaluationId: varchar("evaluation_id").notNull(),
  exploitable: boolean("exploitable").notNull(),
  confidence: integer("confidence").notNull(), // 0-100
  score: integer("score").notNull(), // 0-100
  attackPath: jsonb("attack_path").$type<AttackPathStep[]>(),
  attackGraph: jsonb("attack_graph").$type<AttackGraph>(),
  businessLogicFindings: jsonb("business_logic_findings").$type<BusinessLogicFinding[]>(),
  multiVectorFindings: jsonb("multi_vector_findings").$type<MultiVectorFinding[]>(),
  workflowAnalysis: jsonb("workflow_analysis").$type<WorkflowStateMachine>(),
  impact: text("impact"),
  recommendations: jsonb("recommendations").$type<Recommendation[]>(),
  evidenceArtifacts: jsonb("evidence_artifacts").$type<EvidenceArtifact[]>(),
  intelligentScore: jsonb("intelligent_score").$type<IntelligentScore>(),
  remediationGuidance: jsonb("remediation_guidance").$type<RemediationGuidance>(),
  
  // LLM Judge Validation - automated AI-based finding validation  
  llmValidation: jsonb("llm_validation").$type<LLMValidationResult>(),
  llmValidationVerdict: varchar("llm_validation_verdict"), // One of llmValidationVerdicts - denormalized for filtering
  
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

// ============================================================================
// POLICY GUARDIAN SAFETY DECISIONS
// Tracks policy enforcement decisions (ALLOW/DENY/MODIFY) for audit trail
// ============================================================================

export const policyDecisionTypes = ["ALLOW", "DENY", "MODIFY"] as const;
export type PolicyDecisionType = typeof policyDecisionTypes[number];

export const safetyDecisions = pgTable("safety_decisions", {
  id: varchar("id").primaryKey(),
  evaluationId: varchar("evaluation_id").notNull(),
  organizationId: varchar("organization_id").notNull().default("default"),
  agentName: varchar("agent_name").notNull(),
  originalAction: text("original_action").notNull(),
  decision: varchar("decision").notNull(), // ALLOW, DENY, MODIFY
  modifiedAction: text("modified_action"),
  reasoning: text("reasoning").notNull(),
  policyReferences: jsonb("policy_references").$type<string[]>().default([]),
  executionMode: varchar("execution_mode").default("safe"), // safe, simulation, live
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertSafetyDecisionSchema = createInsertSchema(safetyDecisions).omit({
  id: true,
  createdAt: true,
});

export type InsertSafetyDecision = z.infer<typeof insertSafetyDecisionSchema>;
export type SafetyDecisionRecord = typeof safetyDecisions.$inferSelect;

// ============================================================================
// LIVE NETWORK TESTING RESULTS
// ============================================================================

export interface PortScanResult {
  port: number;
  state: "open" | "closed" | "filtered";
  service?: string;
  banner?: string;
  version?: string;
}

export interface NetworkVulnerability {
  id: string;
  port: number;
  service?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  cveIds?: string[];
  remediation?: string;
}

export const liveScanResults = pgTable("live_scan_results", {
  id: varchar("id").primaryKey(),
  evaluationId: varchar("evaluation_id").notNull(),
  organizationId: varchar("organization_id").notNull(),
  targetHost: varchar("target_host").notNull(),
  resolvedIp: varchar("resolved_ip"),
  resolvedHostname: varchar("resolved_hostname"),
  ports: jsonb("ports").$type<PortScanResult[]>(),
  vulnerabilities: jsonb("vulnerabilities").$type<NetworkVulnerability[]>(),
  scanStarted: timestamp("scan_started"),
  scanCompleted: timestamp("scan_completed"),
  status: varchar("status").default("pending"), // pending, running, completed, failed, aborted
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertLiveScanResultSchema = createInsertSchema(liveScanResults).omit({
  id: true,
  createdAt: true,
});

export type InsertLiveScanResult = z.infer<typeof insertLiveScanResultSchema>;
export type LiveScanResult = typeof liveScanResults.$inferSelect;

// ============================================================================
// REPORTING & BATCH VALIDATION SCHEMAS
// ============================================================================

// Report Types
export const reportTypes = [
  "executive_summary",      // High-level for C-suite and board
  "technical_deepdive",     // Detailed for security engineers
  "compliance_mapping",     // Mapped to compliance frameworks
  "evidence_bundle",        // Full evidence package for auditors
] as const;

export type ReportType = typeof reportTypes[number];

// Report Version - V1 (template-based) vs V2 (AI narrative)
export const reportVersions = [
  "v1_template",    // Logic-based template reports with structured data
  "v2_narrative",   // AI-generated narrative pentest reports (ENO-based)
] as const;

export type ReportVersion = typeof reportVersions[number];

// Export Formats
export const exportFormats = [
  "pdf",
  "csv",
  "json",
  "html",
] as const;

export type ExportFormat = typeof exportFormats[number];

// Report Finding Schema
export const reportFindingSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  assetId: z.string(),
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  exploitable: z.boolean(),
  score: z.number().min(0).max(100),
  description: z.string(),
  impact: z.string().optional(),
  recommendation: z.string().optional(),
  complianceViolations: z.array(z.object({
    framework: z.enum(complianceFrameworks),
    control: z.string(),
    description: z.string(),
  })).optional(),
  evidence: z.array(z.string()).optional(),
});

export type ReportFinding = z.infer<typeof reportFindingSchema>;

// Executive Summary Schema
export const executiveSummarySchema = z.object({
  reportDate: z.string(),
  reportPeriod: z.object({
    from: z.string(),
    to: z.string(),
  }),
  organizationId: z.string(),
  overallRiskLevel: z.enum(["critical", "high", "medium", "low"]),
  keyMetrics: z.object({
    totalEvaluations: z.number(),
    exploitableFindings: z.number(),
    criticalFindings: z.number(),
    highFindings: z.number(),
    mediumFindings: z.number(),
    lowFindings: z.number(),
    averageScore: z.number(),
    averageConfidence: z.number(),
  }),
  riskTrend: z.enum(["improving", "stable", "degrading"]),
  topRisks: z.array(z.object({
    assetId: z.string(),
    riskDescription: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    financialImpact: z.string().optional(),
  })),
  recommendations: z.array(z.object({
    priority: z.number(),
    action: z.string(),
    impact: z.string(),
    effort: z.enum(["low", "medium", "high"]),
  })),
  executiveNarrative: z.string(),
  executiveSummary: z.string().optional(),
  findings: z.array(z.object({
    title: z.string(),
    description: z.string(),
    recommendation: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
  })).optional(),
});

export type ExecutiveSummary = z.infer<typeof executiveSummarySchema>;

// Technical Report Schema
export const technicalReportSchema = z.object({
  reportDate: z.string(),
  reportPeriod: z.object({
    from: z.string(),
    to: z.string(),
  }),
  organizationId: z.string(),
  findings: z.array(reportFindingSchema),
  attackPaths: z.array(z.object({
    evaluationId: z.string(),
    assetId: z.string(),
    steps: z.array(attackPathStepSchema),
    complexity: z.number(),
    timeToCompromise: z.string().optional(),
  })),
  vulnerabilityBreakdown: z.object({
    byType: z.record(z.string(), z.number()),
    bySeverity: z.record(z.string(), z.number()),
    byAsset: z.record(z.string(), z.number()),
  }),
  technicalDetails: z.array(z.object({
    evaluationId: z.string(),
    assetId: z.string(),
    exposureType: z.string(),
    technicalAnalysis: z.string(),
    exploitCode: z.string().optional(),
    mitigations: z.array(z.string()),
  })),
  executiveSummary: z.string().optional(),
  recommendations: z.array(z.string()).optional(),
});

export type TechnicalReport = z.infer<typeof technicalReportSchema>;

// Compliance Report Schema
export const complianceReportSchema = z.object({
  reportDate: z.string(),
  framework: z.enum(complianceFrameworks),
  organizationId: z.string(),
  overallCompliance: z.number().min(0).max(100),
  controlStatus: z.array(z.object({
    controlId: z.string(),
    controlName: z.string(),
    status: z.enum(["compliant", "non_compliant", "partial", "not_applicable"]),
    findings: z.array(z.string()),
    remediationRequired: z.boolean(),
    remediationDeadline: z.string().optional(),
  })),
  gaps: z.array(z.object({
    controlId: z.string(),
    gapDescription: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    remediationGuidance: z.string(),
  })),
  auditReadiness: z.object({
    score: z.number().min(0).max(100),
    readyControls: z.number(),
    totalControls: z.number(),
    priorityActions: z.array(z.string()),
  }),
  executiveSummary: z.string().optional(),
  findings: z.array(z.object({
    title: z.string(),
    description: z.string(),
    recommendation: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    status: z.enum(["open", "closed", "in_progress"]).optional(),
  })).optional(),
  recommendations: z.array(z.string()).optional(),
  complianceStatus: z.record(z.string(), z.object({
    status: z.string(),
    coverage: z.number(),
  })).optional(),
});

export type ComplianceReport = z.infer<typeof complianceReportSchema>;

// ============================================================================
// ENGAGEMENT METADATA & ATTESTATION SCHEMAS
// ============================================================================

// Professional engagement context for consulting-grade reports
export const engagementMetadataSchema = z.object({
  // Client & Engagement Details
  clientName: z.string().optional(),
  clientIndustry: z.enum([
    "finance", "healthcare", "government", "retail", "technology", 
    "manufacturing", "energy", "telecommunications", "education", "other"
  ]).optional(),
  engagementId: z.string().optional(),
  contractReference: z.string().optional(),
  
  // Assessment Scope
  assessmentPeriod: z.object({
    startDate: z.string(),
    endDate: z.string(),
  }),
  scopeBoundaries: z.object({
    inScope: z.array(z.string()),   // Systems/networks in scope
    outOfScope: z.array(z.string()), // Explicitly excluded items
    limitations: z.array(z.string()), // Testing limitations/restrictions
  }).optional(),
  
  // Methodology
  methodology: z.object({
    framework: z.enum(["OWASP", "PTES", "NIST", "OSSTMM", "ISSAF", "custom"]),
    description: z.string().optional(),
    testingApproach: z.enum(["black_box", "gray_box", "white_box"]).optional(),
    riskRating: z.enum(["CVSS", "DREAD", "custom"]).optional(),
  }),
  
  // Assessment Team
  assessmentTeam: z.array(z.object({
    name: z.string(),
    role: z.string(), // Lead Tester, Security Analyst, etc.
    credentials: z.array(z.string()).optional(), // OSCP, CISSP, etc.
  })).optional(),
  
  // Classification
  classification: z.enum([
    "confidential", "internal", "public", "restricted", "top_secret"
  ]).default("confidential"),
  distributionList: z.array(z.string()).optional(),
});

export type EngagementMetadata = z.infer<typeof engagementMetadataSchema>;

// Formal attestation for report sign-off
export const attestationSchema = z.object({
  // Assessment Statement
  assessmentStatement: z.string().default(
    "This security assessment was conducted in accordance with industry best practices and the methodology described herein. The findings represent the security posture of the target environment at the time of testing."
  ),
  
  // Scope Confirmation
  scopeConfirmation: z.string().default(
    "Testing was limited to the systems and networks explicitly identified in the scope section. No testing was performed against production systems unless explicitly authorized."
  ),
  
  // Limitations Disclaimer
  limitationsDisclaimer: z.string().default(
    "Security testing provides a point-in-time assessment. New vulnerabilities may be discovered after this assessment. The absence of identified vulnerabilities does not guarantee the absence of security weaknesses."
  ),
  
  // Data Handling
  dataHandlingStatement: z.string().default(
    "All sensitive data obtained during testing has been handled in accordance with applicable data protection requirements and will be securely deleted following the retention period."
  ),
  
  // Sign-off Section
  attestedBy: z.object({
    leadTester: z.object({
      name: z.string(),
      title: z.string(),
      signature: z.string().optional(), // Could be digital signature
      date: z.string(),
    }).optional(),
    technicalReviewer: z.object({
      name: z.string(),
      title: z.string(),
      signature: z.string().optional(),
      date: z.string(),
    }).optional(),
    clientAcceptance: z.object({
      name: z.string(),
      title: z.string(),
      signature: z.string().optional(),
      date: z.string(),
    }).optional(),
  }).optional(),
  
  // Report Version Control
  versionHistory: z.array(z.object({
    version: z.string(),
    date: z.string(),
    author: z.string(),
    changes: z.string(),
  })).optional(),
  
  // Report Status
  reportStatus: z.enum(["draft", "final", "amended"]).default("draft"),
});

export type Attestation = z.infer<typeof attestationSchema>;

// Attack Narrative Schema - Story mode for technical reports
export const attackNarrativeSchema = z.object({
  title: z.string(),
  overview: z.string().min(100), // Brief summary of the attack scenario
  
  // Full narrative prose
  narrative: z.string().min(300), // "We gained initial access via..."
  
  // Key milestones in the attack chain
  milestones: z.array(z.object({
    phase: z.enum([
      "reconnaissance", "initial_access", "execution", "persistence",
      "privilege_escalation", "defense_evasion", "credential_access",
      "discovery", "lateral_movement", "collection", "exfiltration", "impact"
    ]),
    timestamp: z.string().optional(), // When this occurred during testing
    description: z.string(),
    technique: z.string(), // MITRE ATT&CK technique name
    techniqueId: z.string().optional(), // e.g., T1190
    targetAsset: z.string(),
    evidence: z.array(z.string()).optional(), // Evidence artifact IDs
  })),
  
  // Impact achieved
  finalImpact: z.object({
    accessLevel: z.enum(["none", "low", "medium", "high", "domain_admin", "root"]),
    dataAccessed: z.array(z.string()).optional(),
    systemsCompromised: z.array(z.string()).optional(),
    businessImpact: z.string(),
  }),
  
  // Time to compromise
  timeMetrics: z.object({
    totalTime: z.string(), // e.g., "2 hours 15 minutes"
    initialAccessTime: z.string().optional(),
    escalationTime: z.string().optional(),
    lateralMovementTime: z.string().optional(),
  }).optional(),
});

export type AttackNarrative = z.infer<typeof attackNarrativeSchema>;

// Reports Database Table
export const reports = pgTable("reports", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  reportType: varchar("report_type").notNull(), // executive_summary, technical_deepdive, compliance_mapping, evidence_bundle
  reportVersion: varchar("report_version").notNull().default("v1_template"), // v1_template or v2_narrative
  title: text("title").notNull(),
  dateRangeFrom: timestamp("date_range_from").notNull(),
  dateRangeTo: timestamp("date_range_to").notNull(),
  framework: varchar("framework"), // For compliance reports
  status: varchar("status").notNull().default("generating"), // generating, completed, failed, draft, final
  content: jsonb("content"), // The actual report content
  evaluationIds: jsonb("evaluation_ids").$type<string[]>(), // Evaluations included
  engagementMetadata: jsonb("engagement_metadata").$type<EngagementMetadata>(), // Professional engagement context
  attestation: jsonb("attestation").$type<Attestation>(), // Formal sign-off section
  attackNarrative: jsonb("attack_narrative").$type<AttackNarrative>(), // Story-mode narrative
  generatedBy: varchar("generated_by"), // user/system identifier
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const insertReportSchema = createInsertSchema(reports).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export type InsertReport = z.infer<typeof insertReportSchema>;
export type Report = typeof reports.$inferSelect;

// Report Narratives Table (V2 - ENO persistence)
export const reportNarratives = pgTable("report_narratives", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  evaluationId: varchar("evaluation_id"), // Single evaluation reference
  reportScopeId: varchar("report_scope_id"), // For multi-evaluation reports
  reportVersion: varchar("report_version").notNull().default("v2_narrative"),
  enoJson: jsonb("eno_json"), // The full ENO object
  modelMeta: jsonb("model_meta").$type<{
    modelName: string;
    promptHash: string;
    temperature: number;
    generationTimeMs: number;
  }>(),
  createdBy: varchar("created_by"), // user/system identifier
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertReportNarrativeSchema = createInsertSchema(reportNarratives).omit({
  id: true,
  createdAt: true,
});

export type InsertReportNarrative = z.infer<typeof insertReportNarrativeSchema>;
export type ReportNarrative = typeof reportNarratives.$inferSelect;

// ============================================================================
// SCHEDULING SCHEMAS
// ============================================================================

// Schedule Frequency
export const scheduleFrequencies = [
  "once",
  "daily",
  "weekly",
  "monthly",
  "quarterly",
] as const;

export type ScheduleFrequency = typeof scheduleFrequencies[number];

// Scheduled Scans
export const scheduledScans = pgTable("scheduled_scans", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  name: text("name").notNull(),
  description: text("description"),
  assets: jsonb("assets").$type<Array<{
    assetId: string;
    exposureType: string;
    priority: string;
    description: string;
  }>>().notNull(),
  frequency: varchar("frequency").notNull(), // once, daily, weekly, monthly, quarterly
  dayOfWeek: integer("day_of_week"), // 0-6 for weekly
  dayOfMonth: integer("day_of_month"), // 1-31 for monthly
  timeOfDay: varchar("time_of_day"), // HH:MM format
  enabled: boolean("enabled").default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertScheduledScanSchema = createInsertSchema(scheduledScans).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastRunAt: true,
});

export type InsertScheduledScan = z.infer<typeof insertScheduledScanSchema>;
export type ScheduledScan = typeof scheduledScans.$inferSelect;

// Drift Detection / Comparison Result
export const driftResultSchema = z.object({
  comparisonId: z.string(),
  baselineEvaluationId: z.string(),
  currentEvaluationId: z.string(),
  assetId: z.string(),
  comparedAt: z.string(),
  changes: z.object({
    scoreChange: z.number(), // Positive = worse, negative = better
    exploitabilityChange: z.enum(["became_exploitable", "became_safe", "unchanged"]),
    newFindings: z.array(z.string()),
    resolvedFindings: z.array(z.string()),
    severityChanges: z.array(z.object({
      findingId: z.string(),
      from: z.enum(["critical", "high", "medium", "low"]),
      to: z.enum(["critical", "high", "medium", "low"]),
    })),
  }),
  summary: z.string(),
  riskTrend: z.enum(["improving", "stable", "degrading"]),
});

export type DriftResult = z.infer<typeof driftResultSchema>;

// Evaluation History for Drift Detection
export const evaluationHistory = pgTable("evaluation_history", {
  id: varchar("id").primaryKey(),
  assetId: varchar("asset_id").notNull(),
  evaluationId: varchar("evaluation_id").notNull(),
  batchJobId: varchar("batch_job_id"),
  scheduledScanId: varchar("scheduled_scan_id"),
  snapshot: jsonb("snapshot").$type<{
    exploitable: boolean;
    score: number;
    confidence: number;
    findingSummary: string[];
  }>(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertEvaluationHistorySchema = createInsertSchema(evaluationHistory).omit({
  id: true,
  createdAt: true,
});

export type InsertEvaluationHistory = z.infer<typeof insertEvaluationHistorySchema>;
export type EvaluationHistory = typeof evaluationHistory.$inferSelect;

// ========== GOVERNANCE, SAFETY & TRUST CONTROLS ==========

// Organization Governance Settings
export const organizationGovernance = pgTable("organization_governance", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().unique(),
  executionMode: varchar("execution_mode").notNull().default("safe"), // safe, live, simulation
  killSwitchActive: boolean("kill_switch_active").default(false),
  killSwitchActivatedAt: timestamp("kill_switch_activated_at"),
  killSwitchActivatedBy: varchar("kill_switch_activated_by"),
  rateLimitPerHour: integer("rate_limit_per_hour").default(100),
  rateLimitPerDay: integer("rate_limit_per_day").default(1000),
  concurrentEvaluationsLimit: integer("concurrent_evaluations_limit").default(5),
  currentConcurrentEvaluations: integer("current_concurrent_evaluations").default(0),
  allowedTargetPatterns: jsonb("allowed_target_patterns").$type<string[]>().default([]),
  blockedTargetPatterns: jsonb("blocked_target_patterns").$type<string[]>().default([]),
  allowedNetworkRanges: jsonb("allowed_network_ranges").$type<string[]>().default([]),
  requireAuthorizationForLive: boolean("require_authorization_for_live").default(true),
  autoKillOnCritical: boolean("auto_kill_on_critical").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertOrganizationGovernanceSchema = createInsertSchema(organizationGovernance).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertOrganizationGovernance = z.infer<typeof insertOrganizationGovernanceSchema>;
export type OrganizationGovernance = typeof organizationGovernance.$inferSelect;

// Authorization Log (Red-Team Activity Audit Trail)
export const authorizationLogActions = [
  "evaluation_started",
  "evaluation_completed",
  "kill_switch_activated",
  "kill_switch_deactivated",
  "execution_mode_changed",
  "scope_rule_modified",
  "rate_limit_exceeded",
  "unauthorized_target_blocked",
  "live_execution_authorized",
  "batch_job_started",
  "simulation_run",
] as const;

export type AuthorizationLogAction = typeof authorizationLogActions[number];

export const authorizationLogs = pgTable("authorization_logs", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  userId: varchar("user_id"),
  userName: varchar("user_name"),
  action: varchar("action").notNull(),
  targetAsset: varchar("target_asset"),
  evaluationId: varchar("evaluation_id"),
  executionMode: varchar("execution_mode"),
  details: jsonb("details").$type<Record<string, any>>(),
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  authorized: boolean("authorized").default(true),
  authorizationReason: text("authorization_reason"),
  riskLevel: varchar("risk_level"), // low, medium, high, critical
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAuthorizationLogSchema = createInsertSchema(authorizationLogs).omit({
  id: true,
  createdAt: true,
});

export type InsertAuthorizationLog = z.infer<typeof insertAuthorizationLogSchema>;
export type AuthorizationLog = typeof authorizationLogs.$inferSelect;

// Scope Rules (Target Whitelist/Blacklist)
export const scopeRules = pgTable("scope_rules", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  ruleType: varchar("rule_type").notNull(), // allow, block
  targetType: varchar("target_type").notNull(), // ip, cidr, hostname, pattern
  targetValue: text("target_value").notNull(),
  priority: integer("priority").default(0), // Higher priority rules evaluated first
  enabled: boolean("enabled").default(true),
  expiresAt: timestamp("expires_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertScopeRuleSchema = createInsertSchema(scopeRules).omit({
  id: true,
  createdAt: true,
});

export type InsertScopeRule = z.infer<typeof insertScopeRuleSchema>;
export type ScopeRule = typeof scopeRules.$inferSelect;

// Rate Limit Tracking
export const rateLimitTracking = pgTable("rate_limit_tracking", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  windowStart: timestamp("window_start").notNull(),
  windowType: varchar("window_type").notNull(), // hour, day
  requestCount: integer("request_count").default(0),
  evaluationCount: integer("evaluation_count").default(0),
  blockedCount: integer("blocked_count").default(0),
});

// ========== IMMUTABLE VALIDATION AUDIT LOG ==========
// This table is append-only for compliance and forensics

export const validationAuditLogActions = [
  "probe_executed",
  "payload_sent",
  "vulnerability_confirmed",
  "exploit_attempted",
  "credential_tested",
  "mode_escalated",
  "approval_requested",
  "approval_granted",
  "approval_denied",
  "execution_blocked",
  "kill_switch_triggered",
  "evidence_captured",
  "target_accessed",
  "data_retrieved",
  "chain_executed",
  "chain_step_completed",
  "exploit_chain_started",
  "post_exploitation_proof",
] as const;

export type ValidationAuditLogAction = typeof validationAuditLogActions[number];

export const validationAuditLogs = pgTable("validation_audit_logs", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  evaluationId: varchar("evaluation_id"),
  agentId: varchar("agent_id"),
  action: varchar("action").notNull(),
  executionMode: varchar("execution_mode").notNull(), // safe, simulation, live
  targetHost: varchar("target_host"),
  targetPort: integer("target_port"),
  probeType: varchar("probe_type"),
  vulnerabilityType: varchar("vulnerability_type"),
  payloadUsed: text("payload_used"),
  payloadHash: varchar("payload_hash"),
  resultStatus: varchar("result_status"), // success, failure, blocked, timeout
  confidenceScore: integer("confidence_score"),
  verdict: varchar("verdict"), // confirmed, likely, theoretical, false_positive
  evidence: text("evidence"),
  evidenceHash: varchar("evidence_hash"),
  requestedBy: varchar("requested_by"),
  approvedBy: varchar("approved_by"),
  approvalId: varchar("approval_id"),
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  riskLevel: varchar("risk_level"), // low, medium, high, critical
  executionDurationMs: integer("execution_duration_ms"),
  metadata: jsonb("metadata").$type<Record<string, any>>(),
  checksum: varchar("checksum"), // SHA-256 of record for tamper detection
  previousRecordHash: varchar("previous_record_hash"), // Chain link for immutability
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertValidationAuditLogSchema = createInsertSchema(validationAuditLogs).omit({
  id: true,
  createdAt: true,
});

export type InsertValidationAuditLog = z.infer<typeof insertValidationAuditLogSchema>;
export type ValidationAuditLog = typeof validationAuditLogs.$inferSelect;

// ========== APPROVAL WORKFLOW ==========

export const approvalStatuses = ["pending", "approved", "denied", "expired", "cancelled"] as const;
export type ApprovalStatus = typeof approvalStatuses[number];

export const approvalLevels = ["manager", "security_lead", "ciso", "dual_control"] as const;
export type ApprovalLevel = typeof approvalLevels[number];

export const approvalRequests = pgTable("approval_requests", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  requestType: varchar("request_type").notNull(), // mode_change, live_execution, scope_expansion
  requestedBy: varchar("requested_by").notNull(),
  requestedByName: varchar("requested_by_name"),
  requiredLevel: varchar("required_level").notNull(), // manager, security_lead, ciso
  status: varchar("status").notNull().default("pending"),
  targetHost: varchar("target_host"),
  targetScope: jsonb("target_scope").$type<string[]>(),
  executionMode: varchar("execution_mode"),
  operationType: varchar("operation_type"),
  justification: text("justification").notNull(),
  riskAssessment: text("risk_assessment"),
  estimatedImpact: varchar("estimated_impact"), // minimal, moderate, significant, severe
  durationMinutes: integer("duration_minutes"),
  approvedBy: varchar("approved_by"),
  approvedByName: varchar("approved_by_name"),
  approvalNotes: text("approval_notes"),
  denialReason: text("denial_reason"),
  expiresAt: timestamp("expires_at"),
  approvedAt: timestamp("approved_at"),
  deniedAt: timestamp("denied_at"),
  metadata: jsonb("metadata").$type<Record<string, any>>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertApprovalRequestSchema = createInsertSchema(approvalRequests).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertApprovalRequest = z.infer<typeof insertApprovalRequestSchema>;
export type ApprovalRequest = typeof approvalRequests.$inferSelect;

// ========== ADVANCED / FUTURE DIFFERENTIATORS ==========

// AI Adversary Profiles
export const adversaryProfiles = [
  "script_kiddie",
  "opportunistic_criminal", 
  "organized_crime",
  "insider_threat",
  "nation_state",
  "apt_group",
  "hacktivist",
  "competitor",
] as const;

export type AdversaryProfile = typeof adversaryProfiles[number];

export const aiAdversaryProfiles = pgTable("ai_adversary_profiles", {
  id: varchar("id").primaryKey(),
  name: varchar("name").notNull(),
  profileType: varchar("profile_type").notNull(), // script_kiddie, nation_state, etc.
  description: text("description"),
  capabilities: jsonb("capabilities").$type<{
    technicalSophistication: number; // 1-10
    resources: number; // 1-10
    persistence: number; // 1-10
    stealth: number; // 1-10
    targetedAttacks: boolean;
    zerodays: boolean;
    socialEngineering: boolean;
    physicalAccess: boolean;
  }>(),
  typicalTTPs: jsonb("typical_ttps").$type<string[]>(), // MITRE ATT&CK technique IDs
  motivations: jsonb("motivations").$type<string[]>(), // financial, espionage, disruption, etc.
  targetPreferences: jsonb("target_preferences").$type<string[]>(), // industries, asset types
  avgDwellTime: integer("avg_dwell_time"), // Days
  detectionDifficulty: varchar("detection_difficulty"), // low, medium, high, very_high
  isBuiltIn: boolean("is_built_in").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAiAdversaryProfileSchema = createInsertSchema(aiAdversaryProfiles).omit({
  id: true,
  createdAt: true,
});

export type InsertAiAdversaryProfile = z.infer<typeof insertAiAdversaryProfileSchema>;
export type AiAdversaryProfile = typeof aiAdversaryProfiles.$inferSelect;

// Attack Predictions
export const attackPredictions = pgTable("attack_predictions", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  assetId: varchar("asset_id"),
  predictionDate: timestamp("prediction_date").defaultNow(),
  timeHorizon: varchar("time_horizon").notNull(), // 7d, 30d, 90d
  predictedAttackVectors: jsonb("predicted_attack_vectors").$type<Array<{
    vector: string;
    likelihood: number; // 0-100
    confidence: number; // 0-100
    adversaryProfile: string;
    estimatedImpact: string;
    mitreAttackId: string;
  }>>(),
  overallBreachLikelihood: integer("overall_breach_likelihood"), // 0-100
  riskFactors: jsonb("risk_factors").$type<Array<{
    factor: string;
    contribution: number; // percentage
    trend: string; // increasing, stable, decreasing
  }>>(),
  recommendedActions: jsonb("recommended_actions").$type<string[]>(),
  modelVersion: varchar("model_version"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAttackPredictionSchema = createInsertSchema(attackPredictions).omit({
  id: true,
  createdAt: true,
});

export type InsertAttackPrediction = z.infer<typeof insertAttackPredictionSchema>;
export type AttackPrediction = typeof attackPredictions.$inferSelect;

// Defensive Posture Score
export const defensivePostureScores = pgTable("defensive_posture_scores", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  calculatedAt: timestamp("calculated_at").defaultNow(),
  overallScore: integer("overall_score").notNull(), // 0-100
  categoryScores: jsonb("category_scores").$type<{
    networkSecurity: number;
    applicationSecurity: number;
    identityManagement: number;
    dataProtection: number;
    incidentResponse: number;
    securityAwareness: number;
    compliancePosture: number;
  }>(),
  breachLikelihood: integer("breach_likelihood"), // 0-100
  meanTimeToDetect: integer("mean_time_to_detect"), // Hours
  meanTimeToRespond: integer("mean_time_to_respond"), // Hours
  vulnerabilityExposure: jsonb("vulnerability_exposure").$type<{
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>(),
  trendDirection: varchar("trend_direction"), // improving, stable, degrading
  benchmarkPercentile: integer("benchmark_percentile"), // vs industry
  recommendations: jsonb("recommendations").$type<string[]>(),
});

export const insertDefensivePostureScoreSchema = createInsertSchema(defensivePostureScores).omit({
  id: true,
  calculatedAt: true,
});

export type InsertDefensivePostureScore = z.infer<typeof insertDefensivePostureScoreSchema>;
export type DefensivePostureScore = typeof defensivePostureScores.$inferSelect;

// Purple Team Feedback Loop
export const purpleTeamFindings = pgTable("purple_team_findings", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  evaluationId: varchar("evaluation_id"),
  findingType: varchar("finding_type").notNull(), // offensive_success, detection_gap, control_bypass
  offensiveTechnique: varchar("offensive_technique"), // MITRE ATT&CK ID
  offensiveDescription: text("offensive_description"),
  detectionStatus: varchar("detection_status"), // detected, partially_detected, missed
  existingControl: text("existing_control"),
  controlEffectiveness: integer("control_effectiveness"), // 0-100
  defensiveRecommendation: text("defensive_recommendation"),
  implementationPriority: varchar("implementation_priority"), // critical, high, medium, low
  estimatedEffort: varchar("estimated_effort"), // hours, days, weeks
  feedbackStatus: varchar("feedback_status").default("pending"), // pending, in_progress, implemented, wont_fix
  assignedTo: varchar("assigned_to"),
  resolvedAt: timestamp("resolved_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertPurpleTeamFindingSchema = createInsertSchema(purpleTeamFindings).omit({
  id: true,
  createdAt: true,
});

export type InsertPurpleTeamFinding = z.infer<typeof insertPurpleTeamFindingSchema>;
export type PurpleTeamFinding = typeof purpleTeamFindings.$inferSelect;

// AI vs AI Simulation
export const aiSimulations = pgTable("ai_simulations", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  attackerProfileId: varchar("attacker_profile_id"),
  defenderConfig: jsonb("defender_config").$type<{
    detectionCapabilities: string[];
    responseAutomation: boolean;
    honeypots: boolean;
    deception: boolean;
  }>(),
  targetEnvironment: jsonb("target_environment").$type<{
    assets: string[];
    networkTopology: string;
    securityControls: string[];
  }>(),
  simulationStatus: varchar("simulation_status").default("pending"), // pending, running, completed, failed
  simulationResults: jsonb("simulation_results").$type<{
    attackerSuccesses: number;
    defenderBlocks: number;
    timeToDetection: number; // minutes
    timeToContainment: number; // minutes
    attackPath: string[];
    detectionPoints: string[];
    missedAttacks: string[];
    recommendations: string[];
  }>(),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAiSimulationSchema = createInsertSchema(aiSimulations).omit({
  id: true,
  createdAt: true,
});

export type InsertAiSimulation = z.infer<typeof insertAiSimulationSchema>;
export type AiSimulation = typeof aiSimulations.$inferSelect;

// ============================================
// INFRASTRUCTURE DATA INGESTION TABLES
// ============================================

// Asset Status Types
export const assetStatuses = ["active", "inactive", "decommissioned", "unknown"] as const;
export type AssetStatus = typeof assetStatuses[number];

// Asset Types
export const assetTypes = [
  "server",
  "workstation", 
  "network_device",
  "container",
  "database",
  "web_application",
  "api_endpoint",
  "cloud_instance",
  "storage_bucket",
  "lambda_function",
  "kubernetes_cluster",
  "load_balancer",
  "firewall",
  "iot_device",
  "mobile_device",
  "virtual_machine",
  "other"
] as const;
export type AssetType = typeof assetTypes[number];

// Cloud Providers
export const cloudProviders = ["aws", "azure", "gcp", "oracle", "ibm", "other"] as const;
export type CloudProvider = typeof cloudProviders[number];

// Scanner Types
export const scannerTypes = [
  "nessus",
  "qualys", 
  "tenable",
  "rapid7",
  "openvas",
  "nmap",
  "custom_csv",
  "custom_json",
  "api_import"
] as const;
export type ScannerType = typeof scannerTypes[number];

// Import Job Status
export const importJobStatuses = ["pending", "processing", "completed", "failed", "cancelled"] as const;
export type ImportJobStatus = typeof importJobStatuses[number];

// Discovered Assets - Normalized asset inventory
export const discoveredAssets = pgTable("discovered_assets", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  assetIdentifier: varchar("asset_identifier").notNull(), // IP, hostname, ARN, etc.
  displayName: text("display_name"),
  assetType: varchar("asset_type").notNull(), // One of assetTypes
  status: varchar("status").default("active"), // One of assetStatuses
  
  // Network info
  ipAddresses: jsonb("ip_addresses").$type<string[]>(),
  hostname: varchar("hostname"),
  fqdn: varchar("fqdn"),
  macAddress: varchar("mac_address"),
  
  // Cloud info
  cloudProvider: varchar("cloud_provider"), // One of cloudProviders
  cloudRegion: varchar("cloud_region"),
  cloudAccountId: varchar("cloud_account_id"),
  cloudResourceId: varchar("cloud_resource_id"), // ARN, resource ID, etc.
  cloudTags: jsonb("cloud_tags").$type<Record<string, string>>(),
  
  // OS/Software info
  operatingSystem: varchar("operating_system"),
  osVersion: varchar("os_version"),
  installedSoftware: jsonb("installed_software").$type<Array<{
    name: string;
    version: string;
    vendor?: string;
  }>>(),
  
  // Services/Ports
  openPorts: jsonb("open_ports").$type<Array<{
    port: number;
    protocol: string;
    service?: string;
    version?: string;
  }>>(),
  
  // Business context
  businessUnit: varchar("business_unit"),
  owner: varchar("owner"),
  criticality: varchar("criticality").default("medium"), // critical, high, medium, low
  environment: varchar("environment"), // production, staging, development
  
  // Metadata
  lastSeen: timestamp("last_seen"),
  firstDiscovered: timestamp("first_discovered").defaultNow(),
  discoverySource: varchar("discovery_source"), // Which import/scan found it
  importJobId: varchar("import_job_id"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertDiscoveredAssetSchema = createInsertSchema(discoveredAssets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertDiscoveredAsset = z.infer<typeof insertDiscoveredAssetSchema>;
export type DiscoveredAsset = typeof discoveredAssets.$inferSelect;

// Vulnerability Severity
export const vulnSeverities = ["critical", "high", "medium", "low", "informational"] as const;
export type VulnSeverity = typeof vulnSeverities[number];

// Vulnerability Imports - Imported scanner findings
export const vulnerabilityImports = pgTable("vulnerability_imports", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  importJobId: varchar("import_job_id").notNull(),
  assetId: varchar("asset_id"), // Reference to discoveredAssets
  
  // Core vulnerability data
  title: text("title").notNull(),
  description: text("description"),
  severity: varchar("severity").notNull(), // One of vulnSeverities
  cveId: varchar("cve_id"), // CVE-XXXX-XXXXX
  cvssScore: integer("cvss_score"), // 0-100 (stored as x10 for precision)
  cvssVector: varchar("cvss_vector"),
  
  // Scanner-specific data
  scannerPluginId: varchar("scanner_plugin_id"),
  scannerName: varchar("scanner_name"),
  scannerSeverity: varchar("scanner_severity"), // Original severity from scanner
  
  // Affected resource
  affectedHost: varchar("affected_host"),
  affectedPort: integer("affected_port"),
  affectedService: varchar("affected_service"),
  affectedSoftware: varchar("affected_software"),
  affectedVersion: varchar("affected_version"),
  
  // Remediation info
  solution: text("solution"),
  solutionType: varchar("solution_type"), // patch, workaround, upgrade, configuration
  patchAvailable: boolean("patch_available"),
  exploitAvailable: boolean("exploit_available"),
  
  // References
  references: jsonb("references").$type<Array<{
    type: string; // cve, cwe, url, vendor
    value: string;
  }>>(),
  
  // Status tracking
  status: varchar("status").default("open"), // open, remediated, accepted, false_positive
  assignedTo: varchar("assigned_to"),
  dueDate: timestamp("due_date"),
  
  // Link to AEV evaluation if analyzed
  aevEvaluationId: varchar("aev_evaluation_id"),
  
  // Raw data preservation
  rawData: jsonb("raw_data"), // Original scanner output
  
  detectedAt: timestamp("detected_at"), // When scanner found it
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertVulnerabilityImportSchema = createInsertSchema(vulnerabilityImports).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertVulnerabilityImport = z.infer<typeof insertVulnerabilityImportSchema>;
export type VulnerabilityImport = typeof vulnerabilityImports.$inferSelect;

// Import Jobs - Track bulk import status
export const importJobs = pgTable("import_jobs", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Job info
  name: text("name").notNull(),
  description: text("description"),
  sourceType: varchar("source_type").notNull(), // One of scannerTypes
  
  // File info (for file uploads)
  fileName: varchar("file_name"),
  fileSize: integer("file_size"),
  fileMimeType: varchar("file_mime_type"),
  
  // Status tracking
  status: varchar("status").default("pending"), // One of importJobStatuses
  progress: integer("progress").default(0), // 0-100
  
  // Results
  totalRecords: integer("total_records").default(0),
  processedRecords: integer("processed_records").default(0),
  successfulRecords: integer("successful_records").default(0),
  failedRecords: integer("failed_records").default(0),
  skippedRecords: integer("skipped_records").default(0),
  
  // Asset/Vuln counts
  assetsDiscovered: integer("assets_discovered").default(0),
  vulnerabilitiesFound: integer("vulnerabilities_found").default(0),
  
  // Error tracking
  errors: jsonb("errors").$type<Array<{
    line?: number;
    record?: string;
    error: string;
  }>>(),
  
  // Processing info
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  
  // User who initiated
  initiatedBy: varchar("initiated_by"),
  
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertImportJobSchema = createInsertSchema(importJobs).omit({
  id: true,
  createdAt: true,
});

export type InsertImportJob = z.infer<typeof insertImportJobSchema>;
export type ImportJob = typeof importJobs.$inferSelect;

// Cloud Connection Status
export const cloudConnectionStatuses = ["connected", "disconnected", "error", "pending"] as const;
export type CloudConnectionStatus = typeof cloudConnectionStatuses[number];

// Cloud Connections - Store cloud API credentials
export const cloudConnections = pgTable("cloud_connections", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Connection info
  name: text("name").notNull(),
  provider: varchar("provider").notNull(), // One of cloudProviders
  
  // AWS-specific
  awsAccessKeyId: varchar("aws_access_key_id"),
  awsRegions: jsonb("aws_regions").$type<string[]>(),
  awsAssumeRoleArn: varchar("aws_assume_role_arn"),
  
  // Azure-specific
  azureTenantId: varchar("azure_tenant_id"),
  azureClientId: varchar("azure_client_id"),
  azureSubscriptionIds: jsonb("azure_subscription_ids").$type<string[]>(),
  
  // GCP-specific
  gcpProjectIds: jsonb("gcp_project_ids").$type<string[]>(),
  gcpServiceAccountEmail: varchar("gcp_service_account_email"),
  
  // Status
  status: varchar("status").default("pending"), // One of cloudConnectionStatuses
  lastSyncAt: timestamp("last_sync_at"),
  lastSyncStatus: varchar("last_sync_status"),
  lastError: text("last_error"),
  
  // Sync configuration
  syncEnabled: boolean("sync_enabled").default(true),
  syncInterval: integer("sync_interval").default(3600), // Seconds
  
  // Stats
  assetsDiscovered: integer("assets_discovered").default(0),
  lastAssetCount: integer("last_asset_count").default(0),
  
  // IAM Security Findings (populated during discovery)
  iamFindings: jsonb("iam_findings").$type<{
    findings: Array<{
      id: string;
      provider: string;
      findingType: string;
      resourceId: string;
      resourceName: string;
      severity: "critical" | "high" | "medium" | "low";
      title: string;
      description: string;
      riskFactors: string[];
      recommendation: string;
      metadata?: Record<string, any>;
    }>;
    summary: {
      criticalFindings: number;
      highFindings: number;
      mediumFindings: number;
      lowFindings: number;
      totalUsers?: number;
      totalRoles?: number;
      totalAccessKeys?: number;
      totalSubscriptions?: number;
      totalRoleAssignments?: number;
      totalServicePrincipals?: number;
      totalCustomRoles?: number;
      totalBindings?: number;
      totalServiceAccounts?: number;
      totalGroups?: number;
    };
    scannedAt: string;
  }>(),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertCloudConnectionSchema = createInsertSchema(cloudConnections).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertCloudConnection = z.infer<typeof insertCloudConnectionSchema>;
export type CloudConnection = typeof cloudConnections.$inferSelect;

// Cloud Connection Credentials - Encrypted secrets storage
export const cloudCredentials = pgTable("cloud_credentials", {
  id: varchar("id").primaryKey(),
  connectionId: varchar("connection_id").notNull().references(() => cloudConnections.id),
  
  // Encrypted credential data (envelope encryption with KMS)
  encryptedData: text("encrypted_data").notNull(), // AES-256 encrypted JSON
  encryptionKeyId: varchar("encryption_key_id").notNull(), // Reference to KMS key
  
  // Credential type
  credentialType: varchar("credential_type").notNull(), // aws_access_key, aws_role, azure_sp, azure_certificate, gcp_service_account, gcp_workload_identity
  
  // Metadata (non-sensitive)
  lastRotatedAt: timestamp("last_rotated_at"),
  expiresAt: timestamp("expires_at"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertCloudCredentialSchema = createInsertSchema(cloudCredentials).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertCloudCredential = z.infer<typeof insertCloudCredentialSchema>;
export type CloudCredential = typeof cloudCredentials.$inferSelect;

// SSH Credentials - Per-asset SSH access credentials for agent deployment
export const sshCredentials = pgTable("ssh_credentials", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Target identification - can be asset ID or connection-wide default
  assetId: varchar("asset_id"), // Reference to discoveredAssets (optional for defaults)
  connectionId: varchar("connection_id"), // Reference to cloudConnections (for connection-level defaults)
  
  // SSH connection details
  host: varchar("host"), // IP or hostname (can be derived from asset if linked)
  port: integer("port").default(22),
  username: varchar("username").notNull(),
  
  // Authentication method
  authMethod: varchar("auth_method").notNull().default("key"), // key, password
  
  // Encrypted credentials
  encryptedPrivateKey: text("encrypted_private_key"), // AES-256 encrypted SSH private key
  encryptedPassword: text("encrypted_password"), // AES-256 encrypted password
  encryptionKeyId: varchar("encryption_key_id").notNull(), // Reference to encryption key
  
  // Key metadata
  keyFingerprint: varchar("key_fingerprint"), // SHA256 fingerprint for identification
  
  // Sudo/privilege escalation
  useSudo: boolean("use_sudo").default(true),
  sudoPassword: boolean("sudo_password").default(false), // Whether sudo requires password
  
  // Status
  status: varchar("status").default("active"), // active, revoked, expired
  lastUsedAt: timestamp("last_used_at"),
  lastValidatedAt: timestamp("last_validated_at"),
  validationError: text("validation_error"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertSshCredentialSchema = createInsertSchema(sshCredentials).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertSshCredential = z.infer<typeof insertSshCredentialSchema>;
export type SshCredential = typeof sshCredentials.$inferSelect;

// Cloud Discovery Jobs - Track asset discovery runs
export const cloudDiscoveryJobStatuses = ["pending", "running", "completed", "failed", "cancelled"] as const;
export type CloudDiscoveryJobStatus = typeof cloudDiscoveryJobStatuses[number];

export const cloudDiscoveryJobs = pgTable("cloud_discovery_jobs", {
  id: varchar("id").primaryKey(),
  connectionId: varchar("connection_id").notNull().references(() => cloudConnections.id),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Job status
  status: varchar("status").default("pending"), // One of cloudDiscoveryJobStatuses
  jobType: varchar("job_type").default("full"), // full, incremental, targeted
  
  // Progress tracking
  totalRegions: integer("total_regions").default(0),
  completedRegions: integer("completed_regions").default(0),
  totalAssets: integer("total_assets").default(0),
  newAssets: integer("new_assets").default(0),
  updatedAssets: integer("updated_assets").default(0),
  removedAssets: integer("removed_assets").default(0),
  
  // Timing
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  estimatedDuration: integer("estimated_duration"), // seconds
  
  // Error handling
  errors: jsonb("errors").$type<Array<{
    resource?: string;
    region?: string;
    error: string;
    timestamp: string;
  }>>(),
  
  // Trigger info
  triggeredBy: varchar("triggered_by"), // user_id, scheduler, webhook
  triggerType: varchar("trigger_type").default("manual"), // manual, scheduled, event
  
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertCloudDiscoveryJobSchema = createInsertSchema(cloudDiscoveryJobs).omit({
  id: true,
  createdAt: true,
});

export type InsertCloudDiscoveryJob = z.infer<typeof insertCloudDiscoveryJobSchema>;
export type CloudDiscoveryJob = typeof cloudDiscoveryJobs.$inferSelect;

// Cloud Assets - Discovered cloud resources
export const cloudAssetTypes = [
  "vm", "container", "kubernetes_node", "kubernetes_cluster", "database", 
  "storage", "network", "load_balancer", "serverless", "managed_service"
] as const;
export type CloudAssetType = typeof cloudAssetTypes[number];

export const cloudAssets = pgTable("cloud_assets", {
  id: varchar("id").primaryKey(),
  connectionId: varchar("connection_id").notNull().references(() => cloudConnections.id),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Provider-assigned identifiers
  providerResourceId: varchar("provider_resource_id").notNull(), // AWS ARN, Azure Resource ID, GCP Resource Name
  provider: varchar("provider").notNull(), // aws, azure, gcp
  
  // Asset classification
  assetType: varchar("asset_type").notNull(), // One of cloudAssetTypes
  assetName: text("asset_name").notNull(),
  
  // Location
  region: varchar("region"),
  availabilityZone: varchar("availability_zone"),
  
  // Compute details (for VMs, containers)
  instanceType: varchar("instance_type"),
  cpuCount: integer("cpu_count"),
  memoryMb: integer("memory_mb"),
  
  // Network
  publicIpAddresses: jsonb("public_ip_addresses").$type<string[]>(),
  privateIpAddresses: jsonb("private_ip_addresses").$type<string[]>(),
  
  // State
  powerState: varchar("power_state"), // running, stopped, terminated
  healthStatus: varchar("health_status"),
  
  // Agent deployment
  agentInstalled: boolean("agent_installed").default(false),
  agentId: varchar("agent_id"), // Reference to endpointAgents.id if installed
  agentDeployable: boolean("agent_deployable").default(true), // Can we deploy an agent?
  agentDeploymentMethod: varchar("agent_deployment_method"), // ssm, vm_extension, os_config, manual
  lastAgentDeploymentAttempt: timestamp("last_agent_deployment_attempt"),
  agentDeploymentStatus: varchar("agent_deployment_status"), // pending, deploying, success, failed
  agentDeploymentError: text("agent_deployment_error"),
  
  // Tags from provider
  providerTags: jsonb("provider_tags").$type<Record<string, string>>(),
  
  // Metadata
  rawMetadata: jsonb("raw_metadata").$type<Record<string, any>>(),
  
  // Discovery tracking
  firstDiscoveredAt: timestamp("first_discovered_at").defaultNow(),
  lastSeenAt: timestamp("last_seen_at").defaultNow(),
  discoveryJobId: varchar("discovery_job_id"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertCloudAssetSchema = createInsertSchema(cloudAssets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  firstDiscoveredAt: true,
});

export type InsertCloudAsset = z.infer<typeof insertCloudAssetSchema>;
export type CloudAsset = typeof cloudAssets.$inferSelect;

// Agent Deployment Jobs - Track agent installation attempts
export const agentDeploymentStatuses = ["pending", "queued", "deploying", "verifying", "success", "failed", "cancelled"] as const;
export type AgentDeploymentStatus = typeof agentDeploymentStatuses[number];

export const agentDeploymentJobs = pgTable("agent_deployment_jobs", {
  id: varchar("id").primaryKey(),
  cloudAssetId: varchar("cloud_asset_id").notNull().references(() => cloudAssets.id),
  connectionId: varchar("connection_id").notNull().references(() => cloudConnections.id),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Deployment method
  deploymentMethod: varchar("deployment_method").notNull(), // ssm, vm_extension, os_config, daemonset, manual
  
  // Status
  status: varchar("status").default("pending"), // One of agentDeploymentStatuses
  
  // Deployment details
  deploymentCommand: text("deployment_command"), // The actual command/script
  deploymentConfig: jsonb("deployment_config").$type<Record<string, any>>(),
  
  // Progress
  attempts: integer("attempts").default(0),
  maxAttempts: integer("max_attempts").default(3),
  
  // Timing
  scheduledAt: timestamp("scheduled_at"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  
  // Result
  resultAgentId: varchar("result_agent_id"), // ID of the registered agent if successful
  errorMessage: text("error_message"),
  errorDetails: jsonb("error_details").$type<Record<string, any>>(),
  
  // Audit
  initiatedBy: varchar("initiated_by"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertAgentDeploymentJobSchema = createInsertSchema(agentDeploymentJobs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertAgentDeploymentJob = z.infer<typeof insertAgentDeploymentJobSchema>;
export type AgentDeploymentJob = typeof agentDeploymentJobs.$inferSelect;

// ============================================
// ENDPOINT AGENT SYSTEM
// ============================================

// Agent Status
export const agentStatuses = ["online", "offline", "stale", "error"] as const;
export type AgentStatus = typeof agentStatuses[number];

// Agent Platform Types
export const agentPlatforms = ["linux", "windows", "macos", "container", "kubernetes", "other"] as const;
export type AgentPlatform = typeof agentPlatforms[number];

// Endpoint Agents - Registered agents
export const endpointAgents = pgTable("endpoint_agents", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Agent identity
  agentName: text("agent_name").notNull(),
  apiKey: varchar("api_key").notNull().unique(), // For authentication
  apiKeyHash: varchar("api_key_hash"), // Hashed version for verification
  
  // Host information
  hostname: varchar("hostname"),
  platform: varchar("platform"), // One of agentPlatforms
  platformVersion: varchar("platform_version"),
  architecture: varchar("architecture"), // x86_64, arm64, etc.
  
  // Network info
  ipAddresses: jsonb("ip_addresses").$type<string[]>(),
  macAddresses: jsonb("mac_addresses").$type<string[]>(),
  
  // Agent metadata
  agentVersion: varchar("agent_version"),
  capabilities: jsonb("capabilities").$type<string[]>(), // service_scan, vuln_detect, config_audit, etc.
  
  // Status tracking
  status: varchar("status").default("offline"), // One of agentStatuses
  lastHeartbeat: timestamp("last_heartbeat"),
  lastTelemetry: timestamp("last_telemetry"),
  
  // Configuration
  telemetryInterval: integer("telemetry_interval").default(300), // seconds
  scanEnabled: boolean("scan_enabled").default(true),
  configAuditEnabled: boolean("config_audit_enabled").default(true),
  
  // Tags for organization
  tags: jsonb("tags").$type<string[]>(),
  environment: varchar("environment"), // production, staging, development
  
  registeredAt: timestamp("registered_at").defaultNow(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertEndpointAgentSchema = createInsertSchema(endpointAgents).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  registeredAt: true,
});

export type InsertEndpointAgent = z.infer<typeof insertEndpointAgentSchema>;
export type EndpointAgent = typeof endpointAgents.$inferSelect;

// Agent Registration Tokens - Single-use tokens for agent auto-registration
export const agentRegistrationTokens = pgTable("agent_registration_tokens", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Token (stored as hash for security)
  tokenHash: varchar("token_hash").notNull(),
  
  // Metadata
  name: text("name"), // Optional friendly name for the token
  description: text("description"),
  
  // Usage tracking
  usedAt: timestamp("used_at"),
  usedByAgentId: varchar("used_by_agent_id"),
  
  // Expiration
  expiresAt: timestamp("expires_at").notNull(),
  
  // Audit
  createdByUserId: varchar("created_by_user_id"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAgentRegistrationTokenSchema = createInsertSchema(agentRegistrationTokens).omit({
  id: true,
  createdAt: true,
  usedAt: true,
  usedByAgentId: true,
});

export type InsertAgentRegistrationToken = z.infer<typeof insertAgentRegistrationTokenSchema>;
export type AgentRegistrationToken = typeof agentRegistrationTokens.$inferSelect;

// Agent Commands - Queued commands for agents to execute
export const agentCommandStatuses = ["pending", "acknowledged", "executed", "failed", "expired"] as const;
export type AgentCommandStatus = typeof agentCommandStatuses[number];

export const agentCommandTypes = ["force_checkin", "run_scan", "config_update", "restart", "shutdown"] as const;
export type AgentCommandType = typeof agentCommandTypes[number];

export const agentCommands = pgTable("agent_commands", {
  id: varchar("id").primaryKey(),
  agentId: varchar("agent_id").notNull(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Command details
  commandType: varchar("command_type").notNull(), // One of agentCommandTypes
  payload: jsonb("payload").$type<Record<string, any>>(), // Optional command parameters
  
  // Status tracking
  status: varchar("status").default("pending"), // One of agentCommandStatuses
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  acknowledgedAt: timestamp("acknowledged_at"),
  executedAt: timestamp("executed_at"),
  expiresAt: timestamp("expires_at"), // Command expires if not executed by this time
  
  // Results
  result: jsonb("result").$type<Record<string, any>>(),
  errorMessage: text("error_message"),
});

export const insertAgentCommandSchema = createInsertSchema(agentCommands).omit({
  id: true,
  createdAt: true,
  acknowledgedAt: true,
  executedAt: true,
});

export type InsertAgentCommand = z.infer<typeof insertAgentCommandSchema>;
export type AgentCommand = typeof agentCommands.$inferSelect;

// Agent Telemetry - Live data from agents
export const agentTelemetry = pgTable("agent_telemetry", {
  id: varchar("id").primaryKey(),
  agentId: varchar("agent_id").notNull(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // System info
  systemInfo: jsonb("system_info").$type<{
    hostname: string;
    platform: string;
    platformVersion: string;
    kernel: string;
    architecture: string;
    uptime: number;
    bootTime: string;
  }>(),
  
  // Resource metrics
  resourceMetrics: jsonb("resource_metrics").$type<{
    cpuUsage: number;
    memoryTotal: number;
    memoryUsed: number;
    memoryPercent: number;
    diskTotal: number;
    diskUsed: number;
    diskPercent: number;
  }>(),
  
  // Running services
  services: jsonb("services").$type<Array<{
    name: string;
    version?: string;
    port?: number;
    protocol?: string;
    status: string;
    pid?: number;
  }>>(),
  
  // Open ports
  openPorts: jsonb("open_ports").$type<Array<{
    port: number;
    protocol: string;
    service?: string;
    state: string;
    localAddress: string;
    remoteAddress?: string;
  }>>(),
  
  // Network connections
  networkConnections: jsonb("network_connections").$type<Array<{
    localAddress: string;
    localPort: number;
    remoteAddress: string;
    remotePort: number;
    protocol: string;
    state: string;
    process?: string;
  }>>(),
  
  // Installed software
  installedSoftware: jsonb("installed_software").$type<Array<{
    name: string;
    version: string;
    vendor?: string;
    installDate?: string;
  }>>(),
  
  // Configuration data
  configData: jsonb("config_data").$type<Record<string, any>>(),
  
  // Security findings from agent
  securityFindings: jsonb("security_findings").$type<Array<{
    type: string; // outdated_software, weak_config, open_port, etc.
    severity: string;
    title: string;
    description: string;
    affectedComponent: string;
    recommendation?: string;
  }>>(),
  
  // Raw data for debugging
  rawData: jsonb("raw_data"),
  
  collectedAt: timestamp("collected_at").notNull(),
  receivedAt: timestamp("received_at").defaultNow(),
});

export const insertAgentTelemetrySchema = createInsertSchema(agentTelemetry).omit({
  id: true,
  receivedAt: true,
});

export type InsertAgentTelemetry = z.infer<typeof insertAgentTelemetrySchema>;
export type AgentTelemetry = typeof agentTelemetry.$inferSelect;

// Agent Findings - Security issues detected by agents
export const agentFindingStatuses = ["new", "acknowledged", "in_progress", "resolved", "false_positive"] as const;
export type AgentFindingStatus = typeof agentFindingStatuses[number];

// Verification status for findings - distinguishes AI analysis from human verification
export const findingVerificationStatuses = ["unverified", "verified_exploitable", "verified_false_positive", "needs_review"] as const;
export type FindingVerificationStatus = typeof findingVerificationStatuses[number];

// LLM Judge validation verdicts - automated AI-based finding validation
export const llmValidationVerdicts = ["confirmed", "noise", "needs_review", "error"] as const;
export type LLMValidationVerdict = typeof llmValidationVerdicts[number];

// LLM Judge validation result structure
export interface LLMValidationResult {
  verdict: LLMValidationVerdict;
  confidence: number; // 0-100
  reason: string;
  missingEvidence?: string[];
  suggestedActions?: string[];
  validatedAt: string; // ISO timestamp
  model: string; // e.g., "gpt-4o-mini"
}

export const agentFindings = pgTable("agent_findings", {
  id: varchar("id").primaryKey(),
  agentId: varchar("agent_id").notNull(),
  organizationId: varchar("organization_id").notNull().default("default"),
  telemetryId: varchar("telemetry_id"), // Reference to source telemetry
  
  // Finding details
  findingType: varchar("finding_type").notNull(), // outdated_software, weak_config, open_port, cve_detected, etc.
  severity: varchar("severity").notNull(), // critical, high, medium, low, informational
  title: text("title").notNull(),
  description: text("description"),
  
  // Affected component
  affectedComponent: varchar("affected_component"),
  affectedVersion: varchar("affected_version"),
  affectedPort: integer("affected_port"),
  affectedService: varchar("affected_service"),
  
  // CVE info if applicable
  cveId: varchar("cve_id"),
  cvssScore: integer("cvss_score"),
  
  // AI Confidence & Verification - prevents false positives
  confidenceScore: integer("confidence_score").default(0), // 0-100, AI confidence in exploitability
  confidenceFactors: jsonb("confidence_factors").$type<{
    hasKnownExploit: boolean;
    patchAvailable: boolean;
    networkExposed: boolean;
    privilegeRequired: string;
    userInteractionRequired: boolean;
    exploitComplexity: string;
  }>(),
  verificationStatus: varchar("verification_status").default("unverified"), // One of findingVerificationStatuses
  verifiedBy: varchar("verified_by"), // User ID who verified
  verifiedAt: timestamp("verified_at"),
  verificationNotes: text("verification_notes"),
  
  // LLM Judge Validation - automated AI-based finding validation
  llmValidation: jsonb("llm_validation").$type<LLMValidationResult>(),
  llmValidationVerdict: varchar("llm_validation_verdict"), // One of llmValidationVerdicts - denormalized for filtering
  
  // Remediation
  recommendation: text("recommendation"),
  
  // Status tracking
  status: varchar("status").default("new"), // One of agentFindingStatuses
  assignedTo: varchar("assigned_to"),
  
  // Link to AEV evaluation if auto-triggered
  aevEvaluationId: varchar("aev_evaluation_id"),
  autoEvaluationTriggered: boolean("auto_evaluation_triggered").default(false),
  
  // Timestamps
  detectedAt: timestamp("detected_at").notNull(),
  acknowledgedAt: timestamp("acknowledged_at"),
  resolvedAt: timestamp("resolved_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertAgentFindingSchema = createInsertSchema(agentFindings).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertAgentFinding = z.infer<typeof insertAgentFindingSchema>;
export type AgentFinding = typeof agentFindings.$inferSelect;

// ============================================================================
// UI Authentication - Control Plane Users
// Separate from API key authentication for service-to-service communication
// ============================================================================

// System role identifiers - these 6 roles are immutable and cannot be deleted
export const systemRoleIds = [
  "org_owner",
  "security_admin", 
  "security_engineer",
  "security_analyst",
  "executive_viewer",
  "compliance_officer"
] as const;
export type SystemRoleId = typeof systemRoleIds[number];

// UI user statuses
export const uiUserStatuses = ["active", "inactive", "locked", "pending"] as const;
export type UIUserStatus = typeof uiUserStatuses[number];

// UI Roles table - immutable system roles
export const uiRoles = pgTable("ui_roles", {
  id: varchar("id").primaryKey(), // e.g., "org_owner", "security_admin"
  
  // Role metadata
  name: varchar("name").notNull(), // Human-readable name
  description: text("description"),
  
  // Permission flags - what this role can do
  canManageUsers: boolean("can_manage_users").notNull().default(false),
  canManageRoles: boolean("can_manage_roles").notNull().default(false),
  canManageSettings: boolean("can_manage_settings").notNull().default(false),
  canManageAgents: boolean("can_manage_agents").notNull().default(false),
  canCreateEvaluations: boolean("can_create_evaluations").notNull().default(false),
  canRunSimulations: boolean("can_run_simulations").notNull().default(false),
  canViewEvaluations: boolean("can_view_evaluations").notNull().default(true),
  canViewReports: boolean("can_view_reports").notNull().default(true),
  canExportData: boolean("can_export_data").notNull().default(false),
  canAccessAuditLogs: boolean("can_access_audit_logs").notNull().default(false),
  canManageCompliance: boolean("can_manage_compliance").notNull().default(false),
  canUseKillSwitch: boolean("can_use_kill_switch").notNull().default(false),
  
  // System role flag - prevents deletion/modification
  isSystemRole: boolean("is_system_role").notNull().default(false),
  
  // Hierarchy level (lower = more permissions, used for permission inheritance)
  hierarchyLevel: integer("hierarchy_level").notNull().default(100),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertUIRoleSchema = createInsertSchema(uiRoles).omit({
  createdAt: true,
  updatedAt: true,
});

export type InsertUIRole = z.infer<typeof insertUIRoleSchema>;
export type UIRole = typeof uiRoles.$inferSelect;

// UI Users table - control plane authentication
export const uiUsers = pgTable("ui_users", {
  id: varchar("id").primaryKey(),
  tenantId: varchar("tenant_id").notNull().default("default"),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Authentication
  email: varchar("email").notNull(),
  passwordHash: varchar("password_hash").notNull(),
  
  // Profile
  displayName: varchar("display_name"),
  
  // Role reference - points to ui_roles.id
  roleId: varchar("role_id").notNull().default("executive_viewer"),
  
  // Status and security
  status: varchar("status").notNull().default("active"), // One of uiUserStatuses
  tokenVersion: integer("token_version").notNull().default(0), // Increment to invalidate all tokens
  failedLoginAttempts: integer("failed_login_attempts").notNull().default(0),
  lockedUntil: timestamp("locked_until"),
  
  // Timestamps
  lastLoginAt: timestamp("last_login_at"),
  lastActivityAt: timestamp("last_activity_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertUIUserSchema = createInsertSchema(uiUsers).omit({
  id: true,
  tokenVersion: true,
  failedLoginAttempts: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertUIUser = z.infer<typeof insertUIUserSchema>;
export type UIUser = typeof uiUsers.$inferSelect;

// UI Refresh Tokens - for token rotation and revocation
export const uiRefreshTokens = pgTable("ui_refresh_tokens", {
  id: varchar("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  
  // Token data
  tokenHash: varchar("token_hash").notNull(), // Hashed refresh token
  tokenVersion: integer("token_version").notNull(), // Must match user's tokenVersion
  
  // Device/session fingerprint
  userAgent: varchar("user_agent"),
  ipAddress: varchar("ip_address"),
  sessionId: varchar("session_id"),
  
  // Expiration
  expiresAt: timestamp("expires_at").notNull(),
  
  // Revocation
  revokedAt: timestamp("revoked_at"),
  revokedReason: varchar("revoked_reason"),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  lastUsedAt: timestamp("last_used_at"),
});

export const insertUIRefreshTokenSchema = createInsertSchema(uiRefreshTokens).omit({
  id: true,
  createdAt: true,
});

export type InsertUIRefreshToken = z.infer<typeof insertUIRefreshTokenSchema>;
export type UIRefreshToken = typeof uiRefreshTokens.$inferSelect;

// ============================================================================
// FULL ASSESSMENT (Multi-System Pentest)
// Comprehensive security assessments across all systems
// ============================================================================

export const fullAssessmentStatuses = [
  "pending",
  "reconnaissance",
  "vulnerability_analysis",
  "attack_synthesis",
  "lateral_analysis",
  "impact_assessment",
  "completed",
  "failed",
] as const;
export type FullAssessmentStatus = typeof fullAssessmentStatuses[number];

export const fullAssessments = pgTable("full_assessments", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Assessment metadata
  name: varchar("name").notNull(),
  description: text("description"),
  
  // Assessment mode: 'agent' (default) requires endpoint agents, 'external' uses web app/API scanning for serverless
  assessmentMode: varchar("assessment_mode").notNull().default("agent"), // 'agent' | 'external'
  targetUrl: varchar("target_url"), // Required for external mode
  
  // Scope
  agentIds: jsonb("agent_ids").$type<string[]>(), // Which agents to include (null = all)
  findingIds: jsonb("finding_ids").$type<string[]>(), // Findings included in assessment
  
  // Status tracking
  status: varchar("status").notNull().default("pending"),
  progress: integer("progress").notNull().default(0), // 0-100
  currentPhase: varchar("current_phase"),
  
  // Results (populated on completion)
  overallRiskScore: integer("overall_risk_score"), // 0-100
  criticalPathCount: integer("critical_path_count"),
  systemsAnalyzed: integer("systems_analyzed"),
  findingsAnalyzed: integer("findings_analyzed"),
  
  // Attack graph across all systems
  unifiedAttackGraph: jsonb("unified_attack_graph").$type<{
    nodes: Array<{
      id: string;
      type: "system" | "vulnerability" | "technique" | "impact";
      label: string;
      severity?: string;
      systemId?: string;
    }>;
    edges: Array<{
      source: string;
      target: string;
      label?: string;
      technique?: string;
    }>;
    criticalPaths: Array<{
      pathId: string;
      nodes: string[];
      riskScore: number;
      description: string;
    }>;
  }>(),
  
  // Executive summary
  executiveSummary: text("executive_summary"),
  
  // Detailed findings by phase
  reconFindings: jsonb("recon_findings"),
  vulnerabilityFindings: jsonb("vulnerability_findings"),
  lateralMovementPaths: jsonb("lateral_movement_paths"),
  businessImpactAnalysis: jsonb("business_impact_analysis"),
  
  // Web Application Reconnaissance (new)
  webAppRecon: jsonb("web_app_recon").$type<{
    targetUrl?: string;
    scanDurationMs?: number;
    applicationInfo?: {
      title?: string;
      technologies: string[];
      frameworks: string[];
      missingSecurityHeaders: string[];
    };
    attackSurface?: {
      totalEndpoints: number;
      highPriorityEndpoints: number;
      inputParameters: number;
      apiEndpoints: number;
      authenticationPoints: number;
      fileUploadPoints: number;
    };
    endpoints?: Array<{
      url: string;
      method: string;
      path: string;
      type: string;
      priority: string;
      parameters: Array<{
        name: string;
        vulnerabilityPotential: string[];
      }>;
    }>;
  }>(),
  
  // Validated Findings with LLM verification (new)
  validatedFindings: jsonb("validated_findings").$type<Array<{
    id: string;
    endpointUrl: string;
    endpointPath: string;
    parameter: string;
    vulnerabilityType: string;
    severity: string;
    confidence: number;
    verdict: string;
    evidence: string[];
    recommendations: string[];
    reproductionSteps: string[];
    cvssEstimate?: string;
    mitreAttackId?: string;
    llmValidation?: {
      verdict: string;
      confidence: number;
      reason: string;
    };
  }>>(),
  
  // Agent dispatch statistics (new)
  agentDispatchStats: jsonb("agent_dispatch_stats").$type<{
    totalTasks: number;
    completedTasks: number;
    failedTasks: number;
    falsePositivesFiltered: number;
    executionTimeMs: number;
    tasksByVulnerabilityType: Record<string, number>;
  }>(),
  
  // Prioritized recommendations across all systems
  recommendations: jsonb("recommendations").$type<Array<{
    id: string;
    priority: string;
    title: string;
    description: string;
    affectedSystems: string[];
    effort: string;
    impact: string;
  }>>(),
  
  // Timing
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  durationMs: integer("duration_ms"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertFullAssessmentSchema = createInsertSchema(fullAssessments).omit({
  id: true,
  progress: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertFullAssessment = z.infer<typeof insertFullAssessmentSchema>;
export type FullAssessment = typeof fullAssessments.$inferSelect;

// ============================================================================
// External Reconnaissance Scans
// Stores results from external internet-facing asset scans
// ============================================================================

export const reconScans = pgTable("recon_scans", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  target: varchar("target").notNull(),
  status: varchar("status").notNull().default("pending"),
  
  scanTime: timestamp("scan_time").defaultNow(),
  
  portScan: jsonb("port_scan").$type<Array<{
    port: number;
    state: string;
    service?: string;
    banner?: string;
  }>>(),
  
  sslCheck: jsonb("ssl_check").$type<{
    valid?: boolean;
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
    daysUntilExpiry?: number;
    protocol?: string;
    cipher?: string;
    keySize?: number;
    vulnerabilities: string[];
  }>(),
  
  httpFingerprint: jsonb("http_fingerprint").$type<{
    server?: string;
    poweredBy?: string;
    technologies: string[];
    headers: Record<string, string>;
    statusCode?: number;
    redirectsTo?: string;
    securityHeaders: {
      present: string[];
      missing: string[];
    };
  }>(),
  
  dnsEnum: jsonb("dns_enum").$type<{
    ipv4: string[];
    ipv6: string[];
    mx: Array<{ priority: number; exchange: string }>;
    ns: string[];
    txt: string[];
    cname: string[];
  }>(),
  
  // Enhanced 6-section structure fields
  networkExposure: jsonb("network_exposure").$type<{
    openPorts: number;
    highRiskPorts: number;
    serviceVersions: Array<{ port: number; service: string; version?: string }>;
    protocolFindings: Array<{ protocol: string; finding: string; severity: string }>;
  }>(),
  
  transportSecurity: jsonb("transport_security").$type<{
    tlsVersion: string;
    cipherSuite: string;
    forwardSecrecy: boolean;
    hstsEnabled: boolean;
    hstsMaxAge?: number;
    hstsIncludeSubdomains: boolean;
    hstsPreload: boolean;
    certificateTransparency: boolean;
    ocspStapling: boolean;
    downgradeRisks: Array<{
      type: 'protocol' | 'cipher' | 'header' | 'redirect';
      description: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      mitigiation: string;
    }>;
    gradeEstimate: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  }>(),
  
  applicationIdentity: jsonb("application_identity").$type<{
    frameworks: string[];
    cms?: string;
    webServer?: string;
    language?: string;
    libraries: string[];
    wafDetected?: string;
  }>(),
  
  authenticationSurface: jsonb("authentication_surface").$type<{
    loginPages: Array<{
      path: string;
      method: string;
      indicators: string[];
      riskLevel: 'high' | 'medium' | 'low';
    }>;
    adminPanels: Array<{
      path: string;
      detected: boolean;
      technology?: string;
      protected: boolean;
    }>;
    oauthEndpoints: Array<{
      path: string;
      provider?: string;
      scopes?: string[];
    }>;
    passwordResetForms: Array<{
      path: string;
      method: string;
      tokenBased: boolean;
    }>;
    apiAuthentication: {
      bearerTokenSupported: boolean;
      apiKeySupported: boolean;
      basicAuthSupported: boolean;
      jwtDetected: boolean;
    };
    vulnerabilities: string[];
  }>(),
  
  infrastructure: jsonb("infrastructure").$type<{
    hostingProvider?: string;
    cdnProvider?: string;
    dnsProvider?: string;
    cloudPlatform?: string;
    subdomains: string[];
    relatedDomains: string[];
    shadowAssets: Array<{
      hostname: string;
      type: 'subdomain' | 'related' | 'historical';
      risk: string;
    }>;
    spfRecord?: string;
    dmarcRecord?: string;
    mailSecurityIssues: string[];
  }>(),
  
  attackReadiness: jsonb("attack_readiness").$type<{
    overallScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
    executiveSummary: string;
    categoryScores: {
      networkExposure: number;
      transportSecurity: number;
      applicationIdentity: number;
      authenticationSurface: number;
      dnsInfrastructure: number;
    };
    aevNextActions: Array<{
      priority: number;
      action: string;
      exploitType: string;
      targetVector: string;
      confidence: number;
      requiredMode: 'observe' | 'passive' | 'active' | 'exploit';
    }>;
    attackVectors: Array<{
      vector: string;
      mitreAttackId: string;
      feasibility: 'confirmed' | 'likely' | 'possible' | 'unlikely';
      prerequisites: string[];
    }>;
    prioritizedRemediations: Array<{
      priority: number;
      finding: string;
      remediation: string;
      effort: 'quick' | 'moderate' | 'significant';
      impact: 'high' | 'medium' | 'low';
    }>;
  }>(),
  
  errors: jsonb("errors").$type<string[]>().default([]),
  
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertReconScanSchema = createInsertSchema(reconScans).omit({
  createdAt: true,
});

export type InsertReconScan = z.infer<typeof insertReconScanSchema>;
export type ReconScan = typeof reconScans.$inferSelect;

// ============================================================================
// API SCAN RESULTS
// ============================================================================

export interface ApiEndpointResult {
  path: string;
  methods: string[];
  authenticated: boolean;
  parameters?: string[];
  responseType?: string;
}

export interface ApiVulnerability {
  type: string;
  endpoint: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence?: string;
  remediation?: string;
}

export const apiScanResults = pgTable("api_scan_results", {
  id: varchar("id").primaryKey(),
  scanId: varchar("scan_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  organizationId: varchar("organization_id").notNull(),
  baseUrl: varchar("base_url").notNull(),
  specUrl: varchar("spec_url"),
  endpoints: jsonb("endpoints").$type<ApiEndpointResult[]>().default([]),
  vulnerabilities: jsonb("vulnerabilities").$type<ApiVulnerability[]>().default([]),
  aiFindings: jsonb("ai_findings").$type<string[]>().default([]),
  status: varchar("status").default("pending"),
  scanStarted: timestamp("scan_started"),
  scanCompleted: timestamp("scan_completed"),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertApiScanResultSchema = createInsertSchema(apiScanResults).omit({
  createdAt: true,
});

export type InsertApiScanResult = z.infer<typeof insertApiScanResultSchema>;
export type ApiScanResult = typeof apiScanResults.$inferSelect;

// ============================================================================
// AUTH SCAN RESULTS
// ============================================================================

export interface AuthTestResult {
  testName: string;
  passed: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  details: string;
  evidence?: Record<string, any>;
}

export const authScanResults = pgTable("auth_scan_results", {
  id: varchar("id").primaryKey(),
  scanId: varchar("scan_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  organizationId: varchar("organization_id").notNull(),
  targetUrl: varchar("target_url").notNull(),
  authType: varchar("auth_type").notNull(),
  testResults: jsonb("test_results").$type<AuthTestResult[]>().default([]),
  vulnerabilities: jsonb("vulnerabilities").$type<Array<{
    type: string;
    severity: string;
    description: string;
    evidence?: string;
  }>>().default([]),
  overallScore: integer("overall_score"),
  status: varchar("status").default("pending"),
  scanStarted: timestamp("scan_started"),
  scanCompleted: timestamp("scan_completed"),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAuthScanResultSchema = createInsertSchema(authScanResults).omit({
  createdAt: true,
});

export type InsertAuthScanResult = z.infer<typeof insertAuthScanResultSchema>;
export type AuthScanResult = typeof authScanResults.$inferSelect;

// ============================================================================
// EXPLOIT VALIDATION RESULTS
// ============================================================================

export const exploitValidationResults = pgTable("exploit_validation_results", {
  id: varchar("id").primaryKey(),
  validationId: varchar("validation_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  organizationId: varchar("organization_id").notNull(),
  findingId: varchar("finding_id").notNull(),
  evaluationId: varchar("evaluation_id"),
  exploitType: varchar("exploit_type").notNull(),
  safeMode: boolean("safe_mode").default(true),
  verdict: varchar("verdict"), // confirmed, noise, needs_review
  exploitable: boolean("exploitable"),
  confidence: integer("confidence"),
  validationStats: jsonb("validation_stats").$type<{
    total: number;
    confirmed: number;
    noise: number;
    needsReview: number;
  }>(),
  evidence: jsonb("evidence").$type<string[]>().default([]),
  attackPath: jsonb("attack_path").$type<Array<{
    phase: string;
    action: string;
    tools?: string[];
  }>>(),
  status: varchar("status").default("pending"),
  validationStarted: timestamp("validation_started"),
  validationCompleted: timestamp("validation_completed"),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertExploitValidationResultSchema = createInsertSchema(exploitValidationResults).omit({
  createdAt: true,
});

export type InsertExploitValidationResult = z.infer<typeof insertExploitValidationResultSchema>;
export type ExploitValidationResult = typeof exploitValidationResults.$inferSelect;

// ============================================================================
// REMEDIATION RESULTS
// ============================================================================

export interface RemediationActionResult {
  id: string;
  type: string;
  target: string;
  status: "pending" | "executed" | "verified" | "failed" | "skipped";
  result?: string;
  error?: string;
  executedAt?: string;
}

export const remediationResults = pgTable("remediation_results", {
  id: varchar("id").primaryKey(),
  remediationId: varchar("remediation_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  organizationId: varchar("organization_id").notNull(),
  evaluationId: varchar("evaluation_id"),
  findingIds: jsonb("finding_ids").$type<string[]>().default([]),
  dryRun: boolean("dry_run").default(true),
  actions: jsonb("actions").$type<RemediationActionResult[]>().default([]),
  guidance: jsonb("guidance").$type<{
    prioritizedActions?: Array<{
      priority: number;
      action: string;
      impact: string;
      effort: string;
    }>;
    codeFixes?: Record<string, string>;
    wafRules?: string[];
    iamPolicies?: string[];
    networkControls?: string[];
  }>(),
  summary: jsonb("summary").$type<{
    total: number;
    executed: number;
    verified: number;
    failed: number;
    skipped: number;
  }>(),
  status: varchar("status").default("pending"),
  remediationStarted: timestamp("remediation_started"),
  remediationCompleted: timestamp("remediation_completed"),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertRemediationResultSchema = createInsertSchema(remediationResults).omit({
  createdAt: true,
});

export type InsertRemediationResult = z.infer<typeof insertRemediationResultSchema>;
export type RemediationResult = typeof remediationResults.$inferSelect;

// ============================================================================
// VALIDATION EVIDENCE ARTIFACTS
// Raw HTTP request/response pairs for true AEV (Adversarial Exposure Validation)
// ============================================================================

export const validationVerdicts = [
  "confirmed",      // Exploit executed successfully, evidence captured
  "likely",         // Behavioral indicators present, partial validation
  "theoretical",    // AI analysis only, no execution attempted
  "false_positive", // Validation attempted, not exploitable
  "error",          // Validation failed due to error
] as const;
export type ValidationVerdict = typeof validationVerdicts[number];

export const evidenceTypes = [
  "http_request_response",  // Full HTTP transaction capture
  "timing_analysis",        // Time-based detection evidence
  "callback_received",      // Out-of-band callback (canary token, DNS)
  "error_based",            // Error message differential
  "screenshot",             // Visual evidence capture
  "banner_grab",            // Network service banner
  "configuration",          // Configuration file or setting
  "credential",             // Credential exposure (redacted)
] as const;
export type EvidenceType = typeof evidenceTypes[number];

export interface HttpRequestCapture {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: string;
}

export interface HttpResponseCapture {
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  body?: string;
  bodyTruncated?: boolean;
  timestamp: string;
}

export interface TimingData {
  requestSentAt: string;
  responseReceivedAt: string;
  durationMs: number;
  expectedDurationMs?: number;
  deviation?: number;
}

export const validationEvidenceArtifacts = pgTable("validation_evidence_artifacts", {
  id: varchar("id").primaryKey(),
  
  // Associations
  tenantId: varchar("tenant_id").notNull(),
  organizationId: varchar("organization_id").notNull(),
  evaluationId: varchar("evaluation_id"),
  findingId: varchar("finding_id"),
  validationId: varchar("validation_id"),
  scanId: varchar("scan_id"),
  
  // Evidence classification
  evidenceType: varchar("evidence_type").notNull(), // http_request_response, timing_analysis, etc.
  verdict: varchar("verdict").notNull().default("theoretical"), // confirmed, likely, theoretical, false_positive
  confidenceScore: integer("confidence_score"), // 0-100
  
  // Vulnerability context
  vulnerabilityType: varchar("vulnerability_type"), // sqli, xss, auth_bypass, etc.
  targetUrl: varchar("target_url"),
  targetHost: varchar("target_host"),
  targetPort: integer("target_port"),
  
  // Raw HTTP evidence (for http_request_response type)
  httpRequest: jsonb("http_request").$type<HttpRequestCapture>(),
  httpResponse: jsonb("http_response").$type<HttpResponseCapture>(),
  
  // Timing evidence (for timing_analysis type)
  timingData: jsonb("timing_data").$type<TimingData>(),
  
  // Payload used for testing
  payloadUsed: text("payload_used"),
  payloadType: varchar("payload_type"), // sqli_time_based, xss_reflected, etc.
  
  // Analysis results
  observedBehavior: text("observed_behavior"), // What happened when payload was sent
  expectedBehavior: text("expected_behavior"), // What we expected to see
  differentialAnalysis: text("differential_analysis"), // How response differed from baseline
  
  // Callback evidence (for out-of-band)
  callbackReceived: boolean("callback_received").default(false),
  callbackDetails: jsonb("callback_details").$type<{
    receivedAt?: string;
    sourceIp?: string;
    requestData?: string;
    tokenId?: string;
  }>(),
  
  // Screenshot/binary evidence
  screenshotUrl: varchar("screenshot_url"),
  rawDataBase64: text("raw_data_base64"), // For binary evidence (limited size)
  
  // Validation metadata
  validationMethod: varchar("validation_method"), // manual, automated, agent_based
  executionMode: varchar("execution_mode"), // safe, simulation, live
  
  // Size tracking (for cleanup policies)
  artifactSizeBytes: integer("artifact_size_bytes"),
  
  // Timestamps
  capturedAt: timestamp("captured_at").defaultNow(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertValidationEvidenceArtifactSchema = createInsertSchema(validationEvidenceArtifacts).omit({
  id: true,
  createdAt: true,
});

export type InsertValidationEvidenceArtifact = z.infer<typeof insertValidationEvidenceArtifactSchema>;
export type ValidationEvidenceArtifact = typeof validationEvidenceArtifacts.$inferSelect;

// ============================================================================
// COVERAGE AUTOPILOT - Enrollment Tokens
// ============================================================================

// Enrollment Tokens - Short-lived tokens for Coverage Autopilot bootstrap
export const enrollmentTokens = pgTable("enrollment_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Token (stored as SHA256 hash for security)
  tokenHash: varchar("token_hash").notNull(),
  tokenHint: varchar("token_hint").notNull(), // Last 6 characters for identification
  
  // Expiration & revocation
  expiresAt: timestamp("expires_at").notNull(),
  revoked: boolean("revoked").default(false),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertEnrollmentTokenSchema = createInsertSchema(enrollmentTokens).omit({
  id: true,
  createdAt: true,
});

export type InsertEnrollmentToken = z.infer<typeof insertEnrollmentTokenSchema>;
export type EnrollmentToken = typeof enrollmentTokens.$inferSelect;

// ============================================================================
// WEB APPLICATION RECONNAISSANCE SCANS
// ============================================================================

export const webAppReconScans = pgTable("web_app_recon_scans", {
  id: varchar("id").primaryKey(),
  targetUrl: varchar("target_url").notNull(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Scan configuration
  enableParallelAgents: boolean("enable_parallel_agents").default(true),
  maxConcurrentAgents: integer("max_concurrent_agents").default(5),
  vulnerabilityTypes: jsonb("vulnerability_types").$type<string[]>(),
  enableLLMValidation: boolean("enable_llm_validation").default(true),
  
  // Status tracking
  status: varchar("status").notNull().default("pending"), // pending, web_recon, web_recon_complete, agent_dispatch, completed, failed
  progress: integer("progress").default(0),
  currentPhase: varchar("current_phase"),
  
  // Results
  reconResult: jsonb("recon_result").$type<{
    targetUrl: string;
    durationMs: number;
    applicationInfo: {
      title?: string;
      technologies: string[];
      frameworks: string[];
      missingSecurityHeaders: string[];
    };
    attackSurface: {
      totalEndpoints: number;
      inputParameters: number;
      formCount: number;
      uniquePaths: number;
    };
    endpoints: Array<{
      url: string;
      method: string;
      path: string;
      type: string;
      priority: string;
      parameters: Array<{
        name: string;
        location: string;
        vulnerabilityPotential: Record<string, number>;
      }>;
    }>;
  }>(),
  
  agentDispatchResult: jsonb("agent_dispatch_result").$type<{
    totalTasks: number;
    completedTasks: number;
    failedTasks: number;
    falsePositivesFiltered: number;
    executionTimeMs: number;
    tasksByVulnerabilityType: Record<string, number>;
  }>(),
  
  validatedFindings: jsonb("validated_findings").$type<Array<{
    id: string;
    endpointUrl: string;
    endpointPath: string;
    parameter: string;
    vulnerabilityType: string;
    severity: string;
    confidence: number;
    verdict: string;
    evidence: string[];
    recommendations: string[];
    reproductionSteps: string[];
    cvssEstimate?: string;
    mitreAttackId?: string;
    llmValidation?: {
      verdict: string;
      confidence: number;
      reason: string;
    };
  }>>(),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const insertWebAppReconScanSchema = createInsertSchema(webAppReconScans).omit({
  createdAt: true,
  completedAt: true,
});

export type InsertWebAppReconScan = z.infer<typeof insertWebAppReconScanSchema>;
export type WebAppReconScan = typeof webAppReconScans.$inferSelect;

// Auto-Deploy Configuration for automatic agent deployment on new asset discovery
export const autoDeployConfigs = pgTable("auto_deploy_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id", { length: 255 }).notNull(),
  
  // Enable/disable auto-deployment
  enabled: boolean("enabled").default(false).notNull(),
  
  // Which cloud providers to auto-deploy on
  providers: jsonb("providers").$type<string[]>().default(["aws", "azure", "gcp"]),
  
  // Asset types to deploy agents to (e.g., "ec2", "vm", "gce")
  assetTypes: jsonb("asset_types").$type<string[]>().default(["ec2", "vm", "gce"]),
  
  // Platforms to deploy (linux, windows)
  targetPlatforms: jsonb("target_platforms").$type<string[]>().default(["linux", "windows"]),
  
  // Deployment options
  deploymentOptions: jsonb("deployment_options").$type<{
    maxConcurrentDeployments: number;
    deploymentTimeoutSeconds: number;
    retryFailedDeployments: boolean;
    maxRetries: number;
    skipOfflineAssets: boolean;
  }>().default({
    maxConcurrentDeployments: 10,
    deploymentTimeoutSeconds: 300,
    retryFailedDeployments: true,
    maxRetries: 3,
    skipOfflineAssets: true,
  }),
  
  // Filtering rules (optional)
  filterRules: jsonb("filter_rules").$type<{
    includeTags?: Record<string, string>;
    excludeTags?: Record<string, string>;
    includeRegions?: string[];
    excludeRegions?: string[];
    minInstanceSize?: string;
  }>(),
  
  // Statistics
  totalDeploymentsTriggered: integer("total_deployments_triggered").default(0),
  lastDeploymentTriggeredAt: timestamp("last_deployment_triggered_at"),
  
  // Metadata
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  createdBy: varchar("created_by", { length: 255 }),
});

export const insertAutoDeployConfigSchema = createInsertSchema(autoDeployConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  totalDeploymentsTriggered: true,
  lastDeploymentTriggeredAt: true,
});

export type InsertAutoDeployConfig = z.infer<typeof insertAutoDeployConfigSchema>;
export type AutoDeployConfig = typeof autoDeployConfigs.$inferSelect;

// ============================================================================
// API DEFINITIONS (OpenAPI/Swagger)
// ============================================================================

export const apiDefinitions = pgTable("api_definitions", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Basic info
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  version: varchar("version", { length: 50 }),
  specVersion: varchar("spec_version", { length: 20 }), // "openapi-3.0", "openapi-3.1", "swagger-2.0"
  
  // Source
  baseUrl: varchar("base_url", { length: 500 }),
  rawSpec: text("raw_spec"), // Original uploaded spec
  
  // Parsed data
  servers: jsonb("servers").$type<Array<{ url: string; description?: string }>>(),
  securitySchemes: jsonb("security_schemes").$type<Record<string, {
    type: string;
    scheme?: string;
    bearerFormat?: string;
    in?: string;
    name?: string;
    flows?: Record<string, any>;
  }>>(),
  
  // Endpoints summary
  totalEndpoints: integer("total_endpoints").default(0),
  totalOperations: integer("total_operations").default(0),
  
  // Status
  status: varchar("status").default("active"), // active, archived
  lastScannedAt: timestamp("last_scanned_at"),
  
  // Metadata
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  createdBy: varchar("created_by", { length: 255 }),
});

export const insertApiDefinitionSchema = createInsertSchema(apiDefinitions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertApiDefinition = z.infer<typeof insertApiDefinitionSchema>;
export type ApiDefinition = typeof apiDefinitions.$inferSelect;

// API Endpoints extracted from definitions
export const apiEndpoints = pgTable("api_endpoints", {
  id: varchar("id").primaryKey(),
  apiDefinitionId: varchar("api_definition_id").notNull().references(() => apiDefinitions.id),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Endpoint details
  path: varchar("path", { length: 500 }).notNull(),
  method: varchar("method", { length: 10 }).notNull(), // GET, POST, PUT, DELETE, PATCH, etc.
  operationId: varchar("operation_id", { length: 255 }),
  summary: text("summary"),
  description: text("description"),
  tags: jsonb("tags").$type<string[]>(),
  
  // Parameters
  parameters: jsonb("parameters").$type<Array<{
    name: string;
    in: "query" | "path" | "header" | "cookie";
    required: boolean;
    type: string;
    format?: string;
    description?: string;
    enum?: string[];
  }>>(),
  
  // Request body
  requestBody: jsonb("request_body").$type<{
    required: boolean;
    contentTypes: string[];
    schema?: Record<string, any>;
  }>(),
  
  // Responses
  responses: jsonb("responses").$type<Record<string, {
    description: string;
    contentTypes?: string[];
    schema?: Record<string, any>;
  }>>(),
  
  // Security requirements
  security: jsonb("security").$type<Array<Record<string, string[]>>>(),
  
  // Analysis metadata
  vulnerabilityPotential: jsonb("vulnerability_potential").$type<{
    sqli: number;
    xss: number;
    authBypass: number;
    idor: number;
    injection: number;
    ssrf: number;
  }>(),
  priority: varchar("priority", { length: 20 }).default("medium"), // critical, high, medium, low
  
  // Scan tracking
  lastScannedAt: timestamp("last_scanned_at"),
  scanStatus: varchar("scan_status").default("pending"), // pending, scanning, completed, failed
  findingsCount: integer("findings_count").default(0),
  
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertApiEndpointSchema = createInsertSchema(apiEndpoints).omit({
  id: true,
  createdAt: true,
});

export type InsertApiEndpoint = z.infer<typeof insertApiEndpointSchema>;
export type ApiEndpoint = typeof apiEndpoints.$inferSelect;

// ============================================================================
// PHASE 3: EXPLOIT EXECUTION SANDBOX
// Isolated execution environment with rollback capability
// ============================================================================

export const sandboxSessionStatuses = [
  "initializing",
  "ready",
  "executing",
  "paused",
  "completed",
  "failed",
  "rolled_back",
] as const;
export type SandboxSessionStatus = typeof sandboxSessionStatuses[number];

export const sandboxExecutionModes = [
  "safe",        // Read-only analysis, no actual payloads
  "simulation",  // Simulated payloads with evidence capture
  "live",        // Live payload execution (requires approval)
] as const;
export type SandboxExecutionMode = typeof sandboxExecutionModes[number];

// Sandbox Sessions - Main session tracking
export const sandboxSessions = pgTable("sandbox_sessions", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Session info
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  targetUrl: varchar("target_url", { length: 500 }),
  targetHost: varchar("target_host", { length: 255 }),
  
  // Execution configuration
  executionMode: varchar("execution_mode").notNull().default("safe"),
  status: varchar("status").notNull().default("initializing"),
  
  // State management for rollback
  initialStateSnapshot: jsonb("initial_state_snapshot").$type<{
    capturedAt: string;
    targetState: Record<string, any>;
    environmentVariables: Record<string, string>;
    networkConfig: Record<string, any>;
  }>(),
  currentStateSnapshot: jsonb("current_state_snapshot").$type<{
    capturedAt: string;
    targetState: Record<string, any>;
    changesFromInitial: string[];
  }>(),
  
  // Resource limits
  resourceLimits: jsonb("resource_limits").$type<{
    maxExecutionTimeMs: number;
    maxMemoryMB: number;
    maxPayloadSizeBytes: number;
    maxRequestsPerMinute: number;
  }>(),
  
  // Execution stats
  totalExecutions: integer("total_executions").default(0),
  successfulExecutions: integer("successful_executions").default(0),
  failedExecutions: integer("failed_executions").default(0),
  
  // Governance
  approvedBy: varchar("approved_by", { length: 255 }),
  approvedAt: timestamp("approved_at"),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const insertSandboxSessionSchema = createInsertSchema(sandboxSessions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  completedAt: true,
});

export type InsertSandboxSession = z.infer<typeof insertSandboxSessionSchema>;
export type SandboxSession = typeof sandboxSessions.$inferSelect;

// Sandbox Snapshots - Point-in-time state captures for rollback
export const sandboxSnapshots = pgTable("sandbox_snapshots", {
  id: varchar("id").primaryKey(),
  sessionId: varchar("session_id").notNull().references(() => sandboxSessions.id),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Snapshot info
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  snapshotType: varchar("snapshot_type").notNull().default("manual"), // manual, auto, pre-execution
  
  // State data
  stateData: jsonb("state_data").$type<{
    targetState: Record<string, any>;
    executionHistory: string[];
    credentialsDiscovered: string[];
    filesModified: string[];
    networkConnections: string[];
  }>(),
  
  // Metadata
  sizeBytes: integer("size_bytes"),
  isRestorable: boolean("is_restorable").default(true),
  
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertSandboxSnapshotSchema = createInsertSchema(sandboxSnapshots).omit({
  id: true,
  createdAt: true,
});

export type InsertSandboxSnapshot = z.infer<typeof insertSandboxSnapshotSchema>;
export type SandboxSnapshot = typeof sandboxSnapshots.$inferSelect;

// Sandbox Executions - Individual payload/exploit execution logs
export const sandboxExecutions = pgTable("sandbox_executions", {
  id: varchar("id").primaryKey(),
  sessionId: varchar("session_id").notNull().references(() => sandboxSessions.id),
  organizationId: varchar("organization_id").notNull().default("default"),
  
  // Execution info
  executionType: varchar("execution_type").notNull(), // payload, exploit, probe, scan
  payloadName: varchar("payload_name", { length: 255 }),
  payloadCategory: varchar("payload_category", { length: 100 }), // sqli, xss, rce, etc.
  
  // Target
  targetEndpoint: varchar("target_endpoint", { length: 500 }),
  targetMethod: varchar("target_method", { length: 10 }),
  
  // Payload details
  payloadContent: text("payload_content"),
  payloadEncoding: varchar("payload_encoding", { length: 50 }),
  
  // Execution result
  status: varchar("status").notNull().default("pending"), // pending, running, success, failed, blocked
  success: boolean("success"),
  
  // Evidence capture
  evidence: jsonb("evidence").$type<{
    request: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body?: string;
    };
    response: {
      statusCode: number;
      headers: Record<string, string>;
      body?: string;
      timing: number;
    };
    indicators: string[];
    screenshots?: string[];
  }>(),
  
  // MITRE ATT&CK mapping
  mitreAttackId: varchar("mitre_attack_id", { length: 20 }),
  mitreTactic: varchar("mitre_tactic", { length: 50 }),
  
  // Timing
  executionTimeMs: integer("execution_time_ms"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertSandboxExecutionSchema = createInsertSchema(sandboxExecutions).omit({
  id: true,
  createdAt: true,
});

export type InsertSandboxExecution = z.infer<typeof insertSandboxExecutionSchema>;
export type SandboxExecution = typeof sandboxExecutions.$inferSelect;

// ============================================================================
// PHASE 3: LIVE LATERAL MOVEMENT
// Credential reuse, pass-the-hash/ticket, pivot discovery
// ============================================================================

export const credentialTypes = [
  "password",
  "ntlm_hash",
  "kerberos_ticket",
  "ssh_key",
  "api_token",
  "session_cookie",
  "certificate",
] as const;
export type CredentialType = typeof credentialTypes[number];

export const lateralMovementTechniques = [
  "pass_the_hash",
  "pass_the_ticket",
  "credential_reuse",
  "ssh_pivot",
  "rdp_pivot",
  "smb_relay",
  "wmi_exec",
  "psexec",
  "dcom_exec",
  "winrm",
] as const;
export type LateralMovementTechnique = typeof lateralMovementTechniques[number];

// Discovered Credentials - Credentials found during assessments
export const discoveredCredentials = pgTable("discovered_credentials", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Source of discovery
  sourceType: varchar("source_type").notNull(), // scan, exploit, harvest, manual
  sourceId: varchar("source_id"), // Related evaluation/scan ID
  sourceHost: varchar("source_host", { length: 255 }),
  
  // Credential details
  credentialType: varchar("credential_type").notNull(),
  username: varchar("username", { length: 255 }),
  domain: varchar("domain", { length: 255 }),
  credentialValue: text("credential_value"), // Encrypted/hashed for storage
  credentialHash: varchar("credential_hash", { length: 128 }), // For deduplication
  
  // Scope and usability
  validatedOn: jsonb("validated_on").$type<string[]>(), // Hosts where this credential works
  potentialTargets: jsonb("potential_targets").$type<string[]>(), // Hosts to try
  usableForTechniques: jsonb("usable_for_techniques").$type<string[]>(), // pth, ptt, ssh, etc.
  
  // Risk assessment
  privilegeLevel: varchar("privilege_level").default("user"), // user, admin, system, root
  riskScore: integer("risk_score"), // 0-100
  
  // Status
  isActive: boolean("is_active").default(true),
  lastValidatedAt: timestamp("last_validated_at"),
  expiresAt: timestamp("expires_at"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertDiscoveredCredentialSchema = createInsertSchema(discoveredCredentials).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertDiscoveredCredential = z.infer<typeof insertDiscoveredCredentialSchema>;
export type DiscoveredCredential = typeof discoveredCredentials.$inferSelect;

// Lateral Movement Findings - Results from lateral movement testing
export const lateralMovementFindings = pgTable("lateral_movement_findings", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Session reference
  sandboxSessionId: varchar("sandbox_session_id").references(() => sandboxSessions.id),
  
  // Finding details
  technique: varchar("technique").notNull(), // One of lateralMovementTechniques
  sourceHost: varchar("source_host", { length: 255 }).notNull(),
  targetHost: varchar("target_host", { length: 255 }).notNull(),
  
  // Credential used
  credentialId: varchar("credential_id").references(() => discoveredCredentials.id),
  credentialType: varchar("credential_type"),
  
  // Result
  success: boolean("success").notNull(),
  accessLevel: varchar("access_level"), // none, user, admin, system
  
  // Evidence
  evidence: jsonb("evidence").$type<{
    technique: string;
    sourceHost: string;
    targetHost: string;
    credentialUsed: string;
    commandExecuted?: string;
    outputCaptured?: string;
    screenshotPath?: string;
    timing: number;
  }>(),
  
  // MITRE ATT&CK mapping
  mitreAttackId: varchar("mitre_attack_id", { length: 20 }),
  mitreTactic: varchar("mitre_tactic", { length: 50 }),
  
  // Risk and business impact
  severity: varchar("severity").default("medium"), // critical, high, medium, low
  businessImpact: text("business_impact"),
  
  // Recommendations
  recommendations: jsonb("recommendations").$type<string[]>(),
  
  executionTimeMs: integer("execution_time_ms"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertLateralMovementFindingSchema = createInsertSchema(lateralMovementFindings).omit({
  id: true,
  createdAt: true,
});

export type InsertLateralMovementFinding = z.infer<typeof insertLateralMovementFindingSchema>;
export type LateralMovementFinding = typeof lateralMovementFindings.$inferSelect;

// Pivot Points - Discovered network pivot opportunities
export const pivotPoints = pgTable("pivot_points", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Pivot location
  hostname: varchar("hostname", { length: 255 }).notNull(),
  ipAddress: varchar("ip_address", { length: 45 }),
  networkSegment: varchar("network_segment", { length: 50 }),
  
  // Access info
  accessMethod: varchar("access_method"), // ssh, rdp, smb, etc.
  accessCredentialId: varchar("access_credential_id").references(() => discoveredCredentials.id),
  accessLevel: varchar("access_level").default("user"),
  
  // Reachability
  reachableFrom: jsonb("reachable_from").$type<string[]>(),
  reachableTo: jsonb("reachable_to").$type<string[]>(),
  
  // Pivot potential
  pivotScore: integer("pivot_score"), // 0-100, higher = better pivot point
  strategicValue: text("strategic_value"),
  
  // Services and capabilities
  discoveredServices: jsonb("discovered_services").$type<{
    port: number;
    service: string;
    version?: string;
  }[]>(),
  
  // Status
  isActive: boolean("is_active").default(true),
  lastVerifiedAt: timestamp("last_verified_at"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertPivotPointSchema = createInsertSchema(pivotPoints).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertPivotPoint = z.infer<typeof insertPivotPointSchema>;
export type PivotPoint = typeof pivotPoints.$inferSelect;

// Attack Paths - Visualized paths through the network
export const attackPaths = pgTable("attack_paths", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  tenantId: varchar("tenant_id").notNull().default("default"),
  
  // Path info
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  
  // Path definition
  entryPoint: varchar("entry_point", { length: 255 }).notNull(),
  targetObjective: varchar("target_objective", { length: 255 }),
  
  // Path nodes and edges
  pathNodes: jsonb("path_nodes").$type<{
    id: string;
    hostname: string;
    type: "entry" | "pivot" | "target";
    accessLevel: string;
  }[]>(),
  pathEdges: jsonb("path_edges").$type<{
    from: string;
    to: string;
    technique: string;
    credentialRequired: boolean;
    successProbability: number;
  }[]>(),
  
  // Risk assessment
  totalHops: integer("total_hops"),
  overallRisk: varchar("overall_risk").default("medium"),
  exploitability: integer("exploitability"), // 0-100
  
  // MITRE ATT&CK
  mitreTechniques: jsonb("mitre_techniques").$type<string[]>(),
  killChainPhases: jsonb("kill_chain_phases").$type<string[]>(),
  
  // Status
  status: varchar("status").default("discovered"), // discovered, validated, exploited
  lastValidatedAt: timestamp("last_validated_at"),
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertAttackPathSchema = createInsertSchema(attackPaths).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertAttackPath = z.infer<typeof insertAttackPathSchema>;
export type AttackPath = typeof attackPaths.$inferSelect;

// ============================================================================
// Security Policies - RAG Vector Storage for Rules of Engagement
// pgvector-enabled table for semantic search of security policies
// ============================================================================

export const policyTypes = [
  "rules_of_engagement",
  "acceptable_use",
  "scope_definition",
  "escalation_procedure",
  "compliance_requirement",
  "risk_tolerance",
  "incident_response",
  "authorization_matrix",
  "other",
] as const;
export type PolicyType = typeof policyTypes[number];

export const securityPolicies = pgTable("security_policies", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  
  // Document content
  content: text("content").notNull(),
  
  // Metadata for filtering and context
  metadata: jsonb("metadata").$type<{
    filename?: string;
    policyType?: PolicyType;
    effectiveDate?: string;
    expirationDate?: string;
    version?: string;
    author?: string;
    department?: string;
    classification?: "public" | "internal" | "confidential" | "restricted";
    tags?: string[];
    chunkIndex?: number;
    totalChunks?: number;
    sourceHash?: string;
  }>().default({}),
  
  // Vector embedding for semantic search (OpenAI text-embedding-ada-002 = 1536 dimensions)
  embedding: vector("embedding"),
  
  // Organization isolation
  organizationId: varchar("organization_id", { length: 255 }),
  
  // Timestamps
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertSecurityPolicySchema = createInsertSchema(securityPolicies, {
  // Override embedding type since drizzle-zod doesn't handle customType
  embedding: z.array(z.number()).optional(),
}).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertSecurityPolicy = z.infer<typeof insertSecurityPolicySchema>;
export type SecurityPolicy = typeof securityPolicies.$inferSelect;
