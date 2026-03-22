import type { Express } from "express";
import { type Server } from "http";
import { storage } from "./storage";
import { db } from "./db";
import { AEV_ONLY_MODE } from "./feature-flags";
import { sql, and, eq } from "drizzle-orm";
import { insertEvaluationSchema, complianceFrameworks, getPermissionsForDbRole } from "@shared/schema";
import { runAgentOrchestrator } from "./services/agents";
import { wsService } from "./services/websocket";
import { reportGenerator } from "./services/report-generator";
import { queueService } from "./services/queue";
import {
  apiRateLimiter,
  authRateLimiter,
  evaluationRateLimiter,
  reportRateLimiter,
  getAllRateLimitStatuses
} from "./services/rate-limiter";
import {
  loginUser,
  refreshUserTokens,
  logoutUser,
  logoutAllSessions,
  createInitialAdminUser,
  uiAuthMiddleware,
  requireRole,
  requirePermission,
  getTrialInfo,
  hashPassword,
  type UIAuthenticatedRequest,
} from "./services/ui-auth";
import { randomUUID } from "crypto";
import { z } from "zod";
import { registerReportV2Routes } from "./src/reportsV2/routes";
import { runBreachChain, resumeBreachChain, abortBreachChain } from "./services/breach-orchestrator";
import { generateNarrative } from "./services/breach-chain/narrative-generator";
import { compareChains } from "./services/breach-chain/chain-differ";
import { registerTenantRoutes, seedDefaultTenant } from "./routes/tenants";
import { tenantMiddleware } from "./middleware/tenant";
import { runtimeGuard } from "./services/runtime-guard";
import { storageService } from "./services/storage";

// UI Auth Validation Schemas
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  tenantId: z.string().optional().default("default"),
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
  displayName: z.string().max(128).optional(),
  tenantId: z.string().optional().default("default"),
  organizationId: z.string().optional().default("default"),
  roleId: z.string().optional().default("executive_viewer"),
});

const refreshTokenSchema = z.object({
  refreshToken: z.string(),
});

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  wsService.initialize(httpServer);
  
  // Seed default tenant on startup
  await seedDefaultTenant();
  
  // Apply tenant middleware globally (after session/auth middleware)
  app.use(tenantMiddleware);
  
  // Register tenant routes
  registerTenantRoutes(app);
  
  // ========== HEALTH CHECK ENDPOINTS ==========
  // K8s / CI / Load Balancer friendly health checks
  // Note: Health endpoints intentionally excluded from rate limiting to ensure
  // Kubernetes probes, load balancer checks, and monitoring systems always succeed.
  // These endpoints return minimal data and pose negligible abuse risk.
  // Public feature flags endpoint — exposes server-side env flags to the browser
  app.get("/api/flags", (_req, res) => {
    const { BREACH_ENHANCEMENT_FLAGS } = require("../shared/schema");
    const flags: Record<string, boolean> = {};
    for (const flag of Object.values(BREACH_ENHANCEMENT_FLAGS) as string[]) {
      flags[flag] = process.env[flag] === "true" || process.env[flag] === "1";
    }
    res.json(flags);
  });

  app.get("/healthz", (_req, res) => {
    res.status(200).json({
      ok: true,
      service: "odinforge-backend",
      ts: new Date().toISOString(),
    });
  });

  app.get("/readyz", async (_req, res) => {
    const checks: Record<string, { ok: boolean; latencyMs?: number; error?: string }> = {};
    let allHealthy = true;

    // 1. PostgreSQL connectivity + basic query
    try {
      const dbStart = Date.now();
      await db.execute(sql`SELECT 1`);
      checks.postgres = { ok: true, latencyMs: Date.now() - dbStart };
    } catch (err: any) {
      checks.postgres = { ok: false, error: err.message };
      allHealthy = false;
    }

    // 2. RLS context is functional (can set and clear)
    try {
      const rlsStart = Date.now();
      await db.execute(sql`SELECT set_config('app.current_organization_id', '__readyz_probe__', TRUE)`);
      const result = await db.execute(sql`SELECT current_setting('app.current_organization_id', TRUE) as v`);
      const val = (result.rows[0] as any)?.v;
      await db.execute(sql`SELECT set_config('app.current_organization_id', '', TRUE)`);
      checks.rls = {
        ok: val === "__readyz_probe__",
        latencyMs: Date.now() - rlsStart,
        ...(val !== "__readyz_probe__" ? { error: "RLS context set/get mismatch" } : {}),
      };
      if (!checks.rls.ok) allHealthy = false;
    } catch (err: any) {
      checks.rls = { ok: false, error: err.message };
      allHealthy = false;
    }

    // 3. Redis / Queue service
    try {
      const { queueService } = await import("./services/queue/queue-service");
      const redisUp = queueService.isUsingRedis();
      checks.redis = { ok: true, error: redisUp ? undefined : "in-memory fallback" };
      // Redis being unavailable degrades but doesn't fail readiness
    } catch (err: any) {
      checks.redis = { ok: true, error: "queue not initialized: " + err.message };
    }

    const status = allHealthy ? 200 : 503;
    res.status(status).json({
      ok: allHealthy,
      ready: allHealthy,
      checks,
      ts: new Date().toISOString(),
    });
  });

  // Prometheus metrics endpoint (no auth — scraped by Prometheus)
  app.get("/metrics", async (_req, res) => {
    try {
      const { metricsRegistry } = await import("./services/metrics");
      res.set("Content-Type", metricsRegistry.contentType);
      res.end(await metricsRegistry.metrics());
    } catch (error) {
      res.status(500).end("Metrics unavailable");
    }
  });

  // Platform mode (always available, no auth)
  app.get("/api/mode", (_req, res) => {
    res.json({ aevOnly: AEV_ONLY_MODE });
  });

  // ========== PORTFOLIO ORCHESTRATION ENDPOINTS (Phase 13) ==========

  app.get("/api/portfolio/summary", apiRateLimiter, uiAuthMiddleware, async (_req, res) => {
    try {
      const { getPortfolioOrchestrator } = await import("./services/aev/portfolio-orchestrator");
      const portfolio = getPortfolioOrchestrator();
      res.json(portfolio.getPortfolioSummary());
    } catch (error) {
      res.status(500).json({ error: "Failed to get portfolio summary" });
    }
  });

  app.get("/api/portfolio/runs", apiRateLimiter, uiAuthMiddleware, async (_req, res) => {
    try {
      const { getPortfolioOrchestrator } = await import("./services/aev/portfolio-orchestrator");
      const portfolio = getPortfolioOrchestrator();
      res.json(portfolio.getAllRuns());
    } catch (error) {
      res.status(500).json({ error: "Failed to get runs" });
    }
  });

  app.get("/api/portfolio/runs/:runId", apiRateLimiter, uiAuthMiddleware, async (req, res) => {
    try {
      const { getPortfolioOrchestrator } = await import("./services/aev/portfolio-orchestrator");
      const portfolio = getPortfolioOrchestrator();
      const run = portfolio.getRun(req.params.runId);
      if (!run) return res.status(404).json({ error: "Run not found" });
      res.json(run);
    } catch (error) {
      res.status(500).json({ error: "Failed to get run" });
    }
  });

  app.get("/api/portfolio/ranking", apiRateLimiter, uiAuthMiddleware, async (_req, res) => {
    try {
      const { getPortfolioOrchestrator } = await import("./services/aev/portfolio-orchestrator");
      const portfolio = getPortfolioOrchestrator();
      res.json(portfolio.rankTargets());
    } catch (error) {
      res.status(500).json({ error: "Failed to rank targets" });
    }
  });

  // ========== UI AUTHENTICATION ENDPOINTS ==========
  // These routes are for control plane UI authentication ONLY
  // They do NOT affect /api/* service-to-service authentication
  
  app.post("/ui/api/auth/login", authRateLimiter, async (req, res) => {
    try {
      const parsed = loginSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      }

      const { email, password, tenantId } = parsed.data;
      const result = await loginUser(email, password, tenantId, req);

      if (!result.success) {
        return res.status(401).json({ error: result.error });
      }

      const role = await storage.getUIRole(result.user.roleId);
      const trialInfo = await getTrialInfo(result.user.tenantId);
      res.json({
        user: {
          id: result.user.id,
          email: result.user.email,
          displayName: result.user.displayName,
          roleId: result.user.roleId,
          role: role || undefined,
          tenantId: result.user.tenantId,
          organizationId: result.user.organizationId,
        },
        accessToken: result.tokens.accessToken,
        refreshToken: result.tokens.refreshToken,
        accessTokenExpiresAt: result.tokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: result.tokens.refreshTokenExpiresAt,
        trial: trialInfo,
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ error: "Authentication failed" });
    }
  });

  // Public signup endpoint - allows new users to register
  app.post("/ui/api/auth/signup", authRateLimiter, async (req, res) => {
    try {
      const signupSchema = z.object({
        email: z.string().email(),
        password: z.string().min(8).max(128),
        displayName: z.string().max(128).optional(),
      });

      const parsed = signupSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      }

      const { email, password, displayName } = parsed.data;
      const tenantId = "default";
      const organizationId = "default";

      const existing = await storage.getUIUserByEmail(email, tenantId);
      if (existing) {
        return res.status(409).json({ error: "An account with this email already exists" });
      }

      // First user in the org becomes org_owner, subsequent users get security_analyst
      const existingUsers = await storage.getUIUsers(tenantId);
      const isFirstUser = !existingUsers || existingUsers.length === 0;

      // Initialize trial for the tenant if this is the first user and tenant is new
      if (isFirstUser) {
        const tenant = await storage.getTenant(tenantId);
        if (tenant && !tenant.trialEndsAt && tenant.status === "active") {
          const trialDays = 14;
          const trialEndsAt = new Date(Date.now() + trialDays * 24 * 60 * 60 * 1000);
          await storage.updateTenant(tenantId, {
            status: "trial",
            trialEndsAt,
          });
          console.log(`[Trial] Initialized ${trialDays}-day trial for tenant ${tenantId}, expires ${trialEndsAt.toISOString()}`);
        }
      }

      const passwordHash = await hashPassword(password);
      const user = await storage.createUIUser({
        email,
        passwordHash,
        displayName: displayName || email.split("@")[0],
        tenantId,
        organizationId,
        roleId: isFirstUser ? "org_owner" : "security_analyst",
        status: "active",
      });

      // Auto-login after signup
      const loginResult = await loginUser(email, password, tenantId, req);
      if (!loginResult.success) {
        return res.status(201).json({ 
          success: true, 
          message: "Account created. Please log in.",
          user: { id: user.id, email: user.email }
        });
      }

      const role = await storage.getUIRole(user.roleId);
      const trialInfo = await getTrialInfo(user.tenantId);
      res.status(201).json({
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          roleId: user.roleId,
          role: role || undefined,
          tenantId: user.tenantId,
          organizationId: user.organizationId,
        },
        accessToken: loginResult.tokens.accessToken,
        refreshToken: loginResult.tokens.refreshToken,
        accessTokenExpiresAt: loginResult.tokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: loginResult.tokens.refreshTokenExpiresAt,
        trial: trialInfo,
      });
    } catch (error) {
      console.error("Signup error:", error);
      res.status(500).json({ error: "Registration failed" });
    }
  });

  app.post("/ui/api/auth/refresh", async (req, res) => {
    try {
      const parsed = refreshTokenSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      }

      const result = await refreshUserTokens(parsed.data.refreshToken, req);

      if (!result.success) {
        return res.status(401).json({ error: result.error });
      }

      const role = await storage.getUIRole(result.user.roleId);
      res.json({
        user: {
          id: result.user.id,
          email: result.user.email,
          displayName: result.user.displayName,
          roleId: result.user.roleId,
          role: role || undefined,
          tenantId: result.user.tenantId,
          organizationId: result.user.organizationId,
        },
        accessToken: result.tokens.accessToken,
        refreshToken: result.tokens.refreshToken,
        accessTokenExpiresAt: result.tokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: result.tokens.refreshTokenExpiresAt,
      });
    } catch (error) {
      console.error("Token refresh error:", error);
      res.status(500).json({ error: "Token refresh failed" });
    }
  });

  app.post("/ui/api/auth/logout", uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const refreshToken = req.body.refreshToken;
      if (req.uiUser) {
        await logoutUser(refreshToken, req.uiUser.userId);
      }
      res.json({ success: true, message: "Logged out successfully" });
    } catch (error) {
      console.error("Logout error:", error);
      res.status(500).json({ error: "Logout failed" });
    }
  });

  app.post("/ui/api/auth/logout-all", uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      if (req.uiUser) {
        await logoutAllSessions(req.uiUser.userId);
      }
      res.json({ success: true, message: "All sessions logged out" });
    } catch (error) {
      console.error("Logout all error:", error);
      res.status(500).json({ error: "Logout all sessions failed" });
    }
  });

  app.get("/ui/api/auth/session", uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      if (!req.uiUser) {
        return res.status(401).json({ error: "Not authenticated" });
      }

      const user = await storage.getUIUser(req.uiUser.userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const role = await storage.getUIRole(user.roleId);
      const permissions = getPermissionsForDbRole(user.roleId);
      const trialInfo = await getTrialInfo(user.tenantId);
      res.json({
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          roleId: user.roleId,
          role: role || undefined,
          permissions,
          tenantId: user.tenantId,
          organizationId: user.organizationId,
          lastLoginAt: user.lastLoginAt,
          lastActivityAt: user.lastActivityAt,
        },
        trial: trialInfo,
      });
    } catch (error) {
      console.error("Session fetch error:", error);
      res.status(500).json({ error: "Failed to fetch session" });
    }
  });

  // Debug: Check current user's permissions (temporary diagnostic endpoint)
  app.get("/ui/api/auth/debug-permissions", uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    const permissions = getPermissionsForDbRole(req.uiUser?.roleId || "");
    res.json({
      roleId: req.uiUser?.roleId,
      email: req.uiUser?.email,
      organizationId: req.uiUser?.organizationId,
      permissionCount: permissions.length,
      hasAgentsManage: permissions.includes("agents:manage" as any),
      hasAssetsRead: permissions.includes("assets:read" as any),
      permissions,
    });
  });

  // Admin-only: Register new users
  app.post("/ui/api/auth/register", uiAuthMiddleware, requireRole("org_owner", "security_admin"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const parsed = registerSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      }

      const { email, password, displayName, tenantId, organizationId, roleId } = parsed.data;

      // Validate roleId exists
      const targetRole = await storage.getUIRole(roleId);
      if (!targetRole) {
        return res.status(400).json({ error: "Invalid role ID" });
      }

      const existing = await storage.getUIUserByEmail(email, tenantId);
      if (existing) {
        return res.status(409).json({ error: "User with this email already exists" });
      }

      const passwordHash = await hashPassword(password);
      const user = await storage.createUIUser({
        email,
        passwordHash,
        displayName,
        tenantId,
        organizationId,
        roleId,
        status: "active",
      });

      const role = await storage.getUIRole(user.roleId);
      res.status(201).json({
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          roleId: user.roleId,
          role: role || undefined,
          tenantId: user.tenantId,
          organizationId: user.organizationId,
        },
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ error: "Failed to register user" });
    }
  });

  // Admin-only: List users in tenant
  app.get("/ui/api/users", uiAuthMiddleware, requireRole("org_owner", "security_admin"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const users = await storage.getUIUsers(tenantId);
      const roles = await storage.getUIRoles();
      const roleMap = new Map(roles.map(r => [r.id, r]));
      
      res.json({
        users: users.map(u => ({
          id: u.id,
          email: u.email,
          displayName: u.displayName,
          roleId: u.roleId,
          role: roleMap.get(u.roleId) || undefined,
          status: u.status,
          lastLoginAt: u.lastLoginAt,
          createdAt: u.createdAt,
        })),
      });
    } catch (error) {
      console.error("Fetch users error:", error);
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });

  // Seed initial admin user if none exists (bootstrap endpoint)
  app.post("/ui/api/auth/bootstrap", async (req, res) => {
    try {
      const users = await storage.getUIUsers("default");
      if (users.length > 0) {
        return res.status(403).json({ error: "Bootstrap already completed. Users exist." });
      }

      const parsed = registerSchema.safeParse({ ...req.body, roleId: "org_owner" });
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      }

      const user = await createInitialAdminUser(
        parsed.data.email,
        parsed.data.password,
        parsed.data.tenantId,
        parsed.data.organizationId
      );

      res.status(201).json({
        message: "Initial admin user created successfully",
        user: {
          id: user.id,
          email: user.email,
          roleId: user.roleId,
        },
      });
    } catch (error) {
      console.error("Bootstrap error:", error);
      res.status(500).json({ error: "Failed to bootstrap admin user" });
    }
  });

  // Get available roles
  app.get("/ui/api/roles", uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const roles = await storage.getUIRoles();
      res.json({ roles });
    } catch (error) {
      console.error("Fetch roles error:", error);
      res.status(500).json({ error: "Failed to fetch roles" });
    }
  });

  // ========== END UI AUTHENTICATION ==========
  // Rate limiting is applied per-endpoint (not globally) to avoid double-counting

  app.post("/api/aev/evaluate", evaluationRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const parsed = insertEvaluationSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error });
      }

      // Check kill switch before starting evaluation
      const orgId = parsed.data.organizationId || "default";
      const governance = await storage.getOrganizationGovernance(orgId);
      if (governance?.killSwitchActive) {
        await storage.createAuthorizationLog({
          organizationId: orgId,
          action: "unauthorized_target_blocked",
          details: { reason: "kill_switch_active", assetId: parsed.data.assetId },
          authorized: false,
          riskLevel: "high",
        });
        return res.status(403).json({ 
          error: "Operations halted", 
          message: "Kill switch is active. All evaluations are blocked until deactivated." 
        });
      }

      const evaluation = await storage.createEvaluation(parsed.data);
      
      res.json({ evaluationId: evaluation.id, assetId: evaluation.assetId, status: "started" });

      // Extract app logic data from request body if present (for app_logic exposure type)
      const appLogicData = req.body.appLogicData || undefined;

      runEvaluation(evaluation.id, {
        assetId: parsed.data.assetId,
        exposureType: parsed.data.exposureType,
        priority: parsed.data.priority || "medium",
        description: parsed.data.description,
        adversaryProfile: parsed.data.adversaryProfile || undefined,
        organizationId: parsed.data.organizationId || "default",
        appLogicData,
      }).catch(err => {
        console.error(`[AEV] Background evaluation ${evaluation.id} failed:`, err);
      });
    } catch (error) {
      console.error("Error starting evaluation:", error);
      res.status(500).json({ error: "Failed to start evaluation" });
    }
  });

  // ── AEV Chain Loop — multi-iteration exploit with persistent state ────
  app.post("/api/aev/chain-loop", evaluationRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const { evaluationId, assetId, description, exposureType, executionMode } = req.body;
      if (!evaluationId) {
        return res.status(400).json({ error: "evaluationId is required" });
      }
      const orgId = (req as any).uiUser?.organizationId || "default";
      const { runChainLoop } = await import("./services/agents/orchestrator");
      // Fire and forget — return immediately, run in background
      const context = {
        assetId: assetId || evaluationId,
        evaluationId,
        exposureType: exposureType || "network_vulnerability",
        priority: "high" as const,
        description: description || "Chain loop evaluation",
        organizationId: orgId,
        executionMode: executionMode || "simulation",
      };
      // Start async — don't await
      runChainLoop(context).catch(err => {
        console.error("[AEV] Chain loop failed:", err);
      });
      res.json({ evaluationId, status: "started", mode: "chain_loop" });
    } catch (error) {
      console.error("[AEV] Failed to start chain loop:", error);
      res.status(500).json({ error: "Failed to start chain loop" });
    }
  });

  // ── AEV Telemetry — query run data for an evaluation ──────────────────
  app.get("/api/aev/runs/:evaluationId", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const { aevRuns, aevToolCalls, aevLlmTurns, aevFailures } = await import("@shared/schema");
      const { eq } = await import("drizzle-orm");
      const runs = await db.select().from(aevRuns).where(eq(aevRuns.evaluationId, evaluationId));
      if (runs.length === 0) {
        return res.json({ runs: [], toolCalls: [], llmTurns: [], failures: [] });
      }
      const runIds = runs.map(r => r.id);
      const { inArray } = await import("drizzle-orm");
      const [toolCalls, llmTurns, failures] = await Promise.all([
        db.select().from(aevToolCalls).where(inArray(aevToolCalls.runId, runIds)),
        db.select().from(aevLlmTurns).where(inArray(aevLlmTurns.runId, runIds)),
        db.select().from(aevFailures).where(inArray(aevFailures.runId, runIds)),
      ]);
      res.json({ runs, toolCalls, llmTurns, failures });
    } catch (error) {
      console.error("[AEV] Failed to fetch telemetry:", error);
      res.status(500).json({ error: "Failed to fetch telemetry data" });
    }
  });

  // ── AEV Telemetry — single run detail with nested tool calls, LLM turns, failures
  app.get("/api/aev/run-detail/:runId", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { runId } = req.params;
      const { aevRuns, aevToolCalls, aevLlmTurns, aevFailures } = await import("@shared/schema");
      const { eq } = await import("drizzle-orm");
      const [run] = await db.select().from(aevRuns).where(eq(aevRuns.id, runId));
      if (!run) return res.status(404).json({ error: "Run not found" });
      const [toolCalls, llmTurns, failures] = await Promise.all([
        db.select().from(aevToolCalls).where(eq(aevToolCalls.runId, runId)),
        db.select().from(aevLlmTurns).where(eq(aevLlmTurns.runId, runId)),
        db.select().from(aevFailures).where(eq(aevFailures.runId, runId)),
      ]);
      res.json({ run, toolCalls, llmTurns, failures });
    } catch (error) {
      console.error("[AEV] Failed to fetch run detail:", error);
      res.status(500).json({ error: "Failed to fetch run detail" });
    }
  });

  app.get("/api/aev/evaluations", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
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

  app.get("/api/aev/evaluations/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
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
        debateSummary: result?.debateSummary,
        duration: result?.duration,
      });
    } catch (error) {
      console.error("Error fetching evaluation:", error);
      res.status(500).json({ error: "Failed to fetch evaluation" });
    }
  });
  app.get("/api/aev/evaluations/:id/progress", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const evaluation = await storage.getEvaluation(req.params.id);
      if (!evaluation) {
        return res.status(404).json({ error: "Evaluation not found" });
      }
      res.json({
        status: evaluation.status,
        phaseProgress: evaluation.phaseProgress || [],
        createdAt: evaluation.createdAt,
        updatedAt: evaluation.updatedAt,
      });
    } catch (error) {
      console.error("Error fetching evaluation progress:", error);
      res.status(500).json({ error: "Failed to fetch evaluation progress" });
    }
  });

  app.delete("/api/aev/evaluations/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:delete"), async (req, res) => {
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

  app.patch("/api/aev/evaluations/:id/archive", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:archive"), async (req, res) => {
    try {
      const evaluationId = req.params.id;
      const evaluation = await storage.getEvaluation(evaluationId);
      
      if (!evaluation) {
        return res.status(404).json({ error: "Evaluation not found" });
      }

      await storage.updateEvaluationStatus(evaluationId, "archived");
      
      res.json({ success: true, message: "Evaluation archived successfully" });
    } catch (error) {
      console.error("Error archiving evaluation:", error);
      res.status(500).json({ error: "Failed to archive evaluation" });
    }
  });

  app.patch("/api/aev/evaluations/:id/unarchive", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:archive"), async (req, res) => {
    try {
      const evaluationId = req.params.id;
      const evaluation = await storage.getEvaluation(evaluationId);
      
      if (!evaluation) {
        return res.status(404).json({ error: "Evaluation not found" });
      }

      await storage.updateEvaluationStatus(evaluationId, "completed");
      
      res.json({ success: true, message: "Evaluation restored successfully" });
    } catch (error) {
      console.error("Error restoring evaluation:", error);
      res.status(500).json({ error: "Failed to restore evaluation" });
    }
  });

  // Live scan results endpoints
  app.get("/api/aev/live-scans", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const results = await storage.getLiveScanResults(organizationId);
      res.json(results);
    } catch (error) {
      console.error("Error fetching live scan results:", error);
      res.status(500).json({ error: "Failed to fetch live scan results" });
    }
  });

  app.get("/api/aev/live-scans/:evaluationId", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const result = await storage.getLiveScanResultByEvaluationId(req.params.evaluationId);
      if (!result) {
        return res.status(404).json({ error: "Live scan result not found" });
      }
      res.json(result);
    } catch (error) {
      console.error("Error fetching live scan result:", error);
      res.status(500).json({ error: "Failed to fetch live scan result" });
    }
  });

  // Abort a running live scan (core-v2: live-network-testing removed, stub only)
  app.post("/api/aev/live-scans/:evaluationId/abort", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (_req, res) => {
    res.json({ success: false, message: "Live network scan service not available in core-v2 build" });
  });

  app.get("/api/aev/stats", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
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

      // Telemetry aggregates from aev_runs + aev_failures
      const { aevRuns, aevFailures } = await import("@shared/schema");
      const allRuns = await db.select().from(aevRuns);
      const allFailures = await db.select().from(aevFailures);

      const stopReasonDist: Record<string, number> = {};
      let totalDurationMs = 0;
      let runsWithDuration = 0;
      for (const run of allRuns) {
        if (run.stopReason) stopReasonDist[run.stopReason] = (stopReasonDist[run.stopReason] || 0) + 1;
        if (run.durationMs) { totalDurationMs += run.durationMs; runsWithDuration++; }
      }

      const failureCodeDist: Record<string, number> = {};
      for (const f of allFailures) {
        if (f.failureCode) failureCodeDist[f.failureCode] = (failureCodeDist[f.failureCode] || 0) + 1;
      }

      res.json({
        total: evaluations.length,
        active: evaluations.filter(e => e.status === "pending" || e.status === "in_progress").length,
        completed: evaluations.filter(e => e.status === "completed").length,
        exploitable: exploitableCount,
        safe: safeCount,
        avgConfidence,
        telemetry: {
          totalRuns: allRuns.length,
          avgDurationMs: runsWithDuration > 0 ? Math.round(totalDurationMs / runsWithDuration) : 0,
          stopReasonDistribution: stopReasonDist,
          failureCodePareto: failureCodeDist,
        },
      });
    } catch (error) {
      console.error("Error fetching stats:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  // ========== EXECUTION MODE ENDPOINTS ==========
  
  app.get("/api/aev/execution-modes", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { 
        getExecutionModeSummary, 
        executionModeEnforcer 
      } = await import("./services/validation/execution-modes");
      
      const tenantId = req.query.tenantId as string || "default";
      const currentMode = executionModeEnforcer.getMode(tenantId);
      
      const modes = ["safe", "simulation", "live"] as const;
      const summaries = modes.map(mode => ({
        ...getExecutionModeSummary(mode),
        isCurrent: mode === currentMode,
      }));
      
      res.json({
        currentMode,
        tenantId,
        modes: summaries,
      });
    } catch (error) {
      console.error("Error fetching execution modes:", error);
      res.status(500).json({ error: "Failed to fetch execution modes" });
    }
  });
  
  app.get("/api/aev/execution-modes/current", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { 
        getExecutionModeSummary, 
        getExecutionModeConfig,
        executionModeEnforcer 
      } = await import("./services/validation/execution-modes");
      
      const tenantId = req.query.tenantId as string || "default";
      const currentMode = executionModeEnforcer.getMode(tenantId);
      const config = getExecutionModeConfig(currentMode);
      const summary = getExecutionModeSummary(currentMode);
      
      res.json({
        mode: currentMode,
        tenantId,
        summary,
        config,
      });
    } catch (error) {
      console.error("Error fetching current execution mode:", error);
      res.status(500).json({ error: "Failed to fetch current execution mode" });
    }
  });
  
  app.post("/api/aev/execution-modes/set", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:manage"), async (req, res) => {
    try {
      const { 
        executionModeEnforcer,
        validateModeTransition,
        getExecutionModeSummary,
      } = await import("./services/validation/execution-modes");
      
      const { mode, tenantId = "default", durationMinutes, reason } = req.body;
      
      if (!mode || !["safe", "simulation", "live"].includes(mode)) {
        return res.status(400).json({ error: "Invalid mode. Must be 'safe', 'simulation', or 'live'" });
      }
      
      const currentMode = executionModeEnforcer.getMode(tenantId);
      
      const transitionResult = validateModeTransition({
        fromMode: currentMode,
        toMode: mode,
        requestedBy: "api",
        reason: reason || "Mode change requested via API",
        targetScope: [tenantId],
        duration: durationMinutes || 60,
      });
      
      if (!transitionResult.allowed) {
        return res.status(403).json({ 
          error: transitionResult.reason,
          allowed: false,
        });
      }
      
      if (transitionResult.requiresApproval) {
        return res.status(202).json({
          status: "pending_approval",
          message: transitionResult.reason,
          approvalLevel: transitionResult.approvalLevel,
          currentMode,
          requestedMode: mode,
        });
      }
      
      if (durationMinutes && durationMinutes > 0) {
        executionModeEnforcer.setTenantOverride(tenantId, mode, durationMinutes);
      } else {
        executionModeEnforcer.setMode(mode);
      }
      
      console.log(`[ExecutionMode] Mode changed: ${currentMode} -> ${mode} for tenant ${tenantId}`);
      
      res.json({
        success: true,
        previousMode: currentMode,
        newMode: mode,
        tenantId,
        durationMinutes: durationMinutes || "permanent",
        summary: getExecutionModeSummary(mode),
      });
    } catch (error) {
      console.error("Error setting execution mode:", error);
      res.status(500).json({ error: "Failed to set execution mode" });
    }
  });
  
  app.post("/api/aev/execution-modes/validate-operation", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const { 
        validateOperation,
        executionModeEnforcer,
      } = await import("./services/validation/execution-modes");
      
      const { operation, target, tenantId = "default" } = req.body;
      
      const validOperations = [
        "bannerGrabbing", "versionDetection", "portScanning", 
        "credentialTesting", "payloadInjection", "exploitExecution", "dataExfiltration"
      ];
      
      if (!operation || !validOperations.includes(operation)) {
        return res.status(400).json({ 
          error: `Invalid operation. Must be one of: ${validOperations.join(", ")}` 
        });
      }
      
      const mode = executionModeEnforcer.getMode(tenantId);
      const result = validateOperation(mode, operation, target);
      
      res.json({
        mode,
        operation,
        target,
        ...result,
      });
    } catch (error) {
      console.error("Error validating operation:", error);
      res.status(500).json({ error: "Failed to validate operation" });
    }
  });

  // ========== APPROVAL WORKFLOW ENDPOINTS ==========
  
  app.get("/api/aev/approval-requests", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { approvalWorkflowService } = await import("./services/validation/audit-service");
      const organizationId = req.query.organizationId as string || "default";
      const requiredLevel = req.query.requiredLevel as string | undefined;
      
      const requests = await approvalWorkflowService.getPendingApprovals(
        organizationId, 
        requiredLevel as any
      );
      
      res.json({ requests });
    } catch (error) {
      console.error("Error fetching approval requests:", error);
      res.status(500).json({ error: "Failed to fetch approval requests" });
    }
  });
  
  app.get("/api/aev/approval-requests/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { approvalWorkflowService } = await import("./services/validation/audit-service");
      const request = await approvalWorkflowService.getApprovalRequest(req.params.id);
      
      if (!request) {
        return res.status(404).json({ error: "Approval request not found" });
      }
      
      res.json(request);
    } catch (error) {
      console.error("Error fetching approval request:", error);
      res.status(500).json({ error: "Failed to fetch approval request" });
    }
  });
  
  app.post("/api/aev/approval-requests", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:approve_live"), async (req, res) => {
    try {
      const { approvalWorkflowService } = await import("./services/validation/audit-service");
      
      const {
        requestType,
        requiredLevel,
        organizationId = "default",
        tenantId = "default",
        requestedBy,
        requestedByName,
        targetHost,
        targetScope,
        executionMode,
        operationType,
        justification,
        riskAssessment,
        estimatedImpact,
        durationMinutes,
      } = req.body;
      
      if (!requestType || !requiredLevel || !justification) {
        return res.status(400).json({ 
          error: "Missing required fields: requestType, requiredLevel, justification" 
        });
      }
      
      const request = await approvalWorkflowService.createApprovalRequest(
        requestType,
        requiredLevel,
        {
          organizationId,
          tenantId,
          requestedBy,
          requestedByName,
          targetHost,
          targetScope,
          executionMode,
          operationType,
          justification,
          riskAssessment,
          estimatedImpact,
          durationMinutes,
        }
      );
      
      res.status(201).json(request);
    } catch (error) {
      console.error("Error creating approval request:", error);
      res.status(500).json({ error: "Failed to create approval request" });
    }
  });
  
  app.post("/api/aev/approval-requests/:id/approve", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:approve_live"), async (req, res) => {
    try {
      const { approvalWorkflowService } = await import("./services/validation/audit-service");
      const { approverId, approverName, notes } = req.body;
      
      if (!approverId || !approverName) {
        return res.status(400).json({ error: "Missing required fields: approverId, approverName" });
      }
      
      const updated = await approvalWorkflowService.approveRequest(
        req.params.id,
        approverId,
        approverName,
        notes
      );
      
      res.json(updated);
    } catch (error: any) {
      console.error("Error approving request:", error);
      res.status(400).json({ error: error.message || "Failed to approve request" });
    }
  });
  
  app.post("/api/aev/approval-requests/:id/deny", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:approve_live"), async (req, res) => {
    try {
      const { approvalWorkflowService } = await import("./services/validation/audit-service");
      const { denierId, denierName, reason } = req.body;
      
      if (!denierId || !denierName || !reason) {
        return res.status(400).json({ error: "Missing required fields: denierId, denierName, reason" });
      }
      
      const updated = await approvalWorkflowService.denyRequest(
        req.params.id,
        denierId,
        denierName,
        reason
      );
      
      res.json(updated);
    } catch (error: any) {
      console.error("Error denying request:", error);
      res.status(400).json({ error: error.message || "Failed to deny request" });
    }
  });
  
  app.post("/api/aev/approval-requests/:id/cancel", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const { approvalWorkflowService } = await import("./services/validation/audit-service");
      const { cancelledBy } = req.body;
      
      const updated = await approvalWorkflowService.cancelRequest(req.params.id, cancelledBy || "unknown");
      res.json(updated);
    } catch (error: any) {
      console.error("Error cancelling request:", error);
      res.status(400).json({ error: error.message || "Failed to cancel request" });
    }
  });

  // ========== VALIDATION AUDIT LOG ENDPOINTS ==========
  
  app.get("/api/aev/audit-logs", apiRateLimiter, uiAuthMiddleware, requirePermission("audit:read"), async (req, res) => {
    try {
      const { auditService } = await import("./services/validation/audit-service");
      const organizationId = req.query.organizationId as string || "default";
      const limit = parseInt(req.query.limit as string) || 100;
      const action = req.query.action as string | undefined;
      const executionMode = req.query.executionMode as string | undefined;
      
      const logs = await auditService.getAuditLogs(organizationId, {
        limit,
        action: action as any,
        executionMode: executionMode as any,
      });
      
      res.json({ logs, total: logs.length });
    } catch (error) {
      console.error("Error fetching audit logs:", error);
      res.status(500).json({ error: "Failed to fetch audit logs" });
    }
  });
  
  app.get("/api/aev/audit-logs/stats", apiRateLimiter, uiAuthMiddleware, requirePermission("audit:read"), async (req, res) => {
    try {
      const { auditService } = await import("./services/validation/audit-service");
      const organizationId = req.query.organizationId as string || "default";

      const logs = await auditService.getAuditLogs(organizationId, { limit: 10000 });

      const now = new Date();
      const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

      const today = logs.filter(l => new Date(l.createdAt) >= todayStart).length;
      const critical = logs.filter(l => l.riskLevel === "critical").length;
      const uniqueUsers = new Set(logs.map(l => l.requestedBy).filter(Boolean)).size;

      res.json({
        total: logs.length,
        today,
        critical,
        uniqueUsers,
      });
    } catch (error) {
      console.error("Error fetching audit log stats:", error);
      res.status(500).json({ error: "Failed to fetch audit log stats" });
    }
  });

  app.get("/api/aev/audit-logs/verify", apiRateLimiter, uiAuthMiddleware, requirePermission("audit:read"), async (req, res) => {
    try {
      const { auditService } = await import("./services/validation/audit-service");
      const organizationId = req.query.organizationId as string || "default";
      
      const verification = await auditService.verifyAuditIntegrity(organizationId);
      
      res.json(verification);
    } catch (error) {
      console.error("Error verifying audit integrity:", error);
      res.status(500).json({ error: "Failed to verify audit integrity" });
    }
  });

  // ========== SANDBOX EXECUTION ENDPOINTS ==========
  
  app.get("/api/aev/sandbox/config", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:read"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const tenantId = req.query.tenantId as string || "default";
      
      const config = sandboxExecutor.getTenantConfig(tenantId);
      res.json(config);
    } catch (error) {
      console.error("Error fetching sandbox config:", error);
      res.status(500).json({ error: "Failed to fetch sandbox config" });
    }
  });
  
  app.put("/api/aev/sandbox/config", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:manage"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { tenantId, ...config } = req.body;
      
      if (tenantId) {
        sandboxExecutor.setTenantConfig(tenantId, config);
      } else {
        sandboxExecutor.setConfig(config);
      }
      
      res.json({ success: true, config: sandboxExecutor.getTenantConfig(tenantId || "default") });
    } catch (error) {
      console.error("Error updating sandbox config:", error);
      res.status(500).json({ error: "Failed to update sandbox config" });
    }
  });
  
  app.get("/api/aev/sandbox/stats", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const tenantId = req.query.tenantId as string | undefined;
      
      const stats = sandboxExecutor.getStats(tenantId);
      const activeOperations = sandboxExecutor.getActiveOperations(tenantId);
      
      res.json({ stats, activeOperations });
    } catch (error) {
      console.error("Error fetching sandbox stats:", error);
      res.status(500).json({ error: "Failed to fetch sandbox stats" });
    }
  });
  
  app.get("/api/aev/sandbox/kill-switch", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:read"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const state = sandboxExecutor.getKillSwitchState();
      res.json(state);
    } catch (error) {
      console.error("Error fetching kill switch state:", error);
      res.status(500).json({ error: "Failed to fetch kill switch state" });
    }
  });
  
  app.post("/api/aev/sandbox/kill-switch/engage", apiRateLimiter, uiAuthMiddleware, requirePermission("platform:emergency_access"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { scope = "global", reason, engagedBy, affectedTenants, affectedOperations } = req.body;
      
      if (!reason || !engagedBy) {
        return res.status(400).json({ error: "Missing required fields: reason, engagedBy" });
      }
      
      const state = sandboxExecutor.engageKillSwitch({
        scope,
        reason,
        engagedBy,
        affectedTenants,
        affectedOperations,
      });
      
      res.json({ success: true, state });
    } catch (error) {
      console.error("Error engaging kill switch:", error);
      res.status(500).json({ error: "Failed to engage kill switch" });
    }
  });
  
  app.post("/api/aev/sandbox/kill-switch/disengage", apiRateLimiter, uiAuthMiddleware, requirePermission("platform:emergency_access"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { disengagedBy } = req.body;
      
      if (!disengagedBy) {
        return res.status(400).json({ error: "Missing required field: disengagedBy" });
      }
      
      const state = sandboxExecutor.disengageKillSwitch(disengagedBy);
      res.json({ success: true, state });
    } catch (error) {
      console.error("Error disengaging kill switch:", error);
      res.status(500).json({ error: "Failed to disengage kill switch" });
    }
  });
  
  app.post("/api/aev/sandbox/abort/:operationId", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { reason } = req.body;
      
      const aborted = sandboxExecutor.abortOperation(req.params.operationId, reason || "Manually aborted");
      
      if (!aborted) {
        return res.status(404).json({ error: "Operation not found or not running" });
      }
      
      res.json({ success: true, operationId: req.params.operationId });
    } catch (error) {
      console.error("Error aborting operation:", error);
      res.status(500).json({ error: "Failed to abort operation" });
    }
  });
  
  app.post("/api/aev/sandbox/abort-all", apiRateLimiter, uiAuthMiddleware, requirePermission("platform:emergency_access"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { tenantId, reason } = req.body;
      
      const count = sandboxExecutor.abortAllOperations(tenantId, reason || "All operations aborted");
      res.json({ success: true, abortedCount: count });
    } catch (error) {
      console.error("Error aborting all operations:", error);
      res.status(500).json({ error: "Failed to abort all operations" });
    }
  });
  
  app.post("/api/aev/sandbox/validate-target", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { target, tenantId = "default" } = req.body;
      
      if (!target) {
        return res.status(400).json({ error: "Missing required field: target" });
      }
      
      const result = sandboxExecutor.validateTarget(target, tenantId);
      res.json(result);
    } catch (error) {
      console.error("Error validating target:", error);
      res.status(500).json({ error: "Failed to validate target" });
    }
  });
  
  app.post("/api/aev/sandbox/check-limits", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const { tenantId = "default" } = req.body;
      
      const rateCheck = sandboxExecutor.checkRateLimits(tenantId);
      const concurrencyCheck = sandboxExecutor.checkConcurrencyLimits(tenantId);
      const killSwitchEngaged = sandboxExecutor.isKillSwitchEngaged(tenantId);
      
      res.json({
        rateLimits: rateCheck,
        concurrencyLimits: concurrencyCheck,
        killSwitchEngaged,
      });
    } catch (error) {
      console.error("Error checking limits:", error);
      res.status(500).json({ error: "Failed to check limits" });
    }
  });

  // ========== SYSTEM MONITORING ENDPOINTS ==========

  // Real system health status — replaces hardcoded mock data on the System Health page
  const serverStartTime = Date.now();

  app.get("/api/system/health-status", apiRateLimiter, uiAuthMiddleware, async (req, res) => {
    try {
      const checks: {
        name: string;
        status: "healthy" | "degraded" | "down";
        responseTime?: number;
        message?: string;
      }[] = [];

      // 1. PostgreSQL check
      const dbStart = Date.now();
      try {
        await db.execute(sql`SELECT 1`);
        checks.push({
          name: "PostgreSQL Database",
          status: "healthy",
          responseTime: Date.now() - dbStart,
        });
      } catch (err: any) {
        checks.push({
          name: "PostgreSQL Database",
          status: "down",
          responseTime: Date.now() - dbStart,
          message: err.message || "Connection failed",
        });
      }

      // 2. Redis check
      const redisStart = Date.now();
      const redisUp = queueService.isUsingRedis();
      checks.push({
        name: "Redis Cache",
        status: redisUp ? "healthy" : "degraded",
        responseTime: Date.now() - redisStart,
        message: redisUp ? undefined : "Using in-memory fallback",
      });

      // 3. WebSocket server check
      const wsStats = wsService.getStats();
      checks.push({
        name: "WebSocket Server",
        status: "healthy",
        message: `${wsStats.activeConnections} active connections`,
      });

      // 4. S3 / MinIO storage check
      const s3Start = Date.now();
      try {
        await storageService.exists("__health_probe__");
        checks.push({
          name: "S3 Storage",
          status: "healthy",
          responseTime: Date.now() - s3Start,
        });
      } catch (err: any) {
        // HeadObject 404 = connection works, object just doesn't exist
        if (err.name === "NotFound" || err.$metadata?.httpStatusCode === 404) {
          checks.push({
            name: "S3 Storage",
            status: "healthy",
            responseTime: Date.now() - s3Start,
          });
        } else {
          checks.push({
            name: "S3 Storage",
            status: "down",
            responseTime: Date.now() - s3Start,
            message: err.message || "Connection failed",
          });
        }
      }

      // 5. Job Queue check
      const queueStats = await queueService.getQueueStats();
      const queueBacklog = queueStats.waiting + queueStats.active;
      checks.push({
        name: "Job Queue",
        status: queueBacklog > 100 ? "degraded" : "healthy",
        message: `${queueStats.active} running, ${queueStats.waiting} pending`,
      });

      // Compute overall uptime
      const uptimeMs = Date.now() - serverStartTime;
      const uptimeHours = Math.floor(uptimeMs / (1000 * 60 * 60));
      const uptimeMinutes = Math.floor((uptimeMs % (1000 * 60 * 60)) / (1000 * 60));

      const version = process.env.npm_package_version || "1.0.0";

      res.json({
        components: checks,
        uptime: {
          ms: uptimeMs,
          hours: uptimeHours,
          minutes: uptimeMinutes,
          formatted: uptimeHours > 0 ? `${uptimeHours}h ${uptimeMinutes}m` : `${uptimeMinutes}m`,
        },
        version,
        ts: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Error fetching system health:", error);
      res.status(500).json({ error: "Failed to fetch system health" });
    }
  });

  app.get("/api/system/websocket-stats", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const stats = wsService.getStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching WebSocket stats:", error);
      res.status(500).json({ error: "Failed to fetch WebSocket stats" });
    }
  });

  // ========== REPORTING ENDPOINTS ==========

  function formatServerDTG(d: Date): string {
    const DTG_MONTHS = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
    const day = String(d.getUTCDate()).padStart(2, '0');
    const hours = String(d.getUTCHours()).padStart(2, '0');
    const minutes = String(d.getUTCMinutes()).padStart(2, '0');
    const month = DTG_MONTHS[d.getUTCMonth()];
    const year = String(d.getUTCFullYear()).slice(-2);
    return `${day}${hours}${minutes}Z${month}${year}`;
  }

  app.post("/api/reports/generate", reportRateLimiter, uiAuthMiddleware, requirePermission("reports:generate"), async (req, res) => {
    try {
      const { type, format, from, to, framework, organizationId = "default", evaluationId, engagementMetadata, breachChainId } = req.body;

      // If breachChainId is provided, generate report from breach chain data
      if (breachChainId) {
        const chain = await storage.getBreachChain(breachChainId);
        if (!chain) {
          return res.status(404).json({ error: `Breach chain ${breachChainId} not found` });
        }

        const executionMode = (chain.config as any)?.executionMode || "safe";
        const chainStart = chain.startedAt ? new Date(chain.startedAt) : (chain.createdAt ? new Date(chain.createdAt) : new Date());
        const chainEnd = chain.completedAt ? new Date(chain.completedAt) : new Date();
        const durationMin = chain.durationMs ? Math.round(chain.durationMs / 60000) : Math.round((chainEnd.getTime() - chainStart.getTime()) / 60000);

        // Build findings from phase results
        const findings: any[] = [];
        const phaseNames: string[] = [];
        if (Array.isArray(chain.phaseResults)) {
          for (const phase of chain.phaseResults) {
            const phaseFriendly = (phase.phaseName || "unknown").replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());
            phaseNames.push(phaseFriendly);
            if (phase.findings) {
              for (const f of phase.findings) {
                findings.push({
                  id: f.id,
                  title: f.title,
                  severity: f.severity,
                  description: f.description,
                  technique: f.technique || "",
                  phase: phaseFriendly,
                  mitreId: f.mitreId,
                  recommendation: f.severity === "critical"
                    ? "Immediate remediation required. Isolate affected systems and apply emergency patches within 48 hours."
                    : f.severity === "high"
                    ? "Prioritize remediation within 30 days. Implement compensating controls in the interim."
                    : "Schedule remediation within the next assessment cycle. Monitor for exploitation attempts.",
                });
              }
            }
          }
        }

        // Sort findings: critical first, then high, medium, low
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
        findings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
        for (const f of findings) {
          const sev = f.severity as keyof typeof severityCounts;
          if (sev in severityCounts) severityCounts[sev]++;
        }

        const riskScore = chain.overallRiskScore || 0;
        const assetsCompromised = chain.totalAssetsCompromised || 0;
        const credsHarvested = chain.totalCredentialsHarvested || 0;
        const maxPrivilege = chain.maxPrivilegeAchieved || "none";
        const domainsBreached = Array.isArray(chain.domainsBreached) ? chain.domainsBreached : [];
        const targetCount = chain.assetIds?.length || 0;

        // Risk tier
        const riskTier = riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 40 ? "MODERATE" : "LOW";
        const riskColor = riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 40 ? "medium" : "low";

        // Build executive summary narrative
        const execParts: string[] = [];
        execParts.push(
          `OdinForge conducted a cross-domain breach chain simulation against ${targetCount} target asset${targetCount !== 1 ? "s" : ""} operating in ${executionMode} mode. The assessment executed ${phaseNames.length} attack phases over a period of ${durationMin} minute${durationMin !== 1 ? "s" : ""}, simulating a real-world adversary's lateral progression through the environment.`
        );

        if (findings.length > 0) {
          execParts.push(
            `The simulation identified ${findings.length} security finding${findings.length !== 1 ? "s" : ""} across the kill chain, including ${severityCounts.critical} critical and ${severityCounts.high} high-severity issue${severityCounts.critical + severityCounts.high !== 1 ? "s" : ""}. ${assetsCompromised > 0 ? `${assetsCompromised} asset${assetsCompromised !== 1 ? "s were" : " was"} compromised during the simulation, ` : ""}${credsHarvested > 0 ? `with ${credsHarvested} credential${credsHarvested !== 1 ? "s" : ""} harvested. ` : ""}${maxPrivilege !== "none" ? `The highest privilege level achieved was ${maxPrivilege.replace(/_/g, " ")}.` : ""}`
          );
        } else {
          execParts.push(
            "No exploitable vulnerabilities were confirmed during this assessment. The target environment demonstrated adequate defensive controls against the simulated attack scenarios."
          );
        }

        if (domainsBreached.length > 0) {
          execParts.push(
            `The attacker successfully traversed ${domainsBreached.length} security domain${domainsBreached.length !== 1 ? "s" : ""}: ${domainsBreached.map(d => d.replace(/_/g, " ")).join(", ")}. This indicates gaps in segmentation controls that could enable an adversary to escalate from initial compromise to full environment control.`
          );
        }

        const overallRisk = riskScore >= 80
          ? "The overall risk posture is CRITICAL. Immediate action is required to remediate the identified attack paths. The demonstrated breach chain represents a realistic threat scenario with high likelihood of exploitation by a motivated adversary."
          : riskScore >= 60
          ? "The overall risk posture is HIGH. Significant security gaps were identified that could be exploited by a skilled adversary. Prioritized remediation is recommended within 30 days, with compensating controls deployed immediately."
          : riskScore >= 40
          ? "The overall risk posture is MODERATE. While the environment demonstrates some defensive capabilities, identified weaknesses could be chained together by a persistent adversary. Remediation should be planned within the next assessment cycle."
          : "The overall risk posture is LOW. The target environment demonstrated strong defensive controls. Continue regular assessment cycles and monitor for emerging threats.";
        execParts.push(overallRisk);

        // Build chain-specific narrative if available, otherwise use generated
        const executiveSummary = chain.executiveSummary || execParts.join("\n\n");

        // Key metrics for dashboard display
        const keyMetrics: Record<string, string | number> = {
          "Overall Risk Score": `${riskScore}/100 (${riskTier})`,
          "Total Findings": findings.length,
          "Critical Findings": severityCounts.critical,
          "High Findings": severityCounts.high,
          "Assets Compromised": assetsCompromised,
          "Credentials Harvested": credsHarvested,
          "Max Privilege Achieved": maxPrivilege.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase()),
          "Domains Breached": domainsBreached.length,
          "Assessment Duration": `${durationMin} min`,
          "Execution Mode": executionMode.replace(/\b\w/g, (c: string) => c.toUpperCase()),
        };

        // Build recommendations
        const recommendations: any[] = [];
        if (severityCounts.critical > 0) {
          recommendations.push({
            priority: 1,
            action: `Immediately remediate ${severityCounts.critical} critical finding${severityCounts.critical !== 1 ? "s" : ""}. Isolate affected assets and deploy emergency patches within 48 hours.`,
            impact: "Eliminates highest-risk attack vectors",
          });
        }
        if (severityCounts.high > 0) {
          recommendations.push({
            priority: recommendations.length + 1,
            action: `Prioritize remediation of ${severityCounts.high} high-severity finding${severityCounts.high !== 1 ? "s" : ""} within 30 days. Implement compensating controls (WAF rules, network segmentation) in the interim.`,
            impact: "Reduces exploitable attack surface",
          });
        }
        if (domainsBreached.length > 1) {
          recommendations.push({
            priority: recommendations.length + 1,
            action: "Implement network segmentation and zero-trust architecture to prevent cross-domain lateral movement. Review firewall rules and access policies between security zones.",
            impact: "Prevents attacker progression across domains",
          });
        }
        if (credsHarvested > 0) {
          recommendations.push({
            priority: recommendations.length + 1,
            action: "Rotate all compromised credentials immediately. Implement MFA across all administrative interfaces and enforce credential complexity policies.",
            impact: "Eliminates harvested credential risk",
          });
        }
        recommendations.push({
          priority: recommendations.length + 1,
          action: "Conduct follow-up breach chain simulation in 90 days to validate remediation effectiveness and identify newly introduced risks.",
          impact: "Continuous security posture improvement",
        });

        // Build top risks from highest-severity findings
        const topRisks = findings.slice(0, 5).map(f => ({
          severity: f.severity,
          assetId: chain.assetIds?.[0] || "Target",
          riskDescription: `${f.title} — ${f.description}`,
          financialImpact: f.severity === "critical" ? "High" : f.severity === "high" ? "Significant" : "Moderate",
        }));

        // Build attack paths from phase progression
        const attackPaths = Array.isArray(chain.phaseResults)
          ? chain.phaseResults
              .filter(p => p.findings && p.findings.length > 0)
              .map((p, idx) => ({
                assetId: chain.assetIds?.[0] || "Target",
                complexity: p.findings && p.findings.length > 5 ? "Complex" : p.findings && p.findings.length > 2 ? "Moderate" : "Low",
                timeToCompromise: p.durationMs ? `${Math.round(p.durationMs / 1000)}s` : undefined,
                steps: (p.findings || []).slice(0, 5).map((f: any, i: number) => ({
                  order: i + 1,
                  technique: f.technique || f.title,
                  description: f.description,
                })),
              }))
          : [];

        // Risk breakdown for charts
        const riskBreakdown = {
          Critical: severityCounts.critical,
          High: severityCounts.high,
          Medium: severityCounts.medium,
          Low: severityCounts.low,
        };

        // Phase execution summary
        const phases = Array.isArray(chain.phaseResults)
          ? chain.phaseResults.map(p => ({
              name: (p.phaseName || "unknown").replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase()),
              status: p.status,
              findingCount: p.findings?.length || 0,
              durationMs: p.durationMs || 0,
            }))
          : [];

        const reportData = {
          reportType: "breach_chain",
          chainId: chain.id,
          chainName: chain.name,

          // Standard report fields (rendered by preview + PDF builder)
          executiveSummary,
          keyMetrics,
          findings,
          recommendations,
          topRisks,
          attackPaths,
          riskBreakdown,

          // Breach-chain-specific data
          overallRiskScore: riskScore,
          riskTier,
          executionMode,
          targets: chain.assetIds,
          targetDomains: chain.targetDomains || [],
          assetsCompromised,
          credentialsHarvested: credsHarvested,
          maxPrivilegeAchieved: maxPrivilege,
          domainsBreached,
          phases,
          attackGraph: chain.unifiedAttackGraph || null,
          durationMs: chain.durationMs || 0,
        };

        const title = `Cross-Domain Breach Chain Assessment — ${chain.name}`;

        const report = await storage.createReport({
          reportType: "breach_chain",
          title,
          organizationId: chain.organizationId || organizationId,
          status: "completed",
          content: reportData,
          dateRangeFrom: chainStart,
          dateRangeTo: chainEnd,
          engagementMetadata,
        });

        return res.json({
          reportId: report.id,
          title,
          data: reportData,
          content: JSON.stringify(reportData),
          contentType: "application/json",
        });
      }

      // If evaluationId is provided, generate single-evaluation report
      if (evaluationId) {
        if (!type || !format) {
          return res.status(400).json({ error: "Missing required fields: type, format" });
        }

        // Fetch evaluation to get its createdAt for the report date range
        const evaluation = await storage.getEvaluation(evaluationId);
        const evalDate = evaluation?.createdAt ? new Date(evaluation.createdAt) : new Date();

        let reportData: any;
        let title = "";
        
        switch (type) {
          case "executive_summary":
            reportData = await reportGenerator.generateSingleEvaluationExecutiveSummary(evaluationId);
            title = `Executive Summary - Evaluation ${evaluationId}`;
            break;
          case "technical_deep_dive":
            reportData = await reportGenerator.generateSingleEvaluationTechnicalReport(evaluationId);
            title = `Technical Report - Evaluation ${evaluationId}`;
            break;
          case "compliance_mapping":
            if (!framework) {
              return res.status(400).json({ error: "Compliance reports require a framework parameter" });
            }
            if (!complianceFrameworks.includes(framework)) {
              return res.status(400).json({ error: `Invalid framework. Valid options: ${complianceFrameworks.join(", ")}` });
            }
            reportData = await reportGenerator.generateSingleEvaluationComplianceReport(evaluationId, framework);
            title = `Compliance Report (${framework.toUpperCase()}) - Evaluation ${evaluationId}`;
            break;
          default:
            return res.status(400).json({ error: "Invalid report type" });
        }
        
        let content: string;
        let contentType: string;
        
        switch (format) {
          case "json":
            content = reportGenerator.exportToJSON(reportData);
            contentType = "application/json";
            break;
          case "csv":
            const flatData = type === "technical_deep_dive" ? reportData.findings : [reportData];
            const headers = Object.keys(flatData[0] || {});
            content = reportGenerator.exportToCSV(flatData, headers);
            contentType = "text/csv";
            break;
          default:
            content = reportGenerator.exportToJSON(reportData);
            contentType = "application/json";
        }
        
        const report = await storage.createReport({
          reportType: type,
          title,
          organizationId: reportData.organizationId || organizationId,
          status: "completed",
          content: reportData,
          dateRangeFrom: evalDate,
          dateRangeTo: evalDate,
          framework,
          engagementMetadata,
        });

        return res.json({
          reportId: report.id,
          title,
          data: reportData,
          content,
          contentType,
        });
      }

      // Date range based reports
      if (!type || !format || !from || !to) {
        return res.status(400).json({ error: "Missing required fields: type, format, from, to (or evaluationId for single evaluation reports)" });
      }
      
      const fromDate = new Date(from);
      fromDate.setUTCHours(0, 0, 0, 0);
      const toDate = new Date(to);
      toDate.setUTCHours(23, 59, 59, 999);

      let reportData: any;
      let title = "";

      switch (type) {
        case "executive_summary":
          reportData = await reportGenerator.generateExecutiveSummary(fromDate, toDate, organizationId);
          title = `Executive Summary - ${formatServerDTG(fromDate)} to ${formatServerDTG(toDate)}`;
          break;
        case "technical_deep_dive":
          reportData = await reportGenerator.generateTechnicalReport(fromDate, toDate, organizationId);
          title = `Technical Report - ${formatServerDTG(fromDate)} to ${formatServerDTG(toDate)}`;
          break;
        case "compliance_mapping":
          if (!framework) {
            return res.status(400).json({ error: "Compliance reports require a framework parameter" });
          }
          if (!complianceFrameworks.includes(framework)) {
            return res.status(400).json({ error: `Invalid framework. Valid options: ${complianceFrameworks.join(", ")}` });
          }
          reportData = await reportGenerator.generateComplianceReport(framework, fromDate, toDate, organizationId);
          title = `Compliance Report (${framework.toUpperCase()}) - ${formatServerDTG(fromDate)} to ${formatServerDTG(toDate)}`;
          break;
        default:
          return res.status(400).json({ error: "Invalid report type" });
      }
      
      let content: string;
      let contentType: string;
      
      switch (format) {
        case "json":
          content = reportGenerator.exportToJSON(reportData);
          contentType = "application/json";
          break;
        case "csv":
          const flatData = type === "technical_deep_dive" ? reportData.findings : [reportData];
          const headers = Object.keys(flatData[0] || {});
          content = reportGenerator.exportToCSV(flatData, headers);
          contentType = "text/csv";
          break;
        default:
          content = reportGenerator.exportToJSON(reportData);
          contentType = "application/json";
      }
      
      const report = await storage.createReport({
        reportType: type,
        title,
        organizationId,
        status: "completed",
        content: reportData,
        dateRangeFrom: fromDate,
        dateRangeTo: toDate,
        framework,
        engagementMetadata,
      });
      
      res.json({ 
        reportId: report.id, 
        title,
        data: reportData,
        content,
        contentType,
      });
    } catch (error) {
      console.error("Error generating report:", error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });
  
  app.get("/api/reports", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:read"), async (req, res) => {
    try {
      const organizationId = (req.query.organizationId as string) || (req as any).uiUser?.organizationId;
      const reports = await storage.getReports(organizationId);
      res.json(reports);
    } catch (error) {
      console.error("Error fetching reports:", error);
      res.status(500).json({ error: "Failed to fetch reports" });
    }
  });
  
  app.get("/api/reports/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:read"), async (req, res) => {
    try {
      const report = await storage.getReport(req.params.id);
      if (!report) {
        return res.status(404).json({ error: "Report not found" });
      }
      res.json(report);
    } catch (error) {
      console.error("Error fetching report:", error);
      res.status(500).json({ error: "Failed to fetch report" });
    }
  });
  
  app.delete("/api/reports/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:delete"), async (req, res) => {
    try {
      const report = await storage.getReport(req.params.id);
      if (!report) {
        return res.status(404).json({ error: "Report not found" });
      }
      await storage.deleteReport(req.params.id);
      res.json({ success: true, message: "Report deleted successfully" });
    } catch (error) {
      console.error("Error deleting report:", error);
      res.status(500).json({ error: "Failed to delete report" });
    }
  });
  
  app.get("/api/reports/:id/download", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:export"), async (req, res) => {
    try {
      const report = await storage.getReport(req.params.id);
      if (!report) {
        return res.status(404).json({ error: "Report not found" });
      }
      
      const format = req.query.format || "json";
      let content: string;
      let filename: string;
      let contentType: string;
      
      switch (format) {
        case "csv":
          const data = report.content as any;
          const flatData = data?.findings || [data];
          const headers = Object.keys(flatData[0] || {});
          content = reportGenerator.exportToCSV(flatData, headers);
          filename = `${report.title.replace(/\s+/g, "_")}.csv`;
          contentType = "text/csv";
          break;
        case "sarif": {
          const reportContent = report.content as any;
          const sarifEvaluations = reportContent?.evaluations || [];
          const sarifResults = reportContent?.results || [];
          content = reportGenerator.exportToSarif(sarifEvaluations, sarifResults, report.organizationId || "default");
          filename = `${report.title.replace(/\s+/g, "_")}.sarif.json`;
          contentType = "application/sarif+json";
          break;
        }
        case "json":
        default:
          content = reportGenerator.exportToJSON(report.content);
          filename = `${report.title.replace(/\s+/g, "_")}.json`;
          contentType = "application/json";
          break;
      }

      // Sign report if ?signed=true (tamper-evident evidence package)
      if (req.query.signed === "true") {
        const { signReport } = require("./services/report-signer");
        const signedPkg = signReport(content, format as string, report.organizationId || "default");
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Disposition", `attachment; filename="${filename.replace(/\.\w+$/, "")}.signed.json"`);
        return res.send(JSON.stringify(signedPkg, null, 2));
      }

      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.send(content);
    } catch (error) {
      console.error("Error downloading report:", error);
      res.status(500).json({ error: "Failed to download report" });
    }
  });

  // SARIF export for individual evaluations (CI/CD integration)
  app.get("/api/evaluations/:evaluationId/sarif", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:export"), async (req: any, res) => {
    try {
      const { evaluationId } = req.params;
      const evaluation = await storage.getEvaluation(evaluationId);
      if (!evaluation) return res.status(404).json({ error: "Evaluation not found" });

      const result = await storage.getResultByEvaluationId(evaluationId);
      const content = reportGenerator.exportToSarif(
        [evaluation],
        result ? [result] : [],
        evaluation.organizationId || "default"
      );

      // Sign report if ?signed=true (tamper-evident evidence package)
      if (req.query.signed === "true") {
        const { signReport } = require("./services/report-signer");
        const signedPkg = signReport(content, "sarif", evaluation.organizationId || "default");
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Disposition", `attachment; filename="odinforge-${evaluationId}.signed.json"`);
        return res.send(JSON.stringify(signedPkg, null, 2));
      }

      res.setHeader("Content-Type", "application/sarif+json");
      res.setHeader("Content-Disposition", `attachment; filename="odinforge-${evaluationId}.sarif.json"`);
      res.send(content);
    } catch (error) {
      console.error("Error exporting SARIF:", error);
      res.status(500).json({ error: "Failed to export SARIF" });
    }
  });

  // Verify signed evidence package integrity
  app.post("/api/reports/verify-signature", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:read"), async (req, res) => {
    try {
      const { verifyReport } = require("./services/report-signer");
      const result = verifyReport(req.body);
      res.json(result);
    } catch (error) {
      console.error("Error verifying report:", error);
      res.status(500).json({ error: "Failed to verify report" });
    }
  });

  // ========== REPORT V2 NARRATIVE ENDPOINTS ==========
  registerReportV2Routes(app);

  // ========== JOB QUEUE ENDPOINTS ==========
  registerJobQueueRoutes(app);

  // ========== EVIDENCE EXPORT ENDPOINT ==========
  
  app.post("/api/evidence/:evaluationId/export", apiRateLimiter, uiAuthMiddleware, requirePermission("evidence:read"), async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const { format = "json" } = req.body;
      
      // Get the evaluation and its result
      const evaluation = await storage.getEvaluation(evaluationId);
      if (!evaluation) {
        return res.status(404).json({ error: "Evaluation not found" });
      }
      
      const result = await storage.getResultByEvaluationId(evaluationId);
      
      // Extract artifacts from the result
      const artifacts = (result?.evidenceArtifacts as any[]) || [];
      
      // Generate AI-enhanced evidence package
      const evidencePackage = await reportGenerator.generateEvidencePackage(
        evaluationId,
        artifacts,
        result
      );
      
      if (format === "pdf") {
        // Return structured data for PDF generation (handled on frontend)
        res.json({
          success: true,
          format: "pdf",
          data: evidencePackage,
        });
      } else {
        // Return JSON with natural language narratives
        res.json({
          success: true,
          format: "json",
          data: evidencePackage,
        });
      }
    } catch (error) {
      console.error("Error exporting evidence:", error);
      res.status(500).json({ error: "Failed to export evidence" });
    }
  });

  // ========== GOVERNANCE ENDPOINTS ==========

  // Safety Decisions API - PolicyGuardian audit trail
  app.get("/api/evaluations/:evaluationId/safety-decisions", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const organizationId = req.tenant!.organizationId;
      const decisions = await storage.getSafetyDecisionsByEvaluationId(req.params.evaluationId);
      
      // Filter to ensure tenant isolation - only return decisions belonging to this organization
      const filteredDecisions = decisions.filter(d => d.organizationId === organizationId);
      res.json(filteredDecisions);
    } catch (error) {
      console.error("Error fetching safety decisions for evaluation:", error);
      res.status(500).json({ error: "Failed to fetch safety decisions" });
    }
  });

  app.get("/api/safety-decisions", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const organizationId = req.tenant!.organizationId;
      const { decision, limit, offset, startDate, endDate } = req.query;
      
      const decisions = await storage.getSafetyDecisionsByOrganization(organizationId, {
        decision: decision as string | undefined,
        limit: limit ? parseInt(limit as string, 10) : undefined,
        offset: offset ? parseInt(offset as string, 10) : undefined,
        startDate: startDate ? new Date(startDate as string) : undefined,
        endDate: endDate ? new Date(endDate as string) : undefined,
      });
      
      res.json(decisions);
    } catch (error) {
      console.error("Error fetching safety decisions:", error);
      res.status(500).json({ error: "Failed to fetch safety decisions" });
    }
  });

  app.get("/api/safety-decisions/stats", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const organizationId = req.tenant!.organizationId;
      const decisions = await storage.getSafetyDecisionsByOrganization(organizationId);
      
      const stats = {
        total: decisions.length,
        allowed: decisions.filter(d => d.decision === "ALLOW").length,
        denied: decisions.filter(d => d.decision === "DENY").length,
        modified: decisions.filter(d => d.decision === "MODIFY").length,
      };
      
      res.json(stats);
    } catch (error) {
      console.error("Error fetching safety decision stats:", error);
      res.status(500).json({ error: "Failed to fetch safety decision stats" });
    }
  });

  // ========== GOVERNANCE ENDPOINTS ==========
  
  // Rate Limit Status - MUST come before :organizationId route
  app.get("/api/governance/rate-limits", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:read"), async (req, res) => {
    try {
      const statuses = getAllRateLimitStatuses();
      res.json(statuses);
    } catch (error) {
      console.error("Error fetching rate limit status:", error);
      res.status(500).json({ error: "Failed to fetch rate limit status" });
    }
  });

  // Get or create organization governance settings
  app.get("/api/governance/:organizationId", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:read"), async (req, res) => {
    try {
      let governance = await storage.getOrganizationGovernance(req.params.organizationId);
      if (!governance) {
        governance = await storage.createOrganizationGovernance({
          organizationId: req.params.organizationId,
        });
      }
      res.json(governance);
    } catch (error) {
      console.error("Error fetching governance:", error);
      res.status(500).json({ error: "Failed to fetch governance settings" });
    }
  });

  app.patch("/api/governance/:organizationId", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:manage"), async (req, res) => {
    try {
      await storage.updateOrganizationGovernance(req.params.organizationId, req.body);
      
      // Clear governance cache to ensure new settings take effect immediately
      const { governanceEnforcement } = await import("./services/governance/governance-enforcement");
      governanceEnforcement.clearCache(req.params.organizationId);
      
      // Log the change
      await storage.createAuthorizationLog({
        organizationId: req.params.organizationId,
        action: "execution_mode_changed",
        details: req.body,
        authorized: true,
      });
      
      const updated = await storage.getOrganizationGovernance(req.params.organizationId);
      res.json(updated);
    } catch (error) {
      console.error("Error updating governance:", error);
      res.status(500).json({ error: "Failed to update governance settings" });
    }
  });

  // Kill Switch
  app.post("/api/governance/:organizationId/kill-switch", apiRateLimiter, uiAuthMiddleware, requirePermission("platform:emergency_access"), async (req, res) => {
    try {
      const { activate, activatedBy } = req.body;
      
      // Clear governance cache immediately so kill switch takes effect
      const { governanceEnforcement } = await import("./services/governance/governance-enforcement");
      
      if (activate) {
        await storage.activateKillSwitch(req.params.organizationId, activatedBy || "system");
        await storage.createAuthorizationLog({
          organizationId: req.params.organizationId,
          action: "kill_switch_activated",
          userId: activatedBy,
          authorized: true,
          riskLevel: "critical",
        });
      } else {
        await storage.deactivateKillSwitch(req.params.organizationId);
        await storage.createAuthorizationLog({
          organizationId: req.params.organizationId,
          action: "kill_switch_deactivated",
          userId: activatedBy,
          authorized: true,
        });
      }
      
      // Clear cache after updating database
      governanceEnforcement.clearCache(req.params.organizationId);
      
      const governance = await storage.getOrganizationGovernance(req.params.organizationId);
      res.json(governance);
    } catch (error) {
      console.error("Error toggling kill switch:", error);
      res.status(500).json({ error: "Failed to toggle kill switch" });
    }
  });

  // Authorization Logs
  app.get("/api/authorization-logs/:organizationId", apiRateLimiter, uiAuthMiddleware, requirePermission("audit:read"), async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const logs = await storage.getAuthorizationLogs(req.params.organizationId, limit);
      res.json(logs);
    } catch (error) {
      console.error("Error fetching authorization logs:", error);
      res.status(500).json({ error: "Failed to fetch authorization logs" });
    }
  });

  // Scope Rules
  app.get("/api/scope-rules/:organizationId", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:read"), async (req, res) => {
    try {
      const rules = await storage.getScopeRules(req.params.organizationId);
      res.json(rules);
    } catch (error) {
      console.error("Error fetching scope rules:", error);
      res.status(500).json({ error: "Failed to fetch scope rules" });
    }
  });

  app.post("/api/scope-rules", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:manage"), async (req, res) => {
    try {
      const rule = await storage.createScopeRule(req.body);
      
      // Clear scope rules cache so new rule takes effect immediately
      const { governanceEnforcement } = await import("./services/governance/governance-enforcement");
      governanceEnforcement.clearCache(req.body.organizationId);
      
      await storage.createAuthorizationLog({
        organizationId: req.body.organizationId,
        action: "scope_rule_modified",
        details: { action: "created", ruleId: rule.id, ruleName: rule.name },
        authorized: true,
      });
      
      res.json(rule);
    } catch (error) {
      console.error("Error creating scope rule:", error);
      res.status(500).json({ error: "Failed to create scope rule" });
    }
  });

  app.delete("/api/scope-rules/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("governance:manage"), async (req, res) => {
    try {
      await storage.deleteScopeRule(req.params.id);
      
      // Clear all caches since we don't know the organizationId
      const { governanceEnforcement } = await import("./services/governance/governance-enforcement");
      governanceEnforcement.clearCache();
      
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting scope rule:", error);
      res.status(500).json({ error: "Failed to delete scope rule" });
    }
  });

  // ============================================================================
  // CROSS-DOMAIN BREACH CHAINS
  // ============================================================================

  app.post("/api/breach-chains", evaluationRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const { name, description, assetIds, targetDomains, config } = req.body;

      if (!name || !assetIds || !Array.isArray(assetIds) || assetIds.length === 0) {
        return res.status(400).json({ error: "Name and at least one asset ID required" });
      }

      const orgId = req.uiUser?.organizationId || "default";

      // Governance check — enforce kill switch, scope rules, and execution mode
      const { governanceEnforcement } = await import("./services/governance/governance-enforcement");
      const primaryTarget = assetIds[0];
      const governanceCheck = await governanceEnforcement.canStartOperation(orgId, "breach_chain", primaryTarget, config?.executionMode || "safe");
      if (!governanceCheck.canStart) {
        return res.status(403).json({
          error: "Breach chain blocked by governance controls",
          reason: governanceCheck.reason,
        });
      }

      // Validate execution mode — only allow safe/simulation/live
      const requestedMode = config?.executionMode || "safe";
      const validModes = ["safe", "simulation", "live"];
      const executionMode = validModes.includes(requestedMode) ? requestedMode : "safe";

      const defaultConfig = {
        enabledPhases: [
          "application_compromise",
          "credential_extraction",
          "cloud_iam_escalation",
          "container_k8s_breakout",
          "lateral_movement",
          "impact_assessment",
        ],
        requireMinConfidence: 30,
        requireCredentialForCloud: true,
        requireCloudAccessForK8s: true,
        phaseTimeoutMs: config?.timeouts?.perPhaseMs ?? config?.phaseTimeoutMs ?? 900000, // 15 min — 3 sequential AI pipelines × ~200s each
        totalTimeoutMs: config?.timeouts?.totalMs ?? config?.totalTimeoutMs ?? 3600000, // 60 min total
        pauseOnCritical: false,
        ...config,
        executionMode: executionMode as "safe" | "simulation" | "live",
      };

      const chain = await storage.createBreachChain({
        name,
        description: description || null,
        assetIds,
        targetDomains: targetDomains || ["application", "cloud", "k8s", "network"],
        config: defaultConfig,
        organizationId: orgId,
        status: "pending",
        currentPhase: null,
        phaseResults: [],
        currentContext: null,
        unifiedAttackGraph: null,
        overallRiskScore: null,
        totalCredentialsHarvested: null,
        totalAssetsCompromised: null,
        domainsBreached: null,
        maxPrivilegeAchieved: null,
        executiveSummary: null,
        startedAt: null,
        completedAt: null,
        durationMs: null,
      });

      // Fire and forget — breach chain runs in background
      runBreachChain(chain.id).catch(error => {
        console.error(`[BreachChain] Chain ${chain.id} failed:`, error);
      });

      res.json({
        chainId: chain.id,
        message: "Breach chain initiated",
        phases: defaultConfig.enabledPhases,
      });
    } catch (error) {
      console.error("Create breach chain error:", error);
      res.status(500).json({ error: "Failed to create breach chain" });
    }
  });

  app.get("/api/breach-chains", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const orgId = (req.query.organizationId as string) || req.uiUser?.organizationId;
      const chains = await storage.getBreachChains(orgId);
      res.json(chains);
    } catch (error) {
      console.error("Get breach chains error:", error);
      res.status(500).json({ error: "Failed to fetch breach chains" });
    }
  });

  // Compare two breach chains side-by-side — must appear BEFORE /:id to avoid route shadowing
  app.get("/api/breach-chains/compare", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const { a, b } = req.query as { a?: string; b?: string };
      if (!a || !b) {
        return res.status(400).json({ error: "Query params ?a=chainId&b=chainId are required" });
      }
      const [chainA, chainB] = await Promise.all([
        storage.getBreachChain(a),
        storage.getBreachChain(b),
      ]);
      if (!chainA) return res.status(404).json({ error: `Breach chain ${a} not found` });
      if (!chainB) return res.status(404).json({ error: `Breach chain ${b} not found` });
      if (!chainA.unifiedAttackGraph || !chainB.unifiedAttackGraph) {
        return res.status(400).json({ error: "Both chains must be completed with attack graphs" });
      }
      const comparison = compareChains(
        {
          id: chainA.id,
          name: chainA.name,
          completedAt: chainA.completedAt ? chainA.completedAt.toISOString() : null,
          overallRiskScore: chainA.overallRiskScore,
          unifiedAttackGraph: chainA.unifiedAttackGraph,
        },
        {
          id: chainB.id,
          name: chainB.name,
          completedAt: chainB.completedAt ? chainB.completedAt.toISOString() : null,
          overallRiskScore: chainB.overallRiskScore,
          unifiedAttackGraph: chainB.unifiedAttackGraph,
        }
      );
      // Transform to match frontend ComparisonData contract
      const transformed = {
        ...comparison,
        verdict: comparison.verdict.toUpperCase() as "IMPROVED" | "REGRESSED" | "UNCHANGED",
        attackSurfaceDelta: comparison.attackSurfaceChange,
        criticalPathDelta: comparison.criticalPathChange,
        riskScoreDelta: comparison.chainB.riskScore - comparison.chainA.riskScore,
      };
      res.json({ comparison: transformed });
    } catch (error) {
      console.error("Compare breach chains error:", error);
      res.status(500).json({ error: "Failed to compare breach chains" });
    }
  });

  // Trend history — last 10 completed chains for an org, optionally filtered by assetId
  app.get("/api/breach-chains/trend", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const orgId = req.uiUser?.organizationId;
      const { assetId } = req.query as { assetId?: string };
      const allChains = await storage.getBreachChains(orgId);
      const completed = allChains
        .filter((c) => c.status === "completed" && c.completedAt != null)
        .filter((c) => {
          if (!assetId) return true;
          return Array.isArray(c.assetIds) && c.assetIds.includes(assetId);
        })
        .sort((a, b) => {
          const tA = a.completedAt ? new Date(a.completedAt).getTime() : 0;
          const tB = b.completedAt ? new Date(b.completedAt).getTime() : 0;
          return tA - tB;
        })
        .slice(-10)
        .map((c) => ({
          id: c.id,
          name: c.name,
          completedAt: c.completedAt,
          overallRiskScore: c.overallRiskScore,
          nodeCount: c.unifiedAttackGraph?.nodes?.length ?? 0,
          criticalPathLength: c.unifiedAttackGraph?.criticalPath?.length ?? 0,
        }));
      res.json(completed);
    } catch (error) {
      console.error("Breach chain trend error:", error);
      res.status(500).json({ error: "Failed to fetch breach chain trend" });
    }
  });

  app.get("/api/breach-chains/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      res.json(chain);
    } catch (error) {
      console.error("Get breach chain error:", error);
      res.status(500).json({ error: "Failed to fetch breach chain" });
    }
  });

  // Narrative generator — plain-English attack story from a completed breach chain
  app.get("/api/breach-chains/:id/narrative", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (chain.status !== "completed") {
        return res.status(400).json({ error: "Chain must be completed to generate narrative" });
      }
      if (!chain.unifiedAttackGraph) {
        return res.status(400).json({ error: "No attack graph available" });
      }
      const graph = chain.unifiedAttackGraph as { nodes?: unknown[] };
      if (!graph.nodes || graph.nodes.length === 0) {
        return res.json({ narrative: { summary: "No findings to narrate.", phases: [], recommendations: [] } });
      }
      const narrative = generateNarrative(chain.unifiedAttackGraph, chain.name, chain.name);
      res.json({ narrative });
    } catch (error) {
      console.error("Narrative generation error:", error);
      res.status(500).json({ error: "Failed to generate narrative" });
    }
  });

  // Remediation tracking — update a node's remediation status within a breach chain
  app.post("/api/breach-chains/:id/nodes/:nodeId/remediate", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const { id, nodeId } = req.params;
      const { status, notes, remediatedBy } = req.body as {
        status: "in_progress" | "verified_fixed" | "accepted_risk";
        notes?: string;
        remediatedBy?: string;
      };

      if (!status || !["in_progress", "verified_fixed", "accepted_risk"].includes(status)) {
        return res.status(400).json({ error: "Invalid status. Must be in_progress, verified_fixed, or accepted_risk" });
      }

      const chain = await storage.getBreachChain(id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (!chain.unifiedAttackGraph) {
        return res.status(400).json({ error: "No attack graph available" });
      }

      const graph = chain.unifiedAttackGraph;
      const nodeIndex = graph.nodes.findIndex((n) => n.id === nodeId);
      if (nodeIndex === -1) {
        return res.status(404).json({ error: `Node ${nodeId} not found in attack graph` });
      }

      // Update the node in-place
      const updatedNodes = [...graph.nodes];
      updatedNodes[nodeIndex] = {
        ...updatedNodes[nodeIndex],
        remediationStatus: status,
        remediatedAt: new Date().toISOString(),
        remediatedBy: remediatedBy ?? req.uiUser?.email ?? "unknown",
        remediationNotes: notes,
      };
      const updatedGraph = { ...graph, nodes: updatedNodes };

      const updated = await storage.updateBreachChainGraph(id, updatedGraph);

      // Broadcast WebSocket event so clients see the update immediately
      wsService.broadcastToChannel(`breach_chain:${chain.organizationId}`, {
        type: "node_remediation_update",
        chainId: id,
        nodeId,
        status,
        timestamp: new Date().toISOString(),
      });

      // Compute progress: how many critical path nodes are now verified_fixed
      const criticalPathNodes = graph.criticalPath
        .map((nid) => updatedNodes.find((n) => n.id === nid))
        .filter(Boolean);
      const fixed = criticalPathNodes.filter((n) => n?.remediationStatus === "verified_fixed").length;
      const total = criticalPathNodes.length;

      res.json({
        success: true,
        nodeId,
        status,
        criticalPathProgress: { fixed, total },
      });
    } catch (error) {
      console.error("Node remediation error:", error);
      res.status(500).json({ error: "Failed to update node remediation status" });
    }
  });

  // ── Auto-Remediation: Generate fix proposals for breach chain findings ──
  app.post("/api/breach-chains/:id/generate-fix", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const { id: chainId } = req.params;
      const chain = await storage.getBreachChain(chainId);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      const { generateFixProposal } = { generateRemediationDiff: () => ({ diff: "core-v2: remediation engine not available", language: "text" }), getRemediationTemplates: () => [] } as any;

      // Generate proposals for PROVEN/CORROBORATED findings only
      const phaseResults = (chain.phaseResults || []) as any[];
      const proposals: any[] = [];
      let skipped = 0;

      for (const phase of phaseResults) {
        for (const finding of phase.findings || []) {
          const quality = finding.evidenceQuality || "unverifiable";
          if (quality !== "proven" && quality !== "corroborated") {
            skipped++;
            continue;
          }
          if (proposals.length >= 20) break; // cap at 20

          try {
            const proposal = generateFixProposal({
              findingId: finding.id,
              severity: finding.severity || "medium",
              title: finding.title || "Unknown",
              description: finding.description || "",
              technique: finding.technique,
              evidenceQuality: quality,
              targetUrl: finding.targetUrl,
              requestPayload: finding.requestPayload,
              responseBody: finding.responseBody,
            }, chainId);
            proposals.push(proposal);
            await storage.storeFixProposal(chainId, proposal);
          } catch (err) {
            console.warn(`[FixGen] Skipped finding ${finding.id}:`, err);
          }
        }
      }

      res.json({
        success: true,
        chainId,
        proposalsGenerated: proposals.length,
        findingsSkipped: skipped,
        proposals,
      });
    } catch (error) {
      console.error("Fix proposal generation error:", error);
      res.status(500).json({ error: "Failed to generate fix proposals" });
    }
  });

  // ── Auto-Remediation: Get fix proposals for a breach chain ──
  app.get("/api/breach-chains/:id/fix-proposals", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const proposals = await storage.getFixProposals(req.params.id);
      res.json({ proposals });
    } catch (error) {
      console.error("Get fix proposals error:", error);
      res.status(500).json({ error: "Failed to get fix proposals" });
    }
  });

  // ── Auto-Remediation: Verify a fix proposal ──
  app.post("/api/breach-chains/:id/verify-fix-proposal", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const { id: chainId } = req.params;
      const { proposalId } = req.body as { proposalId: string };
      if (!proposalId) return res.status(400).json({ error: "proposalId is required" });

      const proposals = await storage.getFixProposals(chainId);
      const proposal = proposals.find((p: any) => p.id === proposalId);
      if (!proposal) return res.status(404).json({ error: "Fix proposal not found" });

      const { verifyFix } = { generateRemediationDiff: () => ({ diff: "core-v2: remediation engine not available", language: "text" }), getRemediationTemplates: () => [] } as any;
      const verification = await verifyFix(proposal);
      await storage.storeFixVerification(chainId, verification);

      res.json({ success: true, verification });
    } catch (error) {
      console.error("Fix verification error:", error);
      res.status(500).json({ error: "Failed to verify fix" });
    }
  });

  app.post("/api/breach-chains/:id/resume", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (chain.status !== "paused") {
        return res.status(400).json({ error: `Cannot resume chain in ${chain.status} state` });
      }

      resumeBreachChain(chain.id).catch(error => {
        console.error(`[BreachChain] Resume ${chain.id} failed:`, error);
      });

      res.json({ message: "Breach chain resumed", chainId: chain.id });
    } catch (error) {
      console.error("Resume breach chain error:", error);
      res.status(500).json({ error: "Failed to resume breach chain" });
    }
  });

  app.post("/api/breach-chains/:id/abort", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (chain.status !== "running" && chain.status !== "paused") {
        return res.status(400).json({ error: `Cannot abort chain in ${chain.status} state` });
      }

      await abortBreachChain(chain.id);
      res.json({ message: "Breach chain aborted", chainId: chain.id });
    } catch (error) {
      console.error("Abort breach chain error:", error);
      res.status(500).json({ error: "Failed to abort breach chain" });
    }
  });

  app.delete("/api/breach-chains/:id", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:delete"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (chain.status === "running") {
        return res.status(400).json({ error: "Cannot delete a running breach chain — abort it first" });
      }

      await storage.deleteBreachChain(req.params.id);
      res.json({ success: true, message: "Breach chain deleted" });
    } catch (error) {
      console.error("Delete breach chain error:", error);
      res.status(500).json({ error: "Failed to delete breach chain" });
    }
  });

  // ─── Engagement Package API (ADR-005 / ADR-009) ────────────────────────────

  /** POST /api/breach-chains/:id/seal — Seal engagement package (generates all 5 components) */
  app.post("/api/breach-chains/:id/seal", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:generate"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (chain.status === "running") {
        return res.status(400).json({ error: "Cannot seal a running breach chain" });
      }

      const { sealEngagementPackage, createSealEvent } = await import("./services/engagement/engagement-package");
      const { deactivateKeysForEngagement } = await import("./services/engagement/engagement-api-keys");
      const { generateReengagementOffer } = await import("./services/engagement/reengagement-offer");

      const sealedBy = (req as any).uiUser?.email || "system";
      const pkg = sealEngagementPackage(chain, sealedBy);

      // Phase 14: Inject portfolio summary if multiple runs exist
      try {
        const { getPortfolioOrchestrator } = await import("./services/aev/portfolio-orchestrator");
        const portfolio = getPortfolioOrchestrator();
        const allRuns = portfolio.getAllRuns();
        if (allRuns.length > 1 && pkg.metadata) {
          (pkg.metadata as any).portfolioSummary = portfolio.getPortfolioSummary();
        }
      } catch { /* portfolio not initialized — skip */ }

      const sealEvent = createSealEvent(pkg);

      // Deactivate per-engagement API keys (ADR-009)
      const deactivatedKeys = deactivateKeysForEngagement(chain.id, "sealed");

      // Generate reengagement offer
      const offer = generateReengagementOffer(chain, pkg);

      res.json({
        package: {
          packageId: pkg.packageId,
          engagementId: pkg.engagementId,
          sealedAt: pkg.sealedAt,
          sealedBy: pkg.sealedBy,
          integrity: pkg.integrity,
          metadata: pkg.metadata,
        },
        sealEvent,
        deactivatedApiKeys: deactivatedKeys,
        reengagementOffer: offer,
      });
    } catch (error) {
      console.error("Seal engagement package error:", error);
      res.status(500).json({ error: "Failed to seal engagement package" });
    }
  });

  /** GET /api/breach-chains/:id/package — Get full engagement package (must be sealed first) */
  app.get("/api/breach-chains/:id/package", apiRateLimiter, uiAuthMiddleware, requirePermission("reports:export"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      const { sealEngagementPackage } = await import("./services/engagement/engagement-package");
      const pkg = sealEngagementPackage(chain, "readonly-generation");

      // Return requested component or full package
      const component = req.query.component as string | undefined;
      if (component === "ciso") return res.json(pkg.components.cisoReport);
      if (component === "engineer") return res.json(pkg.components.engineerReport);
      if (component === "evidence") return res.json(pkg.components.evidenceJSON);
      if (component === "defenders-mirror") return res.json(pkg.components.defendersMirror);
      if (component === "replay") {
        res.setHeader("Content-Type", "text/html");
        return res.send(pkg.components.breachChainReplayHTML);
      }

      res.json(pkg);
    } catch (error) {
      console.error("Get engagement package error:", error);
      res.status(500).json({ error: "Failed to generate engagement package" });
    }
  });

  /** POST /api/breach-chains/:id/api-key — Create per-engagement API key (ADR-009) */
  app.post("/api/breach-chains/:id/api-key", apiRateLimiter, uiAuthMiddleware, requirePermission("api:write"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      const { createEngagementApiKey } = await import("./services/engagement/engagement-api-keys");
      const ttlDays = typeof req.body?.ttlDays === "number" ? req.body.ttlDays : 30;
      const result = createEngagementApiKey(chain.id, chain.organizationId, ttlDays);

      res.json({
        keyId: result.key.id,
        plaintextKey: result.plaintextKey,
        engagementId: result.key.engagementId,
        expiresAt: result.key.expiresAt,
        warning: "Store this key securely — it will not be shown again.",
      });
    } catch (error) {
      console.error("Create engagement API key error:", error);
      res.status(500).json({ error: "Failed to create engagement API key" });
    }
  });

  /** GET /api/breach-chains/:id/api-keys — List API keys for an engagement */
  app.get("/api/breach-chains/:id/api-keys", apiRateLimiter, uiAuthMiddleware, requirePermission("api:read"), async (req, res) => {
    try {
      const { getKeysForEngagement } = await import("./services/engagement/engagement-api-keys");
      const keys = getKeysForEngagement(req.params.id);
      res.json(keys.map(k => ({ ...k, keyHash: undefined }))); // Never expose hash
    } catch (error) {
      console.error("List engagement API keys error:", error);
      res.status(500).json({ error: "Failed to list engagement API keys" });
    }
  });

  // ─── Breach Chain Enhancement API (spec v1.0) ──────────────────────────────

  /** GET /api/breach-chains/:id/heatmap — ATT&CK technique coverage for this chain */
  app.get("/api/breach-chains/:id/heatmap", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      // core-v2: attack-engine removed — build heatmap from phase results directly
      const engine = { getCoverageMatrix: () => [] as any[] };

      // Collect all technique IDs exercised across all phase results
      const exercisedTechniqueIds: string[] = [];
      const phaseResults = (chain.phaseResults as any[]) || [];
      for (const phase of phaseResults) {
        if (phase?.outputContext?.attackTechniqueIds) {
          exercisedTechniqueIds.push(...phase.outputContext.attackTechniqueIds);
        }
        // Also pull technique IDs from individual findings
        if (phase?.findings) {
          for (const f of phase.findings) {
            if (f.technique && f.technique.startsWith("T")) exercisedTechniqueIds.push(f.technique);
            if (f.mitreId && f.mitreId.startsWith("T")) exercisedTechniqueIds.push(f.mitreId);
          }
        }
      }
      // Also check graph nodes for artifacts
      const graph = chain.unifiedAttackGraph as any;
      if (graph?.nodes) {
        for (const node of graph.nodes) {
          if (node?.artifacts?.attackTechniqueId) {
            exercisedTechniqueIds.push(node.artifacts.attackTechniqueId);
          }
        }
      }

      // core-v2: attack-engine removed — return exercised techniques as basic heatmap
      const result = exercisedTechniqueIds.map(tid => ({
        techniqueId: tid,
        status: "exercised",
        color: "#ef4444",
      }));

      res.json(result);
    } catch (error) {
      console.error("Heatmap error:", error);
      res.status(500).json({ error: "Failed to generate heatmap" });
    }
  });

  /** GET /api/breach-chains/:id/credentials — harvested credentials for this chain */
  app.get("/api/breach-chains/:id/credentials", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      const { getCredentialBus } = await import("./services/aev/credential-bus");
      const bus = getCredentialBus();
      const creds = bus.getCredentialWebData(req.params.id);

      // Also extract from graph node artifacts if bus is empty (after restart)
      if (creds.length === 0) {
        const graph = chain.unifiedAttackGraph as any;
        const extracted: any[] = [];
        if (graph?.nodes) {
          for (const node of graph.nodes) {
            if (node?.artifacts?.credentials) {
              for (const cred of node.artifacts.credentials) {
                extracted.push({
                  id: `${node.id}-${cred.username}`,
                  username: cred.username,
                  privilegeTier: cred.privilegeTier,
                  sourceSystem: cred.sourceSystem,
                  discoveredAt: node.artifacts.discoveredAt || new Date().toISOString(),
                  reusedOn: (cred.reusedOn || []).map((t: string) => ({ target: t, timestamp: new Date().toISOString(), success: true })),
                  unlocked: cred.unlocked || [],
                  hasHash: !!cred.hash,
                  hasCleartext: !!cred.cleartext,
                  hashValue: cred.hash || undefined,
                  hashAlgorithm: cred.hash ? (cred.hash.length === 32 ? "MD5" : cred.hash.length === 40 ? "SHA-1" : cred.hash.length === 64 ? "SHA-256" : "Unknown") : undefined,
                });
              }
            }
          }
        }
        return res.json(extracted);
      }

      res.json(creds);
    } catch (error) {
      console.error("Credentials error:", error);
      res.status(500).json({ error: "Failed to fetch credentials" });
    }
  });

  /** GET /api/breach-chains/:id/defense-gaps — defense gap analysis from real Defender's Mirror rules */
  app.get("/api/breach-chains/:id/defense-gaps", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      // Real detection rules generated by the Defender's Mirror during the engagement.
      // Each rule is template-based from actual attack evidence — never fabricated.
      const detectionRules = (chain as any).detectionRules as Array<{
        id: string;
        phase: string;
        techniqueCategory: string;
        mitreAttackId: string;
        mitreAttackName: string;
        sigmaRule: string;
        yaraRule: string;
        splunkSPL: string;
        generatedAt: string;
      }> || [];

      const graph = chain.unifiedAttackGraph as any;
      const events: any[] = [];
      let totalMissed = 0;
      const byTactic: Record<string, { detected: number; missed: number }> = {};

      // Phase-to-tactic mapping (same as used in attack graph)
      const PHASE_TACTIC: Record<string, string> = {
        application_compromise: "initial-access",
        credential_extraction: "credential-access",
        cloud_iam_escalation: "privilege-escalation",
        container_k8s_breakout: "execution",
        lateral_movement: "lateral-movement",
        impact_assessment: "impact",
      };

      // Group real detection rules by phase — these represent detections that
      // WOULD have caught the attack if deployed, making them genuine "missed" detections
      const rulesByPhase: Record<string, typeof detectionRules> = {};
      for (const rule of detectionRules) {
        if (!rulesByPhase[rule.phase]) rulesByPhase[rule.phase] = [];
        rulesByPhase[rule.phase].push(rule);
      }

      // For each phase that has detection rules, build a defense gap event
      if (graph?.nodes) {
        for (const node of graph.nodes) {
          const art = node?.artifacts;
          if (!art) continue;

          // Find the phase for this node by matching its label to PHASE_DEFINITIONS
          const nodePhaseName = Object.keys(PHASE_TACTIC).find(
            p => art.attackTechniqueName === node.label
          ) || "";
          // Also match by tactic
          const matchingPhase = Object.entries(PHASE_TACTIC).find(
            ([_, tactic]) => tactic === node.tactic
          );
          const phase = matchingPhase ? matchingPhase[0] : nodePhaseName;

          const phaseRules = rulesByPhase[phase] || [];
          if (phaseRules.length === 0) continue;

          // Each Defender's Mirror rule is a "missed" detection — the attack succeeded,
          // meaning the target environment didn't have this rule deployed
          const missedRuleNames = phaseRules.map(r => {
            // Build descriptive name: "Sigma: <technique> (<MITRE ID>)"
            const ruleType = r.sigmaRule ? "Sigma" : r.yaraRule ? "YARA" : "SPL";
            return `${ruleType}: ${r.mitreAttackName} (${r.mitreAttackId})`;
          });

          // Deduplicate rule names (same technique may generate multiple rule types)
          const uniqueMissed = Array.from(new Set(missedRuleNames));
          totalMissed += uniqueMissed.length;

          const tactic = node.tactic || "unknown";
          if (!byTactic[tactic]) byTactic[tactic] = { detected: 0, missed: 0 };
          byTactic[tactic].missed += uniqueMissed.length;

          events.push({
            nodeId: node.id,
            nodeLabel: node.label,
            tactic,
            techniqueId: art.attackTechniqueId,
            techniqueName: art.attackTechniqueName,
            timestamp: art.discoveredAt || new Date().toISOString(),
            detectionsFired: [],  // Attack succeeded — no defenses fired
            detectionsMissed: uniqueMissed,
            evasionNotes: `${phaseRules.length} Defender's Mirror rules generated from real attack evidence`,
          });
        }
      }

      // In a breach chain, all attacks succeeded — so coverage is 0%
      // (the target had none of these rules deployed)
      const totalTechniques = totalMissed;
      const totalDetected = 0;
      const coveragePct = 0;

      res.json({ totalTechniques, totalDetected, totalMissed, coveragePct, byTactic, events });
    } catch (error) {
      console.error("Defense gaps error:", error);
      res.status(500).json({ error: "Failed to compute defense gaps" });
    }
  });

  /** PATCH /api/breach-chains/:id/config — update engagement configuration */
  app.patch("/api/breach-chains/:id/config", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:create"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });

      if (chain.status === "running") {
        return res.status(400).json({ error: "Cannot modify config while engagement is running" });
      }

      const { engagement, executionMode } = req.body;
      const currentConfig = chain.config as any;
      const updatedConfig = {
        ...currentConfig,
        ...(executionMode ? { executionMode } : {}),
        ...(engagement ? { engagement } : {}),
      };

      await storage.updateBreachChain(req.params.id, { config: updatedConfig } as any);
      res.json({ success: true, config: updatedConfig });
    } catch (error) {
      console.error("Config patch error:", error);
      res.status(500).json({ error: "Failed to update engagement config" });
    }
  });

  // ─── GTM v1.0: Replay, Defender's Mirror, Reachability, Evidence Quality ──

  /** GET /api/breach-chains/:id/replay — full engagement replay manifest */
  app.get("/api/breach-chains/:id/replay", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      const manifest = (chain as any).replayManifest;
      if (!manifest) return res.status(404).json({ error: "Replay not available — chain may still be running" });
      res.json(manifest);
    } catch (error) {
      res.status(500).json({ error: "Failed to get replay manifest" });
    }
  });

  /** GET /api/breach-chains/:id/replay/events — filtered, paginated replay events */
  app.get("/api/breach-chains/:id/replay/events", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      const manifest = (chain as any).replayManifest;
      if (!manifest?.events) return res.status(404).json({ error: "Replay not available" });

      let events = manifest.events as any[];
      const { phase, outcome, type, limit, offset } = req.query;
      if (phase) events = events.filter((e: any) => e.phase === parseInt(phase as string));
      if (outcome) events = events.filter((e: any) => e.outcome === outcome);
      if (type) events = events.filter((e: any) => e.eventType === type);
      const off = parseInt(offset as string) || 0;
      const lim = parseInt(limit as string) || 50;
      res.json({ total: events.length, events: events.slice(off, off + lim) });
    } catch (error) {
      res.status(500).json({ error: "Failed to get replay events" });
    }
  });

  /** GET /api/breach-chains/:id/replay/export — export replay as PDF-ready text or JSON */
  app.get("/api/breach-chains/:id/replay/export", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      if (!(chain as any).replayManifest) return res.status(404).json({ error: "Replay not available" });

      const { format } = req.query;
      if (format === "json") {
        const report = reportGenerator.generateReplayReport(chain);
        res.json(report);
      } else {
        // Default: text/markdown format suitable for PDF rendering
        const text = reportGenerator.exportReplayToText(chain);
        res.type("text/markdown").send(text);
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to export replay" });
    }
  });

  /** POST /api/breach-chains/:id/replay/snapshot — state at a specific sequence index */
  app.post("/api/breach-chains/:id/replay/snapshot", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      const manifest = (chain as any).replayManifest;
      if (!manifest?.events) return res.status(404).json({ error: "Replay not available" });

      const { atSequenceIndex } = req.body;
      if (typeof atSequenceIndex !== "number") return res.status(400).json({ error: "atSequenceIndex required" });

      const events = (manifest.events as any[]).filter((e: any) => e.sequenceIndex <= atSequenceIndex);
      const allCreds = new Set<string>();
      const allHosts = new Set<string>();
      for (const e of events) {
        if (e.credentialsHarvested) e.credentialsHarvested.forEach((c: string) => allCreds.add(c));
        if (e.outcome === "success") allHosts.add(e.target);
      }
      res.json({ events, credentialCount: allCreds.size, hostsReached: Array.from(allHosts) });
    } catch (error) {
      res.status(500).json({ error: "Failed to get replay snapshot" });
    }
  });

  /** GET /api/breach-chains/:id/detection-rules — Defender's Mirror rules for this chain */
  app.get("/api/breach-chains/:id/detection-rules", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      const rules = (chain as any).detectionRules || [];
      const { format } = req.query;
      if (format === "sigma") {
        res.json(rules.map((r: any) => ({ id: r.id, mitreAttackId: r.mitreAttackId, rule: r.sigmaRule })));
      } else if (format === "yara") {
        res.json(rules.map((r: any) => ({ id: r.id, mitreAttackId: r.mitreAttackId, rule: r.yaraRule })));
      } else if (format === "splunk") {
        res.json(rules.map((r: any) => ({ id: r.id, mitreAttackId: r.mitreAttackId, rule: r.splunkSPL })));
      } else {
        res.json({ total: rules.length, rules });
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to get detection rules" });
    }
  });

  /** GET /api/breach-chains/:id/reachability — reachability chain graph */
  app.get("/api/breach-chains/:id/reachability", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      const reachability = (chain as any).reachabilityChain;
      if (!reachability) return res.status(404).json({ error: "Reachability chain not available" });
      const { format } = req.query;
      if (format === "dot") {
        res.type("text/plain").send(reachability.graphFormat?.dot || "");
      } else if (format === "d3") {
        res.json(JSON.parse(reachability.graphFormat?.json || "{}"));
      } else {
        res.json(reachability);
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to get reachability chain" });
    }
  });

  /** GET /api/breach-chains/:id/evidence-quality — evidence quality summary */
  app.get("/api/breach-chains/:id/evidence-quality", apiRateLimiter, uiAuthMiddleware, requirePermission("evaluations:read"), async (req, res) => {
    try {
      const chain = await storage.getBreachChain(req.params.id);
      if (!chain) return res.status(404).json({ error: "Breach chain not found" });
      const quality = (chain as any).evidenceQualitySummary;
      if (!quality) return res.status(404).json({ error: "Evidence quality data not available" });
      res.json(quality);
    } catch (error) {
      res.status(500).json({ error: "Failed to get evidence quality" });
    }
  });

  return httpServer;
}

// ========== JOB QUEUE API ROUTES (stub — full implementation removed in core-v2) ==========

function registerJobQueueRoutes(app: Express) {
  // Get queue stats
  app.get("/api/jobs/stats", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const orgId = req.uiUser?.organizationId || "default";
      const stats = await queueService.getQueueStats();

      // Include breach chains in the stats
      const chains = await storage.getBreachChains(orgId);
      const chainCounts = { waiting: 0, active: 0, completed: 0, failed: 0 };
      for (const c of chains) {
        const s = c.status as string;
        if (s === "pending") chainCounts.waiting++;
        else if (s === "running") chainCounts.active++;
        else if (s === "completed") chainCounts.completed++;
        else if (s === "failed" || s === "aborted") chainCounts.failed++;
      }

      res.json({
        ...stats,
        breachChains: chainCounts,
      });
    } catch (error) {
      console.error("Failed to get queue stats:", error);
      res.status(500).json({ error: "Failed to get queue stats" });
    }
  });
}
async function runEvaluation(evaluationId: string, data: {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
  adversaryProfile?: string;
  organizationId?: string;
  appLogicData?: import("@shared/schema").AppLogicExposureData;
}) {
  const startTime = Date.now();
  const orgId = data.organizationId || "default";

  try {
    // Set RLS tenant context for this background task
    const { setTenantContext: setCtx } = await import("./services/rls-setup");
    await setCtx(orgId);

    // Check governance execution mode
    const governance = await storage.getOrganizationGovernance(orgId);
    const executionMode = governance?.executionMode || "safe";
    
    // Check kill switch
    if (governance?.killSwitchActive) {
      console.log(`[GOVERNANCE] Evaluation ${evaluationId} blocked - kill switch active`);
      await storage.updateEvaluationStatus(evaluationId, "failed");
      wsService.sendComplete(evaluationId, false, "Kill switch is active - all evaluations are blocked");
      return;
    }
    
    await storage.updateEvaluationStatus(evaluationId, "in_progress", executionMode);

    // Fast path: For app_logic exposure type, use deterministic analyzer (no LLM cost)

    // core-v2: live-network-testing removed — liveScanResult always null
    const liveScanResult: any = null;

    // Standard evaluation (safe mode or live mode)
    const result = await runAgentOrchestrator(
      data.assetId,
      data.exposureType,
      data.priority,
      data.description,
      evaluationId,
      (agentName, stage, progress, message) => {
        wsService.sendProgress(evaluationId, agentName, stage, progress, message);
      },
      { 
        adversaryProfile: data.adversaryProfile as any,
        organizationId: orgId,
        executionMode: executionMode as "safe" | "simulation" | "live",
      }
    );

    // Auto-detect and merge app-logic findings if API patterns detected
    // core-v2: app-logic-analyzer + live-network-testing removed
    // finalResult is just the orchestrator result — no merges.
    const finalResult = result;

    const duration = Date.now() - startTime;

    await storage.createResult({
      id: `res-${randomUUID().slice(0, 8)}`,
      evaluationId,
      exploitable: finalResult.exploitable,
      confidence: finalResult.confidence,
      score: finalResult.score,
      attackPath: finalResult.attackPath,
      attackGraph: finalResult.attackGraph,
      businessLogicFindings: finalResult.businessLogicFindings,
      multiVectorFindings: finalResult.multiVectorFindings,
      workflowAnalysis: finalResult.workflowAnalysis,
      impact: finalResult.impact,
      recommendations: finalResult.recommendations,
      evidenceArtifacts: finalResult.evidenceArtifacts,
      intelligentScore: finalResult.intelligentScore,
      remediationGuidance: finalResult.remediationGuidance,
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

