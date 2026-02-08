import type { Express } from "express";
import { createServer, type Server } from "http";
import fs from "fs";
import path from "path";
import { storage } from "./storage";
import { db } from "./db";
import { endpointAgents, aevEvaluations } from "@shared/schema";
import { sql, and, eq } from "drizzle-orm";
import { insertEvaluationSchema, insertReportSchema, insertScheduledScanSchema, complianceFrameworks } from "@shared/schema";
import { runAgentOrchestrator } from "./services/agents";
import { runAISimulation } from "./services/agents/ai-simulation";
import { wsService } from "./services/websocket";
import { reportGenerator } from "./services/report-generator";
import { reconReportGenerator } from "./services/recon-report-generator";
import { unifiedAuthService } from "./services/unified-auth";
import { mtlsAuthService } from "./services/mtls-auth";
import { jwtAuthService } from "./services/jwt-auth";
import { queueService, JobType } from "./services/queue";
import { 
  apiRateLimiter, 
  authRateLimiter, 
  agentTelemetryRateLimiter, 
  evaluationRateLimiter,
  reportRateLimiter,
  simulationRateLimiter,
  batchRateLimiter,
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
  hashPassword,
  type UIAuthenticatedRequest,
} from "./services/ui-auth";
import { randomUUID, timingSafeEqual, randomBytes, createHash } from "crypto";
import bcrypt from "bcrypt";
import { z } from "zod";
import { registerReportV2Routes } from "./src/reportsV2/routes";
import { calculateDefensivePosture, calculateAttackPredictions } from "./services/metrics-calculator";
import { AGENT_RELEASE, INSTALLATION_INSTRUCTIONS } from "@shared/agent-releases";
import { fullRecon, reconToExposures, type ReconResult } from "./services/external-recon";
import { runFullAssessment } from "./services/full-assessment";
import { registerTenantRoutes, seedDefaultTenant } from "./routes/tenants";
import { tenantMiddleware, getOrganizationId } from "./middleware/tenant";
import { generateAgentFindings } from "./services/telemetry-analyzer";
import { forensicExportService } from "./services/forensic-export";
import { AuditLogger } from "./services/audit-logger";
import { runtimeGuard } from "./services/runtime-guard";
import { storageService } from "./services/storage";

// Helper function to normalize platform strings for comparison
function normalizePlatform(platform: string): string {
  const lower = platform.toLowerCase().trim();
  
  // Normalize Windows variants
  if (lower.includes("windows") || lower === "win32" || lower === "win64") {
    return "windows";
  }
  
  // Normalize Linux variants
  if (lower.includes("linux") || lower === "ubuntu" || lower === "debian" || lower === "centos" || lower === "rhel" || lower === "fedora") {
    return "linux";
  }
  
  // Normalize macOS variants
  if (lower.includes("darwin") || lower.includes("macos") || lower.includes("mac os") || lower === "osx") {
    return "macos";
  }
  
  // Container/Kubernetes
  if (lower.includes("container") || lower.includes("docker")) {
    return "container";
  }
  
  if (lower.includes("kubernetes") || lower.includes("k8s")) {
    return "kubernetes";
  }
  
  return lower;
}

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

// Agent API Validation Schemas
const agentRegisterSchema = z.object({
  agentName: z.string().min(1).max(128),
  hostname: z.string().max(256).optional(),
  platform: z.enum(["linux", "windows", "macos", "container", "kubernetes"]).optional(),
  platformVersion: z.string().max(64).optional(),
  architecture: z.string().max(32).optional(),
  capabilities: z.array(z.string().max(64)).max(50).optional(),
  environment: z.enum(["production", "staging", "development"]).optional(),
  tags: z.array(z.string().max(64)).max(20).optional(),
});

const securityFindingSchema = z.object({
  type: z.string().max(64).optional(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  title: z.string().max(256),
  description: z.string().max(4096).optional(),
  affectedComponent: z.string().max(256).optional(),
  recommendation: z.string().max(2048).optional(),
});

const agentTelemetrySchema = z.object({
  systemInfo: z.record(z.unknown()).optional().nullable(),
  resourceMetrics: z.record(z.unknown()).optional().nullable(),
  services: z.array(z.record(z.unknown())).optional().nullable(),
  openPorts: z.array(z.record(z.unknown())).optional().nullable(),
  networkConnections: z.array(z.record(z.unknown())).optional().nullable(),
  installedSoftware: z.array(z.record(z.unknown())).optional().nullable(),
  configData: z.record(z.unknown()).optional().nullable(),
  securityFindings: z.array(securityFindingSchema).max(100).optional().nullable(),
  collectedAt: z.string().datetime().optional().nullable(),
});

// Helper function to get the correct server URL (HTTPS for production, HTTP for localhost)
// Priority: PUBLIC_ODINFORGE_URL env var > request host
// This ensures agents always connect to the stable production URL across deployments
function getServerUrl(req: any): string {
  if (process.env.PUBLIC_ODINFORGE_URL) {
    return process.env.PUBLIC_ODINFORGE_URL.replace(/\/$/, "");
  }
  const host = req.get("host") || "localhost:5000";
  const isLocalhost = host.startsWith("localhost") || host.startsWith("127.0.0.1");
  const protocol = isLocalhost ? "http" : "https";
  return `${protocol}://${host}`;
}

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
  app.get("/healthz", (_req, res) => {
    res.status(200).json({
      ok: true,
      service: "odinforge-backend",
      ts: new Date().toISOString(),
    });
  });

  app.get("/readyz", async (_req, res) => {
    res.status(200).json({
      ok: true,
      ready: true,
      ts: new Date().toISOString(),
    });
  });
  
  // ========== AGENT BINARY DOWNLOADS ==========
  // Serve agent binaries from public/agents directory (no auth required for download)
  // Rate limited to prevent bandwidth abuse on large binary downloads
  app.get("/agents/:filename", apiRateLimiter, (req, res) => {
    const filename = req.params.filename;
    // Only allow specific binary filenames
    const validBinaries = [
      "odinforge-agent-linux-amd64",
      "odinforge-agent-linux-arm64",
      "odinforge-agent-darwin-amd64",
      "odinforge-agent-darwin-arm64",
      "odinforge-agent-windows-amd64.exe"
    ];
    
    if (!validBinaries.includes(filename)) {
      return res.status(404).json({ error: "Binary not found" });
    }
    
    const binaryPath = path.join(process.cwd(), "public", "agents", filename);
    if (!fs.existsSync(binaryPath)) {
      return res.status(404).json({ error: "Binary not yet built" });
    }
    
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.sendFile(binaryPath);
  });

  // Serve install.sh script for curl-based installation (no auth required)
  // Automatically injects the server URL so users don't need to enter it manually
  // Optional: ?token=<registration-token> to embed the token in the script
  app.get("/api/agents/install.sh", apiRateLimiter, (req, res) => {
    const scriptPath = path.join(process.cwd(), "odinforge-agent", "install.sh");
    
    if (fs.existsSync(scriptPath)) {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Content-Disposition", "inline; filename=install.sh");
      let script = fs.readFileSync(scriptPath, "utf-8");
      // Inject the server URL - replace placeholder with actual URL
      const serverUrl = getServerUrl(req);
      script = script.replace(/__SERVER_URL_PLACEHOLDER__/g, serverUrl);
      // Inject registration token if provided, otherwise remove placeholder for clarity
      const token = req.query.token as string | undefined;
      script = script.replace(/__REGISTRATION_TOKEN_PLACEHOLDER__/g, token || "");
      res.send(script);
    } else {
      res.status(404).json({ error: "Install script not found" });
    }
  });

  // Serve install.ps1 script for PowerShell-based installation (no auth required)
  // Automatically injects the server URL so users don't need to enter it manually
  // Optional: ?token=<registration-token> to embed the token in the script
  app.get("/api/agents/install.ps1", apiRateLimiter, (req, res) => {
    const scriptPath = path.join(process.cwd(), "odinforge-agent", "install.ps1");
    
    if (fs.existsSync(scriptPath)) {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Content-Disposition", "inline; filename=install.ps1");
      let script = fs.readFileSync(scriptPath, "utf-8");
      // Inject the server URL - replace placeholder with actual URL
      const serverUrl = getServerUrl(req);
      script = script.replace(/__SERVER_URL_PLACEHOLDER__/g, serverUrl);
      // Inject registration token if provided, otherwise remove placeholder for clarity
      const token = req.query.token as string | undefined;
      script = script.replace(/__REGISTRATION_TOKEN_PLACEHOLDER__/g, token || "");
      res.send(script);
    } else {
      res.status(404).json({ error: "Install script not found" });
    }
  });

  // Agent release info endpoint (no auth required for download center)
  app.get("/api/agent-releases/latest", apiRateLimiter, (req, res) => {
    res.json({
      release: AGENT_RELEASE,
      instructions: INSTALLATION_INSTRUCTIONS
    });
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

      const passwordHash = await hashPassword(password);
      const user = await storage.createUIUser({
        email,
        passwordHash,
        displayName: displayName || email.split("@")[0],
        tenantId,
        organizationId,
        roleId: "security_analyst", // Default role for new signups
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
      res.json({
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          roleId: user.roleId,
          role: role || undefined,
          tenantId: user.tenantId,
          organizationId: user.organizationId,
          lastLoginAt: user.lastLoginAt,
          lastActivityAt: user.lastActivityAt,
        },
      });
    } catch (error) {
      console.error("Session fetch error:", error);
      res.status(500).json({ error: "Failed to fetch session" });
    }
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
  
  // Apply API-wide rate limiting as a fallback for all endpoints
  app.use("/api", apiRateLimiter);

  app.post("/api/aev/evaluate", evaluationRateLimiter, async (req, res) => {
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
      });
    } catch (error) {
      console.error("Error starting evaluation:", error);
      res.status(500).json({ error: "Failed to start evaluation" });
    }
  });

  app.get("/api/aev/evaluations", apiRateLimiter, async (req, res) => {
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

  app.get("/api/aev/evaluations/:id", apiRateLimiter, async (req, res) => {
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

  app.delete("/api/aev/evaluations/:id", apiRateLimiter, async (req, res) => {
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

  app.patch("/api/aev/evaluations/:id/archive", apiRateLimiter, async (req, res) => {
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

  app.patch("/api/aev/evaluations/:id/unarchive", apiRateLimiter, async (req, res) => {
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
  app.get("/api/aev/live-scans", apiRateLimiter, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const results = await storage.getLiveScanResults(organizationId);
      res.json(results);
    } catch (error) {
      console.error("Error fetching live scan results:", error);
      res.status(500).json({ error: "Failed to fetch live scan results" });
    }
  });

  app.get("/api/aev/live-scans/:evaluationId", apiRateLimiter, async (req, res) => {
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

  // Abort a running live scan
  app.post("/api/aev/live-scans/:evaluationId/abort", apiRateLimiter, async (req, res) => {
    try {
      const { abortCurrentScan } = await import("./services/live-network-testing");
      const aborted = abortCurrentScan();
      
      if (aborted) {
        await storage.updateLiveScanResult(req.params.evaluationId, { 
          status: "aborted",
          errorMessage: "Scan aborted by user",
        });
      }
      
      res.json({ success: aborted });
    } catch (error) {
      console.error("Error aborting live scan:", error);
      res.status(500).json({ error: "Failed to abort scan" });
    }
  });

  app.get("/api/aev/stats", apiRateLimiter, async (req, res) => {
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

      res.json({
        total: evaluations.length,
        active: evaluations.filter(e => e.status === "pending" || e.status === "in_progress").length,
        completed: evaluations.filter(e => e.status === "completed").length,
        exploitable: exploitableCount,
        safe: safeCount,
        avgConfidence,
      });
    } catch (error) {
      console.error("Error fetching stats:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  // ========== EXECUTION MODE ENDPOINTS ==========
  
  app.get("/api/aev/execution-modes", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/execution-modes/current", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/execution-modes/set", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/execution-modes/validate-operation", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/approval-requests", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/approval-requests/:id", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/approval-requests", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/approval-requests/:id/approve", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/approval-requests/:id/deny", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/approval-requests/:id/cancel", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/audit-logs", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/audit-logs/verify", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/sandbox/config", apiRateLimiter, async (req, res) => {
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
  
  app.put("/api/aev/sandbox/config", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/sandbox/stats", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/aev/sandbox/kill-switch", apiRateLimiter, async (req, res) => {
    try {
      const { sandboxExecutor } = await import("./services/validation/sandbox-executor");
      const state = sandboxExecutor.getKillSwitchState();
      res.json(state);
    } catch (error) {
      console.error("Error fetching kill switch state:", error);
      res.status(500).json({ error: "Failed to fetch kill switch state" });
    }
  });
  
  app.post("/api/aev/sandbox/kill-switch/engage", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/sandbox/kill-switch/disengage", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/sandbox/abort/:operationId", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/sandbox/abort-all", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/sandbox/validate-target", apiRateLimiter, async (req, res) => {
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
  
  app.post("/api/aev/sandbox/check-limits", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/system/websocket-stats", apiRateLimiter, async (req, res) => {
    try {
      const stats = wsService.getStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching WebSocket stats:", error);
      res.status(500).json({ error: "Failed to fetch WebSocket stats" });
    }
  });

  // ========== REPORTING ENDPOINTS ==========
  
  app.post("/api/reports/generate", reportRateLimiter, async (req, res) => {
    try {
      const { type, format, from, to, framework, organizationId = "default", evaluationId, engagementMetadata } = req.body;
      
      // If evaluationId is provided, generate single-evaluation report
      if (evaluationId) {
        if (!type || !format) {
          return res.status(400).json({ error: "Missing required fields: type, format" });
        }
        
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
          dateRangeFrom: new Date(),
          dateRangeTo: new Date(),
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
      // Set toDate to end of day (23:59:59.999) to include entire end date
      const toDate = new Date(to);
      toDate.setHours(23, 59, 59, 999);
      
      let reportData: any;
      let title = "";
      
      switch (type) {
        case "executive_summary":
          reportData = await reportGenerator.generateExecutiveSummary(fromDate, toDate, organizationId);
          title = `Executive Summary - ${fromDate.toLocaleDateString()} to ${toDate.toLocaleDateString()}`;
          break;
        case "technical_deep_dive":
          reportData = await reportGenerator.generateTechnicalReport(fromDate, toDate, organizationId);
          title = `Technical Report - ${fromDate.toLocaleDateString()} to ${toDate.toLocaleDateString()}`;
          break;
        case "compliance_mapping":
          if (!framework) {
            return res.status(400).json({ error: "Compliance reports require a framework parameter" });
          }
          if (!complianceFrameworks.includes(framework)) {
            return res.status(400).json({ error: `Invalid framework. Valid options: ${complianceFrameworks.join(", ")}` });
          }
          reportData = await reportGenerator.generateComplianceReport(framework, fromDate, toDate, organizationId);
          title = `Compliance Report (${framework.toUpperCase()}) - ${fromDate.toLocaleDateString()} to ${toDate.toLocaleDateString()}`;
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
  
  app.get("/api/reports", apiRateLimiter, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const reports = await storage.getReports(organizationId);
      res.json(reports);
    } catch (error) {
      console.error("Error fetching reports:", error);
      res.status(500).json({ error: "Failed to fetch reports" });
    }
  });
  
  app.get("/api/reports/:id", apiRateLimiter, async (req, res) => {
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
  
  app.delete("/api/reports/:id", apiRateLimiter, async (req, res) => {
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
  
  app.get("/api/reports/:id/download", apiRateLimiter, async (req, res) => {
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
        case "json":
        default:
          content = reportGenerator.exportToJSON(report.content);
          filename = `${report.title.replace(/\s+/g, "_")}.json`;
          contentType = "application/json";
          break;
      }
      
      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.send(content);
    } catch (error) {
      console.error("Error downloading report:", error);
      res.status(500).json({ error: "Failed to download report" });
    }
  });

  // Domain Scan Report Generation
  app.get("/api/reports/domain-scan/:scanId", apiRateLimiter, async (req, res) => {
    try {
      const { scanId } = req.params;
      const format = (req.query.format as string) || "json";
      
      const reportData = await reconReportGenerator.generateDomainScanReport(scanId);
      if (!reportData) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      const filename = `domain-scan-${scanId}-${Date.now()}`;
      
      if (format === "csv") {
        const csv = reconReportGenerator.exportToCSV(reportData);
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}.csv"`);
        return res.send(csv);
      }
      
      if (format === "download") {
        const json = reconReportGenerator.exportToJSON(reportData);
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}.json"`);
        return res.send(json);
      }
      
      res.json(reportData);
    } catch (error) {
      console.error("Error generating domain scan report:", error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  // Web App Scan Report Generation
  app.get("/api/reports/web-app-scan/:scanId", apiRateLimiter, async (req, res) => {
    try {
      const { scanId } = req.params;
      const format = (req.query.format as string) || "json";
      
      const reportData = await reconReportGenerator.generateWebAppScanReport(scanId);
      if (!reportData) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      const filename = `web-app-scan-${scanId}-${Date.now()}`;
      
      if (format === "csv") {
        const csv = reconReportGenerator.exportToCSV(reportData);
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}.csv"`);
        return res.send(csv);
      }
      
      if (format === "download") {
        const json = reconReportGenerator.exportToJSON(reportData);
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}.json"`);
        return res.send(json);
      }
      
      res.json(reportData);
    } catch (error) {
      console.error("Error generating web app scan report:", error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  // Web App Scan Report Generation with persistence
  app.post("/api/reports/web-app-scan/:scanId", reportRateLimiter, async (req, res) => {
    try {
      const { scanId } = req.params;
      const { includeCompliance = false, framework, organizationId = "default" } = req.body;
      
      // Get scan data
      const scan = await storage.getWebAppReconScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      // Generate report data
      const reportData = await reconReportGenerator.generateWebAppScanReport(scanId);
      if (!reportData) {
        return res.status(404).json({ error: "Failed to generate report data" });
      }
      
      // Create report title
      const reportType = includeCompliance ? "technical_deep_dive" : "executive_summary";
      const title = `Web App Security Assessment - ${scan.targetUrl}`;
      
      // Save report to database
      const report = await storage.createReport({
        organizationId,
        title,
        reportType,
        status: "completed",
        dateRangeFrom: new Date(scan.createdAt),
        dateRangeTo: new Date(),
        framework: includeCompliance ? framework : null,
        content: {
          executiveSummary: {
            overview: `Security assessment of ${scan.targetUrl}`,
            findingsCount: scan.validatedFindings?.length || 0,
            riskLevel: (scan.validatedFindings?.length || 0) > 0 ? "High" : "Low",
          },
          technicalFindings: scan.validatedFindings || [],
          reconResult: scan.reconResult,
          scanMetadata: {
            scanId: scan.id,
            targetUrl: scan.targetUrl,
            completedAt: scan.updatedAt || scan.createdAt,
          }
        },
      });
      
      res.json({
        success: true,
        reportId: report.id,
        title: report.title,
        message: "Report generated and saved successfully"
      });
    } catch (error) {
      console.error("Error generating web app scan report:", error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  app.get("/api/reports/enhanced/:evaluationId", apiRateLimiter, async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const includeKillChain = req.query.includeKillChain !== "false";
      const includeRemediation = req.query.includeRemediation !== "false";
      const includeVulnerabilityDetails = req.query.includeVulnerabilityDetails !== "false";
      
      const enhancedReport = await reportGenerator.generateEnhancedReport(evaluationId, {
        includeKillChain,
        includeRemediation,
        includeVulnerabilityDetails,
      });
      
      res.json(enhancedReport);
    } catch (error: any) {
      console.error("Error generating enhanced report:", error);
      if (error.message?.includes("not found")) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: "Failed to generate enhanced report" });
    }
  });

  app.post("/api/reports/enhanced/date-range", reportRateLimiter, async (req, res) => {
    try {
      const { from, to, organizationId = "default", includeKillChain = true, includeRemediation = true } = req.body;
      
      if (!from || !to) {
        return res.status(400).json({ error: "Missing required fields: from, to" });
      }
      
      const fromDate = new Date(from);
      const toDate = new Date(to);
      toDate.setHours(23, 59, 59, 999);
      
      const enhancedReport = await reportGenerator.generateEnhancedDateRangeReport(
        fromDate,
        toDate,
        organizationId,
        { includeKillChain, includeRemediation }
      );
      
      res.json(enhancedReport);
    } catch (error) {
      console.error("Error generating enhanced date range report:", error);
      res.status(500).json({ error: "Failed to generate enhanced report" });
    }
  });

  // ========== REPORT V2 NARRATIVE ENDPOINTS ==========
  registerReportV2Routes(app);

  // ========== JOB QUEUE ENDPOINTS ==========
  registerJobQueueRoutes(app);

  // ========== EVIDENCE EXPORT ENDPOINT ==========
  
  app.post("/api/evidence/:evaluationId/export", apiRateLimiter, async (req, res) => {
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

  // ========== SCHEDULED SCAN ENDPOINTS ==========
  
  function calculateInitialNextRunAt(data: {
    frequency: string;
    timeOfDay?: string | null;
    dayOfWeek?: number | null;
    dayOfMonth?: number | null;
  }): Date {
    const now = new Date();
    let nextRun = new Date(now);
    const [hours, minutes] = (data.timeOfDay || "00:00").split(":").map(Number);
    nextRun.setHours(hours, minutes, 0, 0);

    switch (data.frequency) {
      case "once":
        if (nextRun <= now) {
          nextRun.setDate(nextRun.getDate() + 1);
        }
        break;
      case "daily":
        if (nextRun <= now) {
          nextRun.setDate(nextRun.getDate() + 1);
        }
        break;
      case "weekly":
        const targetDay = data.dayOfWeek ?? 0;
        const currentDay = now.getDay();
        let daysUntilTarget = targetDay - currentDay;
        if (daysUntilTarget < 0 || (daysUntilTarget === 0 && nextRun <= now)) {
          daysUntilTarget += 7;
        }
        nextRun.setDate(now.getDate() + daysUntilTarget);
        break;
      case "monthly":
        nextRun.setDate(data.dayOfMonth ?? 1);
        if (nextRun <= now) {
          nextRun.setMonth(nextRun.getMonth() + 1);
        }
        break;
      case "quarterly":
        const currentQuarter = Math.floor(now.getMonth() / 3);
        nextRun = new Date(now.getFullYear(), (currentQuarter + 1) * 3, data.dayOfMonth ?? 1);
        nextRun.setHours(hours, minutes, 0, 0);
        if (nextRun <= now) {
          nextRun.setMonth(nextRun.getMonth() + 3);
        }
        break;
      default:
        nextRun.setDate(nextRun.getDate() + 1);
    }
    return nextRun;
  }
  
  app.post("/api/scheduled-scans", apiRateLimiter, async (req, res) => {
    try {
      const parsed = insertScheduledScanSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error });
      }
      
      const nextRunAt = parsed.data.nextRunAt || calculateInitialNextRunAt(parsed.data);
      const scan = await storage.createScheduledScan({
        ...parsed.data,
        nextRunAt,
      });
      res.json(scan);
    } catch (error) {
      console.error("Error creating scheduled scan:", error);
      res.status(500).json({ error: "Failed to create scheduled scan" });
    }
  });
  
  app.get("/api/scheduled-scans", apiRateLimiter, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const scans = await storage.getScheduledScans(organizationId);
      res.json(scans);
    } catch (error) {
      console.error("Error fetching scheduled scans:", error);
      res.status(500).json({ error: "Failed to fetch scheduled scans" });
    }
  });
  
  app.get("/api/scheduled-scans/:id", apiRateLimiter, async (req, res) => {
    try {
      const scan = await storage.getScheduledScan(req.params.id);
      if (!scan) {
        return res.status(404).json({ error: "Scheduled scan not found" });
      }
      res.json(scan);
    } catch (error) {
      console.error("Error fetching scheduled scan:", error);
      res.status(500).json({ error: "Failed to fetch scheduled scan" });
    }
  });
  
  app.patch("/api/scheduled-scans/:id", apiRateLimiter, async (req, res) => {
    try {
      const scan = await storage.getScheduledScan(req.params.id);
      if (!scan) {
        return res.status(404).json({ error: "Scheduled scan not found" });
      }
      await storage.updateScheduledScan(req.params.id, req.body);
      const updated = await storage.getScheduledScan(req.params.id);
      res.json(updated);
    } catch (error) {
      console.error("Error updating scheduled scan:", error);
      res.status(500).json({ error: "Failed to update scheduled scan" });
    }
  });
  
  app.delete("/api/scheduled-scans/:id", apiRateLimiter, async (req, res) => {
    try {
      const scan = await storage.getScheduledScan(req.params.id);
      if (!scan) {
        return res.status(404).json({ error: "Scheduled scan not found" });
      }
      await storage.deleteScheduledScan(req.params.id);
      res.json({ success: true, message: "Scheduled scan deleted successfully" });
    } catch (error) {
      console.error("Error deleting scheduled scan:", error);
      res.status(500).json({ error: "Failed to delete scheduled scan" });
    }
  });

  app.post("/api/scheduled-scans/:id/trigger", apiRateLimiter, async (req, res) => {
    try {
      const { triggerImmediateScan } = await import("./services/scheduler/scan-scheduler");
      const result = await triggerImmediateScan(req.params.id);
      if (!result) {
        return res.status(404).json({ error: "Scheduled scan not found" });
      }
      res.json({ success: true, batchJobId: result.batchJobId, message: "Scan triggered successfully" });
    } catch (error) {
      console.error("Error triggering scheduled scan:", error);
      res.status(500).json({ error: "Failed to trigger scheduled scan" });
    }
  });

  // ========== VALIDATION EVIDENCE ENDPOINTS ==========
  // Tenant context provided by global tenantMiddleware; enforce org scoping per route
  
  app.get("/api/evidence", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const organizationId = req.tenant!.organizationId;
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : undefined;
      const artifacts = await evidenceStorageService.queryEvidence({ organizationId, limit });
      res.json(artifacts);
    } catch (error) {
      console.error("Error fetching evidence artifacts:", error);
      res.status(500).json({ error: "Failed to fetch evidence artifacts" });
    }
  });

  app.get("/api/evidence/summary", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const organizationId = req.tenant!.organizationId;
      const summary = await evidenceStorageService.getSummary(organizationId);
      res.json(summary);
    } catch (error) {
      console.error("Error fetching evidence summary:", error);
      res.status(500).json({ error: "Failed to fetch evidence summary" });
    }
  });

  app.get("/api/evidence/:id", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const artifact = await evidenceStorageService.getEvidence(req.params.id);
      if (!artifact) {
        return res.status(404).json({ error: "Evidence artifact not found" });
      }
      if (artifact.organizationId !== req.tenant!.organizationId) {
        return res.status(403).json({ error: "Access denied to this evidence" });
      }
      res.json(artifact);
    } catch (error) {
      console.error("Error fetching evidence artifact:", error);
      res.status(500).json({ error: "Failed to fetch evidence artifact" });
    }
  });

  app.get("/api/evaluations/:evaluationId/evidence", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const organizationId = req.tenant!.organizationId;
      const artifacts = await evidenceStorageService.getEvidenceForEvaluation(req.params.evaluationId, organizationId);
      res.json(artifacts);
    } catch (error) {
      console.error("Error fetching evidence for evaluation:", error);
      res.status(500).json({ error: "Failed to fetch evidence for evaluation" });
    }
  });

  // Safety Decisions API - PolicyGuardian audit trail
  app.get("/api/evaluations/:evaluationId/safety-decisions", apiRateLimiter, async (req, res) => {
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

  app.get("/api/safety-decisions", apiRateLimiter, async (req, res) => {
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

  app.get("/api/safety-decisions/stats", apiRateLimiter, async (req, res) => {
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

  app.get("/api/findings/:findingId/evidence", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const organizationId = req.tenant!.organizationId;
      const artifacts = await evidenceStorageService.getEvidenceForFinding(req.params.findingId, organizationId);
      res.json(artifacts);
    } catch (error) {
      console.error("Error fetching evidence for finding:", error);
      res.status(500).json({ error: "Failed to fetch evidence for finding" });
    }
  });

  app.delete("/api/evidence/:id", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const artifact = await evidenceStorageService.getEvidence(req.params.id);
      if (!artifact) {
        return res.status(404).json({ error: "Evidence artifact not found" });
      }
      if (artifact.organizationId !== req.tenant!.organizationId) {
        return res.status(403).json({ error: "Access denied to delete this evidence" });
      }
      await evidenceStorageService.deleteEvidence(req.params.id);
      res.json({ success: true, message: "Evidence artifact deleted" });
    } catch (error) {
      console.error("Error deleting evidence artifact:", error);
      res.status(500).json({ error: "Failed to delete evidence artifact" });
    }
  });

  app.post("/api/evidence/cleanup", apiRateLimiter, async (req, res) => {
    try {
      const { evidenceStorageService } = await import("./services/validation/evidence-storage-service");
      const result = await evidenceStorageService.cleanupOldArtifacts();
      res.json({ success: true, deletedCount: result.deletedCount });
    } catch (error) {
      console.error("Error cleaning up evidence artifacts:", error);
      res.status(500).json({ error: "Failed to clean up evidence artifacts" });
    }
  });

  // ========== GOVERNANCE ENDPOINTS ==========
  
  // Rate Limit Status - MUST come before :organizationId route
  app.get("/api/governance/rate-limits", apiRateLimiter, async (req, res) => {
    try {
      const statuses = getAllRateLimitStatuses();
      res.json(statuses);
    } catch (error) {
      console.error("Error fetching rate limit status:", error);
      res.status(500).json({ error: "Failed to fetch rate limit status" });
    }
  });

  // Get or create organization governance settings
  app.get("/api/governance/:organizationId", apiRateLimiter, async (req, res) => {
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

  app.patch("/api/governance/:organizationId", apiRateLimiter, async (req, res) => {
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
  app.post("/api/governance/:organizationId/kill-switch", apiRateLimiter, async (req, res) => {
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
  app.get("/api/authorization-logs/:organizationId", apiRateLimiter, async (req, res) => {
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
  app.get("/api/scope-rules/:organizationId", apiRateLimiter, async (req, res) => {
    try {
      const rules = await storage.getScopeRules(req.params.organizationId);
      res.json(rules);
    } catch (error) {
      console.error("Error fetching scope rules:", error);
      res.status(500).json({ error: "Failed to fetch scope rules" });
    }
  });

  app.post("/api/scope-rules", apiRateLimiter, async (req, res) => {
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

  app.delete("/api/scope-rules/:id", apiRateLimiter, async (req, res) => {
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

  // ========== ADVANCED AI ENDPOINTS ==========

  // Adversary Profiles
  app.get("/api/adversary-profiles", apiRateLimiter, async (req, res) => {
    try {
      let profiles = await storage.getAdversaryProfiles();
      
      // Seed built-in profiles if none exist
      if (profiles.length === 0) {
        const builtInProfiles = [
          {
            name: "Script Kiddie",
            profileType: "script_kiddie",
            description: "Low-skill attacker using pre-made tools and scripts",
            capabilities: {
              technicalSophistication: 2,
              resources: 1,
              persistence: 2,
              stealth: 1,
              targetedAttacks: false,
              zerodays: false,
              socialEngineering: false,
              physicalAccess: false,
            },
            typicalTTPs: ["T1190", "T1110", "T1059"],
            motivations: ["curiosity", "recognition"],
            targetPreferences: ["any", "opportunistic"],
            avgDwellTime: 1,
            detectionDifficulty: "low",
            isBuiltIn: true,
          },
          {
            name: "Organized Crime",
            profileType: "organized_crime",
            description: "Financially motivated criminal organization with moderate resources",
            capabilities: {
              technicalSophistication: 6,
              resources: 7,
              persistence: 7,
              stealth: 5,
              targetedAttacks: true,
              zerodays: false,
              socialEngineering: true,
              physicalAccess: false,
            },
            typicalTTPs: ["T1566", "T1486", "T1078", "T1027"],
            motivations: ["financial", "ransomware"],
            targetPreferences: ["healthcare", "finance", "retail"],
            avgDwellTime: 14,
            detectionDifficulty: "medium",
            isBuiltIn: true,
          },
          {
            name: "Nation State Actor",
            profileType: "nation_state",
            description: "State-sponsored threat actor with extensive resources and capabilities",
            capabilities: {
              technicalSophistication: 10,
              resources: 10,
              persistence: 10,
              stealth: 9,
              targetedAttacks: true,
              zerodays: true,
              socialEngineering: true,
              physicalAccess: true,
            },
            typicalTTPs: ["T1195", "T1190", "T1003", "T1071", "T1020"],
            motivations: ["espionage", "disruption", "intelligence"],
            targetPreferences: ["government", "defense", "critical_infrastructure"],
            avgDwellTime: 365,
            detectionDifficulty: "very_high",
            isBuiltIn: true,
          },
          {
            name: "Insider Threat",
            profileType: "insider_threat",
            description: "Malicious insider with legitimate access and system knowledge",
            capabilities: {
              technicalSophistication: 5,
              resources: 3,
              persistence: 6,
              stealth: 8,
              targetedAttacks: true,
              zerodays: false,
              socialEngineering: false,
              physicalAccess: true,
            },
            typicalTTPs: ["T1078", "T1530", "T1567", "T1552"],
            motivations: ["financial", "revenge", "ideology"],
            targetPreferences: ["employer_data", "trade_secrets"],
            avgDwellTime: 90,
            detectionDifficulty: "high",
            isBuiltIn: true,
          },
          {
            name: "APT Group",
            profileType: "apt_group",
            description: "Advanced Persistent Threat group with sophisticated tradecraft",
            capabilities: {
              technicalSophistication: 9,
              resources: 8,
              persistence: 9,
              stealth: 8,
              targetedAttacks: true,
              zerodays: true,
              socialEngineering: true,
              physicalAccess: false,
            },
            typicalTTPs: ["T1566.001", "T1059.001", "T1003", "T1021", "T1071"],
            motivations: ["espionage", "financial"],
            targetPreferences: ["technology", "finance", "energy"],
            avgDwellTime: 180,
            detectionDifficulty: "high",
            isBuiltIn: true,
          },
        ];
        
        for (const profile of builtInProfiles) {
          await storage.createAdversaryProfile(profile);
        }
        
        profiles = await storage.getAdversaryProfiles();
      }
      
      res.json(profiles);
    } catch (error) {
      console.error("Error fetching adversary profiles:", error);
      res.status(500).json({ error: "Failed to fetch adversary profiles" });
    }
  });

  app.get("/api/adversary-profiles/:id", apiRateLimiter, async (req, res) => {
    try {
      const profile = await storage.getAdversaryProfile(req.params.id);
      if (!profile) {
        return res.status(404).json({ error: "Adversary profile not found" });
      }
      res.json(profile);
    } catch (error) {
      console.error("Error fetching adversary profile:", error);
      res.status(500).json({ error: "Failed to fetch adversary profile" });
    }
  });

  app.post("/api/adversary-profiles", apiRateLimiter, async (req, res) => {
    try {
      const profile = await storage.createAdversaryProfile(req.body);
      res.json(profile);
    } catch (error) {
      console.error("Error creating adversary profile:", error);
      res.status(500).json({ error: "Failed to create adversary profile" });
    }
  });

  // Attack Predictions - computed from real evaluation data
  app.get("/api/attack-predictions/:organizationId", apiRateLimiter, async (req, res) => {
    try {
      const timeHorizon = req.query.timeHorizon as string || "30d";
      const predictions = await calculateAttackPredictions(req.params.organizationId, timeHorizon);
      res.json(predictions);
    } catch (error) {
      console.error("Error calculating attack predictions:", error);
      res.status(500).json({ error: "Failed to calculate attack predictions" });
    }
  });

  app.post("/api/attack-predictions/generate", apiRateLimiter, async (req, res) => {
    try {
      const { organizationId, timeHorizon } = req.body;
      const predictions = await calculateAttackPredictions(organizationId, timeHorizon || "30d");
      res.json(predictions);
    } catch (error) {
      console.error("Error generating attack prediction:", error);
      res.status(500).json({ error: "Failed to generate attack prediction" });
    }
  });

  // Defensive Posture - computed from real evaluation data
  app.get("/api/defensive-posture/:organizationId", apiRateLimiter, async (req, res) => {
    try {
      const posture = await calculateDefensivePosture(req.params.organizationId);
      res.json(posture);
    } catch (error) {
      console.error("Error calculating defensive posture:", error);
      res.status(500).json({ error: "Failed to calculate defensive posture" });
    }
  });

  app.get("/api/defensive-posture/:organizationId/history", apiRateLimiter, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 30;
      const history = await storage.getDefensivePostureHistory(req.params.organizationId, limit);
      res.json(history);
    } catch (error) {
      console.error("Error fetching posture history:", error);
      res.status(500).json({ error: "Failed to fetch posture history" });
    }
  });

  // Purple Team Findings
  app.get("/api/purple-team/:organizationId", apiRateLimiter, async (req, res) => {
    try {
      const findings = await storage.getPurpleTeamFindings(req.params.organizationId);
      res.json(findings);
    } catch (error) {
      console.error("Error fetching purple team findings:", error);
      res.status(500).json({ error: "Failed to fetch purple team findings" });
    }
  });

  app.post("/api/purple-team", apiRateLimiter, async (req, res) => {
    try {
      const finding = await storage.createPurpleTeamFinding(req.body);
      res.json(finding);
    } catch (error) {
      console.error("Error creating purple team finding:", error);
      res.status(500).json({ error: "Failed to create purple team finding" });
    }
  });

  app.patch("/api/purple-team/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.updatePurpleTeamFinding(req.params.id, req.body);
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating purple team finding:", error);
      res.status(500).json({ error: "Failed to update purple team finding" });
    }
  });

  // AI Simulations
  app.get("/api/ai-simulations/:organizationId", apiRateLimiter, async (req, res) => {
    try {
      const simulations = await storage.getAiSimulations(req.params.organizationId);
      res.json(simulations);
    } catch (error) {
      console.error("Error fetching AI simulations:", error);
      res.status(500).json({ error: "Failed to fetch AI simulations" });
    }
  });

  app.post("/api/ai-simulations", simulationRateLimiter, async (req, res) => {
    try {
      const simulation = await storage.createAiSimulation({
        ...req.body,
        simulationStatus: "pending",
      });
      
      // Start simulation in background
      runAiSimulation(simulation.id);
      
      res.json(simulation);
    } catch (error) {
      console.error("Error creating AI simulation:", error);
      res.status(500).json({ error: "Failed to create AI simulation" });
    }
  });

  app.get("/api/ai-simulations/detail/:id", apiRateLimiter, async (req, res) => {
    try {
      const simulation = await storage.getAiSimulation(req.params.id);
      if (!simulation) {
        return res.status(404).json({ error: "Simulation not found" });
      }
      res.json(simulation);
    } catch (error) {
      console.error("Error fetching AI simulation:", error);
      res.status(500).json({ error: "Failed to fetch AI simulation" });
    }
  });

  // ============================================
  // INFRASTRUCTURE DATA INGESTION ENDPOINTS
  // ============================================

  // Get infrastructure statistics
  app.get("/api/infrastructure/stats", apiRateLimiter, async (req, res) => {
    try {
      const stats = await storage.getInfrastructureStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching infrastructure stats:", error);
      res.status(500).json({ error: "Failed to fetch infrastructure stats" });
    }
  });

  // ========== DISCOVERED ASSETS ==========

  app.get("/api/assets", apiRateLimiter, async (req, res) => {
    try {
      // Fetch discovered assets, cloud assets, and endpoint agents
      const [discoveredAssets, cloudAssetsList, allAgents] = await Promise.all([
        storage.getDiscoveredAssets(),
        storage.getCloudAssets(),
        storage.getEndpointAgents()
      ]);
      
      // Create a map of agent IDs to agent records for quick lookup
      const agentMap = new Map(allAgents.map(agent => [agent.id, agent]));
      
      // Transform cloud assets to a unified format compatible with the Assets page
      const transformedCloudAssets = cloudAssetsList.map(ca => {
        // Verify agent exists in endpoint_agents table - don't trust cloud_assets fields alone
        const agent = ca.agentId ? agentMap.get(ca.agentId) : null;
        const hasValidAgent = agent !== undefined && agent !== null;
        
        return {
          id: ca.id,
          organizationId: ca.organizationId,
          assetIdentifier: ca.providerResourceId,
          displayName: ca.assetName,
          assetType: ca.assetType,
          status: ca.powerState === 'running' ? 'active' : (ca.powerState === 'stopped' ? 'inactive' : 'active'),
          ipAddresses: [...(ca.publicIpAddresses || []), ...(ca.privateIpAddresses || [])],
          hostname: ca.assetName,
          fqdn: null,
          macAddress: null,
          cloudProvider: ca.provider,
          cloudRegion: ca.region,
          cloudAccountId: null,
          cloudResourceId: ca.providerResourceId,
          cloudTags: ca.providerTags,
          operatingSystem: null,
          osVersion: null,
          installedSoftware: null,
          discoveredPorts: null,
          discoveredServices: null,
          source: 'cloud_discovery' as const,
          sourceId: ca.connectionId,
          lastSeen: ca.lastSeenAt,
          firstSeen: ca.firstDiscoveredAt,
          agentId: hasValidAgent ? ca.agentId : null,
          agentStatus: hasValidAgent ? agent.status : null,
          metadata: {
            instanceType: ca.instanceType,
            cpuCount: ca.cpuCount,
            memoryMb: ca.memoryMb,
            availabilityZone: ca.availabilityZone,
            powerState: ca.powerState,
            healthStatus: ca.healthStatus,
            agentDeployable: ca.agentDeployable,
            agentDeploymentStatus: hasValidAgent ? ca.agentDeploymentStatus : null
          },
          createdAt: ca.createdAt,
          updatedAt: ca.updatedAt
        };
      });
      
      // Combine both lists - cloud assets first (most recently discovered)
      const allAssets = [...transformedCloudAssets, ...discoveredAssets];
      res.json(allAssets);
    } catch (error) {
      console.error("Error fetching assets:", error);
      res.status(500).json({ error: "Failed to fetch assets" });
    }
  });

  app.get("/api/assets/:id", apiRateLimiter, async (req, res) => {
    try {
      const asset = await storage.getDiscoveredAsset(req.params.id);
      if (!asset) {
        return res.status(404).json({ error: "Asset not found" });
      }
      res.json(asset);
    } catch (error) {
      console.error("Error fetching asset:", error);
      res.status(500).json({ error: "Failed to fetch asset" });
    }
  });

  app.get("/api/assets/:id/vulnerabilities", apiRateLimiter, async (req, res) => {
    try {
      const vulns = await storage.getVulnerabilityImportsByAssetId(req.params.id);
      res.json(vulns);
    } catch (error) {
      console.error("Error fetching asset vulnerabilities:", error);
      res.status(500).json({ error: "Failed to fetch asset vulnerabilities" });
    }
  });

  app.patch("/api/assets/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.updateDiscoveredAsset(req.params.id, req.body);
      const updated = await storage.getDiscoveredAsset(req.params.id);
      res.json(updated);
    } catch (error) {
      console.error("Error updating asset:", error);
      res.status(500).json({ error: "Failed to update asset" });
    }
  });

  app.delete("/api/assets/:id", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const assetId = req.params.id;
      if (assetId.startsWith("casset-")) {
        await storage.deleteCloudAsset(assetId);
      } else {
        await storage.deleteDiscoveredAsset(assetId);
      }
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting asset:", error);
      res.status(500).json({ error: "Failed to delete asset" });
    }
  });

  // ========== VULNERABILITY IMPORTS ==========

  app.get("/api/vulnerabilities", apiRateLimiter, async (req, res) => {
    try {
      const vulns = await storage.getVulnerabilityImports();
      res.json(vulns);
    } catch (error) {
      console.error("Error fetching vulnerabilities:", error);
      res.status(500).json({ error: "Failed to fetch vulnerabilities" });
    }
  });

  app.get("/api/vulnerabilities/:id", apiRateLimiter, async (req, res) => {
    try {
      const vuln = await storage.getVulnerabilityImport(req.params.id);
      if (!vuln) {
        return res.status(404).json({ error: "Vulnerability not found" });
      }
      res.json(vuln);
    } catch (error) {
      console.error("Error fetching vulnerability:", error);
      res.status(500).json({ error: "Failed to fetch vulnerability" });
    }
  });

  app.patch("/api/vulnerabilities/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.updateVulnerabilityImport(req.params.id, req.body);
      const updated = await storage.getVulnerabilityImport(req.params.id);
      res.json(updated);
    } catch (error) {
      console.error("Error updating vulnerability:", error);
      res.status(500).json({ error: "Failed to update vulnerability" });
    }
  });

  // Create AEV evaluation from imported vulnerability
  app.post("/api/vulnerabilities/:id/evaluate", evaluationRateLimiter, async (req, res) => {
    try {
      const vuln = await storage.getVulnerabilityImport(req.params.id);
      if (!vuln) {
        return res.status(404).json({ error: "Vulnerability not found" });
      }

      // Create evaluation from vulnerability
      const evaluation = await storage.createEvaluation({
        assetId: vuln.affectedHost || vuln.assetId || "unknown",
        exposureType: vuln.cveId ? "cve" : "misconfiguration",
        priority: vuln.severity === "critical" ? "critical" : 
                  vuln.severity === "high" ? "high" : 
                  vuln.severity === "medium" ? "medium" : "low",
        description: `${vuln.title}${vuln.cveId ? ` (${vuln.cveId})` : ""}: ${vuln.description || "No description"}`,
        status: "pending",
      });

      // Link vulnerability to evaluation
      await storage.updateVulnerabilityImport(req.params.id, { aevEvaluationId: evaluation.id });

      // Start evaluation in background
      runEvaluation(evaluation.id, {
        assetId: evaluation.assetId,
        exposureType: evaluation.exposureType,
        priority: evaluation.priority,
        description: evaluation.description,
      });

      res.json({ evaluation, vulnerability: vuln });
    } catch (error) {
      console.error("Error creating evaluation from vulnerability:", error);
      res.status(500).json({ error: "Failed to create evaluation" });
    }
  });

  // ========== IMPORT JOBS ==========

  app.get("/api/imports", apiRateLimiter, async (req, res) => {
    try {
      const jobs = await storage.getImportJobs();
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching import jobs:", error);
      res.status(500).json({ error: "Failed to fetch import jobs" });
    }
  });

  app.get("/api/imports/:id", apiRateLimiter, async (req, res) => {
    try {
      const job = await storage.getImportJob(req.params.id);
      if (!job) {
        return res.status(404).json({ error: "Import job not found" });
      }
      res.json(job);
    } catch (error) {
      console.error("Error fetching import job:", error);
      res.status(500).json({ error: "Failed to fetch import job" });
    }
  });

  app.get("/api/imports/:id/vulnerabilities", apiRateLimiter, async (req, res) => {
    try {
      const vulns = await storage.getVulnerabilityImportsByJobId(req.params.id);
      res.json(vulns);
    } catch (error) {
      console.error("Error fetching import vulnerabilities:", error);
      res.status(500).json({ error: "Failed to fetch import vulnerabilities" });
    }
  });

  app.delete("/api/imports/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.deleteImportJob(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting import job:", error);
      res.status(500).json({ error: "Failed to delete import job" });
    }
  });

  // Upload and parse scanner file
  app.post("/api/imports/upload", apiRateLimiter, async (req, res) => {
    try {
      const { content, fileName, mimeType, name, sourceType } = req.body;
      
      if (!content) {
        return res.status(400).json({ error: "No file content provided" });
      }

      // Import parsers dynamically to avoid issues
      const { autoParseFile } = await import("./services/import-parsers");

      // Create import job
      const job = await storage.createImportJob({
        name: name || fileName || "Scanner Import",
        sourceType: sourceType || "custom_csv",
        fileName,
        status: "processing",
      });

      // Parse file
      const { result, detectedFormat } = autoParseFile(content, job.id, fileName, mimeType);

      // Store assets
      const createdAssets = await storage.createDiscoveredAssets(result.assets);
      
      // Link assets to vulnerabilities and store
      const vulnsWithAssets = result.vulnerabilities.map(v => {
        const matchingAsset = createdAssets.find(a => a.assetIdentifier === v.affectedHost);
        return { ...v, assetId: matchingAsset?.id };
      });
      await storage.createVulnerabilityImports(vulnsWithAssets);

      // Update job with results
      await storage.updateImportJob(job.id, {
        status: result.failedRecords > 0 && result.successfulRecords === 0 ? "failed" : "completed",
        progress: 100,
        totalRecords: result.totalRecords,
        processedRecords: result.totalRecords,
        successfulRecords: result.successfulRecords,
        failedRecords: result.failedRecords,
        assetsDiscovered: createdAssets.length,
        vulnerabilitiesFound: result.vulnerabilities.length,
        errors: result.errors.length > 0 ? result.errors : undefined,
        completedAt: new Date(),
        sourceType: detectedFormat,
      });

      const updatedJob = await storage.getImportJob(job.id);
      res.json({
        job: updatedJob,
        summary: {
          assetsDiscovered: createdAssets.length,
          vulnerabilitiesFound: result.vulnerabilities.length,
          errors: result.errors.length,
          detectedFormat,
        }
      });
    } catch (error) {
      console.error("Error processing import:", error);
      res.status(500).json({ error: "Failed to process import" });
    }
  });

  // ========== CLOUD CONNECTIONS ==========

  app.get("/api/cloud-connections", apiRateLimiter, async (req, res) => {
    try {
      const connections = await storage.getCloudConnections();
      res.json(connections);
    } catch (error) {
      console.error("Error fetching cloud connections:", error);
      res.status(500).json({ error: "Failed to fetch cloud connections" });
    }
  });

  app.get("/api/cloud-connections/:id", apiRateLimiter, async (req, res) => {
    try {
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        return res.status(404).json({ error: "Cloud connection not found" });
      }
      res.json(connection);
    } catch (error) {
      console.error("Error fetching cloud connection:", error);
      res.status(500).json({ error: "Failed to fetch cloud connection" });
    }
  });

  app.post("/api/cloud-connections", apiRateLimiter, async (req, res) => {
    try {
      const connection = await storage.createCloudConnection(req.body);
      res.json(connection);
    } catch (error) {
      console.error("Error creating cloud connection:", error);
      res.status(500).json({ error: "Failed to create cloud connection" });
    }
  });

  app.patch("/api/cloud-connections/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.updateCloudConnection(req.params.id, req.body);
      const updated = await storage.getCloudConnection(req.params.id);
      res.json(updated);
    } catch (error) {
      console.error("Error updating cloud connection:", error);
      res.status(500).json({ error: "Failed to update cloud connection" });
    }
  });

  app.delete("/api/cloud-connections/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.deleteCloudConnection(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting cloud connection:", error);
      res.status(500).json({ error: "Failed to delete cloud connection" });
    }
  });

  // Test cloud connection
  app.post("/api/cloud-connections/:id/test", apiRateLimiter, async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      const { secretsService } = await import("./services/secrets");
      
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        return res.status(404).json({ error: "Cloud connection not found" });
      }

      // Get stored credentials
      const storedCredential = await storage.getCloudCredentialByConnectionId(req.params.id);
      if (!storedCredential) {
        return res.status(400).json({ 
          success: false, 
          error: "No credentials configured. Please add credentials first." 
        });
      }

      // Decrypt credentials - they're already in CloudCredentials format { gcp: {...} } or { aws: {...} }
      const credentials = secretsService.decryptCredentials(
        storedCredential.encryptedData,
        storedCredential.encryptionKeyId
      );

      // Normalize provider to lowercase for adapter lookup
      const normalizedProvider = connection.provider.toLowerCase();

      // Actually test the credentials with the cloud provider
      // Credentials are already wrapped, e.g., { gcp: { serviceAccountJson: "..." } }
      const validation = await cloudIntegrationService.validateCredentials(
        normalizedProvider,
        credentials
      );

      if (!validation.valid) {
        await storage.updateCloudConnection(req.params.id, {
          status: "error",
          lastSyncStatus: "failed",
        });
        return res.status(400).json({ 
          success: false, 
          error: validation.error || "Failed to validate credentials with cloud provider" 
        });
      }

      // Update connection status on success
      await storage.updateCloudConnection(req.params.id, {
        status: "connected",
        lastSyncAt: new Date(),
        lastSyncStatus: "success",
      });

      res.json({ 
        success: true, 
        message: "Connection test successful - credentials validated with cloud provider",
        accountInfo: validation.accountInfo
      });
    } catch (error: any) {
      console.error("Error testing cloud connection:", error);
      res.status(500).json({ error: error.message || "Failed to test cloud connection" });
    }
  });

  // Store credentials for cloud connection (encrypted)
  app.post("/api/cloud-connections/:id/credentials", apiRateLimiter, async (req, res) => {
    try {
      console.log(`[CloudCredentials] Received credential update for connection ${req.params.id}`);
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        console.log(`[CloudCredentials] Connection ${req.params.id} not found`);
        return res.status(404).json({ error: "Cloud connection not found" });
      }
      console.log(`[CloudCredentials] Found connection: provider=${connection.provider}, name=${connection.name}`);

      // Frontend sends flat credentials, wrap them under the provider key
      // Normalize provider to lowercase for consistent credential structure
      const normalizedProvider = connection.provider.toLowerCase();
      let credentials = req.body;
      const receivedKeys = Object.keys(req.body);
      console.log(`[CloudCredentials] Received credential keys: ${receivedKeys.join(', ')}`);
      console.log(`[CloudCredentials] Provider: ${connection.provider} -> normalized: ${normalizedProvider}`);
      
      if (!credentials[normalizedProvider]) {
        credentials = { [normalizedProvider]: req.body };
        console.log(`[CloudCredentials] Wrapped credentials under provider key: ${normalizedProvider}`);
      }

      console.log(`[CloudCredentials] Validating credentials for ${normalizedProvider}...`);
      const result = await cloudIntegrationService.validateAndStoreCredentials(
        req.params.id,
        normalizedProvider,
        credentials
      );

      if (!result.success) {
        console.log(`[CloudCredentials] Validation failed: ${result.error}`);
        return res.status(400).json({ error: result.error });
      }

      console.log(`[CloudCredentials] Validation successful, updating connection status`);
      await storage.updateCloudConnection(req.params.id, {
        status: "connected",
        lastSyncAt: new Date(),
        lastSyncStatus: "success",
      });

      console.log(`[CloudCredentials] Connection ${req.params.id} credentials stored successfully`);
      res.json({ 
        success: true, 
        message: "Credentials validated and stored securely",
        accountInfo: result.accountInfo 
      });
    } catch (error) {
      console.error("[CloudCredentials] Error storing credentials:", error);
      res.status(500).json({ error: "Failed to store credentials" });
    }
  });

  // Start asset discovery for a cloud connection
  app.post("/api/cloud-connections/:id/discover", apiRateLimiter, async (req, res) => {
    try {
      console.log(`[CloudDiscovery] Starting discovery for connection ${req.params.id}`);
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        console.log(`[CloudDiscovery] Connection ${req.params.id} not found`);
        return res.status(404).json({ error: "Cloud connection not found" });
      }
      console.log(`[CloudDiscovery] Found connection: provider=${connection.provider}, name=${connection.name}, status=${connection.status}`);

      console.log(`[CloudDiscovery] Queuing discovery job for org ${connection.organizationId}...`);
      const result = await cloudIntegrationService.startDiscoveryJob(
        req.params.id,
        connection.organizationId,
        { regions: req.body.regions, triggeredBy: req.body.userId }
      );

      if (result.error) {
        console.log(`[CloudDiscovery] Failed to start discovery: ${result.error}`);
        return res.status(400).json({ error: result.error });
      }

      console.log(`[CloudDiscovery] Discovery job queued successfully, jobId: ${result.jobId}`);
      res.json({ 
        success: true, 
        jobId: result.jobId,
        message: "Asset discovery started" 
      });
    } catch (error) {
      console.error("[CloudDiscovery] Error starting discovery:", error);
      res.status(500).json({ error: "Failed to start asset discovery" });
    }
  });

  // Get discovered cloud assets for a connection
  app.get("/api/cloud-connections/:id/assets", apiRateLimiter, async (req, res) => {
    try {
      const assets = await storage.getCloudAssetsByConnection(req.params.id);
      res.json(assets);
    } catch (error) {
      console.error("Error fetching cloud assets:", error);
      res.status(500).json({ error: "Failed to fetch cloud assets" });
    }
  });

  // Get discovery jobs for a connection
  app.get("/api/cloud-connections/:id/discovery-jobs", apiRateLimiter, async (req, res) => {
    try {
      const jobs = await storage.getCloudDiscoveryJobs(req.params.id);
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching discovery jobs:", error);
      res.status(500).json({ error: "Failed to fetch discovery jobs" });
    }
  });
  
  // Scan IAM for a cloud connection
  app.post("/api/cloud-connections/:id/scan-iam", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        res.status(404).json({ error: "Cloud connection not found" });
        return;
      }
      
      const { secretsService } = await import("./services/secrets");
      
      const storedCredential = await storage.getCloudCredentialByConnectionId(req.params.id);
      if (!storedCredential) {
        res.status(400).json({ error: "No credentials stored for this connection" });
        return;
      }
      
      const credentials = secretsService.decryptCredentials(
        storedCredential.encryptedData,
        storedCredential.encryptionKeyId
      );
      
      // Normalize provider to lowercase for consistent comparison
      const normalizedProvider = connection.provider.toLowerCase();
      
      if (normalizedProvider === "aws") {
        const { awsAdapter } = await import("./services/cloud/aws-adapter");
        const result = await awsAdapter.scanIAM({ aws: credentials });
        res.json({
          success: true,
          provider: "aws",
          findings: result.findings,
          summary: result.summary,
          scannedAt: new Date().toISOString(),
        });
      } else if (normalizedProvider === "azure") {
        const { azureAdapter } = await import("./services/cloud/azure-adapter");
        const result = await azureAdapter.scanIAM({ azure: credentials });
        res.json({
          success: true,
          provider: "azure",
          findings: result.findings,
          summary: result.summary,
          scannedAt: new Date().toISOString(),
        });
      } else if (normalizedProvider === "gcp") {
        const { gcpAdapter } = await import("./services/cloud/gcp-adapter");
        const result = await gcpAdapter.scanIAM({ gcp: credentials });
        res.json({
          success: true,
          provider: "gcp",
          findings: result.findings,
          summary: result.summary,
          scannedAt: new Date().toISOString(),
        });
      } else {
        res.status(400).json({ error: `IAM scanning not supported for provider: ${normalizedProvider}` });
      }
    } catch (error) {
      console.error("Error scanning IAM:", error);
      res.status(500).json({ error: "Failed to scan IAM" });
    }
  });

  // Deploy agent to a specific cloud asset
  app.post("/api/cloud-assets/:id/deploy-agent", apiRateLimiter, async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      const { deploymentMethod, sshHost, sshPort, sshUsername, sshPassword, sshPrivateKey, useSudo } = req.body;
      
      // Validate SSH credentials when SSH method is selected
      if (deploymentMethod === "ssh") {
        if (!sshHost || typeof sshHost !== "string" || sshHost.trim() === "") {
          return res.status(400).json({ error: "SSH host is required" });
        }
        if (!sshUsername || typeof sshUsername !== "string" || sshUsername.trim() === "") {
          return res.status(400).json({ error: "SSH username is required" });
        }
        if (!sshPassword && !sshPrivateKey) {
          return res.status(400).json({ error: "Either SSH password or private key is required" });
        }
        // Validate port if provided
        if (sshPort !== undefined && sshPort !== null) {
          const portNum = typeof sshPort === "string" ? parseInt(sshPort, 10) : sshPort;
          if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            return res.status(400).json({ error: "SSH port must be a valid port number (1-65535)" });
          }
        }
      }
      
      // Build deployment options
      const deployOptions: any = { 
        initiatedBy: req.body.userId,
        deploymentMethod: deploymentMethod || "cloud-api",
      };
      
      if (deploymentMethod === "ssh") {
        const portNum = sshPort ? (typeof sshPort === "string" ? parseInt(sshPort, 10) : sshPort) : 22;
        deployOptions.sshCredentials = {
          host: sshHost.trim(),
          port: portNum,
          username: sshUsername.trim(),
          password: sshPassword,
          privateKey: sshPrivateKey,
          useSudo: useSudo !== false, // Default to true
        };
      }
      
      const result = await cloudIntegrationService.deployAgentToAsset(
        req.params.id,
        deployOptions
      );

      if (result.error) {
        return res.status(400).json({ error: result.error });
      }

      res.json({ 
        success: true, 
        jobId: result.jobId,
        message: "Agent deployment started" 
      });
    } catch (error) {
      console.error("Error deploying agent:", error);
      res.status(500).json({ error: "Failed to deploy agent" });
    }
  });

  // Redeploy agent to a cloud asset (force reinstall)
  app.post("/api/cloud-assets/:id/redeploy-agent", apiRateLimiter, async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const asset = await storage.getCloudAsset(req.params.id);
      if (!asset) {
        return res.status(404).json({ error: "Cloud asset not found" });
      }

      const previousAgentId = asset.agentId;

      // First, reset the deployment status to allow redeployment
      // This is necessary because deployAgentToAsset checks agentInstalled flag
      await storage.updateCloudAsset(req.params.id, {
        agentInstalled: false,
        agentDeploymentStatus: "pending",
        agentDeploymentError: null,
        agentId: null,
      });

      // Trigger fresh deployment
      const result = await cloudIntegrationService.deployAgentToAsset(
        req.params.id,
        { initiatedBy: req.body.userId || "redeploy" }
      );

      if (result.error) {
        // Rollback: restore the previous state since deployment failed to start
        await storage.updateCloudAsset(req.params.id, {
          agentInstalled: previousAgentId ? true : false,
          agentDeploymentStatus: asset.agentDeploymentStatus,
          agentDeploymentError: result.error,
          agentId: previousAgentId,
        });
        return res.status(400).json({ error: result.error });
      }

      // Deployment job created successfully - now mark old agent as replaced
      if (previousAgentId) {
        try {
          await storage.updateEndpointAgent(previousAgentId, {
            status: "offline",
            tags: ["replaced", `cloud:${asset.provider || "unknown"}`],
          });
        } catch (err) {
          console.warn("[Redeploy] Failed to update old agent status:", err);
        }
      }

      res.json({ 
        success: true, 
        jobId: result.jobId,
        message: "Agent redeployment started",
        previousAgentId: previousAgentId,
      });
    } catch (error) {
      console.error("Error redeploying agent:", error);
      res.status(500).json({ error: "Failed to redeploy agent" });
    }
  });

  // Cancel stuck deployment for a cloud asset
  app.post("/api/cloud-assets/:id/cancel-deployment", apiRateLimiter, async (req, res) => {
    try {
      const asset = await storage.getCloudAsset(req.params.id);
      if (!asset) {
        return res.status(404).json({ error: "Cloud asset not found" });
      }

      // Only allow cancelling if status is pending or deploying
      if (asset.agentDeploymentStatus !== "pending" && asset.agentDeploymentStatus !== "deploying") {
        return res.status(400).json({ 
          error: `Cannot cancel - current status is "${asset.agentDeploymentStatus}", not pending or deploying` 
        });
      }

      // Find and cancel any active deployment jobs for this asset
      const activeJobs = await storage.getActiveDeploymentJobsForAsset(req.params.id);
      let cancelledJobIds: string[] = [];
      
      for (const job of activeJobs) {
        await storage.updateAgentDeploymentJob(job.id, {
          status: "cancelled",
          error: "Cancelled by user",
          completedAt: new Date(),
        });
        cancelledJobIds.push(job.id);
      }

      // Reset the deployment status to allow fresh deployment
      await storage.updateCloudAsset(req.params.id, {
        agentInstalled: false,
        agentDeploymentStatus: null,
        agentDeploymentError: "Deployment cancelled by user",
        agentId: null,
      });

      console.log(`[CancelDeployment] Cancelled ${cancelledJobIds.length} jobs for asset ${req.params.id}`);

      res.json({ 
        success: true, 
        message: "Deployment cancelled",
        assetId: req.params.id,
        cancelledJobs: cancelledJobIds,
      });
    } catch (error) {
      console.error("Error cancelling deployment:", error);
      res.status(500).json({ error: "Failed to cancel deployment" });
    }
  });

  // Deploy agents to all assets in a connection
  app.post("/api/cloud-connections/:id/deploy-all-agents", batchRateLimiter, async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        return res.status(404).json({ error: "Cloud connection not found" });
      }

      const result = await cloudIntegrationService.deployAgentsToAllAssets(
        req.params.id,
        { assetTypes: req.body.assetTypes, initiatedBy: req.body.userId }
      );

      res.json({ 
        success: true, 
        jobIds: result.jobIds,
        errors: result.errors,
        message: `Started ${result.jobIds.length} agent deployments` 
      });
    } catch (error) {
      console.error("Error deploying agents:", error);
      res.status(500).json({ error: "Failed to deploy agents" });
    }
  });

  // Get all cloud assets
  app.get("/api/cloud-assets", apiRateLimiter, async (req, res) => {
    try {
      const assets = await storage.getCloudAssets();
      res.json(assets);
    } catch (error) {
      console.error("Error fetching cloud assets:", error);
      res.status(500).json({ error: "Failed to fetch cloud assets" });
    }
  });

  // Get deployment jobs for a connection
  app.get("/api/cloud-connections/:id/deployment-jobs", apiRateLimiter, async (req, res) => {
    try {
      const jobs = await storage.getAgentDeploymentJobs(req.params.id);
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching deployment jobs:", error);
      res.status(500).json({ error: "Failed to fetch deployment jobs" });
    }
  });

  // ========== SSH CREDENTIALS MANAGEMENT ==========
  
  const sshCredentialSchema = z.object({
    assetId: z.string().optional(),
    connectionId: z.string().optional(),
    host: z.string().optional(),
    port: z.number().int().min(1).max(65535).default(22),
    username: z.string().min(1),
    authMethod: z.enum(["key", "password"]).default("key"),
    privateKey: z.string().optional(),
    password: z.string().optional(),
    useSudo: z.boolean().default(true),
    sudoPassword: z.boolean().default(false),
  });
  
  // List SSH credentials for organization
  app.get("/api/ssh-credentials", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      const credentials = await storage.getSshCredentials(organizationId);
      
      // Return credentials without sensitive data
      const sanitized = credentials.map(cred => ({
        id: cred.id,
        organizationId: cred.organizationId,
        assetId: cred.assetId,
        connectionId: cred.connectionId,
        host: cred.host,
        port: cred.port,
        username: cred.username,
        authMethod: cred.authMethod,
        useSudo: cred.useSudo,
        sudoPassword: cred.sudoPassword,
        status: cred.status,
        lastUsedAt: cred.lastUsedAt,
        lastValidatedAt: cred.lastValidatedAt,
        validationError: cred.validationError,
        keyFingerprint: cred.keyFingerprint,
        createdAt: cred.createdAt,
        updatedAt: cred.updatedAt,
      }));
      
      res.json(sanitized);
    } catch (error) {
      console.error("Error fetching SSH credentials:", error);
      res.status(500).json({ error: "Failed to fetch SSH credentials" });
    }
  });
  
  // Create SSH credential
  app.post("/api/ssh-credentials", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      const parsed = sshCredentialSchema.safeParse(req.body);
      
      if (!parsed.success) {
        res.status(400).json({ error: "Invalid SSH credential data", details: parsed.error.issues });
        return;
      }
      
      const data = parsed.data;
      
      // Validate that we have either key or password
      if (data.authMethod === "key" && !data.privateKey) {
        res.status(400).json({ error: "Private key is required for key authentication" });
        return;
      }
      if (data.authMethod === "password" && !data.password) {
        res.status(400).json({ error: "Password is required for password authentication" });
        return;
      }
      
      // Encrypt sensitive fields
      const { secretsService } = await import("./services/secrets");
      let encryptedPrivateKey: string | undefined;
      let encryptedPassword: string | undefined;
      let encryptionKeyId = "";
      
      if (data.privateKey) {
        const encrypted = secretsService.encryptField(data.privateKey);
        encryptedPrivateKey = encrypted.encryptedData;
        encryptionKeyId = encrypted.keyId;
      }
      if (data.password) {
        const encrypted = secretsService.encryptField(data.password);
        encryptedPassword = encrypted.encryptedData;
        encryptionKeyId = encrypted.keyId;
      }
      
      // Generate key fingerprint if we have a private key
      let keyFingerprint: string | undefined;
      if (data.privateKey) {
        const crypto = await import("crypto");
        keyFingerprint = crypto.createHash("sha256").update(data.privateKey).digest("hex").slice(0, 32);
      }
      
      const credential = await storage.createSshCredential({
        organizationId,
        assetId: data.assetId,
        connectionId: data.connectionId,
        host: data.host,
        port: data.port,
        username: data.username,
        authMethod: data.authMethod,
        encryptedPrivateKey,
        encryptedPassword,
        encryptionKeyId,
        keyFingerprint,
        useSudo: data.useSudo,
        sudoPassword: data.sudoPassword,
        status: "active",
      });
      
      res.json({
        id: credential.id,
        host: credential.host,
        port: credential.port,
        username: credential.username,
        authMethod: credential.authMethod,
        status: credential.status,
        createdAt: credential.createdAt,
      });
    } catch (error) {
      console.error("Error creating SSH credential:", error);
      res.status(500).json({ error: "Failed to create SSH credential" });
    }
  });
  
  // Test SSH connection
  app.post("/api/ssh-credentials/:id/test", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const { sshDeploymentService } = await import("./services/ssh-deployment");
      
      const config = await sshDeploymentService.getDecryptedCredentials(req.params.id);
      if (!config) {
        res.status(404).json({ error: "SSH credential not found" });
        return;
      }
      
      // If no host in credential, try to get from request body
      if (!config.host && req.body.host) {
        config.host = req.body.host;
      }
      
      if (!config.host) {
        res.status(400).json({ error: "No host specified for connection test" });
        return;
      }
      
      const result = await sshDeploymentService.testConnection(config);
      
      // Update validation status
      await storage.updateSshCredential(req.params.id, {
        lastValidatedAt: new Date(),
        validationError: result.success ? null : result.error,
      });
      
      res.json(result);
    } catch (error) {
      console.error("Error testing SSH connection:", error);
      res.status(500).json({ error: "Failed to test SSH connection" });
    }
  });
  
  // Delete SSH credential
  app.delete("/api/ssh-credentials/:id", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      await storage.deleteSshCredential(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting SSH credential:", error);
      res.status(500).json({ error: "Failed to delete SSH credential" });
    }
  });
  
  // Deploy agent via SSH to a specific asset
  app.post("/api/ssh-credentials/:id/deploy/:assetId", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      const serverUrl = process.env.PUBLIC_ODINFORGE_URL || `https://${req.headers.host}`;
      
      const { sshDeploymentService } = await import("./services/ssh-deployment");
      
      const result = await sshDeploymentService.deployToAsset(
        req.params.assetId,
        organizationId,
        serverUrl
      );
      
      res.json(result);
    } catch (error) {
      console.error("Error deploying via SSH:", error);
      res.status(500).json({ error: "Failed to deploy agent via SSH" });
    }
  });

  // ========== AUTO-DEPLOY CONFIGURATION ==========

  // Validation schemas for auto-deploy configuration
  const validProviders = ["aws", "azure", "gcp"] as const;
  const validAssetTypes = ["ec2", "vm", "gce", "rds", "lambda", "s3", "ecs", "eks", "aks", "gke"] as const;
  const validPlatforms = ["linux", "windows", "macos", "container", "kubernetes"] as const;

  const autoDeployConfigSchema = z.object({
    enabled: z.boolean().optional(),
    providers: z.array(z.enum(validProviders)).optional(),
    assetTypes: z.array(z.enum(validAssetTypes)).optional(),
    targetPlatforms: z.array(z.enum(validPlatforms)).optional(),
    deploymentOptions: z.object({
      maxConcurrentDeployments: z.number().int().min(1).max(50).optional(),
      deploymentTimeoutSeconds: z.number().int().min(60).max(3600).optional(),
      retryFailedDeployments: z.boolean().optional(),
      maxRetries: z.number().int().min(0).max(10).optional(),
      skipOfflineAssets: z.boolean().optional(),
    }).optional(),
    filterRules: z.object({
      includeTags: z.record(z.string()).optional(),
      excludeTags: z.record(z.string()).optional(),
      includeRegions: z.array(z.string()).optional(),
      excludeRegions: z.array(z.string()).optional(),
      minInstanceSize: z.string().optional(),
    }).nullable().optional(),
  });

  const autoDeployToggleSchema = z.object({
    enabled: z.boolean(),
  });

  // Get auto-deploy configuration for organization - requires authenticated user
  app.get("/api/auto-deploy/config", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      let config = await storage.getAutoDeployConfig(organizationId);
      
      // Return default config if none exists
      if (!config) {
        config = {
          id: "",
          organizationId,
          enabled: false,
          providers: ["aws", "azure", "gcp"],
          assetTypes: ["ec2", "vm", "gce"],
          targetPlatforms: ["linux", "windows"],
          deploymentOptions: {
            maxConcurrentDeployments: 10,
            deploymentTimeoutSeconds: 300,
            retryFailedDeployments: true,
            maxRetries: 3,
            skipOfflineAssets: true,
          },
          filterRules: null,
          totalDeploymentsTriggered: 0,
          lastDeploymentTriggeredAt: null,
          createdAt: null,
          updatedAt: null,
          createdBy: null,
        };
      }
      
      res.json(config);
    } catch (error) {
      console.error("Error fetching auto-deploy config:", error);
      res.status(500).json({ error: "Failed to fetch auto-deploy configuration" });
    }
  });

  // Create or update auto-deploy configuration (requires admin)
  app.put("/api/auto-deploy/config", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      
      // Validate request body
      const parseResult = autoDeployConfigSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({ 
          error: "Invalid configuration", 
          details: parseResult.error.errors 
        });
      }
      
      const existingConfig = await storage.getAutoDeployConfig(organizationId);
      
      const configData = {
        ...parseResult.data,
        organizationId,
      };
      
      let config;
      if (existingConfig) {
        config = await storage.updateAutoDeployConfig(organizationId, configData);
      } else {
        config = await storage.createAutoDeployConfig(configData);
      }
      
      console.log(`[AutoDeploy] Configuration ${existingConfig ? 'updated' : 'created'} for org ${organizationId}: enabled=${config?.enabled}`);
      
      res.json(config);
    } catch (error) {
      console.error("Error updating auto-deploy config:", error);
      res.status(500).json({ error: "Failed to update auto-deploy configuration" });
    }
  });

  // Toggle auto-deploy on/off (convenience endpoint) - requires admin
  app.post("/api/auto-deploy/toggle", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      
      // Validate request body
      const parseResult = autoDeployToggleSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({ error: "enabled must be a boolean" });
      }
      
      const { enabled } = parseResult.data;
      
      let existingConfig = await storage.getAutoDeployConfig(organizationId);
      
      let config;
      if (existingConfig) {
        config = await storage.updateAutoDeployConfig(organizationId, { enabled });
      } else {
        config = await storage.createAutoDeployConfig({ organizationId, enabled });
      }
      
      console.log(`[AutoDeploy] Auto-deploy ${enabled ? 'ENABLED' : 'DISABLED'} for org ${organizationId}`);
      
      res.json({ 
        success: true, 
        enabled: config?.enabled,
        message: `Auto-deploy ${enabled ? 'enabled' : 'disabled'} successfully`
      });
    } catch (error) {
      console.error("Error toggling auto-deploy:", error);
      res.status(500).json({ error: "Failed to toggle auto-deploy" });
    }
  });

  // Get auto-deploy statistics - requires authenticated user
  app.get("/api/auto-deploy/stats", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || getOrganizationId(req) || "default";
      const config = await storage.getAutoDeployConfig(organizationId);
      
      res.json({
        enabled: config?.enabled || false,
        totalDeploymentsTriggered: config?.totalDeploymentsTriggered || 0,
        lastDeploymentTriggeredAt: config?.lastDeploymentTriggeredAt || null,
        providers: config?.providers || [],
        assetTypes: config?.assetTypes || [],
      });
    } catch (error) {
      console.error("Error fetching auto-deploy stats:", error);
      res.status(500).json({ error: "Failed to fetch auto-deploy statistics" });
    }
  });

  // ========== AI VS AI SIMULATION API ==========

  // Import the AI simulation runner
  const { runAISimulation } = await import("./services/agents/ai-simulation");

  // Validation schema for simulation creation
  const createSimulationSchema = z.object({
    assetId: z.string().min(1, "assetId is required"),
    exposureType: z.enum(["cve", "misconfiguration", "network", "api", "iam_abuse", "data_exfiltration", "payment_flow"]),
    priority: z.enum(["critical", "high", "medium", "low"]).default("high"),
    description: z.string().min(1, "description is required"),
    rounds: z.number().int().min(1).max(10).default(3),
    sourceEvaluationId: z.string().optional(), // Optional: ID of evaluation with live scan data
  });

  // Start a new AI vs AI simulation
  app.post("/api/simulations", simulationRateLimiter, async (req, res) => {
    try {
      const parseResult = createSimulationSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({ error: parseResult.error.errors[0].message });
      }
      const { assetId, exposureType, priority, description, rounds, sourceEvaluationId } = parseResult.data;

      // Look up live scan data if sourceEvaluationId is provided
      let liveScanData: import("./services/agents/ai-simulation").LiveScanInput | undefined;
      if (sourceEvaluationId) {
        const liveScanResult = await storage.getLiveScanResultByEvaluationId(sourceEvaluationId);
        if (liveScanResult) {
          // Normalize and validate the data structure
          const rawPorts = Array.isArray(liveScanResult.ports) ? liveScanResult.ports : [];
          const rawVulns = Array.isArray(liveScanResult.vulnerabilities) ? liveScanResult.vulnerabilities : [];
          
          liveScanData = {
            targetHost: liveScanResult.targetHost || "unknown",
            resolvedIp: liveScanResult.resolvedIp || undefined,
            ports: rawPorts.map((p: any) => ({
              port: p?.port ?? 0,
              state: p?.state ?? "unknown",
              service: p?.service,
              banner: p?.banner,
              version: p?.version,
            })),
            vulnerabilities: rawVulns.map((v: any) => ({
              port: v?.port ?? 0,
              service: v?.service ?? "unknown",
              severity: v?.severity ?? "medium",
              title: v?.title ?? "Unknown vulnerability",
              description: v?.description ?? "",
              cveIds: Array.isArray(v?.cveIds) ? v.cveIds : [],
              remediation: v?.remediation,
            })),
          };
          console.log(`[SIMULATION] Using live scan data from evaluation ${sourceEvaluationId}: ${liveScanData.ports.length} ports, ${liveScanData.vulnerabilities.length} vulnerabilities`);
        } else {
          console.log(`[SIMULATION] No live scan data found for evaluation ${sourceEvaluationId}`);
        }
      }

      // Check kill switch before starting simulation
      const governance = await storage.getOrganizationGovernance("default");
      if (governance?.killSwitchActive) {
        await storage.createAuthorizationLog({
          organizationId: "default",
          action: "unauthorized_target_blocked",
          details: { reason: "kill_switch_active", type: "simulation", assetId },
          authorized: false,
          riskLevel: "high",
        });
        return res.status(403).json({ 
          error: "Operations halted", 
          message: "Kill switch is active. All simulations are blocked until deactivated." 
        });
      }

      // Create simulation record in database
      const simulation = await storage.createAiSimulation({
        organizationId: "default",
        name: `AI vs AI Simulation: ${assetId}`,
        description,
        simulationStatus: "running",
        startedAt: new Date(),
      });
      const simulationId = simulation.id;

      // Run simulation asynchronously
      runSimulation(simulationId, assetId, exposureType, priority || "high", description, rounds, liveScanData);

      res.json({ 
        simulationId,
        status: "running",
        message: "AI vs AI simulation started. Use WebSocket or GET /api/simulations/:id for progress updates.",
        usingLiveScanData: !!liveScanData,
      });
    } catch (error) {
      console.error("Error starting simulation:", error);
      res.status(500).json({ error: "Failed to start simulation" });
    }
  });

  // Get all simulations
  app.get("/api/simulations", apiRateLimiter, async (req, res) => {
    try {
      const simulations = await storage.getAllAiSimulations();
      res.json(simulations);
    } catch (error) {
      console.error("Error fetching simulations:", error);
      res.status(500).json({ error: "Failed to fetch simulations" });
    }
  });

  // Get a specific simulation
  app.get("/api/simulations/:id", apiRateLimiter, async (req, res) => {
    try {
      const simulation = await storage.getAiSimulation(req.params.id);
      if (!simulation) {
        return res.status(404).json({ error: "Simulation not found" });
      }
      res.json(simulation);
    } catch (error) {
      console.error("Error fetching simulation:", error);
      res.status(500).json({ error: "Failed to fetch simulation" });
    }
  });

  // Delete a simulation
  app.delete("/api/simulations/:id", apiRateLimiter, async (req, res) => {
    try {
      const simulation = await storage.getAiSimulation(req.params.id);
      if (!simulation) {
        return res.status(404).json({ error: "Simulation not found" });
      }
      await storage.deleteAiSimulation(req.params.id);
      res.json({ success: true, message: "Simulation deleted" });
    } catch (error) {
      console.error("Error deleting simulation:", error);
      res.status(500).json({ error: "Failed to delete simulation" });
    }
  });

  // Helper function to run simulation asynchronously
  async function runSimulation(
    simulationId: string,
    assetId: string,
    exposureType: string,
    priority: string,
    description: string,
    rounds: number,
    liveScanData?: import("./services/agents/ai-simulation").LiveScanInput
  ) {
    try {
      wsService.sendProgress(simulationId, "AI Simulation", "starting", 0, 
        liveScanData ? "Starting AI vs AI simulation with live scan data..." : "Starting AI vs AI simulation...");

      const result = await runAISimulation(
        assetId,
        exposureType,
        priority,
        description,
        simulationId,
        rounds,
        (phase, round, progress, message) => {
          wsService.sendProgress(simulationId, `AI Simulation (Round ${round})`, phase, progress, message);
        },
        liveScanData
      );

      // Update simulation with results
      await storage.updateAiSimulation(simulationId, {
        simulationStatus: "completed",
        completedAt: new Date(),
        simulationResults: {
          attackerSuccesses: Math.round(result.finalAttackScore * 100),
          defenderBlocks: Math.round(result.finalDefenseScore * 100),
          timeToDetection: 0,
          timeToContainment: 0,
          attackPath: result.rounds.flatMap(r => 
            r.attackerFindings.attackPath.map(s => s.title)
          ),
          detectionPoints: result.rounds.flatMap(r => 
            r.defenderFindings.detectedAttacks.map(d => d.attackType)
          ),
          missedAttacks: result.rounds.flatMap(r => 
            r.defenderFindings.gapsIdentified
          ),
          recommendations: result.recommendations.map(r => r.description),
        },
      });

      wsService.sendComplete(simulationId, true);
    } catch (error) {
      console.error("Simulation failed:", error);
      await storage.updateAiSimulation(simulationId, {
        simulationStatus: "failed",
        completedAt: new Date(),
      });
      wsService.sendComplete(simulationId, false, String(error));
    }
  }

  // ========== ENDPOINT AGENT API ==========

  // Generate API key for agent
  function generateApiKey(): string {
    return `odin-${randomUUID().replace(/-/g, "")}`;
  }

  // Hash API key for storage
  async function hashApiKey(apiKey: string): Promise<string> {
    return bcrypt.hash(apiKey, 10);
  }

  // Verify API key against hash
  async function verifyApiKey(apiKey: string, hash: string): Promise<boolean> {
    return bcrypt.compare(apiKey, hash);
  }

  // Agent authentication middleware - supports API key, mTLS, and JWT
  async function authenticateAgent(req: any, res: any, next: any) {
    const authHeader = req.headers.authorization;
    const clientCertHeader = req.headers["x-client-cert-fingerprint"] || req.headers["x-ssl-client-cert"];
    const certSecretHeader = req.headers["x-cert-secret"];
    const xApiKeyHeader = req.headers["x-api-key"];

    try {
      // Import RLS bypass functions
      const { withoutTenantContext, setTenantContext } = await import("./services/rls-setup");

      // Get all agents for API key comparison - bypass RLS since we need to check all orgs
      const agents = await withoutTenantContext(async () => {
        return await storage.getEndpointAgents();
      });

      // Use unified auth service for multi-method authentication
      const authResult = await unifiedAuthService.authenticateRequest(
        authHeader,
        clientCertHeader,
        agents,
        certSecretHeader,
        xApiKeyHeader
      );

      if (!authResult.authenticated) {
        return res.status(401).json({ error: authResult.error || "No valid authentication credentials provided" });
      }

      // Find the authenticated agent
      let authenticatedAgent = null;
      if (authResult.agentId) {
        authenticatedAgent = agents.find(a => a.id === authResult.agentId);
      }

      if (!authenticatedAgent) {
        return res.status(401).json({ error: "Agent not found" });
      }

      req.agent = authenticatedAgent;

      // Set tenant context for subsequent operations based on authenticated agent's org
      await setTenantContext(authenticatedAgent.organizationId);

      next();
    } catch (error) {
      console.error("[Auth] Agent authentication error:", error);
      return res.status(500).json({ error: "Internal authentication error" });
    }
  }

  // Get registration token for display in UI
  // Note: The Agents page requires login to access, so this is effectively protected
  app.get("/api/agents/registration-token", apiRateLimiter, async (req, res) => {
    const token = process.env.AGENT_REGISTRATION_TOKEN;
    if (!token) {
      return res.json({ 
        token: null, 
        message: "Auto-registration not configured. Set AGENT_REGISTRATION_TOKEN environment variable." 
      });
    }
    res.json({ token });
  });

  // Register a new agent
  app.post("/api/agents/register", authRateLimiter, async (req, res) => {
    try {
      const parsed = agentRegisterSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error.errors });
      }

      const { agentName, hostname, platform, platformVersion, architecture, capabilities, environment, tags } = parsed.data;

      const apiKey = generateApiKey();
      const apiKeyHash = await hashApiKey(apiKey);
      
      const agent = await storage.createEndpointAgent({
        agentName,
        apiKey: "", // Don't store plaintext key
        apiKeyHash, // Store the hash
        hostname,
        platform,
        platformVersion,
        architecture,
        capabilities: capabilities || [],
        environment,
        tags: tags || [],
        organizationId: "default",
        status: "online",
      });

      res.json({
        id: agent.id,
        apiKey, // Return plaintext key only once at registration
        agentName: agent.agentName,
        message: "Agent registered successfully. Store the API key securely - it cannot be retrieved again.",
      });
    } catch (error) {
      console.error("Error registering agent:", error);
      res.status(500).json({ error: "Failed to register agent" });
    }
  });

  // Auto-register a new agent using registration token (no pre-registration required)
  // Supports both: 1) Single-use tokens from database, 2) Permanent env var token (fallback)
  app.post("/api/agents/auto-register", authRateLimiter, async (req, res) => {
    try {
      const { token, agentName, hostname, platform, platformVersion, architecture, capabilities, environment, tags } = req.body;

      if (!token) {
        return res.status(400).json({ error: "Registration token required" });
      }

      // Track which token type was used and organization for the agent
      let tokenType: "single-use" | "permanent" = "permanent";
      let singleUseTokenRecord: Awaited<ReturnType<typeof storage.getAgentRegistrationTokenByHash>> = undefined;
      let organizationId = "default";

      // First, try to validate as a single-use token from database
      const tokenHash = createHash("sha256").update(token).digest("hex");
      singleUseTokenRecord = await storage.getAgentRegistrationTokenByHash(tokenHash);
      
      if (singleUseTokenRecord) {
        // Check if token is already used
        if (singleUseTokenRecord.usedAt) {
          console.log(`[Agent Registration] Single-use token ${singleUseTokenRecord.id} already used`);
          return res.status(401).json({ error: "Registration token has already been used" });
        }
        
        // Check if token is expired
        if (new Date(singleUseTokenRecord.expiresAt) < new Date()) {
          console.log(`[Agent Registration] Single-use token ${singleUseTokenRecord.id} expired`);
          return res.status(401).json({ error: "Registration token has expired" });
        }
        
        tokenType = "single-use";
        organizationId = singleUseTokenRecord.organizationId;
        console.log(`[Agent Registration] Valid single-use token ${singleUseTokenRecord.id} for org ${organizationId}`);
      } else {
        // Fall back to permanent env var token
        const permanentToken = process.env.AGENT_REGISTRATION_TOKEN;
        
        if (!permanentToken) {
          return res.status(401).json({ 
            error: "Invalid registration token",
            message: "Token not recognized as single-use token and no permanent token configured"
          });
        }

        // Validate against permanent token (constant-time comparison)
        const tokenBuffer = Buffer.from(token);
        const expectedBuffer = Buffer.from(permanentToken);
        
        if (tokenBuffer.length !== expectedBuffer.length || !timingSafeEqual(tokenBuffer, expectedBuffer)) {
          console.log(`[Agent Registration] Token mismatch - not a valid single-use or permanent token`);
          return res.status(401).json({ error: "Invalid registration token" });
        }
        
        console.log(`[Agent Registration] Valid permanent token used`);
      }

      // Check if agent with same hostname already exists (prevent duplicate registrations)
      if (hostname) {
        const existingAgents = await storage.getEndpointAgents(organizationId);
        const existingAgent = existingAgents.find(a => a.hostname === hostname);
        if (existingAgent) {
          // Return existing agent's info but generate a new API key
          const apiKey = generateApiKey();
          const apiKeyHash = await hashApiKey(apiKey);
          
          await storage.updateEndpointAgent(existingAgent.id, { 
            apiKeyHash,
            status: "online",
            lastHeartbeat: new Date()
          });
          
          // Consume single-use token even for re-registration
          if (tokenType === "single-use" && singleUseTokenRecord) {
            await storage.consumeAgentRegistrationToken(singleUseTokenRecord.id, existingAgent.id);
            console.log(`[Agent Registration] Single-use token ${singleUseTokenRecord.id} consumed by existing agent ${existingAgent.id}`);
          }
          
          return res.json({
            id: existingAgent.id,
            apiKey,
            agentName: existingAgent.agentName,
            message: "Agent re-registered successfully. API key has been rotated.",
            existingAgent: true,
            tokenType
          });
        }
      }

      // Create a new agent
      const generatedName = agentName || hostname || `agent-${Date.now()}`;
      const apiKey = generateApiKey();
      const apiKeyHash = await hashApiKey(apiKey);
      
      const agent = await storage.createEndpointAgent({
        agentName: generatedName,
        apiKey: `placeholder-${randomUUID()}`,
        apiKeyHash,
        hostname,
        platform,
        platformVersion,
        architecture,
        capabilities: capabilities || [],
        environment: environment || "production",
        tags: tags || [],
        organizationId,
        status: "online",
      });

      // Consume single-use token after successful registration
      if (tokenType === "single-use" && singleUseTokenRecord) {
        await storage.consumeAgentRegistrationToken(singleUseTokenRecord.id, agent.id);
        console.log(`[Agent Registration] Single-use token ${singleUseTokenRecord.id} consumed by new agent ${agent.id}`);
      }

      res.json({
        id: agent.id,
        apiKey,
        agentName: agent.agentName,
        message: "Agent auto-registered successfully. Store the API key securely.",
        existingAgent: false,
        tokenType
      });
    } catch (error) {
      console.error("Error auto-registering agent:", error);
      res.status(500).json({ error: "Failed to auto-register agent" });
    }
  });

  // Agent heartbeat
  app.post("/api/agents/heartbeat", apiRateLimiter, authenticateAgent, async (req: any, res) => {
    try {
      await storage.updateAgentHeartbeat(req.agent.id);
      res.json({ success: true, timestamp: new Date().toISOString() });
    } catch (error) {
      console.error("Error processing heartbeat:", error);
      res.status(500).json({ error: "Failed to process heartbeat" });
    }
  });

  // Agent telemetry ingestion
  app.post("/api/agents/telemetry", agentTelemetryRateLimiter, authenticateAgent, async (req: any, res) => {
    try {
      const parsed = agentTelemetrySchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid telemetry data", details: parsed.error.errors });
      }

      const { systemInfo, resourceMetrics, services, openPorts, networkConnections, installedSoftware, configData, securityFindings, collectedAt } = parsed.data;

      // Platform validation - cross-check incoming platform against registered agent
      if (systemInfo && req.agent.platform) {
        const incomingPlatform = (systemInfo as any).platform || (systemInfo as any).os;
        if (incomingPlatform) {
          const normalizedIncoming = normalizePlatform(incomingPlatform);
          const normalizedRegistered = normalizePlatform(req.agent.platform);
          
          if (normalizedIncoming !== normalizedRegistered) {
            console.warn(`[Platform Mismatch] Agent ${req.agent.id} (${req.agent.agentName}): ` +
              `Registered as '${req.agent.platform}' but telemetry reports '${incomingPlatform}'. ` +
              `Telemetry rejected.`);
            return res.status(400).json({ 
              error: "Platform mismatch",
              details: `Agent registered as ${req.agent.platform} but telemetry reports ${incomingPlatform}`
            });
          }
        }
      }

      const telemetry = await storage.createAgentTelemetry({
        agentId: req.agent.id,
        organizationId: req.agent.organizationId,
        systemInfo,
        resourceMetrics,
        services,
        openPorts,
        networkConnections,
        installedSoftware,
        configData,
        securityFindings,
        collectedAt: collectedAt ? new Date(collectedAt) : new Date(),
      });

      // Process security findings with deduplication
      const createdFindings: string[] = [];
      const triggeredEvaluations: string[] = [];
      
      if (securityFindings && Array.isArray(securityFindings)) {
        // Get existing findings for this agent to deduplicate
        const existingFindings = await storage.getAgentFindings(req.agent.id);
        const existingFindingKeys = new Set(
          existingFindings
            .filter(f => f.status !== "resolved")
            .map(f => `${f.findingType}|${f.title}|${f.affectedComponent || ""}`)
        );

        for (const finding of securityFindings) {
          const findingKey = `${finding.type || "unknown"}|${finding.title}|${finding.affectedComponent || ""}`;
          
          // Skip if this finding already exists and is not resolved
          if (existingFindingKeys.has(findingKey)) {
            continue;
          }

          const agentFinding = await storage.createAgentFinding({
            agentId: req.agent.id,
            organizationId: req.agent.organizationId,
            telemetryId: telemetry.id,
            findingType: finding.type || "unknown",
            severity: finding.severity || "medium",
            title: finding.title,
            description: finding.description,
            affectedComponent: finding.affectedComponent,
            recommendation: finding.recommendation,
            detectedAt: new Date(),
          });
          createdFindings.push(agentFinding.id);
          
          // Add to set to prevent duplicates within same batch
          existingFindingKeys.add(findingKey);

          // Auto-trigger evaluation for critical/high severity findings
          if (finding.severity === "critical" || finding.severity === "high") {
            const evaluation = await storage.createEvaluation({
              assetId: `${req.agent.hostname || req.agent.agentName}-${finding.affectedComponent || "unknown"}`,
              exposureType: finding.type || "misconfiguration",
              priority: finding.severity,
              description: `Auto-triggered from agent finding:\n\nAgent: ${req.agent.agentName}\nHost: ${req.agent.hostname || "Unknown"}\n\n${finding.title}\n\n${finding.description}`,
              organizationId: req.agent.organizationId,
            });

            await storage.updateAgentFinding(agentFinding.id, {
              aevEvaluationId: evaluation.id,
              autoEvaluationTriggered: true,
            });
            
            triggeredEvaluations.push(evaluation.id);

            // Run evaluation async
            runEvaluation(evaluation.id, {
              assetId: evaluation.assetId,
              exposureType: evaluation.exposureType,
              priority: evaluation.priority,
              description: evaluation.description,
            });
          }
        }
      }

      res.json({ 
        success: true, 
        telemetryId: telemetry.id,
        findingsCreated: createdFindings.length,
        findingIds: createdFindings,
        evaluationsTriggered: triggeredEvaluations.length,
      });
    } catch (error) {
      console.error("Error ingesting telemetry:", error);
      res.status(500).json({ error: "Failed to ingest telemetry" });
    }
  });

  // Go Agent batched events endpoint
  // Accepts batched events from the Go agent collector
  app.post("/api/agents/events", agentTelemetryRateLimiter, authenticateAgent, async (req: any, res) => {
    try {
      // Support both formats:
      // 1. { events: [...] } - wrapped format
      // 2. [...] - direct array format
      let events: any[];
      if (Array.isArray(req.body)) {
        events = req.body;
      } else if (req.body && Array.isArray(req.body.events)) {
        events = req.body.events;
      } else {
        // Log what we received for debugging
        console.log("[Agent Events] Received body type:", typeof req.body, "keys:", req.body ? Object.keys(req.body) : "null");
        return res.status(400).json({ error: "Events must be an array or object with events array" });
      }
      // Note: tenant_id is ignored - we use req.agent.organizationId from authentication

      // Handle empty events array gracefully (agent may flush with no events)
      if (!events || events.length === 0) {
        return res.json({ success: true, eventsProcessed: 0, message: "No events to process" });
      }

      let processedCount = 0;
      let skippedCount = 0;
      const validationErrors: string[] = [];
      const createdFindings: string[] = [];
      const triggeredEvaluations: string[] = [];
      const telemetryIds: string[] = [];

      // Get existing findings for deduplication (include severity for better deduplication)
      const existingFindings = await storage.getAgentFindings(req.agent.id);
      const existingFindingKeys = new Set(
        existingFindings
          .filter(f => f.status !== "resolved")
          .map(f => `${f.findingType}|${f.severity}|${f.title}|${f.affectedComponent || ""}`)
      );

      // Track if we need to update the authenticated agent with Go agent metadata
      let goAgentId: string | null = null;
      let goAgentHostname: string | null = null;
      let goAgentPrimaryIP: string | null = null;
      
      for (let i = 0; i < events.length; i++) {
        const rawEvent = events[i];
        
        // Parse event if it's a JSON string (Go agent may send stringified events)
        let event: any;
        if (typeof rawEvent === "string") {
          try {
            event = JSON.parse(rawEvent);
          } catch {
            validationErrors.push(`Event ${i}: invalid JSON string`);
            skippedCount++;
            continue;
          }
        } else {
          event = rawEvent;
        }
        
        // Validate event is an object
        if (!event || typeof event !== "object") {
          validationErrors.push(`Event ${i}: must be an object`);
          skippedCount++;
          continue;
        }
        
        // Extract Go agent ID if present (for syncing agent identity)
        if (event.agent_id && !goAgentId) {
          goAgentId = event.agent_id;
        }

        // Transform Go agent event format to expected schema
        // Go agent sends: { type, payload: { system, metrics } }
        // Server expects: { systemInfo, resourceMetrics }
        let transformedEvent: any = { ...event };
        
        if (event.type === "heartbeat") {
          // Update agent heartbeat timestamp
          await storage.updateAgentHeartbeat(req.agent.id);
          processedCount++;
          continue; // Heartbeat doesn't need telemetry record
        }
        
        if (event.type === "telemetry" && event.payload) {
          // Transform Go agent payload to expected schema
          // Include network info in systemInfo for display
          const systemInfo = event.payload.system || event.payload.systemInfo || {};
          const networkInfo = event.payload.network || null;
          
          // Platform validation - cross-check incoming platform against registered agent
          const incomingPlatform = systemInfo.platform || systemInfo.os;
          const registeredPlatform = req.agent.platform;
          
          if (incomingPlatform && registeredPlatform) {
            const normalizedIncoming = normalizePlatform(incomingPlatform);
            const normalizedRegistered = normalizePlatform(registeredPlatform);
            
            if (normalizedIncoming !== normalizedRegistered) {
              console.warn(`[Platform Mismatch] Agent ${req.agent.id} (${req.agent.agentName}): ` +
                `Registered as '${registeredPlatform}' but telemetry reports '${incomingPlatform}'. ` +
                `Event quarantined.`);
              validationErrors.push(`Event ${i}: Platform mismatch - agent registered as ${registeredPlatform} but telemetry reports ${incomingPlatform}`);
              skippedCount++;
              continue; // Skip this event to prevent cross-platform data contamination
            }
          }
          
          // Merge network info into systemInfo for easy display
          if (networkInfo) {
            systemInfo.network = networkInfo;
            systemInfo.primaryIP = networkInfo.primary_ip || networkInfo.primaryIP;
            systemInfo.interfaces = networkInfo.interfaces;
            
            // Track primary IP for agent update
            if (!goAgentPrimaryIP && (networkInfo.primary_ip || networkInfo.primaryIP)) {
              goAgentPrimaryIP = networkInfo.primary_ip || networkInfo.primaryIP;
            }
          }
          
          // Extract hostname for agent update
          if (!goAgentHostname && systemInfo.hostname) {
            goAgentHostname = systemInfo.hostname;
          }
          
          transformedEvent = {
            systemInfo: systemInfo,
            resourceMetrics: event.payload.metrics || event.payload.resourceMetrics || null,
            services: event.payload.services || null,
            openPorts: event.payload.ports || event.payload.openPorts || event.payload.open_ports || null,
            networkConnections: event.payload.networkConnections || event.payload.network_connections || null,
            installedSoftware: event.payload.installedSoftware || event.payload.installed_software || null,
            configData: event.payload.configData || event.payload.config_data || null,
            securityFindings: event.payload.securityFindings || event.payload.security_findings || null,
            collectedAt: event.timestamp_utc || event.collectedAt,
          };
        }

        // Validate with schema (strict validation - reject invalid events)
        const parsed = agentTelemetrySchema.safeParse(transformedEvent);
        if (!parsed.success) {
          validationErrors.push(`Event ${i}: ${parsed.error.errors.map(e => e.message).join(", ")}`);
          skippedCount++;
          continue;
        }

        // Use validated data
        const validatedEvent = parsed.data;
        processedCount++;
        
        // Always create telemetry record to ensure findings have linkage
        const telemetry = await storage.createAgentTelemetry({
          agentId: req.agent.id,
          organizationId: req.agent.organizationId,
          systemInfo: validatedEvent.systemInfo || null,
          resourceMetrics: validatedEvent.resourceMetrics || null,
          services: validatedEvent.services || null,
          openPorts: validatedEvent.openPorts || null,
          networkConnections: validatedEvent.networkConnections || null,
          installedSoftware: validatedEvent.installedSoftware || null,
          configData: validatedEvent.configData || null,
          securityFindings: validatedEvent.securityFindings || null,
          collectedAt: validatedEvent.collectedAt ? new Date(validatedEvent.collectedAt) : new Date(),
        });
        const telemetryId = telemetry.id;
        telemetryIds.push(telemetry.id);

        // Auto-generate findings from telemetry analysis (ports, services, resources)
        const autoGeneratedFindings = generateAgentFindings({
          agentId: req.agent.id,
          organizationId: req.agent.organizationId,
          telemetryId: telemetryId,
          openPorts: validatedEvent.openPorts as any,
          services: validatedEvent.services as any,
          resourceMetrics: validatedEvent.resourceMetrics as any,
          systemInfo: validatedEvent.systemInfo as any,
        }, existingFindingKeys);

        for (const findingData of autoGeneratedFindings) {
          const agentFinding = await storage.createAgentFinding(findingData);
          createdFindings.push(agentFinding.id);
          
          // Auto-trigger evaluation for critical/high severity
          if (findingData.severity === "critical" || findingData.severity === "high") {
            const evaluation = await storage.createEvaluation({
              assetId: `${req.agent.hostname || req.agent.agentName}-${findingData.affectedComponent || "unknown"}`,
              exposureType: findingData.findingType,
              priority: findingData.severity,
              description: `Auto-triggered from telemetry analysis:\n\nAgent: ${req.agent.agentName}\nHost: ${req.agent.hostname || "Unknown"}\n\n${findingData.title}\n\n${findingData.description || ""}`,
              organizationId: req.agent.organizationId,
            });

            await storage.updateAgentFinding(agentFinding.id, {
              aevEvaluationId: evaluation.id,
              autoEvaluationTriggered: true,
            });
            
            triggeredEvaluations.push(evaluation.id);

            runEvaluation(evaluation.id, {
              assetId: evaluation.assetId,
              exposureType: evaluation.exposureType,
              priority: evaluation.priority,
              description: evaluation.description,
            });
          }
        }

        // Process security findings with deduplication (from agent-reported findings)
        if (validatedEvent.securityFindings && Array.isArray(validatedEvent.securityFindings)) {
          for (const finding of validatedEvent.securityFindings) {
            // Skip findings without required title
            if (!finding.title) continue;
            
            const severity = finding.severity || "medium";
            const findingType = finding.type || "unknown";
            const findingKey = `${findingType}|${severity}|${finding.title}|${finding.affectedComponent || ""}`;
            
            if (existingFindingKeys.has(findingKey)) {
              continue;
            }

            const agentFinding = await storage.createAgentFinding({
              agentId: req.agent.id,
              organizationId: req.agent.organizationId,
              telemetryId: telemetryId,
              findingType: findingType,
              severity: severity,
              title: finding.title,
              description: finding.description || "",
              affectedComponent: finding.affectedComponent || null,
              recommendation: finding.recommendation || null,
              detectedAt: new Date(),
            });
            createdFindings.push(agentFinding.id);
            existingFindingKeys.add(findingKey);

            // Auto-trigger evaluation for critical/high severity
            if (severity === "critical" || severity === "high") {
              const evaluation = await storage.createEvaluation({
                assetId: `${req.agent.hostname || req.agent.agentName}-${finding.affectedComponent || "unknown"}`,
                exposureType: findingType,
                priority: severity,
                description: `Auto-triggered from agent finding:\n\nAgent: ${req.agent.agentName}\nHost: ${req.agent.hostname || "Unknown"}\n\n${finding.title}\n\n${finding.description || ""}`,
                organizationId: req.agent.organizationId,
              });

              await storage.updateAgentFinding(agentFinding.id, {
                aevEvaluationId: evaluation.id,
                autoEvaluationTriggered: true,
              });
              
              triggeredEvaluations.push(evaluation.id);

              runEvaluation(evaluation.id, {
                assetId: evaluation.assetId,
                exposureType: evaluation.exposureType,
                priority: evaluation.priority,
                description: evaluation.description,
              });
            }
          }
        }
      }

      // Update agent record with Go agent metadata (hostname, IP) if we found it
      if (goAgentHostname || goAgentPrimaryIP || goAgentId) {
        try {
          const updateData: any = {};
          if (goAgentHostname) updateData.hostname = goAgentHostname;
          if (goAgentPrimaryIP) updateData.ipAddresses = [goAgentPrimaryIP];
          
          await storage.updateEndpointAgent(req.agent.id, updateData);
        } catch (err) {
          console.warn("[Agent Events] Failed to update agent metadata:", err);
        }
      }
      
      // Return failure if no events were processed successfully
      if (processedCount === 0 && skippedCount > 0) {
        return res.status(400).json({ 
          success: false, 
          error: "All events in batch were invalid",
          eventsSkipped: skippedCount,
          validationErrors: validationErrors.slice(0, 10),
        });
      }

      res.json({ 
        success: processedCount > 0, 
        eventsProcessed: processedCount,
        eventsSkipped: skippedCount,
        telemetryRecords: telemetryIds.length,
        findingsCreated: createdFindings.length,
        evaluationsTriggered: triggeredEvaluations.length,
        ...(validationErrors.length > 0 && { validationWarnings: validationErrors.slice(0, 5) }),
      });
    } catch (error) {
      console.error("Error processing agent events:", error);
      res.status(500).json({ error: "Failed to process events" });
    }
  });

  // Serve Kubernetes DaemonSet manifest (no auth required)
  app.get("/api/agents/kubernetes/daemonset.yaml", apiRateLimiter, async (req, res) => {
    try {
      const fs = await import("fs");
      const path = await import("path");
      const manifestPath = path.join(process.cwd(), "odinforge-agent", "kubernetes", "daemonset.yaml");
      
      if (fs.existsSync(manifestPath)) {
        res.setHeader("Content-Type", "text/yaml; charset=utf-8");
        res.setHeader("Content-Disposition", "inline; filename=daemonset.yaml");
        const manifest = fs.readFileSync(manifestPath, "utf-8");
        res.send(manifest);
      } else {
        res.status(404).json({ error: "Kubernetes manifest not found" });
      }
    } catch (error) {
      console.error("Error serving Kubernetes manifest:", error);
      res.status(500).json({ error: "Failed to serve Kubernetes manifest" });
    }
  });

  // Agent build status endpoint
  app.get("/api/agents/build-status", apiRateLimiter, async (req, res) => {
    try {
      const { getAgentBuildStatus } = await import("./services/agent-builder");
      const status = getAgentBuildStatus();
      res.json({
        ...status,
        allAvailable: status.missing.length === 0,
        version: AGENT_RELEASE.version,
      });
    } catch (error) {
      console.error("Error getting agent build status:", error);
      res.status(500).json({ error: "Failed to get agent build status" });
    }
  });

  // Download agent binary by platform - serves from object storage (production) or local (development)
  app.get("/api/agents/download/:platform", apiRateLimiter, async (req, res) => {
    try {
      const { platform } = req.params;
      const validPlatforms = ["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64"];
      
      if (!validPlatforms.includes(platform)) {
        return res.status(404).json({ 
          error: `Invalid platform: ${platform}`,
          validPlatforms,
        });
      }
      
      const filename = platform === "windows-amd64" 
        ? `odinforge-agent-${platform}.exe` 
        : `odinforge-agent-${platform}`;

      // Try S3-compatible storage first (works in both dev and production)
      try {
        const storageKey = `public/agents/${filename}`;
        const exists = await storageService.exists(storageKey);

        if (exists) {
          console.log(`[AgentDownload] Serving ${filename} from storage`);
          res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
          return await storageService.downloadFile(storageKey, res);
        }
      } catch (storageError: any) {
        console.log(`[AgentDownload] Storage lookup failed, trying local: ${storageError.message}`);
      }
      
      // Fall back to local file (for development)
      const { getAgentBinaryPath } = await import("./services/agent-builder");
      const binaryPath = getAgentBinaryPath(platform);
      
      if (!binaryPath) {
        return res.status(404).json({ 
          error: `Agent binary not available for platform: ${platform}`,
          validPlatforms,
          message: "Binary not found in object storage or locally."
        });
      }

      console.log(`[AgentDownload] Serving ${filename} from local filesystem`);
      const fs = await import("fs");
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
      const fileStream = fs.createReadStream(binaryPath);
      fileStream.pipe(res);
    } catch (error) {
      console.error("Error serving agent binary:", error);
      res.status(500).json({ error: "Failed to serve agent binary" });
    }
  });

  // Helper function to calculate real-time agent status based on last heartbeat
  function calculateAgentStatus(lastHeartbeat: Date | null, storedStatus: string): string {
    if (!lastHeartbeat) {
      return "offline";
    }
    const now = new Date();
    const diffMs = now.getTime() - new Date(lastHeartbeat).getTime();
    const diffMinutes = diffMs / (1000 * 60);
    
    // Online: heartbeat within last 2 minutes
    if (diffMinutes <= 2) {
      return "online";
    }
    // Stale: heartbeat between 2-10 minutes ago
    if (diffMinutes <= 10) {
      return "stale";
    }
    // Offline: no heartbeat for more than 10 minutes
    return "offline";
  }

  // Get all agents (for dashboard)
  app.get("/api/agents", apiRateLimiter, async (req, res) => {
    try {
      const agents = await storage.getEndpointAgents();
      // Don't expose API keys in list view, calculate real-time status
      const safeAgents = agents.map(({ apiKey, apiKeyHash, ...agent }) => ({
        ...agent,
        status: calculateAgentStatus(agent.lastHeartbeat, agent.status),
      }));
      res.json(safeAgents);
    } catch (error) {
      console.error("Error fetching agents:", error);
      res.status(500).json({ error: "Failed to fetch agents" });
    }
  });

  // Agent stats for dashboard (must be before :id route)
  app.get("/api/agents/stats/summary", apiRateLimiter, async (req, res) => {
    try {
      // Get agents and calculate real-time status for accurate counts
      const agents = await storage.getEndpointAgents();
      const agentsWithRealStatus = agents.map(agent => ({
        ...agent,
        status: calculateAgentStatus(agent.lastHeartbeat, agent.status),
      }));
      
      const findings = await storage.getAgentFindings();
      
      const stats = {
        totalAgents: agents.length,
        onlineAgents: agentsWithRealStatus.filter(a => a.status === "online").length,
        offlineAgents: agentsWithRealStatus.filter(a => a.status === "offline").length,
        staleAgents: agentsWithRealStatus.filter(a => a.status === "stale").length,
        totalFindings: findings.length,
        criticalFindings: findings.filter(f => f.severity === "critical").length,
        highFindings: findings.filter(f => f.severity === "high").length,
        newFindings: findings.filter(f => f.status === "new").length,
      };
      
      res.json(stats);
    } catch (error) {
      console.error("Error fetching agent stats:", error);
      res.status(500).json({ error: "Failed to fetch agent stats" });
    }
  });

  // ========== AUTO-CLEANUP CONFIGURATION (must be before :id routes) ==========
  // Auto-cleanup configuration (in-memory, resets on restart)
  let autoCleanupConfig = {
    enabled: false,
    intervalHours: 24, // Run every 24 hours
    maxAgeHours: 72,   // Delete agents inactive for 72 hours
    lastRun: null as string | null,
    nextRun: null as string | null,
    deletedCount: 0
  };
  let autoCleanupInterval: NodeJS.Timeout | null = null;

  const runAutoCleanup = async () => {
    if (!autoCleanupConfig.enabled) return;
    
    try {
      console.log(`[Auto-Cleanup] Running automatic stale agent cleanup (maxAge: ${autoCleanupConfig.maxAgeHours}h)`);
      const result = await storage.deleteStaleAgents(autoCleanupConfig.maxAgeHours);
      autoCleanupConfig.lastRun = new Date().toISOString();
      autoCleanupConfig.deletedCount += result.deleted;
      autoCleanupConfig.nextRun = new Date(Date.now() + autoCleanupConfig.intervalHours * 60 * 60 * 1000).toISOString();
      
      if (result.deleted > 0) {
        console.log(`[Auto-Cleanup] Deleted ${result.deleted} stale agent(s): ${result.agents.join(", ")}`);
        // Broadcast update via WebSocket
        wsService.broadcastProgress("agent-cleanup", {
          type: "auto_cleanup_complete",
          deleted: result.deleted,
          agents: result.agents
        });
      }
    } catch (error) {
      console.error("[Auto-Cleanup] Error during automatic cleanup:", error);
    }
  };

  const startAutoCleanup = () => {
    if (autoCleanupInterval) {
      clearInterval(autoCleanupInterval);
    }
    if (autoCleanupConfig.enabled) {
      autoCleanupConfig.nextRun = new Date(Date.now() + autoCleanupConfig.intervalHours * 60 * 60 * 1000).toISOString();
      autoCleanupInterval = setInterval(runAutoCleanup, autoCleanupConfig.intervalHours * 60 * 60 * 1000);
      console.log(`[Auto-Cleanup] Scheduled to run every ${autoCleanupConfig.intervalHours} hours`);
    }
  };

  // Get auto-cleanup settings (must be before /api/agents/:id)
  app.get("/api/agents/auto-cleanup", apiRateLimiter, async (req, res) => {
    res.json({
      enabled: autoCleanupConfig.enabled,
      intervalHours: autoCleanupConfig.intervalHours,
      maxAgeHours: autoCleanupConfig.maxAgeHours,
      lastRun: autoCleanupConfig.lastRun,
      nextRun: autoCleanupConfig.nextRun,
      deletedCount: autoCleanupConfig.deletedCount
    });
  });

  // Update auto-cleanup settings
  app.post("/api/agents/auto-cleanup", apiRateLimiter, async (req, res) => {
    try {
      const { enabled, intervalHours, maxAgeHours } = req.body;
      
      if (typeof enabled === "boolean") {
        autoCleanupConfig.enabled = enabled;
      }
      if (typeof intervalHours === "number" && intervalHours >= 1 && intervalHours <= 168) {
        autoCleanupConfig.intervalHours = intervalHours;
      }
      if (typeof maxAgeHours === "number" && maxAgeHours >= 1 && maxAgeHours <= 720) {
        autoCleanupConfig.maxAgeHours = maxAgeHours;
      }

      startAutoCleanup();

      res.json({
        success: true,
        config: {
          enabled: autoCleanupConfig.enabled,
          intervalHours: autoCleanupConfig.intervalHours,
          maxAgeHours: autoCleanupConfig.maxAgeHours,
          nextRun: autoCleanupConfig.nextRun
        },
        message: autoCleanupConfig.enabled 
          ? `Auto-cleanup enabled: will run every ${autoCleanupConfig.intervalHours}h, removing agents inactive for ${autoCleanupConfig.maxAgeHours}h`
          : "Auto-cleanup disabled"
      });
    } catch (error) {
      console.error("Error updating auto-cleanup settings:", error);
      res.status(500).json({ error: "Failed to update auto-cleanup settings" });
    }
  });

  // Trigger immediate auto-cleanup run
  app.post("/api/agents/auto-cleanup/run-now", apiRateLimiter, async (req, res) => {
    try {
      const result = await storage.deleteStaleAgents(autoCleanupConfig.maxAgeHours);
      autoCleanupConfig.lastRun = new Date().toISOString();
      autoCleanupConfig.deletedCount += result.deleted;
      
      res.json({
        success: true,
        deleted: result.deleted,
        agents: result.agents,
        message: `Manually triggered cleanup: deleted ${result.deleted} stale agent(s)`
      });
    } catch (error) {
      console.error("Error running immediate cleanup:", error);
      res.status(500).json({ error: "Failed to run cleanup" });
    }
  });

  // Get agent by ID
  app.get("/api/agents/:id", apiRateLimiter, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }
      // Don't expose API key, calculate real-time status
      const { apiKey, apiKeyHash, ...safeAgent } = agent;
      res.json({
        ...safeAgent,
        status: calculateAgentStatus(agent.lastHeartbeat, agent.status),
      });
    } catch (error) {
      console.error("Error fetching agent:", error);
      res.status(500).json({ error: "Failed to fetch agent" });
    }
  });

  // Force agent check-in - queue command for agent to execute on next heartbeat
  app.post("/api/agents/:id/force-checkin", apiRateLimiter, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }
      
      // Queue a force_checkin command in the database
      const command = await storage.createAgentCommand({
        agentId: agent.id,
        organizationId: agent.organizationId,
        commandType: "force_checkin",
        payload: { requestedAt: new Date().toISOString() },
        status: "pending",
      });
      
      res.json({ 
        success: true, 
        message: "Check-in command queued. Agent will execute on next heartbeat (within 2 minutes).",
        commandId: command.id,
        agentId: agent.id,
        queuedAt: command.createdAt,
        expiresAt: command.expiresAt,
      });
    } catch (error) {
      console.error("Error forcing agent check-in:", error);
      res.status(500).json({ error: "Failed to queue agent check-in command" });
    }
  });

  // Queue validation probe command for agent to execute from inside target network
  app.post("/api/agents/:id/validation-probe", apiRateLimiter, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }
      
      const { host, probes, credentialServices, port, timeout, evaluationId } = req.body;
      
      if (!host) {
        return res.status(400).json({ error: "Target host is required" });
      }
      
      if ((!probes || probes.length === 0) && (!credentialServices || credentialServices.length === 0)) {
        return res.status(400).json({ error: "At least one probe type or credential service must be specified" });
      }
      
      // Validate probe types
      const validProbes = ["smtp", "dns", "ldap", "port_scan"];
      const validCredServices = ["ssh", "ftp", "telnet", "mysql", "postgres", "redis", "mongodb"];
      
      if (probes) {
        const invalidProbes = probes.filter((p: string) => !validProbes.includes(p));
        if (invalidProbes.length > 0) {
          return res.status(400).json({ error: `Invalid probe types: ${invalidProbes.join(", ")}` });
        }
      }
      
      if (credentialServices) {
        const invalidServices = credentialServices.filter((s: string) => !validCredServices.includes(s));
        if (invalidServices.length > 0) {
          return res.status(400).json({ error: `Invalid credential services: ${invalidServices.join(", ")}` });
        }
      }
      
      // Queue the validation_probe command for the agent
      const command = await storage.createAgentCommand({
        agentId: agent.id,
        organizationId: agent.organizationId,
        commandType: "validation_probe",
        payload: { 
          host,
          probes: probes || [],
          credentialServices: credentialServices || [],
          port: port || 0,
          timeout: timeout || 5000,
          evaluationId,
          requestedAt: new Date().toISOString(),
        },
        status: "pending",
      });
      
      res.json({ 
        success: true, 
        message: "Validation probe command queued. Agent will execute on next heartbeat.",
        commandId: command.id,
        agentId: agent.id,
        targetHost: host,
        probes: probes || [],
        credentialServices: credentialServices || [],
        queuedAt: command.createdAt,
        expiresAt: command.expiresAt,
      });
    } catch (error) {
      console.error("Error queuing validation probe:", error);
      res.status(500).json({ error: "Failed to queue validation probe command" });
    }
  });

  // Get pending commands for an agent (called by agent during heartbeat)
  app.get("/api/agents/:id/commands", apiRateLimiter, async (req, res) => {
    try {
      const apiKey = req.headers["x-api-key"] as string;
      if (!apiKey) {
        return res.status(401).json({ error: "API key required" });
      }
      
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent || agent.apiKey !== apiKey) {
        return res.status(401).json({ error: "Invalid agent or API key" });
      }
      
      // Expire old commands first
      await storage.expireOldCommands();
      
      // Get pending commands
      const commands = await storage.getPendingAgentCommands(agent.id);
      
      // Mark commands as acknowledged
      for (const cmd of commands) {
        await storage.acknowledgeAgentCommand(cmd.id);
      }
      
      res.json({ commands });
    } catch (error) {
      console.error("Error fetching agent commands:", error);
      res.status(500).json({ error: "Failed to fetch commands" });
    }
  });

  // Complete a command (called by agent after executing)
  app.post("/api/agents/:id/commands/:commandId/complete", apiRateLimiter, async (req, res) => {
    try {
      const apiKey = req.headers["x-api-key"] as string;
      if (!apiKey) {
        return res.status(401).json({ error: "API key required" });
      }
      
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent || agent.apiKey !== apiKey) {
        return res.status(401).json({ error: "Invalid agent or API key" });
      }
      
      const { result, errorMessage } = req.body;
      
      await storage.completeAgentCommand(req.params.commandId, result, errorMessage);
      
      res.json({ success: true });
    } catch (error) {
      console.error("Error completing agent command:", error);
      res.status(500).json({ error: "Failed to complete command" });
    }
  });

  // Get agent telemetry
  app.get("/api/agents/:id/telemetry", apiRateLimiter, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const telemetry = await storage.getAgentTelemetry(req.params.id, limit);
      
      // Transform telemetry data to match frontend expected format
      const transformedTelemetry = telemetry.map(t => {
        // Transform resourceMetrics from Go agent format to frontend format
        let resourceMetrics = t.resourceMetrics as any;
        if (resourceMetrics) {
          resourceMetrics = {
            cpuPercent: resourceMetrics.cpu_percent ?? resourceMetrics.cpuPercent,
            memoryPercent: resourceMetrics.mem_used_pct ?? resourceMetrics.memoryPercent,
            diskPercent: resourceMetrics.disk_used_pct ?? resourceMetrics.diskPercent,
            // Preserve any additional fields
            ...resourceMetrics,
          };
        }
        
        // Transform systemInfo to include kernelVersion, osVersion
        let systemInfo = t.systemInfo as any;
        if (systemInfo) {
          systemInfo = {
            ...systemInfo,
            kernelVersion: systemInfo.kernel_version ?? systemInfo.kernelVersion,
            osVersion: systemInfo.platform_version ?? systemInfo.osVersion,
          };
        }
        
        return {
          ...t,
          resourceMetrics,
          systemInfo,
        };
      });
      
      res.json(transformedTelemetry);
    } catch (error) {
      console.error("Error fetching agent telemetry:", error);
      res.status(500).json({ error: "Failed to fetch agent telemetry" });
    }
  });

  // Get agent findings
  app.get("/api/agents/:id/findings", apiRateLimiter, async (req, res) => {
    try {
      const includeNoise = req.query.includeNoise === "true";
      let findings = await storage.getAgentFindings(req.params.id);
      
      if (!includeNoise) {
        findings = findings.filter(f => f.llmValidationVerdict !== "noise");
      }
      
      res.json(findings);
    } catch (error) {
      console.error("Error fetching agent findings:", error);
      res.status(500).json({ error: "Failed to fetch agent findings" });
    }
  });

  // Delete agent
  app.delete("/api/agents/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.deleteEndpointAgent(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting agent:", error);
      res.status(500).json({ error: "Failed to delete agent" });
    }
  });

  // ============================================================================
  // ENTERPRISE AGENT MANAGEMENT ENDPOINTS
  // Provides complete agent lifecycle management with health monitoring
  // ============================================================================

  /**
   * Provision a new agent with complete setup
   * POST /api/agents/provision
   * Returns: API key, install command, and config file (ONE-TIME only)
   */
  app.post("/api/agents/provision", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { agentManagementService } = await import("./services/agent-management");

      const { hostname, platform, architecture, organizationId, environment, tags } = req.body;

      if (!hostname || !platform || !architecture) {
        return res.status(400).json({
          error: "Missing required fields: hostname, platform, architecture"
        });
      }

      const result = await agentManagementService.provisionAgent({
        hostname,
        platform,
        architecture,
        organizationId,
        environment,
        tags,
      });

      // Log for audit
      console.log(`[AUDIT] Agent provisioned: ${result.agentId} for ${hostname}`);

      res.json({
        success: true,
        ...result,
        warning: "Store the API key securely - it cannot be retrieved again",
      });
    } catch (error) {
      console.error("Error provisioning agent:", error);
      res.status(500).json({ error: "Failed to provision agent" });
    }
  });

  /**
   * Check health status of a specific agent
   * GET /api/agents/:id/health
   */
  app.get("/api/agents/:id/health", apiRateLimiter, async (req, res) => {
    try {
      const { agentManagementService } = await import("./services/agent-management");

      const health = await agentManagementService.checkAgentHealth(req.params.id);

      res.json(health);
    } catch (error: any) {
      if (error.message.includes("not found")) {
        return res.status(404).json({ error: "Agent not found" });
      }
      console.error("Error checking agent health:", error);
      res.status(500).json({ error: "Failed to check agent health" });
    }
  });

  /**
   * Check health of all agents
   * GET /api/agents/health/summary
   */
  app.get("/api/agents/health/summary", apiRateLimiter, async (req, res) => {
    try {
      const { agentManagementService } = await import("./services/agent-management");

      const summary = await agentManagementService.checkAllAgentsHealth();

      res.json(summary);
    } catch (error) {
      console.error("Error checking all agents health:", error);
      res.status(500).json({ error: "Failed to check agents health" });
    }
  });

  /**
   * Auto-recover an unhealthy agent
   * POST /api/agents/:id/recover
   */
  app.post("/api/agents/:id/recover", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { agentManagementService } = await import("./services/agent-management");

      const result = await agentManagementService.autoRecoverAgent(req.params.id);

      console.log(`[AUDIT] Agent recovery attempted for ${req.params.id}: ${result.message}`);

      res.json(result);
    } catch (error: any) {
      if (error.message.includes("not found")) {
        return res.status(404).json({ error: "Agent not found" });
      }
      console.error("Error recovering agent:", error);
      res.status(500).json({ error: "Failed to recover agent" });
    }
  });

  /**
   * Rotate agent API key
   * POST /api/agents/:id/rotate-key
   * Returns new API key and config file (ONE-TIME only)
   */
  app.post("/api/agents/:id/rotate-key", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { agentManagementService } = await import("./services/agent-management");

      const result = await agentManagementService.rotateApiKey(req.params.id);

      console.log(`[AUDIT] API key rotated for agent ${req.params.id}`);

      res.json({
        success: true,
        ...result,
        warning: "Update the agent configuration with the new API key immediately. The old key is now invalid.",
      });
    } catch (error: any) {
      if (error.message.includes("not found")) {
        return res.status(404).json({ error: "Agent not found" });
      }
      console.error("Error rotating API key:", error);
      res.status(500).json({ error: "Failed to rotate API key" });
    }
  });

  // Cleanup stale agents (agents that haven't checked in for specified hours)
  app.post("/api/agents/cleanup", apiRateLimiter, async (req, res) => {
    try {
      const maxAgeHours = Math.max(1, Math.min(720, Number(req.body.maxAgeHours) || 24));
      if (isNaN(maxAgeHours)) {
        return res.status(400).json({ error: "Invalid maxAgeHours value" });
      }
      const result = await storage.deleteStaleAgents(maxAgeHours);
      res.json({ 
        success: true, 
        deleted: result.deleted,
        agents: result.agents,
        message: `Deleted ${result.deleted} stale agent(s) that haven't checked in for ${maxAgeHours} hours`
      });
    } catch (error) {
      console.error("Error cleaning up stale agents:", error);
      res.status(500).json({ error: "Failed to cleanup stale agents" });
    }
  });

  // Get stale resources summary (agents that never checked in, stuck deployments, expired tokens)
  app.get("/api/agents/stale-resources", apiRateLimiter, async (req, res) => {
    try {
      const { agentCleanupService } = await import("./services/agent-cleanup");
      const organizationId = getOrganizationId(req) || "default";
      const summary = await agentCleanupService.getStaleResources(organizationId);
      res.json(summary);
    } catch (error) {
      console.error("Error fetching stale resources:", error);
      res.status(500).json({ error: "Failed to fetch stale resources" });
    }
  });

  // Cleanup stale resources (agents, deployment jobs, expired tokens)
  app.post("/api/agents/stale-resources/cleanup", apiRateLimiter, async (req, res) => {
    try {
      const { agentCleanupService } = await import("./services/agent-cleanup");
      const organizationId = getOrganizationId(req) || "default";
      const options = {
        cleanAgents: req.body.cleanAgents !== false,
        cleanDeploymentJobs: req.body.cleanDeploymentJobs !== false,
        cleanExpiredTokens: req.body.cleanExpiredTokens !== false,
        agentIds: req.body.agentIds,
        deploymentJobIds: req.body.deploymentJobIds,
      };
      const result = await agentCleanupService.cleanupStaleResources(organizationId, options);
      res.json(result);
    } catch (error) {
      console.error("Error cleaning up stale resources:", error);
      res.status(500).json({ error: "Failed to cleanup stale resources" });
    }
  });

  // Delete a specific agent
  app.delete("/api/agents/stale-resources/agent/:id", apiRateLimiter, async (req, res) => {
    try {
      const { agentCleanupService } = await import("./services/agent-cleanup");
      const organizationId = getOrganizationId(req) || "default";
      const result = await agentCleanupService.deleteAgent(organizationId, req.params.id);
      if (result.success) {
        res.json({ success: true, message: `Agent ${req.params.id} deleted` });
      } else {
        res.status(404).json({ error: result.error || "Agent not found" });
      }
    } catch (error) {
      console.error("Error deleting agent:", error);
      res.status(500).json({ error: "Failed to delete agent" });
    }
  });

  // Retry a failed deployment job
  app.post("/api/agents/stale-resources/deployment/:id/retry", apiRateLimiter, async (req, res) => {
    try {
      const { agentCleanupService } = await import("./services/agent-cleanup");
      const organizationId = getOrganizationId(req) || "default";
      const result = await agentCleanupService.retryDeployment(organizationId, req.params.id);
      if (result.success) {
        res.json({ success: true, message: `Deployment job ${req.params.id} queued for retry` });
      } else {
        res.status(404).json({ error: result.error || "Deployment job not found" });
      }
    } catch (error) {
      console.error("Error retrying deployment:", error);
      res.status(500).json({ error: "Failed to retry deployment" });
    }
  });

  // Get all agent findings
  app.get("/api/agent-findings", apiRateLimiter, async (req, res) => {
    try {
      const includeNoise = req.query.includeNoise === "true";
      let findings = await storage.getAgentFindings();
      
      if (!includeNoise) {
        findings = findings.filter(f => f.llmValidationVerdict !== "noise");
      }
      
      res.json(findings);
    } catch (error) {
      console.error("Error fetching agent findings:", error);
      res.status(500).json({ error: "Failed to fetch agent findings" });
    }
  });

  // Update agent finding status
  app.patch("/api/agent-findings/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.updateAgentFinding(req.params.id, req.body);
      const finding = await storage.getAgentFinding(req.params.id);
      res.json(finding);
    } catch (error) {
      console.error("Error updating agent finding:", error);
      res.status(500).json({ error: "Failed to update agent finding" });
    }
  });

  // Verify a finding (mark as verified exploitable or false positive)
  // Protected: requires authentication and security_analyst or higher role
  const verifyFindingSchema = z.object({
    verificationStatus: z.enum(["verified_exploitable", "verified_false_positive"]),
    verificationNotes: z.string().max(2000).optional(),
  });
  
  app.post("/api/agent-findings/:id/verify", apiRateLimiter, uiAuthMiddleware, requireRole("security_analyst", "security_admin", "org_owner"), async (req: UIAuthenticatedRequest, res) => {
    try {
      const parseResult = verifyFindingSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid request body", details: parseResult.error.format() });
      }
      
      const { verificationStatus, verificationNotes } = parseResult.data;
      const verifiedBy = req.user?.username || "unknown";
      
      const finding = await storage.getAgentFinding(req.params.id);
      if (!finding) {
        return res.status(404).json({ error: "Finding not found" });
      }
      
      await storage.updateAgentFinding(req.params.id, {
        verificationStatus,
        verificationNotes: verificationNotes || null,
        verifiedBy,
        verifiedAt: new Date(),
        status: verificationStatus === "verified_false_positive" ? "false_positive" : finding.status,
      });
      
      const updatedFinding = await storage.getAgentFinding(req.params.id);
      res.json(updatedFinding);
    } catch (error) {
      console.error("Error verifying agent finding:", error);
      res.status(500).json({ error: "Failed to verify agent finding" });
    }
  });

  // ============================================================================
  // mTLS Certificate Management Endpoints
  // Note: These endpoints require authenticated session (admin access)
  // ============================================================================

  // Middleware to check admin authentication for credential management
  const requireAdminAuth = (req: any, res: any, next: any) => {
    // Check for authenticated session (Replit Auth)
    if (req.isAuthenticated && req.isAuthenticated()) {
      return next();
    }
    // Check for admin API key header
    const adminKey = req.headers["x-admin-key"];
    const expectedAdminKey = process.env.ADMIN_API_KEY;
    if (expectedAdminKey && adminKey === expectedAdminKey) {
      return next();
    }
    // In development mode without session, allow access with warning
    if (process.env.NODE_ENV === "development" && !expectedAdminKey) {
      console.warn("WARNING: Credential management endpoint accessed without authentication (development mode)");
      return next();
    }
    return res.status(401).json({ error: "Admin authentication required for credential management" });
  };

  // Request a new certificate for an agent
  app.post("/api/agents/:id/certificates", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const commonName = req.body.commonName || agent.agentName;
      const validityDays = req.body.validityDays || 365;

      const certificate = await mtlsAuthService.generateCertificate({
        agentId: agent.id,
        organizationId: agent.organizationId,
        commonName,
        validityDays,
      });

      console.log(`[AUDIT] Certificate generated for agent ${agent.id} by admin`);

      res.json({
        certificateId: certificate.certificateId,
        fingerprint: certificate.fingerprint,
        certificate: certificate.certificate,
        privateKey: certificate.privateKey,
        validFrom: certificate.validFrom,
        validTo: certificate.validTo,
        message: "Certificate generated. Store the private key securely - it cannot be retrieved again.",
      });
    } catch (error) {
      console.error("Error generating certificate:", error);
      res.status(500).json({ error: "Failed to generate certificate" });
    }
  });

  // List certificates for an agent
  app.get("/api/agents/:id/certificates", apiRateLimiter, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const certificates = await mtlsAuthService.getAgentCertificates(agent.id);
      res.json(certificates.map(cert => ({
        id: cert.id,
        fingerprint: cert.fingerprint,
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        status: cert.status,
        createdAt: cert.createdAt,
      })));
    } catch (error) {
      console.error("Error fetching certificates:", error);
      res.status(500).json({ error: "Failed to fetch certificates" });
    }
  });

  // Renew a certificate
  app.post("/api/agents/:id/certificates/:certId/renew", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const newCert = await mtlsAuthService.renewCertificate(req.params.certId);
      if (!newCert) {
        return res.status(400).json({ error: "Unable to renew certificate" });
      }

      console.log(`[AUDIT] Certificate ${req.params.certId} renewed for agent ${agent.id} by admin`);

      res.json({
        certificateId: newCert.certificateId,
        fingerprint: newCert.fingerprint,
        certificate: newCert.certificate,
        privateKey: newCert.privateKey,
        validFrom: newCert.validFrom,
        validTo: newCert.validTo,
        message: "Certificate renewed. Store the new private key securely.",
      });
    } catch (error) {
      console.error("Error renewing certificate:", error);
      res.status(500).json({ error: "Failed to renew certificate" });
    }
  });

  // Revoke a certificate
  app.delete("/api/agents/:id/certificates/:certId", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const reason = req.body.reason || "Manually revoked";
      const success = await mtlsAuthService.revokeCertificate(req.params.certId, reason);
      
      if (!success) {
        return res.status(404).json({ error: "Certificate not found" });
      }

      console.log(`[AUDIT] Certificate ${req.params.certId} revoked by admin: ${reason}`);

      res.json({ success: true, message: "Certificate revoked" });
    } catch (error) {
      console.error("Error revoking certificate:", error);
      res.status(500).json({ error: "Failed to revoke certificate" });
    }
  });

  // ============================================================================
  // JWT Token Management Endpoints
  // Note: Token generation requires admin auth, refresh is self-service
  // ============================================================================

  // Generate JWT tokens for an agent
  app.post("/api/agents/:id/tokens", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const scopes = req.body.scopes || ["read", "write"];
      const tokenPair = await jwtAuthService.generateTokenPair({
        organizationId: agent.organizationId,
        agentId: agent.id,
        scopes,
        subject: agent.agentName,
      });

      console.log(`[AUDIT] JWT tokens generated for agent ${agent.id} by admin`);

      res.json({
        accessToken: tokenPair.accessToken,
        refreshToken: tokenPair.refreshToken,
        accessTokenExpiresAt: tokenPair.accessTokenExpiresAt,
        refreshTokenExpiresAt: tokenPair.refreshTokenExpiresAt,
        message: "Tokens generated. Store the refresh token securely.",
      });
    } catch (error) {
      console.error("Error generating tokens:", error);
      res.status(500).json({ error: "Failed to generate tokens" });
    }
  });

  // Refresh JWT tokens
  app.post("/api/auth/refresh", authRateLimiter, async (req, res) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(400).json({ error: "Refresh token required" });
      }

      const newTokens = await jwtAuthService.refreshAccessToken(refreshToken);
      if (!newTokens) {
        return res.status(401).json({ error: "Invalid or expired refresh token" });
      }

      res.json({
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
        accessTokenExpiresAt: newTokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: newTokens.refreshTokenExpiresAt,
      });
    } catch (error) {
      console.error("Error refreshing tokens:", error);
      res.status(500).json({ error: "Failed to refresh tokens" });
    }
  });

  // Revoke all credentials for an agent
  app.post("/api/agents/:id/revoke-all", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const result = await unifiedAuthService.revokeAgentCredentials(agent.id);
      console.log(`[AUDIT] All credentials revoked for agent ${agent.id} by admin: ${result.revokedCerts} certs, ${result.revokedTokens} tokens`);
      
      res.json({
        success: true,
        revokedCertificates: result.revokedCerts,
        revokedTokens: result.revokedTokens,
        message: "All agent credentials revoked",
      });
    } catch (error) {
      console.error("Error revoking credentials:", error);
      res.status(500).json({ error: "Failed to revoke credentials" });
    }
  });

  // Get agent authentication status
  app.get("/api/agents/:id/auth-status", apiRateLimiter, async (req, res) => {
    try {
      const agent = await storage.getEndpointAgent(req.params.id);
      if (!agent) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const status = await unifiedAuthService.getAgentAuthStatus(agent.id);
      res.json({
        agentId: agent.id,
        agentName: agent.agentName,
        hasApiKey: !!agent.apiKeyHash || !!agent.apiKey,
        ...status,
      });
    } catch (error) {
      console.error("Error fetching auth status:", error);
      res.status(500).json({ error: "Failed to fetch auth status" });
    }
  });

  // ============================================================================
  // Agent Registration Token Management
  // Generate single-use tokens for secure agent auto-registration
  // ============================================================================

  // Generate a new single-use registration token
  app.post("/api/agents/registration-tokens", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { organizationId, label, expiresInHours } = req.body;
      const org = organizationId || "default";
      const expHours = expiresInHours || 24; // Default 24 hours
      
      // Generate a secure random token
      const token = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256").update(token).digest("hex");
      const id = `regtoken-${randomBytes(4).toString("hex")}`;
      const expiresAt = new Date(Date.now() + expHours * 60 * 60 * 1000);
      
      const registrationToken = await storage.createAgentRegistrationToken({
        id,
        tokenHash,
        organizationId: org,
        label: label || `Token created at ${new Date().toISOString()}`,
        expiresAt,
      });
      
      console.log(`[AUDIT] Registration token ${id} created for org ${org}, expires ${expiresAt.toISOString()}`);
      
      res.json({
        id: registrationToken.id,
        token, // Only returned once, never stored
        label: registrationToken.label,
        organizationId: registrationToken.organizationId,
        expiresAt: registrationToken.expiresAt,
        message: "Single-use registration token created. Store securely - the token value cannot be retrieved again.",
      });
    } catch (error) {
      console.error("Error creating registration token:", error);
      res.status(500).json({ error: "Failed to create registration token" });
    }
  });

  // List registration tokens for an organization (admin only)
  app.get("/api/agents/registration-tokens", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = (req.query.organizationId as string) || "default";
      const tokens = await storage.getAgentRegistrationTokens(organizationId);
      
      // Return token metadata without the hash
      res.json(tokens.map(t => ({
        id: t.id,
        label: t.label,
        organizationId: t.organizationId,
        expiresAt: t.expiresAt,
        usedAt: t.usedAt,
        usedByAgentId: t.usedByAgentId,
        createdAt: t.createdAt,
        isExpired: new Date(t.expiresAt) < new Date(),
        isUsed: !!t.usedAt,
      })));
    } catch (error) {
      console.error("Error fetching registration tokens:", error);
      res.status(500).json({ error: "Failed to fetch registration tokens" });
    }
  });

  // Delete a registration token
  app.delete("/api/agents/registration-tokens/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      await storage.deleteAgentRegistrationToken(req.params.id);
      console.log(`[AUDIT] Registration token ${req.params.id} deleted`);
      res.json({ success: true, message: "Registration token deleted" });
    } catch (error) {
      console.error("Error deleting registration token:", error);
      res.status(500).json({ error: "Failed to delete registration token" });
    }
  });

  // Cleanup expired/used tokens (maintenance endpoint)
  app.post("/api/agents/registration-tokens/cleanup", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const deletedCount = await storage.cleanupExpiredAgentRegistrationTokens();
      console.log(`[AUDIT] Cleaned up ${deletedCount} expired/used registration tokens`);
      res.json({ success: true, deletedCount, message: `Removed ${deletedCount} expired or used tokens` });
    } catch (error) {
      console.error("Error cleaning up registration tokens:", error);
      res.status(500).json({ error: "Failed to cleanup registration tokens" });
    }
  });

  // Generate a ready-to-use install command with embedded token (zero user interaction)
  // This is the primary endpoint for automated agent deployment
  app.post("/api/agents/install-command", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { platform, organizationId, label, expiresInHours, serverUrl: customServerUrl } = req.body;
      const org = organizationId || "default";
      const expHours = expiresInHours || 24;
      const targetPlatform = platform || "linux";
      
      // Generate a single-use token
      const token = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256").update(token).digest("hex");
      const id = `regtoken-${randomBytes(4).toString("hex")}`;
      const expiresAt = new Date(Date.now() + expHours * 60 * 60 * 1000);
      
      await storage.createAgentRegistrationToken({
        id,
        tokenHash,
        organizationId: org,
        label: label || `Auto-install command generated at ${new Date().toISOString()}`,
        expiresAt,
      });
      
      // Construct the server URL - prefer custom URL, then Replit domain, then request host
      let serverUrl: string;
      if (customServerUrl) {
        serverUrl = customServerUrl.replace(/\/$/, ''); // Remove trailing slash
      } else {
        // Determine server URL from host header
        const host = req.get("host") || "localhost:5000";
        const isLocalhost = host.startsWith("localhost") || host.startsWith("127.0.0.1");
        const protocol = isLocalhost ? "http" : "https";
        serverUrl = `${protocol}://${host}`;
        }
      }
      
      // Generate platform-specific install commands
      let installCommand: string;
      let scriptUrl: string;
      
      if (targetPlatform === "windows") {
        scriptUrl = `${serverUrl}/api/agents/install.ps1?token=${encodeURIComponent(token)}`;
        installCommand = `irm '${scriptUrl}' | iex`;
      } else {
        // Linux (default)
        scriptUrl = `${serverUrl}/api/agents/install.sh?token=${encodeURIComponent(token)}`;
        installCommand = `curl -sSL '${scriptUrl}' | sudo bash`;
      }
      
      console.log(`[AUDIT] Install command generated for org ${org}, platform ${targetPlatform}, token ${id}`);
      
      res.json({
        installCommand,
        scriptUrl,
        platform: targetPlatform,
        tokenId: id,
        organizationId: org,
        expiresAt,
        expiresInHours: expHours,
        message: "Copy and run this command on your target machine. The token is single-use and will expire after first registration or timeout.",
      });
    } catch (error) {
      console.error("Error generating install command:", error);
      res.status(500).json({ error: "Failed to generate install command" });
    }
  });

  // ============================================================================
  // Tenant Management Endpoints
  // Note: These endpoints require admin authentication
  // ============================================================================

  // Create a new tenant
  app.post("/api/tenants", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { name, organizationId, allowedScopes, accessTokenTTL, refreshTokenTTL } = req.body;
      if (!name) {
        return res.status(400).json({ error: "Tenant name required" });
      }

      const tenant = await jwtAuthService.createTenant({
        organizationId: organizationId || "default",
        name,
        allowedScopes,
        accessTokenTTL,
        refreshTokenTTL,
      });

      console.log(`[AUDIT] Tenant ${tenant.id} created by admin: ${name}`);

      res.json({
        id: tenant.id,
        name: tenant.name,
        organizationId: tenant.organizationId,
        secretKey: tenant.secretKey,
        allowedScopes: tenant.allowedScopes,
        accessTokenTTL: tenant.accessTokenTTL,
        refreshTokenTTL: tenant.refreshTokenTTL,
        createdAt: tenant.createdAt,
        message: "Tenant created. Store the secret key securely - it cannot be retrieved again.",
      });
    } catch (error) {
      console.error("Error creating tenant:", error);
      res.status(500).json({ error: "Failed to create tenant" });
    }
  });

  // List tenants
  app.get("/api/tenants", apiRateLimiter, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const tenants = await jwtAuthService.listTenants(organizationId);
      res.json(tenants);
    } catch (error) {
      console.error("Error fetching tenants:", error);
      res.status(500).json({ error: "Failed to fetch tenants" });
    }
  });

  // Get tenant by ID
  app.get("/api/tenants/:id", apiRateLimiter, async (req, res) => {
    try {
      const tenant = await jwtAuthService.getTenant(req.params.id);
      if (!tenant) {
        return res.status(404).json({ error: "Tenant not found" });
      }
      
      res.json({
        id: tenant.id,
        name: tenant.name,
        organizationId: tenant.organizationId,
        allowedScopes: tenant.allowedScopes,
        accessTokenTTL: tenant.accessTokenTTL,
        refreshTokenTTL: tenant.refreshTokenTTL,
        active: tenant.active,
        createdAt: tenant.createdAt,
        updatedAt: tenant.updatedAt,
      });
    } catch (error) {
      console.error("Error fetching tenant:", error);
      res.status(500).json({ error: "Failed to fetch tenant" });
    }
  });

  // Deactivate tenant
  app.delete("/api/tenants/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const success = await jwtAuthService.deactivateTenant(req.params.id);
      if (!success) {
        return res.status(404).json({ error: "Tenant not found" });
      }
      
      console.log(`[AUDIT] Tenant ${req.params.id} deactivated by admin`);
      
      res.json({ success: true, message: "Tenant deactivated" });
    } catch (error) {
      console.error("Error deactivating tenant:", error);
      res.status(500).json({ error: "Failed to deactivate tenant" });
    }
  });

  // ============================================================================
  // Auth Configuration Endpoint
  // Note: Config changes require admin authentication
  // ============================================================================

  // Get authentication configuration (read-only, no auth required)
  app.get("/api/auth/config", authRateLimiter, async (req, res) => {
    try {
      const config = unifiedAuthService.getConfig();
      res.json(config);
    } catch (error) {
      console.error("Error fetching auth config:", error);
      res.status(500).json({ error: "Failed to fetch auth config" });
    }
  });

  // Update authentication configuration (admin only)
  app.patch("/api/auth/config", authRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const updates = req.body;
      unifiedAuthService.configure(updates);
      console.log(`[AUDIT] Auth config updated by admin:`, updates);
      const config = unifiedAuthService.getConfig();
      res.json(config);
    } catch (error) {
      console.error("Error updating auth config:", error);
      res.status(500).json({ error: "Failed to update auth config" });
    }
  });

  // ============================================================================
  // ORGANIZATION SETTINGS ENDPOINTS
  // ============================================================================

  // In-memory organization settings (extends governance table data)
  const organizationSettings = {
    organizationName: "OdinForge Security",
    organizationDescription: "Advanced adversarial exposure validation platform",
    contactEmail: "security@odinforge.ai",
    contactPhone: "",
    sessionTimeoutMinutes: 30,
    mfaRequired: false,
    mfaGracePeriodDays: 7,
    passwordMinLength: 12,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSpecial: true,
    passwordExpiryDays: 90,
    emailNotificationsEnabled: true,
    emailCriticalAlerts: true,
    emailHighAlerts: true,
    emailMediumAlerts: false,
    emailLowAlerts: false,
    emailDailyDigest: true,
    alertThresholdCritical: 90,
    alertThresholdHigh: 70,
    alertThresholdMedium: 40,
    apiRateLimitPerMinute: 60,
    apiRateLimitPerHour: 1000,
    apiRateLimitPerDay: 10000,
    apiLoggingEnabled: true,
    webhooksEnabled: false,
    webhookUrl: "",
  };

  // Get organization settings
  app.get("/api/organization/settings", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      res.json(organizationSettings);
    } catch (error) {
      console.error("Error fetching organization settings:", error);
      res.status(500).json({ error: "Failed to fetch organization settings" });
    }
  });

  // Update organization settings
  app.patch("/api/organization/settings", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const updates = req.body;
      Object.keys(updates).forEach(key => {
        if (key in organizationSettings) {
          (organizationSettings as any)[key] = updates[key];
        }
      });
      console.log(`[AUDIT] Organization settings updated:`, Object.keys(updates));
      res.json(organizationSettings);
    } catch (error) {
      console.error("Error updating organization settings:", error);
      res.status(500).json({ error: "Failed to update organization settings" });
    }
  });

  // ============================================================================
  // USER MANAGEMENT ENDPOINTS
  // Note: Requires admin authentication for all operations
  // ============================================================================

  // Get all users
  app.get("/api/users", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const users = await storage.getAllUsers(organizationId);
      res.json(users.map(u => ({ ...u, password: undefined })));
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });

  // Create a new user
  app.post("/api/users", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { username, password, role, displayName, email } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
      }

      const existingUser = await storage.getUserByUsername(username);
      if (existingUser) {
        return res.status(409).json({ error: "Username already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await storage.createUser({
        username,
        password: hashedPassword,
        role: role || "security_analyst",
        displayName,
        email,
      });

      console.log(`[AUDIT] User ${user.id} (${username}) created by admin`);
      res.json({ ...user, password: undefined });
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ error: "Failed to create user" });
    }
  });

  // Update a user
  app.patch("/api/users/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { role, displayName, email, password } = req.body;
      const user = await storage.getUser(req.params.id);
      
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const updates: any = {};
      if (role !== undefined) updates.role = role;
      if (displayName !== undefined) updates.displayName = displayName;
      if (email !== undefined) updates.email = email;
      if (password) updates.password = await bcrypt.hash(password, 10);

      await storage.updateUser(req.params.id, updates);
      const updatedUser = await storage.getUser(req.params.id);
      
      console.log(`[AUDIT] User ${req.params.id} updated by admin`);
      res.json({ ...updatedUser, password: undefined });
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ error: "Failed to update user" });
    }
  });

  // Delete a user
  app.delete("/api/users/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const user = await storage.getUser(req.params.id);
      
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      await storage.deleteUser(req.params.id);
      
      console.log(`[AUDIT] User ${req.params.id} (${user.username}) deleted by admin`);
      res.json({ success: true, message: "User deleted successfully" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ error: "Failed to delete user" });
    }
  });

  // ========== EXTERNAL RECONNAISSANCE ENDPOINTS ==========
  // These routes perform external scanning of internet-facing assets
  // without requiring agent installation

  const reconScanSchema = z.object({
    target: z.string().min(1).max(256),
    scanTypes: z.object({
      portScan: z.boolean().default(true),
      sslCheck: z.boolean().default(true),
      httpFingerprint: z.boolean().default(true),
      dnsEnum: z.boolean().default(true),
    }).optional(),
  });

  app.post("/api/recon/scan", evaluationRateLimiter, async (req, res) => {
    try {
      const parsed = reconScanSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      }

      const { target, scanTypes } = parsed.data;
      const scanId = `recon-${randomUUID().slice(0, 8)}`;

      // Validate target - only allow domain names and IPs, no internal ranges
      const hostname = target.startsWith('http') 
        ? new URL(target).hostname 
        : target.split('/')[0].split(':')[0];
      
      // Block internal/private IPs
      const privatePatterns = [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[01])\./,
        /^192\.168\./,
        /^127\./,
        /^localhost$/i,
        /^0\./,
      ];
      
      if (privatePatterns.some(p => p.test(hostname))) {
        return res.status(400).json({ 
          error: "Cannot scan private/internal addresses",
          message: "External reconnaissance is only available for public internet-facing targets"
        });
      }

      // Create pending scan record in database
      await storage.createReconScan({
        id: scanId,
        target: hostname,
        status: "pending",
        organizationId: "default",
        errors: [],
      });

      // Start scan asynchronously
      res.json({ 
        scanId,
        message: "Scan started",
        target: hostname
      });

      // Run the scan in background with progress reporting
      fullRecon(target, {
        portScan: scanTypes?.portScan ?? true,
        sslCheck: scanTypes?.sslCheck ?? true,
        httpFingerprint: scanTypes?.httpFingerprint ?? true,
        dnsEnum: scanTypes?.dnsEnum ?? true,
      }, (phase, progress, message, portsFound, vulnerabilitiesFound) => {
        // Send progress update via WebSocket
        wsService.sendReconProgress(scanId, phase, progress, message, portsFound, vulnerabilitiesFound);
      }).then(async (result) => {
        try {
          // Save completed scan to database
          await storage.updateReconScan(scanId, {
            status: "completed",
            scanTime: result.scanTime,
            portScan: result.portScan || null,
            sslCheck: result.sslCheck || null,
            httpFingerprint: result.httpFingerprint || null,
            dnsEnum: result.dnsEnum || null,
            errors: result.errors || [],
          });
          // Notify via WebSocket
          wsService.broadcast({
            type: 'recon_complete',
            scanId,
            target: hostname,
            timestamp: new Date().toISOString(),
          });
        } catch (dbErr) {
          console.error("Failed to save recon scan result:", dbErr);
        }
      }).catch(async (err) => {
        console.error("Recon scan error:", err);
        try {
          await storage.updateReconScan(scanId, {
            status: "failed",
            errors: [err.message],
          });
        } catch (dbErr) {
          console.error("Failed to update recon scan status:", dbErr);
        }
      });
    } catch (error) {
      console.error("Recon scan error:", error);
      res.status(500).json({ error: "Scan initiation failed" });
    }
  });

  app.get("/api/recon/results/:scanId", apiRateLimiter, async (req, res) => {
    try {
      const { scanId } = req.params;
      const scan = await storage.getReconScan(scanId);
      
      if (!scan) {
        return res.status(404).json({ 
          error: "Scan not found",
          message: "The scan ID was not found."
        });
      }
      
      if (scan.status === "pending") {
        return res.status(202).json({ 
          status: "pending",
          error: "Scan still in progress",
          message: "The scan is still running. Try again in a few seconds."
        });
      }

      if (scan.status === "failed") {
        return res.json({
          scanId,
          status: "failed",
          result: {
            target: scan.target,
            scanTime: scan.scanTime || new Date(),
            errors: scan.errors || ["Scan failed"],
          },
          exposures: [],
          canCreateEvaluation: false,
          error: scan.errors?.[0] || "Scan failed",
        });
      }

      // Convert database record to ReconResult format for reconToExposures
      const result: ReconResult = {
        target: scan.target,
        scanTime: scan.scanTime || new Date(),
        portScan: scan.portScan || undefined,
        networkExposure: scan.networkExposure || undefined,
        sslCheck: scan.sslCheck || undefined,
        transportSecurity: scan.transportSecurity || undefined,
        httpFingerprint: scan.httpFingerprint || undefined,
        applicationIdentity: scan.applicationIdentity || undefined,
        authenticationSurface: scan.authenticationSurface || undefined,
        dnsEnum: scan.dnsEnum || undefined,
        infrastructure: scan.infrastructure || undefined,
        attackReadiness: scan.attackReadiness || undefined,
        errors: scan.errors || [],
      };

      // Convert to exposures for evaluation integration
      const exposures = reconToExposures(result);

      res.json({
        scanId,
        status: "completed",
        result,
        exposures,
        canCreateEvaluation: exposures.length > 0,
      });
    } catch (error) {
      console.error("Get recon results error:", error);
      res.status(500).json({ error: "Failed to retrieve results" });
    }
  });

  // Create evaluation from recon findings
  app.post("/api/recon/create-evaluation", evaluationRateLimiter, async (req, res) => {
    try {
      const { scanId, selectedExposures } = req.body;
      
      if (!scanId || !Array.isArray(selectedExposures) || selectedExposures.length === 0) {
        return res.status(400).json({ error: "scanId and selectedExposures are required" });
      }

      // Fetch from database instead of in-memory map
      const scan = await storage.getReconScan(scanId);
      if (!scan || scan.status !== "completed") {
        return res.status(404).json({ error: "Scan results not found or still in progress" });
      }

      // Convert database record to ReconResult format
      const result: ReconResult = {
        target: scan.target,
        scanTime: scan.scanTime || new Date(),
        portScan: scan.portScan || undefined,
        sslCheck: scan.sslCheck || undefined,
        httpFingerprint: scan.httpFingerprint || undefined,
        dnsEnum: scan.dnsEnum || undefined,
        errors: scan.errors || [],
      };

      // Create evaluation from findings
      const exposures = reconToExposures(result);
      const selected = exposures.filter((_, i: number) => selectedExposures.includes(i));
      
      if (selected.length === 0) {
        return res.status(400).json({ error: "No valid exposures selected" });
      }

      // Determine priority based on highest severity
      const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const highestSeverity = selected.reduce((highest, exp) => {
        return severityOrder.indexOf(exp.severity) < severityOrder.indexOf(highest) 
          ? exp.severity 
          : highest;
      }, 'info' as 'critical' | 'high' | 'medium' | 'low' | 'info');
      
      const priorityMap: Record<string, string> = {
        critical: 'critical',
        high: 'high',
        medium: 'medium',
        low: 'low',
        info: 'low',
      };

      const evaluation = await storage.createEvaluation({
        assetId: result.target,
        exposureType: selected[0].type,
        priority: priorityMap[highestSeverity] || 'medium',
        description: `External reconnaissance findings:\n${selected.map(e => `- ${e.description}`).join('\n')}\n\nEvidence:\n${selected.map(e => e.evidence).join('\n')}`,
        organizationId: "default",
      });

      // Create LiveScanResult so this can be used in AI simulations
      const ports = (result.portScan || []).map((p: any) => ({
        port: p.port,
        state: p.state,
        service: p.service || null,
        banner: p.banner || null,
      }));

      const vulnerabilities = selected.map((exp: any) => ({
        issue: exp.description,
        recommendation: `Address ${exp.type} finding: ${exp.description}`,
        cve: null,
        severity: exp.severity,
      }));

      // Use current time for timestamps
      const now = new Date();
      const startTime = scan.scanTime instanceof Date ? scan.scanTime : now;
      
      await storage.createLiveScanResult({
        evaluationId: evaluation.id,
        organizationId: "default",
        targetHost: result.target,
        resolvedIp: null,
        resolvedHostname: null,
        ports,
        vulnerabilities,
        scanStarted: startTime,
        scanCompleted: now,
        status: "completed",
      });

      res.json({ 
        evaluationId: evaluation.id,
        message: "Evaluation created from reconnaissance findings"
      });
    } catch (error) {
      console.error("Create evaluation from recon error:", error);
      res.status(500).json({ error: "Failed to create evaluation" });
    }
  });

  // ============================================================================
  // Full Assessment (Multi-System Pentest) Endpoints
  // ============================================================================

  // Create and start a full assessment (supports enhanced mode with target URL)
  app.post("/api/full-assessments", evaluationRateLimiter, async (req, res) => {
    try {
      const { 
        name, 
        description, 
        agentIds, 
        organizationId,
        // Assessment mode: 'agent' (default) requires agents, 'external' is for serverless (no agents needed)
        assessmentMode,
        // Enhanced assessment options
        targetUrl,
        enableWebAppRecon,
        enableParallelAgents,
        maxConcurrentAgents,
        vulnerabilityTypes,
        enableLLMValidation,
      } = req.body;
      
      if (!name) {
        return res.status(400).json({ error: "Assessment name is required" });
      }
      
      // Validate external mode requires target URL
      const mode = assessmentMode === "external" ? "external" : "agent";
      if (mode === "external" && !targetUrl) {
        return res.status(400).json({ error: "Target URL is required for external (serverless) assessments" });
      }

      const assessment = await storage.createFullAssessment({
        name,
        description,
        agentIds: agentIds || null,
        organizationId: organizationId || "default",
        assessmentMode: mode,
        targetUrl: targetUrl || null,
        status: "pending",
        currentPhase: mode === "external" ? "web_recon" : (targetUrl ? "web_recon" : "reconnaissance"),
      });

      // External mode: Uses only web app scanning (no agents required)
      if (mode === "external") {
        runFullAssessment(assessment.id).catch(error => {
          console.error("External assessment failed:", error);
        });
      }
      // Enhanced mode: Agent-based with additional web app recon
      else if (targetUrl) {
        const { runEnhancedFullAssessment } = await import("./services/full-assessment");
        runEnhancedFullAssessment(assessment.id, {
          targetUrl,
          enableWebAppRecon: enableWebAppRecon !== false,
          enableParallelAgents: enableParallelAgents !== false,
          maxConcurrentAgents: maxConcurrentAgents || 5,
          vulnerabilityTypes: vulnerabilityTypes || ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal", "ssrf"],
          enableLLMValidation: enableLLMValidation !== false,
        }).catch(error => {
          console.error("Enhanced full assessment failed:", error);
        });
      } 
      // Standard mode: Agent-based only
      else {
        runFullAssessment(assessment.id).catch(error => {
          console.error("Full assessment failed:", error);
        });
      }

      res.json({ 
        assessmentId: assessment.id,
        message: mode === "external" 
          ? "External assessment started (no agents required)" 
          : targetUrl 
            ? "Enhanced full assessment started with web application reconnaissance" 
            : "Full assessment started",
        mode: mode === "external" ? "external" : (targetUrl ? "enhanced" : "standard"),
      });
    } catch (error) {
      console.error("Create full assessment error:", error);
      res.status(500).json({ error: "Failed to create assessment" });
    }
  });

  // Get all full assessments
  app.get("/api/full-assessments", apiRateLimiter, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const assessments = await storage.getFullAssessments(organizationId);
      res.json(assessments);
    } catch (error) {
      console.error("Get full assessments error:", error);
      res.status(500).json({ error: "Failed to fetch assessments" });
    }
  });

  // Get a specific full assessment
  app.get("/api/full-assessments/:id", apiRateLimiter, async (req, res) => {
    try {
      const assessment = await storage.getFullAssessment(req.params.id);
      if (!assessment) {
        return res.status(404).json({ error: "Assessment not found" });
      }
      res.json(assessment);
    } catch (error) {
      console.error("Get full assessment error:", error);
      res.status(500).json({ error: "Failed to fetch assessment" });
    }
  });

  // Delete a full assessment
  app.delete("/api/full-assessments/:id", apiRateLimiter, async (req, res) => {
    try {
      await storage.deleteFullAssessment(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Delete full assessment error:", error);
      res.status(500).json({ error: "Failed to delete assessment" });
    }
  });

  return httpServer;
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
    if (data.exposureType === "app_logic" && data.appLogicData) {
      const { analyzeAppLogicExposure } = await import("./services/app-logic-analyzer");
      
      wsService.sendProgress(evaluationId, "App Logic Analyzer", "init", 10, "Initializing deterministic analyzer...");
      wsService.sendProgress(evaluationId, "App Logic Analyzer", "analysis", 50, "Checking IDOR/BOLA patterns...");
      
      const result = analyzeAppLogicExposure({
        assetId: data.assetId,
        description: data.description,
        data: data.appLogicData,
      });
      
      wsService.sendProgress(evaluationId, "App Logic Analyzer", "complete", 100, "Analysis complete");
      
      const duration = Date.now() - startTime;
      
      await storage.createResult({
        id: `res-${randomUUID().slice(0, 8)}`,
        evaluationId,
        exploitable: result.exploitable,
        confidence: result.confidence,
        score: result.score,
        attackPath: result.attackPath,
        impact: result.impact,
        recommendations: result.recommendations.map(r => r.title),
        evidenceArtifacts: [],
        intelligentScore: {
          overall: result.score,
          exploitability: result.exploitable ? result.score : result.score * 0.3,
          impact: result.exploitable ? 70 : 30,
          defensibility: result.exploitable ? 30 : 70,
          confidence: result.confidence,
        },
        remediationGuidance: {
          immediate: result.recommendations.filter(r => r.priority === "critical" || r.priority === "high").map(r => r.description),
          shortTerm: result.recommendations.filter(r => r.priority === "medium").map(r => r.description),
          longTerm: result.recommendations.filter(r => r.priority === "low").map(r => r.description),
          estimatedEffort: result.exploitable ? "medium" : "low",
          priorityOrder: result.recommendations.map(r => r.title),
        },
        duration,
      });
      
      await storage.updateEvaluationStatus(evaluationId, "completed");
      wsService.sendComplete(evaluationId, true);
      console.log(`[AEV] App logic evaluation ${evaluationId} completed in ${duration}ms (deterministic, no LLM)`);
      return;
    }

    // If in simulation mode, run AI vs AI simulation instead
    if (executionMode === "simulation") {
      console.log(`[GOVERNANCE] Running AI vs AI simulation for evaluation ${evaluationId}`);
      
      const simulationResult = await runAISimulation(
        data.assetId,
        data.exposureType,
        data.priority,
        data.description,
        evaluationId,
        3, // 3 rounds by default
        (phase, round, progress, message) => {
          wsService.sendProgress(evaluationId, `Simulation ${phase}`, `round-${round}`, progress, message);
        }
      );

      const duration = Date.now() - startTime;

      // Store as AI simulation result
      await storage.createAiSimulation({
        id: `sim-${randomUUID().slice(0, 8)}`,
        evaluationId,
        assetId: data.assetId,
        exposureType: data.exposureType,
        status: "completed",
        rounds: simulationResult.rounds.length,
        attackerScore: simulationResult.finalAttackScore,
        defenderScore: simulationResult.finalDefenseScore,
        attackerResults: simulationResult.rounds.map(r => r.attackerFindings),
        defenderResults: simulationResult.rounds.map(r => r.defenderFindings),
        purpleTeamFindings: [simulationResult.purpleTeamFeedback],
        recommendations: simulationResult.recommendations,
        duration,
      });

      // Also create a standard result with simulation summary for UI compatibility
      const attackerScore = simulationResult.finalAttackScore;
      const defenderScore = simulationResult.finalDefenseScore;
      const recsAsStrings = simulationResult.recommendations.map(r => r.title);
      
      await storage.createResult({
        id: `res-${randomUUID().slice(0, 8)}`,
        evaluationId,
        exploitable: attackerScore > 50,
        confidence: Math.round((attackerScore + defenderScore) / 2),
        score: attackerScore,
        attackPath: simulationResult.rounds[0]?.attackerFindings?.attackPath || [],
        attackGraph: simulationResult.rounds[0]?.attackerFindings?.attackGraph,
        businessLogicFindings: simulationResult.rounds[0]?.attackerFindings?.businessLogicFindings,
        multiVectorFindings: simulationResult.rounds[0]?.attackerFindings?.multiVectorFindings,
        workflowAnalysis: simulationResult.rounds[0]?.attackerFindings?.workflowAnalysis,
        impact: simulationResult.rounds[0]?.attackerFindings?.impact,
        recommendations: recsAsStrings,
        evidenceArtifacts: [],
        intelligentScore: {
          overall: attackerScore,
          exploitability: attackerScore,
          impact: defenderScore > 70 ? 30 : 70,
          defensibility: defenderScore,
          confidence: 85,
        },
        remediationGuidance: {
          immediate: recsAsStrings.slice(0, 2),
          shortTerm: recsAsStrings.slice(2, 4),
          longTerm: recsAsStrings.slice(4),
          estimatedEffort: "medium",
          priorityOrder: recsAsStrings,
        },
        duration,
      });

      await storage.updateEvaluationStatus(evaluationId, "completed");
      wsService.sendComplete(evaluationId, true);
      return;
    }

    // If in live mode, perform actual network scanning in addition to AI analysis
    let liveScanResult: import("./services/live-network-testing").ScanResult | null = null;
    if (executionMode === "live") {
      console.log(`[GOVERNANCE] Live mode enabled for evaluation ${evaluationId} - performing network scan`);
      
      const { performLiveScan, parseTargetFromAsset } = await import("./services/live-network-testing");
      const target = parseTargetFromAsset(data.assetId, data.description);
      
      if (target) {
        try {
          wsService.sendProgress(evaluationId, "Live Scanner", "init", 5, `Initializing live scan for ${target.host}...`);
          
          liveScanResult = await performLiveScan(
            evaluationId,
            target,
            orgId,
            (progress) => {
              wsService.sendProgress(
                evaluationId, 
                "Live Scanner", 
                progress.phase, 
                progress.progress, 
                progress.message
              );
            }
          );
          
          // Store live scan result
          await storage.createLiveScanResult({
            evaluationId,
            organizationId: orgId,
            targetHost: target.host,
            resolvedIp: liveScanResult.ip,
            resolvedHostname: liveScanResult.hostname,
            ports: liveScanResult.ports.map(p => ({
              port: p.port,
              state: p.state,
              service: p.service,
              banner: p.banner,
              version: p.version,
            })),
            vulnerabilities: liveScanResult.vulnerabilities.map((v, i) => ({
              id: `vuln-${i + 1}`,
              port: v.port,
              service: v.service,
              severity: v.severity,
              title: v.issue,
              description: v.issue,
              cveIds: v.cve ? [v.cve] : [],
              remediation: v.recommendation,
            })),
            scanStarted: liveScanResult.scanStarted,
            scanCompleted: liveScanResult.scanCompleted,
            status: "completed",
          });
          
          console.log(`[LIVE] Scan completed: ${liveScanResult.ports.length} open ports, ${liveScanResult.vulnerabilities.length} vulnerabilities`);
        } catch (liveError) {
          console.error(`[LIVE] Scan failed for ${target.host}:`, liveError);
          wsService.sendProgress(evaluationId, "Live Scanner", "error", 0, `Live scan failed: ${String(liveError)}`);
          // Continue with AI analysis even if live scan fails
        }
      } else {
        console.log(`[LIVE] No scannable target found in asset ${data.assetId}`);
      }
    }

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
    const { detectsApiPatterns, tryAutoAnalyze } = await import("./services/app-logic-analyzer");
    
    let finalResult = result;
    // Only run app-logic analyzer if patterns are detected (cheap check first)
    if (detectsApiPatterns(data.description)) {
      const appLogicResult = tryAutoAnalyze(data.assetId, data.description);
      
      if (appLogicResult && appLogicResult.exploitable) {
        console.log(`[AEV] Auto-detected app logic issues in ${evaluationId}`);
        wsService.sendProgress(evaluationId, "App Logic Analyzer", "merge", 95, "Merging app-logic findings...");
        
        // Merge attack paths
        const mergedAttackPath = [
          ...(result.attackPath || []),
          ...(appLogicResult.attackPath || []).map((step, i) => ({
            ...step,
            id: (result.attackPath?.length || 0) + i + 1,
            title: `[Auto-detected] ${step.title}`,
          })),
        ];
        
        // Merge recommendations (result.recommendations is string[], appLogicResult has structured recs)
        const existingRecTitles = new Set(result.recommendations || []);
        const newRecTitles = (appLogicResult.recommendations || [])
          .map(r => r.title)
          .filter(title => !existingRecTitles.has(title));
        const mergedRecommendations = [
          ...(result.recommendations || []),
          ...newRecTitles,
        ];
        
        // Build businessLogicFindings from app-logic detections
        const appLogicFindings = {
          detected: true,
          autoDetected: true,
          findings: (appLogicResult.attackPath || []).map(step => ({
            type: step.technique || "app_logic",
            severity: step.severity || "high",
            description: step.description,
            impact: appLogicResult.impact,
          })),
        };
        
        // Take higher score/confidence if app-logic found issues
        finalResult = {
          ...result,
          exploitable: result.exploitable || appLogicResult.exploitable,
          confidence: Math.max(result.confidence, appLogicResult.confidence),
          score: Math.max(result.score, appLogicResult.score),
          attackPath: mergedAttackPath,
          recommendations: mergedRecommendations,
          businessLogicFindings: result.businessLogicFindings || appLogicFindings,
          impact: appLogicResult.exploitable && !result.exploitable 
            ? appLogicResult.impact 
            : result.impact,
        };
      }
    }

    // Merge live scan findings into final result if available
    if (liveScanResult && liveScanResult.vulnerabilities.length > 0) {
      console.log(`[LIVE] Merging ${liveScanResult.vulnerabilities.length} live scan findings`);
      
      // Add live scan vulnerabilities to attack path
      const liveAttackSteps = liveScanResult.vulnerabilities.map((v, i) => ({
        id: (finalResult.attackPath?.length || 0) + i + 1,
        title: `[Live Scan] ${v.issue}`,
        phase: "initial_access" as const,
        technique: "network_vulnerability",
        severity: v.severity,
        description: v.issue,
        prerequisites: [`Open port ${v.port} (${v.service || "unknown service"})`],
        artifacts: v.cve ? [{ type: "cve", value: v.cve }] : [],
      }));
      
      // Add live scan recommendations
      const liveRecommendations = liveScanResult.vulnerabilities
        .filter(v => v.recommendation)
        .map(v => `[Live] ${v.recommendation}`);
      
      const existingRecs = new Set(finalResult.recommendations || []);
      const newLiveRecs = liveRecommendations.filter(r => !existingRecs.has(r));
      
      // Update score based on live findings
      const criticalCount = liveScanResult.vulnerabilities.filter(v => v.severity === "critical").length;
      const highCount = liveScanResult.vulnerabilities.filter(v => v.severity === "high").length;
      const liveScoreBoost = Math.min(30, criticalCount * 15 + highCount * 5);
      
      finalResult = {
        ...finalResult,
        exploitable: finalResult.exploitable || criticalCount > 0 || highCount > 0,
        score: Math.min(100, finalResult.score + liveScoreBoost),
        attackPath: [...(finalResult.attackPath || []), ...liveAttackSteps],
        recommendations: [...(finalResult.recommendations || []), ...newLiveRecs],
        evidenceArtifacts: [
          ...(finalResult.evidenceArtifacts || []),
          {
            type: "live_scan" as const,
            name: "Network Scan Results",
            content: `Scanned ${liveScanResult.ip}: ${liveScanResult.ports.length} open ports found`,
            timestamp: liveScanResult.scanCompleted?.toISOString() || new Date().toISOString(),
          },
        ],
      };
    }

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

// AI vs AI Simulation runner
async function runAiSimulation(simulationId: string) {
  try {
    const simulation = await storage.getAiSimulation(simulationId);
    if (!simulation) {
      console.error("Simulation not found:", simulationId);
      return;
    }

    await storage.updateAiSimulation(simulationId, { 
      simulationStatus: "running",
      startedAt: new Date(),
    });
    
    // Simulate AI vs AI battle with realistic delays
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Generate simulation results
    const attackPath = [
      "T1190 - Exploit Public-Facing Application",
      "T1059.001 - PowerShell Execution",
      "T1003.001 - LSASS Memory Dump",
      "T1021.002 - SMB/Windows Admin Shares",
      "T1486 - Data Encrypted for Impact",
    ];
    
    const results = {
      attackerSuccesses: Math.floor(Math.random() * 5) + 1,
      defenderBlocks: Math.floor(Math.random() * 8) + 3,
      timeToDetection: Math.floor(Math.random() * 30) + 5,
      timeToContainment: Math.floor(Math.random() * 60) + 15,
      attackPath,
      detectionPoints: [
        "Network IDS flagged anomalous traffic",
        "EDR detected credential dumping",
        "SIEM correlated lateral movement",
      ],
      missedAttacks: [
        "Initial exploitation went undetected",
        "Persistence mechanism not flagged",
      ],
      recommendations: [
        "Improve web application firewall rules",
        "Enable enhanced PowerShell logging",
        "Deploy deception technology",
        "Implement network segmentation",
      ],
    };
    
    await storage.updateAiSimulation(simulationId, {
      simulationStatus: "completed",
      completedAt: new Date(),
      simulationResults: results,
    });

    // Create Purple Team Findings from simulation results
    const organizationId = simulation.organizationId || "org-default";
    
    // Create findings for each attack technique
    for (const technique of attackPath) {
      const wasDetected = results.detectionPoints.length > 0 && Math.random() > 0.4;
      const controlEffectiveness = wasDetected ? Math.floor(Math.random() * 40) + 50 : Math.floor(Math.random() * 30) + 10;
      
      await storage.createPurpleTeamFinding({
        organizationId,
        findingType: wasDetected ? "detection_success" : "detection_gap",
        offensiveTechnique: technique,
        offensiveDescription: `Attack technique from AI vs AI simulation`,
        detectionStatus: wasDetected ? "detected" : "missed",
        controlEffectiveness,
        defensiveRecommendation: results.recommendations[Math.floor(Math.random() * results.recommendations.length)],
        implementationPriority: controlEffectiveness < 40 ? "critical" : controlEffectiveness < 60 ? "high" : "medium",
        feedbackStatus: "pending",
      });
    }
  } catch (error) {
    console.error("AI simulation failed:", error);
    await storage.updateAiSimulation(simulationId, {
      simulationStatus: "failed",
      completedAt: new Date(),
    });
  }
}

// ========== JOB QUEUE API ROUTES ==========

function registerJobQueueRoutes(app: Express) {
  // Admin auth middleware for job queue routes
  const requireAdminAuth = (req: any, res: any, next: any) => {
    // Check for authenticated session (Replit Auth)
    if (req.isAuthenticated && req.isAuthenticated()) {
      return next();
    }
    // Check for admin password header
    const adminPassword = req.headers["x-admin-password"];
    const expectedAdminPassword = process.env.ADMIN_PASSWORD;
    if (expectedAdminPassword && adminPassword === expectedAdminPassword) {
      return next();
    }
    // Check for admin API key header
    const adminKey = req.headers["x-admin-key"];
    const expectedAdminKey = process.env.ADMIN_API_KEY;
    if (expectedAdminKey && adminKey === expectedAdminKey) {
      return next();
    }
    // In development mode without session, allow access with warning
    if (process.env.NODE_ENV === "development" && !expectedAdminKey && !expectedAdminPassword) {
      console.warn("WARNING: Endpoint accessed without authentication (development mode)");
      return next();
    }
    return res.status(401).json({ error: "Admin authentication required" });
  };

  // Get queue stats
  app.get("/api/jobs/stats", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const stats = await queueService.getQueueStats();
      res.json({
        ...stats,
        usingRedis: queueService.isUsingRedis(),
      });
    } catch (error) {
      console.error("Failed to get queue stats:", error);
      res.status(500).json({ error: "Failed to get queue statistics" });
    }
  });

  // List jobs for tenant
  app.get("/api/jobs", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const status = req.query.status as string | undefined;
      const type = req.query.type as JobType | undefined;
      const limit = parseInt(req.query.limit as string) || 50;
      const offset = parseInt(req.query.offset as string) || 0;

      const jobs = await queueService.getJobsByTenant(tenantId, {
        status: status as any,
        type,
        limit,
        offset,
      });

      res.json({ jobs, total: jobs.length });
    } catch (error) {
      console.error("Failed to list jobs:", error);
      res.status(500).json({ error: "Failed to list jobs" });
    }
  });

  // Get single job
  app.get("/api/jobs/:jobId", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const job = await queueService.getJob(req.params.jobId);
      if (!job) {
        return res.status(404).json({ error: "Job not found" });
      }

      // Verify tenant access
      const tenantId = req.uiUser?.tenantId || "default";
      if (job.tenantId !== tenantId) {
        return res.status(403).json({ error: "Access denied" });
      }

      res.json(job);
    } catch (error) {
      console.error("Failed to get job:", error);
      res.status(500).json({ error: "Failed to get job" });
    }
  });

  // Cancel job
  app.post("/api/jobs/:jobId/cancel", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const job = await queueService.getJob(req.params.jobId);
      if (!job) {
        return res.status(404).json({ error: "Job not found" });
      }

      const tenantId = req.uiUser?.tenantId || "default";
      if (job.tenantId !== tenantId) {
        return res.status(403).json({ error: "Access denied" });
      }

      const success = await queueService.cancelJob(req.params.jobId);
      if (success) {
        res.json({ success: true, message: "Job cancelled" });
      } else {
        res.status(400).json({ error: "Unable to cancel job" });
      }
    } catch (error) {
      console.error("Failed to cancel job:", error);
      res.status(500).json({ error: "Failed to cancel job" });
    }
  });

  // Retry failed job
  app.post("/api/jobs/:jobId/retry", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const job = await queueService.getJob(req.params.jobId);
      if (!job) {
        return res.status(404).json({ error: "Job not found" });
      }

      const tenantId = req.uiUser?.tenantId || "default";
      if (job.tenantId !== tenantId) {
        return res.status(403).json({ error: "Access denied" });
      }

      const success = await queueService.retryJob(req.params.jobId);
      if (success) {
        res.json({ success: true, message: "Job queued for retry" });
      } else {
        res.status(400).json({ error: "Unable to retry job" });
      }
    } catch (error) {
      console.error("Failed to retry job:", error);
      res.status(500).json({ error: "Failed to retry job" });
    }
  });

  // Submit evaluation job via queue
  app.post("/api/jobs/evaluation", uiAuthMiddleware, evaluationRateLimiter, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const organizationId = req.uiUser?.organizationId || "default";
      const userId = req.uiUser?.userId;

      const { assetId, exposureType, priority, description, executionMode } = req.body;

      // Create evaluation record first
      const evaluation = await storage.createEvaluation({
        assetId,
        exposureType,
        priority: priority || "medium",
        description,
        organizationId,
        executionMode: executionMode || "safe",
      });

      // Queue the job
      const jobId = await queueService.addJob("evaluation", {
        type: "evaluation",
        tenantId,
        organizationId,
        userId,
        evaluationId: evaluation.id,
        executionMode: executionMode || "safe",
        assetId,
        exposureData: { exposureType, priority, description },
      });

      res.status(201).json({
        jobId,
        evaluationId: evaluation.id,
        message: "Evaluation job queued successfully",
      });
    } catch (error) {
      console.error("Failed to queue evaluation:", error);
      res.status(500).json({ error: "Failed to queue evaluation job" });
    }
  });

  // Submit network scan job
  app.post("/api/jobs/network-scan", evaluationRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const organizationId = req.uiUser?.organizationId || "default";
      const userId = req.uiUser?.userId;

      const { targets, portRange, scanType } = req.body;

      if (!targets || !Array.isArray(targets) || targets.length === 0) {
        return res.status(400).json({ error: "targets array is required" });
      }

      const scanId = `scan-${randomUUID().slice(0, 8)}`;

      const jobId = await queueService.addJob("network_scan", {
        type: "network_scan",
        tenantId,
        organizationId,
        userId,
        scanId,
        targets,
        portRange,
        scanType,
      });

      res.status(201).json({
        jobId,
        scanId,
        message: "Network scan job queued successfully",
      });
    } catch (error) {
      console.error("Failed to queue network scan:", error);
      res.status(500).json({ error: "Failed to queue network scan job" });
    }
  });

  // Get all scan results for the organization
  app.get("/api/scans", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.uiUser?.organizationId || "default";
      const results = await storage.getLiveScanResults(organizationId);
      res.json(results);
    } catch (error) {
      console.error("Failed to fetch scan results:", error);
      res.status(500).json({ error: "Failed to fetch scan results" });
    }
  });

  // Get scan results by scan ID
  app.get("/api/scans/:scanId", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const { scanId } = req.params;
      const organizationId = req.uiUser?.organizationId || "default";
      const result = await storage.getLiveScanResultByEvaluationId(scanId);
      
      if (!result) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      if (result.organizationId !== organizationId) {
        return res.status(403).json({ error: "Access denied" });
      }
      
      res.json(result);
    } catch (error) {
      console.error("Failed to fetch scan result:", error);
      res.status(500).json({ error: "Failed to fetch scan result" });
    }
  });

  // Submit external recon job
  app.post("/api/jobs/external-recon", evaluationRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const organizationId = req.uiUser?.organizationId || "default";
      const userId = req.uiUser?.userId;

      const { target, modules } = req.body;

      if (!target) {
        return res.status(400).json({ error: "target is required" });
      }

      const reconId = `recon-${randomUUID().slice(0, 8)}`;

      const jobId = await queueService.addJob("external_recon", {
        type: "external_recon",
        tenantId,
        organizationId,
        userId,
        reconId,
        target,
        modules,
      });

      res.status(201).json({
        jobId,
        reconId,
        message: "External recon job queued successfully",
      });
    } catch (error) {
      console.error("Failed to queue external recon:", error);
      res.status(500).json({ error: "Failed to queue external recon job" });
    }
  });

  // Submit web app reconnaissance scan
  app.post("/api/jobs/web-app-recon", evaluationRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const organizationId = req.uiUser?.organizationId || "default";
      const userId = req.uiUser?.userId;

      const { 
        targetUrl, 
        enableParallelAgents = true,
        maxConcurrentAgents = 5,
        vulnerabilityTypes = ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal", "ssrf"],
        enableLLMValidation = true 
      } = req.body;

      if (!targetUrl) {
        return res.status(400).json({ error: "targetUrl is required" });
      }

      // Validate URL format
      try {
        new URL(targetUrl);
      } catch {
        return res.status(400).json({ error: "Invalid URL format" });
      }

      const scanId = `webapp-${randomUUID().slice(0, 8)}`;

      // Create a record for this scan
      await storage.createWebAppReconScan({
        id: scanId,
        targetUrl,
        organizationId,
        tenantId,
        status: "pending",
        enableParallelAgents,
        maxConcurrentAgents,
        vulnerabilityTypes,
        enableLLMValidation,
      });

      // Run the scan in the background
      (async () => {
        try {
          const { runWebAppReconnaissance } = await import("./services/web-app-recon");
          const { dispatchParallelAgents } = await import("./services/parallel-agent-dispatcher");
          
          await storage.updateWebAppReconScan(scanId, { 
            status: "web_recon",
            progress: 5,
            currentPhase: "Crawling target application..."
          });
          
          // Broadcast progress via WebSocket
          wsService.broadcastScanProgress(scanId, "web_recon", 5, "Crawling target application...");
          
          const webAppReconResult = await runWebAppReconnaissance(
            targetUrl,
            (phase, progress, message) => {
              wsService.broadcastScanProgress(scanId, phase, Math.round(5 + progress * 0.35), message);
            }
          );
          
          await storage.updateWebAppReconScan(scanId, {
            status: "web_recon_complete",
            progress: 40,
            currentPhase: "Web reconnaissance complete",
            reconResult: {
              targetUrl: webAppReconResult.targetUrl,
              durationMs: webAppReconResult.durationMs,
              applicationInfo: webAppReconResult.applicationInfo,
              attackSurface: webAppReconResult.attackSurface,
              endpoints: webAppReconResult.endpoints.slice(0, 100),
            },
          });
          
          wsService.broadcastScanProgress(scanId, "web_recon_complete", 40, `Discovered ${webAppReconResult.endpoints.length} endpoints`);
          
          // Run parallel agent dispatch if enabled
          if (enableParallelAgents && webAppReconResult.endpoints.length > 0) {
            await storage.updateWebAppReconScan(scanId, {
              status: "agent_dispatch",
              progress: 45,
              currentPhase: "Dispatching security validation agents..."
            });
            
            wsService.broadcastScanProgress(scanId, "agent_dispatch", 45, "Dispatching security validation agents...");
            
            const agentResult = await dispatchParallelAgents(
              webAppReconResult,
              {
                maxConcurrentAgents,
                enableLLMValidation,
                vulnerabilityTypes,
              },
              (phase, progress, message) => {
                wsService.broadcastScanProgress(scanId, phase, Math.round(45 + progress * 0.50), message);
              }
            );
            
            await storage.updateWebAppReconScan(scanId, {
              status: "completed",
              progress: 100,
              currentPhase: "Scan complete",
              agentDispatchResult: {
                totalTasks: agentResult.totalTasks,
                completedTasks: agentResult.completedTasks,
                failedTasks: agentResult.failedTasks,
                falsePositivesFiltered: agentResult.falsePositivesFiltered,
                executionTimeMs: agentResult.executionTimeMs,
                tasksByVulnerabilityType: agentResult.tasksByVulnerabilityType,
              },
              validatedFindings: agentResult.findings.map(f => ({
                id: f.id,
                endpointUrl: f.endpointUrl,
                endpointPath: f.endpointPath,
                parameter: f.parameter,
                vulnerabilityType: f.vulnerabilityType,
                severity: f.severity,
                confidence: f.confidence,
                verdict: f.verdict,
                evidence: f.evidence,
                recommendations: f.recommendations,
                reproductionSteps: f.reproductionSteps,
                cvssEstimate: f.cvssEstimate,
                mitreAttackId: f.mitreAttackId,
                llmValidation: f.llmValidation,
              })),
            });
            
            wsService.broadcastScanProgress(scanId, "completed", 100, `Found ${agentResult.findings.length} validated vulnerabilities`);
          } else {
            await storage.updateWebAppReconScan(scanId, {
              status: "completed",
              progress: 100,
              currentPhase: "Scan complete (recon only)",
            });
            
            wsService.broadcastScanProgress(scanId, "completed", 100, "Web reconnaissance complete");
          }
          
        } catch (error) {
          console.error("[WebAppRecon] Scan failed:", error);
          await storage.updateWebAppReconScan(scanId, {
            status: "failed",
            progress: 0,
            currentPhase: `Error: ${error instanceof Error ? error.message : "Unknown error"}`,
          });
          wsService.broadcastScanProgress(scanId, "failed", 0, `Scan failed: ${error instanceof Error ? error.message : "Unknown error"}`);
        }
      })();

      res.status(201).json({
        scanId,
        message: "Web app reconnaissance scan started",
      });
    } catch (error) {
      console.error("Failed to start web app recon:", error);
      res.status(500).json({ error: "Failed to start web app reconnaissance" });
    }
  });

  // Get web app recon scan status
  app.get("/api/web-app-recon/:scanId", apiRateLimiter, async (req, res) => {
    try {
      const scan = await storage.getWebAppReconScan(req.params.scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      res.json(scan);
    } catch (error) {
      console.error("Failed to fetch web app recon scan:", error);
      res.status(500).json({ error: "Failed to fetch scan" });
    }
  });

  // Get all web app recon scans
  app.get("/api/web-app-recon", apiRateLimiter, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const scans = await storage.getWebAppReconScans(organizationId);
      res.json(scans);
    } catch (error) {
      console.error("Failed to fetch web app recon scans:", error);
      res.status(500).json({ error: "Failed to fetch scans" });
    }
  });

  // Delete web app recon scan
  app.delete("/api/web-app-recon/:scanId", apiRateLimiter, uiAuthMiddleware, async (req, res) => {
    try {
      await storage.deleteWebAppReconScan(req.params.scanId);
      res.json({ success: true });
    } catch (error) {
      console.error("Failed to delete web app recon scan:", error);
      res.status(500).json({ error: "Failed to delete scan" });
    }
  });

  // Submit report generation job
  app.post("/api/jobs/report", uiAuthMiddleware, reportRateLimiter, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const organizationId = req.uiUser?.organizationId || "default";
      const userId = req.uiUser?.userId;

      const { evaluationIds, format, reportType } = req.body;

      if (!evaluationIds || !Array.isArray(evaluationIds) || evaluationIds.length === 0) {
        return res.status(400).json({ error: "evaluationIds array is required" });
      }

      const reportId = `rpt-${randomUUID().slice(0, 8)}`;

      const jobId = await queueService.addJob("report_generation", {
        type: "report_generation",
        tenantId,
        organizationId,
        userId,
        reportId,
        evaluationIds,
        format,
        reportType,
      });

      res.status(201).json({
        jobId,
        reportId,
        message: "Report generation job queued successfully",
      });
    } catch (error) {
      console.error("Failed to queue report generation:", error);
      res.status(500).json({ error: "Failed to queue report generation job" });
    }
  });

  // Submit AI simulation job
  app.post("/api/jobs/ai-simulation", uiAuthMiddleware, simulationRateLimiter, async (req: UIAuthenticatedRequest, res) => {
    try {
      const tenantId = req.uiUser?.tenantId || "default";
      const organizationId = req.uiUser?.organizationId || "default";
      const userId = req.uiUser?.userId;

      const { scenario, rounds } = req.body;

      if (!scenario) {
        return res.status(400).json({ error: "scenario is required" });
      }

      const simulationId = `sim-${randomUUID().slice(0, 8)}`;

      const jobId = await queueService.addJob("ai_simulation", {
        type: "ai_simulation",
        tenantId,
        organizationId,
        userId,
        simulationId,
        scenario,
        rounds,
      });

      res.status(201).json({
        jobId,
        simulationId,
        message: "AI simulation job queued successfully",
      });
    } catch (error) {
      console.error("Failed to queue AI simulation:", error);
      res.status(500).json({ error: "Failed to queue AI simulation job" });
    }
  });

  // ============================================================================
  // COVERAGE AUTOPILOT ENDPOINTS
  // ============================================================================

  // POST /api/enrollment/token - Create a new enrollment token (60 min expiry)
  app.post("/api/enrollment/token", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = getOrganizationId(req) || "default";
      
      // Generate a cryptographically secure token
      const rawToken = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256").update(rawToken).digest("hex");
      const tokenHint = rawToken.slice(-6);
      
      // Set expiration to 60 minutes from now
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      
      const tokenId = `enroll-${randomUUID().slice(0, 8)}`;
      
      await storage.createEnrollmentToken({
        id: tokenId,
        organizationId,
        tokenHash,
        tokenHint,
        expiresAt,
        revoked: false,
      });
      
      res.status(201).json({
        token: rawToken,
        tokenId,
        tokenHint,
        expiresAt: expiresAt.toISOString(),
        expiresInMinutes: 60,
        message: "Enrollment token created. This token will only be shown once.",
      });
    } catch (error) {
      console.error("Failed to create enrollment token:", error);
      res.status(500).json({ error: "Failed to create enrollment token" });
    }
  });

  // GET /api/enrollment/tokens - List active enrollment tokens (no raw tokens)
  app.get("/api/enrollment/tokens", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = getOrganizationId(req) || "default";
      
      const tokens = await storage.getActiveEnrollmentTokens(organizationId);
      
      res.json({
        tokens: tokens.map(t => ({
          id: t.id,
          tokenHint: t.tokenHint,
          expiresAt: t.expiresAt,
          createdAt: t.createdAt,
          revoked: t.revoked,
        })),
      });
    } catch (error) {
      console.error("Failed to list enrollment tokens:", error);
      res.status(500).json({ error: "Failed to list enrollment tokens" });
    }
  });

  // DELETE /api/enrollment/tokens/:id - Revoke an enrollment token
  app.delete("/api/enrollment/tokens/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const organizationId = getOrganizationId(req) || "default";
      
      await storage.revokeEnrollmentToken(id, organizationId);
      
      res.json({ message: "Token revoked successfully" });
    } catch (error) {
      console.error("Failed to revoke enrollment token:", error);
      res.status(500).json({ error: "Failed to revoke enrollment token" });
    }
  });

  // GET /api/agent-install-command - Generate a ready-to-use install command with fresh token
  // This is the primary endpoint for getting a one-liner to embed in templates
  app.get("/api/agent-install-command", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.uiUser?.organizationId || "default";
      const expiryMinutes = Math.min(Math.max(parseInt(req.query.expiry as string) || 60, 5), 10080); // 5 min to 7 days
      
      // Generate a cryptographically secure token
      const rawToken = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256").update(rawToken).digest("hex");
      const tokenHint = rawToken.slice(-6);
      
      // Set expiration
      const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
      
      const tokenId = `enroll-${randomUUID().slice(0, 8)}`;
      
      await storage.createEnrollmentToken({
        id: tokenId,
        organizationId,
        tokenHash,
        tokenHint,
        expiresAt,
        revoked: false,
      });
      
      // Get server URL using existing helper (enforces HTTPS for production)
      const serverUrl = getServerUrl(req);
      
      // Generate install commands for different platforms
      // Use sudo for Linux since agent requires root installation
      const linuxCommand = `curl -sSL '${serverUrl}/api/agents/install.sh' | sudo bash -s -- --server-url "${serverUrl}" --api-key "${rawToken}"`;
      const windowsCommand = `irm '${serverUrl}/api/agents/install.ps1' | iex; Install-OdinForgeAgent -ServerUrl "${serverUrl}" -ApiKey "${rawToken}"`;
      
      // Cloud user-data scripts (run as root in cloud-init/user-data context)
      // Note: Cloud user-data typically runs as root, but we include explicit bash for clarity
      const cloudInit = `#!/bin/bash
set -e
curl -sSL '${serverUrl}/api/agents/install.sh' | bash -s -- --server-url "${serverUrl}" --api-key "${rawToken}"`;

      const awsUserData = `#!/bin/bash
set -e
curl -sSL '${serverUrl}/api/agents/install.sh' | bash -s -- --server-url "${serverUrl}" --api-key "${rawToken}"`;

      const azureCustomScript = linuxCommand;
      
      const gcpStartupScript = `#!/bin/bash
set -e
curl -sSL '${serverUrl}/api/agents/install.sh' | bash -s -- --server-url "${serverUrl}" --api-key "${rawToken}"`;

      res.json({
        tokenId,
        tokenHint,
        expiresAt: expiresAt.toISOString(),
        expiresInMinutes: expiryMinutes,
        serverUrl,
        commands: {
          linux: linuxCommand,
          windows: windowsCommand,
        },
        cloudTemplates: {
          cloudInit,
          aws: {
            userDataLinux: awsUserData,
            userDataWindows: `<powershell>\n${windowsCommand}\n</powershell>`,
          },
          azure: {
            customScriptLinux: azureCustomScript,
            customScriptWindows: windowsCommand,
          },
          gcp: {
            startupScriptLinux: gcpStartupScript,
            startupScriptWindows: windowsCommand,
          },
        },
        usage: {
          description: "Copy the appropriate command and embed it in your VM template, cloud-init, or deployment script.",
          notes: [
            `Token expires in ${expiryMinutes} minutes`,
            "For longer-lived tokens, use ?expiry=1440 (24 hours) or ?expiry=10080 (7 days)",
            "Each token can be used by multiple agents",
          ],
        },
      });
    } catch (error) {
      console.error("Failed to generate install command:", error);
      res.status(500).json({ error: "Failed to generate install command" });
    }
  });

  // GET /api/bootstrap?token= - Generate bootstrap commands for all platforms
  app.get("/api/bootstrap", apiRateLimiter, async (req, res) => {
    try {
      const { token } = req.query;
      
      if (!token || typeof token !== "string") {
        return res.status(400).json({ error: "Enrollment token is required" });
      }
      
      // Validate the token
      const tokenHash = createHash("sha256").update(token).digest("hex");
      const enrollmentToken = await storage.getEnrollmentTokenByHash(tokenHash);
      
      if (!enrollmentToken) {
        return res.status(401).json({ error: "Invalid enrollment token" });
      }
      
      if (enrollmentToken.revoked) {
        return res.status(401).json({ error: "Enrollment token has been revoked" });
      }
      
      if (new Date(enrollmentToken.expiresAt) < new Date()) {
        return res.status(401).json({ error: "Enrollment token has expired" });
      }
      
      const organizationId = enrollmentToken.organizationId;
      
      // Get server URL from environment or request
      const serverUrl = process.env.PUBLIC_ODINFORGE_URL || 
        `${req.protocol}://${req.get("host")}`;
      const agentImage = process.env.ODINFORGE_AGENT_IMAGE || "ghcr.io/sixsensees/odinforge-agent:latest";
      
      // Generate bootstrap commands
      const bootstrap = {
        host: {
          linux: `curl -sSL '${serverUrl}/api/agents/install.sh' | sudo bash -s -- --server-url "${serverUrl}" --api-key "${token}" --tenant-id "${organizationId}"`,
          windows: `irm '${serverUrl}/api/agents/install.ps1' | iex; Install-OdinForgeAgent -ServerUrl "${serverUrl}" -ApiKey "${token}" -TenantId "${organizationId}"`,
        },
        cloud: {
          aws: {
            userDataLinux: `#!/bin/bash
curl -sSL '${serverUrl}/api/agents/install.sh' | bash -s -- --server-url "${serverUrl}" --api-key "${token}" --tenant-id "${organizationId}"`,
            userDataWindows: `<powershell>
irm '${serverUrl}/api/agents/install.ps1' | iex
Install-OdinForgeAgent -ServerUrl "${serverUrl}" -ApiKey "${token}" -TenantId "${organizationId}"
</powershell>`,
          },
          azure: {
            vmssLinux: `#!/bin/bash
curl -sSL '${serverUrl}/api/agents/install.sh' | bash -s -- --server-url "${serverUrl}" --api-key "${token}" --tenant-id "${organizationId}"`,
            vmssWindows: `irm '${serverUrl}/api/agents/install.ps1' | iex; Install-OdinForgeAgent -ServerUrl "${serverUrl}" -ApiKey "${token}" -TenantId "${organizationId}"`,
          },
          gcp: {
            startupLinux: `#!/bin/bash
curl -sSL '${serverUrl}/api/agents/install.sh' | bash -s -- --server-url "${serverUrl}" --api-key "${token}" --tenant-id "${organizationId}"`,
            startupWindows: `irm '${serverUrl}/api/agents/install.ps1' | iex; Install-OdinForgeAgent -ServerUrl "${serverUrl}" -ApiKey "${token}" -TenantId "${organizationId}"`,
          },
        },
        k8s: {
          apply: `curl -sSL '${serverUrl}/k8s/odinforge-agent-daemonset.yaml' | \\
  sed -e 's|__SERVER_URL__|${serverUrl}|g' \\
      -e 's|__TENANT_ID__|${organizationId}|g' \\
      -e 's|__ENROLL_TOKEN__|${token}|g' \\
      -e 's|__AGENT_IMAGE__|${agentImage}|g' | \\
  kubectl apply -f -`,
          verify: `kubectl -n odinforge get ds odinforge-agent && kubectl -n odinforge rollout status ds/odinforge-agent --timeout=120s && kubectl -n odinforge get pods -o wide`,
        },
      };
      
      res.json(bootstrap);
    } catch (error) {
      console.error("Failed to generate bootstrap commands:", error);
      res.status(500).json({ error: "Failed to generate bootstrap commands" });
    }
  });

  // POST /api/inventory/assets - Ingest discovered assets
  app.post("/api/inventory/assets", batchRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = getOrganizationId(req) || "default";
      const { provider, assets } = req.body;
      
      if (!provider || !["aws", "azure", "gcp", "k8s"].includes(provider)) {
        return res.status(400).json({ error: "Invalid provider. Must be aws, azure, gcp, or k8s" });
      }
      
      if (!assets || !Array.isArray(assets)) {
        return res.status(400).json({ error: "assets array is required" });
      }
      
      let imported = 0;
      let updated = 0;
      
      for (const asset of assets) {
        const result = await storage.upsertCloudAsset({
          organizationId,
          provider,
          assetType: asset.assetType || "vm",
          assetName: asset.name || asset.assetName,
          region: asset.region,
          providerResourceId: asset.externalId || asset.id || `${provider}-${randomUUID().slice(0, 8)}`,
          rawMetadata: asset.metadata || asset,
          lastSeenAt: new Date(),
        });
        
        if (result.isNew) {
          imported++;
        } else {
          updated++;
        }
      }
      
      res.status(200).json({
        message: "Assets ingested successfully",
        imported,
        updated,
        total: assets.length,
      });
    } catch (error) {
      console.error("Failed to ingest assets:", error);
      res.status(500).json({ error: "Failed to ingest assets" });
    }
  });

  // GET /api/coverage - Get coverage statistics
  app.get("/api/coverage", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = getOrganizationId(req) || "default";
      
      const coverage = await storage.getCoverageStats(organizationId);
      
      res.json(coverage);
    } catch (error) {
      console.error("Failed to get coverage stats:", error);
      res.status(500).json({ error: "Failed to get coverage statistics" });
    }
  });

  // ============================================================================
  // API DEFINITIONS (OpenAPI/Swagger)
  // ============================================================================

  // POST /api/api-definitions - Upload and parse OpenAPI/Swagger spec
  app.post("/api/api-definitions", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = getOrganizationId(req) || "default";
      const tenantId = req.headers["x-tenant-id"] as string || "default";
      const { spec, specUrl, name } = req.body;

      if (!spec && !specUrl) {
        return res.status(400).json({ error: "Either 'spec' (raw content) or 'specUrl' is required" });
      }

      const { openAPIParserService } = await import("./services/openapi-parser");
      
      let parsed;
      if (specUrl) {
        parsed = await openAPIParserService.parseFromUrl(specUrl, organizationId, tenantId);
      } else {
        parsed = await openAPIParserService.parseSpec(spec, organizationId, tenantId);
      }

      if (name) {
        parsed.definition.name = name;
      }

      const definition = await storage.createApiDefinition(parsed.definition);
      
      const endpointsWithDefId = parsed.endpoints.map(ep => ({
        ...ep,
        apiDefinitionId: definition.id,
      }));
      const endpoints = await storage.createApiEndpoints(endpointsWithDefId);

      res.status(201).json({
        definition,
        endpoints,
        summary: {
          totalPaths: definition.totalEndpoints,
          totalOperations: endpoints.length,
          byPriority: {
            critical: endpoints.filter(e => e.priority === "critical").length,
            high: endpoints.filter(e => e.priority === "high").length,
            medium: endpoints.filter(e => e.priority === "medium").length,
            low: endpoints.filter(e => e.priority === "low").length,
          },
        },
      });
    } catch (error: any) {
      console.error("Failed to parse OpenAPI spec:", error);
      res.status(400).json({ 
        error: "Failed to parse OpenAPI spec", 
        details: error.message 
      });
    }
  });

  // GET /api/api-definitions - List API definitions
  app.get("/api/api-definitions", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = getOrganizationId(req) || "default";
      const definitions = await storage.getApiDefinitions(organizationId);
      res.json(definitions);
    } catch (error) {
      console.error("Failed to get API definitions:", error);
      res.status(500).json({ error: "Failed to get API definitions" });
    }
  });

  // GET /api/api-definitions/:id - Get API definition with endpoints
  app.get("/api/api-definitions/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const definition = await storage.getApiDefinition(id);
      
      if (!definition) {
        return res.status(404).json({ error: "API definition not found" });
      }

      const endpoints = await storage.getApiEndpoints(id);
      
      res.json({ definition, endpoints });
    } catch (error) {
      console.error("Failed to get API definition:", error);
      res.status(500).json({ error: "Failed to get API definition" });
    }
  });

  // DELETE /api/api-definitions/:id - Delete API definition
  app.delete("/api/api-definitions/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const definition = await storage.getApiDefinition(id);
      
      if (!definition) {
        return res.status(404).json({ error: "API definition not found" });
      }

      await storage.deleteApiDefinition(id);
      res.json({ success: true, message: "API definition deleted" });
    } catch (error) {
      console.error("Failed to delete API definition:", error);
      res.status(500).json({ error: "Failed to delete API definition" });
    }
  });

  // GET /api/api-definitions/:id/endpoints - Get endpoints for definition
  app.get("/api/api-definitions/:id/endpoints", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const { priority, method } = req.query;
      
      let endpoints = await storage.getApiEndpoints(id);
      
      if (priority) {
        endpoints = endpoints.filter(e => e.priority === priority);
      }
      if (method) {
        endpoints = endpoints.filter(e => e.method === (method as string).toUpperCase());
      }
      
      res.json(endpoints);
    } catch (error) {
      console.error("Failed to get API endpoints:", error);
      res.status(500).json({ error: "Failed to get API endpoints" });
    }
  });

  // POST /api/api-definitions/:id/scan - Trigger web app scan using API definition endpoints
  app.post("/api/api-definitions/:id/scan", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const organizationId = getOrganizationId(req) || "default";
      const tenantId = req.headers["x-tenant-id"] as string || "default";
      const { 
        priority, 
        vulnerabilityTypes = ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal", "ssrf"],
        maxConcurrentAgents = 5,
        enableLLMValidation = true
      } = req.body;

      const definition = await storage.getApiDefinition(id);
      if (!definition) {
        return res.status(404).json({ error: "API definition not found" });
      }

      let endpoints = await storage.getApiEndpoints(id);
      
      if (priority && priority !== "all") {
        const priorityOrder = ["critical", "high", "medium", "low"];
        const maxPriorityIndex = priorityOrder.indexOf(priority);
        endpoints = endpoints.filter(e => 
          priorityOrder.indexOf(e.priority || "low") <= maxPriorityIndex
        );
      }

      if (endpoints.length === 0) {
        return res.status(400).json({ error: "No endpoints match the filter criteria" });
      }

      const targetUrl = definition.baseUrl || definition.servers?.[0]?.url;
      if (!targetUrl) {
        return res.status(400).json({ error: "No base URL found in API definition" });
      }

      const scanId = `api-scan-${randomUUID().slice(0, 8)}`;

      // Create a web app recon scan record
      await storage.createWebAppReconScan({
        id: scanId,
        targetUrl,
        organizationId,
        tenantId,
        status: "pending",
        enableParallelAgents: true,
        maxConcurrentAgents,
        vulnerabilityTypes,
        enableLLMValidation,
      });

      await storage.updateApiDefinition(id, { lastScannedAt: new Date() });

      // Convert API endpoints to the format expected by parallel agent dispatcher
      // Normalize URL to handle trailing/leading slash mismatches
      const normalizedBaseUrl = targetUrl.replace(/\/+$/, "");
      const convertedEndpoints = endpoints.map(ep => {
        const normalizedPath = ep.path.startsWith("/") ? ep.path : `/${ep.path}`;
        return {
        url: `${normalizedBaseUrl}${normalizedPath}`,
        method: ep.method,
        path: ep.path,
        type: ep.requestBody ? "api-mutation" : "api",
        priority: ep.priority === "critical" ? "high" : ep.priority || "medium",
        parameters: (ep.parameters || []).map(p => ({
          name: p.name,
          location: p.in,
          vulnerabilityPotential: ep.vulnerabilityPotential || {},
        })),
        // Include request body info for better scanning
        hasRequestBody: !!ep.requestBody,
        requestBodyContentTypes: ep.requestBody?.contentTypes || [],
      };
      });

      // Run the scan in background
      (async () => {
        try {
          const { dispatchParallelAgents } = await import("./services/parallel-agent-dispatcher");
          
          await storage.updateWebAppReconScan(scanId, { 
            status: "agent_dispatch",
            progress: 40,
            currentPhase: "Dispatching validation agents to API endpoints..."
          });
          
          wsService.broadcastScanProgress(scanId, "agent_dispatch", 40, `Scanning ${endpoints.length} API endpoints...`);

          // Create a mock recon result to pass to the dispatcher
          const mockReconResult = {
            targetUrl,
            scanStarted: new Date(),
            scanCompleted: new Date(),
            durationMs: 0,
            applicationInfo: {
              title: definition.name,
              technologies: [],
              frameworks: [],
              securityHeaders: {},
              missingSecurityHeaders: [],
            },
            endpoints: convertedEndpoints,
            forms: [],
            attackSurface: {
              totalEndpoints: endpoints.length,
              highPriorityEndpoints: endpoints.filter(e => e.priority === "critical" || e.priority === "high").length,
              inputParameters: endpoints.reduce((sum, e) => sum + (e.parameters?.length || 0), 0),
              apiEndpoints: endpoints.length,
              authenticationPoints: endpoints.filter(e => /auth|login|token/i.test(e.path)).length,
              fileUploadPoints: endpoints.filter(e => e.requestBody?.contentTypes?.includes("multipart/form-data")).length,
            },
            securityObservations: [],
            recommendedTestOrder: [],
          };

          const dispatchResult = await dispatchParallelAgents(
            mockReconResult as any,
            {
              maxConcurrent: maxConcurrentAgents,
              vulnerabilityTypes: vulnerabilityTypes,
              enableLLMValidation,
            },
            (phase, progress, message) => {
              const adjustedProgress = Math.round(40 + progress * 0.55);
              wsService.broadcastScanProgress(scanId, phase, adjustedProgress, message);
            }
          );

          // Update endpoint scan statuses and findings counts
          for (const endpoint of endpoints) {
            const relatedFindings = dispatchResult.findings.filter(f => 
              f.endpoint?.includes(endpoint.path)
            );
            await storage.updateApiEndpoint(endpoint.id, {
              scanStatus: "completed",
              lastScannedAt: new Date(),
              findingsCount: relatedFindings.length,
            });
          }

          await storage.updateWebAppReconScan(scanId, {
            status: "completed",
            progress: 100,
            currentPhase: "Scan complete",
            agentDispatchResult: {
              totalTasks: dispatchResult.totalTasks,
              completedTasks: dispatchResult.completedTasks,
              failedTasks: dispatchResult.failedTasks,
              findingsCount: dispatchResult.findings.length,
              falsePositivesFiltered: dispatchResult.falsePositivesFiltered,
              executionTimeMs: dispatchResult.executionTimeMs,
            },
            validatedFindings: dispatchResult.findings,
          });

          wsService.broadcastScanProgress(scanId, "completed", 100, 
            `Found ${dispatchResult.findings.length} validated vulnerabilities`);

        } catch (scanError) {
          console.error(`[API Scan ${scanId}] Error:`, scanError);
          await storage.updateWebAppReconScan(scanId, {
            status: "failed",
            currentPhase: `Error: ${scanError instanceof Error ? scanError.message : "Unknown error"}`,
          });
          wsService.broadcastScanProgress(scanId, "failed", 0, "Scan failed");
        }
      })();

      res.status(202).json({
        scanId,
        message: "API definition scan started",
        targetUrl,
        endpointsToScan: endpoints.length,
        configuration: {
          priority: priority || "all",
          vulnerabilityTypes,
          maxConcurrentAgents,
          enableLLMValidation,
        },
      });
    } catch (error) {
      console.error("Failed to trigger API definition scan:", error);
      res.status(500).json({ error: "Failed to trigger scan" });
    }
  });

  // ============================================================================
  // SECURITY PROBES
  // ============================================================================

  // POST /api/probes/credentials - Run credential probe against a target
  app.post("/api/probes/credentials", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { target, services } = req.body;

      if (!target) {
        return res.status(400).json({ error: "target is required" });
      }

      const { runCredentialProbe, generateCredentialReport } = await import("./services/probes/credential-probe");
      
      const result = await runCredentialProbe(target, services);
      
      res.json({
        ...result,
        report: generateCredentialReport(result),
      });
    } catch (error) {
      console.error("Failed to run credential probe:", error);
      res.status(500).json({ error: "Failed to run credential probe" });
    }
  });

  // POST /api/probes/ldap - Run LDAP injection probe against a target
  app.post("/api/probes/ldap", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { target, port = 389, baseDn, testUser } = req.body;

      if (!target) {
        return res.status(400).json({ error: "target is required" });
      }

      const { runLdapProbe } = await import("./services/probes/ldap-probe");
      
      const result = await runLdapProbe(target, port, baseDn, testUser);
      
      res.json(result);
    } catch (error) {
      console.error("Failed to run LDAP probe:", error);
      res.status(500).json({ error: "Failed to run LDAP probe" });
    }
  });

  // POST /api/probes/smtp-relay - Run SMTP open relay probe against a target
  app.post("/api/probes/smtp-relay", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { target, port = 25, testEmail } = req.body;

      if (!target) {
        return res.status(400).json({ error: "target is required" });
      }

      const { runSmtpRelayProbe } = await import("./services/probes/smtp-relay-probe");
      
      const result = await runSmtpRelayProbe(target, port, testEmail);
      
      res.json(result);
    } catch (error) {
      console.error("Failed to run SMTP relay probe:", error);
      res.status(500).json({ error: "Failed to run SMTP relay probe" });
    }
  });

  // ============================================================================
  // COMPLIANCE MAPPING
  // ============================================================================

  // GET /api/compliance/frameworks - List available compliance frameworks
  app.get("/api/compliance/frameworks", apiRateLimiter, async (req, res) => {
    try {
      const { complianceService } = await import("./services/compliance-mapping");
      res.json({
        frameworks: complianceService.frameworks.map(f => ({
          id: f,
          name: {
            soc2: "SOC 2",
            iso27001: "ISO 27001:2022",
            nist_csf: "NIST Cybersecurity Framework",
            pci_dss: "PCI DSS v4.0",
          }[f],
          controlCount: complianceService.getAllControls(f).length,
        })),
      });
    } catch (error) {
      console.error("Failed to get compliance frameworks:", error);
      res.status(500).json({ error: "Failed to get compliance frameworks" });
    }
  });

  // GET /api/compliance/controls/:framework - Get controls for a framework
  app.get("/api/compliance/controls/:framework", apiRateLimiter, async (req, res) => {
    try {
      const { framework } = req.params;
      const { complianceService } = await import("./services/compliance-mapping");
      
      if (!complianceService.frameworks.includes(framework as any)) {
        return res.status(400).json({ 
          error: "Invalid framework",
          validFrameworks: complianceService.frameworks,
        });
      }
      
      const controls = complianceService.getAllControls(framework as any);
      res.json({ framework, controls });
    } catch (error) {
      console.error("Failed to get compliance controls:", error);
      res.status(500).json({ error: "Failed to get compliance controls" });
    }
  });

  // POST /api/compliance/map-finding - Map a finding type to compliance controls
  app.post("/api/compliance/map-finding", apiRateLimiter, async (req, res) => {
    try {
      const { findingType } = req.body;
      
      if (!findingType) {
        return res.status(400).json({ error: "findingType is required" });
      }
      
      const { complianceService } = await import("./services/compliance-mapping");
      const mapping = complianceService.mapFindingToControls(findingType);
      
      res.json(mapping);
    } catch (error) {
      console.error("Failed to map finding:", error);
      res.status(500).json({ error: "Failed to map finding to controls" });
    }
  });

  // POST /api/compliance/gap-report - Generate compliance gap report from findings
  app.post("/api/compliance/gap-report", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { framework, findings } = req.body;
      
      if (!framework) {
        return res.status(400).json({ error: "framework is required" });
      }
      
      const { complianceService } = await import("./services/compliance-mapping");
      
      if (!complianceService.frameworks.includes(framework)) {
        return res.status(400).json({ 
          error: "Invalid framework",
          validFrameworks: complianceService.frameworks,
        });
      }

      const report = complianceService.generateComplianceGapReport(framework, findings || []);
      const markdown = complianceService.generateComplianceReportMarkdown(report);
      
      res.json({
        ...report,
        markdownReport: markdown,
      });
    } catch (error) {
      console.error("Failed to generate compliance report:", error);
      res.status(500).json({ error: "Failed to generate compliance report" });
    }
  });

  // GET /api/compliance/scan-report/:scanId - Generate compliance report from a scan's findings
  app.get("/api/compliance/scan-report/:scanId", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { scanId } = req.params;
      const { framework = "soc2" } = req.query;
      
      const scan = await storage.getWebAppReconScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      const { complianceService } = await import("./services/compliance-mapping");
      
      if (!complianceService.frameworks.includes(framework as any)) {
        return res.status(400).json({ 
          error: "Invalid framework",
          validFrameworks: complianceService.frameworks,
        });
      }

      const findings = (scan.validatedFindings || []).map((f: any) => ({
        type: f.vulnerability || f.type || "unknown",
        severity: f.severity || "medium",
        title: f.title || f.description || "Finding",
        evidence: f.evidence,
      }));

      const report = complianceService.generateComplianceGapReport(framework as any, findings);
      const markdown = complianceService.generateComplianceReportMarkdown(report);
      
      res.json({
        scanId,
        targetUrl: scan.targetUrl,
        scanCompletedAt: scan.updatedAt,
        ...report,
        markdownReport: markdown,
      });
    } catch (error) {
      console.error("Failed to generate scan compliance report:", error);
      res.status(500).json({ error: "Failed to generate compliance report" });
    }
  });

  // ========================================
  // API Fuzzing Routes
  // ========================================

  // POST /api/fuzz/generate - Generate fuzz test cases for an endpoint
  app.post("/api/fuzz/generate", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { endpoint } = req.body;

      if (!endpoint || !endpoint.path || !endpoint.method) {
        return res.status(400).json({ error: "Endpoint path and method are required" });
      }

      const { apiFuzzingEngine } = await import("./services/api-fuzzer");
      const testCases = apiFuzzingEngine.generateTestCasesFromOpenAPIEndpoint(endpoint);

      res.json({
        endpointPath: endpoint.path,
        method: endpoint.method,
        totalTestCases: testCases.length,
        testCases: testCases.slice(0, 100),
        categories: apiFuzzingEngine.getPayloadCategories(),
      });
    } catch (error) {
      console.error("Failed to generate fuzz test cases:", error);
      res.status(500).json({ error: "Failed to generate fuzz test cases" });
    }
  });

  // POST /api/fuzz/execute - Execute fuzz test cases against a target
  app.post("/api/fuzz/execute", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { 
        endpoint,
        targetBaseUrl,
        config = {},
      } = req.body;

      if (!endpoint || !targetBaseUrl) {
        return res.status(400).json({ error: "Endpoint and targetBaseUrl are required" });
      }

      const { apiFuzzingEngine, fuzzingExecutor } = await import("./services/api-fuzzer");
      const testCases = apiFuzzingEngine.generateTestCasesFromOpenAPIEndpoint(endpoint);

      const executionConfig = {
        targetBaseUrl,
        concurrency: config.concurrency || 3,
        timeoutMs: config.timeoutMs || 10000,
        delayBetweenRequests: config.delayBetweenRequests || 100,
        headers: config.headers,
        authentication: config.authentication,
        stopOnCritical: config.stopOnCritical || false,
        maxTestCases: config.maxTestCases || 50,
      };

      const result = await fuzzingExecutor.executeTestCases(testCases, executionConfig);
      const report = fuzzingExecutor.generateReport(result);

      res.json({
        ...result,
        markdownReport: report,
      });
    } catch (error) {
      console.error("Failed to execute fuzz tests:", error);
      res.status(500).json({ error: "Failed to execute fuzz tests" });
    }
  });

  // POST /api/fuzz/api-definition/:id - Fuzz all endpoints from an API definition
  app.post("/api/fuzz/api-definition/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const { targetBaseUrl, config = {} } = req.body;

      const apiDef = await storage.getApiDefinition(id);
      if (!apiDef) {
        return res.status(404).json({ error: "API definition not found" });
      }

      const endpoints = await storage.getApiEndpointsByDefinition(id);
      if (!endpoints || endpoints.length === 0) {
        return res.status(404).json({ error: "No endpoints found for this API definition" });
      }

      const baseUrl = targetBaseUrl || apiDef.baseUrl;
      if (!baseUrl) {
        return res.status(400).json({ error: "Target base URL is required" });
      }

      const { apiFuzzingEngine, fuzzingExecutor } = await import("./services/api-fuzzer");
      
      const allTestCases = endpoints.flatMap(ep => 
        apiFuzzingEngine.generateTestCasesFromOpenAPIEndpoint({
          path: ep.path,
          method: ep.method,
          parameters: ep.parameters as any[],
          requestBody: ep.requestBody as any,
        })
      );

      const priorityTestCases = config.onlyCritical 
        ? apiFuzzingEngine.filterTestCasesByRisk(allTestCases, "high")
        : allTestCases;

      const executionConfig = {
        targetBaseUrl: baseUrl,
        concurrency: config.concurrency || 3,
        timeoutMs: config.timeoutMs || 10000,
        delayBetweenRequests: config.delayBetweenRequests || 100,
        headers: config.headers,
        authentication: config.authentication,
        stopOnCritical: config.stopOnCritical || false,
        maxTestCases: config.maxTestCases || 200,
      };

      const result = await fuzzingExecutor.executeTestCases(priorityTestCases, executionConfig);
      const report = fuzzingExecutor.generateReport(result);

      res.json({
        apiDefinitionId: id,
        apiName: apiDef.name,
        endpointCount: endpoints.length,
        ...result,
        markdownReport: report,
      });
    } catch (error) {
      console.error("Failed to fuzz API definition:", error);
      res.status(500).json({ error: "Failed to fuzz API definition" });
    }
  });

  // POST /api/fuzz/validate-response - Validate a response against expected schema
  app.post("/api/fuzz/validate-response", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { responseBody, statusCode, responseHeaders, responseTimeMs, expected } = req.body;

      if (responseBody === undefined || statusCode === undefined) {
        return res.status(400).json({ error: "responseBody and statusCode are required" });
      }

      const { responseValidator } = await import("./services/api-fuzzer");
      const result = responseValidator.validate(
        typeof responseBody === "string" ? responseBody : JSON.stringify(responseBody),
        statusCode,
        responseHeaders || {},
        responseTimeMs || 0,
        expected || {}
      );

      res.json(result);
    } catch (error) {
      console.error("Failed to validate response:", error);
      res.status(500).json({ error: "Failed to validate response" });
    }
  });

  // POST /api/fuzz/infer-schema - Infer JSON schema from a sample response
  app.post("/api/fuzz/infer-schema", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sampleResponse } = req.body;

      if (sampleResponse === undefined) {
        return res.status(400).json({ error: "sampleResponse is required" });
      }

      const { responseValidator } = await import("./services/api-fuzzer");
      const schema = responseValidator.createSchemaFromSample(sampleResponse);

      res.json({ schema });
    } catch (error) {
      console.error("Failed to infer schema:", error);
      res.status(500).json({ error: "Failed to infer schema" });
    }
  });

  // GET /api/fuzz/categories - Get available fuzzing categories
  app.get("/api/fuzz/categories", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { apiFuzzingEngine } = await import("./services/api-fuzzer");
      res.json({
        categories: apiFuzzingEngine.getPayloadCategories(),
        formats: apiFuzzingEngine.getSupportedFormats(),
      });
    } catch (error) {
      console.error("Failed to get fuzz categories:", error);
      res.status(500).json({ error: "Failed to get fuzz categories" });
    }
  });

  // ========================================
  // OAuth/SAML Security Testing Routes
  // ========================================

  // POST /api/auth-test/jwt/analyze - Analyze a JWT token
  app.post("/api/auth-test/jwt/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({ error: "Token is required" });
      }

      const { oauthTokenTester } = await import("./services/auth-testing");
      const analysis = await oauthTokenTester.analyzeToken(token);

      res.json(analysis);
    } catch (error: any) {
      console.error("Failed to analyze JWT:", error);
      res.status(500).json({ error: error.message || "Failed to analyze JWT" });
    }
  });

  // POST /api/auth-test/jwt/test - Run JWT security tests
  app.post("/api/auth-test/jwt/test", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { targetUrl, token, headers, testTypes, timeoutMs } = req.body;

      if (!targetUrl || !token) {
        return res.status(400).json({ error: "targetUrl and token are required" });
      }

      const { oauthTokenTester } = await import("./services/auth-testing");
      const results = await oauthTokenTester.runAllTests({
        targetUrl,
        token,
        headers,
        testTypes,
        timeoutMs,
      });

      const report = oauthTokenTester.generateReport(results);

      res.json({
        totalTests: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        criticalFindings: results.filter(r => !r.passed && r.severity === "critical").length,
        highFindings: results.filter(r => !r.passed && r.severity === "high").length,
        results,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to run JWT tests:", error);
      res.status(500).json({ error: error.message || "Failed to run JWT tests" });
    }
  });

  // POST /api/auth-test/oauth/redirect - Test OAuth redirect URI validation
  app.post("/api/auth-test/oauth/redirect", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { 
        authorizationEndpoint, 
        clientId, 
        originalRedirectUri,
        state,
        scope,
        responseType,
        additionalParams,
        timeoutMs,
        testTypes,
      } = req.body;

      if (!authorizationEndpoint || !clientId || !originalRedirectUri) {
        return res.status(400).json({ 
          error: "authorizationEndpoint, clientId, and originalRedirectUri are required" 
        });
      }

      const { oauthRedirectTester } = await import("./services/auth-testing");
      const results = await oauthRedirectTester.runAllTests({
        authorizationEndpoint,
        clientId,
        originalRedirectUri,
        state,
        scope,
        responseType,
        additionalParams,
        timeoutMs,
        testTypes,
      });

      const report = oauthRedirectTester.generateReport(results);

      res.json({
        totalTests: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        criticalFindings: results.filter(r => !r.passed && r.severity === "critical").length,
        highFindings: results.filter(r => !r.passed && r.severity === "high").length,
        results,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to run OAuth redirect tests:", error);
      res.status(500).json({ error: error.message || "Failed to run OAuth redirect tests" });
    }
  });

  // POST /api/auth-test/saml/analyze - Analyze a SAML assertion
  app.post("/api/auth-test/saml/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { assertion } = req.body;

      if (!assertion) {
        return res.status(400).json({ error: "SAML assertion is required" });
      }

      const { samlTester } = await import("./services/auth-testing");
      const analysis = await samlTester.parseAssertion(assertion);

      res.json(analysis);
    } catch (error: any) {
      console.error("Failed to analyze SAML:", error);
      res.status(500).json({ error: error.message || "Failed to analyze SAML" });
    }
  });

  // POST /api/auth-test/saml/test - Run SAML security tests
  app.post("/api/auth-test/saml/test", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { acsUrl, originalAssertion, relayState, headers, timeoutMs, testTypes } = req.body;

      if (!acsUrl || !originalAssertion) {
        return res.status(400).json({ error: "acsUrl and originalAssertion are required" });
      }

      const { samlTester } = await import("./services/auth-testing");
      const results = await samlTester.runAllTests({
        acsUrl,
        originalAssertion,
        relayState,
        headers,
        timeoutMs,
        testTypes,
      });

      const report = samlTester.generateReport(results);

      res.json({
        totalTests: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        criticalFindings: results.filter(r => !r.passed && r.severity === "critical").length,
        highFindings: results.filter(r => !r.passed && r.severity === "high").length,
        results,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to run SAML tests:", error);
      res.status(500).json({ error: error.message || "Failed to run SAML tests" });
    }
  });

  // ========================================
  // Container/K8s Security Scanning Routes
  // ========================================

  // POST /api/container-security/scan-manifest - Scan a single K8s manifest
  app.post("/api/container-security/scan-manifest", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { manifest } = req.body;

      if (!manifest) {
        return res.status(400).json({ error: "K8s manifest is required" });
      }

      const { containerSecurityScanner } = await import("./services/container-security");
      const findings = containerSecurityScanner.scanManifest(manifest);
      const report = containerSecurityScanner.generateReport(findings);

      res.json({
        totalFindings: findings.length,
        criticalFindings: findings.filter(f => f.severity === "critical").length,
        highFindings: findings.filter(f => f.severity === "high").length,
        mediumFindings: findings.filter(f => f.severity === "medium").length,
        lowFindings: findings.filter(f => f.severity === "low").length,
        findings,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to scan manifest:", error);
      res.status(500).json({ error: error.message || "Failed to scan manifest" });
    }
  });

  // POST /api/container-security/scan-manifests - Scan multiple K8s manifests (YAML/JSON)
  app.post("/api/container-security/scan-manifests", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { content } = req.body;

      if (!content) {
        return res.status(400).json({ error: "K8s manifest content is required" });
      }

      const { k8sManifestAnalyzer } = await import("./services/container-security");
      const manifests = k8sManifestAnalyzer.parseManifests(content);
      
      if (manifests.length === 0) {
        return res.status(400).json({ error: "No valid K8s manifests found in content" });
      }

      const result = k8sManifestAnalyzer.analyzeManifests(manifests);
      const report = k8sManifestAnalyzer.generateReport(result);

      res.json({
        ...result,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to scan manifests:", error);
      res.status(500).json({ error: error.message || "Failed to scan manifests" });
    }
  });

  // POST /api/container-security/scan-dockerfile - Scan a Dockerfile for security issues
  app.post("/api/container-security/scan-dockerfile", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { content, imageName } = req.body;

      if (!content) {
        return res.status(400).json({ error: "Dockerfile content is required" });
      }

      const { containerSecurityScanner } = await import("./services/container-security");
      const findings = containerSecurityScanner.scanDockerfile(content, imageName || "dockerfile");
      const report = containerSecurityScanner.generateReport(findings);

      res.json({
        imageName: imageName || "dockerfile",
        totalFindings: findings.length,
        criticalFindings: findings.filter(f => f.severity === "critical").length,
        highFindings: findings.filter(f => f.severity === "high").length,
        mediumFindings: findings.filter(f => f.severity === "medium").length,
        lowFindings: findings.filter(f => f.severity === "low").length,
        findings,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to scan Dockerfile:", error);
      res.status(500).json({ error: error.message || "Failed to scan Dockerfile" });
    }
  });

  // POST /api/container-security/scan-pod-spec - Scan a pod spec directly
  app.post("/api/container-security/scan-pod-spec", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { podSpec, resourceName, namespace, resourceType } = req.body;

      if (!podSpec) {
        return res.status(400).json({ error: "Pod spec is required" });
      }

      const { containerSecurityScanner } = await import("./services/container-security");
      const findings = containerSecurityScanner.scanPodSpec(
        podSpec,
        resourceName || "unknown",
        namespace || "default",
        resourceType || "pod"
      );
      const report = containerSecurityScanner.generateReport(findings);

      res.json({
        resourceName: resourceName || "unknown",
        namespace: namespace || "default",
        totalFindings: findings.length,
        criticalFindings: findings.filter(f => f.severity === "critical").length,
        highFindings: findings.filter(f => f.severity === "high").length,
        findings,
        markdownReport: report,
      });
    } catch (error: any) {
      console.error("Failed to scan pod spec:", error);
      res.status(500).json({ error: error.message || "Failed to scan pod spec" });
    }
  });

  // ============================================================================
  // PHASE 3: EXPLOIT EXECUTION SANDBOX API
  // ============================================================================

  // POST /api/sandbox/sessions - Create a new sandbox session
  app.post("/api/sandbox/sessions", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { name, description, targetUrl, targetHost, executionMode, resourceLimits } = req.body;

      if (!name) {
        return res.status(400).json({ error: "Session name is required" });
      }

      const { sandboxSessionManager } = await import("./services/sandbox");
      const { session, id } = await sandboxSessionManager.createSession({
        name,
        description,
        targetUrl,
        targetHost,
        executionMode: executionMode || "safe",
        resourceLimits,
      });

      res.json({ session, id });
    } catch (error: any) {
      console.error("Failed to create sandbox session:", error);
      res.status(500).json({ error: error.message || "Failed to create sandbox session" });
    }
  });

  // GET /api/sandbox/sessions - List all sandbox sessions
  app.get("/api/sandbox/sessions", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const sessions = await sandboxSessionManager.listSessions();
      res.json({ sessions });
    } catch (error: any) {
      console.error("Failed to list sandbox sessions:", error);
      res.status(500).json({ error: error.message || "Failed to list sandbox sessions" });
    }
  });

  // GET /api/sandbox/sessions/:id - Get a specific sandbox session
  app.get("/api/sandbox/sessions/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const session = await sandboxSessionManager.getSession(req.params.id);
      if (!session) {
        return res.status(404).json({ error: "Session not found" });
      }
      res.json({ session });
    } catch (error: any) {
      console.error("Failed to get sandbox session:", error);
      res.status(500).json({ error: error.message || "Failed to get sandbox session" });
    }
  });

  // POST /api/sandbox/sessions/:id/execute - Execute a payload in the sandbox
  app.post("/api/sandbox/sessions/:id/execute", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { payloadName, payloadCategory, payloadContent, targetEndpoint, targetMethod, mitreAttackId, mitreTactic } = req.body;

      if (!payloadContent || !targetEndpoint) {
        return res.status(400).json({ error: "Payload content and target endpoint are required" });
      }

      const { sandboxSessionManager } = await import("./services/sandbox");
      const result = await sandboxSessionManager.executePayload(req.params.id, {
        payloadName: payloadName || "Custom Payload",
        payloadCategory: payloadCategory || "custom",
        payloadContent,
        targetEndpoint,
        targetMethod: targetMethod || "POST",
        mitreAttackId,
        mitreTactic,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to execute payload:", error);
      res.status(500).json({ error: error.message || "Failed to execute payload" });
    }
  });

  // POST /api/sandbox/sessions/:id/snapshots - Create a snapshot
  app.post("/api/sandbox/sessions/:id/snapshots", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { name, description } = req.body;

      if (!name) {
        return res.status(400).json({ error: "Snapshot name is required" });
      }

      const { sandboxSessionManager } = await import("./services/sandbox");
      const snapshot = await sandboxSessionManager.createSnapshot(req.params.id, name, description);
      
      if (!snapshot) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json({ snapshot });
    } catch (error: any) {
      console.error("Failed to create snapshot:", error);
      res.status(500).json({ error: error.message || "Failed to create snapshot" });
    }
  });

  // GET /api/sandbox/sessions/:id/snapshots - List snapshots for a session
  app.get("/api/sandbox/sessions/:id/snapshots", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const snapshots = await sandboxSessionManager.listSnapshots(req.params.id);
      res.json({ snapshots });
    } catch (error: any) {
      console.error("Failed to list snapshots:", error);
      res.status(500).json({ error: error.message || "Failed to list snapshots" });
    }
  });

  // POST /api/sandbox/sessions/:id/rollback - Rollback to a snapshot
  app.post("/api/sandbox/sessions/:id/rollback", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { snapshotId } = req.body;

      if (!snapshotId) {
        return res.status(400).json({ error: "Snapshot ID is required" });
      }

      const { sandboxSessionManager } = await import("./services/sandbox");
      const result = await sandboxSessionManager.rollbackToSnapshot(req.params.id, snapshotId);
      res.json(result);
    } catch (error: any) {
      console.error("Failed to rollback:", error);
      res.status(500).json({ error: error.message || "Failed to rollback" });
    }
  });

  // GET /api/sandbox/sessions/:id/executions - Get execution history
  app.get("/api/sandbox/sessions/:id/executions", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const executions = await sandboxSessionManager.getExecutions(req.params.id);
      res.json({ executions });
    } catch (error: any) {
      console.error("Failed to get executions:", error);
      res.status(500).json({ error: error.message || "Failed to get executions" });
    }
  });

  // GET /api/sandbox/sessions/:id/stats - Get session statistics
  app.get("/api/sandbox/sessions/:id/stats", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const stats = await sandboxSessionManager.getSessionStats(req.params.id);
      
      if (!stats) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json({ stats });
    } catch (error: any) {
      console.error("Failed to get session stats:", error);
      res.status(500).json({ error: error.message || "Failed to get session stats" });
    }
  });

  // POST /api/sandbox/sessions/:id/close - Close a sandbox session
  app.post("/api/sandbox/sessions/:id/close", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const success = await sandboxSessionManager.closeSession(req.params.id);
      
      if (!success) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json({ success: true, message: "Session closed successfully" });
    } catch (error: any) {
      console.error("Failed to close session:", error);
      res.status(500).json({ error: error.message || "Failed to close session" });
    }
  });

  // GET /api/sandbox/payloads - Get available payload categories
  app.get("/api/sandbox/payloads", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { sandboxSessionManager } = await import("./services/sandbox");
      const categories = sandboxSessionManager.getPayloadCategories();
      res.json({ categories });
    } catch (error: any) {
      console.error("Failed to get payload categories:", error);
      res.status(500).json({ error: error.message || "Failed to get payload categories" });
    }
  });

  // POST /api/sandbox/command-injection/test - Test for command injection vulnerabilities
  app.post("/api/sandbox/command-injection/test", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { command, userInput, injectionType } = req.body;

      if (!command || !userInput) {
        return res.status(400).json({ error: "Command and userInput are required" });
      }

      const { commandExecutor } = await import("./services/sandbox/command-executor");
      const result = await commandExecutor.testCommandInjection(
        command,
        userInput,
        injectionType || "argument"
      );

      res.json({ result });
    } catch (error: any) {
      console.error("Failed to test command injection:", error);
      res.status(500).json({ error: error.message || "Failed to test command injection" });
    }
  });

  // POST /api/sandbox/command-injection/validate - Validate a command for safety
  app.post("/api/sandbox/command-injection/validate", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { command } = req.body;

      if (!command) {
        return res.status(400).json({ error: "Command is required" });
      }

      const { commandExecutor } = await import("./services/sandbox/command-executor");
      const validation = await commandExecutor.validateCommandSafety(command);

      res.json({ validation });
    } catch (error: any) {
      console.error("Failed to validate command:", error);
      res.status(500).json({ error: error.message || "Failed to validate command" });
    }
  });

  // POST /api/sandbox/command-injection/execute - Execute a validated safe command
  app.post("/api/sandbox/command-injection/execute", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { command, expectedPattern } = req.body;

      if (!command) {
        return res.status(400).json({ error: "Command is required" });
      }

      const { commandExecutor } = await import("./services/sandbox/command-executor");
      
      const pattern = expectedPattern ? new RegExp(expectedPattern) : undefined;
      const result = await commandExecutor.executeValidationCommand(command, pattern);

      res.json({ result });
    } catch (error: any) {
      console.error("Failed to execute command:", error);
      res.status(500).json({ error: error.message || "Failed to execute command" });
    }
  });

  // GET /api/sandbox/command-injection/safe-commands - Get list of safe commands
  app.get("/api/sandbox/command-injection/safe-commands", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { commandExecutor } = await import("./services/sandbox/command-executor");
      const safeCommands = commandExecutor.getSafeCommands();
      const injectionPatterns = commandExecutor.getInjectionPatterns();
      
      res.json({ safeCommands, injectionPatterns });
    } catch (error: any) {
      console.error("Failed to get safe commands:", error);
      res.status(500).json({ error: error.message || "Failed to get safe commands" });
    }
  });

  // ============================================================================
  // PHASE 3: LIVE LATERAL MOVEMENT API
  // ============================================================================

  // GET /api/lateral-movement/techniques - Get available lateral movement techniques
  app.get("/api/lateral-movement/techniques", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { lateralMovementService } = await import("./services/lateral-movement");
      const techniques = lateralMovementService.getTechniques();
      res.json({ techniques });
    } catch (error: any) {
      console.error("Failed to get techniques:", error);
      res.status(500).json({ error: error.message || "Failed to get techniques" });
    }
  });

  // POST /api/lateral-movement/credentials - Add a discovered credential
  app.post("/api/lateral-movement/credentials", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sourceType, sourceHost, credentialType, username, domain, credentialValue, privilegeLevel } = req.body;

      if (!credentialType || !username) {
        return res.status(400).json({ error: "Credential type and username are required" });
      }

      const { lateralMovementService } = await import("./services/lateral-movement");
      const credential = await lateralMovementService.addCredential({
        sourceType: sourceType || "manual",
        sourceHost,
        credentialType,
        username,
        domain,
        credentialValue: credentialValue || "",
        privilegeLevel: privilegeLevel || "user",
        tenantId: "default",
      });

      res.json({ credential });
    } catch (error: any) {
      console.error("Failed to add credential:", error);
      res.status(500).json({ error: error.message || "Failed to add credential" });
    }
  });

  // GET /api/lateral-movement/credentials - List discovered credentials
  app.get("/api/lateral-movement/credentials", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { lateralMovementService } = await import("./services/lateral-movement");
      const credentials = await lateralMovementService.listCredentials();
      res.json({ credentials });
    } catch (error: any) {
      console.error("Failed to list credentials:", error);
      res.status(500).json({ error: error.message || "Failed to list credentials" });
    }
  });

  // POST /api/lateral-movement/test-reuse - Test credential reuse across hosts
  app.post("/api/lateral-movement/test-reuse", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { credentialType, username, domain, credentialValue, targetHosts, techniques } = req.body;

      if (!username || !targetHosts || !targetHosts.length) {
        return res.status(400).json({ error: "Username and target hosts are required" });
      }

      const { lateralMovementService } = await import("./services/lateral-movement");
      const result = await lateralMovementService.testCredentialReuse({
        credentialType: credentialType || "password",
        username,
        domain,
        credentialValue: credentialValue || "",
        targetHosts,
        techniques: techniques || ["credential_reuse"],
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to test credential reuse:", error);
      res.status(500).json({ error: error.message || "Failed to test credential reuse" });
    }
  });

  // POST /api/lateral-movement/test - Test a specific lateral movement technique
  app.post("/api/lateral-movement/test", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sourceHost, targetHost, technique, credentialId, customCredential, useRealConnection, timeout } = req.body;

      if (!targetHost || !technique) {
        return res.status(400).json({ error: "Target host and technique are required" });
      }

      const { lateralMovementService } = await import("./services/lateral-movement");
      const result = await lateralMovementService.testLateralMovement(
        {
          sourceHost: sourceHost || "attacker",
          targetHost,
          technique,
          credentialId,
          customCredential,
        },
        {
          useRealConnection: useRealConnection === true,
          timeout: timeout || 10000,
        }
      );

      res.json(result);
    } catch (error: any) {
      console.error("Failed to test lateral movement:", error);
      res.status(500).json({ error: error.message || "Failed to test lateral movement" });
    }
  });

  // POST /api/lateral-movement/probe-host - Probe a host for lateral movement protocols
  app.post("/api/lateral-movement/probe-host", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { host, protocols, timeout } = req.body;

      if (!host) {
        return res.status(400).json({ error: "Host is required" });
      }

      const { protocolConnectors } = await import("./services/lateral-movement/protocol-connectors");
      const validProtocols = protocols || ["smb", "winrm", "ssh"];
      const result = await protocolConnectors.probeHost(host, validProtocols, timeout || 5000);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to probe host:", error);
      res.status(500).json({ error: error.message || "Failed to probe host" });
    }
  });

  // POST /api/lateral-movement/test-protocol - Test a specific protocol connection
  app.post("/api/lateral-movement/test-protocol", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { targetHost, port, protocol, username, domain, credential, timeout } = req.body;

      if (!targetHost || !protocol) {
        return res.status(400).json({ error: "Target host and protocol are required" });
      }

      const { protocolConnectors } = await import("./services/lateral-movement/protocol-connectors");
      const result = await protocolConnectors.testProtocolConnection({
        targetHost,
        port: port || protocolConnectors.DEFAULT_PORTS[protocol as keyof typeof protocolConnectors.DEFAULT_PORTS] || 445,
        protocol,
        username,
        domain,
        credential,
        timeout: timeout || 10000,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to test protocol:", error);
      res.status(500).json({ error: error.message || "Failed to test protocol" });
    }
  });

  // POST /api/lateral-movement/pass-the-hash - Simulate pass-the-hash attack
  app.post("/api/lateral-movement/pass-the-hash", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { ntlmHash, username, domain, targetHost } = req.body;

      if (!ntlmHash || !username || !targetHost) {
        return res.status(400).json({ error: "NTLM hash, username, and target host are required" });
      }

      const { lateralMovementService } = await import("./services/lateral-movement");
      const result = await lateralMovementService.simulatePassTheHash(
        ntlmHash,
        username,
        domain || "WORKGROUP",
        targetHost
      );

      res.json(result);
    } catch (error: any) {
      console.error("Failed to simulate pass-the-hash:", error);
      res.status(500).json({ error: error.message || "Failed to simulate pass-the-hash" });
    }
  });

  // POST /api/lateral-movement/pass-the-ticket - Simulate pass-the-ticket attack
  app.post("/api/lateral-movement/pass-the-ticket", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { ticket, servicePrincipal, targetHost } = req.body;

      if (!ticket || !servicePrincipal || !targetHost) {
        return res.status(400).json({ error: "Ticket, service principal, and target host are required" });
      }

      const { lateralMovementService } = await import("./services/lateral-movement");
      const result = await lateralMovementService.simulatePassTheTicket(
        ticket,
        servicePrincipal,
        targetHost
      );

      res.json(result);
    } catch (error: any) {
      console.error("Failed to simulate pass-the-ticket:", error);
      res.status(500).json({ error: error.message || "Failed to simulate pass-the-ticket" });
    }
  });

  // POST /api/lateral-movement/discover-pivots - Discover pivot points in a network
  app.post("/api/lateral-movement/discover-pivots", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { startingHost, scanDepth, techniques, excludeHosts } = req.body;

      if (!startingHost) {
        return res.status(400).json({ error: "Starting host is required" });
      }

      const { lateralMovementService } = await import("./services/lateral-movement");
      const result = await lateralMovementService.discoverPivotPoints({
        startingHost,
        scanDepth: scanDepth || 3,
        techniques: techniques || ["credential_reuse", "ssh_pivot", "smb_relay"],
        excludeHosts,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to discover pivots:", error);
      res.status(500).json({ error: error.message || "Failed to discover pivots" });
    }
  });

  // GET /api/lateral-movement/findings - Get lateral movement findings
  app.get("/api/lateral-movement/findings", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { lateralMovementService } = await import("./services/lateral-movement");
      const findings = await lateralMovementService.getFindings();
      res.json({ findings });
    } catch (error: any) {
      console.error("Failed to get findings:", error);
      res.status(500).json({ error: error.message || "Failed to get findings" });
    }
  });

  // GET /api/lateral-movement/pivot-points - Get discovered pivot points
  app.get("/api/lateral-movement/pivot-points", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { lateralMovementService } = await import("./services/lateral-movement");
      const pivotPoints = await lateralMovementService.getPivotPoints();
      res.json({ pivotPoints });
    } catch (error: any) {
      console.error("Failed to get pivot points:", error);
      res.status(500).json({ error: error.message || "Failed to get pivot points" });
    }
  });

  // GET /api/lateral-movement/attack-paths - Get discovered attack paths
  app.get("/api/lateral-movement/attack-paths", apiRateLimiter, requireAdminAuth, async (_req, res) => {
    try {
      const { lateralMovementService } = await import("./services/lateral-movement");
      const attackPaths = await lateralMovementService.getAttackPaths();
      res.json({ attackPaths });
    } catch (error: any) {
      console.error("Failed to get attack paths:", error);
      res.status(500).json({ error: error.message || "Failed to get attack paths" });
    }
  });

  // ============================================
  // AWS Cloud Penetration Testing Endpoints
  // ============================================

  // POST /api/cloud-pentest/aws/iam/analyze - Analyze IAM permissions for privilege escalation
  app.post("/api/cloud-pentest/aws/iam/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { permissions, userId, userName, accountId } = req.body;

      if (!permissions || !Array.isArray(permissions)) {
        return res.status(400).json({ error: "Permissions array is required" });
      }

      const { awsPentestService } = await import("./services/cloud-pentest/aws-pentest-service");
      const result = await awsPentestService.analyzeIAMPrivilegeEscalation(
        permissions,
        userId || "unknown",
        userName || "unknown",
        accountId
      );

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze IAM permissions:", error);
      res.status(500).json({ error: error.message || "Failed to analyze IAM permissions" });
    }
  });

  // POST /api/cloud-pentest/aws/s3/analyze - Analyze S3 buckets for misconfigurations
  app.post("/api/cloud-pentest/aws/s3/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { buckets } = req.body;

      if (!buckets || !Array.isArray(buckets)) {
        return res.status(400).json({ error: "Buckets array is required" });
      }

      const { awsPentestService } = await import("./services/cloud-pentest/aws-pentest-service");
      const result = await awsPentestService.analyzeS3Buckets(buckets);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze S3 buckets:", error);
      res.status(500).json({ error: error.message || "Failed to analyze S3 buckets" });
    }
  });

  // POST /api/cloud-pentest/aws/lambda/analyze - Analyze Lambda functions for vulnerabilities
  app.post("/api/cloud-pentest/aws/lambda/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { functions } = req.body;

      if (!functions || !Array.isArray(functions)) {
        return res.status(400).json({ error: "Functions array is required" });
      }

      const { awsPentestService } = await import("./services/cloud-pentest/aws-pentest-service");
      const result = await awsPentestService.analyzeLambdaFunctions(functions);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze Lambda functions:", error);
      res.status(500).json({ error: error.message || "Failed to analyze Lambda functions" });
    }
  });

  // ============================================
  // Azure Cloud Penetration Testing Endpoints
  // ============================================

  // POST /api/cloud-pentest/azure/managed-identities/analyze - Analyze managed identity exploitation
  app.post("/api/cloud-pentest/azure/managed-identities/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { identities } = req.body;

      if (!identities || !Array.isArray(identities)) {
        return res.status(400).json({ error: "Identities array is required" });
      }

      const { azurePentestService } = await import("./services/cloud-pentest/azure-pentest-service");
      const result = await azurePentestService.analyzeManagedIdentities(identities);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze managed identities:", error);
      res.status(500).json({ error: error.message || "Failed to analyze managed identities" });
    }
  });

  // POST /api/cloud-pentest/azure/storage/analyze - Analyze storage exposure
  app.post("/api/cloud-pentest/azure/storage/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { accounts, containers } = req.body;

      if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ error: "Accounts array is required" });
      }

      const { azurePentestService } = await import("./services/cloud-pentest/azure-pentest-service");
      const result = await azurePentestService.analyzeStorageExposure(accounts, containers || []);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze storage exposure:", error);
      res.status(500).json({ error: error.message || "Failed to analyze storage exposure" });
    }
  });

  // POST /api/cloud-pentest/azure/rbac/analyze - Analyze RBAC escalation
  app.post("/api/cloud-pentest/azure/rbac/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { principalId, principalName, roleAssignments } = req.body;

      if (!principalId || !roleAssignments || !Array.isArray(roleAssignments)) {
        return res.status(400).json({ error: "Principal ID and role assignments are required" });
      }

      const { azurePentestService } = await import("./services/cloud-pentest/azure-pentest-service");
      const result = await azurePentestService.analyzeRBACEscalation(
        principalId,
        principalName || "unknown",
        roleAssignments
      );

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze RBAC escalation:", error);
      res.status(500).json({ error: error.message || "Failed to analyze RBAC escalation" });
    }
  });

  // ============================================
  // GCP Cloud Penetration Testing Endpoints
  // ============================================

  // POST /api/cloud-pentest/gcp/service-accounts/analyze - Analyze service account impersonation
  app.post("/api/cloud-pentest/gcp/service-accounts/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { accounts } = req.body;

      if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ error: "Accounts array is required" });
      }

      const { gcpPentestService } = await import("./services/cloud-pentest/gcp-pentest-service");
      const result = await gcpPentestService.analyzeServiceAccounts(accounts);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze service accounts:", error);
      res.status(500).json({ error: error.message || "Failed to analyze service accounts" });
    }
  });

  // POST /api/cloud-pentest/gcp/compute-metadata/analyze - Analyze compute metadata abuse
  app.post("/api/cloud-pentest/gcp/compute-metadata/analyze", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { instances } = req.body;

      if (!instances || !Array.isArray(instances)) {
        return res.status(400).json({ error: "Instances array is required" });
      }

      const { gcpPentestService } = await import("./services/cloud-pentest/gcp-pentest-service");
      const result = await gcpPentestService.analyzeComputeMetadata(instances);

      res.json(result);
    } catch (error: any) {
      console.error("Failed to analyze compute metadata:", error);
      res.status(500).json({ error: error.message || "Failed to analyze compute metadata" });
    }
  });

  // ============================================
  // Compliance Reporting Endpoints
  // ============================================

  // GET /api/compliance/frameworks - Get available compliance frameworks
  app.get("/api/compliance/frameworks", apiRateLimiter, async (req, res) => {
    try {
      const { complianceReportService } = await import("./services/compliance/compliance-report-service");
      const frameworks = complianceReportService.getAvailableFrameworks();

      res.json(frameworks.map(f => ({
        id: f.id,
        name: f.name,
        version: f.version,
        description: f.description,
        controlCount: f.controls.length,
      })));
    } catch (error: any) {
      console.error("Failed to get compliance frameworks:", error);
      res.status(500).json({ error: error.message || "Failed to get compliance frameworks" });
    }
  });

  // GET /api/compliance/frameworks/:frameworkId - Get framework details
  app.get("/api/compliance/frameworks/:frameworkId", apiRateLimiter, async (req, res) => {
    try {
      const { frameworkId } = req.params;
      const { complianceReportService } = await import("./services/compliance/compliance-report-service");
      const framework = complianceReportService.getFramework(frameworkId);

      if (!framework) {
        return res.status(404).json({ error: "Framework not found" });
      }

      res.json(framework);
    } catch (error: any) {
      console.error("Failed to get framework:", error);
      res.status(500).json({ error: error.message || "Failed to get framework" });
    }
  });

  // POST /api/compliance/reports/generate - Generate compliance report
  app.post("/api/compliance/reports/generate", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const {
        frameworkId,
        organizationName,
        findings,
        assessmentDate,
        assessmentScope,
        assessor,
        includePassingControls,
        includeRemediationPlan,
        format,
      } = req.body;

      if (!frameworkId || !organizationName) {
        return res.status(400).json({ error: "Framework ID and organization name are required" });
      }

      const { complianceReportService } = await import("./services/compliance/compliance-report-service");
      
      const report = complianceReportService.generateReport({
        frameworkId,
        organizationName,
        findings: findings || [],
        assessmentDate: assessmentDate ? new Date(assessmentDate) : undefined,
        assessmentScope,
        assessor,
        includePassingControls: includePassingControls ?? true,
        includeRemediationPlan: includeRemediationPlan ?? true,
      });

      if (format === "html") {
        const html = complianceReportService.exportToHTML(report);
        res.setHeader("Content-Type", "text/html");
        res.setHeader("Content-Disposition", `attachment; filename="${report.id}.html"`);
        return res.send(html);
      }

      if (format === "csv") {
        const csv = complianceReportService.exportToCSV(report);
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="${report.id}.csv"`);
        return res.send(csv);
      }

      res.json(report);
    } catch (error: any) {
      console.error("Failed to generate compliance report:", error);
      res.status(500).json({ error: error.message || "Failed to generate compliance report" });
    }
  });

  // POST /api/compliance/map-findings - Map findings to compliance controls
  app.post("/api/compliance/map-findings", apiRateLimiter, async (req, res) => {
    try {
      const { frameworkId, findings } = req.body;

      if (!frameworkId || !findings || !Array.isArray(findings)) {
        return res.status(400).json({ error: "Framework ID and findings array are required" });
      }

      const { complianceReportService } = await import("./services/compliance/compliance-report-service");
      
      const report = complianceReportService.generateReport({
        frameworkId,
        organizationName: "Analysis",
        findings,
        includePassingControls: false,
        includeRemediationPlan: false,
      });

      res.json({
        frameworkId,
        controlMappings: report.controlMappings,
        executiveSummary: report.executiveSummary,
      });
    } catch (error: any) {
      console.error("Failed to map findings:", error);
      res.status(500).json({ error: error.message || "Failed to map findings" });
    }
  });

  // ============================================
  // Container Security Testing Endpoints
  // ============================================

  // POST /api/container-security/escape-test - Test container for escape vectors
  app.post("/api/container-security/escape-test", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const config = req.body;

      if (!config.containerId || !config.image) {
        return res.status(400).json({ error: "Container ID and image are required" });
      }

      const { containerEscapeService } = await import("./services/container-security/container-escape-service");
      const result = await containerEscapeService.testContainerEscape({
        containerId: config.containerId,
        containerName: config.containerName || config.containerId,
        image: config.image,
        privileged: config.privileged,
        capabilities: config.capabilities,
        securityOpt: config.securityOpt,
        user: config.user,
        readonlyRootfs: config.readonlyRootfs,
        pidMode: config.pidMode,
        ipcMode: config.ipcMode,
        networkMode: config.networkMode,
        mounts: config.mounts,
        devices: config.devices,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to test container escape:", error);
      res.status(500).json({ error: error.message || "Failed to test container escape" });
    }
  });

  // POST /api/container-security/kubernetes/abuse-test - Test Kubernetes cluster for abuse vectors
  app.post("/api/container-security/kubernetes/abuse-test", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const config = req.body;

      if (!config.clusterContext || !config.namespace) {
        return res.status(400).json({ error: "Cluster context and namespace are required" });
      }

      const { kubernetesPentestService } = await import("./services/container-security/kubernetes-pentest-service");
      const result = await kubernetesPentestService.testKubernetesAbuse({
        clusterContext: config.clusterContext,
        namespace: config.namespace,
        pods: config.pods,
        serviceAccounts: config.serviceAccounts,
        roles: config.roles,
        roleBindings: config.roleBindings,
        networkPolicies: config.networkPolicies,
        secrets: config.secrets,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to test Kubernetes abuse:", error);
      res.status(500).json({ error: error.message || "Failed to test Kubernetes abuse" });
    }
  });

  // ============================================
  // Business Logic Fuzzing Endpoints
  // ============================================

  // POST /api/business-logic/fuzz-workflow - Fuzz a multi-step business workflow
  app.post("/api/business-logic/fuzz-workflow", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const config = req.body;

      if (!config.workflowName || !config.targetUrl || !config.steps) {
        return res.status(400).json({ error: "Workflow name, target URL, and steps are required" });
      }

      const { workflowFuzzerService } = await import("./services/business-logic/workflow-fuzzer-service");
      const result = await workflowFuzzerService.fuzzWorkflow({
        workflowName: config.workflowName,
        targetUrl: config.targetUrl,
        steps: config.steps,
        authToken: config.authToken,
        enableRaceConditionTesting: config.enableRaceConditionTesting ?? true,
        enableTransactionManipulation: config.enableTransactionManipulation ?? true,
        enableAuthBypassTesting: config.enableAuthBypassTesting ?? true,
        parallelRequestCount: config.parallelRequestCount || 10,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to fuzz workflow:", error);
      res.status(500).json({ error: error.message || "Failed to fuzz workflow" });
    }
  });

  // ============================================
  // Remediation Automation Endpoints
  // ============================================

  // POST /api/remediation/generate - Generate IaC fixes for a finding
  app.post("/api/remediation/generate", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const finding = req.body;

      if (!finding.id || !finding.type || !finding.title) {
        return res.status(400).json({ error: "Finding ID, type, and title are required" });
      }

      const { iacRemediationService } = await import("./services/remediation/iac-remediation-service");
      const result = iacRemediationService.generateRemediation({
        id: finding.id,
        type: finding.type,
        severity: finding.severity || "medium",
        title: finding.title,
        description: finding.description || "",
        affectedResource: finding.affectedResource || "unknown",
        resourceType: finding.resourceType || "",
        cloudProvider: finding.cloudProvider,
        currentConfig: finding.currentConfig,
        cweId: finding.cweId,
        mitreId: finding.mitreId,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to generate remediation:", error);
      res.status(500).json({ error: error.message || "Failed to generate remediation" });
    }
  });

  // POST /api/remediation/batch - Generate fixes for multiple findings
  app.post("/api/remediation/batch", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { findings } = req.body;

      if (!findings || !Array.isArray(findings) || findings.length === 0) {
        return res.status(400).json({ error: "Array of findings is required" });
      }

      const { iacRemediationService } = await import("./services/remediation/iac-remediation-service");
      const results = iacRemediationService.generateBatchRemediation(findings);

      res.json({ remediations: results, totalFindings: findings.length });
    } catch (error: any) {
      console.error("Failed to generate batch remediation:", error);
      res.status(500).json({ error: error.message || "Failed to generate batch remediation" });
    }
  });

  // POST /api/remediation/create-pr - Create a pull request with security fixes
  app.post("/api/remediation/create-pr", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { repositoryUrl, branchName, title, description, changes, labels, reviewers } = req.body;

      if (!repositoryUrl || !branchName || !title || !changes) {
        return res.status(400).json({ error: "Repository URL, branch name, title, and changes are required" });
      }

      const { iacRemediationService } = await import("./services/remediation/iac-remediation-service");
      const result = await iacRemediationService.createPullRequest({
        repositoryUrl,
        branchName,
        title,
        description: description || "",
        changes,
        labels,
        reviewers,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to create PR:", error);
      res.status(500).json({ error: error.message || "Failed to create PR" });
    }
  });

  // ============================================
  // Tool Integration Endpoints - Metasploit
  // ============================================

  // GET /api/tools/metasploit/modules - List available Metasploit modules
  app.get("/api/tools/metasploit/modules", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { type } = req.query;
      const { metasploitService } = await import("./services/tool-integration/metasploit-service");
      
      const modules = await metasploitService.listModules(type as any);
      res.json({ modules, count: modules.length });
    } catch (error: any) {
      console.error("Failed to list modules:", error);
      res.status(500).json({ error: error.message || "Failed to list modules" });
    }
  });

  // GET /api/tools/metasploit/modules/search - Search Metasploit modules
  app.get("/api/tools/metasploit/modules/search", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { query } = req.query;
      if (!query) {
        return res.status(400).json({ error: "Search query is required" });
      }

      const { metasploitService } = await import("./services/tool-integration/metasploit-service");
      const modules = await metasploitService.searchModules(query as string);
      res.json({ modules, count: modules.length });
    } catch (error: any) {
      console.error("Failed to search modules:", error);
      res.status(500).json({ error: error.message || "Failed to search modules" });
    }
  });

  // POST /api/tools/metasploit/exploit - Run an exploit
  app.post("/api/tools/metasploit/exploit", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { module, target, port, options, payload, payloadOptions } = req.body;

      if (!module || !target || !port) {
        return res.status(400).json({ error: "Module, target, and port are required" });
      }

      const { metasploitService } = await import("./services/tool-integration/metasploit-service");
      const result = await metasploitService.runExploit({
        module,
        target,
        port,
        options,
        payload,
        payloadOptions,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to run exploit:", error);
      res.status(500).json({ error: error.message || "Failed to run exploit" });
    }
  });

  // GET /api/tools/metasploit/sessions - List active sessions
  app.get("/api/tools/metasploit/sessions", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { metasploitService } = await import("./services/tool-integration/metasploit-service");
      const sessions = await metasploitService.listSessions();
      res.json({ sessions, count: sessions.length });
    } catch (error: any) {
      console.error("Failed to list sessions:", error);
      res.status(500).json({ error: error.message || "Failed to list sessions" });
    }
  });

  // POST /api/tools/metasploit/sessions/:sessionId/exec - Execute command in session
  app.post("/api/tools/metasploit/sessions/:sessionId/exec", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { command } = req.body;

      if (!command) {
        return res.status(400).json({ error: "Command is required" });
      }

      const { metasploitService } = await import("./services/tool-integration/metasploit-service");
      const output = await metasploitService.executeSessionCommand(sessionId, command);
      res.json({ output });
    } catch (error: any) {
      console.error("Failed to execute command:", error);
      res.status(500).json({ error: error.message || "Failed to execute command" });
    }
  });

  // ============================================
  // Tool Integration Endpoints - Nuclei
  // ============================================

  // GET /api/tools/nuclei/templates - List Nuclei templates
  app.get("/api/tools/nuclei/templates", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { tags, severity } = req.query;
      const { nucleiService } = await import("./services/tool-integration/nuclei-service");

      const tagsArray = tags ? (tags as string).split(",") : undefined;
      const severityArray = severity ? (severity as string).split(",") : undefined;

      const templates = await nucleiService.listTemplates(tagsArray, severityArray);
      res.json({ templates, count: templates.length });
    } catch (error: any) {
      console.error("Failed to list templates:", error);
      res.status(500).json({ error: error.message || "Failed to list templates" });
    }
  });

  // POST /api/tools/nuclei/scan - Run Nuclei scan
  app.post("/api/tools/nuclei/scan", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { target, templates, tags, severity, excludeTags, rateLimit, concurrency, timeout } = req.body;

      if (!target) {
        return res.status(400).json({ error: "Target is required" });
      }

      const { nucleiService } = await import("./services/tool-integration/nuclei-service");
      const result = await nucleiService.runScan({
        target,
        templates,
        tags,
        severity,
        excludeTags,
        rateLimit,
        concurrency,
        timeout,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Failed to run Nuclei scan:", error);
      res.status(500).json({ error: error.message || "Failed to run Nuclei scan" });
    }
  });

  // ============================================
  // Session Replay Endpoints
  // ============================================

  // POST /api/sessions/create - Create a new exploit session
  app.post("/api/sessions/create", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { name, target, assessor, organization, scope, tools, notes } = req.body;

      if (!name || !target) {
        return res.status(400).json({ error: "Name and target are required" });
      }

      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      const session = await sessionReplayService.createSession({
        name,
        target,
        assessor,
        organization,
        scope,
        tools,
        notes,
      });

      res.json(session);
    } catch (error: any) {
      console.error("Failed to create session:", error);
      res.status(500).json({ error: error.message || "Failed to create session" });
    }
  });

  // GET /api/sessions - List all sessions
  app.get("/api/sessions", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { status } = req.query;
      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      
      const sessions = await sessionReplayService.listSessions(status as string);
      res.json({ sessions, count: sessions.length });
    } catch (error: any) {
      console.error("Failed to list sessions:", error);
      res.status(500).json({ error: error.message || "Failed to list sessions" });
    }
  });

  // GET /api/sessions/:sessionId - Get session details
  app.get("/api/sessions/:sessionId", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      
      const session = await sessionReplayService.getSession(sessionId);
      if (!session) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json(session);
    } catch (error: any) {
      console.error("Failed to get session:", error);
      res.status(500).json({ error: error.message || "Failed to get session" });
    }
  });

  // POST /api/sessions/:sessionId/stop - Stop recording a session
  app.post("/api/sessions/:sessionId/stop", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      
      const session = await sessionReplayService.stopRecording(sessionId);
      if (!session) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json(session);
    } catch (error: any) {
      console.error("Failed to stop session:", error);
      res.status(500).json({ error: error.message || "Failed to stop session" });
    }
  });

  // POST /api/sessions/:sessionId/events - Add event to session
  app.post("/api/sessions/:sessionId/events", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { type, source, description, data } = req.body;

      if (!type || !source || !description) {
        return res.status(400).json({ error: "Type, source, and description are required" });
      }

      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      const event = await sessionReplayService.addEvent(sessionId, { type, source, description, data });
      
      if (!event) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json(event);
    } catch (error: any) {
      console.error("Failed to add event:", error);
      res.status(500).json({ error: error.message || "Failed to add event" });
    }
  });

  // GET /api/sessions/:sessionId/playback - Get session playback data
  app.get("/api/sessions/:sessionId/playback", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { startTime, endTime, eventTypes, speed } = req.query;

      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      const playback = await sessionReplayService.getPlayback({
        sessionId,
        startTime: startTime ? parseInt(startTime as string) : undefined,
        endTime: endTime ? parseInt(endTime as string) : undefined,
        eventTypes: eventTypes ? (eventTypes as string).split(",") : undefined,
        speed: speed ? parseFloat(speed as string) : undefined,
      });

      if (!playback) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json(playback);
    } catch (error: any) {
      console.error("Failed to get playback:", error);
      res.status(500).json({ error: error.message || "Failed to get playback" });
    }
  });

  // GET /api/sessions/:sessionId/network - Get network visualization
  app.get("/api/sessions/:sessionId/network", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      
      const visualization = await sessionReplayService.getNetworkVisualization(sessionId);
      if (!visualization) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json(visualization);
    } catch (error: any) {
      console.error("Failed to get network visualization:", error);
      res.status(500).json({ error: error.message || "Failed to get network visualization" });
    }
  });

  // GET /api/sessions/:sessionId/evidence-chain - Get evidence chain
  app.get("/api/sessions/:sessionId/evidence-chain", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      
      const chain = await sessionReplayService.getEvidenceChain(sessionId);
      if (!chain) {
        return res.status(404).json({ error: "Session not found" });
      }

      res.json(chain);
    } catch (error: any) {
      console.error("Failed to get evidence chain:", error);
      res.status(500).json({ error: error.message || "Failed to get evidence chain" });
    }
  });

  // POST /api/sessions/simulate - Create a simulated session for demo
  app.post("/api/sessions/simulate", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { target } = req.body;

      if (!target) {
        return res.status(400).json({ error: "Target is required" });
      }

      const { sessionReplayService } = await import("./services/session-replay/session-replay-service");
      const session = await sessionReplayService.simulateSession(target);

      res.json(session);
    } catch (error: any) {
      console.error("Failed to simulate session:", error);
      res.status(500).json({ error: error.message || "Failed to simulate session" });
    }
  });

  // ============================================================================
  // RAG Policy Search Endpoints
  // Semantic search over security policies for Rules of Engagement context
  // ============================================================================

  // POST /api/policies/search - Semantic search over security policies
  app.post("/api/policies/search", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { query, organizationId, policyType, limit, minSimilarity } = req.body;

      if (!query || typeof query !== "string") {
        return res.status(400).json({ error: "Query is required and must be a string" });
      }

      const { searchPolicies } = await import("./services/rag/policy-search");
      const results = await searchPolicies(query, {
        organizationId,
        policyType,
        limit: limit || 5,
        minSimilarity: minSimilarity || 0.7,
      });

      res.json({
        query,
        results,
        count: results.length,
      });
    } catch (error: any) {
      console.error("Policy search failed:", error);
      res.status(500).json({ error: error.message || "Policy search failed" });
    }
  });

  // GET /api/policies/context - Get policy context for AI agent injection
  app.get("/api/policies/context", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const query = req.query.query as string;
      const organizationId = req.query.organizationId as string | undefined;

      if (!query) {
        return res.status(400).json({ error: "Query parameter is required" });
      }

      const { getPolicyContext } = await import("./services/rag/policy-search");
      const context = await getPolicyContext(query, { organizationId });

      res.json({
        query,
        context,
        hasContext: context.length > 0,
      });
    } catch (error: any) {
      console.error("Failed to get policy context:", error);
      res.status(500).json({ error: error.message || "Failed to get policy context" });
    }
  });

  // POST /api/policies/check-compliance - Check if an action is permitted by policies
  app.post("/api/policies/check-compliance", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const { action, targetType, executionMode, organizationId } = req.body;

      if (!action || typeof action !== "string") {
        return res.status(400).json({ error: "Action is required and must be a string" });
      }

      const { checkPolicyCompliance } = await import("./services/rag/policy-search");
      const result = await checkPolicyCompliance(action, {
        targetType,
        executionMode,
        organizationId,
      });

      res.json(result);
    } catch (error: any) {
      console.error("Compliance check failed:", error);
      res.status(500).json({ error: error.message || "Compliance check failed" });
    }
  });

  // GET /api/policies - List all policies
  app.get("/api/policies", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const policyType = req.query.policyType as string | undefined;

      const { listPolicies } = await import("./services/rag/policy-search");
      const policies = await listPolicies(organizationId, policyType);

      res.json({
        policies,
        count: policies.length,
      });
    } catch (error: any) {
      console.error("Failed to list policies:", error);
      res.status(500).json({ error: error.message || "Failed to list policies" });
    }
  });

  // GET /api/policies/stats - Get policy statistics
  app.get("/api/policies/stats", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;

      const { getPolicyStats } = await import("./services/rag/policy-search");
      const stats = await getPolicyStats(organizationId);

      res.json(stats);
    } catch (error: any) {
      console.error("Failed to get policy stats:", error);
      res.status(500).json({ error: error.message || "Failed to get policy stats" });
    }
  });

  // DELETE /api/policies/:id - Delete a policy
  app.delete("/api/policies/:id", apiRateLimiter, requireAdminAuth, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ error: "Invalid policy ID" });
      }

      const { deletePolicy } = await import("./services/rag/policy-search");
      await deletePolicy(id);

      res.json({ success: true, deletedId: id });
    } catch (error: any) {
      console.error("Failed to delete policy:", error);
      res.status(500).json({ error: error.message || "Failed to delete policy" });
    }
  });

  // ============================================================================
  // FORENSIC EXPORT ROUTES
  // ============================================================================

  // POST /api/forensic-exports - Create a forensic export
  app.post("/api/forensic-exports", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner", "security_analyst"), async (req, res) => {
    try {
      const { evaluationId, executionId, encryptionPassword, includeEvidenceFiles } = req.body;
      const authReq = req as UIAuthenticatedRequest;
      const exportedBy = authReq.user?.email || "unknown";

      if (!evaluationId || !encryptionPassword) {
        return res.status(400).json({ error: "evaluationId and encryptionPassword are required" });
      }

      if (encryptionPassword.length < 12) {
        return res.status(400).json({ error: "Encryption password must be at least 12 characters" });
      }

      const result = await forensicExportService.createExport(
        evaluationId,
        executionId || evaluationId,
        exportedBy,
        encryptionPassword,
        includeEvidenceFiles ?? true
      );

      res.json({
        success: true,
        exportId: result.exportId,
        message: "Forensic export created successfully",
      });
    } catch (error: any) {
      console.error("Failed to create forensic export:", error);
      res.status(500).json({ error: error.message || "Failed to create forensic export" });
    }
  });

  // GET /api/forensic-exports/:exportId/download - Download a forensic export
  app.get("/api/forensic-exports/:exportId/download", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner", "security_analyst"), async (req, res) => {
    try {
      const { exportId } = req.params;

      const result = await forensicExportService.downloadExport(exportId);
      if (!result) {
        return res.status(404).json({ error: "Export not found" });
      }

      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename="${result.filename}"`);
      res.setHeader("Content-Length", result.data.length);
      res.send(result.data);
    } catch (error: any) {
      console.error("Failed to download forensic export:", error);
      res.status(500).json({ error: error.message || "Failed to download forensic export" });
    }
  });

  // GET /api/forensic-exports/evaluation/:evaluationId - Get export history for an evaluation
  app.get("/api/forensic-exports/evaluation/:evaluationId", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner", "security_analyst"), async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const exports = await forensicExportService.getExportHistory(evaluationId);
      res.json(exports);
    } catch (error: any) {
      console.error("Failed to get forensic export history:", error);
      res.status(500).json({ error: error.message || "Failed to get export history" });
    }
  });

  // GET /api/audit-logs/evaluation/:evaluationId - Get audit logs for an evaluation
  app.get("/api/audit-logs/evaluation/:evaluationId", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner", "security_analyst"), async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const logs = await AuditLogger.getLogsForEvaluation(evaluationId);
      res.json(logs);
    } catch (error: any) {
      console.error("Failed to get audit logs:", error);
      res.status(500).json({ error: error.message || "Failed to get audit logs" });
    }
  });

  // ============================================================================
  // HITL (Human-in-the-Loop) APPROVAL ROUTES
  // ============================================================================

  // GET /api/hitl/pending - Get pending approval requests for organization
  app.get("/api/hitl/pending", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner", "security_analyst"), async (req, res) => {
    try {
      const authReq = req as UIAuthenticatedRequest;
      const organizationId = authReq.user?.organizationId || "default";
      const pendingApprovals = await runtimeGuard.getPendingApprovals(organizationId);
      res.json(pendingApprovals);
    } catch (error: any) {
      console.error("Failed to get pending approvals:", error);
      res.status(500).json({ error: error.message || "Failed to get pending approvals" });
    }
  });

  // GET /api/hitl/evaluation/:evaluationId - Get approval history for an evaluation
  app.get("/api/hitl/evaluation/:evaluationId", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner", "security_analyst"), async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const history = await runtimeGuard.getApprovalHistory(evaluationId);
      res.json(history);
    } catch (error: any) {
      console.error("Failed to get approval history:", error);
      res.status(500).json({ error: error.message || "Failed to get approval history" });
    }
  });

  // GET /api/hitl/:approvalId/nonce - Get a nonce for signing an approval response
  // Note: Signatures are computed server-side during approve/reject to prevent client-side forgery
  app.get("/api/hitl/:approvalId/nonce", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req, res) => {
    try {
      const nonce = runtimeGuard.generateNonce();
      res.json({ nonce });
    } catch (error: any) {
      console.error("Failed to generate nonce:", error);
      res.status(500).json({ error: error.message || "Failed to generate nonce" });
    }
  });

  // POST /api/hitl/:approvalId/approve - Approve a pending request
  // Signature computed server-side using authenticated user context
  app.post("/api/hitl/:approvalId/approve", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req, res) => {
    try {
      const { approvalId } = req.params;
      const { nonce } = req.body;
      const authReq = req as UIAuthenticatedRequest;
      const respondedBy = authReq.user?.email || "unknown";

      if (!nonce) {
        return res.status(400).json({ error: "nonce is required" });
      }

      const signature = runtimeGuard.generateSignature(approvalId, true, nonce);

      const result = await runtimeGuard.processApprovalResponse(
        approvalId,
        true,
        respondedBy,
        signature,
        nonce
      );

      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }

      res.json({ success: true, message: "Command approved" });
    } catch (error: any) {
      console.error("Failed to approve command:", error);
      res.status(500).json({ error: error.message || "Failed to approve command" });
    }
  });

  // POST /api/hitl/:approvalId/reject - Reject a pending request
  // Signature computed server-side using authenticated user context
  app.post("/api/hitl/:approvalId/reject", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req, res) => {
    try {
      const { approvalId } = req.params;
      const { nonce, reason } = req.body;
      const authReq = req as UIAuthenticatedRequest;
      const respondedBy = authReq.user?.email || "unknown";

      if (!nonce) {
        return res.status(400).json({ error: "nonce is required" });
      }

      const signature = runtimeGuard.generateSignature(approvalId, false, nonce);

      const result = await runtimeGuard.processApprovalResponse(
        approvalId,
        false,
        respondedBy,
        signature,
        nonce,
        reason
      );

      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }

      res.json({ success: true, message: "Command rejected" });
    } catch (error: any) {
      console.error("Failed to reject command:", error);
      res.status(500).json({ error: error.message || "Failed to reject command" });
    }
  });

  // POST /api/hitl/evaluation/:evaluationId/cancel - Cancel all pending approvals for an evaluation
  app.post("/api/hitl/evaluation/:evaluationId/cancel", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req, res) => {
    try {
      const { evaluationId } = req.params;
      const cancelled = await runtimeGuard.cancelPendingApprovals(evaluationId);
      res.json({ success: true, cancelledCount: cancelled });
    } catch (error: any) {
      console.error("Failed to cancel pending approvals:", error);
      res.status(500).json({ error: error.message || "Failed to cancel pending approvals" });
    }
  });

  // ============================================================================
  // PR AUTOMATION ROUTES
  // ============================================================================

  // POST /api/remediation/configure-pr - Configure GitHub/GitLab credentials
  app.post("/api/remediation/configure-pr", apiRateLimiter, uiAuthMiddleware, requireRole("security_admin", "org_owner"), async (req, res) => {
    try {
      const { provider, token, baseUrl } = req.body;

      if (!provider || !token) {
        return res.status(400).json({ error: "provider and token are required" });
      }

      if (!["github", "gitlab"].includes(provider)) {
        return res.status(400).json({ error: "provider must be 'github' or 'gitlab'" });
      }

      const { prAutomationService } = await import("./services/remediation/pr-automation-service");
      prAutomationService.configure({ provider, token, baseUrl });

      res.json({ success: true, message: `${provider} PR automation configured successfully` });
    } catch (error: any) {
      console.error("Failed to configure PR automation:", error);
      res.status(500).json({ error: error.message || "Failed to configure PR automation" });
    }
  });

  // POST /api/remediation/:findingId/create-pr - Create a PR for a specific finding
  app.post("/api/remediation/:findingId/create-pr", apiRateLimiter, async (req, res) => {
    try {
      const { findingId } = req.params;
      const { repositoryUrl, branchName, labels, reviewers } = req.body;

      if (!repositoryUrl) {
        return res.status(400).json({ error: "repositoryUrl is required" });
      }

      // Generate remediation for the finding
      const { iacRemediationService } = await import("./services/remediation/iac-remediation-service");

      // Mock finding data - in real usage, you'd fetch the actual finding from the database
      const finding = {
        id: findingId,
        type: "security_misconfiguration",
        severity: "high" as const,
        title: "Security Misconfiguration",
        description: "Security misconfiguration detected",
        affectedResource: "example-resource",
        resourceType: "cloud_resource",
      };

      const remediation = iacRemediationService.generateRemediation(finding);

      // Create PR request
      const prRequest = {
        repositoryUrl,
        branchName: branchName || `odinforge-fix-${findingId}`,
        title: `[OdinForge] Fix: ${remediation.findingType}`,
        description: `## Security Remediation\n\n${remediation.recommendations.map(r => `- ${r}`).join("\n")}\n\n**Finding ID:** ${findingId}\n**Risk Level:** ${remediation.riskLevel}\n**Estimated Effort:** ${remediation.estimatedEffort}\n\n### Changes\n${remediation.iacFixes.map(f => `- ${f.description} (${f.iacType})`).join("\n")}\n\n---\n🛡️ Generated by OdinForge AI`,
        changes: remediation.iacFixes.map(fix => ({
          filePath: `terraform/${fix.resourceType}.tf`,
          content: fix.fixedCode,
          changeType: fix.changeType as "create" | "modify" | "delete",
        })),
        labels: labels || ["security", "odinforge", "automated-fix"],
        reviewers: reviewers || [],
      };

      const result = await iacRemediationService.createPullRequest(prRequest);

      res.json({
        success: true,
        pr: result,
        remediation: {
          id: remediation.id,
          fixCount: remediation.iacFixes.length,
          estimatedEffort: remediation.estimatedEffort,
          riskLevel: remediation.riskLevel,
        },
      });
    } catch (error: any) {
      console.error("Failed to create PR:", error);
      res.status(500).json({ error: error.message || "Failed to create pull request" });
    }
  });

  // GET /api/remediation/pr/:prId/status - Check PR status
  app.get("/api/remediation/pr/:prId/status", apiRateLimiter, async (req, res) => {
    try {
      const { prId } = req.params;
      const { repositoryUrl } = req.query;

      if (!repositoryUrl) {
        return res.status(400).json({ error: "repositoryUrl query parameter is required" });
      }

      const { prAutomationService } = await import("./services/remediation/pr-automation-service");
      const status = await prAutomationService.checkPRStatus(prId, repositoryUrl as string);

      res.json(status);
    } catch (error: any) {
      console.error("Failed to check PR status:", error);
      res.status(500).json({ error: error.message || "Failed to check PR status" });
    }
  });

  // ============================================================================
  // Demo Data Management Routes
  // ============================================================================

  /**
   * Load demo data for testing and demonstration
   * Available to all authenticated users for exploration
   */
  app.post("/api/demo-data/load", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      console.log("[Demo Data API] Loading demo data...");
      console.log("[Demo Data API] User:", req.user?.email, "Org:", req.user?.organizationId);

      const { generateDemoData } = await import("./services/demo-data");
      const { withTenantContext } = await import("./services/rls-setup");
      const organizationId = req.user?.organizationId || "default";

      console.log("[Demo Data API] Calling generateDemoData with organizationId:", organizationId);

      // Execute demo data generation with proper tenant context
      const results = await withTenantContext(organizationId, async () => {
        return await generateDemoData({
          organizationId,
          agentCount: 12,
          evaluationCount: 25,
          includeJobs: true,
          includeScans: true,
          includeSessions: true,
          includeAuditLogs: true,
          includeAssets: true,
        });
      });

      console.log("[Demo Data API] Generation complete, results:", results);

      res.json({
        success: true,
        message: "Demo data loaded successfully",
        ...results
      });
    } catch (error: any) {
      console.error("[Demo Data] Error loading demo data:", error);
      console.error("[Demo Data] Stack trace:", error.stack);
      res.status(500).json({ error: error.message || "Failed to load demo data" });
    }
  });

  /**
   * Clear all demo data
   * Available to all authenticated users
   */
  app.post("/api/demo-data/clear", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const { clearDemoData } = await import("./services/demo-data");
      const { withTenantContext } = await import("./services/rls-setup");
      const organizationId = req.user?.organizationId || "default";

      // Execute demo data clearing with proper tenant context
      await withTenantContext(organizationId, async () => {
        await clearDemoData(organizationId);
      });

      res.json({
        success: true,
        message: "Demo data cleared successfully"
      });
    } catch (error: any) {
      console.error("[Demo Data] Error clearing demo data:", error);
      res.status(500).json({ error: error.message || "Failed to clear demo data" });
    }
  });

  /**
   * Check demo data status
   */
  app.get("/api/demo-data/status", apiRateLimiter, uiAuthMiddleware, async (req: UIAuthenticatedRequest, res) => {
    try {
      const organizationId = req.user?.organizationId || "default";

      // Count demo data records
      const agentCount = await db.select({ count: sql<number>`count(*)` })
        .from(endpointAgents)
        .where(and(
          eq(endpointAgents.organizationId, organizationId),
          sql`${endpointAgents.id} LIKE 'agent-demo-%'`
        ));

      const evalCount = await db.select({ count: sql<number>`count(*)` })
        .from(aevEvaluations)
        .where(and(
          eq(aevEvaluations.organizationId, organizationId),
          sql`${aevEvaluations.id} LIKE 'eval-demo-%'`
        ));

      const hasDemoData = (agentCount[0]?.count || 0) > 0 || (evalCount[0]?.count || 0) > 0;

      res.json({
        hasDemoData,
        counts: {
          agents: agentCount[0]?.count || 0,
          evaluations: evalCount[0]?.count || 0,
        }
      });
    } catch (error: any) {
      console.error("[Demo Data] Error checking demo data status:", error);
      res.status(500).json({ error: error.message || "Failed to check demo data status" });
    }
  });

  // Note: Object storage routes removed - using standard S3-compatible storage via storageService
  // File uploads now handled via presigned URLs from storageService.getUploadURL()
}
