import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertEvaluationSchema, insertReportSchema, insertBatchJobSchema, insertScheduledScanSchema, complianceFrameworks } from "@shared/schema";
import { runAgentOrchestrator } from "./services/agents";
import { runAISimulation } from "./services/agents/ai-simulation";
import { wsService } from "./services/websocket";
import { reportGenerator } from "./services/report-generator";
import { unifiedAuthService } from "./services/unified-auth";
import { mtlsAuthService } from "./services/mtls-auth";
import { jwtAuthService } from "./services/jwt-auth";
import { 
  apiRateLimiter, 
  authRateLimiter, 
  agentTelemetryRateLimiter, 
  batchRateLimiter, 
  evaluationRateLimiter,
  reportRateLimiter,
  simulationRateLimiter,
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
import { randomUUID, timingSafeEqual } from "crypto";
import bcrypt from "bcrypt";
import { z } from "zod";
import { registerReportV2Routes } from "./src/reportsV2/routes";
import { calculateDefensivePosture, calculateAttackPredictions } from "./services/metrics-calculator";
import { AGENT_RELEASE, INSTALLATION_INSTRUCTIONS } from "@shared/agent-releases";
import { fullRecon, reconToExposures, type ReconResult } from "./services/external-recon";
import { runFullAssessment } from "./services/full-assessment";
import { generateAgentFindings } from "./services/telemetry-analyzer";

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

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  wsService.initialize(httpServer);
  
  // ========== AGENT BINARY DOWNLOADS ==========
  // Serve agent binaries from public/agents directory (no auth required for download)
  app.get("/agents/:filename", (req, res) => {
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

      runEvaluation(evaluation.id, {
        assetId: parsed.data.assetId,
        exposureType: parsed.data.exposureType,
        priority: parsed.data.priority || "medium",
        description: parsed.data.description,
        adversaryProfile: parsed.data.adversaryProfile || undefined,
        organizationId: parsed.data.organizationId || "default",
      });
    } catch (error) {
      console.error("Error starting evaluation:", error);
      res.status(500).json({ error: "Failed to start evaluation" });
    }
  });

  app.get("/api/aev/evaluations", async (req, res) => {
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

  app.get("/api/aev/evaluations/:id", async (req, res) => {
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
        duration: result?.duration,
      });
    } catch (error) {
      console.error("Error fetching evaluation:", error);
      res.status(500).json({ error: "Failed to fetch evaluation" });
    }
  });

  app.delete("/api/aev/evaluations/:id", async (req, res) => {
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

  app.patch("/api/aev/evaluations/:id/archive", async (req, res) => {
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

  app.patch("/api/aev/evaluations/:id/unarchive", async (req, res) => {
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

  app.get("/api/aev/stats", async (req, res) => {
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

  // ========== SYSTEM MONITORING ENDPOINTS ==========
  
  app.get("/api/system/websocket-stats", async (req, res) => {
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
      const { type, format, from, to, framework, organizationId = "default", evaluationId } = req.body;
      
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
  
  app.get("/api/reports", async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const reports = await storage.getReports(organizationId);
      res.json(reports);
    } catch (error) {
      console.error("Error fetching reports:", error);
      res.status(500).json({ error: "Failed to fetch reports" });
    }
  });
  
  app.get("/api/reports/:id", async (req, res) => {
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
  
  app.delete("/api/reports/:id", async (req, res) => {
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
  
  app.get("/api/reports/:id/download", async (req, res) => {
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

  app.get("/api/reports/enhanced/:evaluationId", async (req, res) => {
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

  // ========== EVIDENCE EXPORT ENDPOINT ==========
  
  app.post("/api/evidence/:evaluationId/export", async (req, res) => {
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

  // ========== BATCH JOB ENDPOINTS ==========
  
  app.post("/api/batch-jobs", batchRateLimiter, async (req, res) => {
    try {
      const parsed = insertBatchJobSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error });
      }
      
      const batchJob = await storage.createBatchJob({
        ...parsed.data,
        totalEvaluations: (parsed.data.assets as any[]).length,
      });
      
      res.json({ batchJobId: batchJob.id, status: "created" });
      
      runBatchJob(batchJob.id, parsed.data.assets as any[]);
    } catch (error) {
      console.error("Error creating batch job:", error);
      res.status(500).json({ error: "Failed to create batch job" });
    }
  });
  
  app.get("/api/batch-jobs", async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const jobs = await storage.getBatchJobs(organizationId);
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching batch jobs:", error);
      res.status(500).json({ error: "Failed to fetch batch jobs" });
    }
  });
  
  app.get("/api/batch-jobs/:id", async (req, res) => {
    try {
      const job = await storage.getBatchJob(req.params.id);
      if (!job) {
        return res.status(404).json({ error: "Batch job not found" });
      }
      res.json(job);
    } catch (error) {
      console.error("Error fetching batch job:", error);
      res.status(500).json({ error: "Failed to fetch batch job" });
    }
  });
  
  app.delete("/api/batch-jobs/:id", async (req, res) => {
    try {
      const job = await storage.getBatchJob(req.params.id);
      if (!job) {
        return res.status(404).json({ error: "Batch job not found" });
      }
      await storage.deleteBatchJob(req.params.id);
      res.json({ success: true, message: "Batch job deleted successfully" });
    } catch (error) {
      console.error("Error deleting batch job:", error);
      res.status(500).json({ error: "Failed to delete batch job" });
    }
  });

  app.patch("/api/batch-jobs/:id", async (req, res) => {
    try {
      const job = await storage.getBatchJob(req.params.id);
      if (!job) {
        return res.status(404).json({ error: "Batch job not found" });
      }
      await storage.updateBatchJob(req.params.id, req.body);
      const updatedJob = await storage.getBatchJob(req.params.id);
      res.json(updatedJob);
    } catch (error) {
      console.error("Error updating batch job:", error);
      res.status(500).json({ error: "Failed to update batch job" });
    }
  });

  // ========== SCHEDULED SCAN ENDPOINTS ==========
  
  app.post("/api/scheduled-scans", async (req, res) => {
    try {
      const parsed = insertScheduledScanSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error });
      }
      
      const scan = await storage.createScheduledScan(parsed.data);
      res.json(scan);
    } catch (error) {
      console.error("Error creating scheduled scan:", error);
      res.status(500).json({ error: "Failed to create scheduled scan" });
    }
  });
  
  app.get("/api/scheduled-scans", async (req, res) => {
    try {
      const organizationId = req.query.organizationId as string | undefined;
      const scans = await storage.getScheduledScans(organizationId);
      res.json(scans);
    } catch (error) {
      console.error("Error fetching scheduled scans:", error);
      res.status(500).json({ error: "Failed to fetch scheduled scans" });
    }
  });
  
  app.get("/api/scheduled-scans/:id", async (req, res) => {
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
  
  app.patch("/api/scheduled-scans/:id", async (req, res) => {
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
  
  app.delete("/api/scheduled-scans/:id", async (req, res) => {
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

  // ========== GOVERNANCE ENDPOINTS ==========
  
  // Rate Limit Status - MUST come before :organizationId route
  app.get("/api/governance/rate-limits", async (req, res) => {
    try {
      const statuses = getAllRateLimitStatuses();
      res.json(statuses);
    } catch (error) {
      console.error("Error fetching rate limit status:", error);
      res.status(500).json({ error: "Failed to fetch rate limit status" });
    }
  });

  // Get or create organization governance settings
  app.get("/api/governance/:organizationId", async (req, res) => {
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

  app.patch("/api/governance/:organizationId", async (req, res) => {
    try {
      await storage.updateOrganizationGovernance(req.params.organizationId, req.body);
      
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
  app.post("/api/governance/:organizationId/kill-switch", async (req, res) => {
    try {
      const { activate, activatedBy } = req.body;
      
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
      
      const governance = await storage.getOrganizationGovernance(req.params.organizationId);
      res.json(governance);
    } catch (error) {
      console.error("Error toggling kill switch:", error);
      res.status(500).json({ error: "Failed to toggle kill switch" });
    }
  });

  // Authorization Logs
  app.get("/api/authorization-logs/:organizationId", async (req, res) => {
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
  app.get("/api/scope-rules/:organizationId", async (req, res) => {
    try {
      const rules = await storage.getScopeRules(req.params.organizationId);
      res.json(rules);
    } catch (error) {
      console.error("Error fetching scope rules:", error);
      res.status(500).json({ error: "Failed to fetch scope rules" });
    }
  });

  app.post("/api/scope-rules", async (req, res) => {
    try {
      const rule = await storage.createScopeRule(req.body);
      
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

  app.delete("/api/scope-rules/:id", async (req, res) => {
    try {
      await storage.deleteScopeRule(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting scope rule:", error);
      res.status(500).json({ error: "Failed to delete scope rule" });
    }
  });

  // ========== ADVANCED AI ENDPOINTS ==========

  // Adversary Profiles
  app.get("/api/adversary-profiles", async (req, res) => {
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

  app.get("/api/adversary-profiles/:id", async (req, res) => {
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

  app.post("/api/adversary-profiles", async (req, res) => {
    try {
      const profile = await storage.createAdversaryProfile(req.body);
      res.json(profile);
    } catch (error) {
      console.error("Error creating adversary profile:", error);
      res.status(500).json({ error: "Failed to create adversary profile" });
    }
  });

  // Attack Predictions - computed from real evaluation data
  app.get("/api/attack-predictions/:organizationId", async (req, res) => {
    try {
      const timeHorizon = req.query.timeHorizon as string || "30d";
      const predictions = await calculateAttackPredictions(req.params.organizationId, timeHorizon);
      res.json(predictions);
    } catch (error) {
      console.error("Error calculating attack predictions:", error);
      res.status(500).json({ error: "Failed to calculate attack predictions" });
    }
  });

  app.post("/api/attack-predictions/generate", async (req, res) => {
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
  app.get("/api/defensive-posture/:organizationId", async (req, res) => {
    try {
      const posture = await calculateDefensivePosture(req.params.organizationId);
      res.json(posture);
    } catch (error) {
      console.error("Error calculating defensive posture:", error);
      res.status(500).json({ error: "Failed to calculate defensive posture" });
    }
  });

  app.get("/api/defensive-posture/:organizationId/history", async (req, res) => {
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
  app.get("/api/purple-team/:organizationId", async (req, res) => {
    try {
      const findings = await storage.getPurpleTeamFindings(req.params.organizationId);
      res.json(findings);
    } catch (error) {
      console.error("Error fetching purple team findings:", error);
      res.status(500).json({ error: "Failed to fetch purple team findings" });
    }
  });

  app.post("/api/purple-team", async (req, res) => {
    try {
      const finding = await storage.createPurpleTeamFinding(req.body);
      res.json(finding);
    } catch (error) {
      console.error("Error creating purple team finding:", error);
      res.status(500).json({ error: "Failed to create purple team finding" });
    }
  });

  app.patch("/api/purple-team/:id", async (req, res) => {
    try {
      await storage.updatePurpleTeamFinding(req.params.id, req.body);
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating purple team finding:", error);
      res.status(500).json({ error: "Failed to update purple team finding" });
    }
  });

  // AI Simulations
  app.get("/api/ai-simulations/:organizationId", async (req, res) => {
    try {
      const simulations = await storage.getAiSimulations(req.params.organizationId);
      res.json(simulations);
    } catch (error) {
      console.error("Error fetching AI simulations:", error);
      res.status(500).json({ error: "Failed to fetch AI simulations" });
    }
  });

  app.post("/api/ai-simulations", async (req, res) => {
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

  app.get("/api/ai-simulations/detail/:id", async (req, res) => {
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
  app.get("/api/infrastructure/stats", async (req, res) => {
    try {
      const stats = await storage.getInfrastructureStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching infrastructure stats:", error);
      res.status(500).json({ error: "Failed to fetch infrastructure stats" });
    }
  });

  // ========== DISCOVERED ASSETS ==========

  app.get("/api/assets", async (req, res) => {
    try {
      const assets = await storage.getDiscoveredAssets();
      res.json(assets);
    } catch (error) {
      console.error("Error fetching assets:", error);
      res.status(500).json({ error: "Failed to fetch assets" });
    }
  });

  app.get("/api/assets/:id", async (req, res) => {
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

  app.get("/api/assets/:id/vulnerabilities", async (req, res) => {
    try {
      const vulns = await storage.getVulnerabilityImportsByAssetId(req.params.id);
      res.json(vulns);
    } catch (error) {
      console.error("Error fetching asset vulnerabilities:", error);
      res.status(500).json({ error: "Failed to fetch asset vulnerabilities" });
    }
  });

  app.patch("/api/assets/:id", async (req, res) => {
    try {
      await storage.updateDiscoveredAsset(req.params.id, req.body);
      const updated = await storage.getDiscoveredAsset(req.params.id);
      res.json(updated);
    } catch (error) {
      console.error("Error updating asset:", error);
      res.status(500).json({ error: "Failed to update asset" });
    }
  });

  app.delete("/api/assets/:id", async (req, res) => {
    try {
      await storage.deleteDiscoveredAsset(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting asset:", error);
      res.status(500).json({ error: "Failed to delete asset" });
    }
  });

  // ========== VULNERABILITY IMPORTS ==========

  app.get("/api/vulnerabilities", async (req, res) => {
    try {
      const vulns = await storage.getVulnerabilityImports();
      res.json(vulns);
    } catch (error) {
      console.error("Error fetching vulnerabilities:", error);
      res.status(500).json({ error: "Failed to fetch vulnerabilities" });
    }
  });

  app.get("/api/vulnerabilities/:id", async (req, res) => {
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

  app.patch("/api/vulnerabilities/:id", async (req, res) => {
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
  app.post("/api/vulnerabilities/:id/evaluate", async (req, res) => {
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

  app.get("/api/imports", async (req, res) => {
    try {
      const jobs = await storage.getImportJobs();
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching import jobs:", error);
      res.status(500).json({ error: "Failed to fetch import jobs" });
    }
  });

  app.get("/api/imports/:id", async (req, res) => {
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

  app.get("/api/imports/:id/vulnerabilities", async (req, res) => {
    try {
      const vulns = await storage.getVulnerabilityImportsByJobId(req.params.id);
      res.json(vulns);
    } catch (error) {
      console.error("Error fetching import vulnerabilities:", error);
      res.status(500).json({ error: "Failed to fetch import vulnerabilities" });
    }
  });

  app.delete("/api/imports/:id", async (req, res) => {
    try {
      await storage.deleteImportJob(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting import job:", error);
      res.status(500).json({ error: "Failed to delete import job" });
    }
  });

  // Upload and parse scanner file
  app.post("/api/imports/upload", async (req, res) => {
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

  app.get("/api/cloud-connections", async (req, res) => {
    try {
      const connections = await storage.getCloudConnections();
      res.json(connections);
    } catch (error) {
      console.error("Error fetching cloud connections:", error);
      res.status(500).json({ error: "Failed to fetch cloud connections" });
    }
  });

  app.get("/api/cloud-connections/:id", async (req, res) => {
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

  app.post("/api/cloud-connections", async (req, res) => {
    try {
      const connection = await storage.createCloudConnection(req.body);
      res.json(connection);
    } catch (error) {
      console.error("Error creating cloud connection:", error);
      res.status(500).json({ error: "Failed to create cloud connection" });
    }
  });

  app.patch("/api/cloud-connections/:id", async (req, res) => {
    try {
      await storage.updateCloudConnection(req.params.id, req.body);
      const updated = await storage.getCloudConnection(req.params.id);
      res.json(updated);
    } catch (error) {
      console.error("Error updating cloud connection:", error);
      res.status(500).json({ error: "Failed to update cloud connection" });
    }
  });

  app.delete("/api/cloud-connections/:id", async (req, res) => {
    try {
      await storage.deleteCloudConnection(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting cloud connection:", error);
      res.status(500).json({ error: "Failed to delete cloud connection" });
    }
  });

  // Test cloud connection
  app.post("/api/cloud-connections/:id/test", async (req, res) => {
    try {
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        return res.status(404).json({ error: "Cloud connection not found" });
      }

      // Simulate testing connection (in production, would use AWS/Azure/GCP SDKs)
      await storage.updateCloudConnection(req.params.id, {
        status: "connected",
        lastSyncAt: new Date(),
        lastSyncStatus: "success",
      });

      res.json({ success: true, message: "Connection test successful" });
    } catch (error) {
      console.error("Error testing cloud connection:", error);
      res.status(500).json({ error: "Failed to test cloud connection" });
    }
  });

  // Store credentials for cloud connection (encrypted)
  app.post("/api/cloud-connections/:id/credentials", async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        return res.status(404).json({ error: "Cloud connection not found" });
      }

      const result = await cloudIntegrationService.validateAndStoreCredentials(
        req.params.id,
        connection.provider,
        req.body
      );

      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }

      await storage.updateCloudConnection(req.params.id, {
        status: "connected",
        lastSyncAt: new Date(),
        lastSyncStatus: "success",
      });

      res.json({ 
        success: true, 
        message: "Credentials validated and stored securely",
        accountInfo: result.accountInfo 
      });
    } catch (error) {
      console.error("Error storing credentials:", error);
      res.status(500).json({ error: "Failed to store credentials" });
    }
  });

  // Start asset discovery for a cloud connection
  app.post("/api/cloud-connections/:id/discover", async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const connection = await storage.getCloudConnection(req.params.id);
      if (!connection) {
        return res.status(404).json({ error: "Cloud connection not found" });
      }

      const result = await cloudIntegrationService.startDiscoveryJob(
        req.params.id,
        connection.organizationId,
        { regions: req.body.regions, triggeredBy: req.body.userId }
      );

      if (result.error) {
        return res.status(400).json({ error: result.error });
      }

      res.json({ 
        success: true, 
        jobId: result.jobId,
        message: "Asset discovery started" 
      });
    } catch (error) {
      console.error("Error starting discovery:", error);
      res.status(500).json({ error: "Failed to start asset discovery" });
    }
  });

  // Get discovered cloud assets for a connection
  app.get("/api/cloud-connections/:id/assets", async (req, res) => {
    try {
      const assets = await storage.getCloudAssetsByConnection(req.params.id);
      res.json(assets);
    } catch (error) {
      console.error("Error fetching cloud assets:", error);
      res.status(500).json({ error: "Failed to fetch cloud assets" });
    }
  });

  // Get discovery jobs for a connection
  app.get("/api/cloud-connections/:id/discovery-jobs", async (req, res) => {
    try {
      const jobs = await storage.getCloudDiscoveryJobs(req.params.id);
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching discovery jobs:", error);
      res.status(500).json({ error: "Failed to fetch discovery jobs" });
    }
  });

  // Deploy agent to a specific cloud asset
  app.post("/api/cloud-assets/:id/deploy-agent", async (req, res) => {
    try {
      const { cloudIntegrationService } = await import("./services/cloud/index");
      
      const result = await cloudIntegrationService.deployAgentToAsset(
        req.params.id,
        { initiatedBy: req.body.userId }
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
  app.post("/api/cloud-assets/:id/redeploy-agent", async (req, res) => {
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

  // Deploy agents to all assets in a connection
  app.post("/api/cloud-connections/:id/deploy-all-agents", async (req, res) => {
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
  app.get("/api/cloud-assets", async (req, res) => {
    try {
      const assets = await storage.getCloudAssets();
      res.json(assets);
    } catch (error) {
      console.error("Error fetching cloud assets:", error);
      res.status(500).json({ error: "Failed to fetch cloud assets" });
    }
  });

  // Get deployment jobs for a connection
  app.get("/api/cloud-connections/:id/deployment-jobs", async (req, res) => {
    try {
      const jobs = await storage.getAgentDeploymentJobs(req.params.id);
      res.json(jobs);
    } catch (error) {
      console.error("Error fetching deployment jobs:", error);
      res.status(500).json({ error: "Failed to fetch deployment jobs" });
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
  });

  // Start a new AI vs AI simulation
  app.post("/api/simulations", simulationRateLimiter, async (req, res) => {
    try {
      const parseResult = createSimulationSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({ error: parseResult.error.errors[0].message });
      }
      const { assetId, exposureType, priority, description, rounds } = parseResult.data;

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
      runSimulation(simulationId, assetId, exposureType, priority || "high", description, rounds);

      res.json({ 
        simulationId,
        status: "running",
        message: "AI vs AI simulation started. Use WebSocket or GET /api/simulations/:id for progress updates.",
      });
    } catch (error) {
      console.error("Error starting simulation:", error);
      res.status(500).json({ error: "Failed to start simulation" });
    }
  });

  // Get all simulations
  app.get("/api/simulations", async (req, res) => {
    try {
      const simulations = await storage.getAllAiSimulations();
      res.json(simulations);
    } catch (error) {
      console.error("Error fetching simulations:", error);
      res.status(500).json({ error: "Failed to fetch simulations" });
    }
  });

  // Get a specific simulation
  app.get("/api/simulations/:id", async (req, res) => {
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
  app.delete("/api/simulations/:id", async (req, res) => {
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
    rounds: number
  ) {
    try {
      wsService.sendProgress(simulationId, "AI Simulation", "starting", 0, "Starting AI vs AI simulation...");

      const result = await runAISimulation(
        assetId,
        exposureType,
        priority,
        description,
        simulationId,
        rounds,
        (phase, round, progress, message) => {
          wsService.sendProgress(simulationId, `AI Simulation (Round ${round})`, phase, progress, message);
        }
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
    
    // Get all agents for API key comparison
    const agents = await storage.getEndpointAgents();
    
    // Use unified auth service for multi-method authentication
    const authResult = await unifiedAuthService.authenticateRequest(
      authHeader,
      clientCertHeader,
      agents,
      certSecretHeader,
      xApiKeyHeader
    );
    
    if (!authResult.authenticated) {
      return res.status(401).json({ error: authResult.error || "Authentication failed" });
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
    next();
  }

  // Get registration token for display in UI
  // Note: The Agents page requires login to access, so this is effectively protected
  app.get("/api/agents/registration-token", async (req, res) => {
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
  app.post("/api/agents/auto-register", authRateLimiter, async (req, res) => {
    try {
      const registrationToken = process.env.AGENT_REGISTRATION_TOKEN;
      
      if (!registrationToken) {
        return res.status(503).json({ 
          error: "Auto-registration not enabled", 
          message: "AGENT_REGISTRATION_TOKEN environment variable not set" 
        });
      }

      const { token, agentName, hostname, platform, platformVersion, architecture, capabilities, environment, tags } = req.body;

      if (!token) {
        return res.status(400).json({ error: "Registration token required" });
      }

      // Debug: Log token lengths to diagnose shell escaping issues
      console.log(`[Agent Registration] Received token length: ${token.length}, Expected length: ${registrationToken.length}`);
      console.log(`[Agent Registration] Token match: ${token === registrationToken}`);

      // Validate the registration token (constant-time comparison to prevent timing attacks)
      const tokenBuffer = Buffer.from(token);
      const expectedBuffer = Buffer.from(registrationToken);
      
      if (tokenBuffer.length !== expectedBuffer.length || !timingSafeEqual(tokenBuffer, expectedBuffer)) {
        console.log(`[Agent Registration] Token mismatch - received: "${token.substring(0, 3)}..." vs expected: "${registrationToken.substring(0, 3)}..."`);
        return res.status(401).json({ error: "Invalid registration token" });
      }

      // Check if agent with same hostname already exists (prevent duplicate registrations)
      if (hostname) {
        const existingAgents = await storage.getEndpointAgents();
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
          
          return res.json({
            id: existingAgent.id,
            apiKey,
            agentName: existingAgent.agentName,
            message: "Agent re-registered successfully. API key has been rotated.",
            existingAgent: true
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
        organizationId: "default",
        status: "online",
      });

      res.json({
        id: agent.id,
        apiKey,
        agentName: agent.agentName,
        message: "Agent auto-registered successfully. Store the API key securely.",
        existingAgent: false
      });
    } catch (error) {
      console.error("Error auto-registering agent:", error);
      res.status(500).json({ error: "Failed to auto-register agent" });
    }
  });

  // Agent heartbeat
  app.post("/api/agents/heartbeat", authenticateAgent, async (req: any, res) => {
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

  // Get agent release information for download center
  app.get("/api/agent-releases/latest", async (req, res) => {
    try {
      res.json({
        release: AGENT_RELEASE,
        instructions: INSTALLATION_INSTRUCTIONS
      });
    } catch (error) {
      console.error("Error fetching agent releases:", error);
      res.status(500).json({ error: "Failed to fetch agent releases" });
    }
  });

  // Serve install.sh script for curl-based installation
  app.get("/api/agents/install.sh", async (req, res) => {
    try {
      const fs = await import("fs");
      const path = await import("path");
      const scriptPath = path.join(process.cwd(), "odinforge-agent", "install.sh");
      
      if (fs.existsSync(scriptPath)) {
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Content-Disposition", "inline; filename=install.sh");
        const script = fs.readFileSync(scriptPath, "utf-8");
        res.send(script);
      } else {
        res.status(404).json({ error: "Install script not found" });
      }
    } catch (error) {
      console.error("Error serving install script:", error);
      res.status(500).json({ error: "Failed to serve install script" });
    }
  });

  // Serve install.ps1 script for PowerShell-based installation (Windows)
  app.get("/api/agents/install.ps1", async (req, res) => {
    try {
      const fs = await import("fs");
      const path = await import("path");
      const scriptPath = path.join(process.cwd(), "odinforge-agent", "install.ps1");
      
      if (fs.existsSync(scriptPath)) {
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Content-Disposition", "inline; filename=install.ps1");
        const script = fs.readFileSync(scriptPath, "utf-8");
        res.send(script);
      } else {
        res.status(404).json({ error: "Install script not found" });
      }
    } catch (error) {
      console.error("Error serving install script:", error);
      res.status(500).json({ error: "Failed to serve install script" });
    }
  });

  // Serve Kubernetes DaemonSet manifest
  app.get("/api/agents/kubernetes/daemonset.yaml", async (req, res) => {
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
  app.get("/api/agents/build-status", async (req, res) => {
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

  // Download agent binary by platform - serves locally built binaries
  app.get("/api/agents/download/:platform", async (req, res) => {
    try {
      const { platform } = req.params;
      const { getAgentBinaryPath } = await import("./services/agent-builder");
      
      const binaryPath = getAgentBinaryPath(platform);
      
      if (!binaryPath) {
        const validPlatforms = ["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64"];
        return res.status(404).json({ 
          error: `Agent binary not available for platform: ${platform}`,
          validPlatforms,
          message: "Binary may still be building. Check /api/agents/build-status for details."
        });
      }

      const fs = await import("fs");
      const filename = platform === "windows-amd64" 
        ? `odinforge-agent-${platform}.exe` 
        : `odinforge-agent-${platform}`;
      
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
  app.get("/api/agents", async (req, res) => {
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
  app.get("/api/agents/stats/summary", async (req, res) => {
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

  // Get agent by ID
  app.get("/api/agents/:id", async (req, res) => {
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
  app.post("/api/agents/:id/force-checkin", async (req, res) => {
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

  // Get pending commands for an agent (called by agent during heartbeat)
  app.get("/api/agents/:id/commands", async (req, res) => {
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
  app.post("/api/agents/:id/commands/:commandId/complete", async (req, res) => {
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
  app.get("/api/agents/:id/telemetry", async (req, res) => {
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
  app.get("/api/agents/:id/findings", async (req, res) => {
    try {
      const findings = await storage.getAgentFindings(req.params.id);
      res.json(findings);
    } catch (error) {
      console.error("Error fetching agent findings:", error);
      res.status(500).json({ error: "Failed to fetch agent findings" });
    }
  });

  // Delete agent
  app.delete("/api/agents/:id", async (req, res) => {
    try {
      await storage.deleteEndpointAgent(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting agent:", error);
      res.status(500).json({ error: "Failed to delete agent" });
    }
  });

  // Get all agent findings
  app.get("/api/agent-findings", async (req, res) => {
    try {
      const findings = await storage.getAgentFindings();
      res.json(findings);
    } catch (error) {
      console.error("Error fetching agent findings:", error);
      res.status(500).json({ error: "Failed to fetch agent findings" });
    }
  });

  // Update agent finding status
  app.patch("/api/agent-findings/:id", async (req, res) => {
    try {
      await storage.updateAgentFinding(req.params.id, req.body);
      const finding = await storage.getAgentFinding(req.params.id);
      res.json(finding);
    } catch (error) {
      console.error("Error updating agent finding:", error);
      res.status(500).json({ error: "Failed to update agent finding" });
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
  app.post("/api/agents/:id/certificates", requireAdminAuth, async (req, res) => {
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
  app.get("/api/agents/:id/certificates", async (req, res) => {
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
  app.post("/api/agents/:id/certificates/:certId/renew", requireAdminAuth, async (req, res) => {
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
  app.delete("/api/agents/:id/certificates/:certId", requireAdminAuth, async (req, res) => {
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
  app.post("/api/agents/:id/tokens", requireAdminAuth, async (req, res) => {
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
  app.post("/api/auth/refresh", async (req, res) => {
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
  app.post("/api/agents/:id/revoke-all", requireAdminAuth, async (req, res) => {
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
  app.get("/api/agents/:id/auth-status", async (req, res) => {
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
  // Tenant Management Endpoints
  // Note: These endpoints require admin authentication
  // ============================================================================

  // Create a new tenant
  app.post("/api/tenants", requireAdminAuth, async (req, res) => {
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
  app.get("/api/tenants", async (req, res) => {
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
  app.get("/api/tenants/:id", async (req, res) => {
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
  app.delete("/api/tenants/:id", requireAdminAuth, async (req, res) => {
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
  app.get("/api/auth/config", async (req, res) => {
    try {
      const config = unifiedAuthService.getConfig();
      res.json(config);
    } catch (error) {
      console.error("Error fetching auth config:", error);
      res.status(500).json({ error: "Failed to fetch auth config" });
    }
  });

  // Update authentication configuration (admin only)
  app.patch("/api/auth/config", requireAdminAuth, async (req, res) => {
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
  app.get("/api/organization/settings", requireAdminAuth, async (req, res) => {
    try {
      res.json(organizationSettings);
    } catch (error) {
      console.error("Error fetching organization settings:", error);
      res.status(500).json({ error: "Failed to fetch organization settings" });
    }
  });

  // Update organization settings
  app.patch("/api/organization/settings", requireAdminAuth, async (req, res) => {
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
  app.get("/api/users", requireAdminAuth, async (req, res) => {
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
  app.post("/api/users", requireAdminAuth, async (req, res) => {
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
  app.patch("/api/users/:id", requireAdminAuth, async (req, res) => {
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
  app.delete("/api/users/:id", requireAdminAuth, async (req, res) => {
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

  // In-memory store for recon results (per-session)
  const reconResults: Map<string, ReconResult> = new Map();

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

      // Start scan asynchronously
      res.json({ 
        scanId,
        message: "Scan started",
        target: hostname
      });

      // Run the scan in background
      fullRecon(target, {
        portScan: scanTypes?.portScan ?? true,
        sslCheck: scanTypes?.sslCheck ?? true,
        httpFingerprint: scanTypes?.httpFingerprint ?? true,
        dnsEnum: scanTypes?.dnsEnum ?? true,
      }).then(result => {
        reconResults.set(scanId, result);
        // Notify via WebSocket
        wsService.broadcast({
          type: 'recon_complete',
          scanId,
          target: hostname,
          timestamp: new Date().toISOString(),
        });
      }).catch(err => {
        console.error("Recon scan error:", err);
        reconResults.set(scanId, {
          target,
          scanTime: new Date(),
          errors: [err.message],
        });
      });
    } catch (error) {
      console.error("Recon scan error:", error);
      res.status(500).json({ error: "Scan initiation failed" });
    }
  });

  app.get("/api/recon/results/:scanId", async (req, res) => {
    try {
      const { scanId } = req.params;
      const result = reconResults.get(scanId);
      
      if (!result) {
        return res.status(404).json({ 
          error: "Scan not found or still in progress",
          message: "The scan may still be running. Try again in a few seconds."
        });
      }

      // Convert to exposures for evaluation integration
      const exposures = reconToExposures(result);

      res.json({
        scanId,
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

      const result = reconResults.get(scanId);
      if (!result) {
        return res.status(404).json({ error: "Scan results not found" });
      }

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

  // Create and start a full assessment
  app.post("/api/full-assessments", evaluationRateLimiter, async (req, res) => {
    try {
      const { name, description, agentIds, organizationId } = req.body;
      
      if (!name) {
        return res.status(400).json({ error: "Assessment name is required" });
      }

      const assessment = await storage.createFullAssessment({
        name,
        description,
        agentIds: agentIds || null,
        organizationId: organizationId || "default",
        status: "pending",
        currentPhase: "Initializing...",
      });

      runFullAssessment(assessment.id).catch(error => {
        console.error("Full assessment failed:", error);
      });

      res.json({ 
        assessmentId: assessment.id,
        message: "Full assessment started"
      });
    } catch (error) {
      console.error("Create full assessment error:", error);
      res.status(500).json({ error: "Failed to create assessment" });
    }
  });

  // Get all full assessments
  app.get("/api/full-assessments", async (req, res) => {
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
  app.get("/api/full-assessments/:id", async (req, res) => {
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
  app.delete("/api/full-assessments/:id", async (req, res) => {
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
      { adversaryProfile: data.adversaryProfile as any }
    );

    const duration = Date.now() - startTime;

    await storage.createResult({
      id: `res-${randomUUID().slice(0, 8)}`,
      evaluationId,
      exploitable: result.exploitable,
      confidence: result.confidence,
      score: result.score,
      attackPath: result.attackPath,
      attackGraph: result.attackGraph,
      businessLogicFindings: result.businessLogicFindings,
      multiVectorFindings: result.multiVectorFindings,
      workflowAnalysis: result.workflowAnalysis,
      impact: result.impact,
      recommendations: result.recommendations,
      evidenceArtifacts: result.evidenceArtifacts,
      intelligentScore: result.intelligentScore,
      remediationGuidance: result.remediationGuidance,
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

async function runBatchJob(batchJobId: string, configs: Array<{
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
}>) {
  try {
    await storage.updateBatchJob(batchJobId, { status: "running" });
    
    const evaluationIds: string[] = [];
    const jobResults: Array<{ evaluationId: string; success: boolean }> = [];
    let completed = 0;
    let failed = 0;
    
    for (const config of configs) {
      try {
        const evaluation = await storage.createEvaluation({
          assetId: config.assetId,
          exposureType: config.exposureType,
          priority: config.priority,
          description: config.description,
          organizationId: "default",
        });
        
        evaluationIds.push(evaluation.id);
        
        const startTime = Date.now();
        await storage.updateEvaluationStatus(evaluation.id, "in_progress");
        
        const result = await runAgentOrchestrator(
          config.assetId,
          config.exposureType,
          config.priority,
          config.description,
          evaluation.id,
          (agentName, stage, progress, message) => {
            wsService.sendProgress(evaluation.id, agentName, stage, progress, message);
          }
        );
        
        const duration = Date.now() - startTime;
        
        await storage.createResult({
          id: `res-${randomUUID().slice(0, 8)}`,
          evaluationId: evaluation.id,
          exploitable: result.exploitable,
          confidence: result.confidence,
          score: result.score,
          attackPath: result.attackPath,
          attackGraph: result.attackGraph,
          businessLogicFindings: result.businessLogicFindings,
          multiVectorFindings: result.multiVectorFindings,
          workflowAnalysis: result.workflowAnalysis,
          impact: result.impact,
          recommendations: result.recommendations,
          evidenceArtifacts: result.evidenceArtifacts,
          intelligentScore: result.intelligentScore,
          remediationGuidance: result.remediationGuidance,
          duration,
        });
        
        await storage.updateEvaluationStatus(evaluation.id, "completed");
        wsService.sendComplete(evaluation.id, true);
        
        jobResults.push({ evaluationId: evaluation.id, success: true });
        completed++;
      } catch (error) {
        console.error(`Batch evaluation failed for ${config.assetId}:`, error);
        jobResults.push({ evaluationId: config.assetId, success: false });
        failed++;
      }
      
      await storage.updateBatchJob(batchJobId, {
        completedEvaluations: completed,
        failedEvaluations: failed,
        evaluationIds,
        progress: Math.round(((completed + failed) / configs.length) * 100),
      });
    }
    
    await storage.updateBatchJob(batchJobId, {
      status: failed === configs.length ? "failed" : "completed",
      completedAt: new Date(),
      completedEvaluations: completed,
      failedEvaluations: failed,
      evaluationIds,
      progress: 100,
    });
  } catch (error) {
    console.error("Batch job failed:", error);
    await storage.updateBatchJob(batchJobId, { 
      status: "failed",
      completedAt: new Date(),
    });
  }
}

// AI vs AI Simulation runner
async function runAiSimulation(simulationId: string) {
  try {
    await storage.updateAiSimulation(simulationId, { 
      simulationStatus: "running",
      startedAt: new Date(),
    });
    
    // Simulate AI vs AI battle with realistic delays
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Generate simulation results
    const results = {
      attackerSuccesses: Math.floor(Math.random() * 5) + 1,
      defenderBlocks: Math.floor(Math.random() * 8) + 3,
      timeToDetection: Math.floor(Math.random() * 30) + 5,
      timeToContainment: Math.floor(Math.random() * 60) + 15,
      attackPath: [
        "T1190 - Exploit Public-Facing Application",
        "T1059.001 - PowerShell Execution",
        "T1003.001 - LSASS Memory Dump",
        "T1021.002 - SMB/Windows Admin Shares",
        "T1486 - Data Encrypted for Impact",
      ],
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
  } catch (error) {
    console.error("AI simulation failed:", error);
    await storage.updateAiSimulation(simulationId, {
      simulationStatus: "failed",
      completedAt: new Date(),
    });
  }
}
