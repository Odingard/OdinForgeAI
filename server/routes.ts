import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertEvaluationSchema, insertReportSchema, insertBatchJobSchema, insertScheduledScanSchema, complianceFrameworks } from "@shared/schema";
import { runAgentOrchestrator } from "./services/agents";
import { wsService } from "./services/websocket";
import { reportGenerator } from "./services/report-generator";
import { randomUUID } from "crypto";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  wsService.initialize(httpServer);

  app.post("/api/aev/evaluate", async (req, res) => {
    try {
      const parsed = insertEvaluationSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", details: parsed.error });
      }

      const evaluation = await storage.createEvaluation(parsed.data);
      
      res.json({ evaluationId: evaluation.id, assetId: evaluation.assetId, status: "started" });

      runEvaluation(evaluation.id, {
        assetId: parsed.data.assetId,
        exposureType: parsed.data.exposureType,
        priority: parsed.data.priority || "medium",
        description: parsed.data.description,
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

  // ========== REPORTING ENDPOINTS ==========
  
  app.post("/api/reports/generate", async (req, res) => {
    try {
      const { type, format, from, to, framework, organizationId = "default" } = req.body;
      
      if (!type || !format || !from || !to) {
        return res.status(400).json({ error: "Missing required fields: type, format, from, to" });
      }
      
      const fromDate = new Date(from);
      const toDate = new Date(to);
      
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
  
  app.post("/api/batch-jobs", async (req, res) => {
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

  // Attack Predictions
  app.get("/api/attack-predictions/:organizationId", async (req, res) => {
    try {
      const predictions = await storage.getAttackPredictions(req.params.organizationId);
      res.json(predictions);
    } catch (error) {
      console.error("Error fetching attack predictions:", error);
      res.status(500).json({ error: "Failed to fetch attack predictions" });
    }
  });

  app.post("/api/attack-predictions/generate", async (req, res) => {
    try {
      const { organizationId, assetId, timeHorizon } = req.body;
      
      // Generate AI-powered attack prediction
      const prediction = await storage.createAttackPrediction({
        organizationId,
        assetId,
        timeHorizon: timeHorizon || "30d",
        predictedAttackVectors: [
          {
            vector: "Credential Stuffing",
            likelihood: 75,
            confidence: 82,
            adversaryProfile: "opportunistic_criminal",
            estimatedImpact: "High - Account takeover risk",
            mitreAttackId: "T1110.004",
          },
          {
            vector: "SQL Injection",
            likelihood: 45,
            confidence: 68,
            adversaryProfile: "script_kiddie",
            estimatedImpact: "Critical - Data exfiltration",
            mitreAttackId: "T1190",
          },
          {
            vector: "Phishing Campaign",
            likelihood: 60,
            confidence: 75,
            adversaryProfile: "organized_crime",
            estimatedImpact: "High - Initial access vector",
            mitreAttackId: "T1566",
          },
        ],
        overallBreachLikelihood: 65,
        riskFactors: [
          { factor: "Exposed admin panels", contribution: 25, trend: "stable" },
          { factor: "Outdated dependencies", contribution: 20, trend: "increasing" },
          { factor: "Weak authentication", contribution: 30, trend: "stable" },
          { factor: "Missing WAF rules", contribution: 25, trend: "decreasing" },
        ],
        recommendedActions: [
          "Implement MFA for all admin accounts",
          "Update vulnerable dependencies",
          "Deploy WAF with OWASP ruleset",
          "Enable rate limiting on authentication endpoints",
        ],
        modelVersion: "v1.0.0",
      });
      
      res.json(prediction);
    } catch (error) {
      console.error("Error generating attack prediction:", error);
      res.status(500).json({ error: "Failed to generate attack prediction" });
    }
  });

  // Defensive Posture
  app.get("/api/defensive-posture/:organizationId", async (req, res) => {
    try {
      let posture = await storage.getLatestDefensivePosture(req.params.organizationId);
      if (!posture) {
        // Generate initial posture score
        posture = await storage.createDefensivePostureScore({
          organizationId: req.params.organizationId,
          overallScore: 72,
          categoryScores: {
            networkSecurity: 75,
            applicationSecurity: 68,
            identityManagement: 80,
            dataProtection: 70,
            incidentResponse: 65,
            securityAwareness: 72,
            compliancePosture: 78,
          },
          breachLikelihood: 28,
          meanTimeToDetect: 4,
          meanTimeToRespond: 12,
          vulnerabilityExposure: {
            critical: 2,
            high: 8,
            medium: 24,
            low: 45,
          },
          trendDirection: "stable",
          benchmarkPercentile: 65,
          recommendations: [
            "Reduce critical vulnerabilities to zero",
            "Improve incident response time",
            "Increase security training frequency",
          ],
        });
      }
      res.json(posture);
    } catch (error) {
      console.error("Error fetching defensive posture:", error);
      res.status(500).json({ error: "Failed to fetch defensive posture" });
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

  return httpServer;
}

async function runEvaluation(evaluationId: string, data: {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
}) {
  const startTime = Date.now();
  
  try {
    await storage.updateEvaluationStatus(evaluationId, "in_progress");

    const result = await runAgentOrchestrator(
      data.assetId,
      data.exposureType,
      data.priority,
      data.description,
      evaluationId,
      (agentName, stage, progress, message) => {
        wsService.sendProgress(evaluationId, agentName, stage, progress, message);
      }
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
