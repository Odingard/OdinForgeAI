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
