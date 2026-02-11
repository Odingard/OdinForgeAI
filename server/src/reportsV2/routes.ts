/**
 * Report V2 API Routes
 * 
 * Endpoints for AI-generated narrative pentest reports.
 */

import type { Express, Request, Response } from "express";
import { z } from "zod";
import { randomUUID } from "crypto";
import { storage } from "../../storage";
import { isFeatureEnabled } from "../../feature-flags";
import { generateFullReport, generateENO } from "./narrativeEngine";
import { buildReportInputFromEvaluation, buildReportInputFromEvaluations } from "./reportInputBuilder";
import { antiTemplateLint, lintReportSection } from "./antiTemplateLint";
import { reportGenerator } from "../../services/report-generator";
import { reportRateLimiter } from "../../services/rate-limiter";

// Engagement metadata schema for consulting-grade reports
const engagementMetadataRequestSchema = z.object({
  clientName: z.string().optional(),
  assessmentPeriod: z.object({
    startDate: z.string(),
    endDate: z.string(),
  }).optional(),
  methodology: z.object({
    framework: z.enum(["OWASP", "PTES", "NIST", "OSSTMM", "ISSAF", "custom"]).optional(),
    testingApproach: z.enum(["black_box", "gray_box", "white_box"]).optional(),
  }).optional(),
  assessmentTeam: z.array(z.object({
    name: z.string(),
    role: z.string(),
    credentials: z.array(z.string()).optional(),
  })).optional(),
}).optional();

// Validation schemas
const generateReportV2Schema = z.object({
  evaluationId: z.string().optional(),
  evaluationIds: z.array(z.string()).optional(),
  dateRange: z.object({
    from: z.string(),
    to: z.string(),
  }).optional(),
  reportTypes: z.array(z.enum(["executive", "technical", "compliance", "evidence", "breach_validation"])).min(1),
  reportVersion: z.literal("v2_narrative"),
  organizationId: z.string().optional(),
  customerContext: z.object({
    industry: z.string().optional(),
    primaryDataTypes: z.array(z.enum(["PII", "PCI", "PHI", "IP", "FINANCIAL", "CLASSIFIED"])).optional(),
    criticalSystems: z.array(z.string()).optional(),
    riskTolerance: z.enum(["low", "medium", "high"]).optional(),
  }).optional(),
  engagementMetadata: engagementMetadataRequestSchema,
  // Breach chain ID for breach_validation report type
  breachChainId: z.string().optional(),
});

const regenerateReportV2Schema = z.object({
  customerContext: z.object({
    industry: z.string().optional(),
    primaryDataTypes: z.array(z.enum(["PII", "PCI", "PHI", "IP", "FINANCIAL", "CLASSIFIED"])).optional(),
    criticalSystems: z.array(z.string()).optional(),
    riskTolerance: z.enum(["low", "medium", "high"]).optional(),
  }).optional(),
  focusAreas: z.array(z.string()).optional(),
  reportTypes: z.array(z.enum(["executive", "technical", "compliance", "evidence", "breach_validation"])).optional(),
});

/**
 * Register V2 report routes
 */
export function registerReportV2Routes(app: Express): void {
  
  /**
   * GET /api/reports/v2/feature-status
   * Check if V2 reports are enabled for the organization
   */
  app.get("/api/reports/v2/feature-status", async (req: Request, res: Response) => {
    try {
      const organizationId = (req.query.organizationId as string) || "default";
      const enabled = isFeatureEnabled("REPORTS_V2_NARRATIVE", organizationId);
      res.json({ enabled, organizationId });
    } catch (error) {
      res.status(500).json({ error: "Failed to check feature status" });
    }
  });

  /**
   * POST /api/reports/v2/generate
   * Generate a new V2 narrative report
   */
  app.post("/api/reports/v2/generate", reportRateLimiter, async (req: Request, res: Response) => {
    try {
      // Check feature flag
      const organizationId = req.body.organizationId || "default";
      if (!isFeatureEnabled("REPORTS_V2_NARRATIVE", organizationId)) {
        return res.status(403).json({ 
          error: "Report V2 Narrative feature is not enabled for this organization" 
        });
      }
      
      // Validate request
      const parsed = generateReportV2Schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ 
          error: "Invalid request body", 
          details: parsed.error.errors 
        });
      }
      
      const { evaluationId, evaluationIds, dateRange, reportTypes, customerContext, breachChainId } = parsed.data;
      
      // Determine scope and get evaluations
      let evaluationsWithResults: Array<{ evaluation: any; result: any }> = [];

      // Parse date range once (if provided) for consistent UTC handling
      let parsedFrom: Date | null = null;
      let parsedTo: Date | null = null;
      if (dateRange) {
        parsedFrom = new Date(dateRange.from);
        parsedFrom.setUTCHours(0, 0, 0, 0);
        parsedTo = new Date(dateRange.to);
        parsedTo.setUTCHours(23, 59, 59, 999);
      }

      if (evaluationId) {
        // Single evaluation
        const evaluation = await storage.getEvaluation(evaluationId);
        if (!evaluation) {
          return res.status(404).json({ error: `Evaluation ${evaluationId} not found` });
        }
        const result = await storage.getResultByEvaluationId(evaluationId);
        evaluationsWithResults = [{ evaluation, result }];
        // Use evaluation date for single-eval reports
        if (!parsedFrom) {
          const evalDate = evaluation.createdAt ? new Date(evaluation.createdAt) : new Date();
          parsedFrom = evalDate;
          parsedTo = evalDate;
        }
      } else if (evaluationIds && evaluationIds.length > 0) {
        // Multiple evaluations
        for (const id of evaluationIds) {
          const evaluation = await storage.getEvaluation(id);
          if (evaluation) {
            const result = await storage.getResultByEvaluationId(id);
            evaluationsWithResults.push({ evaluation, result });
          }
        }
      } else if (parsedFrom && parsedTo) {
        // Date range
        const evaluations = await storage.getEvaluationsByDateRange(parsedFrom, parsedTo, organizationId);
        for (const evaluation of evaluations) {
          const result = await storage.getResultByEvaluationId(evaluation.id);
          evaluationsWithResults.push({ evaluation, result });
        }
      } else {
        return res.status(400).json({
          error: "Must provide evaluationId, evaluationIds, or dateRange"
        });
      }
      
      if (evaluationsWithResults.length === 0) {
        return res.status(404).json({ error: "No evaluations found matching criteria" });
      }
      
      // Build input payload
      const inputPayload = evaluationsWithResults.length === 1
        ? buildReportInputFromEvaluation(
            evaluationsWithResults[0].evaluation,
            evaluationsWithResults[0].result,
            customerContext
          )
        : buildReportInputFromEvaluations(
            evaluationsWithResults,
            customerContext,
            parsedFrom && parsedTo ? { from: parsedFrom, to: parsedTo } : undefined
          );
      
      // Compute Breach Realization Score if breach_validation report requested
      let breachScoreJson: string | undefined;
      if (reportTypes.includes("breach_validation")) {
        const { computeBreachRealizationScore } = await import("../../services/report-logic");

        // Build evaluation/result maps for BRS computation
        const evalDataForBRS = evaluationsWithResults.map(er => ({
          id: er.evaluation.id,
          assetId: er.evaluation.assetId,
          exposureType: er.evaluation.exposureType,
          priority: er.evaluation.priority,
          description: er.evaluation.description || "",
        }));
        const resultMapForBRS = new Map<string, any>();
        evaluationsWithResults.forEach(er => {
          if (er.result) resultMapForBRS.set(er.evaluation.id, er.result);
        });

        // Load breach chain data if provided
        let breachChainData: any;
        if (breachChainId) {
          const chain = await storage.getBreachChain(breachChainId);
          if (chain) {
            breachChainData = {
              domainsBreached: Array.isArray(chain.domainsBreached) ? chain.domainsBreached.length : 0,
              totalDomains: 6,
              maxPrivilegeAchieved: chain.maxPrivilegeAchieved || "",
              totalAssetsCompromised: chain.totalAssetsCompromised || 0,
              totalCredentialsHarvested: chain.totalCredentialsHarvested || 0,
              durationMs: chain.durationMs || undefined,
              phaseResults: Array.isArray(chain.phaseResults) ? chain.phaseResults : [],
            };
          }
        }

        const brs = computeBreachRealizationScore(evalDataForBRS, resultMapForBRS, breachChainData);
        breachScoreJson = JSON.stringify(brs, null, 2);
      }

      // Generate report
      const reportResult = await generateFullReport(inputPayload, reportTypes, {}, breachScoreJson);
      
      if (!reportResult.success || !reportResult.report) {
        // Fallback to V1 if V2 generation fails
        if (evaluationsWithResults.length === 1 && evaluationId) {
          const v1Report = await reportGenerator.generateEnhancedReport(evaluationId, {
            includeKillChain: true,
            includeRemediation: true,
            includeVulnerabilityDetails: true,
          });
          
          return res.json({
            success: true,
            reportId: randomUUID(),
            reportVersion: "v1_template",
            fallbackReason: reportResult.errors.join("; "),
            sections: ["v1_enhanced"],
            report: v1Report,
            warnings: ["V2 generation failed, returned V1 enhanced report as fallback"],
          });
        }
        
        return res.status(500).json({
          success: false,
          error: "Failed to generate V2 report",
          details: reportResult.errors,
          warnings: reportResult.warnings,
        });
      }
      
      // Create report ID and store
      const reportId = randomUUID();
      
      // Store ENO in report_narratives table
      await storage.createReportNarrative({
        id: randomUUID(),
        organizationId,
        evaluationId: evaluationId || null,
        reportScopeId: evaluationIds?.join(",") || null,
        reportVersion: "v2_narrative",
        enoJson: reportResult.report.eno,
        modelMeta: reportResult.report.eno.modelMeta,
        createdBy: "system",
      });
      
      // Store full report
      const sectionsGenerated = [];
      if (reportResult.report.executive) sectionsGenerated.push("executive");
      if (reportResult.report.technical) sectionsGenerated.push("technical");
      if (reportResult.report.compliance) sectionsGenerated.push("compliance");
      if (reportResult.report.evidence) sectionsGenerated.push("evidence");
      if (reportResult.report.breach_validation) sectionsGenerated.push("breach_validation");

      await storage.createReport({
        id: reportId,
        organizationId,
        reportType: sectionsGenerated.join(","),
        reportVersion: "v2_narrative",
        title: `V2 Narrative Report - ${new Date().toISOString().split("T")[0]}`,
        dateRangeFrom: parsedFrom || new Date(),
        dateRangeTo: parsedTo || new Date(),
        status: "completed",
        content: reportResult.report,
        evaluationIds: evaluationsWithResults.map(e => e.evaluation.id),
        generatedBy: "system",
      } as any);
      
      res.json({
        success: true,
        reportId,
        reportVersion: "v2_narrative",
        sectionsGenerated,
        report: reportResult.report,
        warnings: reportResult.warnings,
      });
      
    } catch (error: any) {
      console.error("Error generating V2 report:", error);
      res.status(500).json({ 
        error: "Failed to generate V2 report",
        message: error.message 
      });
    }
  });
  
  /**
   * GET /api/reports/v2/:id
   * Fetch a V2 report by ID
   */
  app.get("/api/reports/v2/:id", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      
      const report = await storage.getReport(id);
      if (!report) {
        return res.status(404).json({ error: "Report not found" });
      }
      
      if (report.reportVersion !== "v2_narrative") {
        return res.status(400).json({ 
          error: "This is not a V2 narrative report",
          reportVersion: report.reportVersion 
        });
      }
      
      res.json({
        success: true,
        report,
      });
      
    } catch (error: any) {
      console.error("Error fetching V2 report:", error);
      res.status(500).json({ error: "Failed to fetch report" });
    }
  });
  
  /**
   * POST /api/reports/v2/:id/regenerate
   * Regenerate a V2 report with updated context
   */
  app.post("/api/reports/v2/:id/regenerate", reportRateLimiter, async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      
      // Check feature flag
      const organizationId = req.body.organizationId || "default";
      if (!isFeatureEnabled("REPORTS_V2_NARRATIVE", organizationId)) {
        return res.status(403).json({ 
          error: "Report V2 Narrative feature is not enabled" 
        });
      }
      
      // Validate request
      const parsed = regenerateReportV2Schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ 
          error: "Invalid request body", 
          details: parsed.error.errors 
        });
      }
      
      // Get original report
      const originalReport = await storage.getReport(id);
      if (!originalReport) {
        return res.status(404).json({ error: "Report not found" });
      }
      
      const evaluationIds = originalReport.evaluationIds || [];
      if (evaluationIds.length === 0) {
        return res.status(400).json({ error: "Original report has no evaluation IDs" });
      }
      
      // Get evaluations
      const evaluationsWithResults: Array<{ evaluation: any; result: any }> = [];
      for (const evalId of evaluationIds) {
        const evaluation = await storage.getEvaluation(evalId);
        if (evaluation) {
          const result = await storage.getResultByEvaluationId(evalId);
          evaluationsWithResults.push({ evaluation, result });
        }
      }
      
      if (evaluationsWithResults.length === 0) {
        return res.status(404).json({ error: "No evaluations found" });
      }
      
      // Build input with updated context
      const inputPayload = evaluationsWithResults.length === 1
        ? buildReportInputFromEvaluation(
            evaluationsWithResults[0].evaluation,
            evaluationsWithResults[0].result,
            parsed.data.customerContext
          )
        : buildReportInputFromEvaluations(
            evaluationsWithResults,
            parsed.data.customerContext
          );
      
      // Regenerate report
      const reportTypes = parsed.data.reportTypes || ["executive", "technical", "compliance", "evidence"];
      const reportResult = await generateFullReport(inputPayload, reportTypes);
      
      if (!reportResult.success || !reportResult.report) {
        return res.status(500).json({
          success: false,
          error: "Failed to regenerate V2 report",
          details: reportResult.errors,
          warnings: reportResult.warnings,
        });
      }
      
      // Create new report ID
      const newReportId = randomUUID();
      
      // Store new ENO
      await storage.createReportNarrative({
        id: randomUUID(),
        organizationId: originalReport.organizationId,
        evaluationId: evaluationIds.length === 1 ? evaluationIds[0] : null,
        reportScopeId: evaluationIds.length > 1 ? evaluationIds.join(",") : null,
        reportVersion: "v2_narrative",
        enoJson: reportResult.report.eno,
        modelMeta: reportResult.report.eno.modelMeta,
        createdBy: "system",
      });
      
      // Store regenerated report
      const sectionsGenerated = [];
      if (reportResult.report.executive) sectionsGenerated.push("executive");
      if (reportResult.report.technical) sectionsGenerated.push("technical");
      if (reportResult.report.compliance) sectionsGenerated.push("compliance");
      if (reportResult.report.evidence) sectionsGenerated.push("evidence");
      if (reportResult.report.breach_validation) sectionsGenerated.push("breach_validation");

      await storage.createReport({
        id: newReportId,
        organizationId: originalReport.organizationId,
        reportType: sectionsGenerated.join(","),
        reportVersion: "v2_narrative",
        title: `V2 Narrative Report (Regenerated) - ${new Date().toISOString().split("T")[0]}`,
        dateRangeFrom: originalReport.dateRangeFrom,
        dateRangeTo: originalReport.dateRangeTo,
        status: "completed",
        content: reportResult.report,
        evaluationIds,
        generatedBy: "system",
      } as any);
      
      res.json({
        success: true,
        originalReportId: id,
        newReportId,
        reportVersion: "v2_narrative",
        sectionsGenerated,
        report: reportResult.report,
        warnings: reportResult.warnings,
      });
      
    } catch (error: any) {
      console.error("Error regenerating V2 report:", error);
      res.status(500).json({ 
        error: "Failed to regenerate report",
        message: error.message 
      });
    }
  });
  
  /**
   * GET /api/reports/v2/:id/eno
   * Get ENO (Engagement Narrative Object) for a report (admin only)
   */
  app.get("/api/reports/v2/:id/eno", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      
      const report = await storage.getReport(id);
      if (!report) {
        return res.status(404).json({ error: "Report not found" });
      }
      
      if (report.reportVersion !== "v2_narrative") {
        return res.status(400).json({ 
          error: "This is not a V2 narrative report" 
        });
      }
      
      const content = report.content as any;
      if (!content?.eno) {
        return res.status(404).json({ error: "ENO not found in report" });
      }
      
      res.json({
        success: true,
        eno: content.eno,
        modelMeta: content.eno.modelMeta,
      });
      
    } catch (error: any) {
      console.error("Error fetching ENO:", error);
      res.status(500).json({ error: "Failed to fetch ENO" });
    }
  });
  
  /**
   * POST /api/reports/v2/lint
   * Run anti-template linting on report content (for testing/debugging)
   */
  app.post("/api/reports/v2/lint", async (req: Request, res: Response) => {
    try {
      const { content, sectionName } = req.body;
      
      if (!content) {
        return res.status(400).json({ error: "Content is required" });
      }
      
      if (typeof content === "string") {
        // Lint a single section
        const result = lintReportSection(content, sectionName || "section");
        res.json({ success: true, lintResult: result });
      } else {
        // Lint an ENO object
        const result = antiTemplateLint(content);
        res.json({ success: true, lintResult: result });
      }
      
    } catch (error: any) {
      console.error("Error linting content:", error);
      res.status(500).json({ error: "Failed to lint content" });
    }
  });
}
