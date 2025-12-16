import { storage } from "../storage";
import OpenAI from "openai";
import type { 
  ExecutiveSummary, 
  TechnicalReport, 
  ComplianceReport,
  ReportFinding,
  AttackPathStep,
  ComplianceFramework,
  ReportType,
} from "@shared/schema";

// Create OpenAI client lazily to handle missing API key gracefully
let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI | null {
  if (openaiClient) return openaiClient;
  
  const apiKey = process.env.AI_INTEGRATIONS_OPENAI_API_KEY;
  if (!apiKey) {
    console.warn("OpenAI API key not configured - reports will use templated narratives");
    return null;
  }
  
  openaiClient = new OpenAI({
    apiKey,
    baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  });
  
  return openaiClient;
}

interface AIResponse {
  executiveSummary: string;
  findings: Array<{title: string; description: string; recommendation: string}>;
  recommendations: string[];
}

export class ReportGenerator {
  
  private generateTemplatedNarrative(
    reportType: "executive" | "technical" | "compliance",
    data: any
  ): AIResponse {
    const templates = {
      executive: {
        executiveSummary: `During the assessment period, ${data.metrics?.totalEvaluations || 0} security evaluations were conducted. ${data.metrics?.exploitableFindings || 0} exploitable vulnerabilities were identified, with ${data.metrics?.criticalFindings || 0} classified as critical. The overall risk level is ${data.overallRiskLevel?.toUpperCase() || "UNKNOWN"}. Immediate action is recommended for critical findings to prevent potential security incidents and business impact.`,
        findings: (data.topRisks || []).slice(0, 5).map((r: any) => ({
          title: `Security Issue: ${r.assetId || "Unknown Asset"}`,
          description: r.riskDescription || "Security vulnerability requiring attention",
          recommendation: "Remediate according to priority and business impact assessment"
        })),
        recommendations: [
          "Address critical vulnerabilities within 24-48 hours",
          "Implement compensating controls for high-risk findings",
          "Schedule regular security assessments to maintain posture"
        ]
      },
      technical: {
        executiveSummary: `Technical security assessment identified ${data.findingsCount || 0} findings across the evaluated assets. ${data.attackPathsCount || 0} exploitable attack paths were documented. Vulnerability distribution shows ${JSON.stringify(data.vulnerabilityBreakdown?.bySeverity || {})}. Technical remediation guidance is provided for each finding.`,
        findings: (data.topFindings || []).slice(0, 5).map((f: any) => ({
          title: f.title || "Technical Finding",
          description: f.description || "Technical vulnerability requiring remediation",
          recommendation: f.recommendation || "Apply vendor patches and configuration hardening"
        })),
        recommendations: [
          "Apply security patches to affected systems",
          "Implement network segmentation to limit lateral movement",
          "Enable enhanced logging and monitoring for affected assets"
        ]
      },
      compliance: {
        executiveSummary: `Compliance assessment against ${data.framework?.toUpperCase() || "framework"} shows ${data.overallCompliance || 0}% overall compliance. ${data.gaps?.length || 0} control gaps were identified requiring remediation. Audit readiness score is ${data.auditReadiness?.score || 0}%. Priority actions should focus on addressing control gaps to improve compliance posture.`,
        findings: (data.gaps || []).slice(0, 5).map((g: any) => ({
          title: `Control Gap: ${g.controlId || "Unknown Control"}`,
          description: g.gapDescription || "Compliance control gap requiring attention",
          recommendation: g.remediationGuidance || "Implement required controls to achieve compliance"
        })),
        recommendations: [
          "Prioritize remediation of non-compliant controls",
          "Document compensating controls for gaps that cannot be immediately addressed",
          "Schedule follow-up assessment to verify remediation effectiveness"
        ]
      }
    };
    
    return templates[reportType];
  }
  
  private async generateAINarrative(
    reportType: "executive" | "technical" | "compliance",
    data: any
  ): Promise<AIResponse> {
    const client = getOpenAIClient();
    
    // Fall back to templated narratives if OpenAI is not available
    if (!client) {
      return this.generateTemplatedNarrative(reportType, data);
    }
    
    try {
      const prompts = {
        executive: `You are a cybersecurity executive advisor writing a security report for C-suite executives and board members.

Based on the following security assessment data, write a comprehensive executive summary in natural language:

${JSON.stringify(data, null, 2)}

Provide your response as JSON with this exact structure (no additional fields):
{
  "executiveSummary": "A 2-3 paragraph executive summary written in clear, non-technical language suitable for executives. Include overall risk posture, key concerns, and strategic recommendations.",
  "findings": [
    {"title": "Finding title", "description": "Clear description of the security issue and its business impact", "recommendation": "Recommended action to address this"}
  ],
  "recommendations": ["Strategic recommendation 1", "Strategic recommendation 2", "Strategic recommendation 3"]
}

Focus on business impact, financial risk, and strategic priorities. Avoid technical jargon. Limit findings to maximum 5 items.`,

        technical: `You are a senior security engineer writing a technical security report.

Based on the following security assessment data, write detailed technical findings:

${JSON.stringify(data, null, 2)}

Provide your response as JSON with this exact structure (no additional fields):
{
  "executiveSummary": "A technical summary of the security assessment covering methodology, scope, and key technical findings.",
  "findings": [
    {"title": "Technical finding title", "description": "Detailed technical description including attack vectors, CVE references, and exploitation details", "recommendation": "Specific technical remediation steps"}
  ],
  "recommendations": ["Technical recommendation 1", "Technical recommendation 2", "Technical recommendation 3"]
}

Include specific technical details, attack paths, and concrete remediation steps. Limit findings to maximum 10 items.`,

        compliance: `You are a compliance and audit specialist writing a compliance assessment report.

Based on the following compliance assessment data, write a compliance-focused report:

${JSON.stringify(data, null, 2)}

Provide your response as JSON with this exact structure (no additional fields):
{
  "executiveSummary": "A compliance summary covering audit readiness, control gaps, and remediation priorities for the specified framework.",
  "findings": [
    {"title": "Compliance gap title", "description": "Description of the control gap and its compliance implications", "recommendation": "Steps to achieve compliance"}
  ],
  "recommendations": ["Compliance recommendation 1", "Compliance recommendation 2", "Compliance recommendation 3"]
}

Focus on regulatory requirements, control effectiveness, and audit readiness. Limit findings to maximum 5 items.`
      };

      const response = await client.chat.completions.create({
        model: "gpt-4o",
        messages: [
          { role: "system", content: "You are a cybersecurity report writer. Always respond with valid JSON matching the exact schema requested. Never include extra fields." },
          { role: "user", content: prompts[reportType] }
        ],
        response_format: { type: "json_object" },
        temperature: 0.7,
        max_tokens: 2500,
      });

      const content = response.choices[0].message.content;
      if (!content) {
        throw new Error("No response from AI");
      }

      const parsed = JSON.parse(content);
      
      // Validate and sanitize the AI response
      const validated: AIResponse = {
        executiveSummary: typeof parsed.executiveSummary === "string" 
          ? parsed.executiveSummary 
          : this.generateTemplatedNarrative(reportType, data).executiveSummary,
        findings: Array.isArray(parsed.findings) 
          ? parsed.findings.slice(0, 10).map((f: any) => ({
              title: String(f.title || "Untitled Finding"),
              description: String(f.description || "No description provided"),
              recommendation: String(f.recommendation || "Review and remediate")
            }))
          : [],
        recommendations: Array.isArray(parsed.recommendations) 
          ? parsed.recommendations.slice(0, 5).map((r: any) => String(r))
          : this.generateTemplatedNarrative(reportType, data).recommendations
      };
      
      return validated;
    } catch (error) {
      console.error("AI narrative generation failed, using template:", error);
      return this.generateTemplatedNarrative(reportType, data);
    }
  }

  async generateExecutiveSummary(
    from: Date,
    to: Date,
    organizationId: string = "default"
  ): Promise<ExecutiveSummary> {
    const evaluations = await storage.getEvaluationsByDateRange(from, to, organizationId);
    const evaluationIds = evaluations.map(e => e.id);
    const results = await storage.getResultsByEvaluationIds(evaluationIds);
    
    const resultsMap = new Map(results.map(r => [r.evaluationId, r]));
    
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let exploitableCount = 0;
    let totalScore = 0;
    let totalConfidence = 0;
    let scoredCount = 0;
    
    const topRisks: ExecutiveSummary["topRisks"] = [];
    
    for (const evaluation of evaluations) {
      const result = resultsMap.get(evaluation.id);
      
      switch (evaluation.priority) {
        case "critical": criticalCount++; break;
        case "high": highCount++; break;
        case "medium": mediumCount++; break;
        case "low": lowCount++; break;
      }
      
      if (result) {
        if (result.exploitable) {
          exploitableCount++;
          
          const intelligentScore = result.intelligentScore as any;
          const financialExposure = intelligentScore?.businessImpact?.factors?.financialExposure;
          
          topRisks.push({
            assetId: evaluation.assetId,
            riskDescription: evaluation.description,
            severity: evaluation.priority as "critical" | "high" | "medium" | "low",
            financialImpact: financialExposure ? 
              `$${financialExposure.directLoss?.min?.toLocaleString() || 0} - $${financialExposure.directLoss?.max?.toLocaleString() || 0}` : 
              undefined,
          });
        }
        
        if (result.score) {
          totalScore += result.score;
          totalConfidence += result.confidence || 0;
          scoredCount++;
        }
      }
    }
    
    const sortedRisks = topRisks
      .sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      })
      .slice(0, 5);
    
    const overallRiskLevel: "critical" | "high" | "medium" | "low" = criticalCount > 0 ? "critical" :
      highCount > 0 ? "high" :
      mediumCount > 0 ? "medium" : "low";
    
    const recommendations: ExecutiveSummary["recommendations"] = [];
    
    if (criticalCount > 0) {
      recommendations.push({
        priority: 1,
        action: "Immediately remediate critical vulnerabilities",
        impact: `${criticalCount} critical findings require immediate attention`,
        effort: "high",
      });
    }
    
    if (exploitableCount > evaluations.length * 0.3) {
      recommendations.push({
        priority: 2,
        action: "Implement network segmentation and access controls",
        impact: "Reduce blast radius of potential compromises",
        effort: "medium",
      });
    }
    
    recommendations.push({
      priority: recommendations.length + 1,
      action: "Schedule recurring security assessments",
      impact: "Continuous monitoring for new vulnerabilities",
      effort: "low",
    });
    
    const baseNarrative = this.generateExecutiveNarrative(
      evaluations.length,
      exploitableCount,
      criticalCount,
      overallRiskLevel
    );
    
    const baseReport = {
      reportDate: new Date().toISOString(),
      reportPeriod: {
        from: from.toISOString(),
        to: to.toISOString(),
      },
      organizationId,
      overallRiskLevel,
      keyMetrics: {
        totalEvaluations: evaluations.length,
        exploitableFindings: exploitableCount,
        criticalFindings: criticalCount,
        highFindings: highCount,
        mediumFindings: mediumCount,
        lowFindings: lowCount,
        averageScore: scoredCount > 0 ? Math.round(totalScore / scoredCount) : 0,
        averageConfidence: scoredCount > 0 ? Math.round(totalConfidence / scoredCount) : 0,
      },
      riskTrend: "stable" as const,
      topRisks: sortedRisks,
      recommendations,
      executiveNarrative: baseNarrative,
    };

    // Generate AI-powered natural language content
    const aiNarrative = await this.generateAINarrative("executive", {
      metrics: baseReport.keyMetrics,
      topRisks: sortedRisks,
      recommendations,
      overallRiskLevel,
    });

    // Merge AI-generated content with safe severity mapping
    const defaultSeverity: "critical" | "high" | "medium" | "low" = "medium";
    const enrichedFindings = aiNarrative.findings.length > 0 
      ? aiNarrative.findings.map((f, i) => ({
          ...f,
          severity: sortedRisks[i]?.severity || defaultSeverity,
        }))
      : sortedRisks.map(r => ({
          title: `Risk: ${r.assetId}`,
          description: r.riskDescription,
          recommendation: "Immediate remediation recommended",
          severity: r.severity,
        }));

    return {
      ...baseReport,
      executiveSummary: aiNarrative.executiveSummary,
      executiveNarrative: aiNarrative.executiveSummary || baseNarrative,
      findings: enrichedFindings,
      recommendations: aiNarrative.recommendations.length > 0 
        ? aiNarrative.recommendations.map((r, i) => ({
            priority: i + 1,
            action: r,
            impact: "Improved security posture",
            effort: i === 0 ? "high" as const : i === 1 ? "medium" as const : "low" as const,
          }))
        : recommendations,
    };
  }
  
  async generateTechnicalReport(
    from: Date,
    to: Date,
    organizationId: string = "default"
  ): Promise<TechnicalReport> {
    const evaluations = await storage.getEvaluationsByDateRange(from, to, organizationId);
    const evaluationIds = evaluations.map(e => e.id);
    const results = await storage.getResultsByEvaluationIds(evaluationIds);
    
    const resultsMap = new Map(results.map(r => [r.evaluationId, r]));
    
    const findings: ReportFinding[] = [];
    const attackPaths: TechnicalReport["attackPaths"] = [];
    const technicalDetails: TechnicalReport["technicalDetails"] = [];
    
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byAsset: Record<string, number> = {};
    
    for (const evaluation of evaluations) {
      const result = resultsMap.get(evaluation.id);
      
      byType[evaluation.exposureType] = (byType[evaluation.exposureType] || 0) + 1;
      bySeverity[evaluation.priority] = (bySeverity[evaluation.priority] || 0) + 1;
      byAsset[evaluation.assetId] = (byAsset[evaluation.assetId] || 0) + 1;
      
      findings.push({
        id: evaluation.id,
        evaluationId: evaluation.id,
        assetId: evaluation.assetId,
        title: `${evaluation.exposureType.replace(/_/g, " ")} - ${evaluation.assetId}`,
        severity: evaluation.priority as "critical" | "high" | "medium" | "low",
        exploitable: result?.exploitable || false,
        score: result?.score || 0,
        description: evaluation.description,
        impact: result?.impact || undefined,
        recommendation: result?.recommendations?.[0]?.description,
      });
      
      if (result?.attackPath) {
        const attackGraph = result.attackGraph as any;
        attackPaths.push({
          evaluationId: evaluation.id,
          assetId: evaluation.assetId,
          steps: result.attackPath as AttackPathStep[],
          complexity: attackGraph?.complexityScore || 50,
          timeToCompromise: attackGraph?.timeToCompromise ? 
            `${attackGraph.timeToCompromise.expected} ${attackGraph.timeToCompromise.unit}` : 
            undefined,
        });
      }
      
      technicalDetails.push({
        evaluationId: evaluation.id,
        assetId: evaluation.assetId,
        exposureType: evaluation.exposureType,
        technicalAnalysis: result?.impact || evaluation.description,
        mitigations: result?.recommendations?.map(r => r.description) || [],
      });
    }
    
    const baseReport = {
      reportDate: new Date().toISOString(),
      reportPeriod: {
        from: from.toISOString(),
        to: to.toISOString(),
      },
      organizationId,
      findings,
      attackPaths,
      vulnerabilityBreakdown: {
        byType,
        bySeverity,
        byAsset,
      },
      technicalDetails,
    };

    // Generate AI-powered natural language content
    const aiNarrative = await this.generateAINarrative("technical", {
      findingsCount: findings.length,
      vulnerabilityBreakdown: { byType, bySeverity },
      attackPathsCount: attackPaths.length,
      topFindings: findings.slice(0, 5),
    });

    // Merge AI-generated content with enhanced findings
    const enhancedFindings = findings.map((f, i) => {
      const aiF = aiNarrative.findings[i];
      return {
        ...f,
        title: aiF?.title || f.title,
        description: aiF?.description || f.description,
        recommendation: aiF?.recommendation || f.recommendation,
      };
    });

    return {
      ...baseReport,
      executiveSummary: aiNarrative.executiveSummary,
      findings: enhancedFindings,
      recommendations: aiNarrative.recommendations,
    };
  }
  
  async generateComplianceReport(
    framework: ComplianceFramework,
    from: Date,
    to: Date,
    organizationId: string = "default"
  ): Promise<ComplianceReport> {
    const evaluations = await storage.getEvaluationsByDateRange(from, to, organizationId);
    const evaluationIds = evaluations.map(e => e.id);
    const results = await storage.getResultsByEvaluationIds(evaluationIds);
    
    const resultsMap = new Map(results.map(r => [r.evaluationId, r]));
    
    const controlMappings = this.getFrameworkControls(framework);
    const controlStatus: ComplianceReport["controlStatus"] = [];
    const gaps: ComplianceReport["gaps"] = [];
    
    let compliantControls = 0;
    
    for (const control of controlMappings) {
      const relatedFindings: string[] = [];
      let hasViolation = false;
      let maxSeverity: "critical" | "high" | "medium" | "low" = "low";
      
      for (const evaluation of evaluations) {
        const result = resultsMap.get(evaluation.id);
        const intelligentScore = result?.intelligentScore as any;
        const complianceImpact = intelligentScore?.businessImpact?.factors?.complianceImpact;
        
        if (complianceImpact?.affectedFrameworks?.includes(framework.toLowerCase())) {
          relatedFindings.push(evaluation.id);
          hasViolation = true;
          
          const violations = complianceImpact.violations || [];
          for (const v of violations) {
            if (v.severity === "critical" && maxSeverity !== "critical") maxSeverity = "critical";
            else if (v.severity === "major" && maxSeverity !== "critical") maxSeverity = "high";
          }
        }
      }
      
      const status = hasViolation ? "non_compliant" : "compliant";
      if (status === "compliant") compliantControls++;
      
      controlStatus.push({
        controlId: control.id,
        controlName: control.name,
        status,
        findings: relatedFindings,
        remediationRequired: hasViolation,
      });
      
      if (hasViolation) {
        gaps.push({
          controlId: control.id,
          gapDescription: `${control.name} has ${relatedFindings.length} finding(s) that may impact compliance`,
          severity: maxSeverity,
          remediationGuidance: `Review and remediate findings: ${relatedFindings.join(", ")}`,
        });
      }
    }
    
    const overallCompliance = Math.round((compliantControls / controlMappings.length) * 100);
    
    const baseReport = {
      reportDate: new Date().toISOString(),
      framework,
      organizationId,
      overallCompliance,
      controlStatus,
      gaps,
      auditReadiness: {
        score: overallCompliance,
        readyControls: compliantControls,
        totalControls: controlMappings.length,
        priorityActions: gaps.slice(0, 3).map(g => `Remediate ${g.controlId}: ${g.gapDescription}`),
      },
    };

    // Generate AI-powered natural language content
    const aiNarrative = await this.generateAINarrative("compliance", {
      framework,
      overallCompliance,
      gaps: gaps.slice(0, 5),
      controlStatus: controlStatus.slice(0, 10),
      auditReadiness: baseReport.auditReadiness,
    });

    // Create compliance findings from AI narrative
    const complianceFindings = aiNarrative.findings.length > 0
      ? aiNarrative.findings.map((f, i) => ({
          ...f,
          severity: gaps[i]?.severity || "medium" as const,
          status: "open" as const,
        }))
      : gaps.map(g => ({
          title: `Control Gap: ${g.controlId}`,
          description: g.gapDescription,
          recommendation: g.remediationGuidance,
          severity: g.severity,
          status: "open" as const,
        }));

    return {
      ...baseReport,
      executiveSummary: aiNarrative.executiveSummary,
      findings: complianceFindings,
      recommendations: aiNarrative.recommendations,
      complianceStatus: Object.fromEntries(
        controlStatus.map(c => [c.controlName, { status: c.status, coverage: c.status === "compliant" ? 100 : 0 }])
      ),
    };
  }
  
  exportToCSV(data: any[], headers: string[]): string {
    const headerRow = headers.join(",");
    const rows = data.map(item => 
      headers.map(h => {
        const value = item[h];
        if (value === null || value === undefined) return "";
        if (typeof value === "string" && (value.includes(",") || value.includes("\n"))) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return String(value);
      }).join(",")
    );
    return [headerRow, ...rows].join("\n");
  }
  
  exportToJSON(data: any): string {
    return JSON.stringify(data, null, 2);
  }
  
  private generateExecutiveNarrative(
    totalEvaluations: number,
    exploitableCount: number,
    criticalCount: number,
    overallRiskLevel: string
  ): string {
    const exploitablePercent = totalEvaluations > 0 ? 
      Math.round((exploitableCount / totalEvaluations) * 100) : 0;
    
    let narrative = `During the reporting period, ${totalEvaluations} security evaluations were conducted. `;
    
    if (exploitableCount === 0) {
      narrative += "No exploitable vulnerabilities were identified, indicating a strong security posture. ";
    } else {
      narrative += `${exploitableCount} (${exploitablePercent}%) of the evaluated exposures were found to be exploitable. `;
    }
    
    if (criticalCount > 0) {
      narrative += `Critical attention is required for ${criticalCount} critical finding${criticalCount > 1 ? "s" : ""} that pose${criticalCount === 1 ? "s" : ""} immediate risk to the organization. `;
    }
    
    switch (overallRiskLevel) {
      case "critical":
        narrative += "The overall risk posture is CRITICAL and requires immediate executive attention and resource allocation for remediation.";
        break;
      case "high":
        narrative += "The overall risk posture is HIGH. A prioritized remediation plan should be executed within the next 30 days.";
        break;
      case "medium":
        narrative += "The overall risk posture is MODERATE. Continued monitoring and scheduled remediation activities are recommended.";
        break;
      case "low":
        narrative += "The overall risk posture is LOW. Maintain current security practices and continue regular assessments.";
        break;
    }
    
    return narrative;
  }
  
  private getFrameworkControls(framework: ComplianceFramework): Array<{ id: string; name: string }> {
    const frameworkControls: Record<string, Array<{ id: string; name: string }>> = {
      soc2: [
        { id: "CC6.1", name: "Logical and Physical Access Controls" },
        { id: "CC6.6", name: "Logical Access Security Measures" },
        { id: "CC6.7", name: "System Boundary Protection" },
        { id: "CC7.1", name: "Detection and Monitoring" },
        { id: "CC7.2", name: "Security Incident Response" },
      ],
      pci_dss: [
        { id: "1.1", name: "Install and Maintain Network Security Controls" },
        { id: "2.1", name: "Apply Secure Configurations" },
        { id: "6.1", name: "Develop and Maintain Secure Systems" },
        { id: "10.1", name: "Log and Monitor Access" },
        { id: "11.1", name: "Test Security Regularly" },
      ],
      hipaa: [
        { id: "164.308(a)(1)", name: "Security Management Process" },
        { id: "164.308(a)(5)", name: "Security Awareness Training" },
        { id: "164.312(a)(1)", name: "Access Control" },
        { id: "164.312(b)", name: "Audit Controls" },
        { id: "164.312(d)", name: "Person or Entity Authentication" },
      ],
      gdpr: [
        { id: "Art.25", name: "Data Protection by Design" },
        { id: "Art.32", name: "Security of Processing" },
        { id: "Art.33", name: "Breach Notification" },
        { id: "Art.35", name: "Data Protection Impact Assessment" },
        { id: "Art.5", name: "Principles of Processing" },
      ],
      ccpa: [
        { id: "1798.100", name: "Consumer Right to Know" },
        { id: "1798.105", name: "Consumer Right to Delete" },
        { id: "1798.150", name: "Data Security Requirements" },
        { id: "1798.125", name: "Non-Discrimination" },
        { id: "1798.140", name: "Definition Compliance" },
      ],
      iso27001: [
        { id: "A.5", name: "Information Security Policies" },
        { id: "A.9", name: "Access Control" },
        { id: "A.12", name: "Operations Security" },
        { id: "A.14", name: "System Acquisition and Development" },
        { id: "A.16", name: "Security Incident Management" },
      ],
      nist_csf: [
        { id: "ID.AM", name: "Asset Management" },
        { id: "PR.AC", name: "Access Control" },
        { id: "DE.CM", name: "Continuous Monitoring" },
        { id: "RS.RP", name: "Response Planning" },
        { id: "RC.RP", name: "Recovery Planning" },
      ],
      fedramp: [
        { id: "AC-1", name: "Access Control Policy" },
        { id: "AU-1", name: "Audit and Accountability Policy" },
        { id: "CA-1", name: "Security Assessment Policy" },
        { id: "SC-1", name: "System and Communications Protection" },
        { id: "SI-1", name: "System and Information Integrity" },
      ],
    };
    
    return frameworkControls[framework] || [];
  }
}

export const reportGenerator = new ReportGenerator();
