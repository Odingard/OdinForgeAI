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
  ExposureType,
} from "@shared/schema";
import {
  getVulnerabilityInfo,
  getRemediationGuidance,
  formatVulnerabilityName,
  formatVulnerabilityShortName,
  type VulnerabilityInfo,
  type RemediationGuidance,
} from "@shared/vulnerability-catalog";
import {
  buildKillChainVisualization,
  generateKillChainReportSection,
  generateTextualKillChainDiagram,
  generatePdfKillChainContent,
  type KillChainReportSection,
  type PdfKillChainContent,
} from "./kill-chain-graph";
import {
  computeExecutiveSummary,
  computeTechnicalReport,
  computeComplianceReport,
  formatRemediationSection,
  type EvaluationData,
  type ResultData,
  type ComputedExecutiveSummary,
  type ComputedTechnicalReport,
  type EvidenceArtifactData,
} from "./report-logic";

// Create OpenAI client lazily to handle missing API key gracefully
let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI | null {
  if (openaiClient) return openaiClient;
  
  const apiKey = process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.warn("OpenAI API key not configured - reports will use templated narratives");
    return null;
  }

  openaiClient = new OpenAI({
    apiKey,
    baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
    timeout: 90000, // 90 second timeout to prevent hanging
    maxRetries: 2,
  });
  
  return openaiClient;
}

interface AIResponse {
  executiveSummary: string;
  findings: Array<{title: string; description: string; recommendation: string}>;
  recommendations: string[];
}

export class ReportGenerator {
  
  private async fetchEvidenceForEvaluations(
    evaluations: Array<{ id: string; organizationId?: string }>
  ): Promise<EvidenceArtifactData[]> {
    if (evaluations.length === 0) {
      return [];
    }
    
    try {
      const artifacts: EvidenceArtifactData[] = [];
      
      for (const evaluation of evaluations) {
        if (!evaluation.organizationId) continue;
        
        const evalEvidence = await storage.getValidationEvidenceArtifactsByEvaluationId(
          evaluation.id,
          evaluation.organizationId
        );
        
        for (const artifact of evalEvidence) {
          artifacts.push({
            id: artifact.id,
            evaluationId: artifact.evaluationId || undefined,
            findingId: artifact.findingId || undefined,
            evidenceType: artifact.evidenceType,
            verdict: artifact.verdict,
            confidenceScore: artifact.confidenceScore || 0,
            targetUrl: artifact.targetUrl || "",
            observedBehavior: artifact.observedBehavior || "",
            capturedAt: artifact.capturedAt || new Date(),
            httpRequest: artifact.httpRequest as EvidenceArtifactData["httpRequest"],
            httpResponse: artifact.httpResponse as EvidenceArtifactData["httpResponse"],
          });
        }
      }
      
      return artifacts;
    } catch (error) {
      console.warn("[ReportGenerator] Failed to fetch evidence artifacts:", error);
      return [];
    }
  }
  
  private generateTemplatedNarrative(
    reportType: "executive" | "technical" | "compliance",
    data: any
  ): AIResponse {
    const totalEvals = data.metrics?.totalEvaluations || 0;
    const exploitableCount = data.metrics?.exploitableFindings || 0;
    const criticalCount = data.metrics?.criticalFindings || 0;
    const highCount = data.metrics?.highFindings || 0;
    const exploitableRate = totalEvals > 0 ? Math.round((exploitableCount / totalEvals) * 100) : 0;
    const riskLevel = data.overallRiskLevel?.toUpperCase() || "UNDETERMINED";

    const templates = {
      executive: {
        executiveSummary: `OdinForge's automated security assessment evaluated ${totalEvals} exposure${totalEvals !== 1 ? "s" : ""} across the organization's attack surface using a multi-agent AI analysis pipeline encompassing reconnaissance, exploit validation, lateral movement analysis, business logic testing, and impact assessment.\n\nThe assessment team determined the organization's overall security posture to be ${riskLevel}. Of the ${totalEvals} exposures evaluated, ${exploitableCount} (${exploitableRate}%) were confirmed exploitable through validated attack paths. ${criticalCount > 0 ? `${criticalCount} finding${criticalCount !== 1 ? "s" : ""} were classified as CRITICAL severity, presenting immediate risk to business operations and requiring emergency remediation.` : "No critical-severity findings were identified during this assessment period."} ${highCount > 0 ? `An additional ${highCount} HIGH severity finding${highCount !== 1 ? "s" : ""} require${highCount === 1 ? "s" : ""} prioritized remediation within 30 days.` : ""}\n\n${exploitableCount > 0 ? "Exploitable findings present material risk to business continuity, data confidentiality, and regulatory compliance. The assessment team recommends immediate deployment of compensating controls for critical findings while remediation is executed." : "The assessment did not identify exploitable attack paths during this evaluation period. The organization should maintain current security controls and continue regular assessment cycles to preserve this favorable posture."}\n\nThe assessment team recommends a phased remediation approach: immediate action on critical findings within 0-30 days, defense-in-depth hardening within 30-60 days, and strategic security program improvements within 60-90 days aligned to NIST CSF and ISO 27001 control frameworks.`,
        findings: (data.topRisks || []).slice(0, 5).map((r: any) => {
          const vulnInfo = r.exposureType ? getVulnerabilityInfo(r.exposureType) : null;
          return {
            title: `Exploitable Exposure: ${r.assetId || "Evaluated Asset"}${vulnInfo ? ` — ${vulnInfo.name}` : ""}`,
            description: `${r.riskDescription || "Security exposure confirmed exploitable during assessment."} This finding presents risk to business operations including potential financial exposure${r.financialImpact ? ` estimated at ${r.financialImpact}` : ""}, operational disruption, and regulatory compliance impact.`,
            recommendation: "Deploy compensating controls immediately while executing full remediation. Validate fix effectiveness through re-assessment of the affected attack surface."
          };
        }),
        recommendations: [
          "Immediate (0-30 days): Remediate critical and exploitable findings — deploy compensating controls, apply emergency patches, and restrict access to affected assets",
          "Short-term (30-60 days): Strengthen defense-in-depth posture — implement network segmentation, enhance monitoring and detection capabilities, and harden access controls across the attack surface",
          "Strategic (60-90 days): Mature the security program — establish continuous security validation processes, align controls to NIST CSF categories, and implement automated vulnerability management workflows"
        ]
      },
      technical: {
        executiveSummary: `This automated security assessment employed a multi-agent AI analysis pipeline consisting of six specialized agents: Reconnaissance (attack surface mapping), Exploit Validation (vulnerability confirmation), Lateral Movement (pivot path analysis), Business Logic (application-layer testing), Multi-Vector (chained attack identification), and Impact Assessment (business consequence analysis).\n\nThe assessment identified ${data.findingsCount || 0} finding${(data.findingsCount || 0) !== 1 ? "s" : ""} across the evaluated assets. ${data.attackPathsCount || 0} validated attack path${(data.attackPathsCount || 0) !== 1 ? "s" : ""} were documented with complete exploitation chains. Severity distribution: ${Object.entries(data.vulnerabilityBreakdown?.bySeverity || {}).map(([sev, count]) => `${String(sev).toUpperCase()}: ${count}`).join(", ") || "No severity data available"}. Vulnerability categories assessed: ${Object.entries(data.vulnerabilityBreakdown?.byType || {}).map(([type, count]) => `${type.replace(/_/g, " ")}: ${count}`).join(", ") || "No type data available"}.\n\nRemediation is prioritized by exploitability and business impact. Immediate actions target confirmed exploitable findings, short-term efforts focus on defense-in-depth improvements, and long-term recommendations address architectural security enhancements.`,
        findings: (data.topFindings || []).slice(0, 10).map((f: any) => {
          const vulnInfo = f.exposureType ? getVulnerabilityInfo(f.exposureType) : null;
          const cweRef = vulnInfo?.cweIds?.[0] ? ` | ${vulnInfo.cweIds[0]}` : "";
          const mitreRef = vulnInfo?.mitreTechniques?.[0] ? ` | MITRE: ${vulnInfo.mitreTechniques[0]}` : "";
          const severity = (f.severity || "MEDIUM").toUpperCase();
          return {
            title: `[${severity}] ${f.title || "Security Finding"}${cweRef}${mitreRef}`,
            description: `${f.description || "Vulnerability identified during automated assessment."} Asset: ${f.assetId || "N/A"}. Exploitable: ${f.exploitable ? "CONFIRMED" : "Not confirmed"}. Confidence: ${f.score || 0}/100.`,
            recommendation: f.recommendation || "Apply vendor-recommended patches and configuration hardening. Verify remediation by re-scanning the affected asset and confirming the vulnerability is no longer exploitable."
          };
        }),
        recommendations: [
          "IMMEDIATE (0-30 days): Apply patches and configuration fixes for all confirmed exploitable findings. Validate each remediation through targeted re-assessment.",
          "SHORT-TERM (30-90 days): Implement network segmentation to constrain lateral movement paths. Deploy enhanced logging and monitoring (SIEM integration) for all affected assets. Review and harden access control policies.",
          "LONG-TERM (90+ days): Establish continuous security validation through automated assessment scheduling. Implement defense-in-depth architecture aligned to MITRE ATT&CK framework. Integrate security testing into CI/CD pipeline."
        ]
      },
      compliance: {
        executiveSummary: `Compliance assessment against ${data.framework?.toUpperCase() || "the target framework"} evaluated ${data.auditReadiness?.totalControls || 0} controls and determined an overall compliance rate of ${data.overallCompliance || 0}%. ${data.gaps?.length || 0} material control gap${(data.gaps?.length || 0) !== 1 ? "s" : ""} were identified requiring remediation to maintain compliance posture. Current audit readiness is assessed at ${data.auditReadiness?.score || 0}%.\n\n${(data.gaps?.length || 0) > 0 ? `The identified control gaps present regulatory exposure that could result in audit findings, certification delays, or regulatory penalties if unaddressed. The assessment team recommends immediate attention to material gaps with a structured evidence collection plan to demonstrate compliance.` : "No material control gaps were identified. The organization should maintain current controls and establish continuous compliance monitoring to preserve this favorable posture."}\n\nRemediation should follow a phased approach: immediate gap closure with interim compensating controls (0-30 days), full control implementation with audit-ready evidence packages (30-60 days), and ongoing compliance assurance through automated monitoring (60-90 days).`,
        findings: (data.gaps || []).slice(0, 5).map((g: any) => ({
          title: `Control Gap: ${g.controlId || "Unknown Control"} — ${g.gapDescription?.split(" ").slice(0, 5).join(" ") || "Compliance Deficiency"}`,
          description: `${g.gapDescription || "Control gap identified during compliance assessment."} This gap presents regulatory exposure and may result in audit findings if unaddressed. Evidence of remediation must be documented for audit readiness.`,
          recommendation: `${g.remediationGuidance || "Implement required controls to achieve compliance."} Document all remediation activities and collect evidence artifacts for audit review. Verify control effectiveness through independent testing.`
        })),
        recommendations: [
          "IMMEDIATE (0-30 days): Close material control gaps — implement compensating controls and begin evidence collection for audit documentation",
          "SHORT-TERM (30-60 days): Complete control implementation — produce audit-ready evidence packages including policies, procedures, technical configurations, and test results",
          "ONGOING: Establish continuous compliance monitoring — automate control validation, maintain evidence repository, and schedule periodic compliance assessments"
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
        executive: `You are a principal security consultant at a top-tier penetration testing firm (comparable to NCC Group, Rapid7, or CrowdStrike) preparing an executive report for Board of Directors and C-suite leadership following a completed security engagement.

Assessment Data:
${JSON.stringify(data, null, 2)}

Produce a JSON response with this exact structure (no additional fields):
{
  "executiveSummary": "3-4 paragraphs structured as follows:\n\nParagraph 1 — ENGAGEMENT OVERVIEW: State the scope of the assessment, the number of assets evaluated, the methodology employed (automated multi-agent AI assessment including reconnaissance, exploit validation, lateral movement analysis, and impact assessment), and the assessment period.\n\nParagraph 2 — SECURITY POSTURE ASSESSMENT: Provide the assessment team's overall characterization of the organization's security posture. Reference the ratio of exploitable findings to total evaluations. Contextualize severity distribution against industry benchmarks. Use authoritative but measured language.\n\nParagraph 3 — CRITICAL FINDINGS AND BUSINESS RISK: Summarize the highest-impact findings in business terms — financial exposure, operational disruption potential, regulatory implications, and reputational risk. Reference specific finding categories (not technical details). Cite NIST CSF or ISO 27001 control areas where gaps exist.\n\nParagraph 4 — STRATEGIC RECOMMENDATIONS: Present a phased remediation roadmap: immediate actions (0-30 days), short-term hardening (30-60 days), and strategic security program improvements (60-90 days). Frame each recommendation as a risk-reduction investment with expected outcome.",
  "findings": [
    {"title": "Concise finding title in active voice (e.g., 'Exploitable Remote Code Execution in External-Facing Application')", "description": "Business-impact description: what is at risk, which business processes are affected, the likelihood of exploitation based on assessment evidence, and the potential financial/operational consequence. Do NOT use technical jargon — write for a non-technical board audience.", "recommendation": "Strategic remediation approach framed as an investment: what to implement, expected risk reduction, and implementation considerations including resource requirements."}
  ],
  "recommendations": ["Immediate (0-30 days): Specific remediation action with expected risk reduction outcome", "Short-term (30-60 days): Security hardening initiative with measurable success criteria", "Strategic (60-90 days): Security program maturity improvement aligned to NIST CSF or ISO 27001"]
}

WRITING RULES — follow these precisely:
- Voice: "The assessment team identified..." / "OdinForge's automated security assessment revealed..." — NEVER use "We" or "I"
- Quantify everything: "3 of 7 evaluated assets (43%) presented exploitable attack paths" not "several assets had issues"
- Business framing: Every finding must connect to financial exposure, operational disruption, regulatory risk, or reputational damage
- No alarmism: Use "presents material risk" not "catastrophic" or "devastating". Use "requires immediate attention" not "emergency"
- Recommendations must be investment-framed: "Investing in network segmentation reduces lateral movement risk by constraining blast radius" not "Implement network segmentation"
- Reference NIST CSF categories (Identify, Protect, Detect, Respond, Recover) or ISO 27001 Annex A controls where relevant
- Limit findings to 5 highest-priority items
- Do NOT include any markdown formatting, only plain text with paragraph breaks`,

        technical: `You are a senior penetration tester at an elite security consultancy (comparable to NCC Group, SpecterOps, or Rapid7) preparing the technical findings section of a penetration test report. Your audience is the security engineering team and technical leadership (CISO, VP Security).

Assessment Data:
${JSON.stringify(data, null, 2)}

Produce a JSON response with this exact structure (no additional fields):
{
  "executiveSummary": "3-4 paragraphs structured as follows:\n\nParagraph 1 — SCOPE AND METHODOLOGY: Define what was tested (asset count, exposure types), the testing methodology (automated multi-agent AI assessment pipeline: Reconnaissance Agent, Exploit Validation Agent, Lateral Movement Agent, Business Logic Agent, Multi-Vector Agent, and Impact Assessment Agent), testing constraints and limitations, and the execution mode (safe/simulation/live).\n\nParagraph 2 — FINDINGS SUMMARY: State total findings count with severity distribution. Reference MITRE ATT&CK tactic coverage (e.g., 'Validated techniques span Initial Access, Execution, Persistence, and Lateral Movement tactic categories'). Highlight the exploitability rate and average confidence score.\n\nParagraph 3 — ATTACK PATH NARRATIVE: Describe the most significant attack chain(s) discovered, connecting individual findings into a coherent exploitation narrative. Explain how an attacker would chain these vulnerabilities from initial access through to business impact. Reference specific MITRE ATT&CK technique IDs (T####).\n\nParagraph 4 — REMEDIATION PRIORITIZATION: Present remediation in three phases: Immediate (0-30 days) for critical/exploitable findings, Short-term (30-90 days) for defense-in-depth improvements, Long-term (90+ days) for architectural security enhancements. Each recommendation should include verification criteria.",
  "findings": [
    {"title": "[SEVERITY] Finding Title | CWE-XXX | MITRE: TXXXX.XXX (include CWE and MITRE IDs where the data supports it)", "description": "Structured as: DESCRIPTION — What the vulnerability is and where it exists (specific asset, service, endpoint). ATTACK VECTOR — How an attacker exploits this (prerequisites, complexity, access required). IMPACT — Technical and business consequences of successful exploitation. EVIDENCE — Reference to assessment evidence supporting this finding (attack path data, scores, confidence levels). ESCALATION POTENTIAL — How this finding connects to other vulnerabilities or enables further compromise.", "recommendation": "Structured as: REMEDIATION — Specific technical fix (configuration change, patch, code fix). VERIFICATION — How to confirm the fix is effective (test procedure, expected result). COMPENSATING CONTROL — Interim mitigation if immediate fix is not feasible."}
  ],
  "recommendations": ["IMMEDIATE (0-30 days): Specific technical remediation with verification criteria", "SHORT-TERM (30-90 days): Defense-in-depth improvement with measurable outcome", "LONG-TERM (90+ days): Architectural security enhancement aligned to MITRE ATT&CK defense framework"]
}

WRITING RULES — follow these precisely:
- Active voice throughout: "The application accepts..." not "It was observed that the application..."
- Reference MITRE ATT&CK technique IDs (T####) and tactic names in findings and attack path narrative
- Include CWE identifiers (CWE-XXX) for each vulnerability class
- Every finding must reference the specific asset(s) affected
- Remediation must be testable: include verification criteria ("Confirm by..." or "Validate that...")
- Findings title format: "[CRITICAL] Title | CWE-79 | MITRE: T1059.007" — include severity, CWE, and technique ID
- Do NOT use passive hedging language ("may potentially", "could possibly") — be direct and evidence-based
- Limit findings to 10 highest-impact items sorted by severity then exploitability
- Do NOT include any markdown formatting, only plain text`,

        compliance: `You are a GRC (Governance, Risk, and Compliance) consultant at a Big 4 professional services firm preparing a compliance assessment report for the audit committee and compliance leadership.

Assessment Data:
${JSON.stringify(data, null, 2)}

Produce a JSON response with this exact structure (no additional fields):
{
  "executiveSummary": "3 paragraphs structured as follows:\n\nParagraph 1 — COMPLIANCE POSTURE: State the overall compliance percentage against the framework, the number of controls assessed, and the number of control gaps identified. Characterize the organization's compliance maturity (initial, developing, defined, managed, optimizing). Reference the specific framework version assessed.\n\nParagraph 2 — MATERIAL CONTROL GAPS: Describe the most significant gaps in business terms — which control objectives are unmet, what regulatory exposure this creates, and the potential consequences (audit findings, regulatory penalties, loss of certification). Reference specific control IDs.\n\nParagraph 3 — REMEDIATION ROADMAP: Present a phased plan to achieve and maintain compliance: immediate gap closure (0-30 days), control implementation and evidence collection (30-60 days), and ongoing compliance assurance program (60-90 days). Include evidence requirements for each phase.",
  "findings": [
    {"title": "Control Gap: [Framework Control ID] — [Control Name]", "description": "GAP ANALYSIS — Control Objective: What the framework requires. Current State: What the assessment found. Target State: What must be achieved. Compliance Impact: Specific regulatory/audit exposure if unaddressed. Evidence Required: What documentation or technical evidence demonstrates compliance.", "recommendation": "REMEDIATION — Implementation: Specific control to implement. Timeline: Expected implementation duration. Evidence: Documentation and artifacts needed to demonstrate compliance to auditors. Verification: How to confirm the control is operating effectively."}
  ],
  "recommendations": ["IMMEDIATE (0-30 days): Close material control gaps with specific implementation steps and evidence requirements", "SHORT-TERM (30-60 days): Implement and document controls with audit-ready evidence packages", "ONGOING: Establish continuous compliance monitoring with automated control validation"]
}

WRITING RULES — follow these precisely:
- Reference specific framework control IDs (SOC 2 TSC CC#.#, PCI DSS Req #.#, HIPAA §164.###, ISO 27001 A.##, NIST CSF XX.XX)
- Frame every gap in terms of audit risk and regulatory exposure — not just technical deficiency
- Each finding must include evidence requirements for demonstrating compliance
- Recommendations must be audit-actionable with clear deliverables
- Use compliance-specific language: "control gap", "compensating control", "evidence artifact", "control objective"
- Limit findings to 5 most material gaps sorted by regulatory exposure
- Do NOT include any markdown formatting, only plain text`
      };

      const response = await client.chat.completions.create({
        model: "gpt-4o",
        messages: [
          { role: "system", content: "You are a senior penetration testing consultant at an elite security firm (NCC Group / Rapid7 / CrowdStrike caliber) preparing formal engagement deliverables. Your reports are read by CISOs, boards of directors, and audit committees. Write with the authority of an experienced practitioner — direct, evidence-based, and precise. NEVER use filler phrases ('it should be noted', 'it is worth mentioning', 'it is important to'). NEVER use passive hedging ('may potentially', 'could possibly'). Use active voice and definitive statements grounded in assessment evidence. Frame every finding in terms of business impact. Always respond with valid JSON matching the exact schema requested. Never include extra fields or markdown formatting." },
          { role: "user", content: prompts[reportType] }
        ],
        response_format: { type: "json_object" },
        temperature: 0.7,
        max_tokens: reportType === "technical" ? 5000 : 4000,
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

    let narrative = `OdinForge's automated security assessment evaluated ${totalEvaluations} exposure${totalEvaluations !== 1 ? "s" : ""} using a multi-agent AI analysis pipeline encompassing reconnaissance, exploit validation, lateral movement analysis, and impact assessment. `;

    if (exploitableCount === 0) {
      narrative += "The assessment did not identify exploitable attack paths during this evaluation period, indicating effective security controls are in place. ";
    } else {
      narrative += `${exploitableCount} of ${totalEvaluations} evaluated exposures (${exploitablePercent}%) were confirmed exploitable through validated attack paths. `;
    }

    if (criticalCount > 0) {
      narrative += `${criticalCount} critical-severity finding${criticalCount > 1 ? "s" : ""} present${criticalCount === 1 ? "s" : ""} immediate risk to business operations and require${criticalCount === 1 ? "s" : ""} emergency remediation. `;
    }

    switch (overallRiskLevel) {
      case "critical":
        narrative += "The assessment team assessed the overall security posture as CRITICAL. Immediate executive attention and emergency remediation resources are required. The assessment team recommends activating incident response procedures for critical findings.";
        break;
      case "high":
        narrative += "The assessment team assessed the overall security posture as HIGH risk. A prioritized remediation plan should be executed within 30 days, with compensating controls deployed immediately for exploitable findings.";
        break;
      case "medium":
        narrative += "The assessment team assessed the overall security posture as MODERATE. Findings should be addressed through scheduled remediation activities within 60 days, with enhanced monitoring deployed for affected assets.";
        break;
      case "low":
        narrative += "The assessment team assessed the overall security posture as LOW risk. The organization should maintain current security controls and continue regular assessment cycles to preserve this favorable posture.";
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
  
  async generateEvidencePackage(
    evaluationId: string,
    artifacts: any[],
    evaluationData?: any
  ): Promise<{
    executiveSummary: string;
    timelineNarrative: string;
    findingsNarrative: string;
    technicalDetails: string;
    artifacts: any[];
    metadata: {
      evaluationId: string;
      generatedAt: string;
      totalArtifacts: number;
      criticalFindings: number;
    };
  }> {
    const client = getOpenAIClient();
    
    // Build context about the evidence
    const criticalFindings = artifacts.filter(a => a.tags?.includes("critical")).length;
    const artifactTypes = Array.from(new Set(artifacts.map(a => a.type)));
    const timeline = artifacts.map(a => ({
      timestamp: a.timestamp,
      type: a.type,
      title: a.title,
      description: a.description?.substring(0, 200),
    })).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    
    const contextData = {
      evaluationId,
      totalArtifacts: artifacts.length,
      criticalFindings,
      artifactTypes,
      timeline,
      artifacts: artifacts.slice(0, 10).map(a => ({
        type: a.type,
        title: a.title,
        description: a.description,
        tags: a.tags,
      })),
      evaluationResult: evaluationData,
    };
    
    // Templated fallback narratives
    const templatedResponse = {
      executiveSummary: `This evidence package contains ${artifacts.length} artifacts collected during the security evaluation of ${evaluationId}. ${criticalFindings > 0 ? `${criticalFindings} critical findings were identified that require immediate attention.` : "No critical findings were identified."} The evidence documents the complete attack chain validation and exploitation attempts conducted during the assessment.`,
      timelineNarrative: `The evaluation began at ${timeline[0]?.timestamp || "unknown time"} and concluded with ${artifacts.length} total evidence artifacts captured. The assessment followed a systematic approach, documenting each phase of the security validation process from reconnaissance through exploitation verification.`,
      findingsNarrative: criticalFindings > 0 
        ? `The assessment identified ${criticalFindings} critical security issues requiring immediate remediation. These findings demonstrate exploitable vulnerabilities that could lead to unauthorized access or data compromise. Full technical details are provided in the artifact data below.`
        : `The assessment completed successfully with no critical vulnerabilities identified. The evidence documents the testing methodology and confirms the security controls functioned as expected.`,
      technicalDetails: `Evidence types collected: ${artifactTypes.join(", ")}. Total artifacts: ${artifacts.length}. The evidence package includes request/response captures, execution traces, log entries, and other forensic data supporting the evaluation conclusions.`,
    };
    
    if (!client) {
      return {
        ...templatedResponse,
        artifacts,
        metadata: {
          evaluationId,
          generatedAt: new Date().toISOString(),
          totalArtifacts: artifacts.length,
          criticalFindings,
        },
      };
    }
    
    try {
      const response = await client.chat.completions.create({
        model: "gpt-4o",
        messages: [
          { 
            role: "system", 
            content: "You are a cybersecurity forensics specialist writing evidence documentation. Always respond with valid JSON matching the exact schema requested." 
          },
          { 
            role: "user", 
            content: `You are documenting evidence from a security assessment. Based on the following evidence artifacts and evaluation data, write clear narratives that explain what the evidence shows.

Evidence Data:
${JSON.stringify(contextData, null, 2)}

Provide your response as JSON with this exact structure:
{
  "executiveSummary": "A 2-3 sentence summary suitable for executives explaining what the evidence collection demonstrates about the security posture. Focus on business impact.",
  "timelineNarrative": "A paragraph describing the sequence of events documented in the evidence, written in chronological order.",
  "findingsNarrative": "A paragraph explaining the key security findings demonstrated by this evidence, what vulnerabilities were proven exploitable, and the risk implications.",
  "technicalDetails": "A paragraph summarizing the technical evidence types collected, the attack techniques documented, and any notable exploitation methods captured."
}

Write in clear, professional language. Be specific about what the evidence demonstrates.`
          }
        ],
        response_format: { type: "json_object" },
        temperature: 0.7,
        max_tokens: 1500,
      });
      
      const content = response.choices[0].message.content;
      if (!content) {
        throw new Error("No response from AI");
      }
      
      const parsed = JSON.parse(content);
      
      // Validate and sanitize the response
      const validated = {
        executiveSummary: typeof parsed.executiveSummary === "string" 
          ? parsed.executiveSummary 
          : templatedResponse.executiveSummary,
        timelineNarrative: typeof parsed.timelineNarrative === "string"
          ? parsed.timelineNarrative
          : templatedResponse.timelineNarrative,
        findingsNarrative: typeof parsed.findingsNarrative === "string"
          ? parsed.findingsNarrative
          : templatedResponse.findingsNarrative,
        technicalDetails: typeof parsed.technicalDetails === "string"
          ? parsed.technicalDetails
          : templatedResponse.technicalDetails,
      };
      
      return {
        ...validated,
        artifacts,
        metadata: {
          evaluationId,
          generatedAt: new Date().toISOString(),
          totalArtifacts: artifacts.length,
          criticalFindings,
        },
      };
    } catch (error) {
      console.error("AI evidence narrative generation failed, using template:", error);
      return {
        ...templatedResponse,
        artifacts,
        metadata: {
          evaluationId,
          generatedAt: new Date().toISOString(),
          totalArtifacts: artifacts.length,
          criticalFindings,
        },
      };
    }
  }

  // Single Evaluation Reports
  async generateSingleEvaluationExecutiveSummary(
    evaluationId: string
  ): Promise<ExecutiveSummary> {
    const evaluation = await storage.getEvaluation(evaluationId);
    if (!evaluation) {
      throw new Error(`Evaluation not found: ${evaluationId}`);
    }
    
    const result = await storage.getResultByEvaluationId(evaluationId);
    
    const criticalCount = evaluation.priority === "critical" ? 1 : 0;
    const highCount = evaluation.priority === "high" ? 1 : 0;
    const mediumCount = evaluation.priority === "medium" ? 1 : 0;
    const lowCount = evaluation.priority === "low" ? 1 : 0;
    const exploitableCount = result?.exploitable ? 1 : 0;
    
    const intelligentScore = result?.intelligentScore as any;
    const financialExposure = intelligentScore?.businessImpact?.factors?.financialExposure;
    
    const topRisks: ExecutiveSummary["topRisks"] = result?.exploitable ? [{
      assetId: evaluation.assetId,
      riskDescription: evaluation.description,
      severity: evaluation.priority as "critical" | "high" | "medium" | "low",
      financialImpact: financialExposure ? 
        `$${financialExposure.directLoss?.min?.toLocaleString() || 0} - $${financialExposure.directLoss?.max?.toLocaleString() || 0}` : 
        undefined,
    }] : [];
    
    const overallRiskLevel = evaluation.priority as "critical" | "high" | "medium" | "low";
    
    const recommendations: ExecutiveSummary["recommendations"] = [];
    if (result?.recommendations) {
      result.recommendations.forEach((rec: any, i: number) => {
        recommendations.push({
          priority: i + 1,
          action: rec.description || rec.title || "Remediation required",
          impact: rec.impact || "Improved security posture",
          effort: rec.effort || "medium",
        });
      });
    }
    
    const baseReport = {
      reportDate: new Date().toISOString(),
      reportPeriod: {
        from: evaluation.createdAt?.toISOString() || new Date().toISOString(),
        to: evaluation.createdAt?.toISOString() || new Date().toISOString(),
      },
      organizationId: evaluation.organizationId || "default",
      overallRiskLevel,
      keyMetrics: {
        totalEvaluations: 1,
        exploitableFindings: exploitableCount,
        criticalFindings: criticalCount,
        highFindings: highCount,
        mediumFindings: mediumCount,
        lowFindings: lowCount,
        averageScore: result?.score || 0,
        averageConfidence: result?.confidence || 0,
      },
      riskTrend: "stable" as const,
      topRisks,
      recommendations,
      executiveNarrative: this.generateExecutiveNarrative(1, exploitableCount, criticalCount, overallRiskLevel),
    };

    const aiNarrative = await this.generateAINarrative("executive", {
      metrics: baseReport.keyMetrics,
      topRisks,
      recommendations,
      overallRiskLevel,
      assetId: evaluation.assetId,
      exposureType: evaluation.exposureType,
      description: evaluation.description,
      attackPath: result?.attackPath,
      impact: result?.impact,
    });

    const defaultSeverity: "critical" | "high" | "medium" | "low" = "medium";
    const enrichedFindings = aiNarrative.findings.length > 0 
      ? aiNarrative.findings.map((f, i) => ({
          ...f,
          severity: topRisks[i]?.severity || defaultSeverity,
        }))
      : topRisks.map(r => ({
          title: `Risk: ${r.assetId}`,
          description: r.riskDescription,
          recommendation: "Immediate remediation recommended",
          severity: r.severity,
        }));

    return {
      ...baseReport,
      executiveSummary: aiNarrative.executiveSummary,
      executiveNarrative: aiNarrative.executiveSummary || baseReport.executiveNarrative,
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

  async generateSingleEvaluationTechnicalReport(
    evaluationId: string
  ): Promise<TechnicalReport> {
    const evaluation = await storage.getEvaluation(evaluationId);
    if (!evaluation) {
      throw new Error(`Evaluation not found: ${evaluationId}`);
    }
    
    const result = await storage.getResultByEvaluationId(evaluationId);
    
    const findings: ReportFinding[] = [{
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
    }];
    
    const attackPaths: TechnicalReport["attackPaths"] = [];
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
    
    const technicalDetails: TechnicalReport["technicalDetails"] = [{
      evaluationId: evaluation.id,
      assetId: evaluation.assetId,
      exposureType: evaluation.exposureType,
      technicalAnalysis: result?.impact || evaluation.description,
      mitigations: result?.recommendations?.map((r: any) => r.description) || [],
    }];
    
    const baseReport = {
      reportDate: new Date().toISOString(),
      reportPeriod: {
        from: evaluation.createdAt?.toISOString() || new Date().toISOString(),
        to: evaluation.createdAt?.toISOString() || new Date().toISOString(),
      },
      organizationId: evaluation.organizationId || "default",
      findings,
      attackPaths,
      vulnerabilityBreakdown: {
        byType: { [evaluation.exposureType]: 1 },
        bySeverity: { [evaluation.priority]: 1 },
        byAsset: { [evaluation.assetId]: 1 },
      },
      technicalDetails,
    };

    const aiNarrative = await this.generateAINarrative("technical", {
      findingsCount: 1,
      vulnerabilityBreakdown: baseReport.vulnerabilityBreakdown,
      attackPathsCount: attackPaths.length,
      topFindings: findings,
      assetId: evaluation.assetId,
      exposureType: evaluation.exposureType,
      description: evaluation.description,
      attackPath: result?.attackPath,
      impact: result?.impact,
    });

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

  async generateSingleEvaluationComplianceReport(
    evaluationId: string,
    framework: ComplianceFramework
  ): Promise<ComplianceReport> {
    const evaluation = await storage.getEvaluation(evaluationId);
    if (!evaluation) {
      throw new Error(`Evaluation not found: ${evaluationId}`);
    }
    
    const result = await storage.getResultByEvaluationId(evaluationId);
    
    const controlMappings = this.getFrameworkControls(framework);
    const controlStatus: ComplianceReport["controlStatus"] = [];
    const gaps: ComplianceReport["gaps"] = [];
    
    const intelligentScore = result?.intelligentScore as any;
    const complianceImpact = intelligentScore?.businessImpact?.factors?.complianceImpact;
    let compliantControls = 0;
    
    for (const control of controlMappings) {
      let hasViolation = false;
      let maxSeverity: "critical" | "high" | "medium" | "low" = "low";
      
      if (complianceImpact?.affectedFrameworks?.includes(framework.toLowerCase())) {
        hasViolation = true;
        const violations = complianceImpact.violations || [];
        for (const v of violations) {
          if (v.severity === "critical" && maxSeverity !== "critical") maxSeverity = "critical";
          else if (v.severity === "major" && maxSeverity !== "critical") maxSeverity = "high";
        }
      }
      
      const status = hasViolation ? "non_compliant" : "compliant";
      if (status === "compliant") compliantControls++;
      
      controlStatus.push({
        controlId: control.id,
        controlName: control.name,
        status,
        findings: hasViolation ? [evaluation.id] : [],
        remediationRequired: hasViolation,
      });
      
      if (hasViolation) {
        gaps.push({
          controlId: control.id,
          gapDescription: `${control.name} has finding(s) that may impact compliance`,
          severity: maxSeverity,
          remediationGuidance: `Review and remediate finding: ${evaluation.id}`,
        });
      }
    }
    
    const overallCompliance = Math.round((compliantControls / controlMappings.length) * 100);
    
    const baseReport = {
      reportDate: new Date().toISOString(),
      framework,
      organizationId: evaluation.organizationId || "default",
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

    const aiNarrative = await this.generateAINarrative("compliance", {
      framework,
      overallCompliance,
      gaps: gaps.slice(0, 5),
      controlStatus: controlStatus.slice(0, 10),
      auditReadiness: baseReport.auditReadiness,
      assetId: evaluation.assetId,
      exposureType: evaluation.exposureType,
      description: evaluation.description,
    });

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
        controlStatus.map(c => [c.controlId, { status: c.status, coverage: c.status === "compliant" ? 100 : 0 }])
      ),
    };
  }

  async generateEnhancedReport(
    evaluationId: string,
    options: {
      includeKillChain?: boolean;
      includeRemediation?: boolean;
      includeVulnerabilityDetails?: boolean;
    } = {}
  ): Promise<{
    reportMetadata: {
      generatedAt: string;
      reportType: "single_evaluation";
      evaluationId: string;
    };
    evaluation: any;
    result: any;
    vulnerability: {
      info: VulnerabilityInfo;
      humanReadableName: string;
      shortName: string;
      cweIds: string[];
      mitreTechniques: string[];
      businessImpact: string;
    };
    remediationGuidance: {
      structured: RemediationGuidance;
      formatted: string;
      steps: Array<{
        order: number;
        title: string;
        description: string;
        effort: string;
        estimatedTime?: string;
        requiredTools?: string[];
        requiredSkills?: string[];
        verificationSteps?: string[];
      }>;
    };
    killChain: {
      section: KillChainReportSection | null;
      textualDiagram: string;
      pdfContent: PdfKillChainContent | null;
    };
    executiveSummary: ComputedExecutiveSummary;
    technicalReport: ComputedTechnicalReport;
    dataStatus: {
      hasEvaluation: boolean;
      hasResult: boolean;
      hasAttackPath: boolean;
      message: string;
    };
  }> {
    const evaluation = await storage.getEvaluation(evaluationId);
    if (!evaluation) {
      throw new Error(`Evaluation not found: ${evaluationId}`);
    }
    
    const result = await storage.getResultByEvaluationId(evaluationId);
    
    const exposureType = evaluation.exposureType as ExposureType;
    const vulnerabilityInfo = getVulnerabilityInfo(exposureType);
    const remediationGuidance = getRemediationGuidance(exposureType);
    
    const evalData: EvaluationData = {
      id: evaluation.id,
      assetId: evaluation.assetId,
      exposureType: exposureType,
      priority: evaluation.priority as "critical" | "high" | "medium" | "low",
      description: evaluation.description,
      organizationId: evaluation.organizationId || undefined,
      createdAt: evaluation.createdAt || undefined,
    };
    
    const resultsMap = new Map<string, ResultData>();
    if (result) {
      resultsMap.set(evaluation.id, {
        evaluationId: result.evaluationId,
        exploitable: result.exploitable || false,
        score: result.score || 0,
        confidence: result.confidence || 0,
        impact: result.impact || undefined,
        attackPath: result.attackPath as AttackPathStep[] | undefined,
        recommendations: result.recommendations as any[] | undefined,
        attackGraph: result.attackGraph as any | undefined,
        intelligentScore: result.intelligentScore as any | undefined,
      });
    }
    
    const computedSummary = computeExecutiveSummary([evalData], resultsMap);
    
    const evidenceArtifacts = await this.fetchEvidenceForEvaluations([{ id: evaluationId, organizationId: evaluation.organizationId || undefined }]);
    const computedTechnical = computeTechnicalReport([evalData], resultsMap, evidenceArtifacts);
    
    let killChainSection: KillChainReportSection | null = null;
    let killChainDiagram = "";
    let killChainPdfContent: PdfKillChainContent | null = null;
    
    if (options.includeKillChain !== false && result?.attackPath) {
      const attackPath = result.attackPath as AttackPathStep[];
      const attackGraph = result.attackGraph as any;
      const visualization = buildKillChainVisualization(attackPath, attackGraph);
      killChainSection = generateKillChainReportSection(visualization);
      killChainDiagram = generateTextualKillChainDiagram(visualization);
      killChainPdfContent = generatePdfKillChainContent(visualization);
    }
    
    let formattedRemediation = "";
    if (options.includeRemediation !== false) {
      formattedRemediation = formatRemediationSection({
        vulnerabilityType: exposureType,
        vulnerabilityName: formatVulnerabilityName(exposureType),
        affectedAssets: [evaluation.assetId],
        immediateActions: remediationGuidance.immediateActions,
        shortTermSteps: remediationGuidance.shortTermRemediation,
        longTermSteps: remediationGuidance.longTermRemediation,
        compensatingControls: remediationGuidance.compensatingControls,
        references: remediationGuidance.references,
      });
    }
    
    const dataStatus = {
      hasEvaluation: true,
      hasResult: !!result,
      hasAttackPath: !!(result?.attackPath && (result.attackPath as any[]).length > 0),
      message: result 
        ? "Complete evaluation data available" 
        : "Evaluation exists but analysis results not yet available",
    };
    
    const vulnerabilityData = options.includeVulnerabilityDetails !== false ? {
      info: vulnerabilityInfo,
      humanReadableName: formatVulnerabilityName(exposureType),
      shortName: formatVulnerabilityShortName(exposureType),
      cweIds: vulnerabilityInfo.cweIds,
      mitreTechniques: vulnerabilityInfo.mitreTechniques,
      businessImpact: vulnerabilityInfo.businessImpact,
    } : {
      info: vulnerabilityInfo,
      humanReadableName: formatVulnerabilityName(exposureType),
      shortName: formatVulnerabilityShortName(exposureType),
      cweIds: [] as string[],
      mitreTechniques: [] as string[],
      businessImpact: "",
    };
    
    const remediationData = options.includeRemediation !== false ? {
      structured: remediationGuidance,
      formatted: formattedRemediation,
      steps: remediationGuidance.shortTermRemediation.map((step) => ({
        order: step.order,
        title: step.title,
        description: step.description,
        effort: step.effort,
        estimatedTime: step.estimatedTime,
        requiredTools: step.requiredTools,
        requiredSkills: step.requiredSkills,
        verificationSteps: step.verificationSteps,
      })),
    } : {
      structured: remediationGuidance,
      formatted: "",
      steps: [] as Array<{
        order: number;
        title: string;
        description: string;
        effort: string;
        estimatedTime?: string;
        requiredTools?: string[];
        requiredSkills?: string[];
        verificationSteps?: string[];
      }>,
    };
    
    return {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        reportType: "single_evaluation",
        evaluationId,
      },
      evaluation,
      result,
      vulnerability: vulnerabilityData,
      remediationGuidance: remediationData,
      killChain: {
        section: killChainSection,
        textualDiagram: killChainDiagram,
        pdfContent: killChainPdfContent,
      },
      executiveSummary: computedSummary,
      technicalReport: computedTechnical,
      dataStatus,
    };
  }

  async generateEnhancedDateRangeReport(
    from: Date,
    to: Date,
    organizationId: string = "default",
    options: {
      includeKillChain?: boolean;
      includeRemediation?: boolean;
    } = {}
  ): Promise<{
    reportMetadata: {
      generatedAt: string;
      reportType: "date_range";
      period: { from: string; to: string };
      organizationId: string;
    };
    dataStatus: {
      hasEvaluations: boolean;
      hasResults: boolean;
      evaluationCount: number;
      resultCount: number;
      message: string;
    };
    evaluations: any[];
    results: any[];
    executiveSummary: ComputedExecutiveSummary;
    technicalReport: ComputedTechnicalReport;
    killChain: {
      section: KillChainReportSection | null;
      textualDiagram: string;
      pdfContent: PdfKillChainContent | null;
    };
    vulnerabilityBreakdown: Array<{
      type: string;
      humanReadableName: string;
      shortName: string;
      cweIds: string[];
      mitreTechniques: string[];
      businessImpact: string;
      count: number;
      exploitableCount: number;
      remediationGuidance: {
        steps: Array<{
          order: number;
          title: string;
          description: string;
          effort: string;
          estimatedTime?: string;
          requiredTools?: string[];
          requiredSkills?: string[];
          verificationSteps?: string[];
        }>;
        compensatingControls: string[];
      };
    }>;
    aggregatedRemediation: {
      totalVulnerabilityTypes: number;
      byExposureType: Array<{
        exposureType: string;
        humanReadableName: string;
        count: number;
        priority: "critical" | "high" | "medium" | "low";
        formattedPlan: string;
      }>;
      prioritizedPlan: string;
      byPriority: {
        critical: number;
        high: number;
        medium: number;
        low: number;
      };
    };
  }> {
    const evaluations = await storage.getEvaluationsByDateRange(from, to, organizationId);
    const evaluationIds = evaluations.map(e => e.id);
    const results = await storage.getResultsByEvaluationIds(evaluationIds);
    
    const evalDataList: EvaluationData[] = evaluations.map(e => ({
      id: e.id,
      assetId: e.assetId,
      exposureType: e.exposureType as ExposureType,
      priority: e.priority as "critical" | "high" | "medium" | "low",
      description: e.description,
      organizationId: e.organizationId || undefined,
      createdAt: e.createdAt || undefined,
    }));
    
    const resultsMap = new Map<string, ResultData>();
    results.forEach(r => {
      resultsMap.set(r.evaluationId, {
        evaluationId: r.evaluationId,
        exploitable: r.exploitable || false,
        score: r.score || 0,
        confidence: r.confidence || 0,
        impact: r.impact || undefined,
        attackPath: r.attackPath as AttackPathStep[] | undefined,
        recommendations: r.recommendations as any[] | undefined,
        attackGraph: r.attackGraph as any | undefined,
        intelligentScore: r.intelligentScore as any | undefined,
      });
    });
    
    const computedSummary = computeExecutiveSummary(evalDataList, resultsMap);
    
    const evidenceArtifacts = await this.fetchEvidenceForEvaluations(
      evalDataList.map(e => ({ id: e.id, organizationId: e.organizationId }))
    );
    const computedTechnical = computeTechnicalReport(evalDataList, resultsMap, evidenceArtifacts);
    
    const allAttackSteps: AttackPathStep[] = [];
    let aggregatedGraph: any | undefined;
    results.forEach(r => {
      if (r.attackPath) {
        allAttackSteps.push(...(r.attackPath as AttackPathStep[]));
      }
      if (r.attackGraph && !aggregatedGraph) {
        aggregatedGraph = r.attackGraph;
      }
    });
    
    let killChainSection: KillChainReportSection | null = null;
    let killChainDiagram = "";
    let killChainPdfContent: PdfKillChainContent | null = null;
    
    if (options.includeKillChain !== false && allAttackSteps.length > 0) {
      const visualization = buildKillChainVisualization(allAttackSteps, aggregatedGraph);
      killChainSection = generateKillChainReportSection(visualization);
      killChainDiagram = generateTextualKillChainDiagram(visualization);
      killChainPdfContent = generatePdfKillChainContent(visualization);
    }
    
    const vulnTypeCount = new Map<ExposureType, { count: number; exploitableCount: number }>();
    evaluations.forEach(e => {
      const type = e.exposureType as ExposureType;
      const entry = vulnTypeCount.get(type) || { count: 0, exploitableCount: 0 };
      entry.count++;
      const result = resultsMap.get(e.id);
      if (result?.exploitable) entry.exploitableCount++;
      vulnTypeCount.set(type, entry);
    });
    
    const vulnerabilityBreakdown = Array.from(vulnTypeCount.entries()).map(([type, data]) => {
      const info = getVulnerabilityInfo(type);
      const guidance = getRemediationGuidance(type);
      return {
        type,
        humanReadableName: formatVulnerabilityName(type),
        shortName: formatVulnerabilityShortName(type),
        cweIds: info.cweIds,
        mitreTechniques: info.mitreTechniques,
        businessImpact: info.businessImpact,
        count: data.count,
        exploitableCount: data.exploitableCount,
        remediationGuidance: {
          steps: guidance.shortTermRemediation.map((step: { order: number; title: string; description: string; effort: string; estimatedTime?: string; requiredTools?: string[]; requiredSkills?: string[]; verificationSteps?: string[] }) => ({
            order: step.order,
            title: step.title,
            description: step.description,
            effort: step.effort,
            estimatedTime: step.estimatedTime,
            requiredTools: step.requiredTools,
            requiredSkills: step.requiredSkills,
            verificationSteps: step.verificationSteps,
          })),
          compensatingControls: guidance.compensatingControls,
        },
      };
    });
    
    const remediationByExposureType: Array<{
      exposureType: string;
      humanReadableName: string;
      count: number;
      priority: "critical" | "high" | "medium" | "low";
      formattedPlan: string;
    }> = [];
    
    if (options.includeRemediation !== false) {
      vulnerabilityBreakdown.forEach(vuln => {
        const evalForType = evaluations.find(e => e.exposureType === vuln.type);
        const priority = evalForType?.priority as "critical" | "high" | "medium" | "low" || "medium";
        const guidance = getRemediationGuidance(vuln.type as ExposureType);
        const formatted = formatRemediationSection({
          vulnerabilityType: vuln.type as ExposureType,
          vulnerabilityName: vuln.humanReadableName,
          affectedAssets: [],
          immediateActions: guidance.immediateActions,
          shortTermSteps: guidance.shortTermRemediation,
          longTermSteps: guidance.longTermRemediation,
          compensatingControls: guidance.compensatingControls,
          references: guidance.references,
        });
        remediationByExposureType.push({
          exposureType: vuln.type,
          humanReadableName: vuln.humanReadableName,
          count: vuln.count,
          priority,
          formattedPlan: formatted,
        });
      });
    }
    
    const sortedRemediation = remediationByExposureType.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
    
    const formattedRemediation = sortedRemediation.length > 0
      ? sortedRemediation.map(r => r.formattedPlan).join("\n\n---\n\n")
      : "";
    
    const priorityCounts = {
      critical: evaluations.filter(e => e.priority === "critical").length,
      high: evaluations.filter(e => e.priority === "high").length,
      medium: evaluations.filter(e => e.priority === "medium").length,
      low: evaluations.filter(e => e.priority === "low").length,
    };
    
    const dataStatus = {
      hasEvaluations: evaluations.length > 0,
      hasResults: results.length > 0,
      evaluationCount: evaluations.length,
      resultCount: results.length,
      message: evaluations.length === 0 
        ? "No evaluations found in the specified date range"
        : results.length === 0
          ? `${evaluations.length} evaluations found, but no analysis results yet`
          : `${evaluations.length} evaluations with ${results.length} completed analyses`,
    };
    
    return {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        reportType: "date_range",
        period: { from: from.toISOString(), to: to.toISOString() },
        organizationId,
      },
      dataStatus,
      evaluations,
      results,
      executiveSummary: computedSummary,
      technicalReport: computedTechnical,
      killChain: {
        section: killChainSection,
        textualDiagram: killChainDiagram,
        pdfContent: killChainPdfContent,
      },
      vulnerabilityBreakdown,
      aggregatedRemediation: {
        totalVulnerabilityTypes: vulnerabilityBreakdown.length,
        byExposureType: sortedRemediation,
        prioritizedPlan: formattedRemediation || "No remediation plan available - no vulnerabilities found in the specified date range",
        byPriority: priorityCounts,
      },
    };
  }
}

export const reportGenerator = new ReportGenerator();
