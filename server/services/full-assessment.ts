import OpenAI from "openai";
import type { FullAssessment, AgentFinding, EndpointAgent } from "@shared/schema";
import { storage } from "../storage";
import { wsService } from "./websocket";
import { runWebAppReconnaissance, type WebAppReconResult } from "./web-app-recon";
import { dispatchParallelAgents, type AgentDispatchResult } from "./parallel-agent-dispatcher";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

export type FullAssessmentProgressCallback = (
  assessmentId: string,
  phase: string,
  progress: number,
  message: string
) => void;

interface SystemProfile {
  agentId: string;
  hostname: string;
  platform: string;
  findings: AgentFinding[];
  openPorts?: any[];
  services?: any[];
}

interface AttackGraphNode {
  id: string;
  type: "system" | "vulnerability" | "technique" | "impact";
  label: string;
  severity?: string;
  systemId?: string;
}

interface AttackGraphEdge {
  source: string;
  target: string;
  label?: string;
  technique?: string;
}

interface CriticalPath {
  pathId: string;
  nodes: string[];
  riskScore: number;
  description: string;
}

interface Recommendation {
  id: string;
  priority: string;
  title: string;
  description: string;
  affectedSystems: string[];
  effort: string;
  impact: string;
}

// External mode assessment for serverless applications (no agents required)
async function runExternalModeAssessment(
  assessmentId: string,
  assessment: FullAssessment,
  startTime: number,
  onProgress?: FullAssessmentProgressCallback
): Promise<void> {
  const targetUrl = assessment.targetUrl;
  
  if (!targetUrl) {
    await updateAssessmentStatus(assessmentId, "failed", 0, "Target URL is required for external mode assessment");
    return;
  }
  
  console.log(`[ExternalAssessment] Starting external-only assessment for ${targetUrl}`);
  
  try {
    // Phase 1: Web App Reconnaissance
    await updateAssessmentStatus(assessmentId, "web_recon", 10, "Starting web application reconnaissance...");
    onProgress?.(assessmentId, "web_recon", 10, "Scanning target application...");
    broadcastProgress(assessmentId, "web_recon", 10, "Scanning target application...");
    
    let reconResult: WebAppReconResult | null = null;
    try {
      reconResult = await runWebAppReconnaissance(targetUrl, (phase, progress, message) => {
        const adjustedProgress = 10 + Math.floor(progress * 0.2);
        onProgress?.(assessmentId, "web_recon", adjustedProgress, message);
        broadcastProgress(assessmentId, "web_recon", adjustedProgress, message);
      });
      
      // Store recon results
      await storage.updateFullAssessment(assessmentId, {
        webAppRecon: {
          targetUrl,
          scanDurationMs: reconResult.durationMs,
          applicationInfo: {
            title: reconResult.applicationInfo.title,
            technologies: reconResult.applicationInfo.technologies,
            frameworks: reconResult.applicationInfo.frameworks,
            missingSecurityHeaders: reconResult.applicationInfo.missingSecurityHeaders,
          },
          attackSurface: reconResult.attackSurface,
          endpoints: reconResult.endpoints.map(e => ({
            url: e.url,
            method: e.method,
            path: e.path,
            type: e.type,
            priority: e.priority,
            parameters: e.parameters.map(p => ({
              name: p.name,
              vulnerabilityPotential: p.vulnerabilityPotential,
            })),
          })),
        },
        reconFindings: {
          technologies: reconResult.applicationInfo.technologies,
          frameworks: reconResult.applicationInfo.frameworks,
          securityHeaders: reconResult.applicationInfo.securityHeaders,
          missingSecurityHeaders: reconResult.applicationInfo.missingSecurityHeaders,
        },
      });
      
      console.log(`[ExternalAssessment] Recon complete: ${reconResult.endpoints.length} endpoints discovered`);
    } catch (reconError) {
      console.error("[ExternalAssessment] Web recon failed:", reconError);
      await updateAssessmentStatus(assessmentId, "failed", 15, `Cannot reach target: ${targetUrl}`);
      return;
    }
    
    // Phase 2: Parallel Agent Dispatch for vulnerability validation
    await updateAssessmentStatus(assessmentId, "vulnerability_scanning", 35, "Dispatching validation agents...");
    onProgress?.(assessmentId, "vulnerability_scanning", 35, "Testing for vulnerabilities...");
    broadcastProgress(assessmentId, "vulnerability_scanning", 35, "Testing for vulnerabilities...");
    
    let agentDispatchResult: AgentDispatchResult | null = null;
    try {
      agentDispatchResult = await dispatchParallelAgents(
        reconResult,
        {
          maxConcurrentAgents: 6,
          enableLLMValidation: true,
          vulnerabilityTypes: ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal", "ssrf"],
        },
        (phase: string, progress: number, message: string) => {
          const adjustedProgress = 35 + Math.floor(progress * 0.3);
          onProgress?.(assessmentId, "vulnerability_scanning", adjustedProgress, message);
          broadcastProgress(assessmentId, "vulnerability_scanning", adjustedProgress, message);
        }
      );
      
      // Store validated findings
      await storage.updateFullAssessment(assessmentId, {
        validatedFindings: agentDispatchResult.findings,
        agentDispatchStats: {
          totalTasks: agentDispatchResult.totalTasks,
          completedTasks: agentDispatchResult.completedTasks,
          failedTasks: agentDispatchResult.failedTasks,
          falsePositivesFiltered: agentDispatchResult.falsePositivesFiltered,
          executionTimeMs: agentDispatchResult.executionTimeMs,
          tasksByVulnerabilityType: agentDispatchResult.tasksByVulnerabilityType,
        },
      });
      
      console.log(`[ExternalAssessment] Validation complete: ${agentDispatchResult.findings.length} vulnerabilities found`);
    } catch (dispatchError) {
      console.error("[ExternalAssessment] Agent dispatch failed:", dispatchError);
      // Continue without validated findings
    }
    
    // Phase 3: AI-powered Analysis
    await updateAssessmentStatus(assessmentId, "attack_synthesis", 70, "Synthesizing attack paths...");
    onProgress?.(assessmentId, "attack_synthesis", 70, "Analyzing attack vectors...");
    broadcastProgress(assessmentId, "attack_synthesis", 70, "Analyzing attack vectors...");
    
    // Build attack graph from external findings
    const externalFindings = agentDispatchResult?.findings || [];
    const attackGraph = await buildExternalAttackGraph(targetUrl, externalFindings, reconResult);
    
    // Phase 4: Business Impact Analysis
    await updateAssessmentStatus(assessmentId, "impact_assessment", 85, "Assessing business impact...");
    onProgress?.(assessmentId, "impact_assessment", 85, "Calculating risk...");
    broadcastProgress(assessmentId, "impact_assessment", 85, "Calculating risk...");
    
    const impactAnalysis = await analyzeExternalBusinessImpact(targetUrl, externalFindings, reconResult);
    
    // Calculate overall risk score
    const riskScore = calculateExternalRiskScore(externalFindings, reconResult);
    
    // Generate recommendations
    const recommendations = generateExternalRecommendations(externalFindings, reconResult);
    
    // Generate executive summary
    const executiveSummary = await generateExternalExecutiveSummary(
      targetUrl,
      reconResult,
      externalFindings,
      riskScore
    );
    
    // Complete the assessment
    await storage.updateFullAssessment(assessmentId, {
      status: "completed",
      progress: 100,
      currentPhase: "completed",
      overallRiskScore: riskScore,
      criticalPathCount: attackGraph.criticalPaths.length,
      systemsAnalyzed: 1, // External mode always analyzes 1 target
      findingsAnalyzed: externalFindings.length,
      unifiedAttackGraph: attackGraph,
      businessImpactAnalysis: impactAnalysis,
      recommendations,
      executiveSummary,
      durationMs: Date.now() - startTime,
      completedAt: new Date(),
    });
    
    broadcastProgress(assessmentId, "completed", 100, "External assessment complete");
    console.log(`[ExternalAssessment] Completed in ${Date.now() - startTime}ms`);
    
  } catch (error) {
    console.error("[ExternalAssessment] Fatal error:", error);
    await updateAssessmentStatus(assessmentId, "failed", 0, `Assessment failed: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}

// Helper functions for external mode
async function buildExternalAttackGraph(
  targetUrl: string,
  findings: any[],
  reconResult: WebAppReconResult
): Promise<{ nodes: any[]; edges: any[]; criticalPaths: any[] }> {
  const nodes: any[] = [];
  const edges: any[] = [];
  const criticalPaths: any[] = [];
  
  // Add target system node
  nodes.push({
    id: "target",
    type: "system",
    label: targetUrl,
  });
  
  // Add vulnerability nodes from findings
  findings.forEach((finding, idx) => {
    const vulnId = `vuln-${idx}`;
    nodes.push({
      id: vulnId,
      type: "vulnerability",
      label: finding.vulnerabilityType || finding.type,
      severity: finding.severity,
      systemId: "target",
    });
    edges.push({
      source: "target",
      target: vulnId,
      label: "exposes",
    });
    
    // Add technique nodes for high/critical findings
    if (finding.severity === "critical" || finding.severity === "high") {
      const techId = `tech-${idx}`;
      nodes.push({
        id: techId,
        type: "technique",
        label: mapVulnToTechnique(finding.vulnerabilityType || finding.type),
      });
      edges.push({
        source: vulnId,
        target: techId,
        label: "enables",
      });
      
      // Build critical path
      criticalPaths.push({
        pathId: `path-${idx}`,
        nodes: ["target", vulnId, techId],
        riskScore: finding.severity === "critical" ? 90 : 70,
        description: `${finding.vulnerabilityType || finding.type} vulnerability leading to potential exploitation`,
      });
    }
  });
  
  return { nodes, edges, criticalPaths };
}

function mapVulnToTechnique(vulnType: string): string {
  const mapping: Record<string, string> = {
    sqli: "T1190 - Exploit Public-Facing Application",
    xss: "T1189 - Drive-by Compromise",
    auth_bypass: "T1078 - Valid Accounts",
    command_injection: "T1059 - Command and Scripting Interpreter",
    path_traversal: "T1083 - File and Directory Discovery",
    ssrf: "T1090 - Proxy",
  };
  return mapping[vulnType] || "T1190 - Exploit Public-Facing Application";
}

async function analyzeExternalBusinessImpact(
  targetUrl: string,
  findings: any[],
  reconResult: WebAppReconResult
): Promise<any> {
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  
  let overallRisk = "low";
  if (criticalCount > 0) overallRisk = "critical";
  else if (highCount > 2) overallRisk = "high";
  else if (highCount > 0) overallRisk = "medium";
  
  return {
    overallRisk,
    dataAtRisk: {
      types: criticalCount > 0 || highCount > 0 ? ["user_data", "credentials", "session_tokens"] : [],
      estimatedRecords: criticalCount > 0 ? "Unknown - potential full database exposure" : "Limited",
      regulatoryImplications: criticalCount > 0 ? ["GDPR", "CCPA", "SOC2"] : [],
    },
    operationalImpact: {
      systemsAffected: 1,
      potentialDowntime: criticalCount > 0 ? "significant" : highCount > 0 ? "moderate" : "minimal",
      businessProcesses: criticalCount > 0 ? ["authentication", "data_processing", "api_access"] : [],
    },
    financialImpact: {
      estimatedRange: criticalCount > 0 ? "$50,000 - $500,000+" : highCount > 0 ? "$10,000 - $100,000" : "$0 - $10,000",
      factors: findings.length > 0 ? ["remediation_costs", "potential_breach_costs", "reputation_damage"] : [],
    },
    reputationalImpact: criticalCount > 0 
      ? "Critical vulnerabilities could lead to significant reputational damage if exploited."
      : highCount > 0 
        ? "High-severity vulnerabilities present moderate reputational risk."
        : "Limited reputational risk based on findings.",
  };
}

function calculateExternalRiskScore(findings: any[], reconResult: WebAppReconResult): number {
  let score = 0;
  
  // Severity-based scoring
  findings.forEach(f => {
    switch (f.severity) {
      case "critical": score += 25; break;
      case "high": score += 15; break;
      case "medium": score += 8; break;
      case "low": score += 3; break;
    }
  });
  
  // Missing security headers penalty
  score += (reconResult.applicationInfo.missingSecurityHeaders?.length || 0) * 2;
  
  // Cap at 100
  return Math.min(100, score);
}

function generateExternalRecommendations(findings: any[], reconResult: WebAppReconResult): any[] {
  const recommendations: any[] = [];
  
  // Group findings by type
  const findingsByType = findings.reduce((acc, f) => {
    const type = f.vulnerabilityType || f.type || "unknown";
    if (!acc[type]) acc[type] = [];
    acc[type].push(f);
    return acc;
  }, {} as Record<string, any[]>);
  
  Object.entries(findingsByType).forEach(([type, typeFindings], idx) => {
    const maxSeverity = (typeFindings as any[]).reduce((max, f) => {
      const order = ["critical", "high", "medium", "low", "info"];
      return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max;
    }, "info");
    
    recommendations.push({
      id: `rec-${idx}`,
      priority: maxSeverity === "critical" ? "P1" : maxSeverity === "high" ? "P2" : "P3",
      title: `Remediate ${type.replace(/_/g, " ")} vulnerabilities`,
      description: `Found ${(typeFindings as any[]).length} ${type.replace(/_/g, " ")} vulnerability(ies) that require remediation.`,
      affectedSystems: [reconResult.targetUrl],
      effort: maxSeverity === "critical" || maxSeverity === "high" ? "medium" : "low",
      impact: maxSeverity === "critical" ? "critical" : maxSeverity === "high" ? "high" : "medium",
    });
  });
  
  // Add recommendations for missing security headers
  if (reconResult.applicationInfo.missingSecurityHeaders?.length > 0) {
    recommendations.push({
      id: `rec-headers`,
      priority: "P2",
      title: "Implement missing security headers",
      description: `Add missing security headers: ${reconResult.applicationInfo.missingSecurityHeaders.join(", ")}`,
      affectedSystems: [reconResult.targetUrl],
      effort: "low",
      impact: "medium",
    });
  }
  
  return recommendations;
}

async function generateExternalExecutiveSummary(
  targetUrl: string,
  reconResult: WebAppReconResult,
  findings: any[],
  riskScore: number
): Promise<string> {
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  
  let riskLevel = "Low";
  if (riskScore >= 70) riskLevel = "Critical";
  else if (riskScore >= 50) riskLevel = "High";
  else if (riskScore >= 25) riskLevel = "Medium";
  
  return `
## External Security Assessment Summary

**Target:** ${targetUrl}
**Assessment Mode:** External (Serverless/API)
**Overall Risk Score:** ${riskScore}/100 (${riskLevel})

### Application Profile
- **Technologies:** ${reconResult.applicationInfo.technologies.join(", ") || "Not detected"}
- **Frameworks:** ${reconResult.applicationInfo.frameworks.join(", ") || "Not detected"}
- **Endpoints Discovered:** ${reconResult.endpoints.length}
- **Missing Security Headers:** ${reconResult.applicationInfo.missingSecurityHeaders?.length || 0}

### Vulnerability Summary
- **Critical:** ${criticalCount}
- **High:** ${highCount}
- **Medium:** ${mediumCount}
- **Total Findings:** ${findings.length}

### Key Observations
${findings.length === 0 
  ? "No active vulnerabilities were detected during this assessment. Continue monitoring and maintain security best practices."
  : criticalCount > 0 
    ? "Critical vulnerabilities require immediate attention. Exploitation could lead to data breach or system compromise."
    : highCount > 0 
      ? "High-severity vulnerabilities should be prioritized for remediation within the next sprint cycle."
      : "Moderate risk profile. Address findings during regular maintenance cycles."}

### Recommended Actions
1. ${criticalCount > 0 ? "URGENT: Address all critical vulnerabilities immediately" : "Review and prioritize vulnerability remediation"}
2. ${reconResult.applicationInfo.missingSecurityHeaders?.length > 0 ? "Implement missing security headers" : "Maintain current security header configuration"}
3. Conduct regular security assessments to maintain security posture
`.trim();
}

export async function runFullAssessment(
  assessmentId: string,
  onProgress?: FullAssessmentProgressCallback
): Promise<void> {
  const startTime = Date.now();
  
  try {
    await updateAssessmentStatus(assessmentId, "reconnaissance", 5, "Starting reconnaissance phase...");
    onProgress?.(assessmentId, "reconnaissance", 5, "Gathering system telemetry...");
    broadcastProgress(assessmentId, "reconnaissance", 5, "Gathering system telemetry...");
    
    // Get the assessment to check for scope constraints
    const assessment = await storage.getFullAssessment(assessmentId);
    if (!assessment) {
      await updateAssessmentStatus(assessmentId, "failed", 0, "Assessment not found");
      return;
    }
    
    // Check if this is an external-only assessment (for serverless apps)
    const isExternalMode = assessment.assessmentMode === "external";
    
    if (isExternalMode) {
      // External mode: Run web app recon instead of agent-based assessment
      await runExternalModeAssessment(assessmentId, assessment, startTime, onProgress);
      return;
    }
    
    // Agent mode: Requires endpoint agents
    // Get agents - scoped to specific IDs if specified, otherwise all
    let agents = await storage.getEndpointAgents();
    if (assessment.agentIds && assessment.agentIds.length > 0) {
      const scopedAgentIds = new Set(assessment.agentIds);
      agents = agents.filter(a => scopedAgentIds.has(a.id));
    }
    
    // Get findings - scoped to specific IDs or by agent scope
    let allFindings: AgentFinding[];
    if (assessment.findingIds && assessment.findingIds.length > 0) {
      // Use only specified finding IDs
      const findings: AgentFinding[] = [];
      for (const findingId of assessment.findingIds) {
        const finding = await storage.getAgentFinding(findingId);
        if (finding) findings.push(finding);
      }
      allFindings = findings;
    } else if (assessment.agentIds && assessment.agentIds.length > 0) {
      // Scope findings to only the specified agents
      allFindings = await getScopedFindings(assessment.agentIds);
    } else {
      // No scope - get all findings
      allFindings = await getAllFindings();
    }
    
    // For scoped assessments, allow completion with zero findings (soft warning)
    const isScoped = (assessment.agentIds && assessment.agentIds.length > 0) || 
                     (assessment.findingIds && assessment.findingIds.length > 0);
    
    if (agents.length === 0) {
      await updateAssessmentStatus(assessmentId, "failed", 0, "No agents available for assessment. Use 'External' mode for serverless apps.");
      return;
    }
    
    if (allFindings.length === 0) {
      if (isScoped) {
        // Scoped assessment with no findings - complete with zero results
        await storage.updateFullAssessment(assessmentId, {
          status: "completed",
          progress: 100,
          currentPhase: "completed",
          overallRiskScore: 0,
          criticalPathCount: 0,
          systemsAnalyzed: agents.length,
          findingsAnalyzed: 0,
          durationMs: Date.now() - startTime,
          completedAt: new Date(),
          unifiedAttackGraph: { nodes: [], edges: [], criticalPaths: [] },
          lateralMovementPaths: { paths: [], highRiskPivots: [] },
          businessImpactAnalysis: { 
            overallRisk: "none",
            dataAtRisk: { types: [], estimatedRecords: "0", regulatoryImplications: [] },
            operationalImpact: { systemsAffected: 0, potentialDowntime: "none", businessProcesses: [] },
            financialImpact: { estimatedRange: "$0", factors: [] },
            reputationalImpact: "No findings in scope to analyze."
          },
          recommendations: [],
          executiveSummary: "No findings were available in the specified scope for this assessment.",
        });
        broadcastProgress(assessmentId, "completed", 100, "Assessment completed with no findings in scope");
        return;
      }
      await updateAssessmentStatus(assessmentId, "failed", 0, "No findings available for assessment");
      return;
    }

    const systemProfiles = await buildSystemProfiles(agents, allFindings);
    await updateAssessmentStatus(assessmentId, "reconnaissance", 20, `Profiled ${systemProfiles.length} systems with ${allFindings.length} findings`);
    onProgress?.(assessmentId, "reconnaissance", 20, `Profiled ${systemProfiles.length} systems`);
    broadcastProgress(assessmentId, "reconnaissance", 20, `Profiled ${systemProfiles.length} systems`);

    await updateAssessmentStatus(assessmentId, "vulnerability_analysis", 30, "Analyzing vulnerabilities across all systems...");
    onProgress?.(assessmentId, "vulnerability_analysis", 30, "Analyzing vulnerabilities...");
    broadcastProgress(assessmentId, "vulnerability_analysis", 30, "Analyzing vulnerabilities...");
    
    const vulnerabilityAnalysis = await analyzeVulnerabilities(systemProfiles);
    await updateAssessmentStatus(assessmentId, "vulnerability_analysis", 45, "Vulnerability analysis complete");

    await updateAssessmentStatus(assessmentId, "attack_synthesis", 50, "Synthesizing cross-system attack paths...");
    onProgress?.(assessmentId, "attack_synthesis", 50, "Mapping attack paths...");
    broadcastProgress(assessmentId, "attack_synthesis", 50, "Mapping attack paths...");
    
    const attackGraph = await synthesizeCrossSystemAttackGraph(systemProfiles, vulnerabilityAnalysis);
    await updateAssessmentStatus(assessmentId, "attack_synthesis", 65, "Attack graph complete");

    await updateAssessmentStatus(assessmentId, "lateral_analysis", 70, "Analyzing lateral movement opportunities...");
    onProgress?.(assessmentId, "lateral_analysis", 70, "Analyzing lateral movement...");
    broadcastProgress(assessmentId, "lateral_analysis", 70, "Analyzing lateral movement...");
    
    const lateralPaths = await analyzeLateralMovement(systemProfiles, attackGraph);
    await updateAssessmentStatus(assessmentId, "lateral_analysis", 80, "Lateral movement analysis complete");

    await updateAssessmentStatus(assessmentId, "impact_assessment", 85, "Assessing business impact...");
    onProgress?.(assessmentId, "impact_assessment", 85, "Assessing business impact...");
    broadcastProgress(assessmentId, "impact_assessment", 85, "Assessing business impact...");
    
    const impactAnalysis = await assessBusinessImpact(systemProfiles, attackGraph, lateralPaths);
    
    const recommendations = await generatePrioritizedRecommendations(
      systemProfiles,
      vulnerabilityAnalysis,
      attackGraph,
      impactAnalysis
    );
    
    const executiveSummary = await generateExecutiveSummary(
      systemProfiles,
      vulnerabilityAnalysis,
      attackGraph,
      impactAnalysis
    );

    const overallRiskScore = calculateOverallRiskScore(attackGraph, impactAnalysis);
    const durationMs = Date.now() - startTime;

    await storage.updateFullAssessment(assessmentId, {
      status: "completed",
      progress: 100,
      currentPhase: "completed",
      overallRiskScore,
      criticalPathCount: attackGraph.criticalPaths.length,
      systemsAnalyzed: systemProfiles.length,
      findingsAnalyzed: allFindings.length,
      unifiedAttackGraph: attackGraph,
      executiveSummary,
      reconFindings: systemProfiles.map(s => ({ agentId: s.agentId, hostname: s.hostname, findingCount: s.findings.length })),
      vulnerabilityFindings: vulnerabilityAnalysis,
      lateralMovementPaths: lateralPaths,
      businessImpactAnalysis: impactAnalysis,
      recommendations,
      completedAt: new Date(),
      durationMs,
    });

    onProgress?.(assessmentId, "completed", 100, "Full assessment complete");
    broadcastProgress(assessmentId, "completed", 100, "Assessment complete");
    
    wsService.broadcast({
      type: "full_assessment_complete",
      assessmentId,
      overallRiskScore,
      criticalPathCount: attackGraph.criticalPaths.length,
    } as any);

  } catch (error) {
    console.error("Full assessment error:", error);
    await storage.updateFullAssessment(assessmentId, {
      status: "failed",
      progress: 0,
      currentPhase: "failed",
    });
    broadcastProgress(assessmentId, "failed", 0, `Assessment failed: ${error instanceof Error ? error.message : "Unknown error"}`);
    throw error;
  }
}

async function updateAssessmentStatus(
  assessmentId: string,
  status: string,
  progress: number,
  phase: string
): Promise<void> {
  await storage.updateFullAssessment(assessmentId, {
    status,
    progress,
    currentPhase: phase,
  });
}

function broadcastProgress(assessmentId: string, phase: string, progress: number, message: string): void {
  wsService.broadcast({
    type: "full_assessment_progress",
    assessmentId,
    phase,
    progress,
    message,
  } as any);
}

async function getAllFindings(): Promise<AgentFinding[]> {
  const agents = await storage.getEndpointAgents();
  const allFindings: AgentFinding[] = [];
  
  for (const agent of agents) {
    const findings = await storage.getAgentFindings(agent.id);
    allFindings.push(...findings);
  }
  
  return allFindings;
}

// Get findings scoped to specific agent IDs only
async function getScopedFindings(agentIds: string[]): Promise<AgentFinding[]> {
  const allFindings: AgentFinding[] = [];
  
  for (const agentId of agentIds) {
    const findings = await storage.getAgentFindings(agentId);
    allFindings.push(...findings);
  }
  
  return allFindings;
}

async function buildSystemProfiles(
  agents: EndpointAgent[],
  findings: AgentFinding[]
): Promise<SystemProfile[]> {
  const profiles: SystemProfile[] = [];
  
  for (const agent of agents) {
    const agentFindings = findings.filter(f => f.agentId === agent.id);
    const telemetry = await storage.getAgentTelemetry(agent.id);
    const latestTelemetry = telemetry[0];
    
    profiles.push({
      agentId: agent.id,
      hostname: agent.hostname || agent.agentName,
      platform: agent.platform || "unknown",
      findings: agentFindings,
      openPorts: latestTelemetry?.openPorts as any[] || [],
      services: latestTelemetry?.services as any[] || [],
    });
  }
  
  return profiles;
}

async function analyzeVulnerabilities(profiles: SystemProfile[]): Promise<any> {
  const findingsSummary = profiles.flatMap(p => 
    p.findings.map(f => ({
      system: p.hostname,
      severity: f.severity,
      title: f.title,
      component: f.affectedComponent,
      cve: f.cveId,
    }))
  );

  if (findingsSummary.length === 0) {
    return { vulnerabilities: [], riskDistribution: {} };
  }

  const prompt = `Analyze these security findings across multiple systems and categorize by exploitability:

Systems and Findings:
${JSON.stringify(findingsSummary, null, 2)}

Provide analysis as JSON:
{
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "title": "string",
      "severity": "critical|high|medium|low",
      "affectedSystems": ["hostname1", "hostname2"],
      "exploitability": "easy|moderate|difficult",
      "chainPotential": "high|medium|low",
      "description": "string"
    }
  ],
  "riskDistribution": {
    "critical": number,
    "high": number,
    "medium": number,
    "low": number
  },
  "keyRisks": ["string"]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a security analyst performing vulnerability assessment. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 4096,
    });

    return JSON.parse(response.choices[0]?.message?.content || "{}");
  } catch (error) {
    console.error("Vulnerability analysis error:", error);
    return { vulnerabilities: findingsSummary, riskDistribution: {} };
  }
}

async function synthesizeCrossSystemAttackGraph(
  profiles: SystemProfile[],
  vulnerabilityAnalysis: any
): Promise<{ nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; criticalPaths: CriticalPath[] }> {
  const systemsInfo = profiles.map(p => ({
    hostname: p.hostname,
    platform: p.platform,
    openPorts: p.openPorts?.slice(0, 10),
    findings: p.findings.map(f => ({ title: f.title, severity: f.severity, component: f.affectedComponent })),
  }));

  const prompt = `Create a unified attack graph showing how an attacker could chain vulnerabilities across these systems:

Systems:
${JSON.stringify(systemsInfo, null, 2)}

Vulnerability Analysis:
${JSON.stringify(vulnerabilityAnalysis, null, 2)}

Generate a comprehensive attack graph as JSON:
{
  "nodes": [
    {"id": "unique-id", "type": "system|vulnerability|technique|impact", "label": "string", "severity": "critical|high|medium|low", "systemId": "hostname"}
  ],
  "edges": [
    {"source": "node-id", "target": "node-id", "label": "description", "technique": "MITRE ATT&CK ID"}
  ],
  "criticalPaths": [
    {"pathId": "path-1", "nodes": ["node-id-1", "node-id-2"], "riskScore": 0-100, "description": "Attack chain description"}
  ]
}

Focus on:
1. Entry points (internet-facing vulnerabilities)
2. Pivot points (how attacker moves between systems)
3. High-value targets (databases, credential stores)
4. Complete attack chains from initial access to impact`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a penetration tester creating attack graphs. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 4096,
    });

    const result = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      nodes: result.nodes || [],
      edges: result.edges || [],
      criticalPaths: result.criticalPaths || [],
    };
  } catch (error) {
    console.error("Attack graph synthesis error:", error);
    return { nodes: [], edges: [], criticalPaths: [] };
  }
}

async function analyzeLateralMovement(
  profiles: SystemProfile[],
  attackGraph: { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; criticalPaths: CriticalPath[] }
): Promise<any> {
  const prompt = `Analyze lateral movement opportunities between these systems:

Systems:
${profiles.map(p => `- ${p.hostname} (${p.platform}): ${p.openPorts?.length || 0} open ports, ${p.findings.length} findings`).join("\n")}

Attack Graph Edges:
${JSON.stringify(attackGraph.edges.slice(0, 20), null, 2)}

Identify lateral movement paths as JSON:
{
  "paths": [
    {
      "id": "lat-1",
      "source": "hostname",
      "target": "hostname",
      "technique": "MITRE technique",
      "method": "How attacker would move",
      "likelihood": "high|medium|low",
      "prerequisites": ["what's needed first"]
    }
  ],
  "highRiskPivots": ["list of systems that enable many lateral paths"]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are analyzing lateral movement in a penetration test. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    return JSON.parse(response.choices[0]?.message?.content || "{}");
  } catch (error) {
    console.error("Lateral movement analysis error:", error);
    return { paths: [], highRiskPivots: [] };
  }
}

async function assessBusinessImpact(
  profiles: SystemProfile[],
  attackGraph: { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; criticalPaths: CriticalPath[] },
  lateralPaths: any
): Promise<any> {
  const prompt = `Assess the business impact if the identified attack paths are exploited:

Systems: ${profiles.map(p => p.hostname).join(", ")}
Critical Attack Paths: ${attackGraph.criticalPaths.length}
Lateral Movement Opportunities: ${lateralPaths.paths?.length || 0}

Critical Path Details:
${JSON.stringify(attackGraph.criticalPaths.slice(0, 5), null, 2)}

Provide business impact assessment as JSON:
{
  "overallRisk": "critical|high|medium|low",
  "dataAtRisk": {
    "types": ["PII", "Financial", "Credentials", etc],
    "estimatedRecords": "range estimate",
    "regulatoryImplications": ["GDPR", "PCI-DSS", etc]
  },
  "operationalImpact": {
    "systemsAffected": number,
    "potentialDowntime": "estimate",
    "businessProcesses": ["list of affected processes"]
  },
  "financialImpact": {
    "estimatedRange": "$X - $Y",
    "factors": ["breach costs", "remediation", etc]
  },
  "reputationalImpact": "description"
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a security risk analyst assessing business impact. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    return JSON.parse(response.choices[0]?.message?.content || "{}");
  } catch (error) {
    console.error("Business impact assessment error:", error);
    return {};
  }
}

async function generatePrioritizedRecommendations(
  profiles: SystemProfile[],
  vulnerabilityAnalysis: any,
  attackGraph: { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; criticalPaths: CriticalPath[] },
  impactAnalysis: any
): Promise<Recommendation[]> {
  const prompt = `Generate prioritized remediation recommendations based on this security assessment:

Systems: ${profiles.length}
Vulnerabilities: ${JSON.stringify(vulnerabilityAnalysis.vulnerabilities?.slice(0, 10) || [], null, 2)}
Critical Paths: ${attackGraph.criticalPaths.length}
Business Impact: ${impactAnalysis.overallRisk || "unknown"}

Provide recommendations as JSON:
{
  "recommendations": [
    {
      "id": "rec-1",
      "priority": "critical|high|medium|low",
      "title": "Short title",
      "description": "Detailed remediation steps",
      "affectedSystems": ["hostname1", "hostname2"],
      "effort": "low|medium|high",
      "impact": "Description of security improvement"
    }
  ]
}

Prioritize by:
1. Breaking critical attack paths
2. Reducing lateral movement opportunities
3. Protecting high-value assets
4. Quick wins with high impact`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a security consultant providing remediation guidance. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 3000,
    });

    const result = JSON.parse(response.choices[0]?.message?.content || "{}");
    return result.recommendations || [];
  } catch (error) {
    console.error("Recommendations generation error:", error);
    return [];
  }
}

async function generateExecutiveSummary(
  profiles: SystemProfile[],
  vulnerabilityAnalysis: any,
  attackGraph: { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; criticalPaths: CriticalPath[] },
  impactAnalysis: any
): Promise<string> {
  const prompt = `Write a concise executive summary for this security assessment:

- Systems Assessed: ${profiles.length}
- Total Findings: ${profiles.reduce((sum, p) => sum + p.findings.length, 0)}
- Critical Attack Paths: ${attackGraph.criticalPaths.length}
- Overall Risk: ${impactAnalysis.overallRisk || "Not determined"}
- Key Risks: ${JSON.stringify(vulnerabilityAnalysis.keyRisks || [])}

Write 2-3 paragraphs suitable for C-level executives. Focus on business risk, not technical details. Be direct and actionable.`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are writing an executive summary for a security assessment. Be concise and business-focused." },
        { role: "user", content: prompt },
      ],
      max_completion_tokens: 1000,
    });

    return response.choices[0]?.message?.content || "Executive summary generation failed.";
  } catch (error) {
    console.error("Executive summary generation error:", error);
    return "Executive summary could not be generated.";
  }
}

function calculateOverallRiskScore(
  attackGraph: { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; criticalPaths: CriticalPath[] },
  impactAnalysis: any
): number {
  let score = 0;
  
  const criticalPaths = attackGraph.criticalPaths.length;
  if (criticalPaths >= 5) score += 40;
  else if (criticalPaths >= 3) score += 30;
  else if (criticalPaths >= 1) score += 20;
  
  const avgPathScore = attackGraph.criticalPaths.reduce((sum, p) => sum + (p.riskScore || 50), 0) / Math.max(1, criticalPaths);
  score += avgPathScore * 0.4;
  
  const overallRisk = impactAnalysis.overallRisk?.toLowerCase();
  if (overallRisk === "critical") score += 20;
  else if (overallRisk === "high") score += 15;
  else if (overallRisk === "medium") score += 10;
  else if (overallRisk === "low") score += 5;
  
  return Math.min(100, Math.max(0, Math.round(score)));
}

// ============================================================================
// Enhanced Full Assessment with Web App Reconnaissance
// ============================================================================

export interface EnhancedAssessmentOptions {
  targetUrl?: string;
  enableWebAppRecon?: boolean;
  enableParallelAgents?: boolean;
  maxConcurrentAgents?: number;
  vulnerabilityTypes?: ("sqli" | "xss" | "auth_bypass" | "command_injection" | "path_traversal" | "ssrf")[];
  enableLLMValidation?: boolean;
}

export async function runEnhancedFullAssessment(
  assessmentId: string,
  options: EnhancedAssessmentOptions = {},
  onProgress?: FullAssessmentProgressCallback
): Promise<void> {
  const startTime = Date.now();
  
  try {
    const assessment = await storage.getFullAssessment(assessmentId);
    if (!assessment) {
      await updateAssessmentStatus(assessmentId, "failed", 0, "Assessment not found");
      return;
    }
    
    let webAppReconResult: WebAppReconResult | null = null;
    let agentDispatchResult: AgentDispatchResult | null = null;
    
    // Phase 1: Web Application Reconnaissance (if target URL provided)
    if (options.targetUrl && options.enableWebAppRecon !== false) {
      await updateAssessmentStatus(assessmentId, "web_recon", 5, "Starting web application reconnaissance...");
      onProgress?.(assessmentId, "web_recon", 5, "Crawling target application...");
      broadcastProgress(assessmentId, "web_recon", 5, "Crawling target application...");
      
      try {
        webAppReconResult = await runWebAppReconnaissance(
          options.targetUrl,
          (phase, progress, message) => {
            const adjustedProgress = Math.round(5 + (progress * 0.15)); // 5-20%
            onProgress?.(assessmentId, "web_recon", adjustedProgress, message);
            broadcastProgress(assessmentId, "web_recon", adjustedProgress, message);
          }
        );
        
        // Store web app recon results
        await storage.updateFullAssessment(assessmentId, {
          webAppRecon: {
            targetUrl: webAppReconResult.targetUrl,
            scanDurationMs: webAppReconResult.durationMs,
            applicationInfo: {
              title: webAppReconResult.applicationInfo.title,
              technologies: webAppReconResult.applicationInfo.technologies,
              frameworks: webAppReconResult.applicationInfo.frameworks,
              missingSecurityHeaders: webAppReconResult.applicationInfo.missingSecurityHeaders,
            },
            attackSurface: webAppReconResult.attackSurface,
            endpoints: webAppReconResult.endpoints.slice(0, 50).map(ep => ({
              url: ep.url,
              method: ep.method,
              path: ep.path,
              type: ep.type,
              priority: ep.priority,
              parameters: ep.parameters.map(p => ({
                name: p.name,
                vulnerabilityPotential: p.vulnerabilityPotential,
              })),
            })),
          },
        });
        
        await updateAssessmentStatus(assessmentId, "web_recon", 20, 
          `Discovered ${webAppReconResult.endpoints.length} endpoints with ${webAppReconResult.attackSurface.inputParameters} input parameters`
        );
        
      } catch (error) {
        console.error("[EnhancedAssessment] Web recon failed:", error);
        await updateAssessmentStatus(assessmentId, "web_recon", 20, 
          `Web reconnaissance failed: ${error instanceof Error ? error.message : "Unknown error"}`
        );
      }
    }
    
    // Phase 2: Parallel Agent Dispatch (if web recon succeeded)
    if (webAppReconResult && webAppReconResult.endpoints.length > 0 && options.enableParallelAgents !== false) {
      await updateAssessmentStatus(assessmentId, "agent_dispatch", 25, "Dispatching specialized security agents...");
      onProgress?.(assessmentId, "agent_dispatch", 25, "Dispatching parallel validation agents...");
      broadcastProgress(assessmentId, "agent_dispatch", 25, "Dispatching parallel validation agents...");
      
      try {
        agentDispatchResult = await dispatchParallelAgents(
          webAppReconResult,
          {
            maxConcurrentAgents: options.maxConcurrentAgents || 5,
            enableLLMValidation: options.enableLLMValidation !== false,
            vulnerabilityTypes: options.vulnerabilityTypes || ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal", "ssrf"],
          },
          (phase, progress, message, stats) => {
            const adjustedProgress = Math.round(25 + (progress * 0.35)); // 25-60%
            onProgress?.(assessmentId, "agent_dispatch", adjustedProgress, message);
            broadcastProgress(assessmentId, "agent_dispatch", adjustedProgress, message);
          }
        );
        
        // Store agent dispatch results
        await storage.updateFullAssessment(assessmentId, {
          validatedFindings: agentDispatchResult.findings.map(f => ({
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
          agentDispatchStats: {
            totalTasks: agentDispatchResult.totalTasks,
            completedTasks: agentDispatchResult.completedTasks,
            failedTasks: agentDispatchResult.failedTasks,
            falsePositivesFiltered: agentDispatchResult.falsePositivesFiltered,
            executionTimeMs: agentDispatchResult.executionTimeMs,
            tasksByVulnerabilityType: agentDispatchResult.tasksByVulnerabilityType,
          },
        });
        
        await updateAssessmentStatus(assessmentId, "agent_dispatch", 60, 
          `Completed ${agentDispatchResult.completedTasks} tasks, found ${agentDispatchResult.findings.length} validated findings`
        );
        
      } catch (error) {
        console.error("[EnhancedAssessment] Agent dispatch failed:", error);
        await updateAssessmentStatus(assessmentId, "agent_dispatch", 60, 
          `Agent dispatch failed: ${error instanceof Error ? error.message : "Unknown error"}`
        );
      }
    }
    
    // Continue with standard assessment phases...
    // The rest of the standard assessment flow continues from here
    await runFullAssessment(assessmentId, onProgress);
    
    // Update with enhanced metrics if we have web app findings
    if (agentDispatchResult && agentDispatchResult.findings.length > 0) {
      const existingAssessment = await storage.getFullAssessment(assessmentId);
      if (existingAssessment) {
        // Add validated findings to the findings count
        const totalFindings = (existingAssessment.findingsAnalyzed || 0) + agentDispatchResult.findings.length;
        
        // Recalculate risk score including web app findings
        const webAppSeverityScore = agentDispatchResult.findings.reduce((sum, f) => {
          const severityScores = { critical: 10, high: 7, medium: 4, low: 1 };
          return sum + (severityScores[f.severity] || 0);
        }, 0);
        
        const adjustedRiskScore = Math.min(100, 
          (existingAssessment.overallRiskScore || 0) + Math.round(webAppSeverityScore / agentDispatchResult.findings.length * 10)
        );
        
        await storage.updateFullAssessment(assessmentId, {
          findingsAnalyzed: totalFindings,
          overallRiskScore: adjustedRiskScore,
        });
      }
    }
    
    const durationMs = Date.now() - startTime;
    console.log(`[EnhancedAssessment] Completed in ${durationMs}ms`);
    
  } catch (error) {
    console.error("[EnhancedAssessment] Fatal error:", error);
    await storage.updateFullAssessment(assessmentId, {
      status: "failed",
      progress: 0,
      currentPhase: "failed",
    });
    broadcastProgress(assessmentId, "failed", 0, `Assessment failed: ${error instanceof Error ? error.message : "Unknown error"}`);
    throw error;
  }
}
