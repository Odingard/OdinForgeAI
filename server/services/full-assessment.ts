import OpenAI from "openai";
import type { FullAssessment, AgentFinding, EndpointAgent } from "@shared/schema";
import { storage } from "../storage";
import { wsService } from "./websocket";

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
      await updateAssessmentStatus(assessmentId, "failed", 0, "No agents available for assessment");
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
          unifiedAttackGraph: { nodes: [], edges: [] },
          criticalPaths: [],
          lateralMovement: [],
          businessImpact: { 
            confidentialityImpact: "none",
            integrityImpact: "none", 
            availabilityImpact: "none",
            financialRisk: "none",
            reputationalRisk: "none",
            complianceRisk: "none",
            narrative: "No findings in scope to analyze."
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
