import type { AttackPathStep, ExposureType, Recommendation } from "@shared/schema";
import { 
  vulnerabilityCatalog, 
  remediationGuidanceTemplates,
  getVulnerabilityInfo,
  getRemediationGuidance,
  formatVulnerabilityName,
  type VulnerabilityInfo,
  type RemediationGuidance,
  type RemediationStep
} from "@shared/vulnerability-catalog";
import {
  buildKillChainVisualization,
  generateKillChainReportSection,
  generateTextualKillChainDiagram,
  type KillChainReportSection
} from "./kill-chain-graph";

export interface EvaluationData {
  id: string;
  assetId: string;
  exposureType: ExposureType;
  priority: "critical" | "high" | "medium" | "low";
  description: string;
  organizationId?: string;
  createdAt?: Date;
}

export interface ResultData {
  evaluationId: string;
  exploitable: boolean;
  score: number;
  confidence: number;
  impact?: string;
  attackPath?: AttackPathStep[];
  recommendations?: Recommendation[];
  attackGraph?: {
    complexityScore?: number;
    timeToCompromise?: { expected: number; unit: string };
    criticalPath?: string[];
  };
  intelligentScore?: {
    businessImpact?: {
      factors?: {
        financialExposure?: {
          directLoss?: { min: number; max: number };
        };
        complianceImpact?: {
          affectedFrameworks?: string[];
          violations?: Array<{ severity: string }>;
        };
      };
    };
  };
}

export interface ComputedExecutiveSummary {
  overallRiskAssessment: string;
  keyFindings: string[];
  riskDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  exploitabilityAnalysis: string;
  businessImpactSummary: string;
  prioritizedActions: Array<{
    priority: number;
    action: string;
    rationale: string;
    estimatedEffort: string;
  }>;
  trendAnalysis?: string;
}

export interface ComputedTechnicalReport {
  vulnerabilityBreakdown: Array<{
    type: ExposureType;
    name: string;
    count: number;
    exploitableCount: number;
    avgScore: number;
    description: string;
    affectedAssets: string[];
  }>;
  attackSurfaceAnalysis: string;
  killChainSection: KillChainReportSection | null;
  technicalFindings: Array<{
    evaluationId: string;
    assetId: string;
    vulnerabilityType: string;
    vulnerabilityName: string;
    severity: string;
    exploitable: boolean;
    score: number;
    technicalDescription: string;
    attackPathSummary: string;
    mitreTechniques: string[];
    cweIds: string[];
    evidenceArtifacts?: Array<{
      id: string;
      evidenceType: string;
      verdict: string;
      confidenceScore: number;
      targetUrl: string;
      observedBehavior: string;
      capturedAt: Date;
      httpRequest?: {
        method: string;
        url: string;
        headers: Record<string, string>;
      };
      httpResponse?: {
        statusCode: number;
        statusText: string;
        headers: Record<string, string>;
        body?: string;
        bodyTruncated?: boolean;
      };
    }>;
  }>;
  remediationPlan: Array<{
    vulnerabilityType: ExposureType;
    vulnerabilityName: string;
    affectedAssets: string[];
    immediateActions: string[];
    shortTermSteps: RemediationStep[];
    longTermSteps: RemediationStep[];
    compensatingControls: string[];
    references: string[];
  }>;
}

export interface ComputedComplianceReport {
  overallAssessment: string;
  controlGapAnalysis: string;
  riskToCompliance: string;
  frameworkSpecificFindings: Array<{
    framework: string;
    relevantVulnerabilities: string[];
    potentialViolations: string[];
    remediationPriority: string;
  }>;
}

function computeRiskLevel(
  criticalCount: number,
  highCount: number,
  mediumCount: number,
  exploitableCount: number,
  totalCount: number
): "critical" | "high" | "medium" | "low" {
  if (criticalCount > 0 || (exploitableCount > 0 && exploitableCount >= totalCount * 0.5)) {
    return "critical";
  }
  if (highCount > 0 || exploitableCount > 0) {
    return "high";
  }
  if (mediumCount > 0) {
    return "medium";
  }
  return "low";
}

function computeRiskDescription(level: "critical" | "high" | "medium" | "low"): string {
  const descriptions = {
    critical: "The organization faces CRITICAL security risk requiring immediate executive attention. Active exploitation paths exist that could result in significant data breach, financial loss, or operational disruption. Emergency remediation resources should be allocated immediately.",
    high: "The organization faces HIGH security risk. Exploitable vulnerabilities have been identified that present material risk to business operations. A prioritized remediation plan should be executed within the next 30 days.",
    medium: "The organization faces MODERATE security risk. While no immediately critical vulnerabilities were identified, the findings present risk that should be addressed through scheduled remediation activities.",
    low: "The organization maintains a LOW security risk posture. Continue current security practices and maintain regular assessment schedules to preserve this favorable position."
  };
  return descriptions[level];
}

export function computeExecutiveSummary(
  evaluations: EvaluationData[],
  results: Map<string, ResultData>
): ComputedExecutiveSummary {
  const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 };
  let exploitableCount = 0;
  let totalScore = 0;
  let scoredCount = 0;
  const affectedAssets = new Set<string>();
  const vulnerabilityTypes = new Map<ExposureType, number>();
  let estimatedFinancialExposure = { min: 0, max: 0 };
  
  evaluations.forEach(eval_ => {
    riskDistribution[eval_.priority]++;
    affectedAssets.add(eval_.assetId);
    
    const count = vulnerabilityTypes.get(eval_.exposureType as ExposureType) || 0;
    vulnerabilityTypes.set(eval_.exposureType as ExposureType, count + 1);
    
    const result = results.get(eval_.id);
    if (result) {
      if (result.exploitable) exploitableCount++;
      if (result.score) {
        totalScore += result.score;
        scoredCount++;
      }
      
      const financial = result.intelligentScore?.businessImpact?.factors?.financialExposure;
      if (financial?.directLoss) {
        estimatedFinancialExposure.min += financial.directLoss.min || 0;
        estimatedFinancialExposure.max += financial.directLoss.max || 0;
      }
    }
  });
  
  const overallRiskLevel = computeRiskLevel(
    riskDistribution.critical,
    riskDistribution.high,
    riskDistribution.medium,
    exploitableCount,
    evaluations.length
  );
  
  const keyFindings: string[] = [];
  
  if (evaluations.length > 0) {
    keyFindings.push(`${evaluations.length} security evaluations were conducted across ${affectedAssets.size} unique assets.`);
  }
  
  if (exploitableCount > 0) {
    const exploitablePercent = Math.round((exploitableCount / evaluations.length) * 100);
    keyFindings.push(`${exploitableCount} (${exploitablePercent}%) of evaluated exposures were confirmed exploitable.`);
  } else {
    keyFindings.push("No exploitable vulnerabilities were confirmed during this assessment period.");
  }
  
  if (riskDistribution.critical > 0) {
    keyFindings.push(`${riskDistribution.critical} CRITICAL severity finding(s) require immediate remediation.`);
  }
  
  if (riskDistribution.high > 0) {
    keyFindings.push(`${riskDistribution.high} HIGH severity finding(s) should be addressed within 30 days.`);
  }
  
  const topVulnTypes = Array.from(vulnerabilityTypes.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([type]) => formatVulnerabilityName(type));
  
  if (topVulnTypes.length > 0) {
    keyFindings.push(`Primary vulnerability categories: ${topVulnTypes.join(", ")}.`);
  }
  
  let exploitabilityAnalysis = "";
  if (exploitableCount === 0) {
    exploitabilityAnalysis = "No confirmed exploitable paths were identified during this assessment. Security controls appear effective at preventing unauthorized access and exploitation attempts.";
  } else if (exploitableCount < evaluations.length * 0.25) {
    exploitabilityAnalysis = `A limited number of exploitable vulnerabilities (${exploitableCount}) were identified, indicating generally effective security controls with specific gaps requiring attention.`;
  } else if (exploitableCount < evaluations.length * 0.5) {
    exploitabilityAnalysis = `A moderate number of exploitable vulnerabilities (${exploitableCount}) were confirmed. This indicates security control gaps that should be prioritized for remediation.`;
  } else {
    exploitabilityAnalysis = `A significant number of exploitable vulnerabilities (${exploitableCount}) were confirmed. This indicates systemic security control weaknesses requiring comprehensive remediation efforts.`;
  }
  
  let businessImpactSummary = "";
  if (estimatedFinancialExposure.max > 0) {
    businessImpactSummary = `Estimated potential financial exposure ranges from $${estimatedFinancialExposure.min.toLocaleString()} to $${estimatedFinancialExposure.max.toLocaleString()}. `;
  }
  
  if (exploitableCount > 0) {
    businessImpactSummary += "Exploitable vulnerabilities could lead to data breach, operational disruption, regulatory penalties, and reputational damage. ";
  }
  
  if (riskDistribution.critical > 0) {
    businessImpactSummary += "Critical findings pose immediate risk to business continuity and should be treated as emergency remediation priorities.";
  } else if (riskDistribution.high > 0) {
    businessImpactSummary += "High-severity findings present material business risk and should be addressed through accelerated remediation timelines.";
  } else {
    businessImpactSummary += "Current findings present manageable business risk when addressed through standard remediation processes.";
  }
  
  const prioritizedActions: ComputedExecutiveSummary["prioritizedActions"] = [];
  
  if (riskDistribution.critical > 0) {
    prioritizedActions.push({
      priority: 1,
      action: "Immediately remediate critical vulnerabilities",
      rationale: `${riskDistribution.critical} critical finding(s) present immediate exploitation risk`,
      estimatedEffort: "24-48 hours emergency response"
    });
  }
  
  if (exploitableCount > 0) {
    prioritizedActions.push({
      priority: prioritizedActions.length + 1,
      action: "Deploy compensating controls for exploitable vulnerabilities",
      rationale: `${exploitableCount} confirmed exploitable path(s) require immediate mitigation`,
      estimatedEffort: "1-3 days"
    });
  }
  
  if (riskDistribution.high > 0) {
    prioritizedActions.push({
      priority: prioritizedActions.length + 1,
      action: "Execute prioritized remediation plan for high-severity findings",
      rationale: `${riskDistribution.high} high-severity finding(s) should be addressed within 30 days`,
      estimatedEffort: "2-4 weeks"
    });
  }
  
  prioritizedActions.push({
    priority: prioritizedActions.length + 1,
    action: "Enhance security monitoring for affected assets",
    rationale: "Increase detection capabilities while remediation is in progress",
    estimatedEffort: "1-2 days"
  });
  
  prioritizedActions.push({
    priority: prioritizedActions.length + 1,
    action: "Schedule follow-up assessment to verify remediation effectiveness",
    rationale: "Confirm vulnerabilities are properly addressed and no new issues introduced",
    estimatedEffort: "1-2 weeks post-remediation"
  });
  
  return {
    overallRiskAssessment: computeRiskDescription(overallRiskLevel),
    keyFindings,
    riskDistribution,
    exploitabilityAnalysis,
    businessImpactSummary,
    prioritizedActions
  };
}

export interface EvidenceArtifactData {
  id: string;
  evaluationId?: string;
  findingId?: string;
  evidenceType: string;
  verdict: string;
  confidenceScore: number;
  targetUrl: string;
  observedBehavior: string;
  capturedAt: Date;
  httpRequest?: {
    method: string;
    url: string;
    headers: Record<string, string>;
  };
  httpResponse?: {
    statusCode: number;
    statusText: string;
    headers: Record<string, string>;
    body?: string;
    bodyTruncated?: boolean;
  };
}

export function computeTechnicalReport(
  evaluations: EvaluationData[],
  results: Map<string, ResultData>,
  evidenceArtifacts?: EvidenceArtifactData[]
): ComputedTechnicalReport {
  const vulnerabilityMap = new Map<ExposureType, {
    count: number;
    exploitableCount: number;
    totalScore: number;
    assets: Set<string>;
    evaluations: Array<{ eval_: EvaluationData; result?: ResultData }>;
  }>();
  
  evaluations.forEach(eval_ => {
    const type = eval_.exposureType as ExposureType;
    const result = results.get(eval_.id);
    
    let entry = vulnerabilityMap.get(type);
    if (!entry) {
      entry = { count: 0, exploitableCount: 0, totalScore: 0, assets: new Set(), evaluations: [] };
      vulnerabilityMap.set(type, entry);
    }
    
    entry.count++;
    entry.assets.add(eval_.assetId);
    entry.evaluations.push({ eval_, result });
    
    if (result) {
      if (result.exploitable) entry.exploitableCount++;
      if (result.score) entry.totalScore += result.score;
    }
  });
  
  const vulnerabilityBreakdown = Array.from(vulnerabilityMap.entries()).map(([type, data]) => {
    const vulnInfo = getVulnerabilityInfo(type);
    return {
      type,
      name: vulnInfo.name,
      count: data.count,
      exploitableCount: data.exploitableCount,
      avgScore: data.count > 0 ? Math.round(data.totalScore / data.count) : 0,
      description: vulnInfo.description,
      affectedAssets: Array.from(data.assets)
    };
  }).sort((a, b) => b.exploitableCount - a.exploitableCount || b.count - a.count);
  
  const totalAssets = new Set(evaluations.map(e => e.assetId)).size;
  const exploitableEvals = evaluations.filter(e => results.get(e.id)?.exploitable);
  
  let attackSurfaceAnalysis = `The assessment covered ${totalAssets} unique asset(s) across ${vulnerabilityMap.size} vulnerability categories. `;
  
  if (exploitableEvals.length > 0) {
    const exploitableAssets = new Set(exploitableEvals.map(e => e.assetId)).size;
    attackSurfaceAnalysis += `${exploitableAssets} asset(s) have confirmed exploitable paths. `;
  }
  
  const primaryVulnTypes = vulnerabilityBreakdown.slice(0, 3).map(v => v.name);
  if (primaryVulnTypes.length > 0) {
    attackSurfaceAnalysis += `Primary attack vectors identified: ${primaryVulnTypes.join(", ")}.`;
  }
  
  let killChainSection: KillChainReportSection | null = null;
  const allAttackSteps: AttackPathStep[] = [];
  let aggregatedGraph: { complexityScore: number; criticalPath: string[] } | undefined;
  
  evaluations.forEach(eval_ => {
    const result = results.get(eval_.id);
    if (result?.attackPath) {
      allAttackSteps.push(...result.attackPath);
    }
    if (result?.attackGraph?.complexityScore && !aggregatedGraph) {
      aggregatedGraph = {
        complexityScore: result.attackGraph.complexityScore,
        criticalPath: result.attackGraph.criticalPath || []
      };
    }
  });
  
  if (allAttackSteps.length > 0) {
    const visualization = buildKillChainVisualization(allAttackSteps, aggregatedGraph);
    killChainSection = generateKillChainReportSection(visualization);
  }
  
  const technicalFindings = evaluations.map(eval_ => {
    const result = results.get(eval_.id);
    const vulnInfo = getVulnerabilityInfo(eval_.exposureType as ExposureType);
    
    let attackPathSummary = "No attack path identified";
    if (result?.attackPath && result.attackPath.length > 0) {
      attackPathSummary = `${result.attackPath.length}-step attack chain: ${result.attackPath.map(s => s.title).join(" → ")}`;
    }
    
    const matchingEvidence = evidenceArtifacts?.filter(
      artifact => artifact.evaluationId === eval_.id
    ).map(artifact => ({
      id: artifact.id,
      evidenceType: artifact.evidenceType,
      verdict: artifact.verdict,
      confidenceScore: artifact.confidenceScore,
      targetUrl: artifact.targetUrl,
      observedBehavior: artifact.observedBehavior,
      capturedAt: artifact.capturedAt,
      httpRequest: artifact.httpRequest,
      httpResponse: artifact.httpResponse,
    }));
    
    return {
      evaluationId: eval_.id,
      assetId: eval_.assetId,
      vulnerabilityType: eval_.exposureType,
      vulnerabilityName: vulnInfo.name,
      severity: eval_.priority.toUpperCase(),
      exploitable: result?.exploitable || false,
      score: result?.score || 0,
      technicalDescription: result?.impact || eval_.description,
      attackPathSummary,
      mitreTechniques: vulnInfo.mitreTechniques,
      cweIds: vulnInfo.cweIds,
      evidenceArtifacts: matchingEvidence && matchingEvidence.length > 0 ? matchingEvidence : undefined,
    };
  });
  
  const remediationPlan: ComputedTechnicalReport["remediationPlan"] = [];
  vulnerabilityMap.forEach((data, type) => {
    const guidance = getRemediationGuidance(type);
    const vulnInfo = getVulnerabilityInfo(type);
    
    remediationPlan.push({
      vulnerabilityType: type,
      vulnerabilityName: vulnInfo.name,
      affectedAssets: Array.from(data.assets),
      immediateActions: guidance.immediateActions,
      shortTermSteps: guidance.shortTermRemediation,
      longTermSteps: guidance.longTermRemediation,
      compensatingControls: guidance.compensatingControls,
      references: guidance.references
    });
  });
  
  return {
    vulnerabilityBreakdown,
    attackSurfaceAnalysis,
    killChainSection,
    technicalFindings,
    remediationPlan
  };
}

export function computeComplianceReport(
  evaluations: EvaluationData[],
  results: Map<string, ResultData>,
  framework: string
): ComputedComplianceReport {
  const frameworkLower = framework.toLowerCase();
  let relevantVulnerabilities: string[] = [];
  let potentialViolations: string[] = [];
  
  evaluations.forEach(eval_ => {
    const result = results.get(eval_.id);
    const complianceImpact = result?.intelligentScore?.businessImpact?.factors?.complianceImpact;
    
    if (complianceImpact?.affectedFrameworks?.some(f => f.toLowerCase().includes(frameworkLower))) {
      relevantVulnerabilities.push(`${eval_.exposureType} affecting ${eval_.assetId}`);
      complianceImpact.violations?.forEach(v => {
        potentialViolations.push(`${v.severity} violation`);
      });
    }
  });
  
  const exploitableCount = Array.from(results.values()).filter(r => r.exploitable).length;
  const criticalCount = evaluations.filter(e => e.priority === "critical").length;
  
  let overallAssessment = "";
  if (criticalCount > 0 || exploitableCount > 0) {
    overallAssessment = `The assessment identified security findings that may impact ${framework.toUpperCase()} compliance. ${criticalCount} critical finding(s) and ${exploitableCount} exploitable vulnerability/vulnerabilities require attention to maintain compliance posture.`;
  } else {
    overallAssessment = `No critical compliance gaps were identified during this assessment. Continue monitoring and regular assessments to maintain ${framework.toUpperCase()} compliance.`;
  }
  
  let controlGapAnalysis = "";
  if (relevantVulnerabilities.length > 0) {
    controlGapAnalysis = `${relevantVulnerabilities.length} finding(s) were identified with potential ${framework.toUpperCase()} compliance implications. These should be reviewed against specific control requirements and addressed through remediation planning.`;
  } else {
    controlGapAnalysis = `No specific ${framework.toUpperCase()} control gaps were identified. Standard vulnerability remediation processes should maintain compliance posture.`;
  }
  
  let riskToCompliance = "";
  if (exploitableCount > 0) {
    riskToCompliance = `Exploitable vulnerabilities present compliance risk if they result in data breach or security incident. Regulatory notification requirements and potential penalties should be considered in remediation prioritization.`;
  } else {
    riskToCompliance = `Current findings present manageable compliance risk when addressed through standard remediation timelines.`;
  }
  
  let remediationPriority = "Standard";
  if (criticalCount > 0) remediationPriority = "Emergency";
  else if (exploitableCount > 0) remediationPriority = "High";
  else if (evaluations.filter(e => e.priority === "high").length > 0) remediationPriority = "Elevated";
  
  return {
    overallAssessment,
    controlGapAnalysis,
    riskToCompliance,
    frameworkSpecificFindings: [{
      framework: framework.toUpperCase(),
      relevantVulnerabilities,
      potentialViolations: Array.from(new Set(potentialViolations)),
      remediationPriority
    }]
  };
}

export function formatRemediationSection(plan: ComputedTechnicalReport["remediationPlan"][0]): string {
  const lines: string[] = [];
  
  lines.push(`## ${plan.vulnerabilityName}`);
  lines.push(`**Affected Assets:** ${plan.affectedAssets.join(", ")}`);
  lines.push("");
  
  lines.push("### Immediate Actions");
  plan.immediateActions.forEach((action, i) => {
    lines.push(`${i + 1}. ${action}`);
  });
  lines.push("");
  
  lines.push("### Short-Term Remediation");
  plan.shortTermSteps.forEach(step => {
    lines.push(`**${step.order}. ${step.title}** (${step.effort} effort, ~${step.estimatedTime})`);
    lines.push(`   ${step.description}`);
    if (step.requiredTools?.length) {
      lines.push(`   *Tools:* ${step.requiredTools.join(", ")}`);
    }
    lines.push(`   *Verification:* ${step.verificationSteps.join("; ")}`);
    lines.push("");
  });
  
  if (plan.longTermSteps.length > 0) {
    lines.push("### Long-Term Remediation");
    plan.longTermSteps.forEach(step => {
      lines.push(`**${step.order}. ${step.title}** (${step.effort} effort, ~${step.estimatedTime})`);
      lines.push(`   ${step.description}`);
      lines.push("");
    });
  }
  
  lines.push("### Compensating Controls");
  plan.compensatingControls.forEach((control, i) => {
    lines.push(`${i + 1}. ${control}`);
  });
  lines.push("");
  
  lines.push("### References");
  plan.references.forEach(ref => {
    lines.push(`- ${ref}`);
  });
  
  return lines.join("\n");
}
