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
    critical: "The assessment team determined the organization's security posture to be CRITICAL. Confirmed exploitable attack paths present immediate risk to business continuity, data confidentiality, and regulatory compliance. The assessment team recommends immediate deployment of compensating controls and activation of emergency remediation procedures. Executive sponsorship is required to ensure adequate resource allocation for remediation within the next 48 hours.",
    high: "The assessment team determined the organization's security posture to be HIGH risk. Exploitable vulnerabilities were confirmed that present material risk to business operations, including potential unauthorized access, data exfiltration, and lateral movement across the environment. A prioritized remediation plan should be executed within 30 days, with compensating controls deployed immediately for confirmed exploitable findings. Enhanced monitoring should be enabled for all affected assets during the remediation window.",
    medium: "The assessment team determined the organization's security posture to be MODERATE. While no immediately critical exploitation paths were confirmed, the identified findings represent defense-in-depth gaps that, if unaddressed, could be chained by a motivated adversary to achieve meaningful compromise. The assessment team recommends addressing findings through scheduled remediation activities within 60 days, prioritized by exploitability and business impact. This represents an opportunity to strengthen the organization's security posture proactively.",
    low: "The assessment team determined the organization's security posture to be LOW risk. Security controls are operating effectively, and no confirmed exploitable attack paths were identified during the assessment period. The organization should maintain current security practices, continue regular assessment cycles, and invest in continuous security validation to sustain this favorable posture. Periodic reassessment is recommended to account for emerging threats and infrastructure changes."
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
    keyFindings.push(`The assessment team evaluated ${evaluations.length} security exposure${evaluations.length !== 1 ? "s" : ""} across ${affectedAssets.size} unique asset${affectedAssets.size !== 1 ? "s" : ""}, employing automated multi-agent AI analysis including reconnaissance, exploit validation, lateral movement analysis, business logic testing, and impact assessment.`);
  }

  if (exploitableCount > 0) {
    const exploitablePercent = Math.round((exploitableCount / evaluations.length) * 100);
    keyFindings.push(`${exploitableCount} of ${evaluations.length} evaluated exposures (${exploitablePercent}%) were confirmed exploitable through validated attack paths, indicating ${exploitablePercent > 50 ? "systemic security control deficiencies requiring comprehensive remediation" : exploitablePercent > 25 ? "material security gaps that present actionable risk to business operations" : "targeted security gaps that should be addressed through prioritized remediation"}.`);
  } else {
    keyFindings.push("The assessment did not confirm exploitable attack paths during this evaluation period. Security controls appear to be operating effectively against the tested attack vectors.");
  }

  if (riskDistribution.critical > 0) {
    keyFindings.push(`${riskDistribution.critical} CRITICAL severity finding${riskDistribution.critical !== 1 ? "s" : ""} present${riskDistribution.critical === 1 ? "s" : ""} immediate risk to business operations and require${riskDistribution.critical === 1 ? "s" : ""} emergency remediation within 48 hours.`);
  }

  if (riskDistribution.high > 0) {
    keyFindings.push(`${riskDistribution.high} HIGH severity finding${riskDistribution.high !== 1 ? "s" : ""} require${riskDistribution.high === 1 ? "s" : ""} prioritized remediation within 30 days to reduce material business risk.`);
  }

  const topVulnTypes = Array.from(vulnerabilityTypes.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([type]) => formatVulnerabilityName(type));

  if (topVulnTypes.length > 0) {
    keyFindings.push(`Primary vulnerability categories identified: ${topVulnTypes.join(", ")}. These categories should be prioritized in the organization's vulnerability management program.`);
  }
  
  let exploitabilityAnalysis = "";
  const allMitreTechniques = new Set<string>();
  evaluations.forEach(eval_ => {
    const vulnInfo = getVulnerabilityInfo(eval_.exposureType as ExposureType);
    vulnInfo.mitreTechniques.forEach(t => allMitreTechniques.add(t.split(".")[0]));
  });
  const techniqueCount = allMitreTechniques.size;
  const mitreCoverage = techniqueCount > 0 ? ` Validated techniques span ${techniqueCount} MITRE ATT&CK technique categor${techniqueCount !== 1 ? "ies" : "y"}, providing coverage across the attack lifecycle.` : "";

  if (exploitableCount === 0) {
    exploitabilityAnalysis = `No confirmed exploitable attack paths were identified during this assessment period. Security controls are operating effectively against the tested attack vectors.${mitreCoverage} The organization should continue regular assessment cycles to maintain this posture against evolving threats.`;
  } else if (exploitableCount < evaluations.length * 0.25) {
    exploitabilityAnalysis = `${exploitableCount} exploitable vulnerability path${exploitableCount !== 1 ? "s were" : " was"} confirmed, representing a limited attack surface. While the overall control environment is effective, the confirmed paths provide an adversary with viable entry points that should be addressed promptly.${mitreCoverage} Targeted remediation of these specific gaps will materially reduce the organization's exposure.`;
  } else if (exploitableCount < evaluations.length * 0.5) {
    exploitabilityAnalysis = `${exploitableCount} exploitable vulnerability paths were confirmed, indicating material security control gaps across the evaluated attack surface. These gaps provide multiple viable attack vectors that a motivated adversary could leverage for unauthorized access, lateral movement, or data exfiltration.${mitreCoverage} Prioritized remediation based on business impact and exploitability is recommended.`;
  } else {
    exploitabilityAnalysis = `${exploitableCount} of ${evaluations.length} evaluated exposures (${Math.round((exploitableCount / evaluations.length) * 100)}%) were confirmed exploitable, indicating systemic security control deficiencies. The breadth of exploitable paths suggests fundamental gaps in the security architecture that require comprehensive remediation beyond point fixes.${mitreCoverage} The assessment team recommends a holistic security posture review in addition to targeted remediation.`;
  }
  
  let businessImpactSummary = "";
  if (estimatedFinancialExposure.max > 0) {
    businessImpactSummary = `The assessment team estimates potential financial exposure in the range of $${estimatedFinancialExposure.min.toLocaleString()} to $${estimatedFinancialExposure.max.toLocaleString()}, accounting for direct losses, incident response costs, and regulatory penalties. `;
  }

  if (exploitableCount > 0) {
    const impactAreas: string[] = [];
    const exposureTypesSet = new Set(evaluations.map(e => e.exposureType));
    if (exposureTypesSet.has("data_exposure" as ExposureType) || exposureTypesSet.has("credential_exposure" as ExposureType)) {
      impactAreas.push("unauthorized data access and potential regulatory notification obligations");
    }
    if (exposureTypesSet.has("network_vulnerability" as ExposureType) || exposureTypesSet.has("misconfiguration" as ExposureType)) {
      impactAreas.push("infrastructure compromise enabling lateral movement across the environment");
    }
    if (exposureTypesSet.has("app_logic" as ExposureType) || exposureTypesSet.has("api_vulnerability" as ExposureType)) {
      impactAreas.push("application-layer exploitation affecting business logic and data integrity");
    }
    if (impactAreas.length === 0) {
      impactAreas.push("unauthorized access, data compromise, and operational disruption");
    }
    businessImpactSummary += `Confirmed exploitable findings present material business risk including ${impactAreas.join("; ")}. `;
  }

  if (riskDistribution.critical > 0) {
    businessImpactSummary += "Critical findings present immediate risk to business continuity and require emergency remediation. The assessment team recommends treating these as P1 incidents with dedicated remediation resources and executive visibility.";
  } else if (riskDistribution.high > 0) {
    businessImpactSummary += "High-severity findings present material business risk that should be addressed through accelerated remediation timelines (30-day target). Compensating controls should be deployed immediately to reduce exposure while permanent fixes are implemented.";
  } else {
    businessImpactSummary += "Current findings present manageable business risk that can be addressed through standard remediation processes. The assessment team recommends maintaining current security investment levels and continuing regular assessment cycles.";
  }
  
  const prioritizedActions: ComputedExecutiveSummary["prioritizedActions"] = [];

  if (riskDistribution.critical > 0) {
    prioritizedActions.push({
      priority: 1,
      action: "Emergency remediation of critical findings (0-48 hours)",
      rationale: `${riskDistribution.critical} critical finding${riskDistribution.critical !== 1 ? "s" : ""} with confirmed exploitation paths present${riskDistribution.critical === 1 ? "s" : ""} immediate risk to business operations. Treating these as P1 incidents reduces the window of exposure.`,
      estimatedEffort: "24-48 hours with dedicated remediation resources"
    });
  }

  if (exploitableCount > 0) {
    prioritizedActions.push({
      priority: prioritizedActions.length + 1,
      action: "Deploy compensating controls for all exploitable findings (0-7 days)",
      rationale: `${exploitableCount} confirmed exploitable path${exploitableCount !== 1 ? "s" : ""} require${exploitableCount === 1 ? "s" : ""} immediate risk reduction. Compensating controls (WAF rules, network ACLs, access restrictions) constrain the blast radius while permanent fixes are developed.`,
      estimatedEffort: "1-3 days for initial deployment, ongoing tuning"
    });
  }

  if (riskDistribution.high > 0) {
    prioritizedActions.push({
      priority: prioritizedActions.length + 1,
      action: "Prioritized remediation of high-severity findings (0-30 days)",
      rationale: `${riskDistribution.high} high-severity finding${riskDistribution.high !== 1 ? "s" : ""} present${riskDistribution.high === 1 ? "s" : ""} material risk that compounds over time. Investing in timely remediation prevents escalation and reduces aggregate exposure.`,
      estimatedEffort: "2-4 weeks with structured remediation sprints"
    });
  }

  prioritizedActions.push({
    priority: prioritizedActions.length + 1,
    action: "Deploy enhanced monitoring and detection for affected assets (0-7 days)",
    rationale: "Increasing detection capabilities during the remediation window provides early warning of exploitation attempts and supports incident response readiness.",
    estimatedEffort: "1-3 days for SIEM rule deployment and alert configuration"
  });

  prioritizedActions.push({
    priority: prioritizedActions.length + 1,
    action: "Conduct validation assessment to verify remediation effectiveness (30-45 days post-remediation)",
    rationale: "Re-assessment confirms vulnerabilities are properly addressed, validates compensating controls are effective, and ensures no regression or new exposures were introduced during remediation.",
    estimatedEffort: "1-2 weeks for targeted re-assessment"
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

  // Collect MITRE ATT&CK technique coverage
  const allTechniques = new Set<string>();
  const allCWEs = new Set<string>();
  vulnerabilityBreakdown.forEach(v => {
    const info = getVulnerabilityInfo(v.type);
    info.mitreTechniques.forEach(t => allTechniques.add(t));
    info.cweIds.forEach(c => allCWEs.add(c));
  });

  let attackSurfaceAnalysis = `The assessment evaluated ${totalAssets} unique asset${totalAssets !== 1 ? "s" : ""} across ${vulnerabilityMap.size} vulnerability categor${vulnerabilityMap.size !== 1 ? "ies" : "y"} using a six-agent analysis pipeline (Reconnaissance, Exploit Validation, Lateral Movement, Business Logic, Multi-Vector, and Impact Assessment). `;

  if (exploitableEvals.length > 0) {
    const exploitableAssets = new Set(exploitableEvals.map(e => e.assetId)).size;
    attackSurfaceAnalysis += `${exploitableAssets} asset${exploitableAssets !== 1 ? "s" : ""} ha${exploitableAssets !== 1 ? "ve" : "s"} confirmed exploitable attack paths with validated exploitation chains. `;
  }

  const primaryVulnTypes = vulnerabilityBreakdown.slice(0, 3).map(v => v.name);
  if (primaryVulnTypes.length > 0) {
    attackSurfaceAnalysis += `Primary attack vectors: ${primaryVulnTypes.join(", ")}. `;
  }

  if (allTechniques.size > 0) {
    attackSurfaceAnalysis += `MITRE ATT&CK coverage: ${allTechniques.size} technique${allTechniques.size !== 1 ? "s" : ""} validated (${Array.from(allTechniques).slice(0, 5).join(", ")}${allTechniques.size > 5 ? `, +${allTechniques.size - 5} more` : ""}). `;
  }
  if (allCWEs.size > 0) {
    attackSurfaceAnalysis += `CWE coverage: ${Array.from(allCWEs).slice(0, 5).join(", ")}${allCWEs.size > 5 ? `, +${allCWEs.size - 5} more` : ""}.`;
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
    
    // Build enriched technical description with CWE/MITRE references
    const baseDescription = result?.impact || eval_.description;
    const cweRef = vulnInfo.cweIds.length > 0 ? `Vulnerability Class: ${vulnInfo.cweIds.join(", ")}. ` : "";
    const mitreRef = vulnInfo.mitreTechniques.length > 0 ? `MITRE ATT&CK: ${vulnInfo.mitreTechniques.join(", ")}. ` : "";
    const exploitStatus = result?.exploitable ? "Exploitation Status: CONFIRMED EXPLOITABLE. " : "Exploitation Status: Not confirmed. ";
    const confidenceNote = result?.score ? `Assessment Confidence: ${result.score}/100. ` : "";
    const enrichedDescription = `${baseDescription}\n\n${cweRef}${mitreRef}${exploitStatus}${confidenceNote}Business Impact: ${vulnInfo.businessImpact || "Refer to remediation guidance for impact assessment."}`;

    return {
      evaluationId: eval_.id,
      assetId: eval_.assetId,
      vulnerabilityType: eval_.exposureType,
      vulnerabilityName: vulnInfo.name,
      severity: eval_.priority.toUpperCase(),
      exploitable: result?.exploitable || false,
      score: result?.score || 0,
      technicalDescription: enrichedDescription,
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

// ============================================================================
// BREACH REALIZATION SCORE
// ============================================================================

export interface BreachRealizationScoreDimension {
  dimension: string;
  score: number;       // 0-100
  weight: number;      // 0-1 (sum to 1.0)
  rationale: string;
}

export interface BreachRealizationScore {
  overall: number;     // 0-100 weighted composite
  dimensions: BreachRealizationScoreDimension[];
  summary: string;     // Plain-language explanation
}

/**
 * Compute Breach Realization Score (BRS) — replaces CVSS as primary severity indicator.
 *
 * Measures how completely an attacker realized a breach across 6 dimensions:
 * - Time to Impact: How fast was first meaningful compromise achieved?
 * - Privilege Escalation Level: What was the highest privilege achieved?
 * - Lateral Movement Capability: How far could the attacker move across domains?
 * - Blast Radius: How many assets/systems were affected?
 * - Detection Difficulty: How hard is this attack to detect with current controls?
 * - Persistence Potential: Can the attacker maintain access long-term?
 */
export function computeBreachRealizationScore(
  evaluations: EvaluationData[],
  results: Map<string, ResultData>,
  breachChainData?: {
    domainsBreached?: number;
    totalDomains?: number;
    maxPrivilegeAchieved?: string;
    totalAssetsCompromised?: number;
    totalCredentialsHarvested?: number;
    durationMs?: number;
    phaseResults?: Array<{
      phaseName: string;
      status: string;
      findingsCount?: number;
    }>;
  }
): BreachRealizationScore {
  const exploitableResults = evaluations
    .map(e => ({ eval_: e, result: results.get(e.id) }))
    .filter(er => er.result?.exploitable);

  const totalEvals = evaluations.length;
  const exploitableCount = exploitableResults.length;

  // --- 1. Time to Impact (weight: 0.15) ---
  let timeToImpactScore = 0;
  let timeToImpactRationale = "";
  if (breachChainData?.durationMs) {
    const minutes = breachChainData.durationMs / 60000;
    if (minutes <= 5) { timeToImpactScore = 100; timeToImpactRationale = `First impact achieved in ${Math.round(minutes)} minutes — faster than most SOC response times.`; }
    else if (minutes <= 15) { timeToImpactScore = 85; timeToImpactRationale = `First impact in ${Math.round(minutes)} minutes — within typical dwell-time detection gap.`; }
    else if (minutes <= 60) { timeToImpactScore = 65; timeToImpactRationale = `First impact in ${Math.round(minutes)} minutes — moderate exploitation timeline.`; }
    else if (minutes <= 240) { timeToImpactScore = 40; timeToImpactRationale = `First impact in ${Math.round(minutes / 60)} hours — extended but achievable timeline.`; }
    else { timeToImpactScore = 20; timeToImpactRationale = `Exploitation required ${Math.round(minutes / 60)} hours — significant effort but still achievable.`; }
  } else if (exploitableCount > 0) {
    // Estimate from attack path complexity
    const avgSteps = exploitableResults.reduce((sum, er) => sum + (er.result?.attackPath?.length || 1), 0) / exploitableCount;
    if (avgSteps <= 2) { timeToImpactScore = 80; timeToImpactRationale = `Simple ${Math.round(avgSteps)}-step attack chains indicate rapid exploitation.`; }
    else if (avgSteps <= 4) { timeToImpactScore = 60; timeToImpactRationale = `${Math.round(avgSteps)}-step attack chains require moderate effort.`; }
    else { timeToImpactScore = 35; timeToImpactRationale = `Complex ${Math.round(avgSteps)}-step chains require sustained attacker effort.`; }
  } else {
    timeToImpactRationale = "No exploitable paths confirmed — time to impact not measurable.";
  }

  // --- 2. Privilege Escalation Level (weight: 0.20) ---
  let privEscScore = 0;
  let privEscRationale = "";
  const maxPriv = breachChainData?.maxPrivilegeAchieved?.toLowerCase() || "";
  if (maxPriv.includes("root") || maxPriv.includes("admin") || maxPriv.includes("system")) {
    privEscScore = 100;
    privEscRationale = `Attacker achieved ${breachChainData?.maxPrivilegeAchieved} — full administrative control.`;
  } else if (maxPriv.includes("elevated") || maxPriv.includes("privileged") || maxPriv.includes("write")) {
    privEscScore = 70;
    privEscRationale = `Attacker achieved elevated privileges (${breachChainData?.maxPrivilegeAchieved}) — significant access beyond initial foothold.`;
  } else if (maxPriv.includes("user") || maxPriv.includes("read")) {
    privEscScore = 40;
    privEscRationale = `Attacker achieved user-level access (${breachChainData?.maxPrivilegeAchieved}) — limited but actionable.`;
  } else if (exploitableCount > 0) {
    // Infer from findings
    const hasCritical = evaluations.some(e => e.priority === "critical");
    const hasHigh = evaluations.some(e => e.priority === "high");
    if (hasCritical) { privEscScore = 80; privEscRationale = "Critical findings suggest high-privilege access is achievable."; }
    else if (hasHigh) { privEscScore = 55; privEscRationale = "High-severity findings suggest meaningful privilege escalation."; }
    else { privEscScore = 30; privEscRationale = "Exploitable findings exist but privilege escalation is limited."; }
  } else {
    privEscRationale = "No privilege escalation paths confirmed.";
  }

  // --- 3. Lateral Movement Capability (weight: 0.20) ---
  let lateralScore = 0;
  let lateralRationale = "";
  const domainsBreached = breachChainData?.domainsBreached || 0;
  const totalDomains = breachChainData?.totalDomains || 6;
  if (domainsBreached >= 4) {
    lateralScore = 100;
    lateralRationale = `Attacker traversed ${domainsBreached}/${totalDomains} security domains — comprehensive cross-domain breach.`;
  } else if (domainsBreached >= 2) {
    lateralScore = 70;
    lateralRationale = `Attacker traversed ${domainsBreached}/${totalDomains} security domains — multi-domain breach confirmed.`;
  } else if (domainsBreached === 1) {
    lateralScore = 35;
    lateralRationale = "Breach contained to single domain — lateral movement limited.";
  } else if (exploitableCount > 1) {
    const distinctAssets = new Set(exploitableResults.map(er => er.eval_.assetId)).size;
    if (distinctAssets > 1) {
      lateralScore = 45;
      lateralRationale = `Exploitable paths across ${distinctAssets} assets suggest lateral movement capability.`;
    } else {
      lateralScore = 20;
      lateralRationale = "Exploitation confirmed on single asset — lateral movement not demonstrated.";
    }
  } else {
    lateralRationale = "No lateral movement capability confirmed.";
  }

  // --- 4. Blast Radius (weight: 0.20) ---
  let blastScore = 0;
  let blastRationale = "";
  const assetsCompromised = breachChainData?.totalAssetsCompromised || 0;
  const credsHarvested = breachChainData?.totalCredentialsHarvested || 0;
  if (assetsCompromised >= 10 || credsHarvested >= 10) {
    blastScore = 100;
    blastRationale = `${assetsCompromised} assets compromised, ${credsHarvested} credentials harvested — catastrophic blast radius.`;
  } else if (assetsCompromised >= 5 || credsHarvested >= 5) {
    blastScore = 75;
    blastRationale = `${assetsCompromised} assets compromised, ${credsHarvested} credentials harvested — significant blast radius.`;
  } else if (assetsCompromised >= 2 || credsHarvested >= 2) {
    blastScore = 50;
    blastRationale = `${assetsCompromised} assets compromised, ${credsHarvested} credentials harvested — moderate blast radius.`;
  } else if (exploitableCount > 0) {
    const criticalCount = evaluations.filter(e => e.priority === "critical").length;
    blastScore = criticalCount > 0 ? 45 : 25;
    blastRationale = exploitableCount === 1
      ? "Single exploitable finding — contained blast radius."
      : `${exploitableCount} exploitable findings — blast radius depends on exploitation sequence.`;
  } else {
    blastRationale = "No confirmed exploitation — blast radius not measurable.";
  }

  // --- 5. Detection Difficulty (weight: 0.15) ---
  let detectionScore = 0;
  let detectionRationale = "";
  // Higher score = harder to detect = worse for defender
  const hasAppLogic = evaluations.some(e => ["app_logic", "business_logic", "idor"].includes(e.exposureType));
  const hasInjection = evaluations.some(e => ["sqli", "xss", "command_injection", "ssti"].includes(e.exposureType));
  const hasAuthBypass = evaluations.some(e => ["auth_bypass", "broken_auth", "credential_exposure"].includes(e.exposureType));
  const hasNetworkLevel = evaluations.some(e => ["network_vulnerability", "misconfiguration"].includes(e.exposureType));

  if (hasAppLogic && hasAuthBypass) {
    detectionScore = 90;
    detectionRationale = "Business logic and auth bypass attacks generate minimal signatures — extremely difficult to detect with standard controls.";
  } else if (hasAppLogic) {
    detectionScore = 75;
    detectionRationale = "Business logic attacks operate within normal application behavior — hard to distinguish from legitimate traffic.";
  } else if (hasAuthBypass) {
    detectionScore = 65;
    detectionRationale = "Authentication bypass may avoid audit trails — detection requires specialized monitoring.";
  } else if (hasInjection) {
    detectionScore = 45;
    detectionRationale = "Injection attacks produce detectable patterns but may evade basic WAF rules through encoding/evasion.";
  } else if (hasNetworkLevel) {
    detectionScore = 30;
    detectionRationale = "Network-level vulnerabilities produce observable traffic patterns — detectable with proper network monitoring.";
  } else if (exploitableCount > 0) {
    detectionScore = 50;
    detectionRationale = "Mixed attack types present moderate detection challenge.";
  } else {
    detectionRationale = "No active exploitation to detect.";
  }

  // --- 6. Persistence Potential (weight: 0.10) ---
  let persistenceScore = 0;
  let persistenceRationale = "";
  if (credsHarvested >= 5) {
    persistenceScore = 95;
    persistenceRationale = `${credsHarvested} harvested credentials enable persistent re-entry even after initial vector is patched.`;
  } else if (credsHarvested >= 1) {
    persistenceScore = 65;
    persistenceRationale = `${credsHarvested} harvested credential(s) provide re-entry capability — persistence requires credential rotation.`;
  } else if (maxPriv.includes("admin") || maxPriv.includes("root")) {
    persistenceScore = 80;
    persistenceRationale = "Administrative access enables backdoor installation and persistence mechanisms.";
  } else if (exploitableCount > 0 && evaluations.some(e => e.priority === "critical")) {
    persistenceScore = 45;
    persistenceRationale = "Critical exploitable paths could be revisited — persistence depends on remediation speed.";
  } else if (exploitableCount > 0) {
    persistenceScore = 25;
    persistenceRationale = "Exploitable paths exist but persistence requires re-exploitation of original vector.";
  } else {
    persistenceRationale = "No confirmed persistence capability.";
  }

  // --- Composite Score ---
  const dimensions: BreachRealizationScoreDimension[] = [
    { dimension: "Time to Impact", score: timeToImpactScore, weight: 0.15, rationale: timeToImpactRationale },
    { dimension: "Privilege Escalation Level", score: privEscScore, weight: 0.20, rationale: privEscRationale },
    { dimension: "Lateral Movement Capability", score: lateralScore, weight: 0.20, rationale: lateralRationale },
    { dimension: "Blast Radius", score: blastScore, weight: 0.20, rationale: blastRationale },
    { dimension: "Detection Difficulty", score: detectionScore, weight: 0.15, rationale: detectionRationale },
    { dimension: "Persistence Potential", score: persistenceScore, weight: 0.10, rationale: persistenceRationale },
  ];

  const overall = Math.round(dimensions.reduce((sum, d) => sum + d.score * d.weight, 0));

  // Generate summary
  let summary = "";
  if (overall >= 80) {
    summary = `Breach Realization Score: ${overall}/100 (CRITICAL). The attacker demonstrated comprehensive breach capability across multiple dimensions. Immediate incident-level response is warranted — this is not a theoretical risk.`;
  } else if (overall >= 60) {
    summary = `Breach Realization Score: ${overall}/100 (HIGH). The attacker achieved meaningful breach progression with confirmed exploitation and cross-boundary movement. Accelerated remediation within 7 days is required.`;
  } else if (overall >= 40) {
    summary = `Breach Realization Score: ${overall}/100 (MODERATE). Exploitable paths exist but breach progression was limited. Prioritized remediation within 30 days will materially reduce exposure.`;
  } else if (overall >= 20) {
    summary = `Breach Realization Score: ${overall}/100 (LOW). Limited exploitation was confirmed but breach realization was minimal. Standard remediation timelines are appropriate.`;
  } else {
    summary = `Breach Realization Score: ${overall}/100 (MINIMAL). No significant breach progression was confirmed. Maintain current security posture and continue regular assessment cycles.`;
  }

  return { overall, dimensions, summary };
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
