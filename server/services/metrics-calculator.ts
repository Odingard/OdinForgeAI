import { storage } from "../storage";
import type { Evaluation, Result, DefensiveValidation, BreachPhaseResult } from "@shared/schema";

interface CategoryScore {
  networkSecurity: number;
  applicationSecurity: number;
  identityManagement: number;
  dataProtection: number;
  incidentResponse: number;
  securityAwareness: number;
  compliancePosture: number;
}

interface VulnerabilityExposure {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DefensivePostureMetrics {
  id: string;
  organizationId: string;
  overallScore: number;
  categoryScores: CategoryScore;
  breachLikelihood: number;
  meanTimeToDetect: number;
  meanTimeToRespond: number;
  mttdDataSource: "siem_observed" | "synthetic";
  mttrDataSource: "siem_observed" | "synthetic";
  mttdSampleSize: number;
  mttrSampleSize: number;
  vulnerabilityExposure: VulnerabilityExposure;
  trendDirection: "improving" | "stable" | "declining";
  benchmarkPercentile: number;
  recommendations: string[];
  dataSource: "computed" | "insufficient_data";
  evaluationsAnalyzed: number;
  modelVersion: string;
  calculatedAt: string;
}

export interface AttackPrediction {
  vector: string;
  likelihood: number;
  confidence: number;
  adversaryProfile: string;
  estimatedImpact: string;
  mitreAttackId: string;
  occurrences: number;
}

export interface AttackPredictionMetrics {
  id: string;
  organizationId: string;
  predictedAttackVectors: AttackPrediction[];
  overallBreachLikelihood: number;
  riskFactors: Array<{ factor: string; contribution: number; trend: string }>;
  recommendedActions: string[];
  dataSource: "computed" | "insufficient_data";
  evaluationsAnalyzed: number;
  timeHorizon: string;
  modelVersion: string;
  calculatedAt: string;
}

const EXPOSURE_TO_CATEGORY: Record<string, keyof CategoryScore> = {
  cve: "applicationSecurity",
  misconfiguration: "networkSecurity",
  behavioral_anomaly: "incidentResponse",
  network: "networkSecurity",
  sql_injection: "applicationSecurity",
  xss: "applicationSecurity",
  auth_bypass: "identityManagement",
  ssrf: "applicationSecurity",
  idor: "identityManagement",
  rce: "applicationSecurity",
  path_traversal: "applicationSecurity",
  api_exposure: "applicationSecurity",
  data_leak: "dataProtection",
  privilege_escalation: "identityManagement",
  cryptographic_weakness: "dataProtection",
};

const EXPOSURE_TO_MITRE: Record<string, string> = {
  cve: "T1190",
  sql_injection: "T1190",
  xss: "T1059.007",
  auth_bypass: "T1078",
  ssrf: "T1071",
  idor: "T1068",
  rce: "T1059",
  path_traversal: "T1083",
  api_exposure: "T1190",
  data_leak: "T1530",
  privilege_escalation: "T1068",
  misconfiguration: "T1574",
  network: "T1046",
  behavioral_anomaly: "T1071",
  cryptographic_weakness: "T1552",
};

const EXPOSURE_DESCRIPTIONS: Record<string, string> = {
  cve: "Known vulnerability exploitation",
  sql_injection: "SQL Injection attacks",
  xss: "Cross-Site Scripting",
  auth_bypass: "Authentication bypass",
  ssrf: "Server-Side Request Forgery",
  idor: "Insecure Direct Object Reference",
  rce: "Remote Code Execution",
  path_traversal: "Path Traversal attacks",
  api_exposure: "API exposure exploitation",
  data_leak: "Data exfiltration",
  privilege_escalation: "Privilege escalation",
  misconfiguration: "Configuration exploitation",
  network: "Network-based attacks",
  behavioral_anomaly: "Anomalous behavior exploitation",
  cryptographic_weakness: "Cryptographic attacks",
};

export async function calculateDefensivePosture(
  organizationId: string
): Promise<DefensivePostureMetrics> {
  const evaluations = await storage.getEvaluations(organizationId);
  const completedEvaluations = evaluations.filter(e => e.status === "completed");
  
  if (completedEvaluations.length < 3) {
    return createInsufficientDataPosture(organizationId, completedEvaluations.length);
  }

  const evaluationIds = completedEvaluations.map(e => e.id);
  const results = await storage.getResultsByEvaluationIds(evaluationIds);

  const vulnerabilityExposure = countBySeverity(completedEvaluations, results);
  const categoryScores = calculateCategoryScores(completedEvaluations, results);
  let overallScore = calculateOverallScore(categoryScores, vulnerabilityExposure);
  let breachLikelihood = calculateBreachLikelihood(results, vulnerabilityExposure);
  const trendDirection = calculateTrend(completedEvaluations, results);

  // Enrich with breach chain data if available
  const breachMetrics = await getBreachChainMetrics(organizationId);
  if (breachMetrics.hasData) {
    // Blend breach chain risk score into breach likelihood (60% real data, 40% eval-based)
    breachLikelihood = Math.round(breachLikelihood * 0.4 + breachMetrics.avgRiskScore * 0.6);
    breachLikelihood = Math.max(5, Math.min(95, breachLikelihood));

    // Penalize overall score based on max privilege achieved in breach chains
    const privPenalty: Record<string, number> = {
      domain_admin: 25, cloud_admin: 20, system: 15, admin: 10, user: 3, none: 0,
    };
    const maxPenalty = Math.max(
      ...breachMetrics.maxPrivilegeLevels.map(p => privPenalty[p] || 0), 0
    );
    overallScore = Math.max(10, overallScore - maxPenalty);

    // Bonus from blocked phases (good defense signal)
    overallScore = Math.min(100, overallScore + Math.round(breachMetrics.phaseBlockRate * 10));

    // Penalize category scores for MITRE techniques that were actually exploited
    for (const mitreId of breachMetrics.mitreIdsObserved) {
      const exposureType = Object.entries(EXPOSURE_TO_MITRE).find(([, id]) => id === mitreId)?.[0];
      if (exposureType) {
        const category = EXPOSURE_TO_CATEGORY[exposureType];
        if (category && categoryScores[category] !== undefined) {
          categoryScores[category] = Math.max(20, categoryScores[category] - 5);
        }
      }
    }
  }

  const benchmarkPercentile = calculateBenchmarkPercentile(overallScore, vulnerabilityExposure);

  // Try to get real SIEM-observed MTTD/MTTR from defensive validations
  const siemMetrics = await getSiemObservedMetrics(organizationId);

  const useSiemMttd = siemMetrics.mttdSampleSize >= 3;
  const useSiemMttr = siemMetrics.mttrSampleSize >= 3;

  const recommendations = generateRecommendations(categoryScores, vulnerabilityExposure);
  if (breachMetrics.hasData) {
    recommendations.unshift(
      `Based on ${breachMetrics.chainCount} breach chain(s): ${breachMetrics.totalFindings} findings, ${breachMetrics.criticalFindings} critical`
    );
  }

  return {
    id: `posture-${organizationId}-${Date.now()}`,
    organizationId,
    overallScore,
    categoryScores,
    breachLikelihood,
    meanTimeToDetect: useSiemMttd ? siemMetrics.avgMttdHours : calculateMTTD(results),
    meanTimeToRespond: useSiemMttr ? siemMetrics.avgMttrHours : calculateMTTR(completedEvaluations),
    mttdDataSource: useSiemMttd ? "siem_observed" : "synthetic",
    mttrDataSource: useSiemMttr ? "siem_observed" : "synthetic",
    mttdSampleSize: useSiemMttd ? siemMetrics.mttdSampleSize : results.length,
    mttrSampleSize: useSiemMttr ? siemMetrics.mttrSampleSize : completedEvaluations.length,
    vulnerabilityExposure,
    trendDirection,
    benchmarkPercentile,
    recommendations: recommendations.slice(0, 5),
    dataSource: "computed",
    evaluationsAnalyzed: completedEvaluations.length,
    modelVersion: "v4.0.0-breach-enhanced",
    calculatedAt: new Date().toISOString(),
  };
}

export async function calculateAttackPredictions(
  organizationId: string,
  timeHorizon: string = "30d"
): Promise<AttackPredictionMetrics> {
  const evaluations = await storage.getEvaluations(organizationId);
  const completedEvaluations = evaluations.filter(e => e.status === "completed");
  
  if (completedEvaluations.length < 3) {
    return createInsufficientDataPredictions(organizationId, timeHorizon, completedEvaluations.length);
  }

  const evaluationIds = completedEvaluations.map(e => e.id);
  const results = await storage.getResultsByEvaluationIds(evaluationIds);

  const exposureFrequency = countExposureTypes(completedEvaluations);
  let predictedVectors = generatePredictedVectors(exposureFrequency, results, completedEvaluations);
  let riskFactors = identifyRiskFactors(completedEvaluations, results);
  let overallBreachLikelihood = calculateOverallBreachLikelihood(results);

  // Enrich with breach chain data if available
  const breachMetrics = await getBreachChainMetrics(organizationId);
  if (breachMetrics.hasData) {
    // Boost confidence for vectors matching real breach chain MITRE techniques
    predictedVectors = predictedVectors.map(v => {
      if (breachMetrics.mitreIdsObserved.includes(v.mitreAttackId)) {
        return {
          ...v,
          confidence: Math.min(95, v.confidence + 20),
          likelihood: Math.min(95, v.likelihood + 10),
        };
      }
      return v;
    });

    // Add vectors from breach chains not already in predictions
    for (const mitreId of breachMetrics.mitreIdsObserved) {
      if (!predictedVectors.some(v => v.mitreAttackId === mitreId)) {
        const exposureType = Object.entries(EXPOSURE_TO_MITRE).find(([, id]) => id === mitreId)?.[0];
        predictedVectors.push({
          vector: exposureType ? (EXPOSURE_DESCRIPTIONS[exposureType] || exposureType) : `MITRE ${mitreId}`,
          likelihood: Math.round(breachMetrics.phaseSuccessRate * 80),
          confidence: 75,
          adversaryProfile: "organized_crime",
          estimatedImpact: breachMetrics.criticalFindings > 0
            ? "Critical - Confirmed by breach chain"
            : "High - Observed in breach chain",
          mitreAttackId: mitreId,
          occurrences: 1,
        });
      }
    }
    predictedVectors.sort((a, b) => b.likelihood - a.likelihood);
    predictedVectors = predictedVectors.slice(0, 8);

    // Add breach chain risk factors
    riskFactors.push({
      factor: `Breach chain success rate (${Math.round(breachMetrics.phaseSuccessRate * 100)}% of phases succeeded)`,
      contribution: Math.round(breachMetrics.phaseSuccessRate * 40),
      trend: "stable",
    });
    if (breachMetrics.criticalFindings > 0) {
      riskFactors.push({
        factor: `${breachMetrics.criticalFindings} critical findings from breach chains`,
        contribution: Math.min(40, breachMetrics.criticalFindings * 15),
        trend: "increasing",
      });
    }
    riskFactors.sort((a, b) => b.contribution - a.contribution);
    riskFactors = riskFactors.slice(0, 6);

    // Blend breach likelihood
    overallBreachLikelihood = Math.round(overallBreachLikelihood * 0.4 + breachMetrics.avgRiskScore * 0.6);
    overallBreachLikelihood = Math.max(10, Math.min(90, overallBreachLikelihood));
  }

  return {
    id: `pred-${organizationId}-${Date.now()}`,
    organizationId,
    predictedAttackVectors: predictedVectors,
    overallBreachLikelihood,
    riskFactors,
    recommendedActions: generateActionableRecommendations(predictedVectors, riskFactors),
    dataSource: "computed",
    evaluationsAnalyzed: completedEvaluations.length,
    timeHorizon,
    modelVersion: "v3.0.0-breach-enhanced",
    calculatedAt: new Date().toISOString(),
  };
}

/**
 * Query defensive validations for real SIEM-observed MTTD/MTTR metrics.
 */
async function getSiemObservedMetrics(organizationId: string): Promise<{
  avgMttdHours: number;
  avgMttrHours: number;
  mttdSampleSize: number;
  mttrSampleSize: number;
}> {
  try {
    const validations = await storage.getDefensiveValidationsByOrg(organizationId);

    const mttdValues = validations
      .filter(v => v.status === "detected" && v.mttdSeconds !== null && v.mttdSeconds !== undefined)
      .map(v => v.mttdSeconds as number);

    const mttrValues = validations
      .filter(v => v.mttrSeconds !== null && v.mttrSeconds !== undefined)
      .map(v => v.mttrSeconds as number);

    const avgMttdHours = mttdValues.length > 0
      ? Math.round((mttdValues.reduce((a, b) => a + b, 0) / mttdValues.length / 3600) * 10) / 10
      : 24;

    const avgMttrHours = mttrValues.length > 0
      ? Math.round((mttrValues.reduce((a, b) => a + b, 0) / mttrValues.length / 3600) * 10) / 10
      : 48;

    return {
      avgMttdHours,
      avgMttrHours,
      mttdSampleSize: mttdValues.length,
      mttrSampleSize: mttrValues.length,
    };
  } catch {
    return { avgMttdHours: 24, avgMttrHours: 48, mttdSampleSize: 0, mttrSampleSize: 0 };
  }
}

/**
 * Get per-technique MTTD/MTTR breakdown from SIEM defensive validations.
 */
export async function getPerTechniqueMetrics(organizationId: string): Promise<Array<{
  mitreAttackId: string;
  mitreTactic: string;
  detectionCount: number;
  missCount: number;
  detectionRate: number;
  avgMttdSeconds: number | null;
  avgMttrSeconds: number | null;
  lastTestedAt: string | null;
}>> {
  const validations = await storage.getDefensiveValidationsByOrg(organizationId);

  const byTechnique: Record<string, DefensiveValidation[]> = {};
  for (const v of validations) {
    if (!v.mitreAttackId) continue;
    if (!byTechnique[v.mitreAttackId]) byTechnique[v.mitreAttackId] = [];
    byTechnique[v.mitreAttackId].push(v);
  }

  const results: Array<{
    mitreAttackId: string;
    mitreTactic: string;
    detectionCount: number;
    missCount: number;
    detectionRate: number;
    avgMttdSeconds: number | null;
    avgMttrSeconds: number | null;
    lastTestedAt: string | null;
  }> = [];

  for (const techniqueId of Object.keys(byTechnique)) {
    const vals = byTechnique[techniqueId];
    const detected = vals.filter((v: DefensiveValidation) => v.status === "detected");
    const missed = vals.filter((v: DefensiveValidation) => v.status === "missed");

    const mttdValues = detected
      .filter((v: DefensiveValidation) => v.mttdSeconds !== null && v.mttdSeconds !== undefined)
      .map((v: DefensiveValidation) => v.mttdSeconds as number);

    const mttrValues = vals
      .filter((v: DefensiveValidation) => v.mttrSeconds !== null && v.mttrSeconds !== undefined)
      .map((v: DefensiveValidation) => v.mttrSeconds as number);

    const totalDecided = detected.length + missed.length;

    const sorted = [...vals].sort((a: DefensiveValidation, b: DefensiveValidation) =>
      new Date(b.createdAt!).getTime() - new Date(a.createdAt!).getTime()
    );
    const latest = sorted[0];

    results.push({
      mitreAttackId: techniqueId,
      mitreTactic: latest?.mitreTactic || "unknown",
      detectionCount: detected.length,
      missCount: missed.length,
      detectionRate: totalDecided > 0 ? Math.round((detected.length / totalDecided) * 100) : 0,
      avgMttdSeconds: mttdValues.length > 0
        ? Math.round(mttdValues.reduce((a: number, b: number) => a + b, 0) / mttdValues.length)
        : null,
      avgMttrSeconds: mttrValues.length > 0
        ? Math.round(mttrValues.reduce((a: number, b: number) => a + b, 0) / mttrValues.length)
        : null,
      lastTestedAt: latest?.createdAt?.toISOString?.() || (latest?.createdAt as any) || null,
    });
  }

  return results.sort((a, b) => b.detectionCount + b.missCount - (a.detectionCount + a.missCount));
}

/**
 * Aggregate daily metrics and store in metricsHistory for trend tracking.
 */
export async function aggregateDailyMetrics(organizationId: string): Promise<void> {
  const { randomUUID } = await import("crypto");
  const siemMetrics = await getSiemObservedMetrics(organizationId);
  const now = new Date();
  const periodStart = new Date(now);
  periodStart.setHours(0, 0, 0, 0);
  const periodEnd = new Date(periodStart);
  periodEnd.setDate(periodEnd.getDate() + 1);

  if (siemMetrics.mttdSampleSize > 0) {
    await storage.createMetricsHistory({
      id: `mh-${randomUUID().slice(0, 8)}`,
      organizationId,
      metricType: "mttd",
      valueSeconds: Math.round(siemMetrics.avgMttdHours * 3600),
      sampleSize: siemMetrics.mttdSampleSize,
      periodStart,
      periodEnd,
    });
  }

  if (siemMetrics.mttrSampleSize > 0) {
    await storage.createMetricsHistory({
      id: `mh-${randomUUID().slice(0, 8)}`,
      organizationId,
      metricType: "mttr",
      valueSeconds: Math.round(siemMetrics.avgMttrHours * 3600),
      sampleSize: siemMetrics.mttrSampleSize,
      periodStart,
      periodEnd,
    });
  }

  // Detection rate
  const validations = await storage.getDefensiveValidationsByOrg(organizationId);
  const detected = validations.filter(v => v.status === "detected").length;
  const missed = validations.filter(v => v.status === "missed").length;
  const total = detected + missed;
  if (total > 0) {
    await storage.createMetricsHistory({
      id: `mh-${randomUUID().slice(0, 8)}`,
      organizationId,
      metricType: "detection_rate",
      valueSeconds: Math.round((detected / total) * 10000), // store as basis points (100% = 10000)
      sampleSize: total,
      periodStart,
      periodEnd,
    });
  }
}

function countBySeverity(evaluations: Evaluation[], results: Result[]): VulnerabilityExposure {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  
  evaluations.forEach(eval_ => {
    const priority = eval_.priority as keyof typeof counts;
    if (priority in counts) {
      counts[priority]++;
    }
  });

  results.forEach(result => {
    if (result.exploitable) {
      if (result.score >= 90) counts.critical++;
      else if (result.score >= 70) counts.high++;
      else if (result.score >= 40) counts.medium++;
      else counts.low++;
    }
  });

  return counts;
}

function calculateCategoryScores(evaluations: Evaluation[], results: Result[]): CategoryScore {
  const categoryIssues: Record<keyof CategoryScore, number[]> = {
    networkSecurity: [],
    applicationSecurity: [],
    identityManagement: [],
    dataProtection: [],
    incidentResponse: [],
    securityAwareness: [],
    compliancePosture: [],
  };

  evaluations.forEach((eval_, idx) => {
    const category = EXPOSURE_TO_CATEGORY[eval_.exposureType] || "applicationSecurity";
    const result = results.find(r => r.evaluationId === eval_.id);
    const score = result ? (100 - result.score) : 50;
    categoryIssues[category].push(score);
  });

  const scores: CategoryScore = {
    networkSecurity: 75,
    applicationSecurity: 75,
    identityManagement: 75,
    dataProtection: 75,
    incidentResponse: 75,
    securityAwareness: 75,
    compliancePosture: 75,
  };

  Object.keys(categoryIssues).forEach(key => {
    const category = key as keyof CategoryScore;
    const issues = categoryIssues[category];
    if (issues.length > 0) {
      const avg = issues.reduce((a, b) => a + b, 0) / issues.length;
      scores[category] = Math.round(Math.max(20, Math.min(100, avg)));
    }
  });

  return scores;
}

function calculateOverallScore(categoryScores: CategoryScore, vuln: VulnerabilityExposure): number {
  const categoryAvg = Object.values(categoryScores).reduce((a, b) => a + b, 0) / 7;
  const vulnPenalty = (vuln.critical * 15) + (vuln.high * 8) + (vuln.medium * 3) + (vuln.low * 1);
  return Math.round(Math.max(10, Math.min(100, categoryAvg - Math.min(50, vulnPenalty))));
}

function calculateBreachLikelihood(results: Result[], vuln: VulnerabilityExposure): number {
  const exploitableCount = results.filter(r => r.exploitable).length;
  const exploitableRatio = results.length > 0 ? exploitableCount / results.length : 0;
  const severityFactor = (vuln.critical * 0.4) + (vuln.high * 0.25) + (vuln.medium * 0.1) + (vuln.low * 0.02);
  return Math.round(Math.min(95, Math.max(5, (exploitableRatio * 50) + Math.min(45, severityFactor))));
}

function calculateMTTD(results: Result[]): number {
  if (results.length === 0) return 24;
  const avgConfidence = results.reduce((a, r) => a + r.confidence, 0) / results.length;
  return Math.max(1, Math.round(24 - (avgConfidence / 10)));
}

function calculateMTTR(evaluations: Evaluation[]): number {
  if (evaluations.length === 0) return 48;
  const criticalCount = evaluations.filter(e => e.priority === "critical").length;
  return Math.max(4, Math.round(12 + (criticalCount * 2)));
}

function calculateTrend(evaluations: Evaluation[], results: Result[]): "improving" | "stable" | "declining" {
  if (evaluations.length < 5) return "stable";
  
  const sorted = [...evaluations].sort((a, b) => 
    new Date(a.createdAt!).getTime() - new Date(b.createdAt!).getTime()
  );
  
  const midpoint = Math.floor(sorted.length / 2);
  const firstHalf = sorted.slice(0, midpoint);
  const secondHalf = sorted.slice(midpoint);
  
  const countCritical = (evals: Evaluation[]) => 
    evals.filter(e => e.priority === "critical" || e.priority === "high").length;
  
  const firstHalfCritical = countCritical(firstHalf);
  const secondHalfCritical = countCritical(secondHalf);
  
  if (secondHalfCritical < firstHalfCritical * 0.7) return "improving";
  if (secondHalfCritical > firstHalfCritical * 1.3) return "declining";
  return "stable";
}

function generateRecommendations(scores: CategoryScore, vuln: VulnerabilityExposure): string[] {
  const recommendations: string[] = [];
  
  if (vuln.critical > 0) {
    recommendations.push(`Address ${vuln.critical} critical vulnerabilities immediately`);
  }
  
  const lowestCategory = Object.entries(scores)
    .sort(([, a], [, b]) => a - b)[0];
  
  const categoryNames: Record<string, string> = {
    networkSecurity: "network security controls",
    applicationSecurity: "application security practices",
    identityManagement: "identity and access management",
    dataProtection: "data protection measures",
    incidentResponse: "incident response capabilities",
    securityAwareness: "security awareness training",
    compliancePosture: "compliance coverage",
  };
  
  recommendations.push(`Strengthen ${categoryNames[lowestCategory[0]]} (score: ${lowestCategory[1]})`);
  
  if (vuln.high > 3) {
    recommendations.push(`Prioritize remediation of ${vuln.high} high-severity findings`);
  }
  
  return recommendations.slice(0, 5);
}

function countExposureTypes(evaluations: Evaluation[]): Record<string, number> {
  const counts: Record<string, number> = {};
  evaluations.forEach(e => {
    counts[e.exposureType] = (counts[e.exposureType] || 0) + 1;
  });
  return counts;
}

function generatePredictedVectors(
  exposureFrequency: Record<string, number>,
  results: Result[],
  evaluations: Evaluation[]
): AttackPrediction[] {
  const predictions: AttackPrediction[] = [];
  const totalEvaluations = evaluations.length;
  
  const sortedExposures = Object.entries(exposureFrequency)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  sortedExposures.forEach(([exposureType, count]) => {
    const relevantEvals = evaluations.filter(e => e.exposureType === exposureType);
    const relevantResults = results.filter(r => 
      relevantEvals.some(e => e.id === r.evaluationId)
    );
    
    const exploitableCount = relevantResults.filter(r => r.exploitable).length;
    const avgScore = relevantResults.length > 0 
      ? relevantResults.reduce((a, r) => a + r.score, 0) / relevantResults.length 
      : 50;
    
    const likelihood = Math.round(Math.min(95, (count / totalEvaluations) * 100 + (avgScore * 0.3)));
    const confidence = Math.round(Math.min(95, 50 + (count * 5) + (exploitableCount * 10)));
    
    const adversaryProfile = determineAdversaryProfile(exposureType, avgScore);
    
    predictions.push({
      vector: EXPOSURE_DESCRIPTIONS[exposureType] || exposureType,
      likelihood,
      confidence,
      adversaryProfile,
      estimatedImpact: getImpactLevel(avgScore),
      mitreAttackId: EXPOSURE_TO_MITRE[exposureType] || "T1190",
      occurrences: count,
    });
  });

  return predictions;
}

function determineAdversaryProfile(exposureType: string, avgScore: number): string {
  if (avgScore >= 80) return "advanced_persistent_threat";
  if (exposureType === "rce" || exposureType === "sql_injection") return "organized_crime";
  if (exposureType === "auth_bypass" || exposureType === "privilege_escalation") return "insider_threat";
  if (avgScore >= 50) return "opportunistic_criminal";
  return "script_kiddie";
}

function getImpactLevel(score: number): string {
  if (score >= 85) return "Critical - Immediate business impact";
  if (score >= 70) return "High - Significant data or system risk";
  if (score >= 50) return "Medium - Moderate exposure risk";
  return "Low - Limited impact potential";
}

function identifyRiskFactors(evaluations: Evaluation[], results: Result[]): Array<{ factor: string; contribution: number; trend: string }> {
  const factors: Array<{ factor: string; contribution: number; trend: string }> = [];
  
  const criticalCount = evaluations.filter(e => e.priority === "critical").length;
  if (criticalCount > 0) {
    factors.push({
      factor: "Critical vulnerabilities",
      contribution: Math.min(40, criticalCount * 15),
      trend: "stable",
    });
  }
  
  const exploitableCount = results.filter(r => r.exploitable).length;
  if (exploitableCount > 0) {
    factors.push({
      factor: "Exploitable findings",
      contribution: Math.min(35, exploitableCount * 8),
      trend: "stable",
    });
  }
  
  const exposureTypes = new Set(evaluations.map(e => e.exposureType));
  if (exposureTypes.size > 5) {
    factors.push({
      factor: "Attack surface diversity",
      contribution: Math.min(25, exposureTypes.size * 3),
      trend: "increasing",
    });
  }
  
  const avgScore = results.length > 0 
    ? results.reduce((a, r) => a + r.score, 0) / results.length 
    : 50;
  if (avgScore > 60) {
    factors.push({
      factor: "High average risk scores",
      contribution: Math.round(avgScore * 0.3),
      trend: "stable",
    });
  }
  
  return factors.slice(0, 4);
}

function calculateOverallBreachLikelihood(results: Result[]): number {
  if (results.length === 0) return 25;
  const exploitableRatio = results.filter(r => r.exploitable).length / results.length;
  const avgScore = results.reduce((a, r) => a + r.score, 0) / results.length;
  return Math.round(Math.min(90, Math.max(10, (exploitableRatio * 40) + (avgScore * 0.5))));
}

function generateActionableRecommendations(
  predictions: AttackPrediction[],
  riskFactors: Array<{ factor: string; contribution: number }>
): string[] {
  const actions: string[] = [];
  
  const topVector = predictions[0];
  if (topVector) {
    actions.push(`Focus on ${topVector.vector} prevention - ${topVector.likelihood}% predicted likelihood`);
  }
  
  const topFactor = riskFactors.sort((a, b) => b.contribution - a.contribution)[0];
  if (topFactor) {
    actions.push(`Address ${topFactor.factor} (${topFactor.contribution}% risk contribution)`);
  }
  
  if (predictions.some(p => p.adversaryProfile === "advanced_persistent_threat")) {
    actions.push("Implement advanced threat detection for APT-level attacks");
  }
  
  actions.push("Conduct regular vulnerability assessments to validate predictions");
  
  return actions.slice(0, 5);
}

function calculateBenchmarkPercentile(overallScore: number, vuln: VulnerabilityExposure): number {
  const basePercentile = overallScore;
  const vulnPenalty = (vuln.critical * 5) + (vuln.high * 2) + (vuln.medium * 0.5);
  return Math.round(Math.min(100, Math.max(0, basePercentile - vulnPenalty)));
}

interface BreachChainMetrics {
  hasData: boolean;
  avgRiskScore: number;
  maxPrivilegeLevels: string[];
  phaseSuccessRate: number;
  phaseBlockRate: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mitreIdsObserved: string[];
  chainCount: number;
}

async function getBreachChainMetrics(organizationId: string): Promise<BreachChainMetrics> {
  const noData: BreachChainMetrics = {
    hasData: false, avgRiskScore: 0, maxPrivilegeLevels: [], phaseSuccessRate: 0,
    phaseBlockRate: 0, totalFindings: 0, criticalFindings: 0, highFindings: 0,
    mitreIdsObserved: [], chainCount: 0,
  };

  try {
    const chains = await storage.getBreachChains(organizationId);
    const completedChains = chains.filter(c => c.status === "completed");
    if (completedChains.length === 0) return noData;

    let totalRisk = 0;
    let totalPhases = 0;
    let completedPhases = 0;
    let blockedPhases = 0;
    let totalFindings = 0;
    let criticalFindings = 0;
    let highFindings = 0;
    const maxPrivLevels: string[] = [];
    const mitreIds = new Set<string>();

    for (const chain of completedChains) {
      totalRisk += chain.overallRiskScore || 0;
      if (chain.maxPrivilegeAchieved) maxPrivLevels.push(chain.maxPrivilegeAchieved);

      const phaseResults = (chain.phaseResults as BreachPhaseResult[]) || [];
      for (const pr of phaseResults) {
        totalPhases++;
        if (pr.status === "completed") completedPhases++;
        if (pr.status === "blocked" || pr.status === "failed") blockedPhases++;
        for (const f of pr.findings) {
          totalFindings++;
          if (f.severity === "critical") criticalFindings++;
          if (f.severity === "high") highFindings++;
          if (f.mitreId) mitreIds.add(f.mitreId);
        }
      }
    }

    return {
      hasData: true,
      avgRiskScore: Math.round(totalRisk / completedChains.length),
      maxPrivilegeLevels: maxPrivLevels,
      phaseSuccessRate: totalPhases > 0 ? completedPhases / totalPhases : 0,
      phaseBlockRate: totalPhases > 0 ? blockedPhases / totalPhases : 0,
      totalFindings, criticalFindings, highFindings,
      mitreIdsObserved: Array.from(mitreIds),
      chainCount: completedChains.length,
    };
  } catch (err) {
    console.error("[MetricsCalculator] Failed to get breach chain metrics:", err);
    return noData;
  }
}

function createInsufficientDataPosture(organizationId: string, evaluationCount: number): DefensivePostureMetrics {
  return {
    id: `posture-${organizationId}-${Date.now()}`,
    organizationId,
    overallScore: 0,
    categoryScores: {
      networkSecurity: 0,
      applicationSecurity: 0,
      identityManagement: 0,
      dataProtection: 0,
      incidentResponse: 0,
      securityAwareness: 0,
      compliancePosture: 0,
    },
    breachLikelihood: 0,
    meanTimeToDetect: 0,
    meanTimeToRespond: 0,
    mttdDataSource: "synthetic",
    mttrDataSource: "synthetic",
    mttdSampleSize: 0,
    mttrSampleSize: 0,
    vulnerabilityExposure: { critical: 0, high: 0, medium: 0, low: 0 },
    trendDirection: "stable",
    benchmarkPercentile: 0,
    recommendations: [
      `Complete at least ${3 - evaluationCount} more evaluations to generate metrics`,
      "Run security assessments on critical assets first",
    ],
    dataSource: "insufficient_data",
    evaluationsAnalyzed: evaluationCount,
    modelVersion: "v3.0.0-siem-enhanced",
    calculatedAt: new Date().toISOString(),
  };
}

function createInsufficientDataPredictions(
  organizationId: string,
  timeHorizon: string,
  evaluationCount: number
): AttackPredictionMetrics {
  return {
    id: `pred-insufficient-${Date.now()}`,
    organizationId,
    predictedAttackVectors: [],
    overallBreachLikelihood: 0,
    riskFactors: [],
    recommendedActions: [
      `Complete at least ${3 - evaluationCount} more evaluations to generate predictions`,
      "Run security assessments across different asset types",
    ],
    dataSource: "insufficient_data",
    evaluationsAnalyzed: evaluationCount,
    timeHorizon,
    modelVersion: "v2.0.0-computed",
    calculatedAt: new Date().toISOString(),
  };
}
