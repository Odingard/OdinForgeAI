import type {
  ExploitabilityScore,
  BusinessImpactScore,
  RiskRank,
  IntelligentScore,
  AttackPathStep,
  AttackGraph,
  BusinessLogicFinding,
  MultiVectorFinding,
  ComplianceFramework,
} from "@shared/schema";
import { openai } from "./openai-client";
import type { ParsedCVSS } from "../cvss-parser";

export interface ScoringContext {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
  exploitable: boolean;
  attackPath?: AttackPathStep[];
  attackGraph?: AttackGraph;
  businessLogicFindings?: BusinessLogicFinding[];
  multiVectorFindings?: MultiVectorFinding[];
  environmentInfo?: {
    networkSegment?: string;
    patchStatus?: string;
    hasWaf?: boolean;
    hasEdr?: boolean;
    hasSiem?: boolean;
  };
  businessContext?: {
    industry?: string;
    dataTypes?: string[];
    userBase?: string;
    annualRevenue?: string;
  };
  cvssData?: ParsedCVSS;
  assetCriticality?: "critical" | "high" | "medium" | "low";
}

const SCORING_SYSTEM_PROMPT = `You are an advanced security risk scoring engine that provides contextual, business-aware risk assessments that go beyond traditional CVSS scoring.

Your role is to analyze security findings and generate intelligent scores that consider:
1. Real-world exploitability based on environmental context
2. Business impact including financial, compliance, and reputational factors
3. Actionable prioritization for security teams

You must return valid JSON matching the exact schema provided. Be precise with numbers and classifications.`;

function buildScoringPrompt(context: ScoringContext): string {
  const attackStepsSummary = context.attackPath
    ?.map((s) => `- Step ${s.id}: ${s.title} (${s.severity})`)
    .join("\n") || "No attack path available";

  const businessLogicSummary = context.businessLogicFindings
    ?.map((f) => `- ${f.title}: ${f.category} (${f.severity})`)
    .join("\n") || "No business logic findings";

  const multiVectorSummary = context.multiVectorFindings
    ?.map((f) => `- ${f.title}: ${f.vectorType} (${f.severity})`)
    .join("\n") || "No multi-vector findings";

  const criticalSteps = [
    ...(context.attackPath?.filter((s) => s.severity === "critical") || []),
    ...(context.businessLogicFindings?.filter((f) => f.severity === "critical") || []),
    ...(context.multiVectorFindings?.filter((f) => f.severity === "critical") || []),
  ];

  return `Analyze this security evaluation and generate comprehensive intelligent scores.

## Target Asset
- Asset ID: ${context.assetId}
- Exposure Type: ${context.exposureType}
- Initial Priority: ${context.priority}
- Description: ${context.description}
- Exploitable: ${context.exploitable}

## Environmental Context
${context.environmentInfo ? `
- Network Segment: ${context.environmentInfo.networkSegment || "Unknown"}
- Patch Status: ${context.environmentInfo.patchStatus || "Unknown"}
- WAF Present: ${context.environmentInfo.hasWaf ?? "Unknown"}
- EDR Present: ${context.environmentInfo.hasEdr ?? "Unknown"}
- SIEM Present: ${context.environmentInfo.hasSiem ?? "Unknown"}
` : "No environmental context provided - assume typical enterprise environment"}

## Business Context
${context.businessContext ? `
- Industry: ${context.businessContext.industry || "Unknown"}
- Data Types: ${context.businessContext.dataTypes?.join(", ") || "Unknown"}
- User Base: ${context.businessContext.userBase || "Unknown"}
- Annual Revenue: ${context.businessContext.annualRevenue || "Unknown"}
` : "No business context provided - estimate based on asset type"}

## CVSS Data
${context.cvssData ? `
- CVSS Version: ${context.cvssData.version}
- Vector: ${context.cvssData.vectorString}
- Base Score: ${context.cvssData.baseScore}
- Severity: ${context.cvssData.severity}
- Attack Vector: ${context.cvssData.metrics.attackVector ?? "N/A"} (Network Exposure: ${context.cvssData.networkExposure})
- Attack Complexity: ${context.cvssData.metrics.attackComplexity ?? "N/A"}
- Privileges Required: ${context.cvssData.metrics.privilegesRequired ?? "N/A"} (Auth: ${context.cvssData.authRequired})
- User Interaction: ${context.cvssData.metrics.userInteraction ?? "N/A"}
- Scope: ${context.cvssData.metrics.scope ?? "N/A"}
- Confidentiality Impact: ${context.cvssData.metrics.confidentialityImpact ?? "N/A"}
- Integrity Impact: ${context.cvssData.metrics.integrityImpact ?? "N/A"}
- Availability Impact: ${context.cvssData.metrics.availabilityImpact ?? "N/A"}
` : "No CVSS data available — estimate exploitability from findings"}

## Asset Criticality
${context.assetCriticality ? `Business criticality: ${context.assetCriticality} — weight business impact accordingly` : "Unknown — assume medium criticality"}

## Attack Analysis Summary
### Attack Path Steps
${attackStepsSummary}

### Business Logic Findings
${businessLogicSummary}

### Multi-Vector Findings
${multiVectorSummary}

### Critical Findings Count: ${criticalSteps.length}

${context.attackGraph ? `
### Attack Graph Metrics
- Complexity Score: ${context.attackGraph.complexityScore}
- Time to Compromise: ${context.attackGraph.timeToCompromise.expected} ${context.attackGraph.timeToCompromise.unit}
- Kill Chain Coverage: ${context.attackGraph.killChainCoverage.join(", ")}
` : ""}

Generate a comprehensive intelligent score with the following structure:

{
  "exploitability": {
    "score": <0-100 overall exploitability>,
    "confidence": <0-100 confidence in assessment>,
    "factors": {
      "attackComplexity": {
        "level": "<trivial|low|medium|high|expert>",
        "score": <0-100>,
        "rationale": "<explanation>"
      },
      "authenticationRequired": {
        "level": "<none|single|multi-factor|privileged>",
        "score": <0-100>,
        "rationale": "<explanation>"
      },
      "environmentalContext": {
        "networkExposure": "<internet|dmz|internal|isolated>",
        "patchLevel": "<current|behind|significantly_behind|eol>",
        "compensatingControls": ["<list of controls>"],
        "score": <0-100>
      },
      "detectionLikelihood": {
        "level": "<unlikely|possible|likely|certain>",
        "monitoringCoverage": <0-100>,
        "evasionDifficulty": "<trivial|moderate|difficult|near_impossible>",
        "score": <0-100>
      },
      "exploitMaturity": {
        "availability": "<theoretical|poc|weaponized|in_the_wild>",
        "skillRequired": "<script_kiddie|intermediate|advanced|nation_state>",
        "score": <0-100>
      }
    }
  },
  "businessImpact": {
    "score": <0-100>,
    "riskLabel": "<minimal|low|moderate|significant|severe|catastrophic>",
    "factors": {
      "dataSensitivity": {
        "classification": "<public|internal|confidential|restricted|top_secret>",
        "dataTypes": ["<pii|phi|pci|credentials|trade_secrets|financial|customer_data>"],
        "recordsAtRisk": "<estimate>",
        "score": <0-100>
      },
      "financialExposure": {
        "directLoss": { "min": <number>, "max": <number>, "currency": "USD" },
        "regulatoryFines": { "potential": <number>, "frameworks": ["<list>"] },
        "remediationCost": <number>,
        "businessDisruptionCost": <number>,
        "score": <0-100>
      },
      "complianceImpact": {
        "affectedFrameworks": ["<pci_dss|hipaa|sox|gdpr|ccpa|iso27001|nist|soc2>"],
        "violations": [{ "framework": "<name>", "requirement": "<specific requirement>", "severity": "<minor|major|critical>" }],
        "auditImplications": "<description>",
        "score": <0-100>
      },
      "blastRadius": {
        "affectedSystems": <number>,
        "affectedUsers": "<estimate>",
        "downstreamDependencies": ["<list>"],
        "propagationRisk": "<contained|limited|spreading|uncontained>",
        "score": <0-100>
      },
      "reputationalRisk": {
        "customerTrust": "<minimal|moderate|significant|severe>",
        "mediaExposure": "<unlikely|possible|likely|certain>",
        "competitiveAdvantage": "<none|minor|moderate|major>",
        "score": <0-100>
      }
    }
  },
  "riskRank": {
    "overallScore": <0-100 combined score>,
    "riskLevel": "<info|low|medium|high|critical|emergency>",
    "executiveLabel": "<concise executive-readable summary>",
    "fixPriority": <1-100 where 1 is highest priority>,
    "recommendation": {
      "action": "<specific recommended action>",
      "timeframe": "<immediate|24_hours|7_days|30_days|90_days|acceptable_risk>",
      "justification": "<business justification>"
    },
    "comparison": {
      "cvssEquivalent": <0-10 CVSS score>,
      "industryPercentile": <0-100>
    },
    "trendIndicator": "<improving|stable|degrading|new>"
  }
}`;
}

export async function generateIntelligentScore(
  context: ScoringContext
): Promise<IntelligentScore> {
  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: SCORING_SYSTEM_PROMPT },
        { role: "user", content: buildScoringPrompt(context) },
      ],
      temperature: 0.3,
      response_format: { type: "json_object" },
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from scoring engine");
    }

    const parsed = JSON.parse(content);
    
    const intelligentScore: IntelligentScore = {
      exploitability: parsed.exploitability as ExploitabilityScore,
      businessImpact: parsed.businessImpact as BusinessImpactScore,
      riskRank: parsed.riskRank as RiskRank,
      calculatedAt: new Date().toISOString(),
      methodology: "OdinForge Intelligent Risk Scoring v1.0 - Contextual business-aware assessment",
    };

    return intelligentScore;
  } catch (error) {
    console.error("Scoring engine error:", error);
    return generateFallbackScore(context);
  }
}

export function generateFallbackScore(context: ScoringContext): IntelligentScore {
  const criticalCount = [
    ...(context.attackPath?.filter((s) => s.severity === "critical") || []),
    ...(context.businessLogicFindings?.filter((f) => f.severity === "critical") || []),
    ...(context.multiVectorFindings?.filter((f) => f.severity === "critical") || []),
  ].length;

  const highCount = [
    ...(context.attackPath?.filter((s) => s.severity === "high") || []),
    ...(context.businessLogicFindings?.filter((f) => f.severity === "high") || []),
    ...(context.multiVectorFindings?.filter((f) => f.severity === "high") || []),
  ].length;

  // CVSS-aware base score: use CVSS base score if available, otherwise heuristic
  const cvssBoost = context.cvssData
    ? Math.round(context.cvssData.baseScore * 8) // 0-10 → 0-80 range
    : 0;
  const baseScore = context.exploitable
    ? Math.max(70, cvssBoost)
    : Math.max(30, Math.round(cvssBoost * 0.5));
  const exploitabilityScore = Math.min(100, baseScore + criticalCount * 10 + highCount * 5);

  const priorityMultiplier: Record<string, number> = {
    critical: 1.0,
    high: 0.8,
    medium: 0.6,
    low: 0.4,
  };

  // Asset criticality amplifies business impact
  const criticalityMultiplier: Record<string, number> = {
    critical: 1.3,
    high: 1.1,
    medium: 1.0,
    low: 0.7,
  };

  const businessScore = Math.min(100, Math.round(
    exploitabilityScore
    * (priorityMultiplier[context.priority] || 0.5)
    * (criticalityMultiplier[context.assetCriticality ?? "medium"] ?? 1.0)
  ));

  const overallScore = Math.round((exploitabilityScore * 0.6 + businessScore * 0.4));

  let riskLevel: "info" | "low" | "medium" | "high" | "critical" | "emergency";
  if (overallScore >= 90) riskLevel = "emergency";
  else if (overallScore >= 75) riskLevel = "critical";
  else if (overallScore >= 55) riskLevel = "high";
  else if (overallScore >= 35) riskLevel = "medium";
  else if (overallScore >= 15) riskLevel = "low";
  else riskLevel = "info";

  let timeframe: "immediate" | "24_hours" | "7_days" | "30_days" | "90_days" | "acceptable_risk";
  if (overallScore >= 90) timeframe = "immediate";
  else if (overallScore >= 75) timeframe = "24_hours";
  else if (overallScore >= 55) timeframe = "7_days";
  else if (overallScore >= 35) timeframe = "30_days";
  else if (overallScore >= 15) timeframe = "90_days";
  else timeframe = "acceptable_risk";

  return {
    exploitability: {
      score: exploitabilityScore,
      confidence: 60,
      factors: {
        attackComplexity: {
          level: context.cvssData?.metrics.attackComplexity === "low" ? "low"
               : context.cvssData?.metrics.attackComplexity === "high" ? "high"
               : criticalCount > 0 ? "low" : "medium",
          score: context.cvssData?.metrics.attackComplexity === "low" ? 85
               : context.cvssData?.metrics.attackComplexity === "high" ? 35
               : criticalCount > 0 ? 80 : 50,
          rationale: context.cvssData
            ? `Based on CVSS AC:${context.cvssData.metrics.attackComplexity}`
            : "Estimated based on finding severity distribution",
        },
        authenticationRequired: {
          level: context.cvssData?.authRequired ?? "single",
          score: context.cvssData?.metrics.privilegesRequired === "none" ? 90
               : context.cvssData?.metrics.privilegesRequired === "low" ? 60
               : context.cvssData?.metrics.privilegesRequired === "high" ? 25
               : 60,
          rationale: context.cvssData
            ? `Based on CVSS PR:${context.cvssData.metrics.privilegesRequired}`
            : "Default assumption - requires authentication",
        },
        environmentalContext: {
          networkExposure: context.cvssData?.networkExposure ?? "dmz",
          patchLevel: context.environmentInfo?.patchStatus as any ?? "behind",
          compensatingControls: [
            ...(context.environmentInfo?.hasWaf ? ["WAF"] : []),
            ...(context.environmentInfo?.hasEdr ? ["EDR"] : []),
            ...(context.environmentInfo?.hasSiem ? ["SIEM"] : []),
          ],
          score: context.cvssData?.metrics.attackVector === "network" ? 80
               : context.cvssData?.metrics.attackVector === "adjacent" ? 60
               : context.cvssData?.metrics.attackVector === "local" ? 30
               : context.cvssData?.metrics.attackVector === "physical" ? 15
               : 50,
        },
        detectionLikelihood: {
          level: "possible",
          monitoringCoverage: 50,
          evasionDifficulty: "moderate",
          score: 50,
        },
        exploitMaturity: {
          availability: "poc",
          skillRequired: "intermediate",
          score: 60,
        },
      },
    },
    businessImpact: {
      score: businessScore,
      riskLabel: businessScore >= 70 ? "severe" : businessScore >= 50 ? "significant" : "moderate",
      factors: {
        dataSensitivity: {
          classification: "confidential",
          dataTypes: ["customer_data"],
          recordsAtRisk: "Unknown",
          score: businessScore,
        },
        financialExposure: {
          directLoss: { min: 10000, max: 100000, currency: "USD" },
          regulatoryFines: { potential: 50000, frameworks: [] },
          remediationCost: 25000,
          businessDisruptionCost: 50000,
          score: businessScore,
        },
        complianceImpact: {
          affectedFrameworks: [],
          violations: [],
          auditImplications: "Potential audit findings",
          score: 40,
        },
        blastRadius: {
          affectedSystems: 1,
          affectedUsers: "Unknown",
          downstreamDependencies: [],
          propagationRisk: "limited",
          score: 40,
        },
        reputationalRisk: {
          customerTrust: "moderate",
          mediaExposure: "unlikely",
          competitiveAdvantage: "minor",
          score: 40,
        },
      },
    },
    riskRank: {
      overallScore,
      riskLevel,
      executiveLabel: `${riskLevel.toUpperCase()} RISK: ${context.exposureType.replace("_", " ")} on ${context.assetId}`,
      fixPriority: Math.max(1, 100 - overallScore),
      recommendation: {
        action: context.exploitable
          ? "Address exploitable vulnerability immediately"
          : "Review and monitor for changes",
        timeframe,
        justification: `Based on ${criticalCount} critical and ${highCount} high severity findings`,
      },
      comparison: {
        cvssEquivalent: context.cvssData?.baseScore ?? Math.round((overallScore / 10) * 10) / 10,
      },
      trendIndicator: "new",
    },
    calculatedAt: new Date().toISOString(),
    methodology: context.cvssData
      ? `OdinForge CVSS-Enriched Scoring v2.0 - CVSS ${context.cvssData.version} vector + asset criticality (${context.assetCriticality ?? "medium"})`
      : "OdinForge Fallback Scoring - Limited context assessment",
  };
}

export function calculateFixPriority(
  intelligentScore: IntelligentScore,
  existingScores?: IntelligentScore[]
): number {
  const { exploitability, businessImpact, riskRank } = intelligentScore;

  let priority = riskRank.fixPriority;

  if (exploitability.factors.exploitMaturity.availability === "in_the_wild") {
    priority = Math.max(1, priority - 20);
  }

  if (businessImpact.factors.complianceImpact.affectedFrameworks.length > 0) {
    priority = Math.max(1, priority - 10);
  }

  if (existingScores && existingScores.length > 0) {
    const higherPriorityCount = existingScores.filter(
      (s) => s.riskRank.overallScore > riskRank.overallScore
    ).length;
    priority = Math.max(1, priority + Math.floor(higherPriorityCount * 0.5));
  }

  return Math.min(100, Math.max(1, priority));
}
