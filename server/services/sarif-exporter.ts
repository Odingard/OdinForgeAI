import type { Evaluation, Result, AttackPathStep } from "@shared/schema";
import { getVulnerabilityInfo, formatVulnerabilityName } from "@shared/vulnerability-catalog";
import type { ExposureType } from "@shared/schema";

/**
 * SARIF 2.1.0 Exporter
 *
 * Generates Static Analysis Results Interchange Format output for CI/CD integration.
 * Maps OdinForge AEV evaluation results to SARIF rules and results with
 * CWE relationships, MITRE ATT&CK references, and threat intel annotations.
 */

// ---------------------------------------------------------------------------
// SARIF 2.1.0 Types (inline — no external dependency)
// ---------------------------------------------------------------------------

interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifToolComponent };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

interface SarifToolComponent {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifReportingDescriptor[];
}

interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties?: {
    tags?: string[];
    "security-severity"?: string;
  };
  relationships?: Array<{
    target: { id: string; toolComponent: { name: string } };
    kinds: string[];
  }>;
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  logicalLocations: Array<{
    name: string;
    kind: string;
    fullyQualifiedName?: string;
  }>;
}

interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  properties?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Level + severity mapping
// ---------------------------------------------------------------------------

function scoreToLevel(score: number): "error" | "warning" | "note" {
  if (score >= 80) return "error";
  if (score >= 50) return "warning";
  return "note";
}

function riskLevelToSeverity(riskLevel: string): string {
  switch (riskLevel) {
    case "critical": return "9.5";
    case "high": return "7.5";
    case "medium": return "5.0";
    case "low": return "2.5";
    default: return "5.0";
  }
}

// ---------------------------------------------------------------------------
// Rule builder — one rule per unique exposureType
// ---------------------------------------------------------------------------

function buildRule(exposureType: string): SarifReportingDescriptor {
  let vulnInfo;
  try {
    vulnInfo = getVulnerabilityInfo(exposureType as ExposureType);
  } catch {
    return {
      id: exposureType,
      name: exposureType,
      shortDescription: { text: exposureType },
      fullDescription: { text: `Security finding: ${exposureType}` },
      properties: { tags: ["security"], "security-severity": "5.0" },
    };
  }

  const relationships: SarifReportingDescriptor["relationships"] = [];
  for (const cweId of vulnInfo.cweIds) {
    relationships.push({
      target: { id: cweId, toolComponent: { name: "CWE" } },
      kinds: ["superset"],
    });
  }

  return {
    id: vulnInfo.id,
    name: formatVulnerabilityName(vulnInfo.id),
    shortDescription: { text: vulnInfo.shortName },
    fullDescription: { text: vulnInfo.description },
    properties: {
      tags: ["security", ...vulnInfo.mitreTechniques],
      "security-severity": riskLevelToSeverity(vulnInfo.riskLevel),
    },
    relationships: relationships.length > 0 ? relationships : undefined,
  };
}

// ---------------------------------------------------------------------------
// Result builder — one result per evaluation+result pair
// ---------------------------------------------------------------------------

function buildSarifResult(
  evaluation: Evaluation,
  result: Result
): SarifResult {
  const attackPath = (result.attackPath as AttackPathStep[] | null) || [];
  const recommendations = (result.recommendations as Array<{ title?: string; description?: string }> | null) || [];

  const messageParts: string[] = [];
  if (result.exploitable) {
    messageParts.push(`EXPLOITABLE (confidence: ${result.confidence}%, score: ${result.score}/100).`);
  } else {
    messageParts.push(`Not exploitable (confidence: ${result.confidence}%, score: ${result.score}/100).`);
  }

  if (attackPath.length > 0) {
    const techniques = attackPath
      .map(s => s.technique || s.title)
      .filter(Boolean)
      .slice(0, 5);
    messageParts.push(`Attack path: ${techniques.join(" → ")}.`);
  }

  if (result.impact) {
    const impactStr = typeof result.impact === "string" ? result.impact : "";
    if (impactStr) messageParts.push(`Impact: ${impactStr.slice(0, 200)}`);
  }

  if (recommendations.length > 0) {
    const topRec = recommendations[0];
    if (topRec?.title) messageParts.push(`Remediation: ${topRec.title}.`);
  }

  // Extract threat intel from intelligentScore if available
  const intelligentScore = result.intelligentScore as Record<string, unknown> | null;
  const properties: Record<string, unknown> = {
    evaluationId: evaluation.id,
    assetId: evaluation.assetId,
    exploitable: result.exploitable,
    confidence: result.confidence,
    odinforgeScore: result.score,
    priority: evaluation.priority,
    executionMode: evaluation.executionMode,
  };

  if (intelligentScore) {
    const methodology = intelligentScore.methodology as string | undefined;
    if (methodology) {
      properties.cisaKevListed = methodology.includes("CISA KEV");
      properties.kevRansomwareCampaign = methodology.includes("[Ransomware]");
    }
    const exploitMaturity = intelligentScore.exploitMaturity as Record<string, unknown> | undefined;
    if (exploitMaturity?.exploitProbability30Day) {
      properties.epssExploitProbability = exploitMaturity.exploitProbability30Day;
    }
  }

  if (result.duration) {
    properties.durationMs = result.duration;
  }

  return {
    ruleId: evaluation.exposureType,
    level: scoreToLevel(result.score),
    message: { text: messageParts.join(" ") },
    locations: [
      {
        logicalLocations: [
          {
            name: evaluation.assetId,
            kind: "asset",
            fullyQualifiedName: `${evaluation.organizationId}/${evaluation.assetId}`,
          },
        ],
      },
    ],
    properties,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function generateSarifReport(
  evaluations: Evaluation[],
  results: Result[],
  organizationId: string
): SarifLog {
  // Build a lookup from evaluationId → result
  const resultByEvalId = new Map<string, Result>();
  for (const r of results) {
    resultByEvalId.set(r.evaluationId, r);
  }

  // Collect unique exposure types for rules
  const exposureTypes = new Set<string>();
  for (const e of evaluations) {
    exposureTypes.add(e.exposureType);
  }

  const rules: SarifReportingDescriptor[] = [];
  Array.from(exposureTypes).forEach(et => {
    rules.push(buildRule(et));
  });

  // Build results
  const sarifResults: SarifResult[] = [];
  for (const evaluation of evaluations) {
    const result = resultByEvalId.get(evaluation.id);
    if (!result) continue;
    sarifResults.push(buildSarifResult(evaluation, result));
  }

  // Build invocation
  const timestamps = evaluations
    .map(e => e.createdAt)
    .filter(Boolean)
    .sort();
  const completedTimestamps = results
    .map(r => r.completedAt)
    .filter(Boolean)
    .sort();

  const invocation: SarifInvocation = {
    executionSuccessful: true,
    startTimeUtc: timestamps[0] ? new Date(timestamps[0]).toISOString() : undefined,
    endTimeUtc: completedTimestamps.length > 0
      ? new Date(completedTimestamps[completedTimestamps.length - 1]!).toISOString()
      : undefined,
    properties: {
      organizationId,
      evaluationCount: evaluations.length,
      exploitableCount: results.filter(r => r.exploitable).length,
    },
  };

  return {
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "OdinForge AEV",
            version: "1.0.0",
            informationUri: "https://odinforge.ai",
            rules,
          },
        },
        results: sarifResults,
        invocations: [invocation],
      },
    ],
  };
}
