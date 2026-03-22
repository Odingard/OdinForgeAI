/**
 * CISO Report Generator — Engagement Package Component 1/5
 *
 * ADR-005: Generates the executive-level breach assessment report with:
 *   - Risk Grade A-F (computed from breach chain results)
 *   - Breach chain narrative (plain language kill chain summary)
 *   - Business impact analysis
 *   - Remediation priorities (ordered by risk reduction)
 *
 * This is a DETERMINISTIC report — no LLM involved.
 * Data comes exclusively from breach chain phase results and evidence.
 */

import type {
  BreachChain,
  BreachPhaseResult,
  BreachPhaseContext,
} from "@shared/schema";
import { reportIntegrityFilter } from "../report-integrity-filter";
import type { EvaluatedFinding } from "../evidence-quality-gate";

// ─── Types ────────────────────────────────────────────────────────────────────

export type RiskGrade = "A" | "B" | "C" | "D" | "E" | "F";

export interface CISOReport {
  reportId: string;
  engagementId: string;
  generatedAt: string;
  organizationId: string;

  riskGrade: RiskGrade;
  riskGradeRationale: string;
  overallRiskScore: number;

  breachChainNarrative: string;
  businessImpact: BusinessImpactSection;
  remediationPriorities: RemediationPriority[];
  keyMetrics: CISOKeyMetrics;
  phaseOverview: PhaseOverview[];
  evidenceIntegritySummary: EvidenceIntegritySummary;
}

interface BusinessImpactSection {
  summary: string;
  domainsCompromised: string[];
  maxPrivilegeAchieved: string;
  credentialExposure: number;
  assetsCompromised: number;
  complianceImplications: string[];
}

interface RemediationPriority {
  rank: number;
  title: string;
  phase: string;
  severity: "critical" | "high" | "medium" | "low";
  effort: "immediate" | "short-term" | "long-term";
  description: string;
}

interface CISOKeyMetrics {
  totalFindings: number;
  customerFindings: number;
  suppressedFindings: number;
  criticalFindings: number;
  highFindings: number;
  phasesCompleted: number;
  totalPhases: number;
  chainDurationMs: number;
  filterPassRate: number;
}

interface PhaseOverview {
  phase: string;
  displayName: string;
  status: string;
  findingCount: number;
  highestSeverity: string;
  summary: string;
}

interface EvidenceIntegritySummary {
  proven: number;
  corroborated: number;
  inferred: number;
  unverifiable: number;
  filterPassRate: number;
}

// ─── Risk Grade Computation ──────────────────────────────────────────────────

const PHASE_DISPLAY_NAMES: Record<string, string> = {
  application_compromise: "Application Compromise",
  credential_extraction: "Credential Extraction",
  cloud_iam_escalation: "Cloud IAM Escalation",
  container_k8s_breakout: "Container/K8s Breakout",
  lateral_movement: "Lateral Movement",
  impact_assessment: "Impact Assessment",
};

function computeRiskGrade(chain: BreachChain): { grade: RiskGrade; rationale: string } {
  const score = chain.overallRiskScore ?? 0;
  const domains = (chain.domainsBreached as string[] | null) ?? [];
  const maxPriv = chain.maxPrivilegeAchieved ?? "none";
  const assetsCompromised = chain.totalAssetsCompromised ?? 0;

  // Grade thresholds based on composite risk signals
  if (score >= 85 || (maxPriv === "domain_admin" || maxPriv === "cloud_admin")) {
    return {
      grade: "F",
      rationale: `Critical risk: risk score ${score}/100, ${maxPriv} privilege achieved across ${domains.length} domain(s). Immediate executive action required.`,
    };
  }
  if (score >= 70 || domains.length >= 3) {
    return {
      grade: "E",
      rationale: `Severe risk: risk score ${score}/100, ${domains.length} domains compromised, ${assetsCompromised} assets exposed. Urgent remediation needed.`,
    };
  }
  if (score >= 55 || domains.length >= 2) {
    return {
      grade: "D",
      rationale: `High risk: risk score ${score}/100, breach chain crossed ${domains.length} domain boundary(ies). Significant security gaps identified.`,
    };
  }
  if (score >= 40 || assetsCompromised >= 3) {
    return {
      grade: "C",
      rationale: `Moderate risk: risk score ${score}/100 with ${assetsCompromised} assets compromised. Targeted remediation recommended.`,
    };
  }
  if (score >= 20) {
    return {
      grade: "B",
      rationale: `Low-moderate risk: risk score ${score}/100. Limited exposure found — address findings in normal remediation cycle.`,
    };
  }
  return {
    grade: "A",
    rationale: `Minimal risk: risk score ${score}/100. No significant exploitable paths discovered in this assessment.`,
  };
}

// ─── Narrative Builder ───────────────────────────────────────────────────────

function buildBreachNarrative(chain: BreachChain): string {
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const domains = (chain.domainsBreached as string[] | null) ?? [];
  const maxPriv = chain.maxPrivilegeAchieved ?? "none";
  const targetAssets = (chain.assetIds as string[]).join(", ");

  const lines: string[] = [];
  lines.push(`OdinForge conducted an adversarial assessment against ${targetAssets}.`);

  const completedPhases = phases.filter(p => p.status === "completed");
  if (completedPhases.length === 0) {
    lines.push("No breach chain phases completed successfully.");
    return lines.join(" ");
  }

  lines.push(`The assessment executed ${completedPhases.length} of ${phases.length} phases.`);

  for (const phase of completedPhases) {
    const name = PHASE_DISPLAY_NAMES[phase.phaseName] ?? phase.phaseName;
    const findingCount = phase.findings?.length ?? 0;
    const criticals = phase.findings?.filter(f => f.severity === "critical").length ?? 0;
    if (findingCount > 0) {
      lines.push(`${name}: ${findingCount} finding(s)${criticals > 0 ? ` including ${criticals} critical` : ""}.`);
    }
  }

  if (domains.length > 0) {
    lines.push(`The attack chain crossed ${domains.length} domain boundary(ies): ${domains.join(", ")}.`);
  }
  if (maxPriv !== "none") {
    lines.push(`Maximum privilege achieved: ${maxPriv}.`);
  }

  return lines.join(" ");
}

// ─── Remediation Priorities ──────────────────────────────────────────────────

function buildRemediationPriorities(phases: BreachPhaseResult[]): RemediationPriority[] {
  const priorities: RemediationPriority[] = [];
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

  for (const phase of phases) {
    for (const finding of phase.findings ?? []) {
      if (finding.severity === "critical" || finding.severity === "high") {
        priorities.push({
          rank: 0, // assigned after sort
          title: finding.title,
          phase: PHASE_DISPLAY_NAMES[phase.phaseName] ?? phase.phaseName,
          severity: finding.severity,
          effort: finding.severity === "critical" ? "immediate" : "short-term",
          description: finding.description,
        });
      }
    }
  }

  priorities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  priorities.forEach((p, i) => { p.rank = i + 1; });

  return priorities.slice(0, 20); // Top 20
}

// ─── Compliance Implications ─────────────────────────────────────────────────

function deriveComplianceImplications(domains: string[]): string[] {
  const implications: string[] = [];
  if (domains.includes("application")) implications.push("PCI-DSS Requirement 6 (Secure Development)", "OWASP Top 10");
  if (domains.includes("cloud")) implications.push("SOC 2 Type II (CC6/CC7)", "ISO 27001 Annex A.12");
  if (domains.includes("network")) implications.push("NIST CSF PR.AC / DE.CM", "CIS Controls v8");
  if (domains.includes("kubernetes")) implications.push("CIS Kubernetes Benchmark", "NIST SP 800-190");
  return implications;
}

// ─── Executive Summary Templates (Phase 14) ─────────────────────────────────

function buildExecutiveSummaryFromPath(path: any): string {
  const steps = path.steps || [];
  // Extract clean vulnerability name and endpoint from step data
  const rawTechnique = steps[0]?.technique || steps[0]?.action || 'unknown vulnerability';
  const entryVuln = rawTechnique.includes(' → ') ? rawTechnique.split(' → ').slice(1).join(' → ') : rawTechnique;
  const entryPoint = rawTechnique.includes(' → ') ? rawTechnique.split(' → ')[0] : (path.name?.split(' → ')[0] || 'target endpoint');
  const stepCount = steps.length;

  const artifactSummary = path.artifacts?.length > 0
    ? `confirmed artifact use (${path.artifacts.slice(0, 3).join(', ')})`
    : 'no artifact reuse observed';

  const pivotSummary = (path.confidence === 'critical' || path.confidence === 'strong')
    ? 'replay-backed progression'
    : 'direct exploit chaining';

  const targetSummary = path.finalImpact?.toLowerCase() || 'system compromise';

  const { impact, expanded } = mapBusinessImpact(path.finalImpact || '');

  return `### Primary Breach Path\n${path.name}\n\n` +
    `Confidence: ${path.confidence}\nPath Score: ${path.score}/100\n\n` +
    `An attacker can exploit ${entryVuln} on ${entryPoint}, progressing through a validated attack chain consisting of ${stepCount} steps. ` +
    `Each stage of this path was confirmed with direct evidence, demonstrating a viable route from initial access to impactful system compromise.\n\n` +
    `### Why This Path Matters\nThis path was identified as the highest risk because it:\n` +
    `- progresses from entry to impact in ${stepCount} validated steps\n` +
    `- includes ${artifactSummary}\n` +
    `- demonstrates ${pivotSummary}\n` +
    `- targets ${targetSummary}\n\n` +
    `### Business Impact\n${impact}\n\nIn practical terms, this means:\n${expanded}`;
}

function buildBusinessImpactFromPath(path: any): string {
  const { impact, expanded } = mapBusinessImpact(path.finalImpact || '');
  return `${impact}\n\n${expanded}`;
}

function mapBusinessImpact(finalImpact: string): { impact: string; expanded: string } {
  const lower = finalImpact.toLowerCase();

  if (lower.includes('admin')) {
    return {
      impact: 'Full administrative control over application systems',
      expanded: 'An attacker could modify configuration, manage users, and control system behavior.',
    };
  }
  if (lower.includes('config') || lower.includes('secret') || lower.includes('credential')) {
    return {
      impact: 'Unauthorized modification of system configuration',
      expanded: 'An attacker could alter application behavior, security controls, or service integrations.',
    };
  }
  if (lower.includes('user') || lower.includes('account') || lower.includes('data')) {
    return {
      impact: 'Unauthorized access to user accounts and sensitive data',
      expanded: 'An attacker could access or manipulate user information, including personal and financial data.',
    };
  }
  if (lower.includes('critical') || lower.includes('proven') || lower.includes('validated')) {
    return {
      impact: 'Critical exploitable vulnerability with validated attack chain',
      expanded: 'An attacker has a confirmed path from initial access to system compromise, backed by real exploitation evidence.',
    };
  }
  return {
    impact: 'Confirmed security weakness with potential for escalation',
    expanded: 'While direct impact may be limited, this condition enables further attack progression.',
  };
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function generateCISOReport(chain: BreachChain, primaryAttackPath?: any): CISOReport {
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const context = chain.currentContext as BreachPhaseContext | null;
  const domains = (chain.domainsBreached as string[] | null) ?? [];
  const { grade, rationale } = computeRiskGrade(chain);

  // Run all findings through the integrity filter
  const allFindings = phases.flatMap(p => p.findings ?? []);
  const evaluated: EvaluatedFinding[] = allFindings.map(f => ({
    ...f,
    id: f.id ?? "unknown",
    severity: f.severity ?? "medium",
    title: f.title ?? "Untitled",
    description: f.description ?? "",
  }));
  const filtered = reportIntegrityFilter.filter(evaluated);

  // Phase overview
  const phaseOverview: PhaseOverview[] = phases.map(p => {
    const customerFindingsInPhase = (p.findings ?? []).filter(f =>
      f.evidenceQuality === "proven" || f.evidenceQuality === "corroborated" || !f.evidenceQuality
    );
    const highestSev = customerFindingsInPhase.reduce(
      (max, f) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[f.severity] ?? 3) < (order[max] ?? 3) ? f.severity : max;
      },
      "low" as string
    );

    return {
      phase: p.phaseName,
      displayName: PHASE_DISPLAY_NAMES[p.phaseName] ?? p.phaseName,
      status: p.status,
      findingCount: customerFindingsInPhase.length,
      highestSeverity: highestSev,
      summary: `${customerFindingsInPhase.length} confirmed finding(s), highest severity: ${highestSev}`,
    };
  });

  const criticals = filtered.customerFindings.filter(f => f.severity === "critical").length;
  const highs = filtered.customerFindings.filter(f => f.severity === "high").length;

  return {
    reportId: `ciso-${chain.id}`,
    engagementId: chain.id,
    generatedAt: new Date().toISOString(),
    organizationId: chain.organizationId,
    riskGrade: grade,
    riskGradeRationale: rationale,
    overallRiskScore: chain.overallRiskScore ?? 0,
    breachChainNarrative: primaryAttackPath
      ? buildExecutiveSummaryFromPath(primaryAttackPath)
      : buildBreachNarrative(chain),
    businessImpact: {
      summary: primaryAttackPath
        ? buildBusinessImpactFromPath(primaryAttackPath)
        : `Assessment identified ${filtered.customerFindings.length} confirmed findings across ${domains.length} domain(s). ${criticals} critical and ${highs} high severity issues require immediate attention.`,
      domainsCompromised: domains,
      maxPrivilegeAchieved: chain.maxPrivilegeAchieved ?? "none",
      credentialExposure: chain.totalCredentialsHarvested ?? 0,
      assetsCompromised: chain.totalAssetsCompromised ?? 0,
      complianceImplications: deriveComplianceImplications(domains),
    },
    remediationPriorities: buildRemediationPriorities(phases),
    keyMetrics: {
      totalFindings: filtered.audit.totalInput,
      customerFindings: filtered.audit.customerOutput,
      suppressedFindings: filtered.audit.suppressed,
      criticalFindings: criticals,
      highFindings: highs,
      phasesCompleted: phases.filter(p => p.status === "completed").length,
      totalPhases: phases.length,
      chainDurationMs: chain.durationMs ?? 0,
      filterPassRate: filtered.audit.filterPassRate,
    },
    phaseOverview,
    evidenceIntegritySummary: {
      proven: filtered.audit.proven,
      corroborated: filtered.audit.corroborated,
      inferred: filtered.audit.inferred,
      unverifiable: filtered.audit.unverifiable,
      filterPassRate: filtered.audit.filterPassRate,
    },
  };
}
