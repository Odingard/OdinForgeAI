/**
 * Engagement Package — Sealed delivery bundle (ADR-005)
 *
 * The Engagement Package is the atomic deliverable for each OdinForge
 * managed assessment. It contains exactly 5 components:
 *
 *   1. CISO PDF Report     — Risk grade A-F, breach narrative, business impact
 *   2. Engineer PDF Report  — Chain trace, HTTP evidence, remediation diffs
 *   3. Evidence JSON        — Machine-readable findings with sealed evidence
 *   4. Defender's Mirror    — Sigma/YARA/Splunk detection rules per finding
 *   5. Breach Chain Replay  — Self-contained HTML step-by-step visualization
 *
 * Sealing an engagement package:
 *   - Generates all 5 components from the breach chain data
 *   - Computes SHA-256 integrity hashes for each component
 *   - Records seal event with timestamp and operator
 *   - Deactivates per-engagement API keys (ADR-009)
 *   - Returns the complete sealed package
 *
 * Once sealed, the engagement is immutable.
 */

import { createHash, randomUUID } from "crypto";
import type { BreachChain, BreachPhaseResult } from "@shared/schema";
import { generateCISOReport, type CISOReport } from "./ciso-report";
import { generateEngineerReport, type EngineerReport } from "./engineer-report";
import { generateReplayHTML, buildReplayManifest, type ReplayManifest } from "./breach-chain-replay";
import { defendersMirror, type DetectionRuleSet, type AttackEvidence } from "../defenders-mirror";
import { reportIntegrityFilter } from "../report-integrity-filter";
import type { EvaluatedFinding } from "../evidence-quality-gate";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EngagementPackage {
  packageId: string;
  engagementId: string;
  organizationId: string;
  sealedAt: string;
  sealedBy: string;

  components: {
    cisoReport: CISOReport;
    engineerReport: EngineerReport;
    evidenceJSON: EvidenceJSONPayload;
    defendersMirror: DetectionRuleSet[];
    breachChainReplayHTML: string;
  };

  integrity: {
    cisoReportHash: string;
    engineerReportHash: string;
    evidenceJSONHash: string;
    defendersMirrorHash: string;
    replayHTMLHash: string;
    packageHash: string;
  };

  metadata: PackageMetadata;
}

export interface EvidenceJSONPayload {
  engagementId: string;
  generatedAt: string;
  evidenceStandard: string;
  findings: EvidenceJSONFinding[];
  auditSummary: {
    totalInput: number;
    customerOutput: number;
    suppressed: number;
    proven: number;
    corroborated: number;
    inferred: number;
    unverifiable: number;
  };
}

interface EvidenceJSONFinding {
  id: string;
  phase: string;
  severity: string;
  title: string;
  description: string;
  source: string | null;
  evidenceQuality: string;
  technique: string | null;
  mitreId: string | null;
  statusCode: number | null;
  responseBodyPreview: string | null;
  curlCommand: string | null;
}

interface PackageMetadata {
  targetAssets: string[];
  executionMode: string;
  phasesExecuted: number;
  totalPhases: number;
  riskGrade: string;
  overallRiskScore: number;
  totalFindings: number;
  customerFindings: number;
  durationMs: number;
  reengagementEligible: boolean;
  reengagementWindowDays: number;
  // Phase 14: Path-driven metadata
  primaryAttackPath?: PackageAttackPath | null;
  supportingAttackPaths?: PackageAttackPath[];
  remediationPlan?: RemediationPlan | null;
  portfolioSummary?: any | null;
  engagementContext?: {
    authenticated: boolean;
    highestRoleReached: 'anonymous' | 'user' | 'admin';
    scopeEnforced: boolean;
    safeModeEnabled: boolean;
  } | null;
}

/** Attack path as it appears in the sealed package */
export interface PackageAttackPath {
  id: string;
  name: string;
  confidence: string;
  score: number;
  narrative: string;
  finalImpact: string;
  businessImpact: string;
  steps: Array<{
    order: number;
    action: string;
    technique: string;
    mitreId: string;
    evidence?: string;
    artifactsUsed?: string[];
    artifactsGained?: string[];
  }>;
  artifacts: string[];
}

/** Remediation plan tied to the primary attack path */
export interface RemediationPlan {
  immediate: string[];      // block entry point
  pivotDisruption: string[];  // fix GraphQL/auth misuse
  artifactProtection: string[]; // secure tokens/sessions
  privilegeBoundary: string[];  // enforce access controls
  monitoring: string[];     // detection recommendations
}

export interface SealEvent {
  packageId: string;
  engagementId: string;
  sealedAt: string;
  sealedBy: string;
  componentHashes: EngagementPackage["integrity"];
}

// ─── Evidence JSON Builder ───────────────────────────────────────────────────

function buildEvidenceJSON(chain: BreachChain): EvidenceJSONPayload {
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const allFindings = phases.flatMap(p =>
    (p.findings ?? []).map(f => ({ ...f, _phase: p.phaseName }))
  );

  const evaluated: EvaluatedFinding[] = allFindings.map(f => ({
    ...f,
    id: f.id ?? "unknown",
    severity: f.severity ?? "medium",
    title: f.title ?? "Untitled",
    description: f.description ?? "",
  }));
  const filtered = reportIntegrityFilter.filter(evaluated);

  const findings: EvidenceJSONFinding[] = filtered.customerFindings.map(f => ({
    id: f.id,
    phase: (f as any)._phase ?? "unknown",
    severity: f.severity,
    title: f.title,
    description: f.description,
    source: (f as any).source ?? null,
    evidenceQuality: (f as any).evidenceQuality ?? "unknown",
    technique: (f as any).technique ?? null,
    mitreId: (f as any).mitreId ?? null,
    statusCode: (f as any).statusCode ?? null,
    responseBodyPreview: ((f as any).responseBody ?? "").slice(0, 500) || null,
    curlCommand: (f as any).curlCommand ?? null,
  }));

  return {
    engagementId: chain.id,
    generatedAt: new Date().toISOString(),
    evidenceStandard: "ADR-001: Sealed EvidenceContract — PROVEN and CORROBORATED only",
    findings,
    auditSummary: {
      totalInput: filtered.audit.totalInput,
      customerOutput: filtered.audit.customerOutput,
      suppressed: filtered.audit.suppressed,
      proven: filtered.audit.proven,
      corroborated: filtered.audit.corroborated,
      inferred: filtered.audit.inferred,
      unverifiable: filtered.audit.unverifiable,
    },
  };
}

// ─── Defender's Mirror Builder ───────────────────────────────────────────────

function buildDefendersMirror(chain: BreachChain): DetectionRuleSet[] {
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const rules: DetectionRuleSet[] = [];

  for (const phase of phases) {
    for (const finding of phase.findings ?? []) {
      // Only generate detection rules for proven/corroborated findings
      if (finding.evidenceQuality === "inferred" || finding.evidenceQuality === "unverifiable") continue;

      const evidence: AttackEvidence = {
        id: finding.id ?? `ev-${randomUUID().slice(0, 8)}`,
        engagementId: chain.id,
        phase: phase.phaseName,
        techniqueCategory: finding.technique ?? "unknown",
        statusCode: finding.statusCode,
        success: true,
      };

      try {
        const ruleSet = defendersMirror.generateFromEvidence(evidence);
        rules.push(ruleSet);
      } catch {
        // Unknown technique category — no detection rule template available
      }
    }
  }

  return rules;
}

// ─── Attack Path Extraction (Phase 14) ───────────────────────────────────────

function extractAttackPaths(chain: BreachChain): { primary: PackageAttackPath | null; supporting: PackageAttackPath[] } {
  // Build paths from phase-result findings — works with or without unifiedAttackGraph
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const allFindings = phases.flatMap(p => (p.findings ?? []).map(f => ({ ...f, _phase: p.phaseName })));

  // Early return only when there are genuinely no findings to work with
  if (allFindings.length === 0) return { primary: null, supporting: [] };

  // Build paths from findings — group by severity and chain potential
  const criticalFindings = allFindings.filter(f => f.severity === 'critical');
  const highFindings = allFindings.filter(f => f.severity === 'high');

  // Primary path: strongest finding chain
  const primaryFindings = criticalFindings.length > 0 ? criticalFindings : highFindings;
  if (primaryFindings.length === 0) return { primary: null, supporting: [] };

  const primaryPath: PackageAttackPath = {
    id: `path-primary-${chain.id.slice(0, 8)}`,
    name: `${primaryFindings[0].technique || primaryFindings[0].title || 'Exploitation'} → ${primaryFindings.length > 1 ? 'Chain' : 'Direct'}`,
    confidence: primaryFindings.length >= 3 ? 'strong' : primaryFindings.length >= 2 ? 'moderate' : 'low',
    score: Math.min(100, primaryFindings.length * 20 + (criticalFindings.length * 15)),
    narrative: buildPathNarrative(chain, primaryFindings),
    finalImpact: assessPathImpact(primaryFindings),
    businessImpact: translatePathBusinessImpact(primaryFindings),
    steps: primaryFindings.map((f, i) => ({
      order: i + 1,
      action: f.title || f.description?.slice(0, 80) || 'Exploit',
      technique: f.technique || f.source || 'unknown',
      mitreId: (f as any).mitreId || 'T1190',
      evidence: (f as any).responseBody?.slice(0, 200) || undefined,
      artifactsGained: (f as any).evidenceQuality === 'proven' ? ['validated_exploit'] : undefined,
    })),
    artifacts: primaryFindings
      .filter(f => (f as any).evidenceQuality === 'proven')
      .map(f => f.title || 'finding'),
  };

  // Supporting paths from remaining findings
  const remainingFindings = allFindings.filter(f => !primaryFindings.includes(f));
  const supporting: PackageAttackPath[] = [];
  if (remainingFindings.length > 0) {
    supporting.push({
      id: `path-supporting-${chain.id.slice(0, 8)}`,
      name: `Supporting findings (${remainingFindings.length})`,
      confidence: 'low',
      score: Math.min(50, remainingFindings.length * 10),
      narrative: `${remainingFindings.length} additional findings across ${new Set(remainingFindings.map(f => (f as any)._phase)).size} phases.`,
      finalImpact: 'Additional validated vulnerabilities',
      businessImpact: 'Secondary exposure requiring remediation',
      steps: remainingFindings.slice(0, 5).map((f, i) => ({
        order: i + 1,
        action: f.title || f.description?.slice(0, 80) || 'Finding',
        technique: f.technique || 'unknown',
        mitreId: (f as any).mitreId || 'T1190',
      })),
      artifacts: [],
    });
  }

  return { primary: primaryPath, supporting };
}

function buildPathNarrative(chain: BreachChain, findings: any[]): string {
  const target = (chain.assetIds as string[])?.[0] || 'target';
  const firstFinding = findings[0];
  const lastFinding = findings[findings.length - 1];
  const vulnTypes = Array.from(new Set(findings.map((f: any) => f.technique || f.source || 'exploit')));

  return `An attacker targeting ${target} can exploit ${firstFinding.title || vulnTypes[0]}` +
    (findings.length > 1 ? `, progressing through ${findings.length} validated steps` : '') +
    `. This results in ${assessPathImpact(findings).toLowerCase()}.`;
}

function assessPathImpact(findings: any[]): string {
  if (findings.some((f: any) => f.technique?.includes('admin') || f.title?.includes('admin'))) {
    return 'Unauthorized administrative access';
  }
  if (findings.some((f: any) => f.technique?.includes('credential') || f.title?.includes('Credential'))) {
    return 'Credential exposure enabling further access';
  }
  if (findings.some((f: any) => f.severity === 'critical')) {
    return 'Critical vulnerability validated with proven evidence';
  }
  return 'Validated security findings with confirmed impact';
}

function translatePathBusinessImpact(findings: any[]): string {
  const hasCritical = findings.some((f: any) => f.severity === 'critical');
  const hasAuth = findings.some((f: any) => /auth|jwt|token|session/i.test(f.technique || f.title || ''));
  const hasConfig = findings.some((f: any) => /config|env|secret/i.test(f.technique || f.title || ''));

  if (hasAuth && hasCritical) return 'Authentication bypass confirmed — unauthorized access to protected resources and user data.';
  if (hasConfig) return 'Configuration exposure — application secrets and credentials accessible to attackers.';
  if (hasCritical) return 'Critical exploitable vulnerability — direct path to application compromise.';
  return 'Validated security weaknesses requiring remediation to prevent exploitation.';
}

// ─── Path-Based Remediation (Phase 14) ──────────────────────────────────────

function generatePathRemediation(primaryPath: PackageAttackPath | null, _findings: any[]): RemediationPlan {
  if (!primaryPath) {
    return {
      immediate: ['Review all findings and prioritize by severity'],
      pivotDisruption: [],
      artifactProtection: [],
      privilegeBoundary: ['Enforce role-based access control across all sensitive functionality'],
      monitoring: ['Enable security monitoring on high-risk endpoints'],
    };
  }

  const steps = primaryPath.steps || [];
  const entryStep = steps[0];
  const rawTech = entryStep?.technique || entryStep?.action || 'entry vulnerability';
  const entryVuln = rawTech.includes(' → ') ? rawTech.split(' → ').slice(1).join(' → ') : rawTech;
  const entryPoint = rawTech.includes(' → ') ? rawTech.split(' → ')[0] : (primaryPath.name?.split(' → ')[0] || 'affected endpoint');
  const attackPatterns = Array.from(new Set(steps.map(s => s.technique).filter(Boolean))).join(', ');

  // Immediate: remediate entry point
  const immediate: string[] = [
    `Remediate ${entryVuln} on ${entryPoint}`,
    'Apply strict input validation and secure handling for all affected components',
    'Disable or restrict exposed functionality enabling initial access',
  ];

  // Pivot disruption: break chain at weakest link
  const pivotDisruption: string[] = [];
  for (const step of steps) {
    if (step.order > 1) {
      pivotDisruption.push(`Break chain progression at step ${step.order} by addressing ${step.technique}`);
    }
  }
  pivotDisruption.push('Enforce strict authorization checks on all intermediate operations');
  pivotDisruption.push('Remove or isolate functionality that enables chained exploitation');

  // Artifact protection
  const artifactProtection = [
    'Rotate all potentially exposed credentials, tokens, and session artifacts',
    'Enforce short-lived tokens and automatic rotation',
    'Implement secure session handling (HttpOnly, SameSite, invalidation on privilege change)',
  ];

  // Privilege boundary
  const privilegeBoundary = [
    'Restrict access to privileged operations and administrative endpoints',
    'Enforce role-based access control across all sensitive functionality',
    'Ensure separation between public, authenticated, and privileged zones',
  ];

  // Monitoring
  const monitoring = [
    `Deploy detection for attack patterns observed in this path: ${attackPatterns}`,
    'Alert on replay behavior, token misuse, and abnormal authentication activity',
    `Monitor high-risk endpoints such as ${entryPoint} and related surfaces`,
  ];

  return {
    immediate: Array.from(new Set(immediate)),
    pivotDisruption: Array.from(new Set(pivotDisruption)),
    artifactProtection: Array.from(new Set(artifactProtection)),
    privilegeBoundary: Array.from(new Set(privilegeBoundary)),
    monitoring: Array.from(new Set(monitoring)),
  };
}

// ─── Hash Utility ────────────────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function sealEngagementPackage(
  chain: BreachChain,
  sealedBy: string
): Promise<EngagementPackage> {
  const packageId = `pkg-${randomUUID().slice(0, 12)}`;

  // Phase 14: Extract attack paths and generate remediation
  const { primary: primaryAttackPath, supporting: supportingAttackPaths } = extractAttackPaths(chain);
  const pathPhases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const pathFindings = pathPhases.flatMap(p => (p.findings ?? []).map(f => ({ ...f, _phase: p.phaseName })));
  const remediationPlan = generatePathRemediation(primaryAttackPath, pathFindings);

  // Generate all 5 components (now path-aware)
  const cisoReport = await generateCISOReport(chain, primaryAttackPath);
  const engineerReport = await generateEngineerReport(chain, primaryAttackPath, supportingAttackPaths, remediationPlan);
  const evidenceJSON = buildEvidenceJSON(chain);
  const mirrorRules = buildDefendersMirror(chain);
  const replayHTML = generateReplayHTML(chain);

  // Compute integrity hashes
  const cisoReportHash = sha256(JSON.stringify(cisoReport));
  const engineerReportHash = sha256(JSON.stringify(engineerReport));
  const evidenceJSONHash = sha256(JSON.stringify(evidenceJSON));
  const defendersMirrorHash = sha256(JSON.stringify(mirrorRules));
  const replayHTMLHash = sha256(replayHTML);
  const packageHash = sha256(
    cisoReportHash + engineerReportHash + evidenceJSONHash + defendersMirrorHash + replayHTMLHash
  );

  const config = chain.config as any;
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];

  return {
    packageId,
    engagementId: chain.id,
    organizationId: chain.organizationId,
    sealedAt: new Date().toISOString(),
    sealedBy,

    components: {
      cisoReport,
      engineerReport,
      evidenceJSON,
      defendersMirror: mirrorRules,
      breachChainReplayHTML: replayHTML,
    },

    integrity: {
      cisoReportHash,
      engineerReportHash,
      evidenceJSONHash,
      defendersMirrorHash,
      replayHTMLHash,
      packageHash,
    },

    metadata: {
      targetAssets: chain.assetIds as string[],
      executionMode: config?.executionMode ?? "live",
      phasesExecuted: phases.filter(p => p.status === "completed").length,
      totalPhases: phases.length,
      riskGrade: cisoReport.riskGrade,
      overallRiskScore: chain.overallRiskScore ?? 0,
      totalFindings: evidenceJSON.auditSummary.totalInput,
      customerFindings: evidenceJSON.auditSummary.customerOutput,
      durationMs: chain.durationMs ?? 0,
      reengagementEligible: true,
      reengagementWindowDays: 90,
      primaryAttackPath,
      supportingAttackPaths,
      remediationPlan,
      portfolioSummary: null, // populated by route handler for multi-target
    },
  };
}

export function createSealEvent(pkg: EngagementPackage): SealEvent {
  return {
    packageId: pkg.packageId,
    engagementId: pkg.engagementId,
    sealedAt: pkg.sealedAt,
    sealedBy: pkg.sealedBy,
    componentHashes: pkg.integrity,
  };
}
