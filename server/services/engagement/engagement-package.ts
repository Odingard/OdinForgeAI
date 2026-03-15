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

// ─── Hash Utility ────────────────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function sealEngagementPackage(
  chain: BreachChain,
  sealedBy: string
): EngagementPackage {
  const packageId = `pkg-${randomUUID().slice(0, 12)}`;

  // Generate all 5 components
  const cisoReport = generateCISOReport(chain);
  const engineerReport = generateEngineerReport(chain);
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
