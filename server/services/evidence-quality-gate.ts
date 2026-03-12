/**
 * Evidence Quality Gate
 *
 * Every finding produced by OdinForge must pass an evidence quality gate
 * before appearing in the customer report. Findings that fail the gate
 * are not silently dropped — they are classified and visually separated.
 *
 * Classification levels:
 *   PROVEN        — real execution + real response confirms finding
 *   CORROBORATED  — real attempt; target confirmed; access failed
 *   INFERRED      — LLM reasoning only; no real execution
 *   UNVERIFIABLE  — attempted; result ambiguous
 */

import { randomUUID } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export enum EvidenceQuality {
  PROVEN        = "proven",
  CORROBORATED  = "corroborated",
  INFERRED      = "inferred",
  UNVERIFIABLE  = "unverifiable",
}

export interface EvaluatedFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  technique?: string;
  mitreId?: string;
  // Extended evidence fields
  evidenceType?: string;
  success?: boolean;
  error?: any;
  source?: string;
  statusCode?: number;
  responseBody?: string;
  authResult?: string;
  accessLevel?: string;
}

export interface QualityVerdict {
  quality: EvidenceQuality;
  passed: boolean;
  reason: string;
  requiresManualReview: boolean;
  finding: EvaluatedFinding;
}

export interface BatchVerdict {
  passed: QualityVerdict[];
  failed: QualityVerdict[];
  summary: {
    proven: number;
    corroborated: number;
    inferred: number;
    unverifiable: number;
    total: number;
    passRate: number;
  };
}

// ─── Real protocol auth evidence types ────────────────────────────────────────

const REAL_AUTH_EVIDENCE_TYPES = new Set([
  "real_smb_auth",
  "real_winrm_exec",
  "real_rdp_nla_handshake",
  "real_ssh_exec",
  "real_ssh_auth",
  "real_smb_auth_failure",
  "real_winrm_auth_failure",
  "real_rdp_nla_failure",
]);

// ─── Gate Implementation ──────────────────────────────────────────────────────

export class EvidenceQualityGate {

  /**
   * Classify a single finding through the evidence quality chain.
   */
  evaluate(finding: EvaluatedFinding): QualityVerdict {
    // 0. Pre-validation: warn on missing source field per LLM Boundary Amendment.
    //    Findings with real HTTP evidence (statusCode + responseBody) or real protocol
    //    evidence can still be classified as PROVEN/CORROBORATED. But findings that
    //    reach the INFERRED/UNVERIFIABLE tier without a source get UNVERIFIABLE.
    if (!finding.source) {
      const hasRealEvidence = this.hasRealHttpEvidence(finding) ||
        this.hasRealProtocolAuthSuccess(finding) ||
        this.isRealAttemptWithFailure(finding);
      if (!hasRealEvidence) {
        console.error(
          `[QualityGate] Finding '${finding.title}' has no source field and no real evidence. ` +
          `Classifying as UNVERIFIABLE. Set source='active_exploit_engine' or ` +
          `'real_http_response' from real execution.`
        );
        return {
          quality: EvidenceQuality.UNVERIFIABLE,
          passed: false,
          reason: "Missing source field — cannot determine evidence origin",
          requiresManualReview: true,
          finding,
        };
      }
    }

    // 1. Real HTTP response with status code and body → PROVEN
    if (this.hasRealHttpEvidence(finding)) {
      return {
        quality: EvidenceQuality.PROVEN,
        passed: true,
        reason: "Real HTTP evidence with response body and status code",
        requiresManualReview: false,
        finding,
      };
    }

    // 2. Real protocol auth success → PROVEN
    if (this.hasRealProtocolAuthSuccess(finding)) {
      return {
        quality: EvidenceQuality.PROVEN,
        passed: true,
        reason: `Real protocol authentication confirmed (${finding.evidenceType})`,
        requiresManualReview: false,
        finding,
      };
    }

    // 3. Real attempt with failure + error data → CORROBORATED
    if (this.isRealAttemptWithFailure(finding)) {
      return {
        quality: EvidenceQuality.CORROBORATED,
        passed: true,
        reason: "Real attempt; target confirmed; authentication or access failed",
        requiresManualReview: false,
        finding,
      };
    }

    // 4. Active exploit engine output with evidence → CORROBORATED
    if (this.isActiveExploitEvidence(finding)) {
      return {
        quality: EvidenceQuality.CORROBORATED,
        passed: true,
        reason: "Active exploit engine produced evidence from real HTTP interaction",
        requiresManualReview: false,
        finding,
      };
    }

    // 5. LLM inference → INFERRED
    if (this.isLlmInference(finding)) {
      return {
        quality: EvidenceQuality.INFERRED,
        passed: false,
        reason: "LLM inference; no real execution evidence",
        requiresManualReview: true,
        finding,
      };
    }

    // 6. Fallback → UNVERIFIABLE
    return {
      quality: EvidenceQuality.UNVERIFIABLE,
      passed: false,
      reason: "Evidence insufficient for classification",
      requiresManualReview: true,
      finding,
    };
  }

  /**
   * Classify a batch of findings. Returns passed/failed split and summary counts.
   */
  evaluateBatch(findings: EvaluatedFinding[]): BatchVerdict {
    const verdicts = findings.map(f => this.evaluate(f));

    const passed = verdicts.filter(v => v.passed);
    const failed = verdicts.filter(v => !v.passed);

    const proven = verdicts.filter(v => v.quality === EvidenceQuality.PROVEN).length;
    const corroborated = verdicts.filter(v => v.quality === EvidenceQuality.CORROBORATED).length;
    const inferred = verdicts.filter(v => v.quality === EvidenceQuality.INFERRED).length;
    const unverifiable = verdicts.filter(v => v.quality === EvidenceQuality.UNVERIFIABLE).length;
    const total = verdicts.length;

    return {
      passed,
      failed,
      summary: {
        proven,
        corroborated,
        inferred,
        unverifiable,
        total,
        passRate: total > 0 ? Math.round((passed.length / total) * 100) : 0,
      },
    };
  }

  // ── Private classification helpers ──────────────────────────────────────────

  private hasRealHttpEvidence(finding: EvaluatedFinding): boolean {
    return (
      finding.evidenceType === "real_http_response" &&
      typeof finding.statusCode === "number" &&
      finding.statusCode > 0
    ) || (
      typeof finding.statusCode === "number" &&
      finding.statusCode > 0 &&
      typeof finding.responseBody === "string" &&
      finding.responseBody.length > 0
    );
  }

  private hasRealProtocolAuthSuccess(finding: EvaluatedFinding): boolean {
    if (!finding.evidenceType) return false;
    return (
      REAL_AUTH_EVIDENCE_TYPES.has(finding.evidenceType) &&
      finding.success === true
    );
  }

  private isRealAttemptWithFailure(finding: EvaluatedFinding): boolean {
    if (!finding.evidenceType) return false;
    return (
      (finding.evidenceType.startsWith("real_") || REAL_AUTH_EVIDENCE_TYPES.has(finding.evidenceType)) &&
      finding.success === false &&
      finding.error != null
    );
  }

  private isActiveExploitEvidence(finding: EvaluatedFinding): boolean {
    return (
      finding.source === "active_exploit_engine" ||
      finding.source === "credential_extraction" ||
      finding.source === "application_compromise"
    );
  }

  private isLlmInference(finding: EvaluatedFinding): boolean {
    return (
      (typeof finding.source === "string" && finding.source.startsWith("llm_inference")) ||
      (typeof finding.source === "string" && finding.source.startsWith("heuristic")) ||
      (typeof finding.title === "string" && finding.title.includes("[LLM Inferred]"))
    );
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const evidenceQualityGate = new EvidenceQualityGate();
