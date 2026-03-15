/**
 * ReportIntegrityFilter — Pre-report audit pass.
 *
 * ADR-001: Every finding in a customer report must have a sealed EvidenceContract.
 * INFERRED and UNVERIFIABLE findings are suppressed from customer output entirely —
 * they are logged internally for engineering review only.
 *
 * This filter runs AFTER the EvidenceQualityGate classification and BEFORE
 * any report rendering (CISO PDF, Engineer PDF, Evidence JSON, SARIF).
 */

import { evidenceQualityGate, EvidenceQuality, type EvaluatedFinding, type QualityVerdict } from "./evidence-quality-gate";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface FilteredReport {
  /** Findings that passed the integrity filter — safe for customer delivery */
  customerFindings: EvaluatedFinding[];
  /** Findings suppressed from customer output — internal engineering review only */
  suppressedFindings: Array<{
    finding: EvaluatedFinding;
    reason: string;
    quality: EvidenceQuality;
  }>;
  /** Audit summary */
  audit: {
    totalInput: number;
    customerOutput: number;
    suppressed: number;
    proven: number;
    corroborated: number;
    inferred: number;
    unverifiable: number;
    filterPassRate: number;
  };
}

// ─── Filter Implementation ────────────────────────────────────────────────────

export class ReportIntegrityFilter {

  /**
   * Filter findings for customer-facing reports.
   * Only PROVEN and CORROBORATED findings pass.
   * INFERRED and UNVERIFIABLE are suppressed with audit trail.
   */
  filter(findings: EvaluatedFinding[]): FilteredReport {
    const customerFindings: EvaluatedFinding[] = [];
    const suppressedFindings: FilteredReport["suppressedFindings"] = [];

    let proven = 0;
    let corroborated = 0;
    let inferred = 0;
    let unverifiable = 0;

    for (const finding of findings) {
      const verdict = evidenceQualityGate.evaluate(finding);

      switch (verdict.quality) {
        case EvidenceQuality.PROVEN:
          proven++;
          customerFindings.push(finding);
          break;
        case EvidenceQuality.CORROBORATED:
          corroborated++;
          customerFindings.push(finding);
          break;
        case EvidenceQuality.INFERRED:
          inferred++;
          suppressedFindings.push({
            finding,
            reason: verdict.reason,
            quality: verdict.quality,
          });
          console.warn(
            `[ReportIntegrityFilter] SUPPRESSED from customer report: "${finding.title}" — ${verdict.reason}`
          );
          break;
        case EvidenceQuality.UNVERIFIABLE:
          unverifiable++;
          suppressedFindings.push({
            finding,
            reason: verdict.reason,
            quality: verdict.quality,
          });
          console.warn(
            `[ReportIntegrityFilter] SUPPRESSED from customer report: "${finding.title}" — ${verdict.reason}`
          );
          break;
      }
    }

    const totalInput = findings.length;

    return {
      customerFindings,
      suppressedFindings,
      audit: {
        totalInput,
        customerOutput: customerFindings.length,
        suppressed: suppressedFindings.length,
        proven,
        corroborated,
        inferred,
        unverifiable,
        filterPassRate: totalInput > 0
          ? Math.round((customerFindings.length / totalInput) * 100)
          : 0,
      },
    };
  }

  /**
   * Quick check: does this single finding pass the integrity filter?
   */
  passes(finding: EvaluatedFinding): boolean {
    const verdict = evidenceQualityGate.evaluate(finding);
    return verdict.quality === EvidenceQuality.PROVEN ||
           verdict.quality === EvidenceQuality.CORROBORATED;
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const reportIntegrityFilter = new ReportIntegrityFilter();
