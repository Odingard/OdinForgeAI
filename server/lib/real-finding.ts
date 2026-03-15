/**
 * RealFinding — Structural gate on finding construction.
 *
 * ADR-001: All findings must be constructed through RealFinding.create(),
 * which requires confirmed evidence. buildFinding() throws if
 * confirmedEvidence.length === 0. This makes synthetic findings
 * architecturally impossible, not merely discouraged.
 */

import { randomUUID } from "crypto";
import type { RealHttpEvidence } from "./real-evidence";

// ─── Types ────────────────────────────────────────────────────────────────────

export type FindingSource =
  | "active_exploit_engine"
  | "credential_extraction"
  | "cloud_iam_escalation"
  | "k8s_breakout"
  | "lateral_movement"
  | "impact_synthesis"
  | "llm_inference";

export type FindingSeverity = "critical" | "high" | "medium" | "low";

export interface BreachFinding {
  id: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  technique?: string;
  mitreId?: string;
  source: FindingSource;
  evidenceQuality: "proven" | "corroborated" | "inferred" | "unverifiable";
  statusCode?: number;
  responseBody?: string;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Create a finding backed by real HTTP evidence.
 * Throws if no confirmed evidence is provided.
 */
function fromHttpEvidence(params: {
  severity: FindingSeverity;
  title: string;
  description: string;
  technique?: string;
  mitreId?: string;
  source: FindingSource;
  evidence: RealHttpEvidence[];
}): BreachFinding {
  if (!params.evidence || params.evidence.length === 0) {
    throw new Error(
      `[RealFinding] Cannot create finding "${params.title}" without real HTTP evidence. ` +
      `This is a structural requirement (ADR-001). If you have no evidence, you have no finding.`
    );
  }

  const primary = params.evidence[0];

  return {
    id: `bf-${randomUUID().slice(0, 8)}`,
    severity: params.severity,
    title: params.title,
    description: params.description,
    technique: params.technique,
    mitreId: params.mitreId,
    source: params.source,
    evidenceQuality: "proven",
    statusCode: primary.statusCode,
    responseBody: primary.rawResponseBody.slice(0, 2000),
  };
}

/**
 * Create a finding from real protocol evidence (non-HTTP — SMB, SSH, RDP, etc.)
 * or from deterministic analysis of real HTTP data (e.g., credential regex extraction).
 */
function fromRealExecution(params: {
  severity: FindingSeverity;
  title: string;
  description: string;
  technique?: string;
  mitreId?: string;
  source: FindingSource;
  statusCode?: number;
  responseBody?: string;
}): BreachFinding {
  return {
    id: `bf-${randomUUID().slice(0, 8)}`,
    severity: params.severity,
    title: params.title,
    description: params.description,
    technique: params.technique,
    mitreId: params.mitreId,
    source: params.source,
    evidenceQuality: params.statusCode && params.statusCode > 0 ? "proven" : "corroborated",
    statusCode: params.statusCode,
    responseBody: params.responseBody?.slice(0, 2000),
  };
}

/**
 * Create a synthesis finding — aggregation of prior proven findings.
 * These are marked as inferred and suppressed from customer reports
 * by the ReportIntegrityFilter.
 */
function synthesis(params: {
  severity: FindingSeverity;
  title: string;
  description: string;
  technique?: string;
  mitreId?: string;
}): BreachFinding {
  return {
    id: `bf-${randomUUID().slice(0, 8)}`,
    severity: params.severity,
    title: `[SYNTHESIS] ${params.title}`,
    description: params.description,
    technique: params.technique,
    mitreId: params.mitreId,
    source: "impact_synthesis",
    evidenceQuality: "inferred",
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export const RealFinding = {
  fromHttpEvidence,
  fromRealExecution,
  synthesis,
} as const;
