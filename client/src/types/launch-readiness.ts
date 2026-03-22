/**
 * Launch Readiness Types — frontend mirror of server-side evaluator types.
 */

export type CheckStatus = "PASS" | "RISK" | "FAIL";

export interface LaunchCheck {
  id: string;
  section: string;
  description: string;
  status: CheckStatus;
  evidence?: string;
}

export interface SectionResult {
  section: string;
  status: CheckStatus;
  checks: LaunchCheck[];
}

export interface LaunchReadinessReport {
  sections: SectionResult[];
  summary: { pass: number; risk: number; fail: number };
  finalVerdict: "GO" | "HOLD" | "NO_GO";
}
