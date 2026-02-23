// =============================================================================
// Intelligence Engine — TypeScript Types
// Auto-generated from intelligence/api.py ODINFORGE_TYPES
// Used for type-safe HTTP calls to the Intelligence Engine (port 8001)
// =============================================================================

export interface IntelligenceRequest {
  request_id:      string;
  organization_id: string;
  entity_id?:      string;
  source_product:  "odinforge" | "mimir";
  findings:        FindingInput[];
  breach_chains?:  BreachChainInput[];
  target_domain?:  string;
  mode?:           "full" | "deterministic" | "statistical" | "narrative";
  tone?:           "executive" | "technical" | "deal_memo";
  industry?:       string;
  org_size?:       "smb" | "mid_market" | "enterprise";
}

export interface FindingInput {
  id:             string;
  source_product: string;
  title:          string;
  category:       string;
  severity:       "critical" | "high" | "medium" | "low" | "info";
  cve_id?:        string;
  cvss_score?:    number;
  epss_score?:    number;
  is_kev_listed:  boolean;
  evidence?:      Record<string, unknown>;
}

export interface BreachChainInput {
  chain_id:         string;
  steps:            string[];
  techniques:       string[];
  confirmed:        boolean;
  cvss_max?:        number;
  epss_max?:        number;
  kill_chain_phase?: string;
}

export interface IntelligenceResponse {
  request_id:      string;
  organization_id: string;
  deterministic:   DeterministicOutput;
  statistical?:    StatisticalOutput;
  narrative?:      NarrativeOutput;
  cache_hit:       boolean;
  tier1_ms:        number;
  tier2_ms?:       number;
  tier3_ms?:       number;
  total_ms:        number;
}

export interface DeterministicOutput {
  composite_score:       number;
  risk_grade:            "A" | "B" | "C" | "D" | "F";
  severity_distribution: Record<string, number>;
  kev_count:             number;
  scoring_breakdown:     ScoringBreakdown;
  top_findings:          FindingInput[];
  cve_matches:           string[];
}

export interface ScoringBreakdown {
  epss_component:           number;
  cvss_component:           number;
  exploitability_component: number;
  kev_override:             boolean;
  final_score:              number;
}

export interface StatisticalOutput {
  similar_patterns:     SimilarPattern[];
  anomaly_signals:      AnomalySignal[];
  outcome_predictions:  OutcomePrediction[];
  calibrated_score:     number;
  calibration_delta:    number;
}

export interface NarrativeOutput {
  executive_summary:       string;
  risk_headline:           string;
  key_findings_narrative:  string;
  remediation_steps:       RemediationStep[];
  breach_path_narrative?:  string;
  anomaly_narrative?:      string;
  deal_memo_summary?:      string;
  generated_by:            string;
  grounded_claims:         number;
}

export interface RemediationStep {
  priority:      number;
  action:        string;
  effort:        string;
  impact:        string;
  evidence_ref?: string;
}

export interface SimilarPattern {
  description:      string;
  similarity_pct:   number;
  historical_count: number;
  outcome:          string;
  confirmed:        boolean;
}

export interface AnomalySignal {
  signal:          string;
  deviation_pct:   number;
  baseline_label:  string;
  direction:       "above" | "below";
}

export interface OutcomePrediction {
  outcome_label:        string;
  probability:          number;
  confidence:           number;
  supporting_evidence:  string[];
}
