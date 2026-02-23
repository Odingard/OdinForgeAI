# =============================================================================
# Intelligence Engine — Schemas
# intelligence/schemas.py
#
# Pydantic contracts for every input and output in the Intelligence Engine.
# The LLM layer validates its output against these schemas before returning.
# If the LLM output does not parse, the fallback template runs instead.
# =============================================================================

from __future__ import annotations

from enum import Enum
from typing import Optional, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator


# =============================================================================
# ENUMS
# =============================================================================

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class RiskGrade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class OutputMode(str, Enum):
    FULL          = "full"          # all three tiers
    DETERMINISTIC = "deterministic" # tier 1 only — fastest, no ML or LLM
    STATISTICAL   = "statistical"   # tier 1 + 2 — no LLM
    NARRATIVE     = "narrative"     # all three tiers, narrative is priority


class NarrativeTone(str, Enum):
    EXECUTIVE  = "executive"   # board-level, non-technical
    TECHNICAL  = "technical"   # security engineer level
    DEAL_MEMO  = "deal_memo"   # M&A / PE firm language


# =============================================================================
# FINDING INPUT — unified finding from OdinForge or Mimir
# =============================================================================

class FindingInput(BaseModel):
    id:             str
    source_product: str                     # "odinforge" | "mimir"
    title:          str
    category:       str
    severity:       SeverityLevel
    cve_id:         Optional[str]  = None
    cvss_score:     Optional[float] = None
    epss_score:     Optional[float] = None
    is_kev_listed:  bool           = False
    evidence:       dict[str, Any] = Field(default_factory=dict)
    description:    Optional[str]  = None

    @field_validator("epss_score")
    @classmethod
    def epss_range(cls, v):
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError("EPSS score must be between 0 and 1")
        return v


class BreachChainInput(BaseModel):
    """Structured attack path from OdinForge breach chain orchestrator."""
    chain_id:        str
    steps:           list[str]          # ordered attack steps
    techniques:      list[str]          # MITRE ATT&CK technique IDs
    confirmed:       bool               # agent-confirmed exploitability
    cvss_max:        Optional[float] = None
    epss_max:        Optional[float] = None
    kill_chain_phase: Optional[str] = None


class SimilarPatternInput(BaseModel):
    """Result from Tier 2 pgvector similarity search."""
    pattern_id:      str
    similarity:      float              # cosine similarity 0-1
    outcome:         str                # "full_compromise" | "data_exfil" | etc.
    historical_count: int               # how many times seen
    confirmed_exploitable: bool


# =============================================================================
# INTELLIGENCE REQUEST — what callers send to the engine
# =============================================================================

class IntelligenceRequest(BaseModel):
    # Identity
    request_id:      str               # caller-generated, used for caching
    organization_id: str
    entity_id:       Optional[str] = None
    source_product:  str               # "odinforge" | "mimir"

    # What to analyze
    findings:        list[FindingInput] = Field(default_factory=list)
    breach_chains:   list[BreachChainInput] = Field(default_factory=list)
    target_domain:   Optional[str] = None
    target_metadata: dict[str, Any] = Field(default_factory=dict)

    # Output control
    mode:            OutputMode    = OutputMode.FULL
    tone:            NarrativeTone = NarrativeTone.TECHNICAL
    max_findings:    int           = 20     # cap findings passed to LLM

    # Context for calibration
    industry:        Optional[str] = None
    org_size:        Optional[str] = None  # "smb" | "mid_market" | "enterprise"

    @field_validator("findings")
    @classmethod
    def cap_findings(cls, v, info):
        max_f = info.data.get("max_findings", 20)
        return v[:max_f]


# =============================================================================
# TIER 1 OUTPUT — deterministic, always present
# =============================================================================

class ScoringBreakdown(BaseModel):
    epss_component:         float   # 0-100
    cvss_component:         float   # 0-100
    exploitability_component: float # 0-100
    kev_override:           bool
    final_score:            float   # 0-100


class DeterministicOutput(BaseModel):
    composite_score:        float               # 0-100
    risk_grade:             RiskGrade
    severity_distribution:  dict[str, int]      # {critical: 2, high: 5, ...}
    kev_count:              int
    scoring_breakdown:      ScoringBreakdown
    top_findings:           list[FindingInput]  # sorted by score descending
    cve_matches:            list[str]           # known CVE IDs matched
    computed_at:            datetime


# =============================================================================
# TIER 2 OUTPUT — statistical, present when mode != DETERMINISTIC
# =============================================================================

class SimilarPattern(BaseModel):
    description:     str
    similarity_pct:  float           # 0-100
    historical_count: int
    outcome:         str
    confirmed:       bool


class AnomalySignal(BaseModel):
    signal:          str
    deviation_pct:   float           # how far from baseline
    baseline_label:  str             # "industry average" | "org historical"
    direction:       str             # "above" | "below"


class OutcomePrediction(BaseModel):
    outcome_label:   str             # "full_compromise" | "data_exfil" | etc.
    probability:     float           # 0.0-1.0 — from ML model, not LLM
    confidence:      float           # 0.0-1.0 — model confidence
    supporting_evidence: list[str]   # specific findings that drive this
    model_version:   str


class StatisticalOutput(BaseModel):
    similar_patterns:       list[SimilarPattern]
    anomaly_signals:        list[AnomalySignal]
    outcome_predictions:    list[OutcomePrediction]
    calibrated_score:       float           # Tier 1 score adjusted by ML
    calibration_delta:      float           # how much ML moved the score
    embedding_version:      str
    model_versions:         dict[str, str]  # {model_name: version}
    computed_at:            datetime


# =============================================================================
# TIER 3 OUTPUT — LLM narrative, optional
# =============================================================================

class RemediationStep(BaseModel):
    priority:        int             # 1 = highest
    action:          str             # what to do
    effort:          str             # "hours" | "days" | "weeks"
    impact:          str             # what risk it removes
    evidence_ref:    Optional[str]   # maps to a specific finding id


class NarrativeOutput(BaseModel):
    # Every field maps to a Tier 1 or Tier 2 source — no invented claims
    executive_summary:      str     # 2-4 sentences, board-level
    risk_headline:          str     # one sentence, the most important thing
    key_findings_narrative: str     # prose summary of top findings
    remediation_steps:      list[RemediationStep]
    breach_path_narrative:  Optional[str] = None   # only if breach chains present
    anomaly_narrative:      Optional[str] = None   # only if anomalies present
    deal_memo_summary:      Optional[str] = None   # only if tone = deal_memo
    generated_by:           str     # "claude-3-5-sonnet" | "template"
    grounded_claims:        int     # count of claims traced to tier 1/2 facts
    generated_at:           datetime


# =============================================================================
# FULL INTELLIGENCE RESPONSE
# =============================================================================

class IntelligenceResponse(BaseModel):
    request_id:      str
    organization_id: str
    entity_id:       Optional[str]

    # Tier outputs — only present if that tier ran
    deterministic:   DeterministicOutput
    statistical:     Optional[StatisticalOutput] = None
    narrative:       Optional[NarrativeOutput]   = None

    # Cache metadata
    cache_hit:       bool = False
    cache_key:       Optional[str] = None

    # Timing
    tier1_ms:        int
    tier2_ms:        Optional[int] = None
    tier3_ms:        Optional[int] = None
    total_ms:        int

    # The final score to use — calibrated if statistical ran, deterministic otherwise
    @property
    def final_score(self) -> float:
        if self.statistical:
            return self.statistical.calibrated_score
        return self.deterministic.composite_score

    @property
    def final_grade(self) -> RiskGrade:
        return self.deterministic.risk_grade


# =============================================================================
# ERROR RESPONSE
# =============================================================================

class IntelligenceError(BaseModel):
    request_id:  str
    error_code:  str
    message:     str
    tier:        str    # which tier failed
    fallback_used: bool = False
