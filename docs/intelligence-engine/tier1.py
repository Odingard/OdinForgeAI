# =============================================================================
# Intelligence Engine — Tier 1: Deterministic
# intelligence/tier1.py
#
# Pure deterministic scoring. No ML, no LLM, no randomness.
# EPSS + CVSS + KEV + rule-based severity mapping.
# This tier is always fast, always correct, always auditable.
#
# Produces a composite risk score and grade from structured finding data.
# Every output is traceable to a specific input value.
# =============================================================================

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .schemas import (
    IntelligenceRequest, DeterministicOutput, ScoringBreakdown,
    FindingInput, RiskGrade, SeverityLevel,
)

logger = logging.getLogger(__name__)


# =============================================================================
# SCORING WEIGHTS — mirror OdinForge's existing formula, extended for Mimir
# Matches the unified Scoring Engine weights from the Platform Architecture doc
# =============================================================================

EPSS_WEIGHT              = 0.30   # exploit prediction
CVSS_WEIGHT              = 0.20   # base vulnerability severity
EXPLOITABILITY_WEIGHT    = 0.20   # agent-confirmed (OdinForge) or OSINT (Mimir)
OSINT_CONTEXT_WEIGHT     = 0.15   # Mimir signal weight (zero for OdinForge-only)
BEHAVIORAL_WEIGHT        = 0.10   # Suite telemetry (zero until Suite ships)
VECTOR_SIMILARITY_WEIGHT = 0.05   # historical breach pattern similarity

# KEV override: confirmed exploited in the wild always elevates to critical
KEV_SCORE_FLOOR = 90.0

# Severity — base score (before EPSS/CVSS adjustment)
SEVERITY_BASE_SCORE: dict[str, float] = {
    "critical": 90.0,
    "high":     70.0,
    "medium":   45.0,
    "low":      20.0,
    "info":      5.0,
}

# Grade thresholds
GRADE_THRESHOLDS: list[tuple[float, RiskGrade]] = [
    (85.0, RiskGrade.F),
    (70.0, RiskGrade.D),
    (50.0, RiskGrade.C),
    (30.0, RiskGrade.B),
    (0.0,  RiskGrade.A),
]


# =============================================================================
# SCORING FUNCTIONS
# =============================================================================

def score_finding(finding: FindingInput) -> float:
    """
    Score a single finding on a 0-100 scale.
    Deterministic — same input always produces same output.
    """
    # Hard override: KEV listed means confirmed exploited in the wild
    if finding.is_kev_listed:
        return KEV_SCORE_FLOOR

    # Base from severity
    base = SEVERITY_BASE_SCORE.get(finding.severity.value, 45.0)

    # EPSS component: 0-1 scale -> 0-100
    epss_raw = finding.epss_score or 0.0
    epss_component = epss_raw * 100.0

    # CVSS component: 0-10 scale -> 0-100
    cvss_raw = finding.cvss_score or 0.0
    cvss_component = (cvss_raw / 10.0) * 100.0

    # Exploitability component:
    # OdinForge: agent-confirmed = 100, not confirmed = 0
    # Mimir: OSINT evidence strength (estimated from evidence dict size)
    exploitability = 0.0
    if finding.source_product == "odinforge":
        # OdinForge explicitly confirms exploitability via its agent loop.
        # We treat the presence of evidence as confirmed.
        exploitability = 100.0 if finding.evidence else 0.0
    elif finding.source_product == "mimir":
        # Mimir is passive — evidence richness is a proxy for confidence
        evidence_count = len(finding.evidence)
        exploitability = min(evidence_count * 12.5, 75.0)  # cap at 75 for OSINT

    # Weighted composite
    composite = (
        epss_component    * EPSS_WEIGHT +
        cvss_component    * CVSS_WEIGHT +
        exploitability    * EXPLOITABILITY_WEIGHT +
        base              * (OSINT_CONTEXT_WEIGHT + BEHAVIORAL_WEIGHT + VECTOR_SIMILARITY_WEIGHT)
    )

    return round(min(composite, 100.0), 2)


def score_to_grade(score: float) -> RiskGrade:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return RiskGrade.A


def aggregate_scores(scored_findings: list[tuple[FindingInput, float]]) -> float:
    """
    Aggregate individual finding scores into an org-level composite.

    Not a simple average — critical and high findings carry disproportionate
    weight, which matches how real risk works. One KEV is worse than 50 infos.
    """
    if not scored_findings:
        return 0.0

    # Weight by severity tier
    tier_weights = {"critical": 4.0, "high": 2.5, "medium": 1.5, "low": 0.8, "info": 0.2}

    weighted_sum = 0.0
    weight_total = 0.0

    for finding, score in scored_findings:
        w = tier_weights.get(finding.severity.value, 1.0)
        weighted_sum += score * w
        weight_total += w

    if weight_total == 0:
        return 0.0

    raw = weighted_sum / weight_total

    # Penalty multiplier for KEV findings — even one confirmed exploited
    # vulnerability elevates the composite
    kev_count = sum(1 for f, _ in scored_findings if f.is_kev_listed)
    kev_multiplier = 1.0 + (min(kev_count, 5) * 0.04)  # max +20% for 5+ KEV

    return round(min(raw * kev_multiplier, 100.0), 2)


def extract_cve_matches(findings: list[FindingInput]) -> list[str]:
    """Return distinct CVE IDs found across all findings."""
    seen: set[str] = set()
    result: list[str] = []
    for f in findings:
        if f.cve_id and f.cve_id not in seen:
            seen.add(f.cve_id)
            result.append(f.cve_id)
    return sorted(result)


def severity_distribution(findings: list[FindingInput]) -> dict[str, int]:
    dist: dict[str, int] = {s.value: 0 for s in SeverityLevel}
    for f in findings:
        dist[f.severity.value] += 1
    return dist


def build_scoring_breakdown(
    scored_findings:  list[tuple[FindingInput, float]],
    composite_score:  float,
    kev_override:     bool,
) -> ScoringBreakdown:
    if not scored_findings:
        return ScoringBreakdown(
            epss_component=0.0, cvss_component=0.0,
            exploitability_component=0.0, kev_override=False, final_score=0.0
        )

    avg_epss = sum(
        (f.epss_score or 0.0) * 100.0 for f, _ in scored_findings
    ) / len(scored_findings)

    avg_cvss = sum(
        ((f.cvss_score or 0.0) / 10.0) * 100.0 for f, _ in scored_findings
    ) / len(scored_findings)

    avg_exploit = sum(
        (100.0 if f.source_product == "odinforge" and f.evidence else 50.0)
        for f, _ in scored_findings
    ) / len(scored_findings)

    return ScoringBreakdown(
        epss_component=round(avg_epss, 2),
        cvss_component=round(avg_cvss, 2),
        exploitability_component=round(avg_exploit, 2),
        kev_override=kev_override,
        final_score=composite_score,
    )


# =============================================================================
# MAIN TIER 1 RUNNER
# =============================================================================

class DeterministicEngine:

    def run(self, request: IntelligenceRequest) -> DeterministicOutput:
        findings = request.findings

        if not findings:
            return DeterministicOutput(
                composite_score=0.0,
                risk_grade=RiskGrade.A,
                severity_distribution={s.value: 0 for s in SeverityLevel},
                kev_count=0,
                scoring_breakdown=ScoringBreakdown(
                    epss_component=0.0, cvss_component=0.0,
                    exploitability_component=0.0, kev_override=False,
                    final_score=0.0,
                ),
                top_findings=[],
                cve_matches=[],
                computed_at=datetime.now(timezone.utc),
            )

        # Score every finding
        scored: list[tuple[FindingInput, float]] = [
            (f, score_finding(f)) for f in findings
        ]

        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)

        # Aggregate
        composite = aggregate_scores(scored)
        kev_count = sum(1 for f in findings if f.is_kev_listed)
        kev_override = kev_count > 0

        grade = score_to_grade(composite)
        dist  = severity_distribution(findings)
        cves  = extract_cve_matches(findings)
        breakdown = build_scoring_breakdown(scored, composite, kev_override)

        # Top 10 findings for downstream tiers
        top_findings = [f for f, _ in scored[:10]]

        logger.debug(
            "[Tier1] org=%s score=%.1f grade=%s kev=%d findings=%d",
            request.organization_id, composite, grade.value, kev_count, len(findings)
        )

        return DeterministicOutput(
            composite_score=composite,
            risk_grade=grade,
            severity_distribution=dist,
            kev_count=kev_count,
            scoring_breakdown=breakdown,
            top_findings=top_findings,
            cve_matches=cves,
            computed_at=datetime.now(timezone.utc),
        )
