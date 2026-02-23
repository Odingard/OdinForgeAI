# =============================================================================
# Intelligence Engine — Template Renderer
# intelligence/templates.py
#
# Produces clean, accurate, well-formatted output without the LLM.
# This is the fallback for: no API key, rate limit, API failure, validation fail.
#
# Template output is NOT a degraded experience — it is fully accurate
# because it renders directly from Tier 1 and Tier 2 structured data.
# The only difference from LLM output is it reads as structured rather
# than as polished prose.
# =============================================================================

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .schemas import (
    IntelligenceRequest, DeterministicOutput, StatisticalOutput,
    NarrativeOutput, RemediationStep, NarrativeTone, RiskGrade,
)


# Risk grade — human-readable descriptions
GRADE_DESCRIPTIONS: dict[str, str] = {
    "A": "low risk — no material security concerns identified",
    "B": "guarded — minor findings present, manageable with standard patching",
    "C": "elevated — moderate exposure requiring attention within 30 days",
    "D": "high risk — significant vulnerabilities requiring urgent remediation",
    "F": "critical risk — active exploitation risk, immediate action required",
}

# Effort mapping for remediation
EFFORT_BY_SEVERITY: dict[str, str] = {
    "critical": "hours",
    "high":     "days",
    "medium":   "days",
    "low":      "weeks",
    "info":     "weeks",
}


class TemplateRenderer:

    def render(
        self,
        request: IntelligenceRequest,
        tier1:   DeterministicOutput,
        tier2:   Optional[StatisticalOutput],
        reason:  str = "template",
    ) -> NarrativeOutput:

        score  = tier2.calibrated_score if tier2 else tier1.composite_score
        grade  = tier1.risk_grade
        dist   = tier1.severity_distribution
        domain = request.target_domain or "the target"
        tone   = request.tone

        executive_summary   = self._executive_summary(domain, grade, dist, tier1.kev_count, tone)
        risk_headline       = self._risk_headline(domain, grade, tier1.kev_count, score)
        findings_narrative  = self._findings_narrative(tier1, tier2, tone)
        remediation_steps   = self._remediation_steps(tier1)
        breach_narrative    = self._breach_narrative(request, tier2) if request.breach_chains else None
        anomaly_narrative   = self._anomaly_narrative(tier2) if tier2 and tier2.anomaly_signals else None
        deal_memo           = self._deal_memo(domain, grade, dist, tier1.kev_count, score, tier2) if tone == NarrativeTone.DEAL_MEMO else None

        return NarrativeOutput(
            executive_summary      = executive_summary,
            risk_headline          = risk_headline,
            key_findings_narrative = findings_narrative,
            remediation_steps      = remediation_steps,
            breach_path_narrative  = breach_narrative,
            anomaly_narrative      = anomaly_narrative,
            deal_memo_summary      = deal_memo,
            generated_by           = f"template:{reason}",
            grounded_claims        = len(tier1.top_findings) + tier1.kev_count,
            generated_at           = datetime.now(timezone.utc),
        )

    def _executive_summary(
        self,
        domain:    str,
        grade:     RiskGrade,
        dist:      dict[str, int],
        kev_count: int,
        tone:      NarrativeTone,
    ) -> str:
        total = sum(dist.values())
        critical = dist.get("critical", 0)
        high     = dist.get("high", 0)
        grade_desc = GRADE_DESCRIPTIONS.get(grade.value, "risk present")

        if tone == NarrativeTone.EXECUTIVE:
            base = (
                f"{domain} has been assessed and rated {grade.value} — {grade_desc}. "
                f"The assessment identified {total} security issue{'s' if total != 1 else ''}"
            )
            if critical or high:
                base += f", including {critical} critical and {high} high severity finding{'s' if (critical + high) != 1 else ''}"
            base += "."
            if kev_count:
                base += (
                    f" {kev_count} finding{'s are' if kev_count > 1 else ' is'} on the "
                    f"CISA Known Exploited Vulnerabilities list, indicating active real-world exploitation."
                )
            return base

        # Technical tone
        base = (
            f"Security assessment of {domain} produced a grade of {grade.value} "
            f"with {total} total finding{'s' if total != 1 else ''} "
            f"({critical} critical, {high} high, "
            f"{dist.get('medium', 0)} medium, {dist.get('low', 0)} low)."
        )
        if kev_count:
            base += f" {kev_count} CISA KEV finding{'s' if kev_count > 1 else ''} present."
        return base

    def _risk_headline(
        self,
        domain:    str,
        grade:     RiskGrade,
        kev_count: int,
        score:     float,
    ) -> str:
        if kev_count > 0:
            return (
                f"{domain} has {kev_count} CISA Known Exploited "
                f"Vulnerabilit{'ies' if kev_count > 1 else 'y'} — "
                f"immediate remediation required."
            )
        if grade == RiskGrade.F:
            return f"{domain} is rated F ({score:.0f}/100) — critical exposure across multiple attack surfaces."
        if grade == RiskGrade.D:
            return f"{domain} is rated D ({score:.0f}/100) — significant vulnerabilities require urgent attention."
        if grade in (RiskGrade.C,):
            return f"{domain} is rated C ({score:.0f}/100) — moderate exposure, remediation recommended within 30 days."
        return f"{domain} is rated {grade.value} ({score:.0f}/100) — risk is within acceptable parameters."

    def _findings_narrative(
        self,
        tier1: DeterministicOutput,
        tier2: Optional[StatisticalOutput],
        tone:  NarrativeTone,
    ) -> str:
        findings = tier1.top_findings
        if not findings:
            return "No significant findings were identified in this assessment."

        parts: list[str] = []
        top = findings[:5]

        if tone == NarrativeTone.EXECUTIVE:
            # Group by category for executive readability
            by_cat: dict[str, list] = {}
            for f in top:
                by_cat.setdefault(f.category.replace("_", " "), []).append(f)
            for cat, cat_findings in by_cat.items():
                count = len(cat_findings)
                worst = cat_findings[0].severity.value
                parts.append(f"{count} {cat} finding{'s' if count > 1 else ''} at {worst} severity")
            summary = "Key issues include: " + "; ".join(parts) + "."
        else:
            # Technical: list specific findings
            for f in top:
                line = f"{f.severity.value.upper()}: {f.title}"
                if f.cve_id:
                    line += f" ({f.cve_id})"
                if f.is_kev_listed:
                    line += " [KEV]"
                parts.append(line)
            summary = "Top findings: " + " | ".join(parts) + "."

        # Add statistical context if available
        if tier2 and tier2.outcome_predictions:
            top_outcome = tier2.outcome_predictions[0]
            prob_pct = round(top_outcome.probability * 100)
            summary += (
                f" Based on historical patterns, {top_outcome.outcome_label.replace('_', ' ')} "
                f"is the most likely outcome at {prob_pct}% probability."
            )

        if tier1.cve_matches:
            cve_list = ", ".join(tier1.cve_matches[:5])
            suffix = f" and {len(tier1.cve_matches) - 5} more" if len(tier1.cve_matches) > 5 else ""
            summary += f" CVEs identified: {cve_list}{suffix}."

        return summary

    def _remediation_steps(self, tier1: DeterministicOutput) -> list[RemediationStep]:
        steps: list[RemediationStep] = []

        # Priority 1: KEV findings always first
        kev_findings = [f for f in tier1.top_findings if f.is_kev_listed]
        for i, f in enumerate(kev_findings[:2]):
            steps.append(RemediationStep(
                priority=1,
                action=f"Patch or mitigate {f.cve_id or f.title} immediately — actively exploited in the wild",
                effort="hours",
                impact="Removes known active exploitation risk",
                evidence_ref=f.title,
            ))

        # Priority 2-3: Critical and high findings
        priority_2 = [
            f for f in tier1.top_findings
            if f.severity.value in ("critical", "high") and not f.is_kev_listed
        ]
        for i, f in enumerate(priority_2[:3]):
            steps.append(RemediationStep(
                priority=2 if f.severity.value == "critical" else 3,
                action=f"Remediate {f.title}" + (f" ({f.cve_id})" if f.cve_id else ""),
                effort=EFFORT_BY_SEVERITY[f.severity.value],
                impact=f"Reduces {f.severity.value} severity exposure in {f.category.replace('_', ' ')}",
                evidence_ref=f.title,
            ))

        # Priority 4-5: Medium findings
        medium = [f for f in tier1.top_findings if f.severity.value == "medium"]
        for f in medium[:2]:
            steps.append(RemediationStep(
                priority=4,
                action=f"Address {f.title}",
                effort="days",
                impact=f"Reduces medium severity exposure",
                evidence_ref=f.title,
            ))

        # Deduplicate and cap at 6
        seen: set[str] = set()
        unique: list[RemediationStep] = []
        for s in sorted(steps, key=lambda x: x.priority):
            key = s.action[:40]
            if key not in seen:
                seen.add(key)
                unique.append(s)
            if len(unique) >= 6:
                break

        return unique

    def _breach_narrative(
        self,
        request: IntelligenceRequest,
        tier2:   Optional[StatisticalOutput],
    ) -> Optional[str]:
        chains = request.breach_chains
        if not chains:
            return None

        confirmed = [c for c in chains if c.confirmed]
        total     = len(chains)

        narrative = (
            f"{total} breach chain{'s' if total != 1 else ''} identified"
            f", {len(confirmed)} confirmed exploitable by active validation. "
        )

        if chains[0].steps:
            narrative += f"Longest chain: {len(chains[0].steps)} steps. "
        if chains[0].techniques:
            narrative += f"Techniques: {', '.join(chains[0].techniques[:4])}."

        if tier2 and tier2.similar_patterns:
            p = tier2.similar_patterns[0]
            narrative += (
                f" This pattern matches {p.historical_count} historical case"
                f"{'s' if p.historical_count != 1 else ''} "
                f"({p.similarity_pct:.0f}% similarity) that led to {p.outcome.replace('_', ' ')}."
            )

        return narrative

    def _anomaly_narrative(self, tier2: Optional[StatisticalOutput]) -> Optional[str]:
        if not tier2 or not tier2.anomaly_signals:
            return None

        parts: list[str] = []
        for signal in tier2.anomaly_signals[:3]:
            direction = "higher" if signal.direction == "above" else "lower"
            parts.append(
                f"{signal.signal} is {signal.deviation_pct:.0f}% {direction} "
                f"than the {signal.baseline_label}"
            )

        return "Anomalies detected: " + "; ".join(parts) + "."

    def _deal_memo(
        self,
        domain:    str,
        grade:     RiskGrade,
        dist:      dict[str, int],
        kev_count: int,
        score:     float,
        tier2:     Optional[StatisticalOutput],
    ) -> str:
        critical = dist.get("critical", 0)
        high     = dist.get("high", 0)
        total    = sum(dist.values())

        memo = (
            f"CYBER DUE DILIGENCE SUMMARY — {domain.upper()}\n\n"
            f"Risk Grade: {grade.value} | Risk Score: {score:.0f}/100\n\n"
            f"Finding Summary: {total} total findings ({critical} critical, {high} high). "
        )

        if kev_count:
            memo += (
                f"{kev_count} CISA KEV finding{'s' if kev_count > 1 else ''} represent "
                f"deal-blocking risk — active exploitation confirmed by CISA. "
            )

        if grade in (RiskGrade.D, RiskGrade.F):
            memo += (
                "Recommendation: require remediation escrow or price adjustment "
                "to reflect cybersecurity liability prior to close. "
            )
        elif grade == RiskGrade.C:
            memo += (
                "Recommendation: include remediation timeline in representations "
                "and warranties. "
            )
        else:
            memo += "Recommendation: standard cybersecurity reps and warranties sufficient. "

        if tier2 and tier2.outcome_predictions:
            top = tier2.outcome_predictions[0]
            memo += (
                f"\nPrimary Risk Scenario: {top.outcome_label.replace('_', ' ')} "
                f"({round(top.probability * 100)}% probability based on historical patterns)."
            )

        return memo
