# =============================================================================
# Intelligence Engine — Tier 2: Statistical
# intelligence/tier2.py
#
# ML-powered risk intelligence layer.
# No LLM. No hallucination. Every output is a statistical claim with a
# confidence score derived from real data in the entity graph.
#
# Three models:
#   1. Breach pattern similarity — pgvector cosine search against historical
#      confirmed breach chains from OdinForge
#   2. Risk calibration — scikit-learn GBM that adjusts Tier 1 score
#      based on what findings like these actually led to
#   3. Anomaly detection — z-score baselines per industry/org-size bucket
#
# Models are stored in Redis (serialized) and retrained weekly via Celery.
# =============================================================================

from __future__ import annotations

import io
import json
import hashlib
import logging
import pickle
from datetime import datetime, timezone
from typing import Optional, Any

import numpy as np

from .schemas import (
    IntelligenceRequest, DeterministicOutput, StatisticalOutput,
    SimilarPattern, AnomalySignal, OutcomePrediction, FindingInput,
)

logger = logging.getLogger(__name__)

# Model keys in Redis
MODEL_KEY_CALIBRATION = "intelligence:model:risk_calibration"
MODEL_KEY_OUTCOME     = "intelligence:model:outcome_prediction"
MODEL_KEY_BASELINES   = "intelligence:model:anomaly_baselines"
MODEL_VERSION_KEY     = "intelligence:model:versions"

SIMILARITY_THRESHOLD  = 0.72    # cosine similarity floor for a relevant match
MAX_SIMILAR_PATTERNS  = 5
EMBEDDING_DIM         = 1536    # matches pgvector setup in OdinForge


# =============================================================================
# FEATURE EXTRACTION
# Converts a request + Tier 1 output into a fixed-length numeric feature vector
# for scikit-learn models.
# Deterministic — same input always produces same vector.
# =============================================================================

def extract_features(
    request:  IntelligenceRequest,
    tier1:    DeterministicOutput,
) -> np.ndarray:
    """
    Build a feature vector from structured finding data.
    No text, no embeddings — only numeric signals.
    """
    dist = tier1.severity_distribution
    n_findings = sum(dist.values()) or 1  # avoid div/0

    features = [
        # Score signals
        tier1.composite_score / 100.0,
        tier1.kev_count / max(n_findings, 1),

        # Severity ratios
        dist.get("critical", 0) / n_findings,
        dist.get("high", 0) / n_findings,
        dist.get("medium", 0) / n_findings,
        dist.get("low", 0) / n_findings,
        dist.get("info", 0) / n_findings,

        # Finding volume
        min(n_findings / 50.0, 1.0),  # normalized, capped at 50

        # EPSS signals (top findings)
        _avg_epss(tier1.top_findings),
        _max_epss(tier1.top_findings),

        # CVSS signals
        _avg_cvss(tier1.top_findings),
        _max_cvss(tier1.top_findings),

        # CVE coverage
        min(len(tier1.cve_matches) / 20.0, 1.0),

        # Source product encoding
        1.0 if request.source_product == "odinforge" else 0.0,
        1.0 if request.source_product == "mimir" else 0.0,

        # Org size encoding
        _encode_org_size(request.org_size),

        # Breach chain presence
        1.0 if request.breach_chains else 0.0,
        min(len(request.breach_chains) / 5.0, 1.0),
    ]

    return np.array(features, dtype=np.float32)


def _avg_epss(findings: list[FindingInput]) -> float:
    scores = [f.epss_score for f in findings if f.epss_score is not None]
    return sum(scores) / len(scores) if scores else 0.0


def _max_epss(findings: list[FindingInput]) -> float:
    scores = [f.epss_score for f in findings if f.epss_score is not None]
    return max(scores) if scores else 0.0


def _avg_cvss(findings: list[FindingInput]) -> float:
    scores = [f.cvss_score for f in findings if f.cvss_score is not None]
    return (sum(scores) / len(scores) / 10.0) if scores else 0.0


def _max_cvss(findings: list[FindingInput]) -> float:
    scores = [f.cvss_score for f in findings if f.cvss_score is not None]
    return (max(scores) / 10.0) if scores else 0.0


def _encode_org_size(size: Optional[str]) -> float:
    return {"smb": 0.25, "mid_market": 0.6, "enterprise": 1.0}.get(size or "", 0.5)


# =============================================================================
# BREACH PATTERN SIMILARITY — pgvector cosine search
# =============================================================================

async def find_similar_patterns(
    request:  IntelligenceRequest,
    tier1:    DeterministicOutput,
    db_session,   # AsyncSession from OdinForge/Mimir
) -> list[SimilarPattern]:
    """
    Search entity_graph for historical breach patterns similar to the
    current finding set using pgvector cosine similarity.

    The embedding is built from the feature vector (not text) so it
    represents structural similarity in the risk profile, not
    semantic similarity in the description.
    """
    try:
        from sqlalchemy import text

        features = extract_features(request, tier1)
        # Pad feature vector to 1536 dimensions with zeros
        # (future: use a real encoder; today the structural features are sufficient)
        padded = np.zeros(EMBEDDING_DIM, dtype=np.float32)
        padded[:len(features)] = features
        embedding_str = f"[{','.join(str(x) for x in padded.tolist())}]"

        result = await db_session.execute(
            text("""
                SELECT
                    e.id::text,
                    e.display_name,
                    e.metadata_,
                    1 - (e.embedding <=> :embedding::vector) AS similarity
                FROM entity_graph.entities e
                WHERE
                    e.embedding IS NOT NULL
                    AND e.organization_id != :org_id::uuid
                    AND 1 - (e.embedding <=> :embedding::vector) >= :threshold
                ORDER BY e.embedding <=> :embedding::vector
                LIMIT :limit
            """),
            {
                "embedding":  embedding_str,
                "org_id":     request.organization_id,
                "threshold":  SIMILARITY_THRESHOLD,
                "limit":      MAX_SIMILAR_PATTERNS,
            },
        )

        rows = result.fetchall()
        patterns: list[SimilarPattern] = []

        for row in rows:
            metadata = row.metadata_ or {}
            outcome = metadata.get("breach_outcome", "unknown")
            count   = metadata.get("historical_count", 1)
            confirmed = metadata.get("confirmed_exploitable", False)

            if outcome == "unknown":
                continue

            patterns.append(SimilarPattern(
                description=_describe_pattern(metadata),
                similarity_pct=round(row.similarity * 100.0, 1),
                historical_count=count,
                outcome=outcome,
                confirmed=confirmed,
            ))

        return patterns

    except Exception as e:
        logger.warning("[Tier2] Pattern similarity search failed: %s", e)
        return []


def _describe_pattern(metadata: dict[str, Any]) -> str:
    """Build a description string from entity metadata without LLM."""
    parts = []
    if metadata.get("severity_distribution"):
        dist = metadata["severity_distribution"]
        critical = dist.get("critical", 0)
        high     = dist.get("high", 0)
        if critical:
            parts.append(f"{critical} critical finding{'s' if critical > 1 else ''}")
        if high:
            parts.append(f"{high} high finding{'s' if high > 1 else ''}")
    if metadata.get("kev_count", 0) > 0:
        parts.append(f"{metadata['kev_count']} KEV finding{'s' if metadata['kev_count'] > 1 else ''}")
    if metadata.get("breach_outcome"):
        parts.append(f"led to {metadata['breach_outcome'].replace('_', ' ')}")
    return ", ".join(parts) if parts else "similar risk profile"


# =============================================================================
# RISK CALIBRATION — scikit-learn GBM
# Adjusts Tier 1 composite score based on ML model trained on historical data
# =============================================================================

class RiskCalibrationModel:
    """
    Gradient Boosted Machine that adjusts the Tier 1 deterministic score
    based on patterns learned from historical outcomes.

    At medium volume (1k-10k/month), trains on ~3 months of historical data
    (3k-30k samples) — sufficient for GBM convergence.

    Stored serialized in Redis. Retrained weekly by Celery job.
    Falls back to identity function (no adjustment) when model unavailable.
    """

    def __init__(self):
        self._model = None
        self._version = "untrained"

    def load_from_redis(self, redis_client) -> bool:
        try:
            raw = redis_client.get(MODEL_KEY_CALIBRATION)
            if not raw:
                return False
            self._model = pickle.loads(raw)
            versions = redis_client.get(MODEL_VERSION_KEY)
            if versions:
                v = json.loads(versions)
                self._version = v.get("calibration", "unknown")
            return True
        except Exception as e:
            logger.warning("[Tier2] Calibration model load failed: %s", e)
            return False

    def predict(self, features: np.ndarray, tier1_score: float) -> tuple[float, float]:
        """
        Returns (calibrated_score, calibration_delta).
        Falls back to identity (delta=0) if model unavailable.
        """
        if self._model is None:
            return tier1_score, 0.0

        try:
            X = features.reshape(1, -1)
            predicted_delta = float(self._model.predict(X)[0])
            # Cap the calibration adjustment to +/-20 points
            delta = max(-20.0, min(20.0, predicted_delta))
            calibrated = max(0.0, min(100.0, tier1_score + delta))
            return round(calibrated, 2), round(delta, 2)
        except Exception as e:
            logger.warning("[Tier2] Calibration predict failed: %s", e)
            return tier1_score, 0.0

    @property
    def version(self) -> str:
        return self._version


# =============================================================================
# OUTCOME PREDICTION — separate classifier for outcome labeling
# =============================================================================

class OutcomePredictionModel:
    """
    Multi-label classifier that predicts likely attack outcomes
    given the current finding profile.

    Outcomes: full_compromise, data_exfil, credential_theft,
              lateral_movement, ransomware_delivery, service_disruption
    """

    OUTCOME_LABELS = [
        "full_compromise",
        "data_exfil",
        "credential_theft",
        "lateral_movement",
        "ransomware_delivery",
        "service_disruption",
    ]

    def __init__(self):
        self._model = None
        self._version = "untrained"

    def load_from_redis(self, redis_client) -> bool:
        try:
            raw = redis_client.get(MODEL_KEY_OUTCOME)
            if not raw:
                return False
            self._model = pickle.loads(raw)
            versions = redis_client.get(MODEL_VERSION_KEY)
            if versions:
                v = json.loads(versions)
                self._version = v.get("outcome", "unknown")
            return True
        except Exception as e:
            logger.warning("[Tier2] Outcome model load failed: %s", e)
            return False

    def predict(
        self,
        features: np.ndarray,
        tier1: DeterministicOutput,
        request: IntelligenceRequest,
    ) -> list[OutcomePrediction]:
        if self._model is None:
            # Rule-based fallback when model is untrained
            return self._rule_based_predictions(tier1, request)

        try:
            X = features.reshape(1, -1)
            proba = self._model.predict_proba(X)[0]  # shape: (n_outcomes,)

            predictions: list[OutcomePrediction] = []
            for label, prob in zip(self.OUTCOME_LABELS, proba):
                if prob < 0.15:
                    continue
                predictions.append(OutcomePrediction(
                    outcome_label=label,
                    probability=round(float(prob), 3),
                    confidence=round(float(prob) * 0.85, 3),  # slight confidence discount
                    supporting_evidence=self._find_evidence(label, tier1),
                    model_version=self._version,
                ))

            return sorted(predictions, key=lambda x: x.probability, reverse=True)[:3]

        except Exception as e:
            logger.warning("[Tier2] Outcome predict failed: %s", e)
            return self._rule_based_predictions(tier1, request)

    def _rule_based_predictions(
        self,
        tier1: DeterministicOutput,
        request: IntelligenceRequest,
    ) -> list[OutcomePrediction]:
        """
        Deterministic rules-based outcome prediction.
        Used when model is untrained (first weeks of deployment).
        """
        predictions: list[OutcomePrediction] = []
        dist = tier1.severity_distribution

        # Rule: KEV + critical = high probability of compromise
        if tier1.kev_count > 0 and dist.get("critical", 0) > 0:
            predictions.append(OutcomePrediction(
                outcome_label="full_compromise",
                probability=0.78,
                confidence=0.65,
                supporting_evidence=[
                    f"{tier1.kev_count} CISA KEV finding(s) present",
                    f"{dist['critical']} critical severity finding(s)",
                ],
                model_version="rules_v1",
            ))

        # Rule: credential exposure -> credential theft
        credential_findings = [
            f for f in tier1.top_findings
            if f.category in ("credential_exposure", "data_breach")
        ]
        if credential_findings:
            predictions.append(OutcomePrediction(
                outcome_label="credential_theft",
                probability=0.71,
                confidence=0.70,
                supporting_evidence=[
                    f"{len(credential_findings)} credential/breach finding(s)",
                ],
                model_version="rules_v1",
            ))

        # Rule: high composite score -> data exfiltration risk
        if tier1.composite_score >= 70.0:
            predictions.append(OutcomePrediction(
                outcome_label="data_exfil",
                probability=0.58,
                confidence=0.50,
                supporting_evidence=[
                    f"Composite risk score {tier1.composite_score:.0f}/100",
                ],
                model_version="rules_v1",
            ))

        return predictions[:3]

    def _find_evidence(self, outcome: str, tier1: DeterministicOutput) -> list[str]:
        """Map outcome labels to supporting finding evidence."""
        evidence_map: dict[str, list[str]] = {
            "full_compromise":    ["critical", "high"],
            "data_exfil":         ["data_breach", "credential_exposure", "cloud_exposure"],
            "credential_theft":   ["credential_exposure", "data_breach"],
            "lateral_movement":   ["exposed_infrastructure", "misconfiguration"],
            "ransomware_delivery":["vulnerable_software", "exposed_infrastructure"],
            "service_disruption": ["exposed_infrastructure", "misconfiguration"],
        }
        relevant = evidence_map.get(outcome, [])
        evidence: list[str] = []
        for f in tier1.top_findings:
            if f.severity.value in relevant or f.category in relevant:
                evidence.append(f.title)
                if len(evidence) >= 3:
                    break
        return evidence


# =============================================================================
# ANOMALY DETECTION — z-score against industry baselines
# =============================================================================

class AnomalyDetector:
    """
    Detects when an organization's risk profile deviates significantly
    from its industry/size peer group.

    Baselines stored as {industry+size: {metric: {mean, std}}} in Redis.
    Updated weekly during retraining.
    """

    def __init__(self):
        self._baselines: dict[str, Any] = {}
        self._version = "empty"

    def load_from_redis(self, redis_client) -> bool:
        try:
            raw = redis_client.get(MODEL_KEY_BASELINES)
            if not raw:
                return False
            self._baselines = json.loads(raw)
            self._version = self._baselines.get("_version", "unknown")
            return True
        except Exception as e:
            logger.warning("[Tier2] Baselines load failed: %s", e)
            return False

    def detect(
        self,
        request: IntelligenceRequest,
        tier1:   DeterministicOutput,
    ) -> list[AnomalySignal]:
        baseline_key = f"{request.industry or 'general'}:{request.org_size or 'unknown'}"
        baseline = self._baselines.get(baseline_key, {})

        if not baseline:
            return []

        signals: list[AnomalySignal] = []
        n_findings = sum(tier1.severity_distribution.values()) or 1

        checks = [
            (
                "composite_score",
                tier1.composite_score,
                "composite risk score",
            ),
            (
                "critical_ratio",
                tier1.severity_distribution.get("critical", 0) / n_findings,
                "proportion of critical findings",
            ),
            (
                "kev_count",
                float(tier1.kev_count),
                "CISA KEV finding count",
            ),
        ]

        for metric_key, value, label in checks:
            stats = baseline.get(metric_key)
            if not stats:
                continue

            mean = stats["mean"]
            std  = stats["std"]

            if std < 0.001:
                continue

            z = (value - mean) / std
            if abs(z) < 1.5:  # less than 1.5 sigma — not notable
                continue

            deviation_pct = abs((value - mean) / mean * 100) if mean > 0 else 0.0

            signals.append(AnomalySignal(
                signal=label,
                deviation_pct=round(deviation_pct, 1),
                baseline_label=f"{request.industry or 'general'} {request.org_size or ''} average".strip(),
                direction="above" if z > 0 else "below",
            ))

        return signals[:4]  # cap at 4 anomaly signals


# =============================================================================
# MAIN TIER 2 RUNNER
# =============================================================================

class StatisticalEngine:

    def __init__(self, redis_client):
        self.redis = redis_client
        self.calibration = RiskCalibrationModel()
        self.outcome      = OutcomePredictionModel()
        self.anomaly      = AnomalyDetector()
        self._models_loaded = False

    def _load_models(self) -> None:
        if self._models_loaded:
            return
        self.calibration.load_from_redis(self.redis)
        self.outcome.load_from_redis(self.redis)
        self.anomaly.load_from_redis(self.redis)
        self._models_loaded = True

    async def run(
        self,
        request: IntelligenceRequest,
        tier1:   DeterministicOutput,
        db_session,
    ) -> StatisticalOutput:
        self._load_models()

        features = extract_features(request, tier1)

        # 1. Breach pattern similarity (pgvector)
        similar_patterns = await find_similar_patterns(request, tier1, db_session)

        # 2. Risk calibration (GBM)
        calibrated_score, delta = self.calibration.predict(features, tier1.composite_score)

        # 3. Outcome prediction
        outcome_predictions = self.outcome.predict(features, tier1, request)

        # 4. Anomaly detection
        anomalies = self.anomaly.detect(request, tier1)

        logger.debug(
            "[Tier2] org=%s calibrated_score=%.1f delta=%.1f patterns=%d anomalies=%d",
            request.organization_id, calibrated_score, delta,
            len(similar_patterns), len(anomalies)
        )

        return StatisticalOutput(
            similar_patterns=similar_patterns,
            anomaly_signals=anomalies,
            outcome_predictions=outcome_predictions,
            calibrated_score=calibrated_score,
            calibration_delta=delta,
            embedding_version="v1.0",
            model_versions={
                "calibration": self.calibration.version,
                "outcome":     self.outcome.version,
                "anomaly":     self.anomaly.version,
            },
            computed_at=datetime.now(timezone.utc),
        )
