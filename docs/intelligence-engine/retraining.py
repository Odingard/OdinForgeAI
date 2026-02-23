# =============================================================================
# Intelligence Engine — Weekly Retraining Job
# intelligence/retraining.py
#
# Celery task that retrains scikit-learn models weekly from entity graph data.
# Runs automatically — zero manual intervention required.
#
# Schedule: Sunday 02:00 UTC (low traffic window)
# Runtime: ~5-15 minutes at medium volume (1k-10k assessments/month)
#
# Wire into Mimir's existing Celery beat schedule:
#   CELERYBEAT_SCHEDULE = {
#       ...existing tasks...,
#       "retrain-intelligence-models": {
#           "task": "intelligence.retraining.retrain_all_models",
#           "schedule": crontab(hour=2, minute=0, day_of_week=0),
#       },
#   }
# =============================================================================

from __future__ import annotations

import json
import pickle
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

import numpy as np

logger = logging.getLogger(__name__)


# =============================================================================
# DATA EXTRACTION — pull training data from entity graph
# =============================================================================

async def extract_training_data(
    db_session,
    lookback_days: int = 90,
) -> list[dict[str, Any]]:
    """
    Pull historical assessment data from entity_graph for model training.

    Returns records like:
    {
        "features": [...],      # numeric feature vector
        "risk_score_actual": float,   # final score after validation
        "outcome_labels": [str],      # confirmed outcomes
        "org_size": str,
        "industry": str,
    }

    Uses assessments with confirmed OdinForge validation as ground truth.
    Mimir OSINT-only assessments contribute to baseline/anomaly training.
    """
    from sqlalchemy import text

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    result = await db_session.execute(
        text("""
            SELECT
                a.id::text,
                a.risk_score,
                a.deal_risk_grade,
                a.summary,
                a.assessment_type,
                a.organization_id::text,
                e.metadata_ as entity_metadata,
                COUNT(f.id) as finding_count,
                COUNT(f.id) FILTER (WHERE f.severity = 'critical') as critical_count,
                COUNT(f.id) FILTER (WHERE f.severity = 'high') as high_count,
                COUNT(f.id) FILTER (WHERE f.severity = 'medium') as medium_count,
                COUNT(f.id) FILTER (WHERE f.severity = 'low') as low_count,
                COUNT(f.id) FILTER (WHERE f.is_kev_listed = TRUE) as kev_count,
                AVG(f.epss_score::float) FILTER (WHERE f.epss_score IS NOT NULL) as avg_epss,
                MAX(f.epss_score::float) FILTER (WHERE f.epss_score IS NOT NULL) as max_epss,
                AVG(f.cvss_score::float) FILTER (WHERE f.cvss_score IS NOT NULL) as avg_cvss,
                MAX(f.cvss_score::float) FILTER (WHERE f.cvss_score IS NOT NULL) as max_cvss
            FROM entity_graph.assessments a
            LEFT JOIN entity_graph.findings f ON f.organization_id = a.organization_id
                AND f.entity_id = a.entity_id
                AND f.created_at >= a.started_at
            LEFT JOIN entity_graph.entities e ON e.id = a.entity_id
            WHERE a.completed_at >= :cutoff
                AND a.status = 'completed'
                AND a.risk_score IS NOT NULL
            GROUP BY a.id, a.risk_score, a.deal_risk_grade, a.summary,
                     a.assessment_type, a.organization_id, e.metadata_
            HAVING COUNT(f.id) > 0
        """),
        {"cutoff": cutoff},
    )

    rows = result.fetchall()
    records: list[dict[str, Any]] = []

    for row in rows:
        n_findings = max(row.finding_count, 1)
        entity_meta = row.entity_metadata or {}

        features = [
            float(row.risk_score or 0) / 100.0,
            float(row.kev_count or 0) / n_findings,
            float(row.critical_count or 0) / n_findings,
            float(row.high_count or 0) / n_findings,
            float(row.medium_count or 0) / n_findings,
            float(row.low_count or 0) / n_findings,
            min(n_findings / 50.0, 1.0),
            float(row.avg_epss or 0),
            float(row.max_epss or 0),
            float(row.avg_cvss or 0) / 10.0,
            float(row.max_cvss or 0) / 10.0,
            0.0,  # cve_coverage placeholder
            1.0 if row.assessment_type in ("exploit_validation", "breach_chain") else 0.0,
            1.0 if row.assessment_type == "osint_recon" else 0.0,
            0.5,  # org_size placeholder
            1.0 if row.assessment_type in ("breach_chain",) else 0.0,
            0.0,  # breach_chain_count placeholder
            0.0, 0.0,  # padding
        ]

        records.append({
            "features":          features,
            "risk_score_actual": float(row.risk_score or 0),
            "deal_risk_grade":   row.deal_risk_grade,
            "org_id":            row.organization_id,
            "industry":          entity_meta.get("industry", "general"),
            "org_size":          entity_meta.get("org_size", "unknown"),
            "summary":           row.summary or {},
        })

    logger.info("[Retraining] Extracted %d training records (lookback %d days)", len(records), lookback_days)
    return records


# =============================================================================
# MODEL TRAINING
# =============================================================================

def train_calibration_model(records: list[dict[str, Any]]) -> Optional[Any]:
    """
    Train a GBM to predict how much the deterministic score should be
    adjusted based on what outcomes were actually observed.

    Target: actual final risk score after full assessment
    Features: deterministic-only signals
    """
    if len(records) < 100:
        logger.warning("[Retraining] Not enough data for calibration model (%d records, need 100)", len(records))
        return None

    try:
        from sklearn.ensemble import GradientBoostingRegressor
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline

        X = np.array([r["features"] for r in records], dtype=np.float32)
        # Target: delta between deterministic score and actual validated score
        # (here we use risk_score_actual as a proxy for the ground truth)
        y = np.array([r["risk_score_actual"] for r in records], dtype=np.float32)

        model = Pipeline([
            ("scaler", StandardScaler()),
            ("gbm", GradientBoostingRegressor(
                n_estimators=150,
                max_depth=4,
                learning_rate=0.08,
                subsample=0.8,
                random_state=42,
            )),
        ])

        # Cross-validate
        cv_scores = cross_val_score(model, X, y, cv=5, scoring="neg_mean_absolute_error")
        mae = -cv_scores.mean()
        logger.info("[Retraining] Calibration model CV MAE: %.2f", mae)

        model.fit(X, y)
        return model

    except Exception as e:
        logger.error("[Retraining] Calibration model training failed: %s", e)
        return None


def train_outcome_model(records: list[dict[str, Any]]) -> Optional[Any]:
    """
    Train a multi-output classifier to predict likely attack outcomes.
    Uses summary data from completed OdinForge breach chain assessments as labels.
    """
    outcome_records = [
        r for r in records
        if r.get("summary", {}).get("breach_outcome")
    ]

    if len(outcome_records) < 50:
        logger.warning("[Retraining] Not enough outcome data (%d records, need 50)", len(outcome_records))
        return None

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder

        X = np.array([r["features"] for r in outcome_records], dtype=np.float32)
        y_raw = [r["summary"].get("breach_outcome", "unknown") for r in outcome_records]

        le = LabelEncoder()
        y = le.fit_transform(y_raw)

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X, y)
        model.classes_ = le.classes_  # attach for decode

        logger.info("[Retraining] Outcome model trained on %d records, %d classes", len(outcome_records), len(le.classes_))
        return model

    except Exception as e:
        logger.error("[Retraining] Outcome model training failed: %s", e)
        return None


def compute_baselines(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute per-industry, per-size baseline statistics for anomaly detection.
    Returns {"{industry}:{size}": {metric: {mean, std}}} structure.
    """
    import statistics

    buckets: dict[str, list[dict]] = {}
    for r in records:
        key = f"{r.get('industry', 'general')}:{r.get('org_size', 'unknown')}"
        buckets.setdefault(key, []).append(r)

    baselines: dict[str, Any] = {"_version": datetime.now(timezone.utc).isoformat()}

    for bucket_key, bucket_records in buckets.items():
        if len(bucket_records) < 10:
            continue

        scores = [r["risk_score_actual"] for r in bucket_records]
        n_findings = [max(sum(r["features"][2:7]), 0.01) for r in bucket_records]
        kev_counts = [r["features"][1] * n for r, n in zip(bucket_records, n_findings)]
        critical_ratios = [r["features"][2] for r in bucket_records]

        def safe_stats(values: list[float]) -> dict[str, float]:
            if len(values) < 2:
                return {"mean": values[0] if values else 0.0, "std": 0.0}
            return {
                "mean": statistics.mean(values),
                "std":  statistics.stdev(values),
            }

        baselines[bucket_key] = {
            "composite_score":  safe_stats(scores),
            "kev_count":        safe_stats(kev_counts),
            "critical_ratio":   safe_stats(critical_ratios),
            "sample_count":     len(bucket_records),
        }

    logger.info("[Retraining] Computed baselines for %d industry/size buckets", len(baselines) - 1)
    return baselines


# =============================================================================
# CELERY TASK
# =============================================================================

async def retrain_all_models_async(db_session, redis_client) -> dict[str, str]:
    """
    Async implementation — called by the Celery task.
    Returns dict of {model_name: "trained" | "skipped" | "failed"}
    """
    from intelligence.tier2 import (
        MODEL_KEY_CALIBRATION, MODEL_KEY_OUTCOME,
        MODEL_KEY_BASELINES, MODEL_VERSION_KEY,
    )

    results: dict[str, str] = {}
    timestamp = datetime.now(timezone.utc).isoformat()

    # Extract training data
    records = await extract_training_data(db_session, lookback_days=90)
    if len(records) < 20:
        logger.warning("[Retraining] Insufficient data (%d records) — skipping all models", len(records))
        return {"all": "skipped_insufficient_data"}

    # Train calibration model
    cal_model = train_calibration_model(records)
    if cal_model:
        redis_client.set(MODEL_KEY_CALIBRATION, pickle.dumps(cal_model))
        results["calibration"] = "trained"
    else:
        results["calibration"] = "skipped"

    # Train outcome model
    out_model = train_outcome_model(records)
    if out_model:
        redis_client.set(MODEL_KEY_OUTCOME, pickle.dumps(out_model))
        results["outcome"] = "trained"
    else:
        results["outcome"] = "skipped"

    # Compute anomaly baselines
    baselines = compute_baselines(records)
    redis_client.set(MODEL_KEY_BASELINES, json.dumps(baselines))
    results["baselines"] = "computed"

    # Update version manifest
    versions = {
        "calibration": f"v_{timestamp}",
        "outcome":     f"v_{timestamp}",
        "baselines":   f"v_{timestamp}",
        "retrained_at": timestamp,
        "record_count": len(records),
    }
    redis_client.set(MODEL_VERSION_KEY, json.dumps(versions))

    logger.info("[Retraining] Complete: %s", results)
    return results


def retrain_all_models(db_url: str, redis_url: str) -> dict[str, str]:
    """
    Synchronous wrapper for the Celery task.
    Celery tasks must be synchronous; this runs the async code in an event loop.
    """
    import asyncio
    import redis as redis_lib
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    async def _run():
        engine = create_async_engine(db_url)
        Session = async_sessionmaker(engine, expire_on_commit=False)
        r_client = redis_lib.from_url(redis_url)

        async with Session() as session:
            result = await retrain_all_models_async(session, r_client)

        await engine.dispose()
        return result

    return asyncio.run(_run())
