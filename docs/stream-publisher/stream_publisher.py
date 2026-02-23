# =============================================================================
# Task 03 — Stream Publisher (Mimir side)
# src/mimir/services/stream_publisher.py
#
# Publishes a MimirAssessmentComplete event to a Redis Stream after every
# assessment finishes. OdinForge's stream consumer reads this and auto-queues
# a targeted AEV validation job against the top-risk findings.
#
# Redis Streams over plain pub/sub because:
#   - Durable: events persist if OdinForge is temporarily down
#   - Consumer groups: OdinForge acks each message — no lost events
#   - Replayable: can replay from any position for debugging
#   - No polling: OdinForge uses XREADGROUP BLOCK for instant delivery
#
# Wire in: src/mimir/services/assessment_service.py
#   After entity graph sync and intelligence engine run:
#     await stream_publisher.publish_assessment_complete(assessment, summary, entity_id, intelligence_response)
# =============================================================================

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional, Any
from uuid import UUID

import redis.asyncio as aioredis
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Stream name — shared contract between Mimir and OdinForge
# Never change this without updating stream_consumer.ts simultaneously
STREAM_NAME        = "sixsense:events:mimir_assessment_complete"
STREAM_MAXLEN      = 10_000      # trim stream to last 10k events (rolling window)
EVENT_VERSION      = "1.0"


# =============================================================================
# EVENT SCHEMA
# Pydantic model defines exactly what goes into the stream.
# OdinForge deserializes this on the other side — keep fields stable.
# =============================================================================

class TopRiskFinding(BaseModel):
    finding_id:    str
    title:         str
    category:      str
    severity:      str
    risk_score:    Optional[float]
    cve_id:        Optional[str]
    is_kev_listed: bool
    entity_id:     Optional[str]   # entity_graph entity this finding belongs to


class MimirAssessmentCompleteEvent(BaseModel):
    # Event metadata
    event_version:   str = EVENT_VERSION
    event_id:        str              # uuid — for idempotency on OdinForge side
    published_at:    str              # ISO timestamp

    # Assessment identity
    assessment_id:   str
    organization_id: str
    target_domain:   str
    entity_id:       str              # entity_graph.entities.id for the root domain

    # Risk summary — OdinForge uses this to decide whether to act
    risk_grade:      str              # A/B/C/D/F
    risk_score:      float            # 0–100, calibrated if intelligence engine ran
    kev_count:       int
    critical_count:  int
    high_count:      int
    total_findings:  int

    # Top findings — OdinForge targets these in its validation job
    # Sorted by risk_score descending, capped at 10
    top_risk_findings: list[TopRiskFinding]

    # Industry / context for intelligence engine calibration on OdinForge side
    industry:        Optional[str]
    company_name:    Optional[str]

    # Source ref — lets OdinForge write back to Mimir if needed
    mimir_assessment_id: str


# =============================================================================
# PUBLISHER
# =============================================================================

class StreamPublisher:

    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client

    async def publish_assessment_complete(
        self,
        assessment_id:    str,
        organization_id:  str,
        target_domain:    str,
        entity_id:        str,
        risk_grade:       str,
        risk_score:       float,
        kev_count:        int,
        critical_count:   int,
        high_count:       int,
        total_findings:   int,
        top_findings:     list[dict[str, Any]],
        industry:         Optional[str] = None,
        company_name:     Optional[str] = None,
    ) -> str:
        """
        Publish a MimirAssessmentComplete event to the Redis Stream.
        Returns the Redis stream entry ID (e.g. "1699999999999-0").

        Called by assessment_service.py after:
          1. All 12 OSINT modules complete
          2. Entity graph writer has synced the assessment
          3. Intelligence engine has run and produced a calibrated score

        Only fires for risk grades C, D, or F — A and B don't warrant
        an automatic OdinForge validation pass.
        """
        # Skip auto-triggering for low-risk grades — no point validating clean targets
        if risk_grade in ("A", "B"):
            logger.info(
                "[StreamPublisher] Skipping event for %s — grade %s below trigger threshold",
                target_domain, risk_grade,
            )
            return ""

        import uuid
        event = MimirAssessmentCompleteEvent(
            event_id        = str(uuid.uuid4()),
            published_at    = datetime.now(timezone.utc).isoformat(),
            assessment_id   = assessment_id,
            organization_id = organization_id,
            target_domain   = target_domain,
            entity_id       = entity_id,
            risk_grade      = risk_grade,
            risk_score      = risk_score,
            kev_count       = kev_count,
            critical_count  = critical_count,
            high_count      = high_count,
            total_findings  = total_findings,
            top_risk_findings = [
                TopRiskFinding(**f) for f in top_findings[:10]
            ],
            industry        = industry,
            company_name    = company_name,
            mimir_assessment_id = assessment_id,
        )

        # Redis Streams require flat string fields — serialize event as JSON string
        entry_id = await self.redis.xadd(
            STREAM_NAME,
            {"event": event.model_dump_json()},
            maxlen=STREAM_MAXLEN,
            approximate=True,   # MAXLEN ~ for performance
        )

        logger.info(
            "[StreamPublisher] Published assessment_complete for %s "
            "(grade=%s score=%.1f findings=%d) — stream entry %s",
            target_domain, risk_grade, risk_score, total_findings, entry_id,
        )

        return entry_id

    async def ensure_consumer_group(self) -> None:
        """
        Create the OdinForge consumer group if it doesn't exist.
        Safe to call on every startup — XGROUP CREATE with MKSTREAM.
        Called once by Mimir at startup before publishing anything.
        """
        try:
            await self.redis.xgroup_create(
                STREAM_NAME,
                "odinforge-consumers",
                id="$",          # only deliver new messages to new consumers
                mkstream=True,   # create stream if it doesn't exist
            )
            logger.info("[StreamPublisher] Consumer group 'odinforge-consumers' created")
        except Exception as e:
            if "BUSYGROUP" in str(e):
                # Group already exists — this is fine
                pass
            else:
                logger.warning("[StreamPublisher] Consumer group setup warning: %s", e)


# =============================================================================
# CONVENIENCE FUNCTION
# Called from assessment_service.py with the full assessment context
# =============================================================================

async def publish_completed_assessment(
    redis_client:        aioredis.Redis,
    assessment_id:       str,
    organization_id:     str,
    target_domain:       str,
    entity_id:           str,
    summary,             # AssessmentSummary model
    top_eg_findings:     list[dict[str, Any]],
    intelligence_response = None,   # IntelligenceResponse from Task 02 engine
    industry:            Optional[str] = None,
    company_name:        Optional[str] = None,
) -> str:
    """
    Top-level convenience function for assessment_service.py.
    Assembles the event from available context and publishes it.

    Example call in assessment_service.py:

        from mimir.services.stream_publisher import publish_completed_assessment

        await publish_completed_assessment(
            redis_client    = self.redis,
            assessment_id   = str(assessment.id),
            organization_id = str(assessment.organization_id),
            target_domain   = assessment.target.domain,
            entity_id       = entity_id,
            summary         = summary,
            top_eg_findings = top_findings_for_stream,
            intelligence_response = intelligence_response,
            industry        = assessment.target.metadata_.get("industry"),
            company_name    = assessment.target.company_name,
        )
    """
    # Use calibrated score from intelligence engine if available
    if intelligence_response and hasattr(intelligence_response, "final_score"):
        risk_score = intelligence_response.final_score
    else:
        risk_score = float(summary.risk_score or 50.0)

    publisher = StreamPublisher(redis_client)
    return await publisher.publish_assessment_complete(
        assessment_id   = assessment_id,
        organization_id = organization_id,
        target_domain   = target_domain,
        entity_id       = entity_id,
        risk_grade      = summary.deal_risk_grade or "C",
        risk_score      = risk_score,
        kev_count       = summary.kev_count or 0,
        critical_count  = summary.critical_count or 0,
        high_count      = summary.high_count or 0,
        total_findings  = summary.total_findings or 0,
        top_findings    = top_eg_findings,
        industry        = industry,
        company_name    = company_name,
    )
