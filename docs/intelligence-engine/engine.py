# =============================================================================
# Intelligence Engine — Orchestrator
# intelligence/engine.py
#
# Runs the three tiers in sequence and assembles the final response.
# This is the single entry point both OdinForge and Mimir call.
# =============================================================================

from __future__ import annotations

import time
import logging
import uuid
from typing import Optional

from .schemas import (
    IntelligenceRequest, IntelligenceResponse, OutputMode,
)
from .tier1 import DeterministicEngine
from .tier2 import StatisticalEngine
from .tier3 import LLMEngine

logger = logging.getLogger(__name__)


class IntelligenceEngine:
    """
    Orchestrates the three-tier intelligence pipeline.

    Tier 1 always runs — it is pure deterministic scoring.
    Tier 2 runs when mode != DETERMINISTIC.
    Tier 3 runs when mode == FULL or NARRATIVE.

    Each tier can fail independently without bringing down the others.
    A Tier 2 failure produces Tier 1 output only.
    A Tier 3 failure produces the template fallback.
    """

    def __init__(
        self,
        redis_client,
        anthropic_api_key: Optional[str] = None,
    ):
        self.tier1 = DeterministicEngine()
        self.tier2 = StatisticalEngine(redis_client)
        self.tier3 = LLMEngine(redis_client, api_key=anthropic_api_key)

    async def analyze(
        self,
        request:   IntelligenceRequest,
        db_session = None,   # required for Tier 2 pgvector queries
    ) -> IntelligenceResponse:

        total_start = time.monotonic()

        # -- TIER 1 — always runs --
        t1_start = time.monotonic()
        tier1_output = self.tier1.run(request)
        t1_ms = int((time.monotonic() - t1_start) * 1000)

        # -- TIER 2 — statistical --
        tier2_output = None
        t2_ms = None

        if request.mode != OutputMode.DETERMINISTIC and db_session is not None:
            try:
                t2_start = time.monotonic()
                tier2_output = await self.tier2.run(request, tier1_output, db_session)
                t2_ms = int((time.monotonic() - t2_start) * 1000)
            except Exception as e:
                logger.error("[Engine] Tier 2 failed for request %s: %s", request.request_id, e)

        # -- TIER 3 — LLM narrative --
        narrative_output = None
        t3_ms = None

        if request.mode in (OutputMode.FULL, OutputMode.NARRATIVE):
            try:
                t3_start = time.monotonic()
                narrative_output = await self.tier3.run(request, tier1_output, tier2_output)
                t3_ms = int((time.monotonic() - t3_start) * 1000)
            except Exception as e:
                logger.error("[Engine] Tier 3 failed for request %s: %s", request.request_id, e)

        total_ms = int((time.monotonic() - total_start) * 1000)

        logger.info(
            "[Engine] request=%s org=%s mode=%s score=%.1f t1=%dms t2=%s t3=%s total=%dms",
            request.request_id,
            request.organization_id,
            request.mode.value,
            tier1_output.composite_score,
            t1_ms,
            f"{t2_ms}ms" if t2_ms else "skip",
            f"{t3_ms}ms" if t3_ms else "skip",
            total_ms,
        )

        return IntelligenceResponse(
            request_id      = request.request_id,
            organization_id = request.organization_id,
            entity_id       = request.entity_id,
            deterministic   = tier1_output,
            statistical     = tier2_output,
            narrative       = narrative_output,
            tier1_ms        = t1_ms,
            tier2_ms        = t2_ms,
            tier3_ms        = t3_ms,
            total_ms        = total_ms,
        )
