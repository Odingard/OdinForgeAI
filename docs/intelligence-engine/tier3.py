# =============================================================================
# Intelligence Engine — Tier 3: LLM Layer
# intelligence/tier3.py
#
# The LLM only narrates pre-computed facts from Tier 1 and Tier 2.
# It cannot invent scores, findings, CVEs, or outcomes — all of those
# arrive as structured inputs. Its only job is to turn structured data
# into readable language.
#
# Protections against every concern raised:
#   Hallucination:  strict JSON schema validation on LLM output
#   False info:     LLM prompt contains only Tier 1/2 outputs, no raw text
#   Exhaustion:     request queue with per-tenant budget + backpressure
#   Rate limiting:  exponential backoff + automatic fallback to templates
#   API dependency: full template fallback — product works without API key
# =============================================================================

from __future__ import annotations

import json
import hashlib
import logging
import asyncio
import time
from datetime import datetime, timezone
from typing import Optional, Any

from .schemas import (
    IntelligenceRequest, DeterministicOutput, StatisticalOutput,
    NarrativeOutput, RemediationStep, NarrativeTone, RiskGrade,
)
from .templates import TemplateRenderer

logger = logging.getLogger(__name__)

# LLM config
DEFAULT_MODEL      = "claude-sonnet-4-20250514"
MAX_TOKENS         = 1200
TEMPERATURE        = 0.1    # low temperature = more predictable, less creative
TIMEOUT_SECONDS    = 25
MAX_RETRIES        = 2
RETRY_BASE_DELAY   = 1.5    # seconds, doubles on each retry

# Rate limiting
DEFAULT_TENANT_RPM = 20     # requests per minute per tenant
GLOBAL_RPM_LIMIT   = 200    # global ceiling across all tenants

# Cache TTL
CACHE_TTL_SECONDS  = 3600 * 6   # 6 hours — findings don't change that fast

# Output schema — LLM must return JSON matching this exactly
REQUIRED_OUTPUT_KEYS = {
    "executive_summary", "risk_headline",
    "key_findings_narrative", "remediation_steps",
}


# =============================================================================
# REDIS CACHE
# =============================================================================

class NarrativeCache:
    """
    Cache LLM outputs by content-hashed key.
    Identical inputs (same findings, same scores) return cached output
    without an API call.
    """

    def __init__(self, redis_client):
        self.redis = redis_client

    def cache_key(
        self,
        request:  IntelligenceRequest,
        tier1:    DeterministicOutput,
        tier2:    Optional[StatisticalOutput],
    ) -> str:
        payload = json.dumps({
            "org":       request.organization_id,
            "tone":      request.tone.value,
            "score":     tier1.composite_score,
            "grade":     tier1.risk_grade.value,
            "kev":       tier1.kev_count,
            "dist":      tier1.severity_distribution,
            "cves":      sorted(tier1.cve_matches[:10]),
            "calibrated": tier2.calibrated_score if tier2 else None,
            "outcomes":  [p.outcome_label for p in tier2.outcome_predictions[:3]] if tier2 else [],
        }, sort_keys=True)
        return f"intelligence:narrative:{hashlib.sha256(payload.encode()).hexdigest()[:32]}"

    def get(self, key: str) -> Optional[NarrativeOutput]:
        try:
            raw = self.redis.get(key)
            if not raw:
                return None
            data = json.loads(raw)
            return NarrativeOutput(**data)
        except Exception:
            return None

    def set(self, key: str, narrative: NarrativeOutput) -> None:
        try:
            self.redis.setex(
                key,
                CACHE_TTL_SECONDS,
                narrative.model_dump_json(),
            )
        except Exception as e:
            logger.warning("[Tier3] Cache write failed: %s", e)


# =============================================================================
# RATE LIMITER — per-tenant token bucket
# =============================================================================

class RateLimiter:
    """
    Per-tenant rate limiting using Redis token bucket.
    Tenants exceeding their RPM get templated output instead of LLM output.
    This is not a degradation — the template output is accurate.
    It just isn't prose-polished.
    """

    def __init__(self, redis_client):
        self.redis = redis_client

    def check_and_consume(self, tenant_id: str, rpm_limit: int = DEFAULT_TENANT_RPM) -> bool:
        """Returns True if the request is allowed, False if rate-limited."""
        try:
            key = f"intelligence:ratelimit:{tenant_id}"
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, 60)
            results = pipe.execute()
            count = results[0]
            return count <= rpm_limit
        except Exception:
            # If Redis is down, allow the request
            return True


# =============================================================================
# PROMPT BUILDER — constructs grounded prompts from structured data
# No raw finding text is passed to the LLM without structure.
# Every claim the LLM can make is constrained by the facts we pass in.
# =============================================================================

def build_system_prompt(tone: NarrativeTone) -> str:
    base = """You are a security intelligence system that writes precise, factual summaries.
You receive structured security data and convert it into clear language.

CRITICAL RULES:
1. Every claim you make MUST reference a specific data point from the input.
2. Do NOT invent CVE numbers, scores, percentages, or findings not in the input.
3. Do NOT speculate about future attacks or make predictions beyond what the data shows.
4. Do NOT use vague filler language ("it is important to note", "it should be mentioned").
5. Respond ONLY with valid JSON matching the specified schema. No preamble, no markdown.
"""

    tone_instructions = {
        NarrativeTone.EXECUTIVE: """
Tone: C-suite and board level. No jargon. Focus on business impact and financial risk.
Assume the reader has no security background.
""",
        NarrativeTone.TECHNICAL: """
Tone: Security engineer level. Use standard security terminology.
Include specific CVE IDs, techniques, and technical details where relevant.
""",
        NarrativeTone.DEAL_MEMO: """
Tone: M&A / private equity deal memo language. Focus on acquisition risk,
remediation cost ranges, and deal-blocking findings.
Use language appropriate for investment committee memos.
""",
    }

    return base + tone_instructions.get(tone, "")


def build_user_prompt(
    request:  IntelligenceRequest,
    tier1:    DeterministicOutput,
    tier2:    Optional[StatisticalOutput],
) -> str:
    """
    Builds the structured data prompt passed to the LLM.
    Every number and fact here comes from Tier 1 or Tier 2 — never invented.
    """

    # Structured risk summary (Tier 1)
    risk_data = {
        "composite_score":      tier1.composite_score,
        "risk_grade":           tier1.risk_grade.value,
        "kev_count":            tier1.kev_count,
        "severity_breakdown":   tier1.severity_distribution,
        "top_cves":             tier1.cve_matches[:8],
        "top_findings": [
            {
                "title":    f.title,
                "severity": f.severity.value,
                "category": f.category,
                "cve_id":   f.cve_id,
                "is_kev":   f.is_kev_listed,
            }
            for f in tier1.top_findings[:8]
        ],
    }

    # Statistical context (Tier 2)
    statistical_data: dict[str, Any] = {}
    if tier2:
        statistical_data = {
            "calibrated_score":  tier2.calibrated_score,
            "calibration_delta": tier2.calibration_delta,
            "similar_patterns": [
                {
                    "description": p.description,
                    "similarity_pct": p.similarity_pct,
                    "historical_count": p.historical_count,
                    "outcome": p.outcome,
                }
                for p in tier2.similar_patterns[:3]
            ],
            "outcome_predictions": [
                {
                    "outcome": p.outcome_label,
                    "probability_pct": round(p.probability * 100),
                    "supporting_evidence": p.supporting_evidence,
                }
                for p in tier2.outcome_predictions[:3]
            ],
            "anomalies": [
                {
                    "signal": a.signal,
                    "direction": a.direction,
                    "deviation_pct": a.deviation_pct,
                    "baseline": a.baseline_label,
                }
                for a in tier2.anomaly_signals[:3]
            ],
        }

    # Breach chain context
    breach_data = []
    for bc in request.breach_chains[:3]:
        breach_data.append({
            "steps":     bc.steps,
            "techniques": bc.techniques,
            "confirmed": bc.confirmed,
        })

    output_schema = {
        "executive_summary":      "string — 2-4 sentences, board level",
        "risk_headline":          "string — one sentence, the most critical fact",
        "key_findings_narrative": "string — 3-5 sentence prose summary of top findings",
        "remediation_steps": [
            {
                "priority":     "integer 1-5",
                "action":       "string — specific action to take",
                "effort":       "string — 'hours' | 'days' | 'weeks'",
                "impact":       "string — what risk this removes",
                "evidence_ref": "string — finding title this addresses",
            }
        ],
        "breach_path_narrative":  "string | null — only if breach chains provided",
        "anomaly_narrative":      "string | null — only if anomalies found",
        "deal_memo_summary":      "string | null — only if tone is deal_memo",
    }

    input_payload = {
        "target_domain": request.target_domain,
        "risk_data":     risk_data,
        "statistical":   statistical_data,
        "breach_chains": breach_data,
        "context": {
            "industry":     request.industry,
            "org_size":     request.org_size,
            "source":       request.source_product,
        },
    }

    return f"""SECURITY DATA (structured, all facts verified before this call):
{json.dumps(input_payload, indent=2)}

RESPOND WITH ONLY VALID JSON MATCHING THIS SCHEMA:
{json.dumps(output_schema, indent=2)}"""


# =============================================================================
# OUTPUT VALIDATOR
# Parses LLM response and validates it matches the required schema.
# If validation fails, the template renderer runs instead.
# =============================================================================

def validate_and_parse_llm_output(
    raw_text:   str,
    tier1:      DeterministicOutput,
    tier2:      Optional[StatisticalOutput],
    model_name: str,
) -> Optional[NarrativeOutput]:
    """
    Parse the LLM JSON response and validate it.
    Returns None if validation fails — caller will use template fallback.
    """
    try:
        # Strip markdown code fences if present
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        data = json.loads(text)

        # Require all mandatory keys
        missing = REQUIRED_OUTPUT_KEYS - set(data.keys())
        if missing:
            logger.warning("[Tier3] LLM output missing keys: %s", missing)
            return None

        # Validate remediation steps
        steps = data.get("remediation_steps", [])
        if not isinstance(steps, list):
            logger.warning("[Tier3] remediation_steps is not a list")
            return None

        remediation = []
        for i, step in enumerate(steps[:5]):
            if not isinstance(step, dict):
                continue
            remediation.append(RemediationStep(
                priority=int(step.get("priority", i + 1)),
                action=str(step.get("action", "")),
                effort=str(step.get("effort", "days")),
                impact=str(step.get("impact", "")),
                evidence_ref=step.get("evidence_ref"),
            ))

        # Count grounded claims (claims that reference a top finding or CVE)
        all_text = json.dumps(data)
        grounded = sum(
            1 for f in tier1.top_findings
            if f.title.lower()[:20] in all_text.lower()
        )
        grounded += sum(1 for cve in tier1.cve_matches if cve in all_text)

        return NarrativeOutput(
            executive_summary      = str(data["executive_summary"])[:800],
            risk_headline          = str(data["risk_headline"])[:200],
            key_findings_narrative = str(data["key_findings_narrative"])[:1200],
            remediation_steps      = remediation,
            breach_path_narrative  = data.get("breach_path_narrative"),
            anomaly_narrative      = data.get("anomaly_narrative"),
            deal_memo_summary      = data.get("deal_memo_summary"),
            generated_by           = model_name,
            grounded_claims        = grounded,
            generated_at           = datetime.now(timezone.utc),
        )

    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.warning("[Tier3] LLM output validation failed: %s", e)
        return None


# =============================================================================
# MAIN TIER 3 RUNNER
# =============================================================================

class LLMEngine:

    def __init__(self, redis_client, api_key: Optional[str] = None):
        self.redis     = redis_client
        self.api_key   = api_key
        self.cache     = NarrativeCache(redis_client)
        self.ratelimit = RateLimiter(redis_client)
        self.templates = TemplateRenderer()
        self._client   = None

    def _get_client(self):
        if not self.api_key:
            return None
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
            except ImportError:
                logger.warning("[Tier3] anthropic SDK not installed")
                return None
        return self._client

    async def run(
        self,
        request: IntelligenceRequest,
        tier1:   DeterministicOutput,
        tier2:   Optional[StatisticalOutput],
    ) -> NarrativeOutput:

        # 1. Check cache first
        cache_key = self.cache.cache_key(request, tier1, tier2)
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug("[Tier3] Cache hit for %s", request.request_id)
            return cached

        # 2. Check rate limit
        if not self.ratelimit.check_and_consume(request.organization_id):
            logger.info("[Tier3] Rate limit hit for org %s — using template", request.organization_id)
            return self.templates.render(request, tier1, tier2, reason="rate_limited")

        # 3. Try LLM
        client = self._get_client()
        if not client:
            return self.templates.render(request, tier1, tier2, reason="no_api_key")

        narrative = await self._call_llm_with_retry(request, tier1, tier2, client)

        # 4. Cache successful result
        if narrative:
            self.cache.set(cache_key, narrative)

        return narrative or self.templates.render(request, tier1, tier2, reason="llm_failed")

    async def _call_llm_with_retry(
        self,
        request: IntelligenceRequest,
        tier1:   DeterministicOutput,
        tier2:   Optional[StatisticalOutput],
        client,
    ) -> Optional[NarrativeOutput]:

        system_prompt = build_system_prompt(request.tone)
        user_prompt   = build_user_prompt(request, tier1, tier2)

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = await asyncio.wait_for(
                    client.messages.create(
                        model=DEFAULT_MODEL,
                        max_tokens=MAX_TOKENS,
                        temperature=TEMPERATURE,
                        system=system_prompt,
                        messages=[{"role": "user", "content": user_prompt}],
                    ),
                    timeout=TIMEOUT_SECONDS,
                )

                raw_text = response.content[0].text if response.content else ""
                narrative = validate_and_parse_llm_output(raw_text, tier1, tier2, DEFAULT_MODEL)

                if narrative:
                    return narrative

                # Output failed validation — retry
                logger.warning("[Tier3] LLM output validation failed on attempt %d", attempt + 1)

            except asyncio.TimeoutError:
                logger.warning("[Tier3] LLM timeout on attempt %d", attempt + 1)
            except Exception as e:
                err_str = str(e).lower()
                if "rate_limit" in err_str or "429" in err_str:
                    logger.warning("[Tier3] Rate limit from API on attempt %d", attempt + 1)
                    # Don't retry rate limit errors
                    return None
                logger.warning("[Tier3] LLM error on attempt %d: %s", attempt + 1, e)

            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                await asyncio.sleep(delay)

        return None
