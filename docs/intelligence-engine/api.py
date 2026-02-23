# =============================================================================
# Intelligence Engine — API Wrapper
# intelligence/api.py
#
# Thin FastAPI server. OdinForge (TypeScript) calls this over HTTP.
# Mimir imports the engine directly (same process, no HTTP hop).
#
# Deploy alongside Mimir — it shares the same Postgres and Redis.
# Runs on port 8001 (separate from Mimir's port 8000).
#
# In production: internal network only. Not exposed externally.
# Auth: shared secret header (X-Internal-Secret) — not customer-facing auth.
# =============================================================================

from __future__ import annotations

import os
import uuid
import logging
from contextlib import asynccontextmanager
from typing import Optional

import redis
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from .schemas import IntelligenceRequest, IntelligenceResponse, OutputMode, NarrativeTone
from .engine import IntelligenceEngine

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIG — from environment variables
# =============================================================================

ENTITY_GRAPH_DATABASE_URL = os.environ["ENTITY_GRAPH_DATABASE_URL"]
REDIS_URL                  = os.environ.get("REDIS_URL", "redis://localhost:6379")
ANTHROPIC_API_KEY          = os.environ.get("ANTHROPIC_API_KEY")
INTERNAL_SECRET            = os.environ.get("INTELLIGENCE_INTERNAL_SECRET", "dev-secret-change-in-prod")
PORT                       = int(os.environ.get("INTELLIGENCE_PORT", 8001))


# =============================================================================
# APP LIFECYCLE
# =============================================================================

engine_instance: Optional[IntelligenceEngine] = None
db_session_factory = None
redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine_instance, db_session_factory, redis_client

    # DB
    pg_engine = create_async_engine(ENTITY_GRAPH_DATABASE_URL, pool_size=5, max_overflow=10)
    db_session_factory = async_sessionmaker(pg_engine, expire_on_commit=False)

    # Redis
    redis_client = redis.from_url(REDIS_URL, decode_responses=False)

    # Intelligence engine
    engine_instance = IntelligenceEngine(
        redis_client=redis_client,
        anthropic_api_key=ANTHROPIC_API_KEY,
    )

    logger.info("[Intelligence API] Started on port %d", PORT)
    logger.info("[Intelligence API] LLM: %s", "enabled" if ANTHROPIC_API_KEY else "disabled — template fallback active")
    yield

    await pg_engine.dispose()
    redis_client.close()


app = FastAPI(
    title="Six Sense Intelligence Engine",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,   # internal API — no public docs
    redoc_url=None,
)


# =============================================================================
# AUTH — internal shared secret
# Not customer-facing. OdinForge is the only caller.
# =============================================================================

async def verify_internal_secret(x_internal_secret: str = Header(...)) -> None:
    if x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


# =============================================================================
# DB DEPENDENCY
# =============================================================================

async def get_db():
    async with db_session_factory() as session:
        yield session


# =============================================================================
# ROUTES
# =============================================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "llm_enabled": ANTHROPIC_API_KEY is not None,
    }


@app.post(
    "/analyze",
    response_model=IntelligenceResponse,
    dependencies=[Depends(verify_internal_secret)],
)
async def analyze(
    request: IntelligenceRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Main analysis endpoint. Called by OdinForge after completing an AEV evaluation.
    Also called by Mimir after completing an OSINT assessment.
    """
    if not request.request_id:
        request = request.model_copy(update={"request_id": str(uuid.uuid4())})

    try:
        response = await engine_instance.analyze(request, db_session=db)
        return response
    except Exception as e:
        logger.error("[Intelligence API] Analysis failed for request %s: %s", request.request_id, e)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post(
    "/analyze/fast",
    response_model=IntelligenceResponse,
    dependencies=[Depends(verify_internal_secret)],
)
async def analyze_fast(request: IntelligenceRequest):
    """
    Tier 1 only — deterministic scoring with no DB or LLM calls.
    Use for real-time scoring during active scans where latency matters.
    Typical response time: <10ms.
    """
    fast_request = request.model_copy(update={"mode": OutputMode.DETERMINISTIC})
    try:
        response = await engine_instance.analyze(fast_request, db_session=None)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/analyze/narrative",
    response_model=IntelligenceResponse,
    dependencies=[Depends(verify_internal_secret)],
)
async def analyze_narrative(
    request: IntelligenceRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Full analysis with LLM narrative. Use for report generation.
    Slower (300-2000ms depending on cache hit). Use async/background job pattern.
    """
    full_request = request.model_copy(update={"mode": OutputMode.FULL})
    try:
        response = await engine_instance.analyze(full_request, db_session=db)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# ERROR HANDLER
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("[Intelligence API] Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal error", "detail": str(exc)},
    )


# =============================================================================
# ENTRYPOINT
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("intelligence.api:app", host="0.0.0.0", port=PORT, reload=False)
