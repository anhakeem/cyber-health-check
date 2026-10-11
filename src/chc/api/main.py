"""FastAPI application for Cyber Health Check (architecture §4 contract).

Endpoints:
  POST /api/v1/check-url      -> reputation verdict for a URL
  POST /api/v1/check-domain   -> reputation verdict for a bare domain
  GET  /api/v1/health         -> liveness + feed status

Errors follow the single shape in architecture §5:
  {"error": {"code": ..., "message": ..., "details": ...}}

SSRF note: the service resolves reputation from feeds/cache only and NEVER
fetches the target URL. Private/reserved indicators are rejected at the
boundary by the reputation service's normalize helpers.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from chc.models import CheckResponse

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1"


class CheckUrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    user_id: str | None = Field(default=None, max_length=128)

    @field_validator("url")
    @classmethod
    def _scheme(cls, v: str) -> str:
        if not v.strip().lower().startswith(("http://", "https://")):
            raise ValueError("url must be http(s)")
        return v.strip()


class CheckDomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    user_id: str | None = Field(default=None, max_length=128)


def _error(status: int, code: str, message: str, details: dict | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "details": details or {}}},
    )


def _safe_errors(exc: RequestValidationError) -> list[dict]:
    out = []
    for e in exc.errors():
        item = {k: v for k, v in e.items() if k in ("type", "loc", "msg")}
        item["loc"] = [str(x) for x in item.get("loc", [])]
        item["msg"] = str(item.get("msg", ""))
        out.append(item)
    return out


def create_app(reputation_factory=None, alert_store_factory=None) -> FastAPI:
    app = FastAPI(title="Cyber Health Check API", version="1.0.0")

    if reputation_factory is None:
        reputation_factory = _default_reputation_factory
    if alert_store_factory is None:
        alert_store_factory = _default_alert_store_factory

    cache: dict[str, object] = {}

    def get_service():
        if "svc" not in cache:
            cache["svc"] = reputation_factory()
        return cache["svc"]

    def get_alert_store():
        if "alerts" not in cache:
            cache["alerts"] = alert_store_factory()
        return cache["alerts"]

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        return _error(422, "VALIDATION_ERROR", "invalid request", {"errors": _safe_errors(exc)})

    def _verdict_response(indicator: str, kind: str):
        try:
            v = get_service().check(indicator, kind)
        except ValueError as exc:
            # A rejected indicator (bad scheme, private IP) is a client error.
            return _error(422, "VALIDATION_ERROR", str(exc))
        except Exception as exc:  # noqa: BLE001
            log.error("check failed: %s", type(exc).__name__)
            return _error(502, "UPSTREAM_ERROR", "reputation lookup failed")
        return CheckResponse(
            indicator=indicator,
            verdict=v.verdict,
            category=v.category,
            confidence=v.confidence,
            sources=list(v.sources),
            cached=getattr(v, "cached", False),
        )

    @app.post(f"{API_PREFIX}/check-url", response_model=CheckResponse)
    async def check_url(req: CheckUrlRequest):
        return _verdict_response(req.url, "url")

    @app.post(f"{API_PREFIX}/check-domain", response_model=CheckResponse)
    async def check_domain(req: CheckDomainRequest):
        return _verdict_response(req.domain, "domain")

    @app.get(f"{API_PREFIX}/alerts")
    async def alerts(org_id: str, severity: str | None = None, since: str | None = None,
                     limit: int = 50, offset: int = 0):
        store = get_alert_store()
        rows = store.list(org_id=org_id, severity=severity, since=since,
                          limit=limit, offset=offset)
        return {
            "alerts": rows,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": store.count(org_id=org_id, severity=severity),
            },
        }

    @app.get(f"{API_PREFIX}/health")
    async def health():
        return {"status": "ok"}

    return app


def _default_reputation_factory():
    """Build the real service from env-configured, commercially-safe feeds."""
    from chc.feeds.ingestor import FeedIngestor
    from chc.reputation import ReputationService

    tier = "dev"  # override with a real tier + gated feeds before production
    ingestor = FeedIngestor(tier=tier)
    # Feed registration happens in deployment wiring once API keys are set;
    # the service is constructed from the ingestor so gating always applies.
    return ReputationService(feeds=ingestor)


def _default_alert_store_factory():
    """Alert store backed by the configured SQLite database."""
    import os

    from chc.alerts import AlertStore

    return AlertStore(db_path=os.environ.get("ALERTS_DB", "./cyber_health_check.db"))


app = create_app()
