"""
WAF main module – ASGI entry point and inspection pipeline orchestrator.

Creates the FastAPI app and a catch-all route that runs every inbound
request through the layered inspection pipeline described in the
architecture document.  Each stage is a separate function that returns
``None`` (pass) or a ``Response`` (block).  The pipeline short-circuits
on the first block.
"""

from __future__ import annotations

import logging
import uuid
from ipaddress import ip_address
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from config import Settings, init_settings
from detection.normalizer import (
    ExcessiveEncodingError,
    InspectionUnit,
    check_path_traversal,
    normalize_request,
)
from detection.semantic import Verdict, analyze as semantic_analyze
from detection.signatures import SignatureVerdict, check_signatures
from logger import AuditLogger
from rate_limiter import RateLimiter
import proxy

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("waf.main")

# ---------------------------------------------------------------------------
# Application globals (initialised at startup)
# ---------------------------------------------------------------------------

settings: Settings = None  # type: ignore[assignment]
rate_limiter: RateLimiter = None  # type: ignore[assignment]
audit_logger: AuditLogger = None  # type: ignore[assignment]

app = FastAPI(
    title="Next-Generation WAF",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    global settings, rate_limiter, audit_logger

    settings = init_settings()
    log.info("Settings loaded – backend=%s", settings.BACKEND_URL)

    # Proxy client
    proxy.init_client(settings.BACKEND_URL)

    # Rate limiter (Redis)
    rate_limiter = RateLimiter(
        redis_url=settings.REDIS_URL,
        rate_limit_rps=settings.RATE_LIMIT_RPS,
        window_sec=settings.RATE_LIMIT_WINDOW_SEC,
        strike_threshold=settings.STRIKE_THRESHOLD,
        ban_ttl_sec=settings.BAN_TTL_SEC,
    )
    await rate_limiter.init()

    # Audit logger (Elasticsearch)
    audit_logger = AuditLogger(
        es_url=settings.ELASTICSEARCH_URL,
        queue_size=settings.LOG_QUEUE_SIZE,
        batch_size=settings.LOG_BATCH_SIZE,
    )
    await audit_logger.start()

    log.info("WAF startup complete")


@app.on_event("shutdown")
async def shutdown() -> None:
    await proxy.close_client()
    await rate_limiter.close()
    await audit_logger.stop()
    log.info("WAF shutdown complete")


# ---------------------------------------------------------------------------
# Health endpoint (not proxied)
# ---------------------------------------------------------------------------

@app.get("/__waf/health")
async def health() -> dict:
    """Report component health for container health checks."""
    checks: dict = {}

    # Redis
    redis_ok = await rate_limiter.ping()
    checks["redis"] = "ok" if redis_ok else "unavailable"

    # Elasticsearch queue
    checks["es_queue_size"] = audit_logger.queue_size
    checks["es_drops"] = audit_logger.drop_count

    # Backend
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient() as c:
            r = await c.get(f"{settings.BACKEND_URL}/", timeout=3.0)
        checks["backend"] = "ok" if r.status_code < 500 else "degraded"
    except Exception:
        checks["backend"] = "unavailable"

    status = "healthy" if checks["redis"] == "ok" else "degraded"
    return {"status": status, **checks}


# ---------------------------------------------------------------------------
# Client IP resolution (Stage 1)
# ---------------------------------------------------------------------------

def resolve_client_ip(request: Request) -> str:
    """Resolve the true client IP.

    Uses the socket peer address by default.  Honours ``X-Forwarded-For``
    only when the peer is in ``TRUSTED_PROXIES``, taking the right-most
    untrusted hop.
    """
    peer_ip = request.client.host if request.client else "0.0.0.0"

    if not settings.TRUSTED_PROXIES:
        return peer_ip

    # Check whether the direct peer is a trusted proxy
    try:
        peer_addr = ip_address(peer_ip)
    except ValueError:
        return peer_ip

    is_trusted = any(peer_addr in net for net in settings.TRUSTED_PROXIES)
    if not is_trusted:
        return peer_ip

    xff = request.headers.get("x-forwarded-for", "")
    if not xff:
        return peer_ip

    # Walk right-to-left and return the first untrusted hop
    hops = [h.strip() for h in xff.split(",")]
    for hop in reversed(hops):
        try:
            hop_addr = ip_address(hop)
        except ValueError:
            continue
        if not any(hop_addr in net for net in settings.TRUSTED_PROXIES):
            return hop
    return peer_ip


# ---------------------------------------------------------------------------
# Stage 3: Request sanity limits
# ---------------------------------------------------------------------------

def check_sanity(request: Request, body: bytes, request_id: str) -> Optional[Response]:
    """Enforce size and method limits before any parsing."""
    # Method
    if request.method.upper() not in settings.ALLOWED_METHODS:
        return JSONResponse(
            {"error": "method not allowed", "id": request_id},
            status_code=405,
        )

    # URL length
    url_str = str(request.url)
    if len(url_str) > settings.MAX_URL_LEN:
        return JSONResponse(
            {"error": "URI too long", "id": request_id},
            status_code=414,
        )

    # Body size
    if len(body) > settings.MAX_BODY_BYTES:
        return JSONResponse(
            {"error": "payload too large", "id": request_id},
            status_code=413,
        )

    # Header count
    if len(request.headers) > settings.MAX_HEADER_COUNT:
        return JSONResponse(
            {"error": "too many headers", "id": request_id},
            status_code=400,
        )

    # Total header size
    total_header_bytes = sum(
        len(k) + len(v) for k, v in request.headers.items()
    )
    if total_header_bytes > settings.MAX_HEADER_BYTES:
        return JSONResponse(
            {"error": "headers too large", "id": request_id},
            status_code=400,
        )

    return None


# ---------------------------------------------------------------------------
# Stage 4: CSRF / CORS check
# ---------------------------------------------------------------------------

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def check_csrf_cors(request: Request, request_id: str) -> Optional[Response]:
    """Validate Origin/Referer for state-changing requests and handle CORS preflight."""
    method = request.method.upper()

    # CORS preflight
    if method == "OPTIONS" and "access-control-request-method" in request.headers:
        origin = request.headers.get("origin", "")
        if _origin_allowed(origin):
            return Response(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": ", ".join(settings.ALLOWED_METHODS),
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    "Access-Control-Max-Age": "3600",
                },
            )
        return JSONResponse(
            {"error": "origin not allowed", "id": request_id},
            status_code=403,
        )

    # State-changing methods require Origin or Referer
    if method in _STATE_CHANGING_METHODS:
        origin = request.headers.get("origin", "")
        if origin:
            if not _origin_allowed(origin):
                return JSONResponse(
                    {"error": "origin not allowed", "id": request_id},
                    status_code=403,
                )
            return None

        # Fall back to Referer
        referer = request.headers.get("referer", "")
        if referer:
            try:
                parsed = urlparse(referer)
                ref_origin = f"{parsed.scheme}://{parsed.netloc}"
            except Exception:
                ref_origin = ""
            if not _origin_allowed(ref_origin):
                return JSONResponse(
                    {"error": "origin not allowed", "id": request_id},
                    status_code=403,
                )
            return None

        # No Origin or Referer on state-changing request
        # Allow for now – some legitimate clients don't send these
        # (non-browser API clients, curl, etc.)

    return None


def _origin_allowed(origin: str) -> bool:
    """Check if *origin* is in the configured allowlist."""
    if not settings.ALLOWED_ORIGINS:
        return True  # no allowlist = allow all
    origin_clean = origin.rstrip("/").lower()
    return any(
        origin_clean == allowed.lower()
        for allowed in settings.ALLOWED_ORIGINS
    )


# ---------------------------------------------------------------------------
# Catch-all pipeline route
# ---------------------------------------------------------------------------

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def waf_pipeline(request: Request, path: str = "") -> Response:
    """Main WAF inspection pipeline – stages 1 through 9."""
    request_id = str(uuid.uuid4())

    # Read body once (shared across stages)
    body = await request.body()

    # Convenience helpers for audit logging
    method = request.method
    url_str = str(request.url)
    user_agent = request.headers.get("user-agent", "")

    async def _block(
        status_code: int,
        rule_id: str,
        rule_category: str,
        module: str,
        fingerprint: str = "",
        source: str = "",
        payload_excerpt: str = "",
    ) -> Response:
        """Log and return a block response."""
        client_ip_for_log = resolve_client_ip(request)
        await audit_logger.log_block(
            request_id=request_id,
            client_ip=client_ip_for_log,
            method=method,
            url=url_str,
            user_agent=user_agent,
            rule_id=rule_id,
            rule_category=rule_category,
            module=module,
            fingerprint=fingerprint,
            source=source,
            payload_excerpt=payload_excerpt,
        )
        return JSONResponse(
            {"error": "blocked", "id": request_id},
            status_code=status_code,
        )

    # ---- Stage 1: Client IP resolution ----
    client_ip = resolve_client_ip(request)

    # ---- Stage 2: Ban check ----
    if await rate_limiter.is_banned(client_ip):
        return await _block(
            429, "BAN", "ban", "rate_limiter", source="ban_check",
        )

    # ---- Stage 2b: Rate limit check ----
    allowed, count = await rate_limiter.check_rate(client_ip)
    if not allowed:
        await audit_logger.log_block(
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            url=url_str,
            user_agent=user_agent,
            rule_id="RATE-LIMIT",
            rule_category="rate_limit",
            module="rate_limiter",
            source="sliding_window",
        )
        return JSONResponse(
            {"error": "rate limited", "id": request_id},
            status_code=429,
            headers={"Retry-After": str(settings.RATE_LIMIT_WINDOW_SEC)},
        )

    # ---- Stage 3: Request sanity limits ----
    sanity_resp = check_sanity(request, body, request_id)
    if sanity_resp:
        return sanity_resp

    # ---- Stage 4: CSRF / CORS ----
    csrf_resp = check_csrf_cors(request, request_id)
    if csrf_resp:
        return csrf_resp

    # ---- Stage 5: Normalization ----
    headers_dict = dict(request.headers)
    content_type = headers_dict.get("content-type", "")

    try:
        units: list[InspectionUnit] = normalize_request(
            path=request.url.path,
            query_string=request.url.query or "",
            headers=headers_dict,
            body=body,
            content_type=content_type,
            max_decode_passes=settings.MAX_DECODE_PASSES,
        )
    except ExcessiveEncodingError:
        return await _block(
            400, "NORM-EXCESSIVE", "normalization.excessive_encoding",
            "normalizer",
        )
    except Exception:
        # Fail closed on detection errors
        log.exception("Normalizer error")
        return await _block(
            403, "DETECTION-ERROR", "detection.error", "normalizer",
        )

    # ---- Stage 5b: Path traversal (post-normalization) ----
    for unit in units:
        if check_path_traversal(unit.canonical):
            await rate_limiter.record_detection_strike(client_ip)
            return await _block(
                403, "PATH-TRAVERSAL", "path_traversal", "normalizer",
                source=unit.source,
                payload_excerpt=unit.canonical[:512],
            )

    # ---- Stage 6: Signature checks ----
    sig_verdict: Optional[SignatureVerdict] = check_signatures(
        units, headers_dict,
    )
    if sig_verdict:
        await rate_limiter.record_detection_strike(client_ip)
        return await _block(
            403,
            sig_verdict.rule_id,
            sig_verdict.category,
            sig_verdict.module,
            fingerprint=sig_verdict.fingerprint,
            source=sig_verdict.source,
        )

    # ---- Stage 7: Semantic analysis (libinjection) ----
    try:
        sem_verdict: Optional[Verdict] = semantic_analyze(
            units, settings.PARAM_ALLOWLIST,
        )
    except Exception:
        log.exception("Semantic analysis error")
        await rate_limiter.record_detection_strike(client_ip)
        return await _block(
            403, "DETECTION-ERROR", "detection.error", "semantic",
        )

    if sem_verdict:
        await rate_limiter.record_detection_strike(client_ip)
        return await _block(
            403,
            f"{sem_verdict.category.upper()}-LIBINJECTION",
            sem_verdict.category,
            sem_verdict.module,
            fingerprint=sem_verdict.fingerprint,
            source=sem_verdict.source,
        )

    # ---- Stage 8 + 9: Proxy to backend + response hardening ----
    return await proxy.proxy_request(request, client_ip, settings.BACKEND_URL)
