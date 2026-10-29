"""
Reverse proxy module – forwards clean traffic to the backend.

Uses a shared ``httpx.AsyncClient`` with connection pooling.  Adds
security response headers, hardens cookies, and strips server-disclosure
headers before returning the response to the client.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

logger = logging.getLogger("waf.proxy")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
})

STRIP_RESPONSE_HEADERS = frozenset({"server", "x-powered-by"})

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "object-src 'none'"
    ),
}

# Regex for parsing Set-Cookie attributes
_COOKIE_ATTR_RE = re.compile(r";\s*", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Client management
# ---------------------------------------------------------------------------

_client: Optional[httpx.AsyncClient] = None


def init_client(backend_url: str) -> None:
    """Create the shared HTTP client.  Called once at startup."""
    global _client
    _client = httpx.AsyncClient(
        base_url=backend_url,
        timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
        follow_redirects=False,
        limits=httpx.Limits(
            max_connections=100,
            max_keepalive_connections=20,
        ),
    )
    logger.info("Proxy client initialised → %s", backend_url)


async def close_client() -> None:
    """Shut down the shared HTTP client."""
    global _client
    if _client:
        await _client.aclose()
        _client = None


# ---------------------------------------------------------------------------
# Cookie hardening
# ---------------------------------------------------------------------------

def _harden_cookie(cookie_str: str, is_https: bool = False) -> str:
    """Add ``HttpOnly`` and ``SameSite=Lax`` to a Set-Cookie value if absent.

    Also adds ``Secure`` when the connection is behind HTTPS.
    """
    parts = _COOKIE_ATTR_RE.split(cookie_str)
    lower_parts = [p.strip().lower() for p in parts]

    attrs = [parts[0]]  # name=value is always first
    existing = set()
    for p in parts[1:]:
        key = p.strip().split("=")[0].lower().strip()
        existing.add(key)
        attrs.append(p.strip())

    if "httponly" not in existing:
        attrs.append("HttpOnly")
    if "samesite" not in existing:
        attrs.append("SameSite=Lax")
    if is_https and "secure" not in existing:
        attrs.append("Secure")

    return "; ".join(attrs)


# ---------------------------------------------------------------------------
# Main proxy handler
# ---------------------------------------------------------------------------

async def proxy_request(
    request: Request,
    client_ip: str,
    backend_url: str,
) -> Response:
    """Forward *request* to the backend, harden the response, and return it.

    Returns a ``502`` on connection error or a ``504`` on timeout.
    """
    if _client is None:
        return Response("WAF proxy not initialised", status_code=502)

    # Build upstream URL preserving the original path and query
    path = request.url.path
    query = request.url.query

    url = httpx.URL(path=path, query=query.encode("utf-8") if query else b"")

    # Forward headers – strip hop-by-hop and replace Host
    fwd_headers: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() not in HOP_BY_HOP and key.lower() != "host":
            fwd_headers[key] = value
    fwd_headers["X-Forwarded-For"] = client_ip
    fwd_headers["X-Forwarded-Proto"] = "http"

    # Read the body (already consumed by the pipeline for inspection)
    body = await request.body()

    try:
        rp_req = _client.build_request(
            method=request.method,
            url=url,
            headers=fwd_headers,
            content=body,
        )
        rp_resp = await _client.send(rp_req, stream=True)
    except httpx.ConnectError:
        logger.error("Backend connection refused")
        return Response(
            content="Bad Gateway",
            status_code=502,
            media_type="text/plain",
        )
    except httpx.TimeoutException:
        logger.error("Backend request timed out")
        return Response(
            content="Gateway Timeout",
            status_code=504,
            media_type="text/plain",
        )
    except Exception:
        logger.exception("Unexpected proxy error")
        return Response(
            content="Bad Gateway",
            status_code=502,
            media_type="text/plain",
        )

    # Build response headers
    resp_headers: dict[str, str] = {}
    set_cookie_values: list[str] = []

    for key, value in rp_resp.headers.multi_items():
        lower_key = key.lower()
        if lower_key in HOP_BY_HOP or lower_key in STRIP_RESPONSE_HEADERS:
            continue
        if lower_key == "set-cookie":
            set_cookie_values.append(value)
            continue
        resp_headers[key] = value

    # Add security headers (don't overwrite stricter existing values)
    existing_lower = {k.lower() for k in resp_headers}
    for hdr, val in SECURITY_HEADERS.items():
        if hdr.lower() not in existing_lower:
            resp_headers[hdr] = val

    # Build the response – stream the body back
    response = StreamingResponse(
        content=rp_resp.aiter_raw(),
        status_code=rp_resp.status_code,
        headers=resp_headers,
        background=BackgroundTask(rp_resp.aclose),
    )

    # Harden and attach cookies
    for cookie_val in set_cookie_values:
        hardened = _harden_cookie(cookie_val)
        response.headers.append("set-cookie", hardened)

    return response
