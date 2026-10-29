import pytest
import httpx

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_health_endpoint(async_client: httpx.AsyncClient, waf_url: str):
    resp = await async_client.get(f"{waf_url}/__waf/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "redis" in data
    assert "backend" in data


@pytest.mark.asyncio
async def test_clean_request_passes_with_security_headers(
    async_client: httpx.AsyncClient, waf_url: str
):
    resp = await async_client.get(f"{waf_url}/login.php")
    # Clean traffic should reach DVWA and return 200
    assert resp.status_code in (200, 302)

    # Verify security response hardening headers
    headers = {k.lower(): v for k, v in resp.headers.items()}
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "referrer-policy" in headers
    assert "content-security-policy" in headers

    # Disclosure headers stripped
    assert "x-powered-by" not in headers


@pytest.mark.asyncio
async def test_sqli_blocked_at_pipeline(
    async_client: httpx.AsyncClient, waf_url: str
):
    resp = await async_client.get(
        f"{waf_url}/vulnerabilities/sqli/",
        params={"id": "1' OR '1'='1", "Submit": "Submit"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("error") == "blocked"
    assert "id" in data


@pytest.mark.asyncio
async def test_xss_blocked_at_pipeline(
    async_client: httpx.AsyncClient, waf_url: str
):
    resp = await async_client.get(
        f"{waf_url}/vulnerabilities/xss_r/",
        params={"name": "<script>alert('xss')</script>"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("error") == "blocked"
    assert "id" in data


@pytest.mark.asyncio
async def test_path_traversal_blocked(
    async_client: httpx.AsyncClient, waf_url: str
):
    resp = await async_client.get(
        f"{waf_url}/vulnerabilities/fi/",
        params={"page": "../../etc/passwd"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("error") == "blocked"


@pytest.mark.asyncio
async def test_scanner_user_agent_blocked(
    async_client: httpx.AsyncClient, waf_url: str
):
    resp = await async_client.get(
        f"{waf_url}/",
        headers={"User-Agent": "sqlmap/1.5.2#stable"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("error") == "blocked"


@pytest.mark.asyncio
async def test_oversized_payload_rejected(
    async_client: httpx.AsyncClient, waf_url: str
):
    # Default MAX_BODY_BYTES is 1MB (1,048,576 bytes)
    oversized_body = b"A" * (1_048_576 + 1024)
    resp = await async_client.post(
        f"{waf_url}/login.php",
        content=oversized_body,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert resp.status_code == 413
    data = resp.json()
    assert data.get("error") == "payload too large"
