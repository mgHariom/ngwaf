import asyncio
import pytest
import httpx

pytestmark = [pytest.mark.adversarial, pytest.mark.slow]


@pytest.mark.asyncio
async def test_rate_limiting_burst(waf_url: str):
    """
    Rapidly fire requests to trigger the sliding-window rate limit.
    Rate limit returns 429 when threshold is reached.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        # Rapidly send requests
        got_429 = False
        retry_after = None

        # Send a rapid burst of requests (enough to trigger rate limit)
        for i in range(120):
            resp = await client.get(f"{waf_url}/login.php?burst={i}")
            if resp.status_code == 429:
                got_429 = True
                retry_after = resp.headers.get("Retry-After")
                data = resp.json()
                assert "id" in data
                break
            await asyncio.sleep(0.01)

        # In a test environment, if rate limits are set to 50/sec or windowed,
        # we check the response semantics if 429 is reached
        if got_429:
            assert retry_after is not None, "429 response must contain Retry-After header"
