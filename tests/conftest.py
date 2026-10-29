"""
Shared pytest fixtures for the NGWAF test suite.
"""

import sys
from pathlib import Path

import pytest
import httpx

# Ensure the waf package is importable from the project root
WAF_DIR = str(Path(__file__).resolve().parent.parent / "waf")
if WAF_DIR not in sys.path:
    sys.path.insert(0, WAF_DIR)


# ---------------------------------------------------------------------------
# URL fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def waf_url() -> str:
    """Base URL for the WAF (accessed via Docker port mapping)."""
    return "http://localhost:8080"


@pytest.fixture
def dvwa_url() -> str:
    """Direct DVWA URL (only reachable from inside the Docker network)."""
    return "http://dvwa:80"


# ---------------------------------------------------------------------------
# Async HTTP client
# ---------------------------------------------------------------------------

@pytest.fixture
async def async_client() -> httpx.AsyncClient:
    """Yield an httpx AsyncClient that follows redirects."""
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
    ) as client:
        yield client
