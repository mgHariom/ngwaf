import pytest
import httpx

pytestmark = pytest.mark.adversarial

SQLI_PAYLOADS = [
    # Baseline SQLi
    ("baseline_quote_or", "1' OR '1'='1"),
    ("baseline_union", "1 UNION SELECT 1,2,3--"),
    ("baseline_comment", "1' OR 1=1 -- -"),
    ("baseline_admin", "admin' --"),
    ("baseline_order_by", "1' ORDER BY 1--"),

    # Double URL encoding
    ("double_url_quote_or", "%2527%2520OR%25201%253D1"),
    ("double_url_union", "%2527%2520UNION%2520SELECT"),

    # Unicode escapes
    ("unicode_escape_quote", r"\u0027 OR 1=1--"),
    ("hex_escape_quote", r"\x27 OR 1=1--"),

    # Whitespace and comment obfuscation
    ("comment_whitespace", "1'/**/OR/**/1=1--"),
    ("multi_space", "1'    OR     '1'='1"),
    ("tab_whitespace", "1'\tOR\t1=1--"),
    ("newline_whitespace", "1'\nOR\n1=1--"),

    # Case variation
    ("case_variation", "1' uNiOn sElEcT 1,2,3--"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,payload", SQLI_PAYLOADS)
async def test_sqli_evasions_blocked(
    async_client: httpx.AsyncClient, waf_url: str, name: str, payload: str
):
    resp = await async_client.get(
        f"{waf_url}/vulnerabilities/sqli/",
        params={"id": payload, "Submit": "Submit"},
    )
    assert resp.status_code == 403, (
        f"SQLi payload {name} ('{payload}') was not blocked! Status: {resp.status_code}"
    )
    data = resp.json()
    assert data.get("error") == "blocked"
    assert "id" in data
