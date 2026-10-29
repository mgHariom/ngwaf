import pytest
import httpx

pytestmark = pytest.mark.adversarial

XSS_PAYLOADS = [
    # Baseline
    ("baseline_script", "<script>alert(1)</script>"),
    ("baseline_img_onerror", "<img src=x onerror=alert(1)>"),
    ("baseline_svg_onload", "<svg onload=alert(1)>"),
    ("baseline_body_onload", "<body onload=alert(1)>"),
    ("baseline_iframe_javascript", "<iframe src=\"javascript:alert(1)\">"),

    # Encoded
    ("double_url_script", "%253Cscript%253Ealert(1)%253C/script%253E"),
    ("html_entity_script", "&lt;script&gt;alert(1)&lt;/script&gt;"),
    ("unicode_escape_script", r"\u003cscript\u003ealert(1)\u003c/script\u003e"),

    # Case obfuscation
    ("case_script", "<sCrIpt>alert(1)</ScRipt>"),
    ("case_img", "<ImG sRc=x OnErRoR=alert(1)>"),

    # Event handlers & tag variations
    ("input_autofocus", "<input autofocus onfocus=alert(1)>"),
    ("details_ontoggle", "<details open ontoggle=alert(1)>"),
    ("marquee_onstart", "<marquee onstart=alert(1)>"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,payload", XSS_PAYLOADS)
async def test_xss_evasions_blocked(
    async_client: httpx.AsyncClient, waf_url: str, name: str, payload: str
):
    resp = await async_client.get(
        f"{waf_url}/vulnerabilities/xss_r/",
        params={"name": payload},
    )
    assert resp.status_code == 403, (
        f"XSS payload {name} ('{payload}') was not blocked! Status: {resp.status_code}"
    )
    data = resp.json()
    assert data.get("error") == "blocked"
    assert "id" in data
