import pytest
import httpx

pytestmark = pytest.mark.adversarial

BENIGN_INPUTS = [
    ("name_with_apostrophe", "O'Brien"),
    ("name_irish", "O'Malley"),
    ("sql_like_phrase", "Please select a team member from the list"),
    ("comparison_operators", "Price > 100 and count < 50"),
    ("heart_symbol", "I <3 coding in Python"),
    ("math_expression", "2 + 2 = 4 and 10 / 2 = 5"),
    ("search_query", "best Italian restaurants in downtown"),
    ("url_query", "https://example.com/search?q=waf&category=security"),
    ("email_address", "user.name+tag@company.co.uk"),
    ("html_styled_text", "Check out <b>our new product</b> today!"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,value", BENIGN_INPUTS)
async def test_benign_traffic_allowed(
    async_client: httpx.AsyncClient, waf_url: str, name: str, value: str
):
    resp = await async_client.get(
        f"{waf_url}/login.php",
        params={"search": value},
    )
    assert resp.status_code != 403, (
        f"Benign input {name} ('{value}') was falsely blocked with 403!"
    )
