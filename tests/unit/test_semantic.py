import pytest
from detection.normalizer import InspectionUnit

libinjection = pytest.importorskip("libinjection")
from detection.semantic import analyze, check_sqli, check_xss


def test_check_sqli_detection():
    sqli_payloads = [
        "1' OR '1'='1",
        "' UNION SELECT null, username, password FROM users--",
        "1; DROP TABLE users",
        "-1 UNION ALL SELECT 1,2,3,4,5",
    ]

    for payload in sqli_payloads:
        result = check_sqli(payload)
        assert result is not None, f"Expected {payload} to be detected as SQLi"
        assert result["category"] == "sqli"
        assert result["fingerprint"] != ""


def test_check_sqli_benign():
    benign_texts = [
        "hello world",
        "John Doe",
        "O'Reilly Media",
        "Just a regular sentence about technology.",
        "search?q=shoes",
    ]

    for text in benign_texts:
        result = check_sqli(text)
        assert result is None, f"Expected {text} to be considered benign"


def test_check_xss_detection():
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=\"javascript:alert(1)\">",
    ]

    for payload in xss_payloads:
        result = check_xss(payload)
        assert result is not None, f"Expected {payload} to be detected as XSS"
        assert result["category"] == "xss"


def test_check_xss_benign():
    benign_texts = [
        "Hello <b>world</b>",
        "3 < 5 and 5 > 2",
        "email@example.com",
    ]

    for text in benign_texts:
        result = check_xss(text)
        assert result is None or not result.get("category") == "xss"


def test_analyze_with_param_allowlist():
    units = [
        InspectionUnit(source="form:bio", raw="<script>alert(1)</script>", canonical="<script>alert(1)</script>"),
        InspectionUnit(source="query:id", raw="1' OR '1'='1", canonical="1' OR '1'='1"),
    ]

    # Without allowlist, bio triggers XSS
    verdict = analyze(units)
    assert verdict is not None
    assert verdict.category == "xss"

    # With bio exempted from XSS, id triggers SQLi
    allowlist = {"bio": ["xss"]}
    verdict = analyze(units, param_allowlist=allowlist)
    assert verdict is not None
    assert verdict.category == "sqli"
    assert verdict.source == "query:id"

    # With both exempted, verdict is None
    allowlist = {"bio": ["xss"], "id": ["sqli"]}
    verdict = analyze(units, param_allowlist=allowlist)
    assert verdict is None
