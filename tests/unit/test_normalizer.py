import pytest
from detection.normalizer import (
    ExcessiveEncodingError,
    InspectionUnit,
    canonicalize,
    check_path_traversal,
    decode_fixpoint,
    extract_cookie_units,
    extract_form_units,
    extract_json_units,
    extract_query_units,
    normalize_request,
)


def test_decode_fixpoint_basic():
    # Plain text returns unchanged and not exceeded
    val, exceeded = decode_fixpoint("hello world")
    assert val == "hello world"
    assert not exceeded

    # Single URL decode
    val, exceeded = decode_fixpoint("hello%20world")
    assert val == "hello world"
    assert not exceeded

    # Double URL decode
    val, exceeded = decode_fixpoint("hello%2520world")
    assert val == "hello world"
    assert not exceeded

    # HTML entity decode
    val, exceeded = decode_fixpoint("&lt;script&gt;&#x61;lert(1)&lt;/script&gt;")
    assert val == "<script>alert(1)</script>"
    assert not exceeded

    # Unicode escape
    val, exceeded = decode_fixpoint(r"\u003cscript\u003e")
    assert val == "<script>"
    assert not exceeded

    # Hex escape
    val, exceeded = decode_fixpoint(r"\x3cscript\x3e")
    assert val == "<script>"
    assert not exceeded


def test_canonicalize_nfkc_and_control_chars():
    # Fullwidth character normalization (NFKC)
    assert canonicalize("ＡＢＣ") == "ABC"

    # Null byte & control character stripping
    assert canonicalize("admin\x00' OR '1'='1") == "admin' OR '1'='1"
    assert canonicalize("foo\x08bar\x07baz") == "foobarbaz"

    # Whitespace collapse (including Unicode spaces)
    assert canonicalize("SELECT   *   FROM \u3000 users \u00a0 WHERE 1=1") == "SELECT * FROM users WHERE 1=1"


def test_excessive_encoding_evasion():
    # A payload crafted to exceed max_passes
    # e.g. 5 layers of percent encoding when max_passes=3
    nested = "alert(1)"
    for _ in range(5):
        import urllib.parse
        nested = urllib.parse.quote(nested)

    with pytest.raises(ExcessiveEncodingError):
        canonicalize(nested, max_passes=3)


def test_check_path_traversal():
    # Direct traversal
    assert check_path_traversal("../etc/passwd")
    assert check_path_traversal("..\\windows\\win.ini")
    assert check_path_traversal("/var/log/../../etc/shadow")
    assert check_path_traversal("..")

    # Safe paths
    assert not check_path_traversal("/home/user/file.txt")
    assert not check_path_traversal("index.php")
    assert not check_path_traversal("..foo/bar")


def test_extract_query_units_hpp():
    # Single param
    units = extract_query_units("id=123&name=alice")
    sources = {u.source: u.raw for u in units}
    assert sources["query:id"] == "123"
    assert sources["query:name"] == "alice"

    # HPP with duplicate params
    units = extract_query_units("id=1' UNION&id=SELECT * FROM users")
    sources = [u.source for u in units]
    raws = [u.raw for u in units]

    assert "query:id" in sources
    assert "query:id:joined-comma" in sources
    assert "query:id:joined-space" in sources

    joined_space = next(u.raw for u in units if u.source == "query:id:joined-space")
    assert joined_space == "1' UNION SELECT * FROM users"


def test_extract_json_units():
    body = b'{"user": {"name": "admin", "roles": ["editor", "staff"]}, "active": true}'
    units = extract_json_units(body)
    sources = {u.source: u.raw for u in units}

    assert sources["json:$.user.name"] == "admin"
    assert sources["json:$.user.roles[0]"] == "editor"
    assert sources["json:$.user.roles[1]"] == "staff"
    assert "json:$.user.key(name)" in sources


def test_extract_cookie_units():
    cookie_header = "sessionid=abc123xyz; role=admin; theme=dark"
    units = extract_cookie_units(cookie_header)
    sources = {u.source: u.raw for u in units}

    assert sources["cookie:sessionid"] == "abc123xyz"
    assert sources["cookie:role"] == "admin"
    assert sources["cookie:theme"] == "dark"


def test_extract_form_units():
    body = b"username=admin&password=secret%26123&username=guest"
    units = extract_form_units(body)
    sources = [u.source for u in units]

    assert "form:username" in sources
    assert "form:password" in sources
    assert "form:username:joined-comma" in sources


def test_normalize_request_end_to_end():
    units = normalize_request(
        path="/vulnerabilities/fi/",
        query_string="page=..%2f..%2fetc%2fpasswd",
        headers={"user-agent": "Mozilla/5.0", "cookie": "security=low"},
        body=b"",
        content_type="",
    )

    path_unit = next(u for u in units if u.source == "path")
    assert path_unit.canonical == "/vulnerabilities/fi/"

    query_unit = next(u for u in units if u.source == "query:page")
    assert query_unit.canonical == "../../etc/passwd"
