"""
Normalization module – canonicalizes all inspectable inputs.

Produces a list of InspectionUnit objects, each tagged with its source
(path, query:<name>, form:<name>, json:<path>, header:<name>, cookie:<name>).

Decoding is fixpoint-based: repeatedly apply URL-decode, HTML-entity decode,
and unicode-escape until the value stops changing, up to MAX_DECODE_PASSES.
"""

from __future__ import annotations

import html
import json as json_mod
import re
import unicodedata
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any
from urllib.parse import parse_qs, unquote


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class InspectionUnit:
    """A single value to inspect, with provenance metadata."""
    source: str          # e.g. "query:id", "form:name", "header:user-agent"
    raw: str             # original value before canonicalization
    canonical: str = ""  # populated by canonicalize()


class ExcessiveEncodingError(Exception):
    """Raised when decoding does not converge within the pass limit."""


# ---------------------------------------------------------------------------
# Unicode / escape helpers
# ---------------------------------------------------------------------------

_UNICODE_ESCAPE_RE = re.compile(
    r"(?:\\u([0-9a-fA-F]{4}))|(?:\\x([0-9a-fA-F]{2}))"
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Unicode whitespace characters to collapse (including exotic ones)
_WHITESPACE_RE = re.compile(
    r"[\s\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+"
)

# Path traversal detection pattern
TRAVERSAL_PATTERN = re.compile(
    r"(?:^|[\\/])\.\.(?:[\\/]|$)"
)


def _unescape_unicode(value: str) -> str:
    """Replace \\uXXXX and \\xNN escape sequences with their characters."""

    def _replacer(m: re.Match) -> str:
        hex_val = m.group(1) or m.group(2)
        try:
            return chr(int(hex_val, 16))
        except (ValueError, OverflowError):
            return m.group(0)

    return _UNICODE_ESCAPE_RE.sub(_replacer, value)


# ---------------------------------------------------------------------------
# Core decoding
# ---------------------------------------------------------------------------

def decode_fixpoint(value: str, max_passes: int = 5) -> tuple[str, bool]:
    """Repeatedly decode until the value stabilises.

    Returns ``(decoded_value, exceeded_limit)``.  When *exceeded_limit*
    is ``True`` the value was still changing after *max_passes* rounds,
    which is treated as an evasion attempt.
    """
    for _ in range(max_passes):
        prev = value
        # URL-decode
        value = unquote(value)
        # HTML-entity decode (named + numeric)
        value = html.unescape(value)
        # Unicode escape sequences
        value = _unescape_unicode(value)
        if value == prev:
            return value, False
    return value, True  # still mutating → evasion


def canonicalize(value: str, max_passes: int = 5) -> str:
    """Produce the canonical form of *value*.

    Raises :class:`ExcessiveEncodingError` if the fixpoint loop
    does not converge.
    """
    decoded, exceeded = decode_fixpoint(value, max_passes)
    if exceeded:
        raise ExcessiveEncodingError(
            f"Value still changing after {max_passes} decode passes"
        )

    # NFKC – collapses fullwidth, compatibility, and composed forms
    result = unicodedata.normalize("NFKC", decoded)

    # Strip null bytes and control characters (preserve tab, CR, LF)
    result = _CONTROL_CHAR_RE.sub("", result)

    # Collapse whitespace runs to a single space
    result = _WHITESPACE_RE.sub(" ", result).strip()

    return result


# ---------------------------------------------------------------------------
# Path traversal detection (detect, never strip)
# ---------------------------------------------------------------------------

def check_path_traversal(value: str) -> bool:
    """Return True if *value* contains a traversal sequence after decoding."""
    return bool(TRAVERSAL_PATTERN.search(value))


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _canonicalize_unit(unit: InspectionUnit, max_passes: int) -> InspectionUnit:
    """Fill in ``unit.canonical`` in-place."""
    unit.canonical = canonicalize(unit.raw, max_passes)
    return unit


def extract_query_units(query_string: str) -> list[InspectionUnit]:
    """Extract inspection units from a query string, handling HPP."""
    if not query_string:
        return []
    params = parse_qs(query_string, keep_blank_values=True)
    units: list[InspectionUnit] = []
    for name, values in params.items():
        for v in values:
            units.append(InspectionUnit(source=f"query:{name}", raw=v))
        # HPP: also inspect joined forms when there are duplicates
        if len(values) > 1:
            units.append(
                InspectionUnit(
                    source=f"query:{name}:joined-comma",
                    raw=",".join(values),
                )
            )
            units.append(
                InspectionUnit(
                    source=f"query:{name}:joined-space",
                    raw=" ".join(values),
                )
            )
    return units


def extract_form_units(body: bytes) -> list[InspectionUnit]:
    """Extract from ``application/x-www-form-urlencoded`` body."""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return []
    params = parse_qs(text, keep_blank_values=True)
    units: list[InspectionUnit] = []
    for name, values in params.items():
        for v in values:
            units.append(InspectionUnit(source=f"form:{name}", raw=v))
        if len(values) > 1:
            units.append(
                InspectionUnit(
                    source=f"form:{name}:joined-comma",
                    raw=",".join(values),
                )
            )
            units.append(
                InspectionUnit(
                    source=f"form:{name}:joined-space",
                    raw=" ".join(values),
                )
            )
    return units


def _walk_json(
    obj: Any,
    path: str = "$",
    depth: int = 0,
    max_depth: int = 10,
) -> list[InspectionUnit]:
    """Recursively walk a parsed JSON structure and inspect every string."""
    if depth > max_depth:
        return []
    units: list[InspectionUnit] = []
    if isinstance(obj, str):
        units.append(InspectionUnit(source=f"json:{path}", raw=obj))
    elif isinstance(obj, dict):
        for key, val in obj.items():
            # Inspect keys too – they can carry payloads
            units.append(
                InspectionUnit(source=f"json:{path}.key({key})", raw=str(key))
            )
            units.extend(
                _walk_json(val, f"{path}.{key}", depth + 1, max_depth)
            )
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            units.extend(
                _walk_json(item, f"{path}[{idx}]", depth + 1, max_depth)
            )
    return units


def extract_json_units(body: bytes) -> list[InspectionUnit]:
    """Extract from ``application/json`` body."""
    try:
        text = body.decode("utf-8", errors="replace")
        data = json_mod.loads(text)
    except (json_mod.JSONDecodeError, UnicodeDecodeError):
        # Not valid JSON – treat as raw string
        return [InspectionUnit(source="body:raw", raw=text if 'text' in dir() else body.decode("utf-8", errors="replace"))]
    return _walk_json(data)


def extract_header_units(headers: dict[str, str]) -> list[InspectionUnit]:
    """Extract select headers for inspection."""
    # Inspect headers that commonly carry attack payloads
    inspect_headers = {
        "user-agent", "referer", "x-forwarded-for", "x-forwarded-host",
        "content-type", "accept", "origin",
    }
    units: list[InspectionUnit] = []
    for name, value in headers.items():
        if name.lower() in inspect_headers:
            units.append(InspectionUnit(source=f"header:{name.lower()}", raw=value))
    return units


def extract_cookie_units(cookie_header: str) -> list[InspectionUnit]:
    """Extract individual cookie values for inspection."""
    if not cookie_header:
        return []
    units: list[InspectionUnit] = []
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, value = pair.partition("=")
            units.append(
                InspectionUnit(source=f"cookie:{name.strip()}", raw=value.strip())
            )
    return units


def extract_multipart_units(
    body: bytes,
    content_type: str,
    text_size_cap: int = 65536,
) -> list[InspectionUnit]:
    """Extract field values, filenames, and text content from multipart data.

    File contents are only inspected if they appear text-like and are
    under *text_size_cap* bytes.
    """
    units: list[InspectionUnit] = []
    # Simple boundary-based parser (production would use python-multipart)
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            boundary = part.split("=", 1)[1].strip('"').strip()
            break
    if not boundary:
        return units

    delimiter = f"--{boundary}".encode()
    parts = body.split(delimiter)

    for part_data in parts[1:]:  # skip preamble
        if part_data.strip() == b"--" or not part_data.strip():
            continue

        # Split headers from body
        if b"\r\n\r\n" in part_data:
            raw_headers, raw_body = part_data.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part_data:
            raw_headers, raw_body = part_data.split(b"\n\n", 1)
        else:
            continue

        headers_text = raw_headers.decode("utf-8", errors="replace")
        field_name = ""
        filename = ""

        for hdr_line in headers_text.split("\n"):
            hdr_line = hdr_line.strip()
            if hdr_line.lower().startswith("content-disposition:"):
                # Extract name
                if 'name="' in hdr_line:
                    field_name = hdr_line.split('name="', 1)[1].split('"', 1)[0]
                # Extract filename
                if 'filename="' in hdr_line:
                    filename = hdr_line.split('filename="', 1)[1].split('"', 1)[0]
                    units.append(
                        InspectionUnit(
                            source=f"multipart:{field_name}:filename",
                            raw=filename,
                        )
                    )

        # Strip trailing boundary markers
        raw_body = raw_body.rstrip(b"\r\n")

        # Inspect field value
        try:
            body_text = raw_body.decode("utf-8", errors="replace")
        except Exception:
            continue

        if filename:
            # File upload – only inspect text-like files under size cap
            if len(raw_body) <= text_size_cap:
                units.append(
                    InspectionUnit(
                        source=f"multipart:{field_name}:content",
                        raw=body_text,
                    )
                )
        else:
            # Regular form field
            units.append(
                InspectionUnit(
                    source=f"multipart:{field_name}",
                    raw=body_text,
                )
            )

    return units


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def normalize_request(
    *,
    path: str,
    query_string: str,
    headers: dict[str, str],
    body: bytes,
    content_type: str,
    max_decode_passes: int = 5,
) -> list[InspectionUnit]:
    """Extract and canonicalize all inspectable inputs from a request.

    Raises :class:`ExcessiveEncodingError` if any value exceeds the
    fixpoint decoding limit (evasion attempt).
    """
    units: list[InspectionUnit] = []

    # Path
    units.append(InspectionUnit(source="path", raw=path))

    # Query parameters (with HPP handling)
    units.extend(extract_query_units(query_string))

    # Headers
    units.extend(extract_header_units(headers))

    # Cookies
    cookie_header = headers.get("cookie", "")
    units.extend(extract_cookie_units(cookie_header))

    # Body (dispatch by content type)
    ct_lower = (content_type or "").lower().split(";")[0].strip()

    if ct_lower == "application/x-www-form-urlencoded":
        units.extend(extract_form_units(body))
    elif ct_lower == "application/json":
        units.extend(extract_json_units(body))
    elif ct_lower.startswith("multipart/form-data"):
        units.extend(extract_multipart_units(body, content_type))
    elif body:
        # Other content types – inspect as raw string up to size limit
        try:
            raw_text = body[:65536].decode("utf-8", errors="replace")
            units.append(InspectionUnit(source="body:raw", raw=raw_text))
        except Exception:
            pass

    # Canonicalize all units
    for unit in units:
        unit.canonical = canonicalize(unit.raw, max_decode_passes)

    return units
