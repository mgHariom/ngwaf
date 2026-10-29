"""
Semantic analysis module – libinjection-based SQLi and XSS detection.

Runs libinjection's fingerprint tokenizer on each normalized inspection
unit and returns a verdict when a match is found.  Supports a configurable
per-parameter allowlist so known rich-text fields can be exempted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import libinjection

from .normalizer import InspectionUnit


@dataclass
class Verdict:
    """Describes why a request was blocked."""
    category: str       # "sqli" or "xss"
    fingerprint: str    # libinjection fingerprint (e.g. "s&1c") or "xss"
    module: str         # always "semantic"
    source: str         # the InspectionUnit.source that triggered the match


def check_sqli(value: str) -> Optional[dict]:
    """Run libinjection SQLi detection on *value*.

    Returns a dict with ``category`` and ``fingerprint`` keys on match,
    or ``None`` if the value is benign.
    """
    if not value or not value.strip():
        return None
    try:
        result = libinjection.is_sql_injection(value)
    except Exception:
        # If libinjection itself errors, treat as suspicious (fail closed)
        return {"category": "sqli", "fingerprint": "error"}
    if result and result.get("is_sqli"):
        return {
            "category": "sqli",
            "fingerprint": result.get("fingerprint", "unknown"),
        }
    return None


def check_xss(value: str) -> Optional[dict]:
    """Run libinjection XSS detection on *value*.

    Returns a dict with ``category`` and ``fingerprint`` keys on match,
    or ``None`` if the value is benign.
    """
    if not value or not value.strip():
        return None
    try:
        result = libinjection.is_xss(value)
    except Exception:
        return {"category": "xss", "fingerprint": "error"}
    if result and result.get("is_xss"):
        return {
            "category": "xss",
            "fingerprint": "xss",
        }
    return None


def analyze(
    units: list[InspectionUnit],
    param_allowlist: dict[str, list[str]] | None = None,
) -> Optional[Verdict]:
    """Run semantic analysis across all inspection units.

    Checks each unit for SQLi and XSS using libinjection.  Respects
    *param_allowlist*: if a parameter name is listed with ``"sqli"``
    or ``"xss"`` in the allowlist, that check is skipped for units
    matching that parameter.

    Returns the first :class:`Verdict` found, or ``None`` if all
    units pass.
    """
    if param_allowlist is None:
        param_allowlist = {}

    for unit in units:
        # Extract the parameter name from the source tag for allowlist lookup
        # e.g. "query:id" → "id", "form:comment" → "comment"
        param_name = _extract_param_name(unit.source)
        allowed = param_allowlist.get(param_name, [])

        # SQLi check
        if "sqli" not in allowed:
            sqli_result = check_sqli(unit.canonical)
            if sqli_result:
                return Verdict(
                    category=sqli_result["category"],
                    fingerprint=sqli_result["fingerprint"],
                    module="semantic",
                    source=unit.source,
                )

        # XSS check
        if "xss" not in allowed:
            xss_result = check_xss(unit.canonical)
            if xss_result:
                return Verdict(
                    category=xss_result["category"],
                    fingerprint=xss_result["fingerprint"],
                    module="semantic",
                    source=unit.source,
                )

    return None


def _extract_param_name(source: str) -> str:
    """Extract the parameter name from an inspection unit source tag.

    Examples::

        "query:id"                → "id"
        "form:comment"            → "comment"
        "query:id:joined-comma"   → "id"
        "json:$.user.name"        → "$.user.name"
        "header:user-agent"       → "user-agent"
        "cookie:session"          → "session"
        "path"                    → "path"
    """
    if ":" not in source:
        return source
    parts = source.split(":")
    if len(parts) >= 2:
        return parts[1]
    return source
