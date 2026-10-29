"""
Signature-based detection module – regex rules for fixed indicators.

A deliberately small, curated set of patterns for threats that are
identified by fixed strings or structures rather than semantic analysis:
scanner User-Agents, OS command injection metacharacters, PHP webshell
tags, and similar.

Each rule has an ID, category, and severity so blocks are attributable
in audit logs.  All patterns are compiled once at import time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .normalizer import InspectionUnit


@dataclass(frozen=True)
class SignatureRule:
    """A single signature detection rule."""
    id: str
    category: str
    severity: str
    pattern: re.Pattern
    targets: tuple[str, ...]  # "normalized" or "header:<name>"


@dataclass
class SignatureVerdict:
    """Describes which signature rule matched."""
    rule_id: str
    category: str
    severity: str
    module: str       # always "signatures"
    source: str       # which input triggered the match
    fingerprint: str  # the rule ID (for log consistency with semantic module)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_RAW_RULES: list[tuple[str, str, str, str, tuple[str, ...]]] = [
    # ---- Scanner / tool User-Agents ----
    (
        "SIG-UA-001",
        "scanner",
        "high",
        r"(?i)(?:sqlmap|nikto|nessus|openvas|w3af|burpsuite|havij|acunetix|"
        r"nmap|dirbuster|gobuster|ffuf|wfuzz|hydra|medusa|masscan|zap|"
        r"arachni|skipfish|whatweb|fierce)",
        ("header:user-agent",),
    ),

    # ---- OS command injection metacharacters ----
    (
        "SIG-CMDI-001",
        "command_injection",
        "critical",
        # Semicolons, pipes, double-ampersands, backticks, $() subshells
        # in contexts where they're likely payloads (not URL-encoded literals)
        r"(?:;\s*(?:ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|"
        r"perl|ruby|php|powershell|cmd))"
        r"|(?:\|\s*(?:ls|cat|id|whoami|uname|bash|sh|nc))"
        r"|(?:&&\s*(?:ls|cat|id|whoami|uname|bash|sh))"
        r"|(?:`[^`]+`)"
        r"|(?:\$\([^)]+\))",
        ("normalized",),
    ),

    # ---- Path traversal (safety net – normalizer also catches this) ----
    (
        "SIG-TRAV-001",
        "path_traversal",
        "high",
        r"(?:(?:^|[\\/])\.\.(?:[\\/]|$))"
        r"|(?:/etc/(?:passwd|shadow|hosts))"
        r"|(?:(?:c:|C:)[\\/](?:windows|winnt))",
        ("normalized",),
    ),

    # ---- PHP webshell patterns ----
    (
        "SIG-WEBSHELL-001",
        "webshell",
        "critical",
        r"(?i)(?:<\?php\s)"
        r"|(?:(?:eval|assert|system|exec|passthru|shell_exec|popen|"
        r"proc_open|pcntl_exec)\s*\()"
        r"|(?:base64_decode\s*\()",
        ("normalized",),
    ),

    # ---- Known webshell filenames ----
    (
        "SIG-WEBSHELL-002",
        "webshell",
        "high",
        r"(?i)(?:c99|r57|b374k|weevely|phpspy|wso|alfa|leafmailer)\.php",
        ("normalized",),
    ),

    # ---- Server-Side Template Injection (SSTI) indicators ----
    (
        "SIG-SSTI-001",
        "ssti",
        "high",
        r"(?:\{\{.*\}\})|(?:\{%.*%\})|(?:\$\{.*\})",
        ("normalized",),
    ),

    # ---- Log4Shell / JNDI patterns ----
    (
        "SIG-JNDI-001",
        "jndi_injection",
        "critical",
        r"(?i)\$\{(?:jndi|lower|upper|env|sys|java):",
        ("normalized",),
    ),
]

# Compile all rules at import time
RULES: list[SignatureRule] = []
for _id, _cat, _sev, _pat, _targets in _RAW_RULES:
    RULES.append(
        SignatureRule(
            id=_id,
            category=_cat,
            severity=_sev,
            pattern=re.compile(_pat),
            targets=_targets,
        )
    )


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------

def check_signatures(
    units: list[InspectionUnit],
    raw_headers: dict[str, str],
) -> Optional[SignatureVerdict]:
    """Run all signature rules against inspection units and raw headers.

    Units are matched against rules targeting ``"normalized"``.  Raw
    header values are matched against rules targeting specific headers
    (e.g. ``"header:user-agent"``).

    Returns the first :class:`SignatureVerdict` found, or ``None``.
    """
    for rule in RULES:
        for target in rule.targets:
            if target == "normalized":
                # Check every normalized inspection unit
                for unit in units:
                    if rule.pattern.search(unit.canonical):
                        return SignatureVerdict(
                            rule_id=rule.id,
                            category=rule.category,
                            severity=rule.severity,
                            module="signatures",
                            source=unit.source,
                            fingerprint=rule.id,
                        )
            elif target.startswith("header:"):
                # Check the specific raw header
                header_name = target.split(":", 1)[1]
                header_value = raw_headers.get(header_name, "")
                if not header_value:
                    # Also try case-insensitive lookup
                    for k, v in raw_headers.items():
                        if k.lower() == header_name.lower():
                            header_value = v
                            break
                if header_value and rule.pattern.search(header_value):
                    return SignatureVerdict(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        module="signatures",
                        source=target,
                        fingerprint=rule.id,
                    )

    return None
