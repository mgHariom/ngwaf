"""
Environment-driven settings for the WAF.
All settings are loaded from environment variables and validated at startup.
Invalid configuration causes immediate exit with a clear error message.
"""

import json
import os
import sys
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Union
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    """Immutable WAF configuration validated at construction time."""

    # Backend
    BACKEND_URL: str = "http://dvwa:80"

    # Data stores
    REDIS_URL: str = "redis://redis:6379/0"
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"

    # Rate limiting
    RATE_LIMIT_RPS: int = 50
    RATE_LIMIT_WINDOW_SEC: int = 60
    STRIKE_THRESHOLD: int = 5
    BAN_TTL_SEC: int = 600

    # Trusted proxies – CIDR list; empty means trust no proxy headers
    TRUSTED_PROXIES: tuple[Union[IPv4Network, IPv6Network], ...] = ()

    # CSRF / CORS
    ALLOWED_ORIGINS: tuple[str, ...] = ("http://localhost:8080",)

    # Sanity limits
    MAX_BODY_BYTES: int = 1_048_576  # 1 MB
    MAX_HEADER_BYTES: int = 8192
    MAX_URL_LEN: int = 2048
    MAX_HEADER_COUNT: int = 64
    ALLOWED_METHODS: tuple[str, ...] = (
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    )

    # Normalizer
    MAX_DECODE_PASSES: int = 5

    # Per-parameter detection exemptions
    # Format: {"param_name": ["sqli", "xss"]}
    PARAM_ALLOWLIST: dict[str, list[str]] = field(default_factory=dict)

    # Async logging
    LOG_QUEUE_SIZE: int = 10_000
    LOG_BATCH_SIZE: int = 50


class ConfigError(Exception):
    """Raised when configuration is invalid."""


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}")


def _parse_positive_int(name: str, raw: str) -> int:
    value = _parse_int(name, raw)
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got: {value}")
    return value


def _parse_url(name: str, raw: str) -> str:
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.hostname:
        raise ConfigError(f"{name} must be a valid URL, got: {raw!r}")
    return raw.rstrip("/")


def _parse_trusted_proxies(raw: str) -> tuple[Union[IPv4Network, IPv6Network], ...]:
    if not raw.strip():
        return ()
    networks = []
    for cidr in raw.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            networks.append(ip_network(cidr, strict=False))
        except ValueError:
            raise ConfigError(f"TRUSTED_PROXIES contains invalid CIDR: {cidr!r}")
    return tuple(networks)


def _parse_origins(raw: str) -> tuple[str, ...]:
    if not raw.strip():
        return ()
    return tuple(o.strip().rstrip("/") for o in raw.split(",") if o.strip())


def _parse_methods(raw: str) -> tuple[str, ...]:
    return tuple(m.strip().upper() for m in raw.split(",") if m.strip())


def _parse_param_allowlist(raw: str) -> dict[str, list[str]]:
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise ConfigError(f"PARAM_ALLOWLIST must be valid JSON, got: {raw!r}")
    if not isinstance(data, dict):
        raise ConfigError("PARAM_ALLOWLIST must be a JSON object")
    for key, val in data.items():
        if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
            raise ConfigError(
                f"PARAM_ALLOWLIST[{key!r}] must be a list of strings"
            )
    return data


def load_settings() -> Settings:
    """Load and validate settings from environment variables.

    Returns a frozen Settings instance. Raises ConfigError on invalid
    configuration so the process exits before serving any traffic.
    """
    env = os.environ.get

    kwargs: dict = {}

    # URLs
    if v := env("BACKEND_URL"):
        kwargs["BACKEND_URL"] = _parse_url("BACKEND_URL", v)
    if v := env("REDIS_URL"):
        kwargs["REDIS_URL"] = _parse_url("REDIS_URL", v)
    if v := env("ELASTICSEARCH_URL"):
        kwargs["ELASTICSEARCH_URL"] = _parse_url("ELASTICSEARCH_URL", v)

    # Rate limiting
    if v := env("RATE_LIMIT_RPS"):
        kwargs["RATE_LIMIT_RPS"] = _parse_positive_int("RATE_LIMIT_RPS", v)
    if v := env("RATE_LIMIT_WINDOW_SEC"):
        kwargs["RATE_LIMIT_WINDOW_SEC"] = _parse_positive_int(
            "RATE_LIMIT_WINDOW_SEC", v
        )
    if v := env("STRIKE_THRESHOLD"):
        kwargs["STRIKE_THRESHOLD"] = _parse_positive_int("STRIKE_THRESHOLD", v)
    if v := env("BAN_TTL_SEC"):
        kwargs["BAN_TTL_SEC"] = _parse_positive_int("BAN_TTL_SEC", v)

    # Trusted proxies
    if (v := env("TRUSTED_PROXIES")) is not None:
        kwargs["TRUSTED_PROXIES"] = _parse_trusted_proxies(v)

    # Origins
    if (v := env("ALLOWED_ORIGINS")) is not None:
        kwargs["ALLOWED_ORIGINS"] = _parse_origins(v)

    # Sanity limits
    if v := env("MAX_BODY_BYTES"):
        kwargs["MAX_BODY_BYTES"] = _parse_positive_int("MAX_BODY_BYTES", v)
    if v := env("MAX_HEADER_BYTES"):
        kwargs["MAX_HEADER_BYTES"] = _parse_positive_int("MAX_HEADER_BYTES", v)
    if v := env("MAX_URL_LEN"):
        kwargs["MAX_URL_LEN"] = _parse_positive_int("MAX_URL_LEN", v)
    if v := env("MAX_HEADER_COUNT"):
        kwargs["MAX_HEADER_COUNT"] = _parse_positive_int("MAX_HEADER_COUNT", v)
    if v := env("ALLOWED_METHODS"):
        kwargs["ALLOWED_METHODS"] = _parse_methods(v)

    # Normalizer
    if v := env("MAX_DECODE_PASSES"):
        kwargs["MAX_DECODE_PASSES"] = _parse_positive_int("MAX_DECODE_PASSES", v)

    # Param allowlist
    if (v := env("PARAM_ALLOWLIST")) is not None:
        kwargs["PARAM_ALLOWLIST"] = _parse_param_allowlist(v)

    # Logging
    if v := env("LOG_QUEUE_SIZE"):
        kwargs["LOG_QUEUE_SIZE"] = _parse_positive_int("LOG_QUEUE_SIZE", v)
    if v := env("LOG_BATCH_SIZE"):
        kwargs["LOG_BATCH_SIZE"] = _parse_positive_int("LOG_BATCH_SIZE", v)

    return Settings(**kwargs)


def init_settings() -> Settings:
    """Load settings or exit the process on bad configuration."""
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"FATAL: configuration error: {exc}", file=sys.stderr)
        sys.exit(1)
    return settings
