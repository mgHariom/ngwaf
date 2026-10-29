import pytest
from ipaddress import ip_network
from config import ConfigError, Settings, load_settings


def test_default_settings(monkeypatch):
    # Clear environment variables that might interfere
    env_keys = [
        "BACKEND_URL", "REDIS_URL", "ELASTICSEARCH_URL",
        "RATE_LIMIT_RPS", "RATE_LIMIT_WINDOW_SEC", "STRIKE_THRESHOLD",
        "BAN_TTL_SEC", "TRUSTED_PROXIES", "ALLOWED_ORIGINS",
        "MAX_BODY_BYTES", "MAX_HEADER_BYTES", "MAX_URL_LEN",
        "MAX_HEADER_COUNT", "ALLOWED_METHODS", "MAX_DECODE_PASSES",
        "PARAM_ALLOWLIST", "LOG_QUEUE_SIZE", "LOG_BATCH_SIZE",
    ]
    for key in env_keys:
        monkeypatch.delenv(key, raising=False)

    s = load_settings()
    assert s.BACKEND_URL == "http://dvwa:80"
    assert s.REDIS_URL == "redis://redis:6379/0"
    assert s.ELASTICSEARCH_URL == "http://elasticsearch:9200"
    assert s.RATE_LIMIT_RPS == 50
    assert s.RATE_LIMIT_WINDOW_SEC == 60
    assert s.STRIKE_THRESHOLD == 5
    assert s.BAN_TTL_SEC == 600
    assert s.TRUSTED_PROXIES == ()
    assert s.ALLOWED_ORIGINS == ("http://localhost:8080",)
    assert s.MAX_BODY_BYTES == 1_048_576


def test_custom_env_overrides(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "http://mybackend:8080/")
    monkeypatch.setenv("RATE_LIMIT_RPS", "100")
    monkeypatch.setenv("TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12")
    monkeypatch.setenv("PARAM_ALLOWLIST", '{"comment": ["xss"]}')

    s = load_settings()
    assert s.BACKEND_URL == "http://mybackend:8080"
    assert s.RATE_LIMIT_RPS == 100
    assert len(s.TRUSTED_PROXIES) == 2
    assert ip_network("10.0.0.0/8") in s.TRUSTED_PROXIES
    assert s.PARAM_ALLOWLIST == {"comment": ["xss"]}


def test_invalid_int_config(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_RPS", "not-a-number")
    with pytest.raises(ConfigError, match="must be an integer"):
        load_settings()


def test_negative_int_config(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_RPS", "-10")
    with pytest.raises(ConfigError, match="must be positive"):
        load_settings()


def test_invalid_url_config(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "not_a_valid_url")
    with pytest.raises(ConfigError, match="must be a valid URL"):
        load_settings()


def test_invalid_cidr_config(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "999.999.999.999/32")
    with pytest.raises(ConfigError, match="invalid CIDR"):
        load_settings()


def test_invalid_json_param_allowlist(monkeypatch):
    monkeypatch.setenv("PARAM_ALLOWLIST", "{bad json")
    with pytest.raises(ConfigError, match="must be valid JSON"):
        load_settings()
