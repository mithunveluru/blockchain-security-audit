import pytest

from blockaudit.config import ConfigError, Settings
from blockaudit.auth import Authenticator, RateLimiter


def env(**kw):
    return {k: str(v) for k, v in kw.items()}


def test_production_requires_admin_token():
    with pytest.raises(ConfigError, match="ADMIN_TOKEN"):
        Settings.from_env(env(BLOCKAUDIT_ENV="production"))


def test_production_rejects_wildcard_cors_and_debug():
    base = dict(BLOCKAUDIT_ENV="production", BLOCKAUDIT_ADMIN_TOKEN="x" * 20)
    with pytest.raises(ConfigError, match="CORS"):
        Settings.from_env(env(**base, CORS_ORIGINS="*"))
    with pytest.raises(ConfigError, match="DEBUG"):
        Settings.from_env(env(**base, FLASK_DEBUG="1"))


def test_short_token_rejected():
    with pytest.raises(ConfigError, match="at least"):
        Settings.from_env(env(BLOCKAUDIT_ADMIN_TOKEN="short"))


def test_dev_without_tokens_generates_one_time_token_on_loopback():
    s = Settings.from_env(env())
    assert s.generated_admin_token and s.tokens["admin"] == s.generated_admin_token
    assert s.host == "127.0.0.1" and s.cors_origins == []


def test_dev_without_tokens_refuses_public_bind():
    with pytest.raises(ConfigError, match="no auth tokens"):
        Settings.from_env(env(HOST="0.0.0.0"))


def test_invalid_numbers_are_reported():
    with pytest.raises(ConfigError, match="PORT"):
        Settings.from_env(env(PORT="abc", BLOCKAUDIT_ADMIN_TOKEN="x" * 20))
    with pytest.raises(ConfigError, match="between"):
        Settings.from_env(env(PORT="70000", BLOCKAUDIT_ADMIN_TOKEN="x" * 20))


def test_secrets_not_in_repr():
    s = Settings.from_env(env(ANTHROPIC_API_KEY="sk-secret-value", BLOCKAUDIT_ADMIN_TOKEN="x" * 20))
    assert "sk-secret-value" not in repr(s)


def test_authenticator_roles_and_rejection():
    a = Authenticator({"admin": "a" * 20, "viewer": "v" * 20})
    assert a.check("a" * 20).role == "admin" and a.check("v" * 20).role == "viewer"
    assert a.check("nope") is None and a.check("") is None and a.check(None) is None
    assert not a.check("v" * 20).allows("analyst") and a.check("a" * 20).allows("viewer")


def test_rate_limiter_window():
    now = [0.0]
    r = RateLimiter(clock=lambda: now[0])
    assert all(r.allow("k", 3)[0] for _ in range(3))
    ok, retry = r.allow("k", 3)
    assert not ok and retry >= 1
    now[0] = 61
    assert r.allow("k", 3)[0]
