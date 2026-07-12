from __future__ import annotations

import pathlib

import pytest

from cognic_tool_approval_probe.config import Config, ConfigError


def _set_min_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the minimal env for ``Config.from_env()`` to SUCCEED by default.

    Uses ``dev_insecure`` + ``COGNIC_ENV=dev`` so the ``jwt``-mode
    oauth-triple requirement does not fire. Optional vars that could leak
    from the ambient environment and break a success-path test are
    defensively cleared; individual failure tests override the specific var
    under test after calling this helper.
    """
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    for leak in (
        "COGNIC_PROBE_LEDGER_PATH",
        "COGNIC_REQUIRED_SCOPES",
        "COGNIC_OAUTH_ISSUER",
        "COGNIC_OAUTH_JWKS_URI",
        "COGNIC_OAUTH_AUDIENCE",
    ):
        monkeypatch.delenv(leak, raising=False)


def test_defaults_ledger_path_and_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    cfg = Config.from_env()
    assert cfg.ledger_path == pathlib.Path("/var/probe/ledger")
    assert cfg.required_scopes == frozenset({"approval_probe.write"})
    assert cfg.auth_mode == "dev_insecure"


def test_ledger_path_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_PROBE_LEDGER_PATH", "/tmp/proof/ledger")
    assert Config.from_env().ledger_path == pathlib.Path("/tmp/proof/ledger")


def test_empty_ledger_path_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_PROBE_LEDGER_PATH", "   ")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_jwt_mode_parses_oauth_triple(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "jwt")
    monkeypatch.setenv("COGNIC_OAUTH_ISSUER", "https://as.example/")
    monkeypatch.setenv("COGNIC_OAUTH_JWKS_URI", "https://as.example/.well-known/jwks.json")
    monkeypatch.setenv("COGNIC_OAUTH_AUDIENCE", "http://127.0.0.1:8766/mcp")
    monkeypatch.setenv("COGNIC_REQUIRED_SCOPES", "approval_probe.write")
    cfg = Config.from_env()
    assert cfg.auth_mode == "jwt"
    assert cfg.oauth_issuer == "https://as.example/"
    assert cfg.required_scopes == frozenset({"approval_probe.write"})


def test_jwt_mode_requires_oauth_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "jwt")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_dev_insecure_only_in_dev_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.delenv("COGNIC_ENV", raising=False)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_invalid_auth_mode_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "none")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_required_scopes_cannot_be_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_min_env(monkeypatch)
    monkeypatch.setenv("COGNIC_REQUIRED_SCOPES", " , ")
    with pytest.raises(ConfigError):
        Config.from_env()
