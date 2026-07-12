from __future__ import annotations

import pathlib
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from cognic_tool_approval_probe.auth import (
    DevTokenVerifier,
    JwtTokenVerifier,
    select_token_verifier,
)
from cognic_tool_approval_probe.config import Config, ConfigError

_ISSUER = "https://as.example/"
_JWKS_URI = "https://as.example/.well-known/jwks.json"
_AUDIENCE = "http://127.0.0.1:8766/mcp"

# Module-scope RSA keypair for the real-crypto tests (key generation is slow
# — do it once). The public key is fed back through a fake JWKS signing key so
# the real ``jwt.decode`` path inside ``_verify_sync`` runs end to end.
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()


def _cfg(
    *,
    ledger_path: pathlib.Path = pathlib.Path("/var/probe/ledger"),
    auth_mode: str = "jwt",
    oauth_issuer: str | None = _ISSUER,
    oauth_jwks_uri: str | None = _JWKS_URI,
    oauth_audience: str | None = _AUDIENCE,
    required_scopes: frozenset[str] = frozenset({"approval_probe.write"}),
) -> Config:
    """Build a Config; any field overridable via keyword (typed for mypy).

    Defaults are jwt-ready (``auth_mode`` + oauth triple populated) so
    ``JwtTokenVerifier(_cfg())`` constructs directly (``PyJWKClient`` does not
    fetch at construction).
    """
    return Config(
        ledger_path=ledger_path,
        auth_mode=auth_mode,
        oauth_issuer=oauth_issuer,
        oauth_jwks_uri=oauth_jwks_uri,
        oauth_audience=oauth_audience,
        required_scopes=required_scopes,
    )


class _FakeKey:
    """Stand-in for a PyJWK signing key.

    Exposes the ``.key`` attribute that ``_verify_sync`` reads and hands to
    ``jwt.decode``.
    """

    def __init__(self, key: RSAPublicKey) -> None:
        self.key = key


def test_select_returns_jwt_verifier_in_jwt_mode() -> None:
    verifier = select_token_verifier(_cfg(auth_mode="jwt"))
    assert isinstance(verifier, JwtTokenVerifier)


def test_select_returns_dev_verifier_in_dev_insecure_mode() -> None:
    verifier = select_token_verifier(_cfg(auth_mode="dev_insecure"))
    assert isinstance(verifier, DevTokenVerifier)


@pytest.mark.parametrize("missing", ["oauth_issuer", "oauth_jwks_uri", "oauth_audience"])
def test_jwt_verifier_refuses_construction_without_full_oauth_triple(missing: str) -> None:
    # A missing audience/issuer would silently weaken jwt.decode's checks —
    # the verifier refuses to exist instead.
    kwargs: dict[str, Any] = {missing: None}
    with pytest.raises(ConfigError):
        JwtTokenVerifier(_cfg(**kwargs))


async def test_jwt_verify_returns_none_when_verify_sync_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = JwtTokenVerifier(_cfg())

    def _raise(token: str) -> dict[str, Any]:
        raise ValueError("unverifiable token")

    monkeypatch.setattr(verifier, "_verify_sync", _raise)
    assert await verifier.verify_token("some.jwt.token") is None


async def test_jwt_verify_returns_access_token_with_scopes_when_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _cfg()
    verifier = JwtTokenVerifier(cfg)

    def _claims(token: str) -> dict[str, Any]:
        return {"scope": "approval_probe.write", "exp": 1, "iat": 1, "azp": "client-x"}

    monkeypatch.setattr(verifier, "_verify_sync", _claims)
    token = await verifier.verify_token("some.jwt.token")
    assert token is not None
    assert token.scopes == ["approval_probe.write"]
    assert token.client_id == "client-x"
    assert token.expires_at == 1
    assert token.resource == cfg.oauth_audience


async def test_jwt_verify_returns_none_when_required_scope_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = JwtTokenVerifier(_cfg(required_scopes=frozenset({"approval_probe.write"})))

    def _claims(token: str) -> dict[str, Any]:
        return {"scope": "some.other.scope", "exp": 1, "iat": 1}

    monkeypatch.setattr(verifier, "_verify_sync", _claims)
    assert await verifier.verify_token("some.jwt.token") is None


async def test_jwt_verify_returns_none_on_non_string_scope_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = JwtTokenVerifier(_cfg())

    def _claims(token: str) -> dict[str, Any]:
        return {"scope": 123, "exp": 1, "iat": 1}

    monkeypatch.setattr(verifier, "_verify_sync", _claims)
    # malformed scope claim → _scopes_from_claims raises ValueError → fail-closed
    assert await verifier.verify_token("some.jwt.token") is None


async def test_jwt_verify_returns_none_on_mixed_list_scope_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = JwtTokenVerifier(_cfg())

    def _claims(token: str) -> dict[str, Any]:
        return {"scope": ["approval_probe.write", 1], "exp": 1, "iat": 1}

    monkeypatch.setattr(verifier, "_verify_sync", _claims)
    assert await verifier.verify_token("some.jwt.token") is None


async def test_jwt_verify_real_decode_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = JwtTokenVerifier(_cfg())
    monkeypatch.setattr(
        verifier._jwks, "get_signing_key_from_jwt", lambda token: _FakeKey(_PUBLIC_KEY)
    )
    now = int(time.time())
    signed = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "exp": now + 3600,
            "iat": now - 10,
            "nbf": now - 10,
            "scope": "approval_probe.write",
        },
        _PRIVATE_KEY,
        algorithm="RS256",
    )
    token = await verifier.verify_token(signed)
    assert token is not None  # happy path through the real decoder
    assert token.scopes == ["approval_probe.write"]


async def test_jwt_verify_real_decode_requires_nbf(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = JwtTokenVerifier(_cfg())
    monkeypatch.setattr(
        verifier._jwks, "get_signing_key_from_jwt", lambda token: _FakeKey(_PUBLIC_KEY)
    )
    now = int(time.time())
    signed = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "exp": now + 3600,
            "iat": now - 10,
            # nbf intentionally omitted → MissingRequiredClaimError → fail-closed
            "scope": "approval_probe.write",
        },
        _PRIVATE_KEY,
        algorithm="RS256",
    )
    assert await verifier.verify_token(signed) is None


async def test_jwt_verify_real_decode_refuses_wrong_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = JwtTokenVerifier(_cfg())
    monkeypatch.setattr(
        verifier._jwks, "get_signing_key_from_jwt", lambda token: _FakeKey(_PUBLIC_KEY)
    )
    now = int(time.time())
    signed = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": "https://some-other-resource.example/mcp",
            "exp": now + 3600,
            "iat": now - 10,
            "nbf": now - 10,
            "scope": "approval_probe.write",
        },
        _PRIVATE_KEY,
        algorithm="RS256",
    )
    assert await verifier.verify_token(signed) is None


async def test_dev_verify_returns_access_token_for_nonempty_bearer() -> None:
    verifier = DevTokenVerifier(_cfg(auth_mode="dev_insecure"))
    token = await verifier.verify_token("anything")
    assert token is not None
    assert token.client_id == "dev"
    assert token.scopes == ["approval_probe.write"]


async def test_dev_verify_returns_none_for_empty_string() -> None:
    verifier = DevTokenVerifier(_cfg(auth_mode="dev_insecure"))
    assert await verifier.verify_token("") is None
