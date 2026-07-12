from __future__ import annotations

import asyncio
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import Config, ConfigError


class DevTokenVerifier(TokenVerifier):
    """DEV-ONLY (reachable only via COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev,
    enforced in Config.from_env). Accepts any non-empty bearer."""

    def __init__(self, cfg: Config) -> None:
        self._scopes = list(cfg.required_scopes)
        self._aud = cfg.oauth_audience or ""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(
            token=token, client_id="dev", scopes=self._scopes, expires_at=None, resource=self._aud
        )


class JwtTokenVerifier(TokenVerifier):
    """Resource-server verifier: validates RS256 signature against the AS JWKS,
    plus audience / issuer / exp / required scope.

    Fails loud at construction if the OAuth triple is incomplete — a missing
    audience or issuer would silently weaken ``jwt.decode``'s checks, so the
    verifier refuses to exist without all three (``Config.from_env`` already
    guarantees them in ``jwt`` mode; this guard covers hand-built configs).
    """

    def __init__(self, cfg: Config) -> None:
        if not (cfg.oauth_issuer and cfg.oauth_jwks_uri and cfg.oauth_audience):
            raise ConfigError(
                "JwtTokenVerifier requires the full OAuth triple "
                "(issuer, JWKS URI, audience) — refusing a weakened verifier"
            )
        self._issuer: str = cfg.oauth_issuer
        self._audience: str = cfg.oauth_audience
        self._required_scopes = cfg.required_scopes
        self._jwks = PyJWKClient(cfg.oauth_jwks_uri)

    def _verify_sync(self, token: str) -> dict[str, Any]:
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self._audience,
            issuer=self._issuer,
            options={"require": ["exp", "iat", "nbf"]},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        try:
            claims = await asyncio.to_thread(self._verify_sync, token)
            granted = _scopes_from_claims(claims)
        except Exception:
            return None  # FastMCP treats None as unauthorized (fail-closed)
        if not self._required_scopes.issubset(granted):
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or "unknown"),
            scopes=sorted(granted),
            expires_at=claims.get("exp"),
            resource=self._audience,
        )


def _scopes_from_claims(claims: dict[str, Any]) -> set[str]:
    """Extract scopes from a 'scope' (space-delimited str) or 'scp' (list) claim.

    Raises ValueError on a malformed claim (non-str / non-str-list) so the
    verifier fails closed rather than bubbling a TypeError or accepting a
    mixed set.
    """
    raw = claims.get("scope") or claims.get("scp") or ""
    if isinstance(raw, str):
        return set(raw.split())
    if isinstance(raw, (list, tuple)) and all(isinstance(s, str) for s in raw):
        return set(raw)
    raise ValueError("malformed scope/scp claim")


def select_token_verifier(cfg: Config) -> TokenVerifier:
    return DevTokenVerifier(cfg) if cfg.auth_mode == "dev_insecure" else JwtTokenVerifier(cfg)
