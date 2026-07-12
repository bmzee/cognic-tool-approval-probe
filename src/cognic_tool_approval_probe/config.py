from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass

_DEFAULT_LEDGER_PATH = "/var/probe/ledger"
_DEFAULT_REQUIRED_SCOPE = "approval_probe.write"


class ConfigError(RuntimeError):
    """Raised at startup when required env is missing or dev_insecure is misused (fail-closed)."""


@dataclass(frozen=True)
class Config:
    ledger_path: pathlib.Path
    auth_mode: str  # "jwt" | "dev_insecure"
    oauth_issuer: str | None
    oauth_jwks_uri: str | None
    oauth_audience: str | None
    required_scopes: frozenset[str]

    @staticmethod
    def from_env() -> "Config":
        auth_mode = os.environ.get("COGNIC_AUTH_MODE", "jwt")
        if auth_mode == "dev_insecure" and os.environ.get("COGNIC_ENV") != "dev":
            raise ConfigError("COGNIC_AUTH_MODE=dev_insecure requires COGNIC_ENV=dev")
        if auth_mode not in ("jwt", "dev_insecure"):
            raise ConfigError(f"invalid COGNIC_AUTH_MODE {auth_mode!r}")

        raw_ledger_path = os.environ.get("COGNIC_PROBE_LEDGER_PATH", _DEFAULT_LEDGER_PATH)
        if not raw_ledger_path.strip():
            raise ConfigError("COGNIC_PROBE_LEDGER_PATH must not be empty when set")

        issuer = os.environ.get("COGNIC_OAUTH_ISSUER")
        jwks = os.environ.get("COGNIC_OAUTH_JWKS_URI")
        audience = os.environ.get("COGNIC_OAUTH_AUDIENCE")
        if auth_mode == "jwt" and not (issuer and jwks and audience):
            raise ConfigError(
                "COGNIC_AUTH_MODE=jwt requires COGNIC_OAUTH_ISSUER, "
                "COGNIC_OAUTH_JWKS_URI, COGNIC_OAUTH_AUDIENCE"
            )
        scopes = frozenset(
            s.strip()
            for s in os.environ.get("COGNIC_REQUIRED_SCOPES", _DEFAULT_REQUIRED_SCOPE).split(",")
            if s.strip()
        )
        if not scopes:
            raise ConfigError("COGNIC_REQUIRED_SCOPES must contain at least one scope")
        return Config(
            ledger_path=pathlib.Path(raw_ledger_path),
            auth_mode=auth_mode,
            oauth_issuer=issuer,
            oauth_jwks_uri=jwks,
            oauth_audience=audience,
            required_scopes=scopes,
        )
