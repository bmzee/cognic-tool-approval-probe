"""Streamable-HTTP MCP server for cognic-tool-approval-probe (FastMCP).

Resource-server OAuth mode: passing ``auth`` + ``token_verifier`` makes FastMCP
auto-publish Protected Resource Metadata and wrap ``/mcp`` with bearer auth.
The verifier is selected fail-closed by :func:`auth.select_token_verifier`
(real JWT/JWKS in ``jwt`` mode; the permissive ``DevTokenVerifier`` only when
``COGNIC_AUTH_MODE=dev_insecure`` + ``COGNIC_ENV=dev``, enforced in
:meth:`config.Config.from_env`).

ONE tool, ``probe_write``: business-side-effect-free, appends a per-call nonce
to the proof-local invocation ledger (see :mod:`cognic_tool_approval_probe.ledger`)
and returns the nonce plus the ledger line count. Nothing else. The pack's
manifest declares ``[risk_tier].tier = "high_risk_custom"``, so the AgentOS
kernel routes every invocation through the ADR-014 four-eyes approval flow —
the tool itself carries no approval logic; the kernel gate in front of it is
the thing under proof.

Query-context note: ``probe_write`` deliberately performs NO query-context
token verification. The kernel stamps ``_cognic_query_context`` only on the
agent-dispatch path and only for tools in ``_QUERY_CONTEXT_STAMPED_TOOLS``
(``core/agent/dispatch.py:104`` — exactly ``{"run_readonly_query"}``); a tool
invoked directly via ``POST /api/v1/mcp/servers/{id}/tools/call`` never
receives one. The OAuth-PRM bearer above is this pack's auth boundary.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from . import ledger
from .auth import select_token_verifier
from .config import Config

_HOST = os.environ.get("COGNIC_MCP_HOST", "127.0.0.1")
_PORT = int(os.environ.get("COGNIC_MCP_PORT", "8766"))
_SERVER_URL = os.environ.get("COGNIC_MCP_SERVER_URL", "http://127.0.0.1:8766/mcp")


def build_server(*, as_issuer: str) -> FastMCP:
    """Construct the FastMCP app: fail-closed config, the selected verifier,
    and the single ``probe_write`` tool.

    ``Config.from_env()`` runs first so missing / invalid env fails closed at
    build time. Construction does NOT touch the ledger — the file is only ever
    opened inside a ``probe_write`` invocation, so an unwritable ledger path
    surfaces as a per-call tool error (fail loud at call time), never as a
    silently missing tool.
    """
    cfg = Config.from_env()

    mcp = FastMCP(
        "cognic-tool-approval-probe",
        host=_HOST,
        port=_PORT,
        streamable_http_path="/mcp",
        json_response=False,
        stateless_http=False,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(as_issuer),
            resource_server_url=AnyHttpUrl(_SERVER_URL),
            required_scopes=list(cfg.required_scopes),
        ),
        token_verifier=select_token_verifier(cfg),
    )

    @mcp.tool(
        name="probe_write",
        description=(
            "Append a per-call nonce to the proof-local invocation ledger and "
            "return the nonce plus the ledger line count. Business-side-effect-"
            "free: the ledger is proof instrumentation for the ADR-014 four-eyes "
            "approval proof (the independent observer that makes 'zero execution' "
            "provable), not a business write."
        ),
    )
    async def probe_write(nonce: str) -> dict[str, Any]:
        # Deliberately synchronous inside the async handler: the append+count
        # pair holds no await point, so the event loop serializes invocations
        # and the ledger's exactly-once property cannot interleave. On any
        # refusal (bad nonce, unwritable path) ledger.append raises
        # LedgerError BEFORE/WITHOUT appending; FastMCP converts the raise
        # into a tool error (isError) — fail loud, never silent.
        count = ledger.append(path=cfg.ledger_path, nonce=nonce)
        return {"nonce": nonce, "ledger_line_count": count}

    return mcp


if __name__ == "__main__":
    build_server(as_issuer=os.environ.get("COGNIC_MCP_AS_ISSUER", "http://127.0.0.1:9000")).run(
        transport="streamable-http"
    )
