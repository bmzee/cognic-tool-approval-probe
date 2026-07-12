"""Tests for build_server — single-tool registration + fail-closed wiring +
the ledger contract driven through the REAL registered tool.

build_server constructs the FastMCP app from Config.from_env() (so missing /
invalid env fails closed at build time) and registers exactly one tool,
``probe_write``, behind the selected token verifier. Construction must NOT
touch the ledger — the file is opened only inside an invocation, so these
unit tests build with no ledger directory present.
"""

from __future__ import annotations

import pathlib

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from cognic_tool_approval_probe.config import ConfigError
from cognic_tool_approval_probe.server import build_server

_EXPECTED_TOOLS = {"probe_write"}


def _structured_of(call_tool_result: object) -> dict[str, object]:
    """Narrow FastMCP.call_tool's (content, structuredContent) return for
    mypy; the structured envelope is what the kernel MCP host consumes."""
    assert isinstance(call_tool_result, tuple)
    structured = call_tool_result[1]
    assert isinstance(structured, dict)
    return structured


def _set_full_dev_env(monkeypatch: pytest.MonkeyPatch, ledger_path: pathlib.Path) -> None:
    """A complete, valid env: dev_insecure auth (so no oauth triple is
    required) plus the ledger path pointed into the test's tmp dir."""
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    monkeypatch.setenv("COGNIC_PROBE_LEDGER_PATH", str(ledger_path))


def test_build_server_returns_fastmcp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    from mcp.server.fastmcp import FastMCP

    _set_full_dev_env(monkeypatch, tmp_path / "ledger")
    assert isinstance(build_server(as_issuer="http://127.0.0.1:9000"), FastMCP)


async def test_build_server_registers_exactly_the_one_tool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    _set_full_dev_env(monkeypatch, tmp_path / "ledger")
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == _EXPECTED_TOOLS


async def test_probe_write_wire_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The MCP-advertised input schema carries exactly the ``nonce`` key —
    deliberately NO ``_cognic_query_context``: the kernel stamps that token
    only on the agent-dispatch path and only for ``run_readonly_query``
    (core/agent/dispatch.py:104); a directly-invoked tool never receives it."""
    _set_full_dev_env(monkeypatch, tmp_path / "ledger")
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    tools = {t.name: t for t in await mcp.list_tools()}
    tool = tools["probe_write"]
    assert set(tool.inputSchema["properties"]) == {"nonce"}
    assert set(tool.inputSchema["required"]) == {"nonce"}
    # dict[str, Any] return annotation → structuredContent populated.
    assert tool.outputSchema is not None


async def test_probe_write_appends_and_echoes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """An in-process call through the REAL registered tool appends exactly one
    ledger line and returns the nonce + line count. Nothing else."""
    ledger_path = tmp_path / "ledger"
    _set_full_dev_env(monkeypatch, ledger_path)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")

    result = await mcp.call_tool("probe_write", {"nonce": "m85c-nonce-1"})
    structured = _structured_of(result)
    assert structured == {"nonce": "m85c-nonce-1", "ledger_line_count": 1}
    assert len(ledger_path.read_text(encoding="utf-8").splitlines()) == 1

    result = await mcp.call_tool("probe_write", {"nonce": "m85c-nonce-2"})
    assert _structured_of(result) == {"nonce": "m85c-nonce-2", "ledger_line_count": 2}
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert lines[0].endswith(" m85c-nonce-1")
    assert lines[1].endswith(" m85c-nonce-2")


async def test_probe_write_unwritable_ledger_is_a_tool_error_and_appends_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The fail-loud contract over the wire: an unwritable ledger path surfaces
    as an MCP tool error (FastMCP wraps the LedgerError raise), never a silent
    success — and nothing is appended or created."""
    ledger_path = tmp_path / "missing-dir" / "ledger"
    _set_full_dev_env(monkeypatch, ledger_path)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    with pytest.raises(ToolError):
        await mcp.call_tool("probe_write", {"nonce": "m85c-nonce-1"})
    assert not ledger_path.exists()
    assert not ledger_path.parent.exists()  # never creates directories


async def test_probe_write_invalid_nonce_is_a_tool_error_and_appends_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    ledger_path = tmp_path / "ledger"
    _set_full_dev_env(monkeypatch, ledger_path)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    with pytest.raises(ToolError):
        await mcp.call_tool("probe_write", {"nonce": "bad\nnonce"})
    assert not ledger_path.exists()  # the refusal appended nothing


def test_build_server_does_not_touch_the_ledger_at_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    ledger_path = tmp_path / "ledger"
    _set_full_dev_env(monkeypatch, ledger_path)
    assert build_server(as_issuer="http://127.0.0.1:9000") is not None
    assert not ledger_path.exists()


def test_build_server_fails_closed_jwt_without_oauth_triple(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    # jwt mode without the oauth triple → Config fails closed before any
    # FastMCP construction.
    monkeypatch.setenv("COGNIC_PROBE_LEDGER_PATH", str(tmp_path / "ledger"))
    monkeypatch.setenv("COGNIC_AUTH_MODE", "jwt")
    for k in ("COGNIC_OAUTH_ISSUER", "COGNIC_OAUTH_JWKS_URI", "COGNIC_OAUTH_AUDIENCE"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ConfigError):
        build_server(as_issuer="http://127.0.0.1:9000")


def test_build_server_fails_closed_dev_insecure_outside_dev(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    monkeypatch.setenv("COGNIC_PROBE_LEDGER_PATH", str(tmp_path / "ledger"))
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.delenv("COGNIC_ENV", raising=False)
    with pytest.raises(ConfigError):
        build_server(as_issuer="http://127.0.0.1:9000")
