"""Pack-manifest contract tests — the high-risk four-eyes probe (v0.1.0)."""

from __future__ import annotations

import pathlib
import tomllib
from typing import Any

_ROOT = pathlib.Path(__file__).resolve().parents[1]

_WHEEL_NAME = "cognic_tool_approval_probe-0.1.0-py3-none-any.whl"


def _manifest() -> dict[str, Any]:
    return tomllib.loads((_ROOT / "cognic-pack-manifest.toml").read_text())


def _pyproject() -> dict[str, Any]:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text())


def test_version_is_0_1_0() -> None:
    assert _pyproject()["project"]["version"] == "0.1.0"


def test_pack_block_identity() -> None:
    pack = _manifest()["pack"]
    assert pack["pack_id"] == "cognic-tool-approval-probe"
    assert pack["kind"] == "tool"
    assert pack["schema_version"] == 1


def test_risk_tier_is_high_risk_custom() -> None:
    # THE load-bearing pin: high_risk_custom is what routes probe_write
    # through the ADR-014 four-eyes flow (tools.rego: high_risk_custom is a
    # _four_eyes_tiers member -> require_4_eyes; approver scope
    # tool.approve.high_risk_custom). A quiet downgrade here would gut the
    # M8.5-C approval proof.
    assert _manifest()["risk_tier"]["tier"] == "high_risk_custom"


def test_risk_tier_never_reads_as_auto_run() -> None:
    # Negative pin: the auto-run tiers (read_only / internal_write) would let
    # probe_write execute without any approval — the exact failure mode the
    # proof exists to rule out.
    assert _manifest()["risk_tier"]["tier"] not in ("read_only", "internal_write")


def test_data_governance_contract() -> None:
    # Honest declaration per cognic_agentos.cli._governance_vocab: the pack
    # handles the caller nonce (internal) and produces an invocation trail
    # (audit_trail); its purpose is proof evidence (audit_evidence); the
    # ledger is retained only for the proof window (purpose_window requires a
    # positive retention_max_window). No egress, no DLP hooks.
    dg = _manifest()["data_governance"]
    assert dg["data_classes"] == ["internal", "audit_trail"]
    assert dg["purpose"] == "audit_evidence"
    assert dg["retention_policy"] == "purpose_window"
    assert isinstance(dg["retention_max_window"], (int, float))
    assert not isinstance(dg["retention_max_window"], bool)
    assert dg["retention_max_window"] > 0
    assert dg["egress_allow_list"] == []


def test_data_governance_declares_no_dlp_hooks() -> None:
    # The oracle pack's schema-guard hooks are oracle-specific; the probe
    # declares NONE. Presence of an unresolvable hook id would fail-close
    # every call at the kernel's DLP gate and mask the approval flow under
    # test.
    dg = _manifest()["data_governance"]
    assert "dlp_pre_hooks" not in dg
    assert "dlp_post_hooks" not in dg


def test_supply_chain_blob_path_matches_wheel_name() -> None:
    sc = _manifest()["supply_chain"]
    assert sc["blob_path"] == _WHEEL_NAME
    assert sc["attestation_paths"] == [
        "attestations/cosign.sig",
        "attestations/sbom.cdx.json",
    ]


def test_wheel_name_tracks_pyproject_version() -> None:
    version = _pyproject()["project"]["version"]
    assert _WHEEL_NAME == f"cognic_tool_approval_probe-{version}-py3-none-any.whl"


def test_mcp_block_contract() -> None:
    mcp = _manifest()["tool"]["cognic"]["mcp"]
    assert mcp["transport"] == "streamable-http"
    assert mcp["auth"] == "oauth-prm"
    assert mcp["scopes"] == ["approval_probe.write"]
    assert mcp["server_url"].startswith("http://")
    top = _manifest()["mcp"]
    assert top["caching"] is False
    assert top["elicitation_form"] is False


def test_identity_block_mandatory_fields() -> None:
    identity = _manifest()["identity"]
    for field in ("agent_id", "display_name", "provider_organization", "provider_url"):
        assert identity[field], f"identity.{field} must be non-empty"


def test_entry_point_declares_the_inert_descriptor() -> None:
    eps = _pyproject()["project"]["entry-points"]["cognic.tools"]
    assert eps == {"approval_probe": "cognic_tool_approval_probe:SERVER_DESCRIPTOR"}


def test_wheel_force_includes_the_manifest() -> None:
    # The kernel's manifest extractor reads the manifest from inside the
    # installed distribution; the wheel must carry it.
    force_include = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert (
        force_include["cognic-pack-manifest.toml"]
        == "cognic_tool_approval_probe/cognic-pack-manifest.toml"
    )


def test_probe_write_declares_the_action_capability_class() -> None:
    """The write probe requires an entitlement and the approval gate."""
    tools = _manifest()["tool"]["cognic"]["tools"]
    assert [(tool["name"], tool["capability_class"]) for tool in tools] == [
        ("probe_write", "action")
    ]
