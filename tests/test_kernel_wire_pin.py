"""Cross-repo wire pins: manifest vocabulary ↔ kernel governance vocabulary.

The probe pack's whole reason to exist is that its manifest tier routes it
through the kernel's ADR-014 four-eyes flow. These pins drive the PACK's
declared values through the KERNEL dev-dep's closed-enum vocabularies + the
approval engine's tier→scope projection, so any kernel-side vocabulary drift
(a renamed tier, a re-mapped grant scope, a dropped data class) trips here,
in the pack's CI — before it can strand the M8.5-C proof.

Skips (loudly) only when the kernel dev-dep is not installed; the committed
dev pin carries it, so the CI lanes run this module unconditionally.
"""

from __future__ import annotations

import pathlib
import tomllib
import typing
from typing import Any

import pytest

kernel_vocab = pytest.importorskip(
    "cognic_agentos.cli._governance_vocab",
    reason="kernel dev-dep not installed (uv sync --extra dev)",
)
kernel_approval = pytest.importorskip(
    "cognic_agentos.core.approval.engine",
    reason="kernel dev-dep not installed (uv sync --extra dev)",
)

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _manifest() -> dict[str, Any]:
    return tomllib.loads((_ROOT / "cognic-pack-manifest.toml").read_text())


def test_declared_tier_is_in_the_kernel_risk_tier_vocabulary() -> None:
    tiers = frozenset(typing.get_args(kernel_vocab.RiskTier))
    assert _manifest()["risk_tier"]["tier"] in tiers


def test_declared_tier_maps_to_the_four_eyes_grant_scope() -> None:
    # The proof grants approver.dana + approver.erin exactly this scope; if
    # the kernel ever re-maps high_risk_custom, the proof's grant fixtures
    # break — catch it here first.
    scope = kernel_approval.grant_scope_for_risk_tier(_manifest()["risk_tier"]["tier"])
    assert scope == "tool.approve.high_risk_custom"


def test_declared_tier_is_not_an_auto_run_tier() -> None:
    # Kernel-side mirror of the manifest pin: auto-run tiers have NO grant
    # scope (grant_scope_for_risk_tier -> None). The probe's tier must have
    # one, or no approval would ever be required.
    assert kernel_approval.grant_scope_for_risk_tier(_manifest()["risk_tier"]["tier"]) is not None
    for auto_tier in ("read_only", "internal_write"):
        assert kernel_approval.grant_scope_for_risk_tier(auto_tier) is None


def test_declared_data_classes_are_in_the_kernel_vocabulary_and_unrestricted() -> None:
    classes = frozenset(typing.get_args(kernel_vocab.DataClass))
    declared = _manifest()["data_governance"]["data_classes"]
    for data_class in declared:
        assert data_class in classes
        # side-effect-free probe: no restricted-tier data ever enters it
        assert data_class not in kernel_vocab.RESTRICTED_DATA_CLASSES
        # and none of its classes force a minimum tier (the HIGH tier is a
        # deliberate governance choice, not a data-class obligation)
        assert data_class not in kernel_vocab.DATA_CLASS_TO_MIN_RISK_TIER


def test_declared_purpose_and_retention_are_in_the_kernel_vocabulary() -> None:
    dg = _manifest()["data_governance"]
    assert dg["purpose"] in frozenset(typing.get_args(kernel_vocab.Purpose))
    assert dg["retention_policy"] in frozenset(typing.get_args(kernel_vocab.RetentionPolicy))
