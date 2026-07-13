"""Pins the reproducible dependency-inventory policy used at release."""

from __future__ import annotations

import pathlib
import re
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNTIME_DIRECT_DEPENDENCIES = {"mcp", "pyjwt", "uvicorn"}
RELEASE_PATHS = (
    ROOT / "release.sh",
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "sign-and-publish.yml",
)


def _normalized_requirement_name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9._-]+", requirement)
    assert match is not None
    return match.group(0).lower().replace("_", "-")


def _root_lock_package() -> dict[str, object]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = lock["package"]
    assert isinstance(packages, list)
    roots = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == "cognic-tool-approval-probe"
        and package.get("source") == {"editable": "."}
    ]
    assert len(roots) == 1
    return roots[0]


def test_committed_lock_is_present_and_not_ignored() -> None:
    assert (ROOT / "uv.lock").is_file()
    ignored = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "uv.lock" not in ignored


def test_lock_runtime_roots_match_the_published_project_contract() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = {_normalized_requirement_name(item) for item in project["dependencies"]}
    assert declared == RUNTIME_DIRECT_DEPENDENCIES

    root = _root_lock_package()
    dependencies = root["dependencies"]
    assert isinstance(dependencies, list)
    locked = {
        str(dependency["name"]).lower().replace("_", "-")
        for dependency in dependencies
        if isinstance(dependency, dict)
    }
    assert locked == RUNTIME_DIRECT_DEPENDENCIES


def test_every_ci_and_release_path_checks_then_syncs_the_lock_frozen() -> None:
    for path in RELEASE_PATHS:
        text = path.read_text(encoding="utf-8")
        check_at = text.index("uv lock --check")
        sync_at = text.index("uv sync --frozen --extra dev")
        assert check_at < sync_at, path
