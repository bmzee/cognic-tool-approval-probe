"""Unit tests for the proof-local invocation ledger.

The ledger is the load-bearing proof artifact: the M8.5-C proof asserts
"ledger stays 0" through a denial + a single grant and "ledger exactly 1"
after the second grant. These tests pin the two non-negotiable properties —
append exactly once per successful call, append NEVER on any refusal — plus
the fail-loud unwritable-path contract and the durability (fsync) discipline.
"""

from __future__ import annotations

import os
import pathlib
import re
from datetime import datetime

import pytest

from cognic_tool_approval_probe import ledger
from cognic_tool_approval_probe.ledger import LedgerError

#: `<iso8601-utc-with-microseconds> <nonce>` — the exact line shape.
_LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00) (?P<nonce>.+)$")


def _lines(path: pathlib.Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _nonce_of(line: str) -> str:
    match = _LINE_RE.match(line)
    assert match is not None, f"ledger line does not match the pinned shape: {line!r}"
    return match["nonce"]


class TestAppendExactlyOnce:
    def test_first_append_creates_the_file_with_exactly_one_line(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "ledger"
        count = ledger.append(path=path, nonce="nonce-1")
        assert count == 1
        lines = _lines(path)
        assert len(lines) == 1
        assert _nonce_of(lines[0]) == "nonce-1"

    def test_each_successful_call_appends_exactly_one_line(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "ledger"
        assert ledger.append(path=path, nonce="nonce-1") == 1
        assert ledger.append(path=path, nonce="nonce-2") == 2
        assert ledger.append(path=path, nonce="nonce-3") == 3
        lines = _lines(path)
        assert len(lines) == 3
        assert [_nonce_of(line) for line in lines] == ["nonce-1", "nonce-2", "nonce-3"]

    def test_line_format_is_iso8601_utc_space_nonce_newline(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "ledger"
        ledger.append(path=path, nonce="m85c-abc123")
        raw = path.read_text(encoding="utf-8")
        assert raw.endswith("\n")
        match = _LINE_RE.match(raw.rstrip("\n"))
        assert match is not None
        assert match["nonce"] == "m85c-abc123"
        # the timestamp parses as ISO-8601 and is UTC
        parsed = datetime.fromisoformat(match["ts"])
        assert parsed.tzinfo is not None
        offset = parsed.utcoffset()
        assert offset is not None
        assert offset.total_seconds() == 0

    def test_append_preserves_existing_lines(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "ledger"
        path.write_text("2026-07-12T00:00:00.000000+00:00 pre-existing\n", encoding="utf-8")
        count = ledger.append(path=path, nonce="nonce-new")
        assert count == 2
        lines = _lines(path)
        assert lines[0].endswith("pre-existing")
        assert lines[1].endswith("nonce-new")

    def test_append_fsyncs_before_returning(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Durability pin: the line must be fsync'd before the call reports
        # success — the proof's kubectl-exec observer must never lose a line
        # to a page cache on pod teardown.
        real_fsync = os.fsync
        fsynced: list[int] = []

        def _recording_fsync(fd: int) -> None:
            fsynced.append(fd)
            real_fsync(fd)

        monkeypatch.setattr("cognic_tool_approval_probe.ledger.os.fsync", _recording_fsync)
        ledger.append(path=tmp_path / "ledger", nonce="nonce-1")
        assert len(fsynced) == 1


class TestRefusalNeverAppends:
    @pytest.mark.parametrize(
        "bad_nonce",
        [
            pytest.param("", id="empty"),
            pytest.param("   ", id="whitespace-only"),
            pytest.param("with\nnewline", id="newline"),
            pytest.param("with\rcarriage-return", id="carriage-return"),
            pytest.param("with\ttab", id="tab"),
            pytest.param("with\x00nul", id="nul"),
            pytest.param("with\x7fdel", id="del"),
            pytest.param("x" * 201, id="overlong"),
        ],
    )
    def test_invalid_nonce_refused_before_any_io(
        self, tmp_path: pathlib.Path, bad_nonce: str
    ) -> None:
        path = tmp_path / "ledger"
        with pytest.raises(LedgerError):
            ledger.append(path=path, nonce=bad_nonce)
        assert not path.exists()  # refusal appends nothing — not even the file

    def test_invalid_nonce_leaves_existing_ledger_untouched(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "ledger"
        ledger.append(path=path, nonce="good-1")
        before = path.read_bytes()
        with pytest.raises(LedgerError):
            ledger.append(path=path, nonce="bad\nnonce")
        assert path.read_bytes() == before

    def test_non_string_nonce_refused(self, tmp_path: pathlib.Path) -> None:
        # Runtime validation at the evidence boundary: annotations are not
        # enforcement, so a direct caller smuggling a non-str is refused.
        path = tmp_path / "ledger"
        with pytest.raises(LedgerError):
            ledger.append(path=path, nonce=12345)  # type: ignore[arg-type]
        assert not path.exists()

    def test_max_length_nonce_is_accepted(self, tmp_path: pathlib.Path) -> None:
        # boundary: exactly 200 chars is fine; 201 (parametrized above) is not
        path = tmp_path / "ledger"
        assert ledger.append(path=path, nonce="x" * 200) == 1


class TestUnwritableFailsLoud:
    def test_missing_parent_directory_fails_loud(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "does-not-exist" / "ledger"
        with pytest.raises(LedgerError) as exc:
            ledger.append(path=path, nonce="nonce-1")
        assert isinstance(exc.value.__cause__, OSError)
        assert not path.parent.exists()  # never creates directories

    def test_path_that_is_a_directory_fails_loud(self, tmp_path: pathlib.Path) -> None:
        with pytest.raises(LedgerError) as exc:
            ledger.append(path=tmp_path, nonce="nonce-1")
        assert isinstance(exc.value.__cause__, OSError)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission bits")
    def test_permission_denied_fails_loud_and_appends_nothing(self, tmp_path: pathlib.Path) -> None:
        locked_dir = tmp_path / "locked"
        locked_dir.mkdir()
        locked_dir.chmod(0o500)  # r-x: no write into the directory
        path = locked_dir / "ledger"
        try:
            with pytest.raises(LedgerError) as exc:
                ledger.append(path=path, nonce="nonce-1")
            assert isinstance(exc.value.__cause__, PermissionError)
            assert not path.exists()
        finally:
            locked_dir.chmod(0o700)  # let pytest clean tmp_path up

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission bits")
    def test_read_only_ledger_file_fails_loud_without_append(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "ledger"
        ledger.append(path=path, nonce="good-1")
        path.chmod(0o400)  # read-only file
        try:
            with pytest.raises(LedgerError):
                ledger.append(path=path, nonce="nonce-2")
            path.chmod(0o600)
            assert len(_lines(path)) == 1  # the refused call appended nothing
        finally:
            path.chmod(0o600)
