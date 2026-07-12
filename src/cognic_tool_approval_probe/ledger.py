"""The proof-local invocation ledger — the load-bearing artifact of the
M8.5-C four-eyes approval proof.

The ledger is the independent execution observer: the proof asserts "ledger
stays 0" through an approval denial and through a single (insufficient) grant,
and "ledger exactly 1" after the second distinct grant. That makes two
properties non-negotiable:

  1. **Append exactly once per successful invocation** — one
     ``<iso8601-utc> <nonce>\\n`` line, written with ``open(..., "a")`` +
     ``flush()`` + ``os.fsync()`` so the line is durable before the call
     reports success.
  2. **Never append on any refusal** — nonce validation runs BEFORE any file
     I/O, and an unwritable ledger path fails loud (:class:`LedgerError` →
     an MCP tool error) instead of ever silently succeeding.

Deployment contract: the ledger's parent directory is provided by the
deployment (e.g. a pod-local volume at ``/var/probe``). This module never
creates directories — a missing parent is an unwritable path and fails loud.
The file itself is created on first append (O_APPEND semantics via mode
``"a+"``); it is readable only by the proof runner (``kubectl exec``), never
served over the MCP surface.

Business-side-effect-free: the ledger is proof instrumentation, not a
business write. Nothing else on the system is touched.
"""

from __future__ import annotations

import os
import pathlib
from datetime import datetime, timezone

#: Upper bound on the caller-supplied nonce. Generous for proof nonces
#: (uuid-shaped strings) while keeping every ledger line small enough that a
#: single POSIX O_APPEND write stays atomic.
_MAX_NONCE_LEN = 200


class LedgerError(RuntimeError):
    """Fail-loud ledger failure: an invalid nonce (refused BEFORE any I/O) or
    an unwritable ledger path (the underlying ``OSError`` is chained). The
    server lets this propagate so FastMCP surfaces it as a tool error
    (``isError``) — a probe_write call NEVER silently succeeds."""


def validate_nonce(nonce: str) -> str:
    """Refuse any nonce that could break the one-line-per-invocation ledger
    property. Runs before any file I/O — a refused nonce appends nothing.

    Runtime validation is deliberate (annotations are not enforcement): the
    ledger is an evidence boundary, so the string really is checked here even
    though FastMCP's schema already declares it ``str``.
    """
    if not isinstance(nonce, str):
        raise LedgerError(f"nonce must be a string, got {type(nonce).__name__}")
    if not nonce.strip():
        raise LedgerError("nonce must be a non-empty, non-whitespace string")
    if len(nonce) > _MAX_NONCE_LEN:
        raise LedgerError(f"nonce exceeds {_MAX_NONCE_LEN} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in nonce):
        raise LedgerError(
            "nonce must not contain control characters "
            "(the ledger is strictly one line per invocation)"
        )
    return nonce


def append(*, path: pathlib.Path, nonce: str) -> int:
    """Append exactly one ``<iso8601-utc> <nonce>\\n`` line to the ledger and
    return the ledger's line count AFTER the append.

    Fail-loud contract:
      - nonce validation failures raise :class:`LedgerError` BEFORE any I/O;
      - an unwritable / unreadable path (missing parent directory, permission
        denial, path-is-a-directory, ...) raises :class:`LedgerError` with the
        ``OSError`` chained — never a silent success.

    Durability: the line is ``flush()``ed and ``os.fsync()``ed before the
    count is taken, so a call that returns has its line on disk.

    Atomicity (proof scope): a single ``"a+"`` handle carries both the
    O_APPEND write and the post-append count, and the whole call is
    synchronous (no awaits), so in the single-process MCP server two
    invocations can never interleave between append and count.
    """
    validated = validate_nonce(nonce)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    line = f"{timestamp} {validated}\n"
    try:
        with open(path, "a+", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0)
            count = sum(1 for _ in handle)
    except OSError as exc:
        raise LedgerError(f"ledger unwritable at {path}: {type(exc).__name__}: {exc}") from exc
    return count
