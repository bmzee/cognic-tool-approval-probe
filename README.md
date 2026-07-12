# cognic-tool-approval-probe

A **FastMCP** (Streamable-HTTP) MCP-server tool pack for **Cognic AgentOS**
that exposes exactly **one tool** — and exists for exactly one reason: to make
the AgentOS **ADR-014 four-eyes runtime approval flow provable** in the
M8.5-C live proof.

| Tool | Inputs | Returns |
|---|---|---|
| `probe_write` | `nonce` | `{ "nonce": <echo>, "ledger_line_count": <int> }` |

The pack has **no kernel runtime dependency**: the AgentOS
authoring/governance CLI (`agentos validate` / `sign` / `verify`) is an
author/CI-time `dev` extra only. The server runs behind a real OAuth-PRM
bearer with a JWT/JWKS verifier.

## The high-risk tier and the four-eyes flow

The manifest declares:

```toml
[risk_tier]
tier = "high_risk_custom"
```

That single line is the load-bearing governance declaration. The AgentOS
kernel reads it from the signed manifest (`harness/mcp_host.py` →
`MCPServerEntry.risk_tier`) and routes **every** `probe_write` invocation
through the ADR-014 runtime tool-approval gate:

- `tools.rego` classifies `high_risk_custom` as a **four-eyes** tier
  (`require_4_eyes`) — two **distinct human** approvals are required.
- The grant scope is **`tool.approve.high_risk_custom`**
  (`core/approval/engine.py` tier→scope map).
- The wire shape at the kernel's MCP invocation route
  (`POST /api/v1/mcp/servers/{id}/tools/call`): first call → **202** with a
  minted `approval_request_id`; grants land via the approvals surface; the
  re-POST with the same `approval_request_id` executes only once the flow is
  fully granted. A denial, an expired request, or a single (insufficient)
  grant never executes the tool.

The tool itself carries **no approval logic** — the kernel gate in front of
it is the thing under proof.

## Business-side-effect-free — the ledger is proof instrumentation

> `probe_write` performs **no business write**. It touches no data source, no
> queue, no customer system, no bank record. Its only observable effect is
> appending one line to a **proof-local invocation ledger** — instrumentation
> that exists so an independent observer (the proof runner, via
> `kubectl exec`) can prove how many times the tool actually executed.

The ledger is the load-bearing proof artifact: the M8.5-C proof asserts the
ledger **stays at 0 lines** through an approval denial and through a single
(insufficient) four-eyes grant, and reads **exactly 1 line** after the second
distinct grant. Two properties are therefore non-negotiable and pinned by the
test suite:

1. **Append exactly once per successful invocation** — one
   `<iso8601-utc> <nonce>\n` line, written with `open(..., "a")` + `flush()` +
   `os.fsync()` so the line is durable before the call reports success.
2. **Never append on any refusal** — nonce validation (non-empty, ≤200 chars,
   no control characters) runs *before* any file I/O, and an unwritable
   ledger path **fails loud** as an MCP tool error (`isError`), never a
   silent success.

The ledger file is created on first append; its **parent directory is
deployment-provided** (the pack never creates directories — a missing parent
is an unwritable path and fails loud). It is readable only by the proof
runner (`kubectl exec`), never served over the MCP surface.

This pack is **never presented as chat-originated and is never a requirement
of the read-only analytical agent** — it is a standalone, operator-invoked
probe for the approval proof.

## No query-context token — deliberate, kernel-verified

The sibling `cognic-tool-oracle-schema` pack verifies a kernel-signed
`_cognic_query_context` token on its `run_readonly_query` tool. This pack
does **not**, because the kernel never stamps one on this path:

- The stamp lives only in the agent dispatcher
  (`core/agent/dispatch.py:104` — `_QUERY_CONTEXT_STAMPED_TOOLS` is exactly
  `{"run_readonly_query"}`) and applies only to agent-dispatched calls.
- A tool invoked **directly** via `POST /api/v1/mcp/servers/{id}/tools/call`
  (`protocol/mcp_host.py` — zero query-context references) receives no token;
  `probe_write` is only ever invoked that way.

The OAuth-PRM bearer (issuer / signature / expiry / audience / required
scope, `approval_probe.write`) is this pack's auth boundary — identical
discipline to the oracle pack's six metadata tools.

## Environment variables

All configuration is environment-driven and fail-closed at startup
(`Config.from_env`); the HTTP bind + URLs are parsed in `server.py`.

| Variable | Default | Meaning |
|---|---|---|
| `COGNIC_PROBE_LEDGER_PATH` | `/var/probe/ledger` | The invocation-ledger file. Parent directory must exist (deployment-provided volume); the file is created on first append. Unwritable → per-call tool error (fail loud). |
| `COGNIC_AUTH_MODE` | `jwt` | `jwt` (real JWKS verifier) or `dev_insecure` (dev-only accept-and-bind verifier; permitted only when `COGNIC_ENV=dev`, else fail-closed at startup). |
| `COGNIC_ENV` | *(unset)* | Must equal `dev` to permit `COGNIC_AUTH_MODE=dev_insecure`. |
| `COGNIC_OAUTH_ISSUER` | *(unset)* | Expected token issuer. **Required** in `jwt` mode. |
| `COGNIC_OAUTH_JWKS_URI` | *(unset)* | Authorization-server JWKS URI for signature verification. **Required** in `jwt` mode. |
| `COGNIC_OAUTH_AUDIENCE` | *(unset)* | Expected audience / resource (this server's resource URL). **Required** in `jwt` mode. |
| `COGNIC_REQUIRED_SCOPES` | `approval_probe.write` | Comma-separated required scopes; must be non-empty. |
| `COGNIC_MCP_HOST` | `127.0.0.1` | Streamable-HTTP bind host. |
| `COGNIC_MCP_PORT` | `8766` | Streamable-HTTP bind port (deliberately not the oracle pack's 8765). |
| `COGNIC_MCP_SERVER_URL` | `http://127.0.0.1:8766/mcp` | Public resource-server URL (audience/resource); deploy-overridden to the ClusterIP. |
| `COGNIC_MCP_AS_ISSUER` | `http://127.0.0.1:9000` | Authorization-server issuer URL passed to `build_server(as_issuer=…)`. |

## Data governance (honest declaration)

`[data_governance]` declares `data_classes = ["internal", "audit_trail"]`
(the caller nonce is internal proof telemetry; the ledger is an invocation
audit trail), `purpose = "audit_evidence"` (the ledger exists solely as
execution evidence for the approval proof), and
`retention_policy = "purpose_window"` with `retention_max_window = 7` — the
ledger *is* retained (that is its point), but only for the proof window; the
proof environment and its volume are torn down afterwards. Wave-1 validates
the window as a positive number (this manifest reads it as days). No egress,
no DLP hooks, no customer / payment / regulator data ever enters the pack.

## Running locally (dev)

The `DevTokenVerifier` is **dev-only**: it accepts any non-empty bearer and
is reachable only when you opt in explicitly (`COGNIC_AUTH_MODE=dev_insecure`
**and** `COGNIC_ENV=dev`). The default `jwt` mode fails closed unless the
OAuth env above is set.

```sh
COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev \
  COGNIC_PROBE_LEDGER_PATH=/tmp/probe-ledger \
  python -m cognic_tool_approval_probe.server
```

**Production requires `COGNIC_AUTH_MODE=jwt`** with `COGNIC_OAUTH_ISSUER` /
`COGNIC_OAUTH_JWKS_URI` / `COGNIC_OAUTH_AUDIENCE` set — the real JWT/JWKS
verifier (issuer / signature / expiry / audience / required scope).

## Testing

```sh
uv sync --extra dev
uv run pytest tests/ -q
```

No external services required: the ledger tests run against `tmp_path`, the
auth tests run a real RS256 sign/verify round-trip with a test keypair, and
the kernel wire-pin tests import the kernel dev-dep's closed-enum
vocabularies (they skip loudly if the dev extra is not installed).

## Authoring / validation / release

The `dev` extra carries the AgentOS authoring CLI (git-pinned in
`pyproject.toml`):

```sh
uv sync --extra dev
agentos validate .            # build-time manifest-shape check
```

`agentos validate` requires each declared `[supply_chain].attestation_paths`
file to exist, so it fails standalone until the real bundle is produced —
the CI `authoring-validate` lane seeds throwaway placeholders on the runner
(never committed). The real bundle (`agentos sign --bundle .`, which shells
out to cosign / syft / grype / pip-licenses) plus
`agentos verify --trust-root cosign.pub .` and the GitHub release upload are
wrapped by **`release.sh`** — the maintainer's one-shot release path. It
requires the maintainer-held cosign private key (`COGNIC_SIGNING_KEY_PATH` +
`COSIGN_PASSWORD`; the key never enters the repo) and the committed public
trust root `cosign.pub` (generate the pair with `cosign generate-key-pair`;
commit **only** `cosign.pub`). On success it prints the sha256 digest pins
(`PROBE_WHEEL_SHA256` / `PROBE_PUB_SHA256`) that get locked into the AgentOS
proof's `stage-packs.sh`.
