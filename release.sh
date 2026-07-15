#!/usr/bin/env bash
# release.sh — the maintainer's one-shot v0.2.0 release path for
# cognic-tool-approval-probe. Mirrors .github/workflows/sign-and-publish.yml's
# build → sign → verify spine, then publishes the GitHub release and prints
# the digest pins the AgentOS proof's stage-packs.sh locks.
#
# REMOTE-AFFECTING: `gh release create` publishes to GitHub. Run only as the
# maintainer, deliberately, from a clean tagged tree.
#
# Required toolchain on PATH (fail-loud preflight below):
#   uv, cosign, syft, grype, pip-licenses, gh
#   (`agentos sign --bundle` shells out to cosign / syft / grype / pip-licenses
#   and fail-loud-refuses if any is missing.)
#
# Required env (VALUES ARE NEVER ECHOED — only presence is checked):
#   COGNIC_SIGNING_KEY_PATH  path to the maintainer-held cosign PRIVATE key
#                            (never committed; *.key is gitignored)
#   COSIGN_PASSWORD          the matching key password (cosign reads it from env)
#
# Required file:
#   cosign.pub               the committed PUBLIC trust root. Generate the pair
#                            once with `cosign generate-key-pair`; commit ONLY
#                            cosign.pub. This script refuses to run without it —
#                            a release verified against nothing is not a release.
#   uv.lock                  the committed dependency inventory consumed by
#                            agentos sign. Release resolution is always frozen.

set -euo pipefail
cd "$(dirname "$0")"

VERSION="0.2.0"
TAG="v${VERSION}"
WHEEL="dist/cognic_tool_approval_probe-${VERSION}-py3-none-any.whl"

# The 7 attestations `agentos sign --bundle` produces; all uploaded to the release.
ATTESTATIONS=(
  attestations/cosign.sig
  attestations/sbom.cdx.json
  attestations/slsa-provenance.intoto.json
  attestations/intoto-layout.json
  attestations/vuln-scan.json
  attestations/license-audit.json
  attestations/bundle.sigstore
)

_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------- preflight (fail loud; echoes NAMES only, never values) ----------
for tool in uv cosign syft grype pip-licenses gh; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "FATAL: required tool not on PATH: $tool" >&2
    exit 1
  }
done
[ -n "${COGNIC_SIGNING_KEY_PATH:-}" ] || {
  echo "FATAL: COGNIC_SIGNING_KEY_PATH is unset (path to the cosign private key)" >&2
  exit 1
}
[ -f "${COGNIC_SIGNING_KEY_PATH}" ] || {
  echo "FATAL: COGNIC_SIGNING_KEY_PATH does not point at a file" >&2
  exit 1
}
[ -n "${COSIGN_PASSWORD:-}" ] || {
  echo "FATAL: COSIGN_PASSWORD is unset" >&2
  exit 1
}
[ -f cosign.pub ] || {
  echo "FATAL: cosign.pub (the committed public trust root) is missing." >&2
  echo "       Generate the pair with \`cosign generate-key-pair\`, commit ONLY" >&2
  echo "       cosign.pub, and keep the private key out of the repo." >&2
  exit 1
}
[ -f uv.lock ] || {
  echo "FATAL: committed uv.lock dependency inventory is missing" >&2
  exit 1
}

# ---------- 1. build the wheel (sign discovers it under the pack root) ----------
rm -rf dist
uv lock --check
uv sync --frozen --extra dev
uv build --wheel
[ -f "$WHEEL" ] || {
  echo "FATAL: expected wheel not produced: $WHEEL" >&2
  exit 1
}

# ---------- 2. sign the full bundle ----------
# cosign sign-blob + syft SBOM + grype vuln scan + pip-licenses audit +
# SLSA provenance + in-toto layout + the 7-attestation persister.
uv run agentos sign --bundle .

# ---------- 3. verify offline against the committed public trust root ----------
# Explicit --trust-root, never the implicit Settings default.
uv run agentos verify --trust-root cosign.pub .

for artefact in "${ATTESTATIONS[@]}"; do
  [ -s "$artefact" ] || {
    echo "FATAL: expected attestation missing or empty after sign: $artefact" >&2
    exit 1
  }
done

# ---------- 4. publish: wheel + the 7 attestations + cosign.pub ----------
gh release create "$TAG" \
  "$WHEEL" \
  "${ATTESTATIONS[@]}" \
  cosign.pub \
  --title "cognic-tool-approval-probe ${TAG}" \
  --notes "High-risk (risk_tier=high_risk_custom, ADR-014 four-eyes) action-class approval-probe MCP tool pack for AgentOS M8.5-D S1. Business-side-effect-free: probe_write appends one nonce line to the proof-local invocation ledger — proof instrumentation, not a business write. Signed bundle: cosign + SBOM + SLSA + in-toto + vuln + license; verify with \`agentos verify --trust-root cosign.pub .\`."

# ---------- 5. print the digest pins for the AgentOS proof ----------
echo
echo "# ---- locked digest pins — paste into the AgentOS proof's stage-packs.sh ----"
printf 'PROBE_WHEEL_SHA256="%s"\n' "$(_sha256 "$WHEEL")"
printf 'PROBE_PUB_SHA256="%s"\n' "$(_sha256 cosign.pub)"
