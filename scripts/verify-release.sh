#!/usr/bin/env bash
# verify-release.sh <version> — SUP-WU-15 (NIST SR-4, CM-14, SA-10; SSDF RV.1)
#
# Consumer-side verification of a kube-policies release. Proves, BEFORE you
# deploy, that every published artifact was produced by this project's GitHub
# Actions release pipeline and has not been tampered with:
#
#   1. container image signatures      (cosign verify)
#   2. SBOM attestations               (cosign verify-attestation --type spdxjson)
#   3. SLSA build provenance           (gh attestation verify  /  cosign slsaprovenance)
#   4. binary + chart blob signatures  (cosign verify-blob, if assets are present)
#
# All trust is anchored to the keyless OIDC identity of release.yml — there is
# NO long-lived public key to distribute or rotate.
#
# Prerequisites: cosign (v2+), gh (for provenance), jq, curl.
# Usage:
#   scripts/verify-release.sh v1.2.3
#   REPO=owner/fork scripts/verify-release.sh v1.2.3
#
# NOTE: this verifies a PUBLISHED release. Until the first signed tag is cut,
# there is nothing in the registry to verify and the script will report that
# the artifacts are not yet found — that is expected, not a failure of the tool.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <vX.Y.Z>" >&2
  exit 2
fi

REPO="${REPO:-Jibbscript/kube-policies}"
REGISTRY="${REGISTRY:-ghcr.io}"
# GHCR image paths are lowercase.
REPO_LC="$(printf '%s' "${REPO}" | tr '[:upper:]' '[:lower:]')"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
# Certificate identity (SAN) minted for the release workflow on this exact tag.
# Escape the literal dots (and the dots in ${VERSION}) so the anchor is exact
# rather than treating '.' as a regex wildcard.
VERSION_RE="${VERSION//./\\.}"
IDENTITY_REGEXP="^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/${VERSION_RE}\$"
IMAGES=("admission-webhook" "policy-manager")

need() { command -v "$1" >/dev/null 2>&1 || { echo "MISSING required tool: $1" >&2; exit 3; }; }
need cosign

rc=0
fail() { echo "  FAIL: $*" >&2; rc=1; }
ok()   { echo "  OK:   $*"; }

echo "Verifying kube-policies ${VERSION}"
echo "  repo            : ${REPO}"
echo "  oidc issuer     : ${OIDC_ISSUER}"
echo "  identity regexp : ${IDENTITY_REGEXP}"
echo

for img in "${IMAGES[@]}"; do
  ref="${REGISTRY}/${REPO_LC}/${img}:${VERSION}"
  echo "Image: ${ref}"

  # 1. Signature. cosign resolves the tag to its digest and checks the
  #    signature attached to that digest (signing is by digest in release.yml).
  if cosign verify \
        --certificate-identity-regexp "${IDENTITY_REGEXP}" \
        --certificate-oidc-issuer "${OIDC_ISSUER}" \
        "${ref}" >/dev/null 2>&1; then
    ok "image signature"
  else
    fail "image signature (cosign verify) for ${ref}"
  fi

  # 2. SBOM attestation (SPDX-JSON), cryptographically bound to the digest.
  if cosign verify-attestation \
        --type spdxjson \
        --certificate-identity-regexp "${IDENTITY_REGEXP}" \
        --certificate-oidc-issuer "${OIDC_ISSUER}" \
        "${ref}" >/dev/null 2>&1; then
    ok "SBOM attestation (spdxjson)"
  else
    fail "SBOM attestation for ${ref}"
  fi

  # 3. SLSA build provenance. Produced by actions/attest-build-provenance and
  #    pushed to the registry; `gh attestation verify` is the canonical check.
  if command -v gh >/dev/null 2>&1; then
    if gh attestation verify "oci://${REGISTRY}/${REPO_LC}/${img}:${VERSION}" \
          --repo "${REPO}" >/dev/null 2>&1; then
      ok "SLSA provenance (gh attestation verify)"
    else
      fail "SLSA provenance for ${ref}"
    fi
  else
    echo "  SKIP: SLSA provenance (gh CLI not installed)"
  fi
  echo
done

# 4. Binary + chart blob signatures, if the release assets were downloaded next
#    to this script's working directory (each <file> ships <file>.sig + <file>.pem).
shopt -s nullglob
blobs=( ./*.tgz ./admission-webhook-* ./policy-manager-* )
checked_blob=0
for f in "${blobs[@]}"; do
  case "${f}" in *.sig|*.pem) continue;; esac
  [[ -f "${f}.sig" && -f "${f}.pem" ]] || continue
  checked_blob=1
  if cosign verify-blob \
        --certificate "${f}.pem" \
        --signature "${f}.sig" \
        --certificate-identity-regexp "${IDENTITY_REGEXP}" \
        --certificate-oidc-issuer "${OIDC_ISSUER}" \
        "${f}" >/dev/null 2>&1; then
    ok "blob signature: ${f}"
  else
    fail "blob signature: ${f}"
  fi
done
[[ "${checked_blob}" -eq 0 ]] && echo "(no local release assets with .sig/.pem found — skipping blob checks)"

echo
if [[ "${rc}" -eq 0 ]]; then
  echo "RESULT: all available verifications PASSED for ${VERSION}."
else
  echo "RESULT: one or more verifications FAILED for ${VERSION}." >&2
fi
exit "${rc}"
