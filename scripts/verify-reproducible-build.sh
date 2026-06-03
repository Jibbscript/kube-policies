#!/usr/bin/env bash
# verify-reproducible-build.sh — SUP-WU-11 (NIST SI-7, SA-10; SLSA reproducible builds)
#
# Builds each shipped binary TWICE, from the same commit, with the exact flags
# the release pipeline uses (.github/workflows/release.yml `build-release`), and
# asserts the two builds produce a byte-identical SHA-256. This is the local /
# CI proof that the build is a pure function of (commit, GOOS, GOARCH) and not
# of wall-clock time or builder-specific filesystem paths.
#
# Determinism contract (must match release.yml):
#   - SOURCE_DATE_EPOCH derived from the commit timestamp (NOT `date`)
#   - -trimpath               (strip machine-specific paths)
#   - CGO_ENABLED=0           (no host C toolchain leakage)
#   - a toolchain matching go.mod (GOTOOLCHAIN=auto resolves the pinned version
#     deterministically; CI's setup-go installs it ahead of time)
#   - a fresh GOCACHE per build so a warm cache cannot mask non-determinism
#
# Usage:
#   scripts/verify-reproducible-build.sh                # both binaries, host os/arch
#   GOOS=linux GOARCH=amd64 scripts/verify-reproducible-build.sh
#
# Exit 0 = reproducible; exit 1 = a binary differed between the two builds.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"
export GOOS GOARCH
export CGO_ENABLED=0
# auto => resolve the exact toolchain pinned by go.mod (e.g. go1.25.0) so both
# builds use an identical compiler even when the host's base `go` is older.
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

# Reproducible inputs. The embedded build date is the commit time, so it is
# identical across rebuilds of the same commit (unlike `date -u`).
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
export SOURCE_DATE_EPOCH
BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -r "${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"  # GNU || BSD date
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse HEAD)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}"

CMDS=("admission-webhook" "policy-manager")
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "Reproducible-build check"
echo "  GOOS/GOARCH       : ${GOOS}/${GOARCH}"
echo "  SOURCE_DATE_EPOCH : ${SOURCE_DATE_EPOCH} (${BUILD_DATE})"
echo "  go version        : $(go version)"
echo

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

build_once() {
  # $1 cmd  $2 output path  $3 fresh GOCACHE dir
  GOCACHE="$3" go build -trimpath -ldflags="${LDFLAGS}" -o "$2" "./cmd/$1"
}

rc=0
for cmd in "${CMDS[@]}"; do
  out1="${WORK}/${cmd}.1"; out2="${WORK}/${cmd}.2"
  build_once "${cmd}" "${out1}" "${WORK}/cache1"
  build_once "${cmd}" "${out2}" "${WORK}/cache2"
  h1="$(sha256 "${out1}")"; h2="$(sha256 "${out2}")"
  if [[ "${h1}" == "${h2}" ]]; then
    echo "REPRODUCIBLE  ${cmd}  ${h1}"
  else
    echo "NOT REPRODUCIBLE  ${cmd}" >&2
    echo "  build #1: ${h1}" >&2
    echo "  build #2: ${h2}" >&2
    rc=1
  fi
done

echo
if [[ "${rc}" -eq 0 ]]; then
  echo "OK — all binaries are byte-identical across independent builds."
else
  echo "FAIL — at least one binary is not reproducible." >&2
fi
exit "${rc}"
