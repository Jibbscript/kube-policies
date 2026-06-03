#!/bin/bash

# scripts/test/merge-coverage.sh — SDL-WU-04 / NIST SA-11
#
# Merge multiple Go coverage profiles into a single combined profile.
# Writes coverage-merged.out in the project root and prints the merged total.
#
# Usage:
#   ./scripts/test/merge-coverage.sh [profile1 [profile2 ...]]
#
# Defaults:
#   profiles: coverage-unit.out coverage-integration.out
#   output  : coverage-merged.out  (always written to PROJECT_ROOT)
#
# Missing input files are skipped with a warning; the script never fails
# solely because an integration profile does not exist (integration tests
# are optional in local dev and some CI matrix legs).
#
# The output profile uses the mode from the first profile that exists.
# See docs/testing.md for the full coverage strategy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUTPUT="${PROJECT_ROOT}/coverage-merged.out"

# Build list of input profiles (resolve relative paths against project root).
if [[ $# -gt 0 ]]; then
    INPUT_PROFILES=("$@")
else
    INPUT_PROFILES=("coverage-unit.out" "coverage-integration.out")
fi

RESOLVED_PROFILES=()
for p in "${INPUT_PROFILES[@]}"; do
    if [[ "${p}" != /* ]]; then
        RESOLVED_PROFILES+=("${PROJECT_ROOT}/${p}")
    else
        RESOLVED_PROFILES+=("${p}")
    fi
done

# Determine the mode line from the first existing profile.
MODE_LINE=""
for p in "${RESOLVED_PROFILES[@]}"; do
    if [[ -f "${p}" ]]; then
        MODE_LINE="$(head -1 "${p}")"
        break
    fi
done

if [[ -z "${MODE_LINE}" ]]; then
    echo "ERROR: no input profiles found; nothing to merge." >&2
    exit 1
fi

# Write merged profile: mode line once, then all non-mode data lines.
{
    echo "${MODE_LINE}"
    for p in "${RESOLVED_PROFILES[@]}"; do
        if [[ -f "${p}" ]]; then
            echo "  merging: ${p}" >&2
            grep -v '^mode:' "${p}" || true
        else
            echo "  warning: skipping missing profile: ${p}" >&2
        fi
    done
} > "${OUTPUT}"

echo "Merged profile written to: ${OUTPUT}"

# Print the combined total for CI log visibility.
go tool cover -func="${OUTPUT}" | grep '^total:'
