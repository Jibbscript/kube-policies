#!/bin/bash

# scripts/test/cover-gate.sh — SDL-WU-03 / NIST SA-11
#
# Enforce a minimum coverage threshold on a Go coverage profile.
# Exits 1 if total coverage falls below MIN_COVERAGE.
#
# Usage:
#   ./scripts/test/cover-gate.sh [coverage-profile]
#
# Environment:
#   MIN_COVERAGE  — integer minimum percentage (default: 60)
#
# Ratchet schedule (SDL-WU-03 / SDL-WU-29):
#   Q1 floor    : 60%  (conservative floor below the current measured unit
#                       total of 68.6% on ./cmd/... ./internal/... ./pkg/...)
#   Q2 target   : 70%
#   Q3 target   : 80%  (long-term gate)
#
# Update MIN_COVERAGE here and in codecov.yml each quarter.
# See docs/testing.md for the full coverage strategy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROFILE="${1:-coverage-unit.out}"
MIN_COVERAGE="${MIN_COVERAGE:-60}"

# Resolve relative profile paths against project root.
if [[ "${PROFILE}" != /* ]]; then
    PROFILE="${PROJECT_ROOT}/${PROFILE}"
fi

if [[ ! -f "${PROFILE}" ]]; then
    echo "ERROR: coverage profile not found: ${PROFILE}" >&2
    exit 1
fi

# Extract the total percentage from 'go tool cover -func' output.
# The total line looks like:  total:  (statements)  72.4%
COVER_OUTPUT="$(go tool cover -func="${PROFILE}")"
TOTAL_LINE="$(echo "${COVER_OUTPUT}" | grep '^total:')"

if [[ -z "${TOTAL_LINE}" ]]; then
    echo "ERROR: could not find total: line in coverage output" >&2
    exit 1
fi

# Parse the percentage value (strip the % sign).
COVERAGE_PCT="$(echo "${TOTAL_LINE}" | awk '{print $3}' | tr -d '%')"

echo "Coverage profile : ${PROFILE}"
echo "Total coverage   : ${COVERAGE_PCT}%"
echo "Minimum required : ${MIN_COVERAGE}%"

# Integer-safe comparison via awk (handles decimals by truncating).
PASS="$(awk -v got="${COVERAGE_PCT}" -v min="${MIN_COVERAGE}" \
    'BEGIN { print (got + 0 >= min + 0) ? "yes" : "no" }')"

if [[ "${PASS}" == "yes" ]]; then
    echo "PASS: coverage ${COVERAGE_PCT}% meets the ${MIN_COVERAGE}% gate."
    exit 0
else
    echo "FAIL: coverage ${COVERAGE_PCT}% is below the ${MIN_COVERAGE}% gate." >&2
    exit 1
fi
