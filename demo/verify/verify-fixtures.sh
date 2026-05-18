#!/usr/bin/env bash
# demo/verify/verify-fixtures.sh — AC-16 fixture drift lint.
#
# Compares demo/capture/fixtures/*.yaml against the canonical files in
# examples/policies/<basename> or examples/exceptions/<basename>. Fixtures
# enumerated in the waiver list (sourced from demo/capture/AGENTS.md) are
# intentionally exempt.
#
# Exit 0 if all non-waived fixtures match. Exit 1 with diff output on first
# mismatch.

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

FIXTURE_DIR="demo/capture/fixtures"
WAIVER_FILE="demo/capture/AGENTS.md"

# Default waiver list per task spec. Overridable by parsing WAIVER_FILE
# if it exposes a `<!-- WAIVER: ... -->` block.
DEFAULT_WAIVERS=(
    "emergency-exception.yaml"
    "emergency-pod.yaml"
    "privileged-pod.yaml"
    "compliant-pod.yaml"
)

# Parse waivers from AGENTS.md if it has a "<!-- WAIVER:" marker per filename.
# Format expected: `<!-- WAIVER: <filename> -->` on its own line.
_load_waivers() {
    local waivers=("${DEFAULT_WAIVERS[@]}")
    if [ -f "${WAIVER_FILE}" ]; then
        while IFS= read -r line; do
            waivers+=("${line}")
        done < <(grep -oE '<!-- *WAIVER: *[A-Za-z0-9_.-]+ *-->' "${WAIVER_FILE}" 2>/dev/null \
            | sed -E 's/<!-- *WAIVER: *([A-Za-z0-9_.-]+) *-->/\1/' || true)
    fi
    printf '%s\n' "${waivers[@]}" | sort -u
}

_is_waived() {
    local name="$1"
    local w
    while IFS= read -r w; do
        [ "$w" = "${name}" ] && return 0
    done <<< "${WAIVERS}"
    return 1
}

_find_canonical() {
    local base="$1"
    for d in examples/policies examples/exceptions; do
        if [ -f "${d}/${base}" ]; then
            printf '%s/%s' "${d}" "${base}"
            return 0
        fi
    done
    return 1
}

WAIVERS="$(_load_waivers)"

if [ ! -d "${FIXTURE_DIR}" ]; then
    echo "verify-fixtures: ${FIXTURE_DIR} missing" >&2
    exit 1
fi

shopt -s nullglob
fixtures=("${FIXTURE_DIR}"/*.yaml)
shopt -u nullglob

if [ ${#fixtures[@]} -eq 0 ]; then
    echo "verify-fixtures: no fixtures present in ${FIXTURE_DIR}" >&2
    exit 1
fi

checked=0
skipped=0
for f in "${fixtures[@]}"; do
    base="$(basename "$f")"
    if _is_waived "${base}"; then
        skipped=$((skipped + 1))
        continue
    fi
    if canonical="$(_find_canonical "${base}")"; then
        if ! diff -q "$f" "${canonical}" >/dev/null; then
            echo "verify-fixtures: drift detected — ${f} differs from ${canonical}" >&2
            diff "${canonical}" "$f" >&2 || true
            exit 1
        fi
        checked=$((checked + 1))
    else
        echo "verify-fixtures: no canonical match for ${base} in examples/policies or examples/exceptions" >&2
        exit 1
    fi
done

echo "verify-fixtures: ${checked} checked, ${skipped} waived"
exit 0
