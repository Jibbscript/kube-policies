#!/usr/bin/env bash
# demo/verify/verify-schema.sh — AC-13 schema-only re-run check.
#
# Usage: verify-schema.sh <prev-public-dir> <curr-public-dir>
#
# Asserts that the two directories contain identical filename sets under
# screenshots/, terminals/, and audit/, and that each pairwise file's MIME
# type (via `file --mime-type`) matches. Per Iter-3 I3-7 the pixel-diff is
# informational only.
#
# When ImageMagick `compare` is available, writes a per-image AE (absolute
# error) count to demo/dist/pixel-diff.json keyed by relative path. This
# value is trend-only and never gates the script's exit code.

set -u
set -o pipefail

if [ $# -ne 2 ]; then
    echo "usage: verify-schema.sh <prev-public-dir> <curr-public-dir>" >&2
    exit 2
fi

PREV="$1"
CURR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${REPO_ROOT}/demo/dist"
mkdir -p "${DIST_DIR}"
PIXEL_DIFF="${DIST_DIR}/pixel-diff.json"

_list_rel() {
    local dir="$1" sub="$2"
    if [ -d "${dir}/${sub}" ]; then
        ( cd "${dir}/${sub}" && find . -type f | sed 's|^\./||' | sort )
    fi
}

_check_subdir() {
    local sub="$1"
    local prev_files curr_files
    prev_files="$(_list_rel "${PREV}" "${sub}" || true)"
    curr_files="$(_list_rel "${CURR}" "${sub}" || true)"
    if [ "${prev_files}" != "${curr_files}" ]; then
        echo "schema mismatch in ${sub}:" >&2
        diff <(printf '%s\n' "${prev_files}") <(printf '%s\n' "${curr_files}") >&2 || true
        return 1
    fi
    # MIME-type parity per file.
    local f
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        local p_mime c_mime
        p_mime=$(file --mime-type -b "${PREV}/${sub}/${f}" 2>/dev/null || echo "")
        c_mime=$(file --mime-type -b "${CURR}/${sub}/${f}" 2>/dev/null || echo "")
        if [ "${p_mime}" != "${c_mime}" ]; then
            echo "MIME mismatch ${sub}/${f}: prev=${p_mime} curr=${c_mime}" >&2
            return 1
        fi
    done <<< "${curr_files}"
}

_check_subdir "screenshots" || exit 1
_check_subdir "terminals" || exit 1
_check_subdir "audit" || exit 1

# Informational pixel-diff (non-gating, trend-only per I3-7).
if command -v compare >/dev/null 2>&1; then
    python3 - "${PREV}" "${CURR}" "${PIXEL_DIFF}" <<'PY'
import json, os, subprocess, sys
prev, curr, out_path = sys.argv[1:]
entries = {}
screenshots_dir = os.path.join(curr, "screenshots")
if os.path.isdir(screenshots_dir):
    for name in sorted(os.listdir(screenshots_dir)):
        if not name.endswith(".png"):
            continue
        a = os.path.join(prev, "screenshots", name)
        b = os.path.join(curr, "screenshots", name)
        if not (os.path.isfile(a) and os.path.isfile(b)):
            continue
        # `compare -metric AE` prints AE on stderr; null: out sink.
        proc = subprocess.run(
            ["compare", "-metric", "AE", a, b, "null:"],
            capture_output=True, text=True,
        )
        # exit code 0=same, 1=different (still has AE); 2=error.
        if proc.returncode in (0, 1):
            try:
                entries[f"screenshots/{name}"] = int(float(proc.stderr.strip().split()[0]))
            except (ValueError, IndexError):
                entries[f"screenshots/{name}"] = None
        else:
            entries[f"screenshots/{name}"] = None
with open(out_path, "w") as f:
    json.dump({
        "note": "trend-only per plan §8.4 / Iter-3 I3-7; non-gating",
        "entries": entries,
    }, f, indent=2)
print(f"pixel-diff written to {out_path}")
PY
else
    # Per AC-13: missing ImageMagick is a warning, not an error.
    echo "verify-schema: 'compare' not in PATH; pixel-diff skipped (informational, non-gating)" >&2
    cat > "${PIXEL_DIFF}" <<'JSON'
{
  "note": "ImageMagick 'compare' not installed — pixel-diff skipped (non-gating per Iter-3 I3-7).",
  "entries": {}
}
JSON
fi

echo "verify-schema: schema identical (screenshots/terminals/audit)"
exit 0
