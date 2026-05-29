#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

missing=0
require_tool() {
	local tool="$1"
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf 'required validation tool missing: %s\n' "${tool}" >&2
		missing=1
	fi
}

PYTHON_BIN="${PYTHON_BIN:-python3}"
require_tool "${PYTHON_BIN}"

if [[ "${missing}" -ne 0 ]]; then
	cat >&2 <<'EOF'

Install the missing tools and rerun `make validate-compliance`.
Suggested macOS install:
  brew install python3
EOF
	exit 127
fi

cd "${ROOT_DIR}"

echo "==> Compliance documentation validators"
"${PYTHON_BIN}" scripts/validate/compliance_check.py
