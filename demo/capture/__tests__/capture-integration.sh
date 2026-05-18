#!/usr/bin/env bash
# demo/capture/__tests__/capture-integration.sh
#
# End-to-end integration smoke test of the capture pipeline against a throwaway
# Kind cluster. Gated behind DEMO_INTEGRATION=1 so it never runs incidentally.
#
# Plan reference: §8.2.
#
# Asserts:
#   1. probe_and_teardown_existing_demo_cluster (from demo/capture/lib.sh) is
#      idempotent — calling it twice in a row leaves the system in a known
#      clean state.
#   2. kubectl wait --for=condition=Active policy/security-baseline succeeds
#      within 30s.
#   3. kubectl wait --for=condition=Ready policyexception/emergency-deployment
#      succeeds within 5s.
#   4. The captured audit log contains a "suppressed_by" entry after the
#      suppression case applies.

set -u
set -o pipefail

if [ "${DEMO_INTEGRATION:-0}" != "1" ]; then
    echo "capture-integration: skipping (set DEMO_INTEGRATION=1 to run)"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${REPO_ROOT}"

LIB="${REPO_ROOT}/demo/capture/lib.sh"
CAPTURE="${REPO_ROOT}/demo/capture/capture.sh"

if [ ! -f "${LIB}" ]; then
    echo "capture-integration: ${LIB} not found — W3 has not landed yet" >&2
    exit 1
fi

# shellcheck source=/dev/null
. "${LIB}"

FAILED=0
_fail() {
    echo "[FAIL] $*" >&2
    FAILED=$((FAILED + 1))
}
_ok() {
    echo "[ok]   $*"
}

# ---- Test 1: idempotent teardown -----------------------------------------
if declare -f probe_and_teardown_existing_demo_cluster >/dev/null; then
    if probe_and_teardown_existing_demo_cluster && probe_and_teardown_existing_demo_cluster; then
        _ok "probe_and_teardown_existing_demo_cluster idempotent"
    else
        _fail "probe_and_teardown_existing_demo_cluster not idempotent"
    fi
else
    _fail "probe_and_teardown_existing_demo_cluster not defined in lib.sh"
fi

# ---- Spin up cluster + apply fixtures via capture.sh up phase ------------
if [ -x "${CAPTURE}" ]; then
    if "${CAPTURE}" up >/dev/null; then
        _ok "capture.sh up succeeded"
    else
        _fail "capture.sh up returned non-zero"
        exit 1
    fi
else
    _fail "capture.sh missing or not executable"
    exit 1
fi

# ---- Test 2: kubectl wait policy --------------------------------------------
if kubectl wait --for=condition=Active --timeout=30s policy/security-baseline >/dev/null 2>&1; then
    _ok "policy/security-baseline Active within 30s"
else
    _fail "policy/security-baseline did not become Active within 30s"
fi

# ---- Test 3: kubectl wait policyexception --------------------------------
if kubectl wait --for=condition=Ready --timeout=5s policyexception/emergency-deployment >/dev/null 2>&1; then
    _ok "policyexception/emergency-deployment Ready within 5s"
else
    _fail "policyexception/emergency-deployment did not become Ready within 5s"
fi

# ---- Test 4: suppressed_by in audit log ----------------------------------
AUDIT="demo/remotion/public/audit/scene-4-audit.json"
if [ -f "${AUDIT}" ]; then
    if jq -e '.suppressed_by[] | select(.policy_id=="security-baseline")' "${AUDIT}" >/dev/null 2>&1; then
        _ok "audit log contains suppressed_by entry"
    else
        _fail "audit log missing suppressed_by"
    fi
else
    _fail "audit log not produced at ${AUDIT}"
fi

# ---- Teardown ------------------------------------------------------------
if declare -f probe_and_teardown_existing_demo_cluster >/dev/null; then
    probe_and_teardown_existing_demo_cluster || true
fi

if [ "${FAILED}" -gt 0 ]; then
    echo "capture-integration: ${FAILED} failure(s)" >&2
    exit 1
fi
echo "capture-integration: all checks passed"
exit 0
