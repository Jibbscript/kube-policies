#!/usr/bin/env bash
# CI grep guard: prevents reintroduction of direct ctrl.SetLogger / klog.SetLogger
# calls or direct imports of those log packages outside pkg/logger/.
#
# This is alias-resilient: catches `import foo "sigs.k8s.io/.../log"; foo.SetLogger(...)`.

set -euo pipefail

# Move to repo root regardless of where the script was invoked.
cd "$(dirname "$0")/.."

# Part 1: no .SetLogger(...) calls outside pkg/logger/
if grep -RIn --include='*.go' --exclude-dir=vendor \
        -E '\.SetLogger\(' \
        pkg cmd internal test 2>/dev/null \
        | grep -v '^pkg/logger/logger\.go:' \
        | grep -v '^pkg/logger/logger_test\.go:' \
        | grep -v '\[controller-runtime\] log\.SetLogger' \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'; then
    echo "ERROR: direct .SetLogger(...) calls found outside pkg/logger/." >&2
    echo "       Use logger.SetControllerRuntimeLogger instead." >&2
    exit 1
fi

# Part 2: no direct imports of the controller-runtime log package or klog
# outside the two allowlisted sites:
#   pkg/logger/                        — canonical wire-up site; the only place
#                                        that should import these packages in
#                                        production code.
#   test/integration/setup_test.go     — canonical bridge-test file that
#                                        deliberately imports klog to verify
#                                        klog.InfoS routes through zap; this is
#                                        load-bearing regression coverage and the
#                                        only legitimate test-side import.
if grep -RIn --include='*.go' --exclude-dir=vendor \
        -E '"sigs\.k8s\.io/controller-runtime/pkg/log"|"k8s\.io/klog/v2"' \
        pkg cmd internal test 2>/dev/null \
        | grep -v '^pkg/logger/' \
        | grep -v '^test/integration/setup_test\.go:'; then
    echo "ERROR: direct import of controller-runtime log or klog/v2 found outside pkg/logger/." >&2
    echo "       Wire via logger.SetControllerRuntimeLogger from cmd/*/main.go." >&2
    exit 1
fi

echo "logger-wiring check: OK"
