#!/usr/bin/env bash
#
# drift-detect.sh — Configuration drift detection for Kube-Policies (CFG-WU-19).
#
# Renders the kube-policies Helm chart (the CM-2 baseline-as-code) and detects
# divergence between that baseline and either (a) the live cluster or (b) a saved
# baseline render. On divergence it prints the diff and EXITS NON-ZERO, so it can
# gate a job or alert an operator.
#
# Modes:
#   cluster  (default) — render the chart, then `kubectl diff` it against the
#                        running cluster. Non-zero exit == the live state differs
#                        from the chart-rendered baseline (drift).
#   baseline           — render the chart and `diff` it against a previously saved
#                        baseline file (--baseline FILE). No cluster required.
#   save               — render the chart and write the baseline file (--baseline
#                        FILE) for later `baseline`-mode comparison. Always exit 0.
#
# Docs: docs/compliance/drift-detection.md
# Policy/plan: docs/compliance/policies/CM-policy.md,
#              docs/compliance/plans/configuration-management-plan.md
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="${ROOT_DIR}/charts/kube-policies"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kube-policies-drift.XXXXXX")"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

# Exit codes:
#   0   no drift
#   1   internal/usage error (bad args, render failure)
#   2   DRIFT detected (live/baseline diverges from the rendered baseline)
#   127 required tool missing
EXIT_OK=0
EXIT_ERR=1
EXIT_DRIFT=2
EXIT_MISSING=127

MODE="cluster"
RELEASE="kube-policies"
NAMESPACE="kube-policies-system"
BASELINE_FILE=""
VALUES_ARGS=()

usage() {
	cat <<'EOF'
Usage: drift-detect.sh [--mode cluster|baseline|save] [options]

Options:
  --mode MODE             cluster (default) | baseline | save
  --release NAME          Helm release name (default: kube-policies)
  --namespace NS          target namespace (default: kube-policies-system)
  --baseline FILE         baseline render file (required for baseline/save modes)
  --values FILE           extra Helm values file (repeatable)
  --set KEY=VALUE         extra Helm --set override (repeatable)
  -h, --help              show this help

Exit: 0 = no drift; 2 = DRIFT detected; 1 = error; 127 = missing tool.

Examples:
  # Detect drift against the live cluster (exits 2 on divergence):
  scripts/ops/drift-detect.sh --release kube-policies --namespace kube-policies-system

  # Save a baseline, then later compare against it (no cluster needed):
  scripts/ops/drift-detect.sh --mode save     --baseline /tmp/kp-baseline.yaml
  scripts/ops/drift-detect.sh --mode baseline --baseline /tmp/kp-baseline.yaml
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--mode)      MODE="${2:?--mode needs a value}"; shift 2 ;;
		--release)   RELEASE="${2:?--release needs a value}"; shift 2 ;;
		--namespace) NAMESPACE="${2:?--namespace needs a value}"; shift 2 ;;
		--baseline)  BASELINE_FILE="${2:?--baseline needs a value}"; shift 2 ;;
		--values)    VALUES_ARGS+=("--values" "${2:?--values needs a value}"); shift 2 ;;
		--set)       VALUES_ARGS+=("--set" "${2:?--set needs a value}"); shift 2 ;;
		-h|--help)   usage; exit "${EXIT_OK}" ;;
		*) printf 'drift-detect: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit "${EXIT_ERR}" ;;
	esac
done

case "${MODE}" in
	cluster|baseline|save) ;;
	*) printf 'drift-detect: invalid --mode %q (want cluster|baseline|save)\n' "${MODE}" >&2; exit "${EXIT_ERR}" ;;
esac

missing=0
require_tool() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'required tool missing: %s\n' "$1" >&2
		missing=1
	fi
}
require_tool helm
if [[ "${MODE}" == "cluster" ]]; then
	require_tool kubectl
fi
if [[ "${missing}" -ne 0 ]]; then
	cat >&2 <<'EOF'

Install the missing tools and rerun. Suggested installs:
  brew install helm kubernetes-cli
EOF
	exit "${EXIT_MISSING}"
fi

if [[ "${MODE}" == "baseline" || "${MODE}" == "save" ]] && [[ -z "${BASELINE_FILE}" ]]; then
	printf 'drift-detect: --baseline FILE is required for --mode %s\n' "${MODE}" >&2
	exit "${EXIT_ERR}"
fi

RENDER="${TMP_DIR}/rendered.yaml"

# normalize_render: strip non-deterministic, legitimately-rotating material so the
# diff reflects real CONFIGURATION drift (the CM-2/CM-6 baseline) rather than
# ephemeral data. The chart's demo autoGenerate paths emit fresh material on every
# render and are NOT baseline drift:
#   - TLS certs (genCA/genSignedCert: tls.crt/tls.key/ca.crt/caBundle)
#   - content-hash pod annotations (checksum/*)
#   - demo auto-generated Secret data: the static internal-token (randAlphaNum 48,
#     internal-token-secret.yaml) and the audit-integrity HMAC key (randAlphaNum 64,
#     audit-integrity-secret.yaml), both base64-encoded under a Secret data
#     token:/key:. These are matched ONLY when the value is a quoted base64 blob
#     of >=40 chars, so short legitimate values (e.g. secretKeyRef `key: admin-...`)
#     are NOT blanked. Operator-supplied tokens/keys are stable and unaffected.
normalize_render() {
	# shellcheck disable=SC2016
	sed -E \
		-e 's/^([[:space:]]*tls\.crt:).*$/\1 <redacted-tls-material>/' \
		-e 's/^([[:space:]]*tls\.key:).*$/\1 <redacted-tls-material>/' \
		-e 's/^([[:space:]]*ca\.crt:).*$/\1 <redacted-tls-material>/' \
		-e 's/^([[:space:]]*caBundle:).*$/\1 <redacted-tls-material>/' \
		-e 's#^([[:space:]]*checksum/[a-z-]+:).*$#\1 <redacted-checksum>#' \
		-e 's/^([[:space:]]*(token|key):)[[:space:]]+"[A-Za-z0-9+/=]{40,}"[[:space:]]*$/\1 <redacted-secret>/' \
		"$1"
}

echo "==> Rendering chart baseline (release=${RELEASE}, namespace=${NAMESPACE})"
# Render the chart with CRDs so the deployable baseline is complete. Any extra
# values/sets the operator passes (to match their deployment) are appended.
if ! helm template "${RELEASE}" "${CHART_DIR}" \
		--namespace "${NAMESPACE}" \
		--include-crds \
		${VALUES_ARGS[@]+"${VALUES_ARGS[@]}"} >"${RENDER}" 2>"${TMP_DIR}/helm.err"; then
	echo "==> ERROR: helm template failed:" >&2
	cat "${TMP_DIR}/helm.err" >&2
	exit "${EXIT_ERR}"
fi

# Normalized render (volatile TLS material / checksums blanked) — the basis for
# all comparisons so legitimately-rotating data is not reported as drift.
NORM="${TMP_DIR}/normalized.yaml"
normalize_render "${RENDER}" >"${NORM}"

case "${MODE}" in
	save)
		cp "${NORM}" "${BASELINE_FILE}"
		echo "==> Saved (normalized) baseline render to ${BASELINE_FILE}"
		exit "${EXIT_OK}"
		;;

	baseline)
		if [[ ! -f "${BASELINE_FILE}" ]]; then
			printf 'drift-detect: baseline file not found: %s\n' "${BASELINE_FILE}" >&2
			exit "${EXIT_ERR}"
		fi
		echo "==> Comparing rendered baseline against saved baseline ${BASELINE_FILE}"
		# Normalize the saved baseline too, so a baseline saved by an older run (or
		# by `save` mode) compares apples-to-apples regardless of when it was written.
		normalize_render "${BASELINE_FILE}" >"${TMP_DIR}/baseline.norm"
		if diff -u "${TMP_DIR}/baseline.norm" "${NORM}" >"${TMP_DIR}/diff.txt"; then
			echo "==> NO DRIFT: rendered baseline matches the saved baseline."
			exit "${EXIT_OK}"
		fi
		echo "==> DRIFT DETECTED: rendered baseline diverges from the saved baseline:" >&2
		cat "${TMP_DIR}/diff.txt" >&2
		exit "${EXIT_DRIFT}"
		;;

	cluster)
		echo "==> Diffing rendered baseline against the live cluster (kubectl diff)"
		# `kubectl diff` exits:
		#   0  -> no difference (live == baseline)        => no drift
		#   1  -> differences found                       => DRIFT
		#   >1 -> error talking to the cluster            => error
		# We feed the NORMALIZED render so rotating TLS material / pod-template
		# checksums are not reported as drift; structural/config drift still shows.
		set +e
		kubectl diff -f "${NORM}" >"${TMP_DIR}/kubectl-diff.txt" 2>"${TMP_DIR}/kubectl-diff.err"
		kdrc=$?
		set -e
		case "${kdrc}" in
			0)
				echo "==> NO DRIFT: live cluster matches the chart-rendered baseline."
				exit "${EXIT_OK}"
				;;
			1)
				echo "==> DRIFT DETECTED: live cluster diverges from the chart-rendered baseline:" >&2
				cat "${TMP_DIR}/kubectl-diff.txt" >&2
				exit "${EXIT_DRIFT}"
				;;
			*)
				echo "==> ERROR: kubectl diff failed (could not reach/compare the cluster):" >&2
				cat "${TMP_DIR}/kubectl-diff.err" >&2
				exit "${EXIT_ERR}"
				;;
		esac
		;;
esac
