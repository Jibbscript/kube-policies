#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kube-policies-validate.XXXXXX")"

cleanup() {
	rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

missing=0
require_tool() {
	local tool="$1"
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf 'required validation tool missing: %s\n' "${tool}" >&2
		missing=1
	fi
}

for tool in helm yq jq promtool amtool kubeconform; do
	require_tool "${tool}"
done

if [[ "${missing}" -ne 0 ]]; then
	cat >&2 <<'EOF'

Install the missing tools and rerun `make validate-manifests`.
Suggested macOS installs:
  brew install helm yq jq prometheus alertmanager kubeconform

Go install fallbacks:
  go install github.com/yannh/kubeconform/cmd/kubeconform@latest
  go install github.com/prometheus/alertmanager/cmd/amtool@latest
EOF
	exit 127
fi

cd "${ROOT_DIR}"

echo "==> Helm lint"
helm lint charts/kube-policies

echo "==> Helm render"
helm template kube-policies charts/kube-policies --include-crds >"${TMP_DIR}/helm-template.yaml"
yq '.' "${TMP_DIR}/helm-template.yaml" >/dev/null

echo "==> YAML syntax"
while IFS= read -r file; do
	yq '.' "${file}" >/dev/null
done < <(
	find charts/kube-policies deployments/kubernetes monitoring examples demo/capture/fixtures test/e2e/fixtures \
		-type f \( -name '*.yaml' -o -name '*.yml' \) \
		! -path 'charts/kube-policies/templates/*' \
		| sort
)

echo "==> Grafana dashboard JSON"
while IFS= read -r file; do
	jq -e '.' "${file}" >/dev/null
done < <(find monitoring/grafana/dashboards -type f -name '*.json' | sort)

echo "==> Prometheus config syntax"
promtool check config --syntax-only monitoring/prometheus/prometheus.yaml
yq -r 'select(.kind == "ConfigMap" and .metadata.name == "prometheus-config") | .data."prometheus.yml"' \
	deployments/kubernetes/monitoring/prometheus-deployment.yaml >"${TMP_DIR}/prometheus-embedded.yml"
test -s "${TMP_DIR}/prometheus-embedded.yml"
promtool check config --syntax-only "${TMP_DIR}/prometheus-embedded.yml"

echo "==> Prometheus rules"
yq -r 'select(.kind == "ConfigMap" and .metadata.name == "prometheus-rules") | .data."kube-policies.yml"' \
	deployments/kubernetes/monitoring/prometheus-deployment.yaml >"${TMP_DIR}/kube-policies-rules.yml"
test -s "${TMP_DIR}/kube-policies-rules.yml"
promtool check rules "${TMP_DIR}/kube-policies-rules.yml"

echo "==> Alertmanager config"
amtool check-config monitoring/alertmanager/alertmanager.yaml
yq -r 'select(.kind == "ConfigMap" and .metadata.name == "alertmanager-config") | .data."alertmanager.yml"' \
	deployments/kubernetes/monitoring/alertmanager-deployment.yaml >"${TMP_DIR}/alertmanager-embedded.yml"
test -s "${TMP_DIR}/alertmanager-embedded.yml"
amtool check-config "${TMP_DIR}/alertmanager-embedded.yml"

echo "==> Kubernetes schema validation"
kubeconform -strict -summary -ignore-missing-schemas \
	"${TMP_DIR}/helm-template.yaml" \
	deployments/kubernetes/base/*.yaml \
	deployments/kubernetes/crds/*.yaml \
	deployments/kubernetes/monitoring/*.yaml \
	examples/policies/*.yaml \
	examples/exceptions/*.yaml \
	demo/capture/fixtures/*.yaml \
	test/e2e/fixtures/*.yaml

# IAM-WU-11 regression guard: verify the admission-webhook pod renders the
# projected serviceAccountToken volume with the expected audience and a TTL
# <= 3600s, and that the --policy-manager-token-path arg matches the mount.
# Guard on yq availability so this no-ops gracefully when yq is absent.
if command -v yq >/dev/null 2>&1; then
	echo "==> IAM-WU-11: projected token volume assertion (tokenreview mode)"
	# Render with default values (tokenreview mode).
	helm template kube-policies charts/kube-policies >"${TMP_DIR}/helm-tr.yaml"

	# Extract the serviceAccountToken audience from the webhook Deployment.
	_aud="$(yq '
		select(.kind == "Deployment" and .metadata.name == "*-admission-webhook")
		| .spec.template.spec.volumes[]
		| select(.name == "pm-internal-token")
		| .projected.sources[]
		| select(has("serviceAccountToken"))
		| .serviceAccountToken.audience
	' "${TMP_DIR}/helm-tr.yaml" | head -1)"

	_exp="$(yq '
		select(.kind == "Deployment" and .metadata.name == "*-admission-webhook")
		| .spec.template.spec.volumes[]
		| select(.name == "pm-internal-token")
		| .projected.sources[]
		| select(has("serviceAccountToken"))
		| .serviceAccountToken.expirationSeconds
	' "${TMP_DIR}/helm-tr.yaml" | head -1)"

	_arg="$(yq '
		select(.kind == "Deployment" and .metadata.name == "*-admission-webhook")
		| .spec.template.spec.containers[]
		| select(.name == "admission-webhook")
		| .args[]
		| select(test("^--policy-manager-token-path="))
	' "${TMP_DIR}/helm-tr.yaml" | head -1)"

	_ok=1
	if [[ -z "${_aud}" ]]; then
		printf 'IAM-WU-11 FAIL: pm-internal-token projected volume not found in admission-webhook Deployment\n' >&2
		_ok=0
	elif [[ "${_aud}" != "policy-manager" ]]; then
		printf 'IAM-WU-11 FAIL: projected token audience=%q want "policy-manager"\n' "${_aud}" >&2
		_ok=0
	fi
	if [[ -n "${_exp}" ]] && [[ "${_exp}" -gt 3600 ]]; then
		printf 'IAM-WU-11 FAIL: projected token expirationSeconds=%s exceeds 3600s (1h)\n' "${_exp}" >&2
		_ok=0
	fi
	_expected_path="--policy-manager-token-path=/var/run/secrets/kube-policies/pm-token/token"
	if [[ "${_arg}" != "${_expected_path}" ]]; then
		printf 'IAM-WU-11 FAIL: --policy-manager-token-path arg=%q want %q\n' "${_arg}" "${_expected_path}" >&2
		_ok=0
	fi
	if [[ "${_ok}" -eq 1 ]]; then
		printf '    IAM-WU-11 projected token volume: audience=%s expirationSeconds=%s arg=%s OK\n' \
			"${_aud}" "${_exp}" "${_arg}"
	else
		exit 1
	fi
fi
