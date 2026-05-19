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
