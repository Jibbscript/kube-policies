#!/usr/bin/env bash
# lint-manifests.sh — manifest-hardening gate (CFG-WU-12 / CFG-WU-13 support).
#
# Renders the kube-policies chart in a realistically-CONFIGURED, hardened mode
# and validates every shipped manifest two ways:
#
#   1. kubeconform -strict   — structural / schema validation (no unknown fields,
#      required fields present) against the rendered chart AND the static
#      deployments/kubernetes/** manifests. Build-failing.
#
#   2. conftest restricted.pss — the Pod Security Standard "restricted" gate
#      (CIS 5.2.x / PSS-Restricted): seccompProfile, drop ALL, readOnlyRootFs,
#      no privilege escalation, runAsNonRoot, non-root runAsGroup, and
#      requests+limits for cpu+memory on every in-scope control-plane container,
#      plus PSA-restricted labels on shipped Namespaces. Build-failing on the
#      rendered chart and on the chart-owned base manifests.
#
# SCOPING / HONESTY NOTE:
#   - All three chart workloads (admission-webhook, policy-manager, dashboard)
#     carry seccompProfile RuntimeDefault + non-root runAsGroup natively in the
#     chart (CFG-WU-01/02/03), rendered from values. No --set injection is needed;
#     restricted.pss gates all three by default.
#   - The bundled monitoring workloads (prometheus/grafana/alertmanager) are
#     hardened (CFG-WU-06/07/08) and GATED here for the per-container restricted
#     controls, AND their kube-policies-monitoring Namespace is PSA-restricted-
#     labeled — all evaluated by the same GATING restricted.pss run over
#     deployments/kubernetes/monitoring/*.yaml (no advisory/non-gating pass).
#
# Usage: scripts/test/lint-manifests.sh
# Requires: helm, kubeconform, conftest on PATH.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

POLICY_DIR="test/policy"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

RENDERED="${WORKDIR}/rendered.yaml"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '==> %s\n' "$*"; }

for bin in helm kubeconform conftest; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    red "::error::required tool not found on PATH: ${bin}"
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# 1. Render the chart: dashboard on, namespace.create=true, configured ingress,
#    and the control-plane components hardened to the restricted profile via
#    --set (the securityContext fields are values-driven; CFG-WU-12).
# ---------------------------------------------------------------------------
info "Rendering chart (dashboard on, namespace.create=true, configured ingress)"
# Resolve gitignored subchart deps (prometheus/grafana) so the render succeeds
# on a fresh clone / CI runner.
bash "$(dirname "${BASH_SOURCE[0]}")/../ci/helm-deps.sh"
helm template kube-policies charts/kube-policies \
  --set dashboard.enabled=true \
  --set namespace.create=true \
  --set 'networkPolicy.webhook.ingressFrom.ipBlocks={10.0.0.0/24}' \
  --set 'networkPolicy.apiServerCIDRs={10.0.0.0/24}' \
  > "${RENDERED}"

# ---------------------------------------------------------------------------
# 2. kubeconform -strict over the rendered chart + static manifests.
# ---------------------------------------------------------------------------
info "kubeconform -strict — rendered chart"
kubeconform -strict -ignore-missing-schemas -summary "${RENDERED}"

info "kubeconform -strict — static deployments/kubernetes manifests"
# -ignore-missing-schemas skips the project's own CRD kinds (Policy/PolicyException)
# which have no published JSON schema; -strict still rejects unknown fields on
# known kinds.
find deployments/kubernetes -name '*.yaml' -o -name '*.yml' \
  | sort \
  | xargs kubeconform -strict -ignore-missing-schemas -summary

# ---------------------------------------------------------------------------
# 3. conftest restricted.pss — GATING on the rendered chart.
# ---------------------------------------------------------------------------
info "conftest restricted.pss — rendered chart (GATING)"
conftest test --policy "${POLICY_DIR}" --namespace restricted.pss "${RENDERED}"

# ---------------------------------------------------------------------------
# 4. conftest restricted.pss — GATING on the chart-owned base manifests.
# ---------------------------------------------------------------------------
if compgen -G "deployments/kubernetes/base/*.yaml" >/dev/null; then
  info "conftest restricted.pss — deployments/kubernetes/base (GATING)"
  conftest test --policy "${POLICY_DIR}" --namespace restricted.pss \
    deployments/kubernetes/base/*.yaml
fi

# ---------------------------------------------------------------------------
# 5. conftest restricted.pss — GATING on the bundled monitoring manifests.
#    The monitoring workloads are hardened (CFG-WU-06/07/08) and the
#    kube-policies-monitoring Namespace is PSA-restricted-labeled (CFG-WU-05/06),
#    so the monitoring stack is gated like the chart-owned manifests.
# ---------------------------------------------------------------------------
if compgen -G "deployments/kubernetes/monitoring/*.yaml" >/dev/null; then
  info "conftest restricted.pss — deployments/kubernetes/monitoring (GATING)"
  conftest test --policy "${POLICY_DIR}" --namespace restricted.pss \
    deployments/kubernetes/monitoring/*.yaml
fi

green "manifest-hardening gate: kubeconform -strict + restricted.pss passed on the rendered chart and chart-owned manifests."
