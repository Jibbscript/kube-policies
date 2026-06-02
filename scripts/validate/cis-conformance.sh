#!/usr/bin/env bash
# cis-conformance.sh — CIS Kubernetes Benchmark conformance (P12-WU-05, CFG-WU-13).
#
# Two-part CIS conformance evidence:
#
#   1. kube-bench (node/control-plane).  Runs Aqua kube-bench against the live
#      (kind) e2e cluster and writes a report artifact. This is an ASSESSMENT
#      artifact (CA-2 evidence), NOT a pass/fail certification gate: many CIS
#      1.x/4.2.x controls are node/control-plane operator responsibilities that
#      kube-policies neither configures nor can fix on a kind node, so this step
#      is intentionally NON-GATING (it does not fail the build on kube-bench
#      FAILs). See docs/compliance/cis-benchmark-results.md for the control owner
#      mapping (node/operator vs chart responsibility) and
#      docs/compliance/assessment/cis-benchmark-results.md for the recorded
#      findings disposition.
#
#   2. Pod Security Standard (restricted) — the chart-owned CIS 5.2.x controls.
#      Renders the kube-policies chart and runs the same conftest restricted.pss
#      policy that scripts/test/lint-manifests.sh enforces (seccompProfile, drop
#      ALL, readOnlyRootFs, no privilege escalation, runAsNonRoot, non-root
#      runAsGroup). This step is REPORTED clearly and reflects the chart-owned
#      restricted Pod Security Standard posture for the shipped workloads.
#
# kube-bench runs in-cluster as a Job (the same shape as the shipped manifest
# deployments/kubernetes/conformance/kube-bench-job.yaml, retargeted to the
# kube-system namespace which always exists) and captures both the human and
# JSON output as artifacts.
#
# Usage:
#   KIND_CLUSTER_NAME=kube-policies-test scripts/validate/cis-conformance.sh
# Env:
#   KIND_CLUSTER_NAME   kind cluster to target (default kube-policies-test)
#   KUBE_BENCH_IMAGE    kube-bench image (default docker.io/aquasec/kube-bench:v0.10.7)
#   REPORT_DIR          where to write artifacts (default test-results/cis-benchmark)
#   BENCH_TARGETS       kube-bench --targets (default "node,master")
# Requires: kubectl (and a reachable cluster), optionally kind. The PSS-restricted
#   step additionally requires helm + conftest on PATH (skipped with a warning if
#   absent so the kube-bench assessment still runs).
set -euo pipefail

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kube-policies-test}"
KUBE_BENCH_IMAGE="${KUBE_BENCH_IMAGE:-docker.io/aquasec/kube-bench:v0.10.7}"
BENCH_TARGETS="${BENCH_TARGETS:-node,master}"
NAMESPACE="kube-system"
JOB_NAME="kube-bench-cis"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${REPORT_DIR:-${REPO_ROOT}/test-results/cis-benchmark}"
mkdir -p "${REPORT_DIR}"

info() { printf '==> %s\n' "$*"; }

if ! command -v kubectl >/dev/null 2>&1; then
  echo "::error::kubectl not found on PATH" >&2
  exit 1
fi

# If a kind cluster of this name exists, point kubectl at it.
if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER_NAME}"; then
  info "Targeting kind cluster ${KIND_CLUSTER_NAME}"
  kind export kubeconfig --name "${KIND_CLUSTER_NAME}" || true
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "::error::no reachable cluster (kubectl cluster-info failed)" >&2
  exit 1
fi

# Clean any prior run.
kubectl -n "${NAMESPACE}" delete job "${JOB_NAME}" --ignore-not-found >/dev/null 2>&1 || true

info "Launching kube-bench Job (${KUBE_BENCH_IMAGE}, targets=${BENCH_TARGETS}) in ${NAMESPACE}"
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: kube-policies
    app.kubernetes.io/component: conformance
spec:
  ttlSecondsAfterFinished: 600
  backoffLimit: 1
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kube-policies
        app.kubernetes.io/component: conformance
    spec:
      hostPID: true
      restartPolicy: Never
      automountServiceAccountToken: false
      containers:
        - name: kube-bench
          image: ${KUBE_BENCH_IMAGE}
          command: ["kube-bench"]
          args: ["run", "--targets", "${BENCH_TARGETS}", "--json"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            runAsGroup: 65534
            seccompProfile:
              type: RuntimeDefault
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - { name: var-lib-kubelet, mountPath: /var/lib/kubelet, readOnly: true }
            - { name: etc-systemd, mountPath: /etc/systemd, readOnly: true }
            - { name: etc-kubernetes, mountPath: /etc/kubernetes, readOnly: true }
      volumes:
        - { name: var-lib-kubelet, hostPath: { path: /var/lib/kubelet } }
        - { name: etc-systemd, hostPath: { path: /etc/systemd } }
        - { name: etc-kubernetes, hostPath: { path: /etc/kubernetes } }
YAML

# Wait for completion (either complete or failed — kube-bench exits non-zero
# when controls FAIL, which is expected on a kind node and must NOT abort us).
info "Waiting for kube-bench Job to finish"
kubectl -n "${NAMESPACE}" wait --for=condition=complete "job/${JOB_NAME}" --timeout=180s \
  || kubectl -n "${NAMESPACE}" wait --for=condition=failed "job/${JOB_NAME}" --timeout=10s \
  || true

JSON_OUT="${REPORT_DIR}/kube-bench-results.json"
TXT_OUT="${REPORT_DIR}/kube-bench-results.txt"

# Capture logs (the --json arg makes kube-bench emit JSON to stdout).
kubectl -n "${NAMESPACE}" logs "job/${JOB_NAME}" > "${JSON_OUT}" 2>/dev/null || true
kubectl -n "${NAMESPACE}" logs "job/${JOB_NAME}" > "${TXT_OUT}" 2>/dev/null || true

if [ ! -s "${JSON_OUT}" ]; then
  echo "::warning::kube-bench produced no output (Job may not have scheduled on this node)" >&2
fi

# Summarise PASS/FAIL/WARN counts from the JSON when jq is available; otherwise
# leave the raw report for the artifact. NON-GATING: we always exit 0.
if command -v jq >/dev/null 2>&1 && [ -s "${JSON_OUT}" ]; then
  info "kube-bench summary (assessment only, non-gating):"
  jq -r '[.Totals.total_pass, .Totals.total_fail, .Totals.total_warn, .Totals.total_info]
         | "  PASS=\(.[0]) FAIL=\(.[1]) WARN=\(.[2]) INFO=\(.[3])"' "${JSON_OUT}" 2>/dev/null \
    || echo "  (could not parse JSON totals — see ${JSON_OUT})"
fi

info "CIS benchmark assessment written to ${REPORT_DIR}/ (kube-bench-results.json/.txt)"
info "This is an assessment artifact, not a certification. See docs/compliance/cis-benchmark-results.md."

# ---------------------------------------------------------------------------
# Pod Security Standard (restricted) conformance — chart-owned CIS 5.2.x.
#
# Render the kube-policies chart and run the same conftest restricted.pss policy
# that scripts/test/lint-manifests.sh enforces as the manifest-hardening gate.
# This is the chart-owned half of CIS 5.x conformance: unlike the node/control-
# plane kube-bench controls above (operator-owned, non-gating here), the
# restricted Pod Security Standard for the shipped workloads is something KP owns
# and reports clearly. The result is captured as an artifact alongside the
# kube-bench report.
# ---------------------------------------------------------------------------
PSS_OUT="${REPORT_DIR}/pss-restricted-conftest.txt"
POLICY_DIR="${REPO_ROOT}/test/policy"

if command -v helm >/dev/null 2>&1 && command -v conftest >/dev/null 2>&1; then
  info "Pod Security Standard (restricted) conformance — rendering chart + conftest restricted.pss"
  RENDERED="$(mktemp)"
  # Resolve gitignored subchart deps (prometheus/grafana) so the render succeeds
  # on a fresh clone / CI runner (mirrors scripts/test/lint-manifests.sh).
  bash "$(dirname "${BASH_SOURCE[0]}")/../ci/helm-deps.sh"
  helm template kube-policies "${REPO_ROOT}/charts/kube-policies" \
    --set dashboard.enabled=true \
    --set namespace.create=true \
    --set 'networkPolicy.webhook.ingressFrom.ipBlocks={10.0.0.0/24}' \
    --set 'networkPolicy.apiServerCIDRs={10.0.0.0/24}' \
    > "${RENDERED}"

  # Capture the conftest output as an artifact AND surface it on the console.
  # Reported clearly: a non-zero conftest exit means a chart workload regressed
  # the restricted Pod Security Standard (CIS 5.2.x) — independently GATING in
  # the manifest-hardening-gate job (scripts/test/lint-manifests.sh).
  if conftest test --policy "${POLICY_DIR}" --namespace restricted.pss "${RENDERED}" \
       2>&1 | tee "${PSS_OUT}"; then
    info "Pod Security Standard (restricted): PASS for all shipped chart workloads (CIS 5.2.x)"
  else
    echo "::warning::Pod Security Standard (restricted) conformance reported FAIL(s) — see ${PSS_OUT}. This is independently GATING in the manifest-hardening-gate job." >&2
  fi
  rm -f "${RENDERED}"
else
  echo "::warning::helm/conftest not on PATH — skipping the Pod Security Standard (restricted) conformance step. The manifest-hardening-gate job (scripts/test/lint-manifests.sh) still enforces it." >&2
fi

info "CIS conformance complete. See docs/compliance/assessment/cis-benchmark-results.md for the recorded findings disposition."
exit 0
