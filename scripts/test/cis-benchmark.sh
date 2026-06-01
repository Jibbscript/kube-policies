#!/usr/bin/env bash
# cis-benchmark.sh — CIS Kubernetes Benchmark assessment (CFG-WU-13).
#
# Runs Aqua kube-bench against the live (kind) e2e cluster and writes a report
# artifact. This is an ASSESSMENT artifact (CA-2 evidence), NOT a pass/fail
# certification gate: many CIS 1.x/4.2.x controls are node/control-plane
# operator responsibilities that kube-policies neither configures nor can fix on
# a kind node, so this script is intentionally NON-GATING (it does not fail the
# build on kube-bench FAILs). See docs/compliance/cis-benchmark-results.md for
# the control owner mapping (node/operator vs chart responsibility).
#
# It runs kube-bench in-cluster as a Job (the same shape as the shipped manifest
# deployments/kubernetes/conformance/kube-bench-job.yaml, retargeted to the
# kube-system namespace which always exists) and captures both the human and
# JSON output as artifacts.
#
# Usage:
#   KIND_CLUSTER_NAME=kube-policies-test scripts/test/cis-benchmark.sh
# Env:
#   KIND_CLUSTER_NAME   kind cluster to target (default kube-policies-test)
#   KUBE_BENCH_IMAGE    kube-bench image (default docker.io/aquasec/kube-bench:v0.10.7)
#   REPORT_DIR          where to write artifacts (default test-results/cis-benchmark)
#   BENCH_TARGETS       kube-bench --targets (default "node,master")
# Requires: kubectl (and a reachable cluster), optionally kind.
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
exit 0
