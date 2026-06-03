#!/usr/bin/env bash
#
# test-pss-admission-e2e.sh — P5 EXIT-GATE PROOF (CFG-WU-05 + CFG-WU-19):
# prove the hardened chart's pods are ADMITTED under a Pod Security Admission
# enforce=restricted namespace, that the enforcement is REAL (a de-hardened pod
# is REJECTED), and that drift-detect.sh exits NON-ZERO on a diverged baseline.
#
# WHY VANILLA KIND SUFFICES (no CNI needed)
# -----------------------------------------
# Pod Security Admission (PSA) is a built-in admission CONTROLLER in the
# kube-apiserver — it is enabled by default on Kubernetes v1.25+ and evaluates a
# pod's securityContext SYNCHRONOUSLY at pod-CREATE time, before any scheduling
# or networking. It needs nothing from the CNI. So unlike the NetworkPolicy
# proof (test-netpol-e2e.sh, which must install Calico), this proof runs on a
# plain default kind cluster. We never schedule the pods — `--dry-run=server`
# round-trips the object through the apiserver's admission chain (which includes
# PSA) and returns the verdict without pulling any image or starting a kubelet.
# That makes the proof fast and image-agnostic: PSA only inspects securityContext.
#
# WHAT IT PROVES (the P5 claim)
# -----------------------------
#   1. POSITIVE: each of the chart's three workloads (admission-webhook,
#      policy-manager, dashboard), with its real rendered securityContext, is
#      ADMITTED into a namespace labeled pod-security.kubernetes.io/enforce=
#      restricted (also audit/warn=restricted). No PodSecurity error.
#   2. NEGATIVE CONTROL: the SAME webhook pod with its hardening stripped
#      (seccompProfile removed, runAsNonRoot:false, allowPrivilegeEscalation
#      cleared, capabilities.drop removed) is REJECTED by restricted PSA. This
#      proves the namespace actually ENFORCES — the positive pass is not vacuous.
#   3. DRIFT (CFG-WU-19): scripts/ops/drift-detect.sh, run in `baseline` mode,
#      saves a baseline from the current chart, then is re-run after the saved
#      baseline is mutated — it must EXIT 2 (DRIFT) and print the divergence.
#
# DESIGN
# ------
# We render the chart's three Deployments with `helm template`, then transform
# each Deployment's spec.template into a standalone `kind: Pod` (carrying the
# Deployment's pod metadata + spec, with the container images swapped to
# registry.k8s.io/pause:3.9 since PSA only reads securityContext, not the image).
# Each Pod is `kubectl apply --dry-run=server` into the labeled namespace and we
# assert ADMITTED vs REJECTED. The transform uses `yq` (mikefarah v4); a pure-
# python3 fallback is used if yq is absent. The drift proof is offline-ish: it
# uses drift-detect.sh's `save` + `baseline` modes (no cluster needed for that
# step), and mutates the saved baseline to force a divergence.
#
# HOW TO RUN
# ----------
#   make test-pss-admission-e2e
#   # or directly:
#   bash scripts/test/test-pss-admission-e2e.sh
# Prereqs: kind, kubectl, helm, docker (running daemon), and yq OR python3 for
# the Deployment->Pod transform. The script creates a uniquely-named cluster
# (kp-pss-<pid>) and deletes it on exit via a trap. Keep it for debugging with
# CLEANUP=false.
#
# Env knobs:
#   KIND_CLUSTER_NAME   override the (unique) cluster name (default kp-pss-<pid>)
#   KUBERNETES_VERSION  kindest/node tag (default v1.31.2; PSA needs v1.25+)
#   CLEANUP             "false" to keep the cluster after the run
#   PSS_NS              labeled restricted namespace name (default pss-restricted)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHART_DIR="${PROJECT_ROOT}/charts/kube-policies"
DRIFT_SCRIPT="${PROJECT_ROOT}/scripts/ops/drift-detect.sh"

# Capture any CALLER-supplied overrides BEFORE sourcing lib.sh. lib.sh runs
# `: "${KIND_CLUSTER_NAME:=kube-policies-test}"` and
# `: "${KUBERNETES_VERSION:=v1.28.0}"` at source time, which ASSIGN those vars —
# so a `:-` default applied AFTER sourcing would be dead, and we'd silently run
# on the wrong (shared) cluster name and an old k8s. Snapshot intent here, then
# re-apply OUR defaults below.
_CALLER_CLUSTER_NAME="${KIND_CLUSTER_NAME:-}"
_CALLER_KUBE_VERSION="${KUBERNETES_VERSION:-}"

# Reuse the repo's shared log/error/success/warn helpers for consistent output.
# shellcheck source=./lib.sh
. "${SCRIPT_DIR}/lib.sh"

# Re-apply our defaults, honoring an explicit caller override (NOT lib.sh's
# shared kube-policies-test / v1.28.0 which it injected at source time).
KIND_CLUSTER_NAME="${_CALLER_CLUSTER_NAME:-kp-pss-$$}"
KUBERNETES_VERSION="${_CALLER_KUBE_VERSION:-v1.31.2}"
CLEANUP="${CLEANUP:-true}"
PSS_NS="${PSS_NS:-pss-restricted}"
HELM_RELEASE="kp"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/kp-pss.XXXXXX")"

# Track pass/fail across assertions so we can report a single final verdict.
FAILURES=0

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup_all() {
    local rc=$?
    if [ "${CLEANUP}" = "true" ]; then
        log "Cleaning up: deleting kind cluster ${KIND_CLUSTER_NAME} and workdir"
        kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
        rm -rf "${WORKDIR}" || true
        # Prove the cluster is gone.
        if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
            error "cluster ${KIND_CLUSTER_NAME} still present after cleanup"
        else
            success "cleanup complete — no dangling cluster ${KIND_CLUSTER_NAME}"
        fi
    else
        warn "CLEANUP=false — leaving cluster ${KIND_CLUSTER_NAME} and ${WORKDIR} in place"
    fi
    exit "${rc}"
}
trap cleanup_all EXIT

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
check_prerequisites() {
    log "Checking prerequisites..."
    local missing=0
    for bin in kind kubectl helm docker; do
        if ! command -v "${bin}" >/dev/null 2>&1; then
            error "${bin} is not installed"
            missing=1
        fi
    done
    if ! command -v yq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        error "need yq (mikefarah v4) OR python3 for the Deployment->Pod transform"
        missing=1
    fi
    [ "${missing}" -eq 0 ] || exit 1
    if ! docker info >/dev/null 2>&1; then
        error "docker daemon is not reachable (docker info failed). Start Docker and retry."
        exit 1
    fi
    success "All prerequisites present and docker is reachable"
}

# ---------------------------------------------------------------------------
# Vanilla kind cluster (default CNI — PSA is in the apiserver, CNI-independent)
# ---------------------------------------------------------------------------
create_cluster() {
    log "Creating vanilla kind cluster: ${KIND_CLUSTER_NAME} (k8s ${KUBERNETES_VERSION})"
    if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
        warn "Cluster ${KIND_CLUSTER_NAME} already exists. Deleting..."
        kind delete cluster --name "${KIND_CLUSTER_NAME}"
    fi
    kind create cluster --name "${KIND_CLUSTER_NAME}" --image "kindest/node:${KUBERNETES_VERSION}"
    success "kind cluster created"
    log "apiserver version:"
    kubectl version -o yaml 2>/dev/null | grep -E "gitVersion" | tail -1 || true
}

# ---------------------------------------------------------------------------
# Restricted namespace
# ---------------------------------------------------------------------------
create_restricted_namespace() {
    log "Creating namespace ${PSS_NS} labeled enforce/audit/warn=restricted"
    kubectl create namespace "${PSS_NS}" >/dev/null
    kubectl label namespace "${PSS_NS}" \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/enforce-version=latest \
        pod-security.kubernetes.io/audit=restricted \
        pod-security.kubernetes.io/warn=restricted \
        --overwrite >/dev/null
    log "Namespace labels:"
    kubectl get namespace "${PSS_NS}" -o jsonpath='{.metadata.labels}' ; echo

    # The "default" ServiceAccount is provisioned ASYNCHRONOUSLY by the SA
    # controller just after the namespace appears. Pods reference it, and the
    # apiserver's SA-existence admission check (which runs BEFORE PodSecurity)
    # rejects with `serviceaccount "default" not found` until it exists — which
    # would MASK the PSA verdict. Wait for it (or create it) before probing.
    log "Waiting for the default ServiceAccount in ${PSS_NS}..."
    local waited=0
    while [ "${waited}" -lt 30 ]; do
        if kubectl -n "${PSS_NS}" get serviceaccount default >/dev/null 2>&1; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if ! kubectl -n "${PSS_NS}" get serviceaccount default >/dev/null 2>&1; then
        warn "default SA not auto-created after 30s; creating it explicitly"
        kubectl -n "${PSS_NS}" create serviceaccount default >/dev/null 2>&1 || true
    fi
    success "restricted namespace ready (default SA present)"
}

# ---------------------------------------------------------------------------
# Deployment -> Pod transform
# ---------------------------------------------------------------------------
# Reads a single-Deployment YAML on stdin, writes a kind:Pod manifest on stdout.
# Carries the Deployment's pod template metadata (labels) + spec, sets the pod's
# name/namespace, and swaps every container image to pause:3.9 (PSA reads only
# securityContext; the image is irrelevant and we never schedule the pod anyway).
# We also DROP serviceAccountName / automountServiceAccountToken so the pod uses
# the always-present "default" SA: the apiserver's ServiceAccount-existence
# admission check runs BEFORE PodSecurity and would otherwise reject the pod
# ("serviceaccount ... not found") and MASK the PSA verdict we are proving.
deployment_to_pod() {
    local pod_name="$1" pod_ns="$2"
    if command -v yq >/dev/null 2>&1; then
        yq eval "
          {
            \"apiVersion\": \"v1\",
            \"kind\": \"Pod\",
            \"metadata\": {
              \"name\": \"${pod_name}\",
              \"namespace\": \"${pod_ns}\",
              \"labels\": .spec.template.metadata.labels
            },
            \"spec\": .spec.template.spec
          }
          | (.spec.containers[].image) = \"registry.k8s.io/pause:3.9\"
          | (.spec.initContainers[]?.image) = \"registry.k8s.io/pause:3.9\"
          | del(.spec.serviceAccountName)
          | del(.spec.serviceAccount)
          | del(.spec.automountServiceAccountToken)
        " -
    else
        pod_name="${pod_name}" pod_ns="${pod_ns}" python3 - <<'PY'
import os, sys, yaml
d = yaml.safe_load(sys.stdin)
tpl = d["spec"]["template"]
spec = tpl["spec"]
for c in spec.get("containers", []):
    c["image"] = "registry.k8s.io/pause:3.9"
for c in spec.get("initContainers", []):
    c["image"] = "registry.k8s.io/pause:3.9"
for k in ("serviceAccountName", "serviceAccount", "automountServiceAccountToken"):
    spec.pop(k, None)
pod = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": os.environ["pod_name"],
        "namespace": os.environ["pod_ns"],
        "labels": tpl.get("metadata", {}).get("labels", {}),
    },
    "spec": spec,
}
yaml.safe_dump(pod, sys.stdout, default_flow_style=False, sort_keys=False)
PY
    fi
}

# ---------------------------------------------------------------------------
# Render chart + split out the three Deployments
# ---------------------------------------------------------------------------
render_and_split() {
    log "Rendering chart (dashboard.enabled=true) and extracting the 3 Deployments"
    local rendered="${WORKDIR}/rendered.yaml"
    helm template "${HELM_RELEASE}" "${CHART_DIR}" --set dashboard.enabled=true \
        >"${rendered}" 2>"${WORKDIR}/helm.err" || {
            error "helm template failed:"; cat "${WORKDIR}/helm.err" >&2; exit 1; }

    # Split each Deployment into its own file keyed by .metadata.name.
    mkdir -p "${WORKDIR}/deploys"
    yq eval-all 'select(.kind == "Deployment")' "${rendered}" \
        | yq eval --split-exp '"'"${WORKDIR}"'/deploys/" + .metadata.name + ".yaml"' - 2>/dev/null || {
            # Fallback split if mikefarah split-exp is unavailable: one doc per file.
            warn "yq split-exp unavailable; using per-doc fallback split"
            yq eval-all 'select(.kind == "Deployment")' "${rendered}" \
                | csplit -s -z -f "${WORKDIR}/deploys/d" -b "%02d.yaml" - '/^---$/' '{*}' 2>/dev/null || true
        }

    local count
    count=$(find "${WORKDIR}/deploys" -name '*.yaml' | wc -l | tr -d ' ')
    if [ "${count}" -ne 3 ]; then
        error "expected 3 Deployments, found ${count}"
        find "${WORKDIR}/deploys" -name '*.yaml' -exec basename {} \; >&2
        exit 1
    fi
    success "extracted 3 Deployments: $(find "${WORKDIR}/deploys" -name '*.yaml' -exec basename {} .yaml \; | tr '\n' ' ')"
}

# ---------------------------------------------------------------------------
# POSITIVE: each hardened pod is ADMITTED
# ---------------------------------------------------------------------------
assert_admitted() {
    log "POSITIVE: applying each hardened chart pod with --dry-run=server into ${PSS_NS}"
    local f name pod out rc
    for f in "${WORKDIR}/deploys"/*.yaml; do
        name="$(basename "${f}" .yaml)"
        pod="${WORKDIR}/pod-${name}.yaml"
        deployment_to_pod "pss-${name}" "${PSS_NS}" <"${f}" >"${pod}"
        set +e
        out="$(kubectl apply --dry-run=server -f "${pod}" 2>&1)"
        rc=$?
        set -e
        if [ "${rc}" -eq 0 ] && ! printf '%s' "${out}" | grep -qi "violates PodSecurity"; then
            success "ADMITTED: ${name} -> ${out}"
        else
            error "EXPECTED ADMIT, GOT REJECT for ${name} (rc=${rc}):"
            printf '%s\n' "${out}" >&2
            FAILURES=$((FAILURES + 1))
        fi
    done
}

# ---------------------------------------------------------------------------
# NEGATIVE CONTROL: a de-hardened webhook pod is REJECTED
# ---------------------------------------------------------------------------
assert_rejected_negative_control() {
    log "NEGATIVE CONTROL: stripping hardening off the webhook pod -> expect REJECT"
    local src
    # The webhook deployment file is named for its rendered metadata.name; find it.
    src="$(find "${WORKDIR}/deploys" -name '*admission-webhook*' -o -name '*webhook*' | head -1)"
    [ -n "${src}" ] || src="$(find "${WORKDIR}/deploys" -name '*.yaml' | head -1)"

    local pod="${WORKDIR}/pod-negative.yaml"
    deployment_to_pod "pss-negative-control" "${PSS_NS}" <"${src}" >"${pod}.full"

    # Strip the restricted-required hardening: remove seccompProfile at both
    # pod and container scope, set runAsNonRoot:false, clear capabilities.drop,
    # and allowPrivilegeEscalation. ANY of these makes restricted PSA reject.
    if command -v yq >/dev/null 2>&1; then
        yq eval '
            del(.spec.securityContext.seccompProfile)
            | del(.spec.containers[].securityContext.seccompProfile)
            | .spec.securityContext.runAsNonRoot = false
            | (.spec.containers[].securityContext.runAsNonRoot) = false
            | (.spec.containers[].securityContext.allowPrivilegeEscalation) = true
            | del(.spec.containers[].securityContext.capabilities)
        ' "${pod}.full" >"${pod}"
    else
        python3 - "${pod}.full" >"${pod}" <<'PY'
import sys, yaml
with open(sys.argv[1]) as fh:
    d = yaml.safe_load(fh)
sc = d["spec"].setdefault("securityContext", {})
sc.pop("seccompProfile", None)
sc["runAsNonRoot"] = False
for c in d["spec"].get("containers", []):
    csc = c.setdefault("securityContext", {})
    csc.pop("seccompProfile", None)
    csc.pop("capabilities", None)
    csc["runAsNonRoot"] = False
    csc["allowPrivilegeEscalation"] = True
yaml.safe_dump(d, sys.stdout, default_flow_style=False, sort_keys=False)
PY
    fi

    local out rc
    set +e
    out="$(kubectl apply --dry-run=server -f "${pod}" 2>&1)"
    rc=$?
    set -e
    if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -qi "violates PodSecurity"; then
        success "REJECTED as expected. apiserver message:"
        printf '%s\n' "${out}"
    else
        error "EXPECTED REJECT, but pod was ADMITTED (rc=${rc}) — namespace not enforcing!"
        printf '%s\n' "${out}" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

# ---------------------------------------------------------------------------
# DRIFT (CFG-WU-19): drift-detect.sh exits NON-ZERO on a diverged baseline
# ---------------------------------------------------------------------------
assert_drift_nonzero() {
    log "DRIFT: drift-detect.sh baseline mode — save, then mutate baseline -> expect exit 2"
    local baseline="${WORKDIR}/kp-baseline.yaml"
    local rc

    # 1. Save a clean baseline from the current chart (always exit 0).
    set +e
    "${DRIFT_SCRIPT}" --mode save --baseline "${baseline}" >"${WORKDIR}/drift-save.log" 2>&1
    rc=$?
    set -e
    if [ "${rc}" -ne 0 ]; then
        error "drift-detect save unexpectedly failed (rc=${rc}):"; cat "${WORKDIR}/drift-save.log" >&2
        FAILURES=$((FAILURES + 1)); return
    fi
    log "saved baseline (rc=${rc}); $(wc -l <"${baseline}" | tr -d ' ') lines"

    # 1b. Sanity: an UNMUTATED baseline must report NO DRIFT (exit 0).
    set +e
    "${DRIFT_SCRIPT}" --mode baseline --baseline "${baseline}" >"${WORKDIR}/drift-nodrift.log" 2>&1
    rc=$?
    set -e
    if [ "${rc}" -eq 0 ]; then
        success "control: unmutated baseline reports NO DRIFT (exit 0)"
    else
        error "control failed: unmutated baseline did not exit 0 (rc=${rc}):"; cat "${WORKDIR}/drift-nodrift.log" >&2
        FAILURES=$((FAILURES + 1))
    fi

    # 2. Mutate the saved baseline to simulate cluster/config drift, then re-run.
    #    Append a bogus resource so the rendered chart no longer matches it.
    printf '\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: drift-injected\n  namespace: kube-policies-system\ndata:\n  tampered: "true"\n' >>"${baseline}"

    set +e
    "${DRIFT_SCRIPT}" --mode baseline --baseline "${baseline}" >"${WORKDIR}/drift-detect.log" 2>&1
    rc=$?
    set -e
    if [ "${rc}" -eq 2 ]; then
        success "DRIFT detected: drift-detect.sh exited ${rc} (non-zero) as required (CFG-WU-19)"
        log "drift output (head):"
        head -20 "${WORKDIR}/drift-detect.log"
    else
        error "EXPECTED non-zero drift exit (2), got rc=${rc}:"; cat "${WORKDIR}/drift-detect.log" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "=== P5 PSA admission + drift exit-gate proof (CFG-WU-05 + CFG-WU-19) ==="
    check_prerequisites
    create_cluster
    create_restricted_namespace
    render_and_split
    assert_admitted
    assert_rejected_negative_control
    assert_drift_nonzero

    echo
    if [ "${FAILURES}" -eq 0 ]; then
        success "=== ALL P5 EXIT-GATE ASSERTIONS PASSED ==="
    else
        error "=== ${FAILURES} P5 EXIT-GATE ASSERTION(S) FAILED ==="
        exit 1
    fi
}

main "$@"
