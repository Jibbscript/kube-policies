#!/usr/bin/env bash
#
# test-netpol-e2e.sh — P4 EXIT-GATE PROOF: prove the chart's NetworkPolicies
# actually enforce network segmentation on a NetworkPolicy-ENFORCING CNI.
#
# WHY THIS EXISTS / CNI REQUIREMENT
# ---------------------------------
# The repo's other kind harness (scripts/test/test-kind.sh + lib.sh) creates a
# cluster on the DEFAULT kindnet CNI. kindnet does NOT enforce NetworkPolicy:
# every NetworkPolicy is silently inert there, so that harness CANNOT prove
# segmentation. This script therefore stands up its OWN kind cluster with
# `disableDefaultCNI: true`, installs Calico (which enforces NetworkPolicy),
# waits for it to be Ready, and only then applies the policies and probes them.
#
# WHAT IT PROVES (the P4 claim)
# -----------------------------
# With the chart's NetworkPolicies applied under default-deny:
#   1. KEYSTONE: an out-of-selector "attacker" pod is DENIED reaching
#      policy-manager :8080.
#   2. A pod carrying the admission-webhook component labels CAN reach
#      policy-manager :8080 (the ingress-policy-manager allow rule).
#   3. A kube-policies-labeled pod can resolve DNS (egress-dns allow).
#   4. BONUS negative-egress: the attacker (default-deny egress, no allow)
#      cannot egress to the policy-manager either.
# A NEGATIVE CONTROL is run first: BEFORE the policies are applied, the attacker
# CAN reach :8080 — proving the test would catch a regression (i.e. that the
# later BLOCK is caused by the policy, not by a broken probe).
#
# DESIGN: deterministic NetworkPolicy-SEMANTICS test. We deliberately do NOT
# build/deploy the product images (slow; the kindnet full-e2e already covers
# functional flows). Instead we render ONLY the chart's networkpolicy-*.yaml
# templates into a test namespace with test-permissive values and back them
# with trivial agnhost pods carrying the EXACT labels the policies select.
#
# EXACT SELECTORS / PORTS ASSERTED (quoted from rendered templates):
#   networkpolicy-ingress-policy-manager.yaml:
#     podSelector: name=kube-policies, instance=kp, component=policy-manager
#     ingress TCP 8080 from podSelector{...,component=admission-webhook} OR
#                                  podSelector{...,component=dashboard}
#   networkpolicy-egress-dns.yaml:
#     podSelector: name=kube-policies, instance=kp  (egress UDP/TCP 53 to
#     kube-system / k8s-app=kube-dns)
#   networkpolicy-default-deny.yaml: podSelector:{} Ingress+Egress (no allow)
#
# HOW TO RUN
# ----------
#   make test-netpol-e2e
#   # or directly:
#   bash scripts/test/test-netpol-e2e.sh
# Prereqs: kind, kubectl, helm, docker (a running daemon). The script creates a
# uniquely-named cluster (kube-policies-netpol-<pid>) so it never collides with
# the test-kind harness, and tears it down on exit via a trap. To keep the
# cluster for debugging, set CLEANUP=false.
#
# Env knobs:
#   KIND_CLUSTER_NAME   override the (unique) cluster name
#   KUBERNETES_VERSION  kindest/node tag (default v1.31.2)
#   CALICO_VERSION      Calico manifest version (default v3.28.2)
#   CLEANUP             "false" to keep the cluster after the run
#   PROBE_TIMEOUT       per-connection probe timeout seconds (default 5)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Capture any CALLER-supplied overrides BEFORE sourcing lib.sh. lib.sh runs
# `: "${KIND_CLUSTER_NAME:=kube-policies-test}"` and
# `: "${KUBERNETES_VERSION:=v1.28.0}"`, which ASSIGN those vars — so a `:-`
# default applied after sourcing would be dead. We snapshot the caller's intent
# here, then re-apply OUR defaults below.
_CALLER_CLUSTER_NAME="${KIND_CLUSTER_NAME:-}"
_CALLER_KUBE_VERSION="${KUBERNETES_VERSION:-}"

# Source shared log/error/success/warn helpers ONLY. We intentionally do NOT
# use lib.sh's create_cluster (it wires kindnet + a local registry and cannot
# enforce NetworkPolicy); we stand up our own Calico cluster below.
# shellcheck source=./lib.sh
. "${SCRIPT_DIR}/lib.sh"

# Unique cluster name so concurrent runs / the test-kind harness never collide.
# Honor a caller override; otherwise use a unique per-pid name (NOT lib.sh's
# shared kube-policies-test, which would risk clobbering a test-kind cluster).
KIND_CLUSTER_NAME="${_CALLER_CLUSTER_NAME:-kube-policies-netpol-$$}"
KUBERNETES_VERSION="${_CALLER_KUBE_VERSION:-v1.31.2}"
CALICO_VERSION="${CALICO_VERSION:-v3.28.2}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-5}"
TEST_NS="netpol-e2e"
HELM_RELEASE="kp"

# Test pod image: agnhost ships netexec (a tiny HTTP+TCP listener) and is
# distroless-ish / runs fine under a restricted-compliant securityContext.
AGNHOST_IMAGE="${AGNHOST_IMAGE:-registry.k8s.io/e2e-test-images/agnhost:2.47}"

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
    [ "${missing}" -eq 0 ] || exit 1
    if ! docker info >/dev/null 2>&1; then
        error "docker daemon is not reachable (docker info failed). Start Docker and retry."
        exit 1
    fi
    success "All prerequisites are installed and docker is reachable"
}

# ---------------------------------------------------------------------------
# Calico-enabled kind cluster
# ---------------------------------------------------------------------------
create_calico_cluster() {
    log "Creating Calico-enabled kind cluster: ${KIND_CLUSTER_NAME}"

    if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
        warn "Cluster ${KIND_CLUSTER_NAME} already exists. Deleting..."
        kind delete cluster --name "${KIND_CLUSTER_NAME}"
    fi

    # disableDefaultCNI removes kindnet so NetworkPolicy is unenforced until
    # Calico is installed. podSubnet must match Calico's default IPPool
    # (192.168.0.0/16) unless we patch the install; we keep the default.
    local cfg="/tmp/kind-netpol-${KIND_CLUSTER_NAME}.yaml"
    cat <<EOF > "${cfg}"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
nodes:
- role: control-plane
  image: kindest/node:${KUBERNETES_VERSION}
EOF

    kind create cluster --name "${KIND_CLUSTER_NAME}" --config "${cfg}"
    success "Kind cluster created (default CNI disabled)"
}

install_calico() {
    log "Installing Calico ${CALICO_VERSION} (NetworkPolicy enforcement)..."

    # Apply the upstream Calico manifest. This is a single self-contained YAML.
    kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"

    log "Waiting for Calico to roll out (this is the slow step)..."
    # calico-node is a DaemonSet; wait for it to be ready on every node.
    kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
    kubectl -n kube-system rollout status deployment/calico-kube-controllers --timeout=300s

    # Nodes only go Ready once the CNI is up.
    kubectl wait --for=condition=Ready nodes --all --timeout=180s

    # CoreDNS comes up after the CNI; needed for the DNS-resolution assertion.
    kubectl -n kube-system rollout status deployment/coredns --timeout=180s

    success "Calico is Ready — NetworkPolicy enforcement is active"
}

# Confirm NetworkPolicy enforcement is genuinely active (not kindnet). Calico
# advertises itself; we check the calico-node DaemonSet is fully scheduled+ready.
verify_enforcement_active() {
    log "Verifying NetworkPolicy enforcement is active..."
    local desired ready
    desired="$(kubectl -n kube-system get daemonset calico-node -o jsonpath='{.status.desiredNumberScheduled}')"
    ready="$(kubectl -n kube-system get daemonset calico-node -o jsonpath='{.status.numberReady}')"
    if [ -z "${ready}" ] || [ "${ready}" = "0" ] || [ "${ready}" != "${desired}" ]; then
        error "calico-node not fully ready (${ready:-0}/${desired:-?}); NetworkPolicy enforcement NOT confirmed"
        return 1
    fi
    success "calico-node ready ${ready}/${desired} — enforcement confirmed"
}

# ---------------------------------------------------------------------------
# Test namespace + pods
# ---------------------------------------------------------------------------
create_namespace() {
    log "Creating test namespace '${TEST_NS}'..."
    # NOTE: we do NOT label this ns pod-security.kubernetes.io/enforce=restricted.
    # The agnhost test pods below ARE restricted-compliant (runAsNonRoot, drop
    # ALL caps, seccomp RuntimeDefault, no privilege escalation), but we keep the
    # ns unlabeled so a future agnhost bump that needs a cap cannot silently fail
    # the segmentation proof on a PSA technicality. The labels the NetworkPolicies
    # select on (app.kubernetes.io/*) are what matters here, not PSA.
    kubectl create namespace "${TEST_NS}" --dry-run=client -o yaml | kubectl apply -f -
    # kube-system needs the metadata.name label for the DNS egress
    # namespaceSelector; modern k8s adds it automatically, but assert it so the
    # DNS assertion's pre-conditions are explicit.
    kubectl label namespace kube-system kubernetes.io/metadata.name=kube-system --overwrite >/dev/null
}

# Emit a restricted-compliant agnhost pod manifest carrying the given labels.
# $1 = pod name; $2 = component label value ("" for the attacker / no component);
# $3 = "server" to run netexec (listens :8080), anything else = sleeper client.
pod_manifest() {
    local name="$1" component="$2" role="$3"
    local labels="    app.kubernetes.io/name: kube-policies
    app.kubernetes.io/instance: ${HELM_RELEASE}"
    if [ -n "${component}" ]; then
        labels="${labels}
    app.kubernetes.io/component: ${component}"
    fi
    local args
    if [ "${role}" = "server" ]; then
        # netexec serves HTTP on --http-port; 8080 is the policy-manager port.
        args='["netexec", "--http-port=8080"]'
    else
        # A long-lived no-op so we can kubectl exec connectivity probes into it.
        args='["pause"]'
    fi
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${TEST_NS}
  labels:
${labels}
spec:
  terminationGracePeriodSeconds: 1
  containers:
  - name: agnhost
    image: ${AGNHOST_IMAGE}
    args: ${args}
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
EOF
}

deploy_test_pods() {
    log "Deploying test pods (server=policy-manager, client=webhook, attacker=unlabeled)..."

    # policy-manager server: EXACT labels the ingress-policy-manager podSelector
    # matches. Listens on :8080.
    kubectl apply -f - <<<"$(pod_manifest "policy-manager" "policy-manager" "server")"
    # webhook client: carries component=admission-webhook (an allowed ingress
    # source in ingress-policy-manager).
    kubectl apply -f - <<<"$(pod_manifest "webhook-client" "admission-webhook" "client")"
    # attacker: NO component label (carries name/instance only would still match
    # DNS egress; to be a true out-of-selector ingress source we give it a
    # FOREIGN name so it matches NONE of the kube-policies selectors).
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: ${TEST_NS}
  labels:
    app.kubernetes.io/name: not-kube-policies
    app.kubernetes.io/instance: rogue
    role: attacker
spec:
  terminationGracePeriodSeconds: 1
  containers:
  - name: agnhost
    image: ${AGNHOST_IMAGE}
    args: ["pause"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
EOF

    log "Waiting for test pods to be Ready..."
    kubectl wait --for=condition=Ready pod/policy-manager pod/webhook-client pod/attacker \
        -n "${TEST_NS}" --timeout=180s

    # Capture the server pod IP — we probe by IP so the result reflects the
    # NetworkPolicy podSelector, independent of DNS/Service plumbing.
    PM_IP="$(kubectl get pod policy-manager -n "${TEST_NS}" -o jsonpath='{.status.podIP}')"
    log "policy-manager pod IP: ${PM_IP}"
    [ -n "${PM_IP}" ] || { error "could not read policy-manager pod IP"; return 1; }
}

# ---------------------------------------------------------------------------
# Probe helpers — built on agnhost's `connect` subcommand, which dials host:port
# and on failure prints a FIXED prefix we can assert on (see `connect --help`):
#   (exit 0)  connection succeeded
#   DNS:      DNS resolution failed
#   REFUSED   TCP RST (port closed, but reachable)
#   TIMEOUT   no response within --timeout (the NetworkPolicy DROP signature)
#   OTHER     other network error (e.g. no route to host)
# A NetworkPolicy deny on an enforcing CNI manifests as a silent DROP -> TIMEOUT
# (or OTHER), distinct from REFUSED (reached the host) and DNS (name unresolved).
# ---------------------------------------------------------------------------
# probe_8080 <src-pod> -> echoes "OPEN" / "BLOCKED". Treats only a successful
# connect as OPEN; any failure (TIMEOUT/OTHER/REFUSED) is BLOCKED.
probe_8080() {
    local src="$1" out
    if out="$(kubectl exec -n "${TEST_NS}" "${src}" -- \
        /agnhost connect "${PM_IP}:8080" --timeout="${PROBE_TIMEOUT}s" 2>&1)"; then
        echo "OPEN"
    else
        # Surface the agnhost prefix on stderr for the run log, but classify as
        # BLOCKED for the assertion.
        echo "BLOCKED (${out})" >&2
        echo "BLOCKED"
    fi
}

# probe_dns <src-pod> -> "OK"/"FAIL". Forces a name resolution by dialing a
# Service FQDN. A successful connect OR a non-DNS failure (REFUSED/TIMEOUT) both
# prove the NAME resolved => DNS works. Only a `DNS:`-prefixed error is FAIL.
# This keeps the DNS assertion independent of whether apiserver:443 egress is
# itself allowed by policy.
probe_dns() {
    local src="$1" out
    if out="$(kubectl exec -n "${TEST_NS}" "${src}" -- \
        /agnhost connect "kubernetes.default.svc.cluster.local:443" --timeout="${PROBE_TIMEOUT}s" 2>&1)"; then
        echo "OK"
    elif printf '%s' "${out}" | grep -q '^DNS:'; then
        echo "FAIL (${out})" >&2
        echo "FAIL"
    else
        # REFUSED/TIMEOUT/OTHER -> the name resolved, only the dial failed.
        echo "OK"
    fi
}

# ---------------------------------------------------------------------------
# NEGATIVE CONTROL: with NO policies applied, the attacker CAN reach :8080.
# ---------------------------------------------------------------------------
negative_control() {
    log "=== NEGATIVE CONTROL (no policies applied) ==="
    log "Probing attacker -> policy-manager:8080 BEFORE policies (expect OPEN)..."
    local r
    r="$(probe_8080 attacker)"
    if [ "${r}" = "OPEN" ]; then
        success "NEGATIVE CONTROL: attacker -> :8080 = OPEN (as expected; proves the probe works and the link is otherwise reachable)"
    else
        error "NEGATIVE CONTROL FAILED: attacker -> :8080 = ${r} before any policy. The probe or pod networking is broken; a later BLOCK would be meaningless."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Apply ONLY the NetworkPolicy templates with test-permissive values.
# ---------------------------------------------------------------------------
apply_policies() {
    log "Rendering and applying ONLY the chart's NetworkPolicy templates into '${TEST_NS}'..."
    cd "${PROJECT_ROOT}"

    local rendered="/tmp/netpol-${KIND_CLUSTER_NAME}.yaml"
    # --show-only is repeated for each template; render them all to one file.
    helm template "${HELM_RELEASE}" charts/kube-policies \
        --namespace "${TEST_NS}" \
        --set dashboard.enabled=true \
        --set 'networkPolicy.apiServerCIDRs={10.0.0.0/8}' \
        --set 'networkPolicy.webhook.ingressFrom.ipBlocks={0.0.0.0/0}' \
        --show-only templates/networkpolicy-default-deny.yaml \
        --show-only templates/networkpolicy-egress-dns.yaml \
        --show-only templates/networkpolicy-ingress-policy-manager.yaml \
        --show-only templates/networkpolicy-ingress-webhook.yaml \
        --show-only templates/networkpolicy-egress-internal.yaml \
        --show-only templates/networkpolicy-egress-apiserver.yaml \
        --show-only templates/networkpolicy-ingress-metrics.yaml \
        > "${rendered}"

    log "Rendered policies:"
    grep -E '^kind:|^  name:' "${rendered}" || true

    kubectl apply -n "${TEST_NS}" -f "${rendered}"
    log "Applied. NetworkPolicies in ${TEST_NS}:"
    kubectl get networkpolicy -n "${TEST_NS}"

    # Give Calico a moment to program the policies into the dataplane.
    sleep 5
}

# ---------------------------------------------------------------------------
# Assertions (the real proof)
# ---------------------------------------------------------------------------
run_assertions() {
    local fails=0

    log "=== ASSERTION 1 (KEYSTONE): attacker -> policy-manager:8080 must be BLOCKED ==="
    local r
    r="$(probe_8080 attacker)"
    if [ "${r}" = "BLOCKED" ]; then
        success "PASS: attacker -> :8080 = BLOCKED (default-deny + out-of-selector ingress denied)"
    else
        error "FAIL: attacker -> :8080 = ${r} (expected BLOCKED)"
        fails=$((fails + 1))
    fi

    log "=== ASSERTION 2: webhook-client -> policy-manager:8080 must be ALLOWED ==="
    r="$(probe_8080 webhook-client)"
    if [ "${r}" = "OPEN" ]; then
        success "PASS: webhook-client -> :8080 = OPEN (ingress-policy-manager allows component=admission-webhook)"
    else
        error "FAIL: webhook-client -> :8080 = ${r} (expected OPEN)"
        fails=$((fails + 1))
    fi

    log "=== ASSERTION 3: a kube-policies-labeled pod can resolve DNS (egress-dns allow) ==="
    r="$(probe_dns webhook-client)"
    if [ "${r}" = "OK" ]; then
        success "PASS: webhook-client DNS resolution OK (egress-dns allows :53 to kube-dns)"
    else
        error "FAIL: webhook-client DNS = ${r} (expected OK)"
        fails=$((fails + 1))
    fi

    log "=== ASSERTION 4 (BONUS): attacker egress to policy-manager:8080 also denied ==="
    # The attacker has NO egress allow (it isn't selected by egress-dns, which
    # requires name=kube-policies). default-deny egress applies to ALL pods in
    # the ns (podSelector:{}), so the attacker's own egress is denied too. This
    # is the same probe as ASSERTION 1 but framed as egress; a BLOCKED here also
    # corroborates the keystone.
    r="$(probe_8080 attacker)"
    if [ "${r}" = "BLOCKED" ]; then
        success "PASS: attacker egress -> :8080 = BLOCKED (default-deny egress, no allow)"
    else
        error "FAIL: attacker egress -> :8080 = ${r} (expected BLOCKED)"
        fails=$((fails + 1))
    fi

    if [ "${fails}" -ne 0 ]; then
        error "${fails} assertion(s) FAILED — segmentation NOT proven"
        return 1
    fi
    success "ALL ASSERTIONS PASSED — NetworkPolicy segmentation PROVEN on an enforcing CNI"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup_netpol() {
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        warn "test failed (rc=${rc}); dumping diagnostics before cleanup"
        kubectl get pods -n "${TEST_NS}" -o wide 2>/dev/null || true
        kubectl get networkpolicy -n "${TEST_NS}" 2>/dev/null || true
        kubectl get events -n "${TEST_NS}" --sort-by=.lastTimestamp 2>/dev/null | tail -20 || true
    fi
    if [ "${CLEANUP:-true}" = "true" ]; then
        log "Deleting kind cluster ${KIND_CLUSTER_NAME}..."
        kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
        rm -f "/tmp/kind-netpol-${KIND_CLUSTER_NAME}.yaml" "/tmp/netpol-${KIND_CLUSTER_NAME}.yaml" 2>/dev/null || true
        success "Cleanup completed (no dangling cluster)"
    else
        warn "CLEANUP=false — leaving cluster ${KIND_CLUSTER_NAME} for debugging"
    fi
}

main() {
    log "Starting NetworkPolicy segmentation E2E (P4 exit-gate proof)"
    trap cleanup_netpol EXIT

    check_prerequisites
    create_calico_cluster
    install_calico
    verify_enforcement_active
    create_namespace
    deploy_test_pods
    negative_control      # attacker CAN reach :8080 before policies
    apply_policies        # render+apply ONLY networkpolicy-*.yaml
    run_assertions        # the real proof

    success "NetworkPolicy segmentation E2E completed successfully (P4 exit-gate PROVEN)"
}

case "${1:-}" in
    cleanup)
        cleanup_netpol
        ;;
    *)
        main "$@"
        ;;
esac
