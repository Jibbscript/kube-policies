#!/bin/bash

# scripts/test/lib.sh — shared cluster orchestration helpers for
# test-kind.sh and demo/capture/capture.sh.
#
# CONTRACT (per .omc/plans/kube-policies-demo-video.md §5.3.1):
#   - This file is intended to be `source`d, not executed.
#   - It uses `set -u` so callers retain control of `errexit` / `pipefail`.
#   - The only top-level statements are variable defaults, color tokens, and
#     small log helpers — everything else is a function definition.
#
# Functions exposed:
#   create_registry          — start/restart a local docker registry on REGISTRY_PORT.
#   create_cluster           — create a Kind cluster wired to the local registry.
#   build_and_push_images    — build admission-webhook + policy-manager images and push.
#   install_cert_manager     — install cert-manager and wait for its deployments.
#   deploy_kube_policies     — Helm-install kube-policies with kind-tuned values.
#   wait_for_deployment      — wait for admission-webhook + policy-manager + webhook configs.
#   cleanup                  — delete test pods, the Kind cluster, and the registry.

set -u

# Default cluster identity. Callers may override before sourcing.
: "${KIND_CLUSTER_NAME:=kube-policies-test}"
: "${KUBERNETES_VERSION:=v1.28.0}"
: "${REGISTRY_NAME:=kind-registry}"
: "${REGISTRY_PORT:=5001}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}"
}

error() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS] $*${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $*${NC}"
}

# Create local registry for Kind
create_registry() {
    log "Creating local registry..."

    # Check if registry already exists
    if docker ps -a --format "table {{.Names}}" | grep -q "^${REGISTRY_NAME}$"; then
        log "Registry ${REGISTRY_NAME} already exists"
        if ! docker ps --format "table {{.Names}}" | grep -q "^${REGISTRY_NAME}$"; then
            log "Starting existing registry..."
            docker start "${REGISTRY_NAME}"
        fi
    else
        log "Creating new registry..."
        docker run -d --restart=always -p "127.0.0.1:${REGISTRY_PORT}:5000" --name "${REGISTRY_NAME}" registry:2
    fi

    success "Registry is running on localhost:${REGISTRY_PORT}"
}

# Create Kind cluster
create_cluster() {
    log "Creating Kind cluster: ${KIND_CLUSTER_NAME}"

    # Check if cluster already exists
    if kind get clusters | grep -q "^${KIND_CLUSTER_NAME}$"; then
        warn "Cluster ${KIND_CLUSTER_NAME} already exists. Deleting..."
        kind delete cluster --name "${KIND_CLUSTER_NAME}"
    fi

    # Create cluster configuration
    cat <<EOF > /tmp/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:${KUBERNETES_VERSION}
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
  # Note: integration tests expect host:8443 to be the admission webhook.
  # We deliberately do NOT bind hostPort 8443 here — docker-proxy would
  # then intercept connections destined for the test's kubectl port-forward
  # set up later in test-kind.sh's run_tests(). See PR for that helper.
- role: worker
  image: kindest/node:${KUBERNETES_VERSION}
- role: worker
  image: kindest/node:${KUBERNETES_VERSION}
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF

    # Create the cluster
    kind create cluster --name "${KIND_CLUSTER_NAME}" --config /tmp/kind-config.yaml

    # Connect registry to cluster network.
    # `kind create cluster` already creates the `kind` network; the create-if-missing
    # block below is idempotent for the case where kind didn't auto-create it (e.g.
    # single-node clusters on some kind versions). Suppress the "already exists"
    # error to avoid aborting under `set -e`.
    docker network create kind 2>/dev/null || true
    docker network connect "kind" "${REGISTRY_NAME}" 2>/dev/null || true

    # Configure per-node certs.d/hosts.toml for the modern containerd registry mirror
    local registry_dir="/etc/containerd/certs.d/localhost:${REGISTRY_PORT}"
    for node in $(kind get nodes --name "${KIND_CLUSTER_NAME}"); do
        docker exec "${node}" mkdir -p "${registry_dir}"
        cat <<HOSTSTOML | docker exec -i "${node}" cp /dev/stdin "${registry_dir}/hosts.toml"
[host."http://${REGISTRY_NAME}:5000"]
  capabilities = ["pull", "resolve"]
HOSTSTOML
    done

    # Document the local registry
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REGISTRY_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

    success "Kind cluster created successfully"
}

# Build and push images
build_and_push_images() {
    log "Building and pushing Kube-Policies images..."

    cd "${PROJECT_ROOT}"

    # Build admission webhook image
    log "Building admission webhook image..."
    docker build -f build/docker/admission-webhook.Dockerfile -t "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:test" .
    docker push "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:test"

    # Build policy manager image
    log "Building policy manager image..."
    docker build -f build/docker/policy-manager.Dockerfile -t "localhost:${REGISTRY_PORT}/kube-policies/policy-manager:test" .
    docker push "localhost:${REGISTRY_PORT}/kube-policies/policy-manager:test"

    # Build dashboard image — needed when dashboard.enabled=true (demo flow).
    # The chart default repository (ghcr.io/Jibbscript/dashboard:1.0.0) is not
    # built locally; we ship a local replacement at the same registry as the
    # other two images. Dockerfile lives at build/Dockerfile.dashboard.
    if [ -f build/Dockerfile.dashboard ]; then
        log "Building dashboard image..."
        docker build -f build/Dockerfile.dashboard -t "localhost:${REGISTRY_PORT}/kube-policies/dashboard:test" .
        docker push "localhost:${REGISTRY_PORT}/kube-policies/dashboard:test"
    else
        warn "build/Dockerfile.dashboard not present; skipping dashboard image build (set dashboard.enabled=false in values to avoid InvalidImageName)"
    fi

    success "Images built and pushed successfully"
}

# Install cert-manager
install_cert_manager() {
    log "Installing cert-manager..."

    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

    # Wait for cert-manager to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager

    success "cert-manager installed successfully"
}

# Deploy Kube-Policies
# Optional first arg: path to an overlay values file (applied AFTER the
# generated /tmp/kind-values.yaml so demo overrides win). test-kind.sh
# passes no arg (legacy behavior preserved). demo/capture/capture.sh
# passes demo/capture/values-demo.yaml to inject the audit-backend=stdout
# + flushInterval=1s overrides plan §5.3.6 / I3-1 require for Scene-4.
deploy_kube_policies() {
    local extra_values="${1:-}"

    log "Deploying Kube-Policies..."

    cd "${PROJECT_ROOT}"

    # Create namespace
    kubectl create namespace kube-policies-system --dry-run=client -o yaml | kubectl apply -f -

    # Install CRDs
    kubectl apply -f deployments/kubernetes/crds/

    # Update Helm values for Kind.
    #
    # NOTE on image refs: the chart's admissionWebhook+policyManager image
    # templates render `{{ registry }}/{{ repository }}:{{ tag }}`. The chart
    # default `registry: docker.io` is fine for the public release case, but
    # for kind+local-registry we MUST override registry explicitly — otherwise
    # the rendered image becomes `docker.io/localhost:${REGISTRY_PORT}/...`
    # which Kubernetes rejects with InvalidImageName (two registry hostnames).
    # Split registry from repository here.
    cat <<EOF > /tmp/kind-values.yaml
admissionWebhook:
  image:
    registry: localhost:${REGISTRY_PORT}
    repository: kube-policies/admission-webhook
    tag: test
  # Disable bundled defaults so e2e tests' own policies fire in isolation.
  # When enabled, every test pod that is non-trivially-compliant triggers 2+
  # bundled rules, and the engine collapses the response to "Multiple policy
  # violations detected (N)" — defeating the per-rule substring assertions in
  # test/e2e/e2e_test.go (require-resource-limits, deny-privileged, ...).
  disableDefaultPolicies: true
  service:
    type: NodePort
    nodePort: 30443

policyManager:
  image:
    registry: localhost:${REGISTRY_PORT}
    repository: kube-policies/policy-manager
    tag: test
  service:
    type: NodePort
    nodePort: 30080

dashboard:
  image:
    registry: localhost:${REGISTRY_PORT}
    repository: kube-policies/dashboard
    tag: test

monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true

# Use cert-manager for TLS certificates
tls:
  certManager:
    enabled: true
    issuer: selfsigned-issuer

# Enable all security policies for testing
policies:
  security:
    enabled: true
    enforcement: true
  resources:
    enabled: true
    enforcement: true
EOF

    # Install using Helm — overlay values applied AFTER the generated file so demo overrides win.
    local helm_values_args=(--values /tmp/kind-values.yaml)
    if [ -n "${extra_values}" ]; then
        if [ ! -f "${extra_values}" ]; then
            error "deploy_kube_policies: extra values file not found: ${extra_values}"
            return 1
        fi
        log "Applying extra Helm values overlay: ${extra_values}"
        helm_values_args+=(--values "${extra_values}")
    fi
    helm upgrade --install kube-policies charts/kube-policies \
        --namespace kube-policies-system \
        "${helm_values_args[@]}" \
        --wait --timeout=600s

    success "Kube-Policies deployed successfully"
}

# Wait for deployment
wait_for_deployment() {
    log "Waiting for Kube-Policies to be ready..."

    # Wait for admission webhook
    kubectl wait --for=condition=available --timeout=300s deployment/kube-policies-admission-webhook -n kube-policies-system

    # Wait for policy manager
    kubectl wait --for=condition=available --timeout=300s deployment/kube-policies-policy-manager -n kube-policies-system

    # Webhook configurations: poll for existence rather than waiting on a
    # Ready condition. ValidatingWebhookConfiguration / MutatingWebhookConfiguration
    # don't have a Ready condition in k8s standard — `kubectl wait --for=condition=ready`
    # would hang until its 300s timeout. We just confirm the resource exists.
    local i
    for cfg in validatingwebhookconfigurations/kube-policies-validating-webhook; do
        for i in 1 2 3 4 5 6 7 8 9 10; do
            if kubectl get "$cfg" >/dev/null 2>&1; then
                break
            fi
            sleep 3
        done
        kubectl get "$cfg" >/dev/null 2>&1 || { warn "$cfg not present after wait"; return 1; }
    done

    success "All components are ready"
}

# Cleanup
cleanup() {
    log "Cleaning up..."

    if [[ "${CLEANUP:-true}" == "true" ]]; then
        # Delete test resources
        kubectl delete pod test-valid-pod -n default --ignore-not-found=true

        # Delete cluster
        kind delete cluster --name "${KIND_CLUSTER_NAME}"

        # Stop and remove registry
        docker stop "${REGISTRY_NAME}" || true
        docker rm "${REGISTRY_NAME}" || true

        success "Cleanup completed"
    else
        warn "Cleanup skipped (CLEANUP=false)"
        log "Cluster: ${KIND_CLUSTER_NAME}"
        log "Registry: ${REGISTRY_NAME} on localhost:${REGISTRY_PORT}"
    fi
}
