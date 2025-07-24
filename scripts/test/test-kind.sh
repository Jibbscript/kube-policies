#!/bin/bash

# test-kind.sh - Test Kube-Policies on Kind cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kube-policies-test}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.28.0}"
REGISTRY_NAME="${REGISTRY_NAME:-kind-registry}"
REGISTRY_PORT="${REGISTRY_PORT:-5001}"

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

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v kind &> /dev/null; then
        error "kind is not installed. Please install kind: https://kind.sigs.k8s.io/docs/user/quick-start/"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install kubectl"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        error "docker is not installed. Please install docker"
        exit 1
    fi
    
    if ! command -v helm &> /dev/null; then
        error "helm is not installed. Please install helm"
        exit 1
    fi
    
    success "All prerequisites are installed"
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
  - containerPort: 8443
    hostPort: 8443
    protocol: TCP
- role: worker
  image: kindest/node:${KUBERNETES_VERSION}
- role: worker
  image: kindest/node:${KUBERNETES_VERSION}
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REGISTRY_PORT}"]
    endpoint = ["http://${REGISTRY_NAME}:5000"]
EOF

    # Create the cluster
    kind create cluster --name "${KIND_CLUSTER_NAME}" --config /tmp/kind-config.yaml
    
    # Connect registry to cluster network
    if ! docker network ls | grep -q "kind"; then
        docker network create kind
    fi
    docker network connect "kind" "${REGISTRY_NAME}" 2>/dev/null || true
    
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
deploy_kube_policies() {
    log "Deploying Kube-Policies..."
    
    cd "${PROJECT_ROOT}"
    
    # Create namespace
    kubectl create namespace kube-policies-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Install CRDs
    kubectl apply -f deployments/kubernetes/crds/
    
    # Update Helm values for Kind
    cat <<EOF > /tmp/kind-values.yaml
admissionWebhook:
  image:
    repository: localhost:${REGISTRY_PORT}/kube-policies/admission-webhook
    tag: test
  service:
    type: NodePort
    nodePort: 30443

policyManager:
  image:
    repository: localhost:${REGISTRY_PORT}/kube-policies/policy-manager
    tag: test
  service:
    type: NodePort
    nodePort: 30080

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

    # Install using Helm
    helm upgrade --install kube-policies charts/kube-policies \
        --namespace kube-policies-system \
        --values /tmp/kind-values.yaml \
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
    
    # Wait for webhook configuration
    kubectl wait --for=condition=ready --timeout=300s validatingwebhookconfiguration/kube-policies-validating-webhook
    kubectl wait --for=condition=ready --timeout=300s mutatingwebhookconfiguration/kube-policies-mutating-webhook
    
    success "All components are ready"
}

# Run tests
run_tests() {
    log "Running E2E tests on Kind cluster..."
    
    cd "${PROJECT_ROOT}"
    
    # Set kubeconfig for tests
    export KUBECONFIG="$(kind get kubeconfig-path --name="${KIND_CLUSTER_NAME}")"
    
    # Run unit tests
    log "Running unit tests..."
    go test -v ./internal/... ./pkg/... -race -coverprofile=coverage-unit.out
    
    # Run integration tests
    log "Running integration tests..."
    go test -v ./test/integration/... -race -coverprofile=coverage-integration.out
    
    # Run E2E tests
    log "Running E2E tests..."
    go test -v ./test/e2e/... -ginkgo.v -ginkgo.progress -coverprofile=coverage-e2e.out
    
    # Generate combined coverage report
    log "Generating coverage report..."
    go tool cover -html=coverage-e2e.out -o coverage-kind.html
    
    success "All tests completed successfully"
}

# Test specific scenarios
test_scenarios() {
    log "Testing Kind-specific scenarios..."
    
    # Test 1: Basic policy enforcement
    log "Test 1: Basic policy enforcement"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged-pod
  namespace: default
spec:
  containers:
  - name: test-container
    image: nginx:1.20
    securityContext:
      privileged: true
EOF
    
    # This should fail
    if kubectl get pod test-privileged-pod -n default &>/dev/null; then
        error "Privileged pod was allowed - policy enforcement failed"
        exit 1
    else
        success "Privileged pod was correctly denied"
    fi
    
    # Test 2: Valid pod creation
    log "Test 2: Valid pod creation"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-valid-pod
  namespace: default
spec:
  securityContext:
    runAsUser: 1000
    runAsNonRoot: true
  containers:
  - name: test-container
    image: nginx:1.20
    securityContext:
      runAsUser: 1000
      runAsNonRoot: true
    resources:
      limits:
        cpu: 100m
        memory: 128Mi
      requests:
        cpu: 50m
        memory: 64Mi
EOF
    
    # Wait for pod to be ready
    kubectl wait --for=condition=ready --timeout=60s pod/test-valid-pod -n default
    success "Valid pod created successfully"
    
    # Test 3: Monitoring endpoints
    log "Test 3: Testing monitoring endpoints"
    
    # Port forward to access metrics
    kubectl port-forward -n kube-policies-system svc/kube-policies-policy-manager 8080:8080 &
    PORT_FORWARD_PID=$!
    sleep 5
    
    # Test metrics endpoint
    if curl -s http://localhost:8080/metrics | grep -q "kube_policies"; then
        success "Metrics endpoint is working"
    else
        error "Metrics endpoint is not working"
    fi
    
    # Test health endpoint
    if curl -s http://localhost:8080/healthz | grep -q "ok"; then
        success "Health endpoint is working"
    else
        error "Health endpoint is not working"
    fi
    
    # Clean up port forward
    kill $PORT_FORWARD_PID 2>/dev/null || true
    
    success "All Kind-specific tests passed"
}

# Collect logs and diagnostics
collect_diagnostics() {
    log "Collecting diagnostics..."
    
    mkdir -p "${PROJECT_ROOT}/test-results/kind"
    
    # Collect cluster info
    kubectl cluster-info > "${PROJECT_ROOT}/test-results/kind/cluster-info.txt"
    kubectl get nodes -o wide > "${PROJECT_ROOT}/test-results/kind/nodes.txt"
    kubectl get pods -A -o wide > "${PROJECT_ROOT}/test-results/kind/pods.txt"
    
    # Collect Kube-Policies logs
    kubectl logs -n kube-policies-system -l app=kube-policies-admission-webhook --tail=1000 > "${PROJECT_ROOT}/test-results/kind/admission-webhook.log" || true
    kubectl logs -n kube-policies-system -l app=kube-policies-policy-manager --tail=1000 > "${PROJECT_ROOT}/test-results/kind/policy-manager.log" || true
    
    # Collect events
    kubectl get events -A --sort-by='.lastTimestamp' > "${PROJECT_ROOT}/test-results/kind/events.txt"
    
    # Collect resource definitions
    kubectl get policies -A -o yaml > "${PROJECT_ROOT}/test-results/kind/policies.yaml" || true
    kubectl get policyexceptions -A -o yaml > "${PROJECT_ROOT}/test-results/kind/exceptions.yaml" || true
    
    success "Diagnostics collected in test-results/kind/"
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

# Main execution
main() {
    log "Starting Kube-Policies testing on Kind cluster"
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    check_prerequisites
    create_registry
    create_cluster
    build_and_push_images
    install_cert_manager
    deploy_kube_policies
    wait_for_deployment
    run_tests
    test_scenarios
    collect_diagnostics
    
    success "Kube-Policies testing on Kind completed successfully!"
}

# Handle command line arguments
case "${1:-}" in
    "cleanup")
        cleanup
        exit 0
        ;;
    "logs")
        collect_diagnostics
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac

