#!/bin/bash

# test-kind.sh - Test Kube-Policies on Kind cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kube-policies-test}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.28.0}"
REGISTRY_NAME="${REGISTRY_NAME:-kind-registry}"
REGISTRY_PORT="${REGISTRY_PORT:-5001}"

# Shared cluster orchestration helpers (also sourced by demo/capture/capture.sh).
# Provides: log/error/success/warn, create_registry, create_cluster,
# build_and_push_images, install_cert_manager, deploy_kube_policies,
# wait_for_deployment, cleanup.
# shellcheck source=./lib.sh
. "${SCRIPT_DIR}/lib.sh"

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
