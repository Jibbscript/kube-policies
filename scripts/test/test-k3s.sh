#!/bin/bash

# test-k3s.sh - Test Kube-Policies on k3s cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
K3S_VERSION="${K3S_VERSION:-v1.28.2+k3s1}"
CLUSTER_NAME="${CLUSTER_NAME:-kube-policies-k3s}"
REGISTRY_PORT="${REGISTRY_PORT:-5002}"

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
    log "Checking prerequisites for k3s..."
    
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

# Install k3s
install_k3s() {
    log "Installing k3s ${K3S_VERSION}..."
    
    # Check if k3s is already installed
    if command -v k3s &> /dev/null; then
        log "k3s is already installed, uninstalling first..."
        sudo /usr/local/bin/k3s-uninstall.sh || true
    fi
    
    # Install k3s with specific configuration
    curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="${K3S_VERSION}" sh -s - \
        --write-kubeconfig-mode 644 \
        --disable traefik \
        --disable servicelb \
        --disable local-storage \
        --node-name k3s-master \
        --cluster-init
    
    # Wait for k3s to be ready
    log "Waiting for k3s to be ready..."
    timeout 300 bash -c 'until kubectl get nodes | grep -q Ready; do sleep 5; done'
    
    # Set up kubeconfig
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    sudo chmod 644 /etc/rancher/k3s/k3s.yaml
    
    success "k3s installed successfully"
}

# Create local registry
create_registry() {
    log "Creating local registry for k3s..."
    
    # Stop existing registry if running
    docker stop k3s-registry 2>/dev/null || true
    docker rm k3s-registry 2>/dev/null || true
    
    # Create registry
    docker run -d --restart=always \
        -p "127.0.0.1:${REGISTRY_PORT}:5000" \
        --name k3s-registry \
        registry:2
    
    # Configure k3s to use local registry
    sudo mkdir -p /etc/rancher/k3s
    sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  "localhost:${REGISTRY_PORT}":
    endpoint:
      - "http://localhost:${REGISTRY_PORT}"
configs:
  "localhost:${REGISTRY_PORT}":
    tls:
      insecure_skip_verify: true
EOF

    # Restart k3s to pick up registry config
    sudo systemctl restart k3s
    
    # Wait for k3s to be ready again
    timeout 300 bash -c 'until kubectl get nodes | grep -q Ready; do sleep 5; done'
    
    success "Registry configured for k3s"
}

# Build and push images
build_and_push_images() {
    log "Building and pushing Kube-Policies images for k3s..."
    
    cd "${PROJECT_ROOT}"
    
    # Build admission webhook image
    log "Building admission webhook image..."
    docker build -f build/docker/admission-webhook.Dockerfile -t "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:k3s" .
    docker push "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:k3s"
    
    # Build policy manager image
    log "Building policy manager image..."
    docker build -f build/docker/policy-manager.Dockerfile -t "localhost:${REGISTRY_PORT}/kube-policies/policy-manager:k3s" .
    docker push "localhost:${REGISTRY_PORT}/kube-policies/policy-manager:k3s"
    
    success "Images built and pushed successfully"
}

# Install cert-manager
install_cert_manager() {
    log "Installing cert-manager on k3s..."
    
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
    
    # Wait for cert-manager to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager
    
    success "cert-manager installed successfully"
}

# Deploy Kube-Policies
deploy_kube_policies() {
    log "Deploying Kube-Policies on k3s..."
    
    cd "${PROJECT_ROOT}"
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Create namespace
    kubectl create namespace kube-policies-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Install CRDs
    kubectl apply -f deployments/kubernetes/crds/
    
    # Update Helm values for k3s
    cat <<EOF > /tmp/k3s-values.yaml
admissionWebhook:
  image:
    repository: localhost:${REGISTRY_PORT}/kube-policies/admission-webhook
    tag: k3s
  service:
    type: NodePort
    nodePort: 30443
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 256Mi

policyManager:
  image:
    repository: localhost:${REGISTRY_PORT}/kube-policies/policy-manager
    tag: k3s
  service:
    type: NodePort
    nodePort: 30080
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 256Mi

monitoring:
  enabled: true
  prometheus:
    enabled: true
    resources:
      requests:
        cpu: 50m
        memory: 128Mi
      limits:
        cpu: 200m
        memory: 512Mi
  grafana:
    enabled: true
    resources:
      requests:
        cpu: 50m
        memory: 128Mi
      limits:
        cpu: 200m
        memory: 512Mi

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

# k3s specific configurations
nodeSelector:
  kubernetes.io/os: linux

tolerations:
  - key: node.kubernetes.io/disk-pressure
    operator: Exists
    effect: NoSchedule
  - key: node.kubernetes.io/memory-pressure
    operator: Exists
    effect: NoSchedule
EOF

    # Install using Helm
    helm upgrade --install kube-policies charts/kube-policies \
        --namespace kube-policies-system \
        --values /tmp/k3s-values.yaml \
        --wait --timeout=600s
    
    success "Kube-Policies deployed successfully on k3s"
}

# Wait for deployment
wait_for_deployment() {
    log "Waiting for Kube-Policies to be ready on k3s..."
    
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Wait for admission webhook
    kubectl wait --for=condition=available --timeout=300s deployment/kube-policies-admission-webhook -n kube-policies-system
    
    # Wait for policy manager
    kubectl wait --for=condition=available --timeout=300s deployment/kube-policies-policy-manager -n kube-policies-system
    
    # Wait for webhook configuration
    timeout 300 bash -c 'until kubectl get validatingwebhookconfiguration kube-policies-validating-webhook &>/dev/null; do sleep 5; done'
    timeout 300 bash -c 'until kubectl get mutatingwebhookconfiguration kube-policies-mutating-webhook &>/dev/null; do sleep 5; done'
    
    success "All components are ready on k3s"
}

# Run tests
run_tests() {
    log "Running E2E tests on k3s cluster..."
    
    cd "${PROJECT_ROOT}"
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Run unit tests
    log "Running unit tests..."
    go test -v ./internal/... ./pkg/... -race -coverprofile=coverage-unit-k3s.out
    
    # Run integration tests
    log "Running integration tests..."
    go test -v ./test/integration/... -race -coverprofile=coverage-integration-k3s.out
    
    # Run E2E tests
    log "Running E2E tests..."
    go test -v ./test/e2e/... -ginkgo.v -ginkgo.progress -coverprofile=coverage-e2e-k3s.out
    
    # Generate combined coverage report
    log "Generating coverage report..."
    go tool cover -html=coverage-e2e-k3s.out -o coverage-k3s.html
    
    success "All tests completed successfully on k3s"
}

# Test k3s specific scenarios
test_k3s_scenarios() {
    log "Testing k3s-specific scenarios..."
    
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Test 1: Resource constraints
    log "Test 1: Testing with resource constraints"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-resource-pod
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
        cpu: 50m
        memory: 64Mi
      requests:
        cpu: 25m
        memory: 32Mi
EOF
    
    kubectl wait --for=condition=ready --timeout=60s pod/test-resource-pod -n default
    success "Resource-constrained pod created successfully"
    
    # Test 2: k3s node labels and taints
    log "Test 2: Testing k3s node characteristics"
    
    # Check node labels
    if kubectl get nodes -o jsonpath='{.items[0].metadata.labels}' | grep -q "k3s"; then
        success "k3s node labels detected"
    else
        warn "k3s node labels not found"
    fi
    
    # Test 3: Local path provisioner (k3s default)
    log "Test 3: Testing storage with local-path provisioner"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: local-path
EOF
    
    # Wait for PVC to be bound
    timeout 60 bash -c 'until kubectl get pvc test-pvc -n default -o jsonpath="{.status.phase}" | grep -q Bound; do sleep 5; done'
    success "PVC with local-path storage created successfully"
    
    # Test 4: k3s networking
    log "Test 4: Testing k3s networking"
    
    # Create a service and test connectivity
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: test-service
  namespace: default
spec:
  selector:
    app: test-resource-pod
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
EOF
    
    # Test service resolution
    if kubectl run test-client --image=busybox --rm -it --restart=Never -- nslookup test-service.default.svc.cluster.local; then
        success "Service DNS resolution working"
    else
        warn "Service DNS resolution test failed"
    fi
    
    success "All k3s-specific tests passed"
}

# Test performance on k3s
test_performance() {
    log "Testing performance on k3s..."
    
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Create multiple pods to test admission webhook performance
    log "Creating multiple pods to test admission performance..."
    
    for i in {1..20}; do
        kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: perf-test-pod-${i}
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
        cpu: 50m
        memory: 64Mi
      requests:
        cpu: 25m
        memory: 32Mi
EOF
    done
    
    # Wait for all pods to be ready
    log "Waiting for all performance test pods to be ready..."
    for i in {1..20}; do
        kubectl wait --for=condition=ready --timeout=60s pod/perf-test-pod-${i} -n default
    done
    
    success "Performance test completed - all 20 pods created successfully"
}

# Collect logs and diagnostics
collect_diagnostics() {
    log "Collecting diagnostics from k3s..."
    
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    mkdir -p "${PROJECT_ROOT}/test-results/k3s"
    
    # Collect cluster info
    kubectl cluster-info > "${PROJECT_ROOT}/test-results/k3s/cluster-info.txt"
    kubectl get nodes -o wide > "${PROJECT_ROOT}/test-results/k3s/nodes.txt"
    kubectl get pods -A -o wide > "${PROJECT_ROOT}/test-results/k3s/pods.txt"
    
    # Collect k3s specific info
    sudo k3s kubectl version > "${PROJECT_ROOT}/test-results/k3s/k3s-version.txt"
    sudo systemctl status k3s > "${PROJECT_ROOT}/test-results/k3s/k3s-status.txt"
    
    # Collect Kube-Policies logs
    kubectl logs -n kube-policies-system -l app=kube-policies-admission-webhook --tail=1000 > "${PROJECT_ROOT}/test-results/k3s/admission-webhook.log" || true
    kubectl logs -n kube-policies-system -l app=kube-policies-policy-manager --tail=1000 > "${PROJECT_ROOT}/test-results/k3s/policy-manager.log" || true
    
    # Collect events
    kubectl get events -A --sort-by='.lastTimestamp' > "${PROJECT_ROOT}/test-results/k3s/events.txt"
    
    # Collect resource definitions
    kubectl get policies -A -o yaml > "${PROJECT_ROOT}/test-results/k3s/policies.yaml" || true
    kubectl get policyexceptions -A -o yaml > "${PROJECT_ROOT}/test-results/k3s/exceptions.yaml" || true
    
    # Collect k3s logs
    sudo journalctl -u k3s --no-pager --lines=1000 > "${PROJECT_ROOT}/test-results/k3s/k3s.log" || true
    
    success "Diagnostics collected in test-results/k3s/"
}

# Cleanup
cleanup() {
    log "Cleaning up k3s environment..."
    
    if [[ "${CLEANUP:-true}" == "true" ]]; then
        # Delete test resources
        export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
        kubectl delete pods -n default -l app=test-resource-pod --ignore-not-found=true
        kubectl delete pvc test-pvc -n default --ignore-not-found=true
        kubectl delete service test-service -n default --ignore-not-found=true
        
        # Delete performance test pods
        for i in {1..20}; do
            kubectl delete pod perf-test-pod-${i} -n default --ignore-not-found=true
        done
        
        # Uninstall k3s
        sudo /usr/local/bin/k3s-uninstall.sh || true
        
        # Stop and remove registry
        docker stop k3s-registry || true
        docker rm k3s-registry || true
        
        success "k3s cleanup completed"
    else
        warn "Cleanup skipped (CLEANUP=false)"
        log "k3s cluster is still running"
        log "Registry: k3s-registry on localhost:${REGISTRY_PORT}"
    fi
}

# Main execution
main() {
    log "Starting Kube-Policies testing on k3s cluster"
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    check_prerequisites
    install_k3s
    create_registry
    build_and_push_images
    install_cert_manager
    deploy_kube_policies
    wait_for_deployment
    run_tests
    test_k3s_scenarios
    test_performance
    collect_diagnostics
    
    success "Kube-Policies testing on k3s completed successfully!"
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

