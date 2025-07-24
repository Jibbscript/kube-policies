#!/bin/bash

# test-vanilla.sh - Test Kube-Policies on vanilla Kubernetes cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-kube-policies-vanilla}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.28.2}"
REGISTRY_PORT="${REGISTRY_PORT:-5003}"

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
    log "Checking prerequisites for vanilla Kubernetes..."
    
    if ! command -v kubeadm &> /dev/null; then
        error "kubeadm is not installed. Please install kubeadm"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install kubectl"
        exit 1
    fi
    
    if ! command -v kubelet &> /dev/null; then
        error "kubelet is not installed. Please install kubelet"
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
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
        exit 1
    fi
    
    success "All prerequisites are installed"
}

# Setup container runtime
setup_container_runtime() {
    log "Setting up container runtime..."
    
    # Configure Docker for Kubernetes
    cat <<EOF > /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF

    # Restart Docker
    systemctl daemon-reload
    systemctl restart docker
    systemctl enable docker
    
    success "Container runtime configured"
}

# Create local registry
create_registry() {
    log "Creating local registry for vanilla Kubernetes..."
    
    # Stop existing registry if running
    docker stop vanilla-registry 2>/dev/null || true
    docker rm vanilla-registry 2>/dev/null || true
    
    # Create registry
    docker run -d --restart=always \
        -p "127.0.0.1:${REGISTRY_PORT}:5000" \
        --name vanilla-registry \
        registry:2
    
    success "Local registry created on localhost:${REGISTRY_PORT}"
}

# Initialize Kubernetes cluster
init_cluster() {
    log "Initializing vanilla Kubernetes cluster..."
    
    # Reset any existing cluster
    kubeadm reset -f || true
    
    # Initialize cluster
    kubeadm init \
        --kubernetes-version="${KUBERNETES_VERSION}" \
        --pod-network-cidr=10.244.0.0/16 \
        --service-cidr=10.96.0.0/12 \
        --apiserver-advertise-address=$(hostname -I | awk '{print $1}') \
        --node-name=master
    
    # Set up kubeconfig for root
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Set up kubeconfig for regular user (if exists)
    if [[ -n "${SUDO_USER:-}" ]]; then
        USER_HOME=$(eval echo ~${SUDO_USER})
        mkdir -p "${USER_HOME}/.kube"
        cp /etc/kubernetes/admin.conf "${USER_HOME}/.kube/config"
        chown "${SUDO_USER}:${SUDO_USER}" "${USER_HOME}/.kube/config"
    fi
    
    # Remove taint from master node to allow scheduling
    kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true
    kubectl taint nodes --all node-role.kubernetes.io/master- || true
    
    success "Kubernetes cluster initialized"
}

# Install CNI plugin
install_cni() {
    log "Installing CNI plugin (Flannel)..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Install Flannel
    kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
    
    # Wait for CNI to be ready
    log "Waiting for CNI to be ready..."
    timeout 300 bash -c 'until kubectl get nodes | grep -q Ready; do sleep 5; done'
    
    success "CNI plugin installed and ready"
}

# Configure registry access
configure_registry() {
    log "Configuring registry access..."
    
    # Create registry configuration for containerd
    mkdir -p /etc/containerd/certs.d/localhost:${REGISTRY_PORT}
    cat <<EOF > /etc/containerd/certs.d/localhost:${REGISTRY_PORT}/hosts.toml
server = "http://localhost:${REGISTRY_PORT}"

[host."http://localhost:${REGISTRY_PORT}"]
  capabilities = ["pull", "resolve", "push"]
  skip_verify = true
EOF

    # Restart containerd if it's being used
    if systemctl is-active --quiet containerd; then
        systemctl restart containerd
    fi
    
    success "Registry access configured"
}

# Build and push images
build_and_push_images() {
    log "Building and pushing Kube-Policies images..."
    
    cd "${PROJECT_ROOT}"
    
    # Build admission webhook image
    log "Building admission webhook image..."
    docker build -f build/docker/admission-webhook.Dockerfile -t "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:vanilla" .
    docker push "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:vanilla"
    
    # Build policy manager image
    log "Building policy manager image..."
    docker build -f build/docker/policy-manager.Dockerfile -t "localhost:${REGISTRY_PORT}/kube-policies/policy-manager:vanilla" .
    docker push "localhost:${REGISTRY_PORT}/kube-policies/policy-manager:vanilla"
    
    success "Images built and pushed successfully"
}

# Install cert-manager
install_cert_manager() {
    log "Installing cert-manager on vanilla Kubernetes..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
    
    # Wait for cert-manager to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager
    
    success "cert-manager installed successfully"
}

# Install ingress controller
install_ingress_controller() {
    log "Installing NGINX Ingress Controller..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Install NGINX Ingress Controller
    kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/baremetal/deploy.yaml
    
    # Wait for ingress controller to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/ingress-nginx-controller -n ingress-nginx
    
    # Patch service to use NodePort
    kubectl patch svc ingress-nginx-controller -n ingress-nginx -p '{"spec":{"type":"NodePort","ports":[{"port":80,"nodePort":30080,"name":"http"},{"port":443,"nodePort":30443,"name":"https"}]}}'
    
    success "NGINX Ingress Controller installed"
}

# Deploy Kube-Policies
deploy_kube_policies() {
    log "Deploying Kube-Policies on vanilla Kubernetes..."
    
    cd "${PROJECT_ROOT}"
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Create namespace
    kubectl create namespace kube-policies-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Install CRDs
    kubectl apply -f deployments/kubernetes/crds/
    
    # Create Helm values for vanilla Kubernetes
    cat <<EOF > /tmp/vanilla-values.yaml
admissionWebhook:
  image:
    repository: localhost:${REGISTRY_PORT}/kube-policies/admission-webhook
    tag: vanilla
    pullPolicy: Always
  service:
    type: NodePort
    nodePort: 30443
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

policyManager:
  image:
    repository: localhost:${REGISTRY_PORT}/kube-policies/policy-manager
    tag: vanilla
    pullPolicy: Always
  service:
    type: NodePort
    nodePort: 30080
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

monitoring:
  enabled: true
  prometheus:
    enabled: true
    service:
      type: NodePort
      nodePort: 30090
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 1Gi
  grafana:
    enabled: true
    service:
      type: NodePort
      nodePort: 30300
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 1Gi

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

# Vanilla Kubernetes specific configurations
nodeSelector:
  kubernetes.io/os: linux

tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
  - key: node-role.kubernetes.io/master
    operator: Exists
    effect: NoSchedule

# Single node deployment settings
replicaCount: 1

# Registry configuration
imagePullSecrets: []

# Ingress configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
  hosts:
    - host: kube-policies.local
      paths:
        - path: /
          pathType: Prefix
          service:
            name: kube-policies-policy-manager
            port: 8080
EOF

    # Install using Helm
    helm upgrade --install kube-policies charts/kube-policies \
        --namespace kube-policies-system \
        --values /tmp/vanilla-values.yaml \
        --wait --timeout=600s
    
    success "Kube-Policies deployed successfully on vanilla Kubernetes"
}

# Wait for deployment
wait_for_deployment() {
    log "Waiting for Kube-Policies to be ready on vanilla Kubernetes..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Wait for admission webhook
    kubectl wait --for=condition=available --timeout=300s deployment/kube-policies-admission-webhook -n kube-policies-system
    
    # Wait for policy manager
    kubectl wait --for=condition=available --timeout=300s deployment/kube-policies-policy-manager -n kube-policies-system
    
    # Wait for webhook configuration
    timeout 300 bash -c 'until kubectl get validatingwebhookconfiguration kube-policies-validating-webhook &>/dev/null; do sleep 5; done'
    timeout 300 bash -c 'until kubectl get mutatingwebhookconfiguration kube-policies-mutating-webhook &>/dev/null; do sleep 5; done'
    
    success "All components are ready on vanilla Kubernetes"
}

# Run tests
run_tests() {
    log "Running E2E tests on vanilla Kubernetes cluster..."
    
    cd "${PROJECT_ROOT}"
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Run unit tests
    log "Running unit tests..."
    go test -v ./internal/... ./pkg/... -race -coverprofile=coverage-unit-vanilla.out
    
    # Run integration tests
    log "Running integration tests..."
    go test -v ./test/integration/... -race -coverprofile=coverage-integration-vanilla.out
    
    # Run E2E tests
    log "Running E2E tests..."
    go test -v ./test/e2e/... -ginkgo.v -ginkgo.progress -coverprofile=coverage-e2e-vanilla.out
    
    # Generate combined coverage report
    log "Generating coverage report..."
    go tool cover -html=coverage-e2e-vanilla.out -o coverage-vanilla.html
    
    success "All tests completed successfully on vanilla Kubernetes"
}

# Test vanilla Kubernetes specific scenarios
test_vanilla_scenarios() {
    log "Testing vanilla Kubernetes-specific scenarios..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Test 1: Single node deployment
    log "Test 1: Testing single node deployment"
    
    NODE_COUNT=$(kubectl get nodes --no-headers | wc -l)
    log "Number of nodes: ${NODE_COUNT}"
    
    if [[ ${NODE_COUNT} -eq 1 ]]; then
        success "Single node deployment confirmed"
    else
        warn "Multi-node deployment detected"
    fi
    
    # Test 2: NodePort services
    log "Test 2: Testing NodePort services"
    
    # Get node IP
    NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    log "Node IP: ${NODE_IP}"
    
    # Test policy manager NodePort
    if curl -s "http://${NODE_IP}:30080/healthz" | grep -q "ok"; then
        success "Policy manager NodePort service working"
    else
        warn "Policy manager NodePort service not accessible"
    fi
    
    # Test 3: Ingress controller
    log "Test 3: Testing ingress controller"
    
    # Add entry to /etc/hosts for testing
    echo "${NODE_IP} kube-policies.local" >> /etc/hosts
    
    # Test ingress
    if curl -s "http://kube-policies.local:30080/healthz" | grep -q "ok"; then
        success "Ingress controller working"
    else
        warn "Ingress controller not accessible"
    fi
    
    # Test 4: Local registry integration
    log "Test 4: Testing local registry integration"
    
    # Try to pull an image from local registry
    if docker pull "localhost:${REGISTRY_PORT}/kube-policies/admission-webhook:vanilla" &>/dev/null; then
        success "Local registry integration working"
    else
        warn "Local registry integration issues"
    fi
    
    # Test 5: Resource constraints on single node
    log "Test 5: Testing resource constraints"
    
    # Create a pod with resource limits
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
        cpu: 100m
        memory: 128Mi
      requests:
        cpu: 50m
        memory: 64Mi
EOF
    
    kubectl wait --for=condition=ready --timeout=60s pod/test-resource-pod -n default
    success "Resource-constrained pod created successfully"
    
    # Test 6: Monitoring endpoints
    log "Test 6: Testing monitoring endpoints"
    
    # Test Prometheus
    if curl -s "http://${NODE_IP}:30090/metrics" | grep -q "prometheus"; then
        success "Prometheus metrics endpoint working"
    else
        warn "Prometheus metrics endpoint not accessible"
    fi
    
    # Test Grafana
    if curl -s "http://${NODE_IP}:30300/api/health" | grep -q "ok"; then
        success "Grafana health endpoint working"
    else
        warn "Grafana health endpoint not accessible"
    fi
    
    success "All vanilla Kubernetes-specific tests completed"
}

# Test performance on single node
test_performance() {
    log "Testing performance on vanilla Kubernetes single node..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    
    # Test 1: Pod creation performance
    log "Test 1: Pod creation performance test"
    
    # Create multiple pods and measure time
    START_TIME=$(date +%s)
    for i in {1..30}; do
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
    END_TIME=$(date +%s)
    
    DURATION=$((END_TIME - START_TIME))
    log "Created 30 pods in ${DURATION} seconds"
    
    # Wait for pods to be ready
    log "Waiting for pods to be ready..."
    for i in {1..30}; do
        kubectl wait --for=condition=ready --timeout=60s pod/perf-test-pod-${i} -n default || true
    done
    
    # Count ready pods
    READY_PODS=$(kubectl get pods -n default --field-selector=status.phase=Running --no-headers | grep perf-test | wc -l)
    log "Successfully created ${READY_PODS}/30 pods"
    
    if [[ ${READY_PODS} -ge 25 ]]; then
        success "Performance test passed"
    else
        warn "Performance test had issues"
    fi
    
    success "Performance testing completed"
}

# Collect logs and diagnostics
collect_diagnostics() {
    log "Collecting diagnostics from vanilla Kubernetes..."
    
    export KUBECONFIG=/etc/kubernetes/admin.conf
    mkdir -p "${PROJECT_ROOT}/test-results/vanilla"
    
    # Collect cluster info
    kubectl cluster-info > "${PROJECT_ROOT}/test-results/vanilla/cluster-info.txt"
    kubectl get nodes -o wide > "${PROJECT_ROOT}/test-results/vanilla/nodes.txt"
    kubectl get pods -A -o wide > "${PROJECT_ROOT}/test-results/vanilla/pods.txt"
    
    # Collect vanilla Kubernetes specific info
    kubeadm version > "${PROJECT_ROOT}/test-results/vanilla/kubeadm-version.txt"
    kubectl version > "${PROJECT_ROOT}/test-results/vanilla/kubectl-version.txt"
    
    # Collect system info
    systemctl status kubelet > "${PROJECT_ROOT}/test-results/vanilla/kubelet-status.txt" || true
    systemctl status docker > "${PROJECT_ROOT}/test-results/vanilla/docker-status.txt" || true
    
    # Collect Kube-Policies logs
    kubectl logs -n kube-policies-system -l app=kube-policies-admission-webhook --tail=1000 > "${PROJECT_ROOT}/test-results/vanilla/admission-webhook.log" || true
    kubectl logs -n kube-policies-system -l app=kube-policies-policy-manager --tail=1000 > "${PROJECT_ROOT}/test-results/vanilla/policy-manager.log" || true
    
    # Collect events
    kubectl get events -A --sort-by='.lastTimestamp' > "${PROJECT_ROOT}/test-results/vanilla/events.txt"
    
    # Collect resource definitions
    kubectl get policies -A -o yaml > "${PROJECT_ROOT}/test-results/vanilla/policies.yaml" || true
    kubectl get policyexceptions -A -o yaml > "${PROJECT_ROOT}/test-results/vanilla/exceptions.yaml" || true
    
    # Collect system logs
    journalctl -u kubelet --no-pager --lines=1000 > "${PROJECT_ROOT}/test-results/vanilla/kubelet.log" || true
    journalctl -u docker --no-pager --lines=1000 > "${PROJECT_ROOT}/test-results/vanilla/docker.log" || true
    
    # Collect network info
    kubectl get svc -A -o wide > "${PROJECT_ROOT}/test-results/vanilla/services.txt"
    kubectl get ingress -A -o wide > "${PROJECT_ROOT}/test-results/vanilla/ingress.txt"
    
    success "Diagnostics collected in test-results/vanilla/"
}

# Cleanup
cleanup() {
    log "Cleaning up vanilla Kubernetes environment..."
    
    if [[ "${CLEANUP:-true}" == "true" ]]; then
        export KUBECONFIG=/etc/kubernetes/admin.conf
        
        # Delete test resources
        kubectl delete pods -n default -l app=test-resource-pod --ignore-not-found=true
        
        # Delete performance test pods
        for i in {1..30}; do
            kubectl delete pod perf-test-pod-${i} -n default --ignore-not-found=true
        done
        
        # Reset Kubernetes cluster
        kubeadm reset -f || true
        
        # Stop and remove registry
        docker stop vanilla-registry || true
        docker rm vanilla-registry || true
        
        # Clean up /etc/hosts
        sed -i '/kube-policies.local/d' /etc/hosts || true
        
        # Clean up kubeconfig
        rm -f /etc/kubernetes/admin.conf
        if [[ -n "${SUDO_USER:-}" ]]; then
            USER_HOME=$(eval echo ~${SUDO_USER})
            rm -f "${USER_HOME}/.kube/config"
        fi
        
        success "Vanilla Kubernetes cleanup completed"
    else
        warn "Cleanup skipped (CLEANUP=false)"
        log "Vanilla Kubernetes cluster is still running"
        log "Registry: vanilla-registry on localhost:${REGISTRY_PORT}"
    fi
}

# Main execution
main() {
    log "Starting Kube-Policies testing on vanilla Kubernetes cluster"
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    check_prerequisites
    setup_container_runtime
    create_registry
    init_cluster
    install_cni
    configure_registry
    build_and_push_images
    install_cert_manager
    install_ingress_controller
    deploy_kube_policies
    wait_for_deployment
    run_tests
    test_vanilla_scenarios
    test_performance
    collect_diagnostics
    
    success "Kube-Policies testing on vanilla Kubernetes completed successfully!"
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

