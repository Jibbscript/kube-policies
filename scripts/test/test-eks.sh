#!/bin/bash

# test-eks.sh - Test Kube-Policies on AWS EKS cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-kube-policies-eks-test}"
AWS_REGION="${AWS_REGION:-us-west-2}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-1.28}"
NODE_GROUP_NAME="${NODE_GROUP_NAME:-kube-policies-nodes}"
ECR_REPOSITORY_PREFIX="${ECR_REPOSITORY_PREFIX:-kube-policies}"

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
    log "Checking prerequisites for EKS..."
    
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed. Please install AWS CLI v2"
        exit 1
    fi
    
    if ! command -v eksctl &> /dev/null; then
        error "eksctl is not installed. Please install eksctl"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install kubectl"
        exit 1
    fi
    
    if ! command -v helm &> /dev/null; then
        error "helm is not installed. Please install helm"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS credentials not configured. Please run 'aws configure'"
        exit 1
    fi
    
    # Check AWS region
    if [[ -z "${AWS_REGION}" ]]; then
        error "AWS_REGION not set. Please set AWS_REGION environment variable"
        exit 1
    fi
    
    success "All prerequisites are installed and configured"
}

# Create ECR repositories
create_ecr_repositories() {
    log "Creating ECR repositories..."
    
    # Get AWS account ID
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    
    # Create repositories
    for component in admission-webhook policy-manager; do
        REPO_NAME="${ECR_REPOSITORY_PREFIX}/${component}"
        
        if aws ecr describe-repositories --repository-names "${REPO_NAME}" --region "${AWS_REGION}" &>/dev/null; then
            log "ECR repository ${REPO_NAME} already exists"
        else
            log "Creating ECR repository: ${REPO_NAME}"
            aws ecr create-repository \
                --repository-name "${REPO_NAME}" \
                --region "${AWS_REGION}" \
                --image-scanning-configuration scanOnPush=true
        fi
    done
    
    success "ECR repositories created"
}

# Build and push images to ECR
build_and_push_images() {
    log "Building and pushing images to ECR..."
    
    cd "${PROJECT_ROOT}"
    
    # Login to ECR
    aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_REGISTRY}"
    
    # Build and push admission webhook
    log "Building admission webhook image..."
    docker build -f build/docker/admission-webhook.Dockerfile -t "${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/admission-webhook:eks" .
    docker push "${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/admission-webhook:eks"
    
    # Build and push policy manager
    log "Building policy manager image..."
    docker build -f build/docker/policy-manager.Dockerfile -t "${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/policy-manager:eks" .
    docker push "${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/policy-manager:eks"
    
    success "Images built and pushed to ECR"
}

# Create EKS cluster
create_eks_cluster() {
    log "Creating EKS cluster: ${CLUSTER_NAME}"
    
    # Check if cluster already exists
    if eksctl get cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" &>/dev/null; then
        warn "EKS cluster ${CLUSTER_NAME} already exists"
        return 0
    fi
    
    # Create cluster configuration
    cat <<EOF > /tmp/eks-cluster.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "${KUBERNETES_VERSION}"

iam:
  withOIDC: true

addons:
  - name: vpc-cni
    version: latest
  - name: coredns
    version: latest
  - name: kube-proxy
    version: latest
  - name: aws-ebs-csi-driver
    version: latest

nodeGroups:
  - name: ${NODE_GROUP_NAME}
    instanceType: t3.medium
    desiredCapacity: 3
    minSize: 2
    maxSize: 5
    volumeSize: 20
    volumeType: gp3
    amiFamily: AmazonLinux2
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonEBSCSIDriverPolicy
    labels:
      role: worker
      environment: test
    tags:
      Environment: test
      Project: kube-policies
      ManagedBy: eksctl

cloudWatch:
  clusterLogging:
    enable: ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    logRetentionInDays: 7
EOF

    # Create the cluster
    eksctl create cluster -f /tmp/eks-cluster.yaml
    
    # Update kubeconfig
    aws eks update-kubeconfig --region "${AWS_REGION}" --name "${CLUSTER_NAME}"
    
    success "EKS cluster created successfully"
}

# Install AWS Load Balancer Controller
install_aws_load_balancer_controller() {
    log "Installing AWS Load Balancer Controller..."
    
    # Create IAM service account
    eksctl create iamserviceaccount \
        --cluster="${CLUSTER_NAME}" \
        --region="${AWS_REGION}" \
        --namespace=kube-system \
        --name=aws-load-balancer-controller \
        --role-name="AmazonEKSLoadBalancerControllerRole-${CLUSTER_NAME}" \
        --attach-policy-arn=arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess \
        --approve \
        --override-existing-serviceaccounts
    
    # Install AWS Load Balancer Controller
    helm repo add eks https://aws.github.io/eks-charts
    helm repo update
    
    helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
        --namespace kube-system \
        --set clusterName="${CLUSTER_NAME}" \
        --set serviceAccount.create=false \
        --set serviceAccount.name=aws-load-balancer-controller \
        --set region="${AWS_REGION}" \
        --set vpcId=$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --query "cluster.resourcesVpcConfig.vpcId" --output text) \
        --wait
    
    success "AWS Load Balancer Controller installed"
}

# Install cert-manager
install_cert_manager() {
    log "Installing cert-manager on EKS..."
    
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
    
    # Wait for cert-manager to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager
    
    success "cert-manager installed successfully"
}

# Deploy Kube-Policies
deploy_kube_policies() {
    log "Deploying Kube-Policies on EKS..."
    
    cd "${PROJECT_ROOT}"
    
    # Create namespace
    kubectl create namespace kube-policies-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Install CRDs
    kubectl apply -f deployments/kubernetes/crds/
    
    # Create Helm values for EKS
    cat <<EOF > /tmp/eks-values.yaml
admissionWebhook:
  image:
    repository: ${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/admission-webhook
    tag: eks
  service:
    type: LoadBalancer
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
      service.beta.kubernetes.io/aws-load-balancer-scheme: "internal"
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

policyManager:
  image:
    repository: ${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/policy-manager
    tag: eks
  service:
    type: LoadBalancer
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
      service.beta.kubernetes.io/aws-load-balancer-scheme: "internal"
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
    storageClass: gp2
    storage: 10Gi
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 1Gi
  grafana:
    enabled: true
    storageClass: gp2
    storage: 5Gi
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

# EKS specific configurations
nodeSelector:
  kubernetes.io/os: linux

tolerations:
  - key: node.kubernetes.io/not-ready
    operator: Exists
    effect: NoExecute
    tolerationSeconds: 300
  - key: node.kubernetes.io/unreachable
    operator: Exists
    effect: NoExecute
    tolerationSeconds: 300

# AWS specific settings
aws:
  region: ${AWS_REGION}
  accountId: ${AWS_ACCOUNT_ID}

# High availability settings
replicaCount: 2
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - kube-policies
        topologyKey: kubernetes.io/hostname
EOF

    # Install using Helm
    helm upgrade --install kube-policies charts/kube-policies \
        --namespace kube-policies-system \
        --values /tmp/eks-values.yaml \
        --wait --timeout=900s
    
    success "Kube-Policies deployed successfully on EKS"
}

# Wait for deployment
wait_for_deployment() {
    log "Waiting for Kube-Policies to be ready on EKS..."
    
    # Wait for admission webhook
    kubectl wait --for=condition=available --timeout=600s deployment/kube-policies-admission-webhook -n kube-policies-system
    
    # Wait for policy manager
    kubectl wait --for=condition=available --timeout=600s deployment/kube-policies-policy-manager -n kube-policies-system
    
    # Wait for load balancers to be ready
    log "Waiting for load balancers to be ready..."
    timeout 600 bash -c 'until kubectl get svc kube-policies-admission-webhook -n kube-policies-system -o jsonpath="{.status.loadBalancer.ingress[0].hostname}" | grep -q amazonaws.com; do sleep 10; done'
    timeout 600 bash -c 'until kubectl get svc kube-policies-policy-manager -n kube-policies-system -o jsonpath="{.status.loadBalancer.ingress[0].hostname}" | grep -q amazonaws.com; do sleep 10; done'
    
    # Wait for webhook configuration
    timeout 300 bash -c 'until kubectl get validatingwebhookconfiguration kube-policies-validating-webhook &>/dev/null; do sleep 5; done'
    timeout 300 bash -c 'until kubectl get mutatingwebhookconfiguration kube-policies-mutating-webhook &>/dev/null; do sleep 5; done'
    
    success "All components are ready on EKS"
}

# Run tests
run_tests() {
    log "Running E2E tests on EKS cluster..."
    
    cd "${PROJECT_ROOT}"
    
    # Run unit tests
    log "Running unit tests..."
    go test -v ./internal/... ./pkg/... -race -coverprofile=coverage-unit-eks.out
    
    # Run integration tests
    log "Running integration tests..."
    go test -v ./test/integration/... -race -coverprofile=coverage-integration-eks.out
    
    # Run E2E tests
    log "Running E2E tests..."
    go test -v ./test/e2e/... -ginkgo.v -ginkgo.progress -coverprofile=coverage-e2e-eks.out
    
    # Generate combined coverage report
    log "Generating coverage report..."
    go tool cover -html=coverage-e2e-eks.out -o coverage-eks.html
    
    success "All tests completed successfully on EKS"
}

# Test EKS specific scenarios
test_eks_scenarios() {
    log "Testing EKS-specific scenarios..."
    
    # Test 1: AWS Load Balancer integration
    log "Test 1: Testing AWS Load Balancer integration"
    
    # Get load balancer hostnames
    WEBHOOK_LB=$(kubectl get svc kube-policies-admission-webhook -n kube-policies-system -o jsonpath="{.status.loadBalancer.ingress[0].hostname}")
    MANAGER_LB=$(kubectl get svc kube-policies-policy-manager -n kube-policies-system -o jsonpath="{.status.loadBalancer.ingress[0].hostname}")
    
    log "Admission webhook load balancer: ${WEBHOOK_LB}"
    log "Policy manager load balancer: ${MANAGER_LB}"
    
    # Test connectivity (from within cluster)
    kubectl run test-connectivity --image=busybox --rm -it --restart=Never -- wget -qO- "http://${MANAGER_LB}:8080/healthz" || true
    
    success "Load balancer integration tested"
    
    # Test 2: EBS CSI driver integration
    log "Test 2: Testing EBS CSI driver integration"
    
    kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-ebs-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
  storageClassName: gp2
EOF
    
    # Wait for PVC to be bound
    timeout 120 bash -c 'until kubectl get pvc test-ebs-pvc -n default -o jsonpath="{.status.phase}" | grep -q Bound; do sleep 5; done'
    success "EBS CSI driver integration working"
    
    # Test 3: IAM roles and service accounts
    log "Test 3: Testing IAM integration"
    
    # Check if service accounts have proper annotations
    if kubectl get sa aws-load-balancer-controller -n kube-system -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}' | grep -q "arn:aws:iam"; then
        success "IAM service account integration working"
    else
        warn "IAM service account integration not detected"
    fi
    
    # Test 4: Multi-AZ deployment
    log "Test 4: Testing multi-AZ deployment"
    
    # Check node distribution across AZs
    AZ_COUNT=$(kubectl get nodes -o jsonpath='{.items[*].metadata.labels.topology\.kubernetes\.io/zone}' | tr ' ' '\n' | sort -u | wc -l)
    log "Nodes distributed across ${AZ_COUNT} availability zones"
    
    if [[ ${AZ_COUNT} -gt 1 ]]; then
        success "Multi-AZ deployment confirmed"
    else
        warn "Single AZ deployment detected"
    fi
    
    # Test 5: CloudWatch logging
    log "Test 5: Testing CloudWatch logging integration"
    
    # Check if cluster logging is enabled
    LOGGING_TYPES=$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --query 'cluster.logging.clusterLogging[?enabled==`true`].types[]' --output text)
    log "Enabled logging types: ${LOGGING_TYPES}"
    
    if [[ -n "${LOGGING_TYPES}" ]]; then
        success "CloudWatch logging is enabled"
    else
        warn "CloudWatch logging not enabled"
    fi
    
    success "All EKS-specific tests completed"
}

# Test performance and scalability
test_performance() {
    log "Testing performance and scalability on EKS..."
    
    # Test 1: High-volume pod creation
    log "Test 1: High-volume pod creation test"
    
    # Create a namespace for performance testing
    kubectl create namespace perf-test --dry-run=client -o yaml | kubectl apply -f -
    
    # Create 50 pods concurrently
    for i in {1..50}; do
        kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: perf-test-pod-${i}
  namespace: perf-test
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
    done &
    
    # Wait for all pods to be created
    wait
    
    # Count successful pods
    READY_PODS=$(kubectl get pods -n perf-test --field-selector=status.phase=Running --no-headers | wc -l)
    log "Successfully created ${READY_PODS}/50 pods"
    
    if [[ ${READY_PODS} -ge 45 ]]; then
        success "High-volume pod creation test passed"
    else
        warn "High-volume pod creation test had issues"
    fi
    
    # Test 2: Admission webhook latency
    log "Test 2: Measuring admission webhook latency"
    
    # Create pods and measure time
    START_TIME=$(date +%s)
    for i in {51..60}; do
        kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: latency-test-pod-${i}
  namespace: perf-test
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
    done
    END_TIME=$(date +%s)
    
    DURATION=$((END_TIME - START_TIME))
    AVG_LATENCY=$((DURATION * 1000 / 10))  # Convert to milliseconds per pod
    
    log "Average admission latency: ${AVG_LATENCY}ms per pod"
    
    if [[ ${AVG_LATENCY} -lt 1000 ]]; then
        success "Admission webhook latency is acceptable"
    else
        warn "Admission webhook latency is high"
    fi
    
    success "Performance testing completed"
}

# Collect logs and diagnostics
collect_diagnostics() {
    log "Collecting diagnostics from EKS..."
    
    mkdir -p "${PROJECT_ROOT}/test-results/eks"
    
    # Collect cluster info
    kubectl cluster-info > "${PROJECT_ROOT}/test-results/eks/cluster-info.txt"
    kubectl get nodes -o wide > "${PROJECT_ROOT}/test-results/eks/nodes.txt"
    kubectl get pods -A -o wide > "${PROJECT_ROOT}/test-results/eks/pods.txt"
    
    # Collect EKS specific info
    aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" > "${PROJECT_ROOT}/test-results/eks/cluster-description.json"
    aws eks describe-nodegroup --cluster-name "${CLUSTER_NAME}" --nodegroup-name "${NODE_GROUP_NAME}" --region "${AWS_REGION}" > "${PROJECT_ROOT}/test-results/eks/nodegroup-description.json"
    
    # Collect Kube-Policies logs
    kubectl logs -n kube-policies-system -l app=kube-policies-admission-webhook --tail=1000 > "${PROJECT_ROOT}/test-results/eks/admission-webhook.log" || true
    kubectl logs -n kube-policies-system -l app=kube-policies-policy-manager --tail=1000 > "${PROJECT_ROOT}/test-results/eks/policy-manager.log" || true
    
    # Collect events
    kubectl get events -A --sort-by='.lastTimestamp' > "${PROJECT_ROOT}/test-results/eks/events.txt"
    
    # Collect resource definitions
    kubectl get policies -A -o yaml > "${PROJECT_ROOT}/test-results/eks/policies.yaml" || true
    kubectl get policyexceptions -A -o yaml > "${PROJECT_ROOT}/test-results/eks/exceptions.yaml" || true
    
    # Collect AWS Load Balancer Controller logs
    kubectl logs -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller --tail=1000 > "${PROJECT_ROOT}/test-results/eks/aws-lb-controller.log" || true
    
    # Collect service information
    kubectl get svc -A -o wide > "${PROJECT_ROOT}/test-results/eks/services.txt"
    
    success "Diagnostics collected in test-results/eks/"
}

# Cleanup
cleanup() {
    log "Cleaning up EKS environment..."
    
    if [[ "${CLEANUP:-true}" == "true" ]]; then
        # Delete test resources
        kubectl delete namespace perf-test --ignore-not-found=true
        kubectl delete pvc test-ebs-pvc -n default --ignore-not-found=true
        
        # Delete EKS cluster
        log "Deleting EKS cluster (this may take 10-15 minutes)..."
        eksctl delete cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --wait
        
        # Delete ECR repositories
        for component in admission-webhook policy-manager; do
            REPO_NAME="${ECR_REPOSITORY_PREFIX}/${component}"
            aws ecr delete-repository --repository-name "${REPO_NAME}" --region "${AWS_REGION}" --force || true
        done
        
        success "EKS cleanup completed"
    else
        warn "Cleanup skipped (CLEANUP=false)"
        log "EKS cluster: ${CLUSTER_NAME} in region ${AWS_REGION}"
        log "ECR repositories: ${ECR_REPOSITORY_PREFIX}/*"
    fi
}

# Main execution
main() {
    log "Starting Kube-Policies testing on EKS cluster"
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    check_prerequisites
    create_ecr_repositories
    build_and_push_images
    create_eks_cluster
    install_aws_load_balancer_controller
    install_cert_manager
    deploy_kube_policies
    wait_for_deployment
    run_tests
    test_eks_scenarios
    test_performance
    collect_diagnostics
    
    success "Kube-Policies testing on EKS completed successfully!"
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

