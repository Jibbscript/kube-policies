# Kube-Policies Testing Guide

This document provides comprehensive guidance for testing the Kube-Policies project across different environments and scenarios.

## Table of Contents

- [Overview](#overview)
- [Test Architecture](#test-architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Test Types](#test-types)
- [Cluster-Specific Testing](#cluster-specific-testing)
- [CI/CD Integration](#cicd-integration)
- [Performance Testing](#performance-testing)
- [Security Testing](#security-testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Overview

The Kube-Policies testing suite provides comprehensive validation across multiple dimensions:

- **Unit Tests**: Test individual components and functions
- **Integration Tests**: Test component interactions and API contracts
- **End-to-End Tests**: Test complete workflows in real Kubernetes environments
- **Performance Tests**: Validate performance characteristics and scalability
- **Security Tests**: Ensure security best practices and vulnerability scanning
- **Cluster Compatibility**: Validate across different Kubernetes distributions

## Test Architecture

```
kube-policies/
├── test/
│   ├── unit/                    # Unit test helpers and fixtures
│   ├── integration/             # Integration test suites
│   ├── e2e/                     # End-to-end test framework
│   │   ├── framework/           # Test framework and utilities
│   │   └── e2e_test.go         # Main E2E test suite
│   └── fixtures/                # Test data and configurations
├── scripts/test/                # Test execution scripts
│   ├── run-all-tests.sh        # Master test runner
│   ├── test-kind.sh            # Kind cluster testing
│   ├── test-k3s.sh             # k3s cluster testing
│   ├── test-eks.sh             # AWS EKS testing
│   └── test-vanilla.sh         # Vanilla Kubernetes testing
└── .github/workflows/           # CI/CD pipeline definitions
    ├── ci.yml                  # Continuous integration
    └── release.yml             # Release pipeline
```

## Prerequisites

### Base Requirements

- **Go 1.20+**: For running unit and integration tests
- **Docker**: For building and running container images
- **kubectl**: For Kubernetes cluster interaction
- **Helm 3.x**: For chart testing and deployment

### Cluster-Specific Requirements

#### Kind
```bash
# Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

#### k3s
```bash
# k3s will be installed automatically by the test script
# Requires sudo privileges
```

#### AWS EKS
```bash
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Configure AWS credentials
aws configure
```

#### Vanilla Kubernetes
```bash
# Install kubeadm, kubelet, kubectl
# Requires root privileges and proper system setup
```

### Optional Tools

```bash
# For enhanced testing capabilities
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Quick Start

### Run All Tests (Default)

```bash
# Run unit, integration, and E2E tests on Kind and k3s
./scripts/test/run-all-tests.sh
```

### Run Specific Test Types

```bash
# Unit tests only
go test -v ./internal/... ./pkg/...

# Integration tests only
go test -v ./test/integration/...

# E2E tests on Kind
./scripts/test/test-kind.sh

# E2E tests on k3s (requires sudo)
sudo ./scripts/test/test-k3s.sh
```

### Custom Test Configuration

```bash
# Test specific clusters
./scripts/test/run-all-tests.sh --clusters kind,eks

# Run tests in parallel
./scripts/test/run-all-tests.sh --parallel

# Include performance tests
./scripts/test/run-all-tests.sh --performance

# Keep test resources for debugging
./scripts/test/run-all-tests.sh --no-cleanup
```

## Test Types

### Unit Tests

Unit tests validate individual components and functions in isolation.

**Location**: `internal/*/`, `pkg/*/`
**Pattern**: `*_test.go` files alongside source code

**Running Unit Tests**:
```bash
# All unit tests
go test -v ./internal/... ./pkg/...

# With coverage
go test -v -race -coverprofile=coverage.out ./internal/... ./pkg/...

# Specific package
go test -v ./internal/admission/
```

**Key Test Areas**:
- Admission controller logic
- Policy engine evaluation
- Configuration management
- Audit logging
- Metrics collection

### Integration Tests

Integration tests validate component interactions and API contracts.

**Location**: `test/integration/`
**Framework**: Go testing with testify assertions

**Running Integration Tests**:
```bash
# All integration tests
go test -v ./test/integration/...

# With test environment
export KUBEBUILDER_ASSETS=$(setup-envtest use 1.28.0 --bin-dir /tmp/envtest-bins -p path)
go test -v ./test/integration/...
```

**Test Scenarios**:
- Admission webhook request/response cycles
- Policy manager API operations
- CRD validation and storage
- Webhook configuration management

### End-to-End Tests

E2E tests validate complete workflows in real Kubernetes environments.

**Location**: `test/e2e/`
**Framework**: Ginkgo + Gomega

**Running E2E Tests**:
```bash
# On existing cluster
go test -v ./test/e2e/...

# With cluster setup (Kind)
./scripts/test/test-kind.sh
```

**Test Scenarios**:
- Policy enforcement on pod creation
- Policy exceptions and overrides
- Multi-rule policy evaluation
- Deployment and service policies
- Performance under load

## Cluster-Specific Testing

### Kind (Kubernetes in Docker)

**Use Case**: Local development and CI/CD
**Advantages**: Fast setup, consistent environment, good for automation

```bash
# Run Kind tests
./scripts/test/test-kind.sh

# Custom configuration
export KIND_CLUSTER_NAME=my-test-cluster
export KUBERNETES_VERSION=v1.28.0
./scripts/test/test-kind.sh
```

**Features Tested**:
- Multi-node cluster simulation
- Load balancer integration
- Container registry integration
- Admission webhook performance

### k3s (Lightweight Kubernetes)

**Use Case**: Edge computing, resource-constrained environments
**Advantages**: Minimal resource usage, single binary, fast startup

```bash
# Run k3s tests (requires sudo)
sudo ./scripts/test/test-k3s.sh

# Custom configuration
export K3S_VERSION=v1.28.2+k3s1
sudo ./scripts/test/test-k3s.sh
```

**Features Tested**:
- Single-node deployment
- Local path storage
- Resource constraints
- Embedded components

### AWS EKS (Elastic Kubernetes Service)

**Use Case**: Production cloud environments
**Advantages**: Managed control plane, AWS integration, enterprise features

```bash
# Run EKS tests (requires AWS credentials)
export AWS_REGION=us-west-2
export CLUSTER_NAME=kube-policies-test
./scripts/test/test-eks.sh
```

**Features Tested**:
- Multi-AZ deployment
- AWS Load Balancer Controller
- EBS CSI driver integration
- IAM roles and service accounts
- CloudWatch logging

### Vanilla Kubernetes

**Use Case**: On-premises, custom distributions
**Advantages**: Full control, custom configurations, bare metal

```bash
# Run vanilla tests (requires root)
sudo ./scripts/test/test-vanilla.sh
```

**Features Tested**:
- kubeadm cluster setup
- CNI plugin integration
- Ingress controller
- Local registry
- Single-node constraints

## CI/CD Integration

### GitHub Actions

The project includes comprehensive GitHub Actions workflows:

**Continuous Integration** (`.github/workflows/ci.yml`):
- Triggered on push/PR to main branches
- Runs lint, unit, integration, and E2E tests
- Builds and scans container images
- Generates coverage reports

**Release Pipeline** (`.github/workflows/release.yml`):
- Triggered on version tags
- Builds multi-arch container images
- Packages Helm charts
- Creates GitHub releases
- Signs artifacts with Cosign

**Workflow Features**:
- Parallel test execution
- Artifact caching
- Security scanning
- Coverage reporting
- Slack/Teams notifications

### Local CI Simulation

```bash
# Simulate CI pipeline locally
./scripts/test/run-all-tests.sh --clusters kind --parallel --performance

# Check what CI would run
act -l  # Requires 'act' tool
```

## Performance Testing

### Benchmarks

```bash
# Run Go benchmarks
go test -bench=. -benchmem ./internal/... ./pkg/...

# Specific benchmarks
go test -bench=BenchmarkPolicyEvaluation ./internal/policy/
```

### Load Testing

```bash
# Enable performance tests
./scripts/test/run-all-tests.sh --performance

# Manual load testing (requires running cluster)
hey -n 1000 -c 10 http://localhost:8080/healthz
```

### Performance Metrics

The test suite measures:
- **Admission Latency**: Time to process admission requests
- **Policy Evaluation**: Time to evaluate Rego policies
- **Throughput**: Requests per second under load
- **Resource Usage**: CPU and memory consumption
- **Scalability**: Performance with increasing load

## Security Testing

### Static Analysis

```bash
# Security scanning with gosec
gosec ./...

# Vulnerability scanning
govulncheck ./...

# Lint for security issues
golangci-lint run --enable=gosec
```

### Container Scanning

```bash
# Scan container images
trivy image kube-policies/admission-webhook:latest
trivy image kube-policies/policy-manager:latest

# Scan filesystem
trivy fs .
```

### Security Test Scenarios

- Privilege escalation prevention
- Container security contexts
- Network policy enforcement
- RBAC validation
- TLS certificate management

## Troubleshooting

### Common Issues

#### Test Failures

```bash
# Check test logs
./scripts/test/run-all-tests.sh --no-cleanup
kubectl logs -n kube-policies-system -l app=kube-policies-admission-webhook

# Debug specific test
go test -v -run TestSpecificFunction ./internal/admission/
```

#### Cluster Issues

```bash
# Check cluster status
kubectl cluster-info
kubectl get nodes
kubectl get pods -A

# Check admission webhook
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration
```

#### Resource Issues

```bash
# Check resource usage
kubectl top nodes
kubectl top pods -A

# Check events
kubectl get events -A --sort-by='.lastTimestamp'
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug
./scripts/test/test-kind.sh

# Keep resources for inspection
export CLEANUP=false
./scripts/test/test-kind.sh
```

### Test Data Collection

Test results and diagnostics are automatically collected in:
- `test-results/kind/` - Kind cluster test results
- `test-results/k3s/` - k3s cluster test results
- `test-results/eks/` - EKS cluster test results
- `test-results/vanilla/` - Vanilla Kubernetes test results
- `test-results/summary/` - Comprehensive test report

## Contributing

### Adding New Tests

1. **Unit Tests**: Add `*_test.go` files alongside source code
2. **Integration Tests**: Add test files to `test/integration/`
3. **E2E Tests**: Extend `test/e2e/e2e_test.go` with new scenarios
4. **Cluster Tests**: Modify cluster-specific scripts in `scripts/test/`

### Test Guidelines

- Use table-driven tests for multiple scenarios
- Include both positive and negative test cases
- Test error conditions and edge cases
- Use meaningful test names and descriptions
- Clean up resources in test teardown

### Example Test Structure

```go
func TestAdmissionController(t *testing.T) {
    tests := []struct {
        name           string
        request        *admissionv1.AdmissionRequest
        expectedResult bool
        expectedError  string
    }{
        {
            name: "should allow valid pod",
            request: &admissionv1.AdmissionRequest{
                // ... test data
            },
            expectedResult: true,
        },
        {
            name: "should deny privileged pod",
            request: &admissionv1.AdmissionRequest{
                // ... test data
            },
            expectedResult: false,
            expectedError: "privileged containers not allowed",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Performance Test Guidelines

- Use Go benchmarks for micro-benchmarks
- Test realistic workloads and data sizes
- Measure both latency and throughput
- Include memory allocation profiling
- Set appropriate benchmark duration

### Security Test Guidelines

- Test all security boundaries
- Validate input sanitization
- Test privilege escalation scenarios
- Verify TLS configuration
- Test authentication and authorization

## Test Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLUSTERS` | Comma-separated list of clusters to test | `kind,k3s` |
| `PARALLEL` | Run cluster tests in parallel | `false` |
| `CLEANUP` | Clean up test resources | `true` |
| `COVERAGE` | Generate coverage reports | `true` |
| `PERFORMANCE` | Run performance tests | `false` |
| `LOG_LEVEL` | Logging level for tests | `info` |
| `KUBERNETES_VERSION` | Kubernetes version to test | `v1.28.2` |

## Continuous Improvement

The testing suite is continuously improved through:

- Regular updates to test scenarios
- Addition of new cluster types and versions
- Performance optimization
- Security enhancement
- Better error reporting and diagnostics

For questions or contributions to the testing framework, please open an issue or submit a pull request.

