#!/bin/bash

# run-all-tests.sh - Master test runner for Kube-Policies
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

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

# Configuration
CLUSTERS="${CLUSTERS:-kind,k3s}"
PARALLEL="${PARALLEL:-false}"
CLEANUP="${CLEANUP:-true}"
COVERAGE="${COVERAGE:-true}"
PERFORMANCE="${PERFORMANCE:-false}"

# Test results tracking
RESULTS_DIR="${PROJECT_ROOT}/test-results/summary"
mkdir -p "${RESULTS_DIR}"

# Test status tracking
declare -A TEST_STATUS
declare -A TEST_DURATION

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    local start_time=$(date +%s)
    
    log "Starting ${test_name}..."
    
    if eval "${test_command}"; then
        TEST_STATUS["${test_name}"]="PASSED"
        success "${test_name} completed successfully"
    else
        TEST_STATUS["${test_name}"]="FAILED"
        error "${test_name} failed"
    fi
    
    local end_time=$(date +%s)
    TEST_DURATION["${test_name}"]=$((end_time - start_time))
}

# Function to run tests in parallel
run_parallel() {
    local pids=()
    local test_name="$1"
    local test_command="$2"
    
    log "Starting ${test_name} in background..."
    eval "${test_command}" &
    pids+=($!)
    
    # Wait for all background processes
    for pid in "${pids[@]}"; do
        if wait "${pid}"; then
            TEST_STATUS["${test_name}"]="PASSED"
        else
            TEST_STATUS["${test_name}"]="FAILED"
        fi
    done
}

# Unit tests
run_unit_tests() {
    log "Running unit tests..."
    
    cd "${PROJECT_ROOT}"
    
    # Run unit tests with coverage
    if [[ "${COVERAGE}" == "true" ]]; then
        go test -v -race -coverprofile=coverage-unit.out -covermode=atomic ./internal/... ./pkg/...
        go tool cover -html=coverage-unit.out -o "${RESULTS_DIR}/coverage-unit.html"
    else
        go test -v -race ./internal/... ./pkg/...
    fi
}

# Integration tests
run_integration_tests() {
    log "Running integration tests..."
    
    cd "${PROJECT_ROOT}"
    
    # Set up test environment
    export KUBEBUILDER_ASSETS=$(setup-envtest use 1.28.0 --bin-dir /tmp/envtest-bins -p path 2>/dev/null || echo "")
    
    if [[ "${COVERAGE}" == "true" ]]; then
        go test -v -race -coverprofile=coverage-integration.out ./test/integration/...
        go tool cover -html=coverage-integration.out -o "${RESULTS_DIR}/coverage-integration.html"
    else
        go test -v -race ./test/integration/...
    fi
}

# Cluster-specific tests
run_kind_tests() {
    log "Running Kind cluster tests..."
    export CLEANUP="${CLEANUP}"
    "${SCRIPT_DIR}/test-kind.sh"
}

run_k3s_tests() {
    log "Running k3s cluster tests..."
    export CLEANUP="${CLEANUP}"
    sudo "${SCRIPT_DIR}/test-k3s.sh"
}

run_eks_tests() {
    log "Running EKS cluster tests..."
    
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &>/dev/null; then
        warn "AWS credentials not configured, skipping EKS tests"
        TEST_STATUS["eks"]="SKIPPED"
        return 0
    fi
    
    export CLEANUP="${CLEANUP}"
    "${SCRIPT_DIR}/test-eks.sh"
}

run_vanilla_tests() {
    log "Running vanilla Kubernetes tests..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root, skipping vanilla Kubernetes tests"
        TEST_STATUS["vanilla"]="SKIPPED"
        return 0
    fi
    
    export CLEANUP="${CLEANUP}"
    "${SCRIPT_DIR}/test-vanilla.sh"
}

# Performance tests
run_performance_tests() {
    log "Running performance tests..."
    
    cd "${PROJECT_ROOT}"
    
    # Run Go benchmarks
    go test -bench=. -benchmem ./internal/... ./pkg/... > "${RESULTS_DIR}/benchmark-results.txt"
    
    # Run load tests if available
    if command -v hey &> /dev/null; then
        log "Running load tests with hey..."
        # This would require a running cluster
        # hey -n 1000 -c 10 http://localhost:8080/healthz > "${RESULTS_DIR}/load-test-results.txt" || true
    fi
}

# Security tests
run_security_tests() {
    log "Running security tests..."
    
    cd "${PROJECT_ROOT}"
    
    # Run gosec
    if command -v gosec &> /dev/null; then
        gosec -fmt json -out "${RESULTS_DIR}/gosec-report.json" ./... || true
    fi
    
    # Run govulncheck
    if command -v govulncheck &> /dev/null; then
        govulncheck ./... > "${RESULTS_DIR}/vulnerability-report.txt" || true
    fi
    
    # Run trivy on filesystem
    if command -v trivy &> /dev/null; then
        trivy fs --format json --output "${RESULTS_DIR}/trivy-fs-report.json" . || true
    fi
}

# Lint tests
run_lint_tests() {
    log "Running lint tests..."
    
    cd "${PROJECT_ROOT}"
    
    # Run golangci-lint
    if command -v golangci-lint &> /dev/null; then
        golangci-lint run --out-format json > "${RESULTS_DIR}/golangci-lint-report.json" || true
    fi
    
    # Run go vet
    go vet ./... > "${RESULTS_DIR}/go-vet-report.txt" 2>&1 || true
    
    # Check formatting
    gofmt -l . > "${RESULTS_DIR}/gofmt-report.txt" || true
}

# Helm tests
run_helm_tests() {
    log "Running Helm chart tests..."
    
    cd "${PROJECT_ROOT}"
    
    # Lint Helm charts
    if command -v helm &> /dev/null; then
        helm lint charts/kube-policies > "${RESULTS_DIR}/helm-lint-report.txt" 2>&1 || true
    fi
    
    # Template and validate
    if command -v helm &> /dev/null && command -v kubectl &> /dev/null; then
        helm template kube-policies charts/kube-policies > "${RESULTS_DIR}/helm-template-output.yaml" 2>&1 || true
        kubectl apply --dry-run=client -f "${RESULTS_DIR}/helm-template-output.yaml" > "${RESULTS_DIR}/kubectl-validate-report.txt" 2>&1 || true
    fi
}

# Generate comprehensive test report
generate_report() {
    log "Generating comprehensive test report..."
    
    local report_file="${RESULTS_DIR}/test-report.html"
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local skipped_tests=0
    
    # Count test results
    for test in "${!TEST_STATUS[@]}"; do
        total_tests=$((total_tests + 1))
        case "${TEST_STATUS[$test]}" in
            "PASSED") passed_tests=$((passed_tests + 1)) ;;
            "FAILED") failed_tests=$((failed_tests + 1)) ;;
            "SKIPPED") skipped_tests=$((skipped_tests + 1)) ;;
        esac
    done
    
    # Generate HTML report
    cat > "${report_file}" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Kube-Policies Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { background-color: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
        .passed { background-color: #d4edda; color: #155724; }
        .failed { background-color: #f8d7da; color: #721c24; }
        .skipped { background-color: #fff3cd; color: #856404; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .status-passed { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-skipped { color: #ffc107; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Kube-Policies Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Project: Kube-Policies</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>Total Tests</h3>
            <div style="font-size: 2em; font-weight: bold;">${total_tests}</div>
        </div>
        <div class="metric passed">
            <h3>Passed</h3>
            <div style="font-size: 2em; font-weight: bold;">${passed_tests}</div>
        </div>
        <div class="metric failed">
            <h3>Failed</h3>
            <div style="font-size: 2em; font-weight: bold;">${failed_tests}</div>
        </div>
        <div class="metric skipped">
            <h3>Skipped</h3>
            <div style="font-size: 2em; font-weight: bold;">${skipped_tests}</div>
        </div>
    </div>
    
    <h2>Test Results</h2>
    <table>
        <thead>
            <tr>
                <th>Test Suite</th>
                <th>Status</th>
                <th>Duration (seconds)</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
EOF

    # Add test results to table
    for test in "${!TEST_STATUS[@]}"; do
        local status="${TEST_STATUS[$test]}"
        local duration="${TEST_DURATION[$test]:-0}"
        local css_class="status-$(echo "${status}" | tr '[:upper:]' '[:lower:]')"
        
        cat >> "${report_file}" <<EOF
            <tr>
                <td>${test}</td>
                <td class="${css_class}">${status}</td>
                <td>${duration}</td>
                <td>See individual test logs</td>
            </tr>
EOF
    done
    
    cat >> "${report_file}" <<EOF
        </tbody>
    </table>
    
    <h2>Coverage Reports</h2>
    <ul>
        <li><a href="coverage-unit.html">Unit Test Coverage</a></li>
        <li><a href="coverage-integration.html">Integration Test Coverage</a></li>
    </ul>
    
    <h2>Additional Reports</h2>
    <ul>
        <li><a href="benchmark-results.txt">Performance Benchmarks</a></li>
        <li><a href="gosec-report.json">Security Scan (gosec)</a></li>
        <li><a href="vulnerability-report.txt">Vulnerability Report</a></li>
        <li><a href="golangci-lint-report.json">Lint Report</a></li>
        <li><a href="helm-lint-report.txt">Helm Chart Lint</a></li>
    </ul>
    
    <div style="margin-top: 40px; padding: 20px; background-color: #f8f9fa; border-radius: 5px;">
        <h3>Test Environment</h3>
        <p><strong>Go Version:</strong> $(go version)</p>
        <p><strong>OS:</strong> $(uname -a)</p>
        <p><strong>Clusters Tested:</strong> ${CLUSTERS}</p>
        <p><strong>Parallel Execution:</strong> ${PARALLEL}</p>
        <p><strong>Coverage Enabled:</strong> ${COVERAGE}</p>
    </div>
</body>
</html>
EOF

    success "Test report generated: ${report_file}"
}

# Print usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Run comprehensive test suite for Kube-Policies

OPTIONS:
    -c, --clusters CLUSTERS     Comma-separated list of clusters to test (default: kind,k3s)
                               Available: kind,k3s,eks,vanilla
    -p, --parallel             Run cluster tests in parallel (default: false)
    --no-cleanup              Don't cleanup test resources (default: cleanup enabled)
    --no-coverage             Disable coverage reporting (default: coverage enabled)
    --performance             Run performance tests (default: false)
    -h, --help                Show this help message

EXAMPLES:
    $0                                    # Run default tests (kind,k3s)
    $0 -c kind                           # Run only Kind tests
    $0 -c kind,k3s,eks --parallel        # Run multiple clusters in parallel
    $0 --performance                     # Include performance tests
    $0 --no-cleanup                      # Keep test resources for debugging

ENVIRONMENT VARIABLES:
    CLUSTERS        Override default clusters
    PARALLEL        Enable parallel execution
    CLEANUP         Enable/disable cleanup (true/false)
    COVERAGE        Enable/disable coverage (true/false)
    PERFORMANCE     Enable/disable performance tests (true/false)
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clusters)
            CLUSTERS="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="true"
            shift
            ;;
        --no-cleanup)
            CLEANUP="false"
            shift
            ;;
        --no-coverage)
            COVERAGE="false"
            shift
            ;;
        --performance)
            PERFORMANCE="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log "Starting comprehensive Kube-Policies test suite"
    log "Configuration:"
    log "  Clusters: ${CLUSTERS}"
    log "  Parallel: ${PARALLEL}"
    log "  Cleanup: ${CLEANUP}"
    log "  Coverage: ${COVERAGE}"
    log "  Performance: ${PERFORMANCE}"
    
    local start_time=$(date +%s)
    
    # Always run these tests
    run_test "lint" "run_lint_tests"
    run_test "unit" "run_unit_tests"
    run_test "integration" "run_integration_tests"
    run_test "security" "run_security_tests"
    run_test "helm" "run_helm_tests"
    
    # Run performance tests if enabled
    if [[ "${PERFORMANCE}" == "true" ]]; then
        run_test "performance" "run_performance_tests"
    fi
    
    # Run cluster-specific tests
    IFS=',' read -ra CLUSTER_ARRAY <<< "${CLUSTERS}"
    
    if [[ "${PARALLEL}" == "true" ]]; then
        log "Running cluster tests in parallel..."
        for cluster in "${CLUSTER_ARRAY[@]}"; do
            case "${cluster}" in
                "kind") run_parallel "kind" "run_kind_tests" ;;
                "k3s") run_parallel "k3s" "run_k3s_tests" ;;
                "eks") run_parallel "eks" "run_eks_tests" ;;
                "vanilla") run_parallel "vanilla" "run_vanilla_tests" ;;
                *) warn "Unknown cluster type: ${cluster}" ;;
            esac
        done
        
        # Wait for all parallel jobs to complete
        wait
    else
        log "Running cluster tests sequentially..."
        for cluster in "${CLUSTER_ARRAY[@]}"; do
            case "${cluster}" in
                "kind") run_test "kind" "run_kind_tests" ;;
                "k3s") run_test "k3s" "run_k3s_tests" ;;
                "eks") run_test "eks" "run_eks_tests" ;;
                "vanilla") run_test "vanilla" "run_vanilla_tests" ;;
                *) warn "Unknown cluster type: ${cluster}" ;;
            esac
        done
    fi
    
    # Generate comprehensive report
    generate_report
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # Print summary
    log "Test suite completed in ${total_duration} seconds"
    log "Results summary:"
    
    local exit_code=0
    for test in "${!TEST_STATUS[@]}"; do
        local status="${TEST_STATUS[$test]}"
        local duration="${TEST_DURATION[$test]:-0}"
        
        case "${status}" in
            "PASSED") success "  ${test}: ${status} (${duration}s)" ;;
            "FAILED") 
                error "  ${test}: ${status} (${duration}s)"
                exit_code=1
                ;;
            "SKIPPED") warn "  ${test}: ${status}" ;;
        esac
    done
    
    if [[ ${exit_code} -eq 0 ]]; then
        success "All tests completed successfully!"
    else
        error "Some tests failed. Check the detailed logs for more information."
    fi
    
    log "Detailed report available at: ${RESULTS_DIR}/test-report.html"
    
    exit ${exit_code}
}

# Run main function
main "$@"

