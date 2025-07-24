# Kube-Policies Makefile
# Provides comprehensive build, test, and deployment targets

# Project information
PROJECT_NAME := kube-policies
ORGANIZATION := github.com/kube-policies
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse HEAD)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Go configuration
GO_VERSION := 1.21
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED ?= 0

# Build configuration
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BUILD_FLAGS := -ldflags="$(LDFLAGS)" -trimpath

# Container configuration
REGISTRY ?= ghcr.io/kube-policies
ADMISSION_WEBHOOK_IMAGE := $(REGISTRY)/admission-webhook
POLICY_MANAGER_IMAGE := $(REGISTRY)/policy-manager
IMAGE_TAG ?= $(VERSION)

# Kubernetes configuration
NAMESPACE ?= kube-policies-system
KUBECONFIG ?= ~/.kube/config

# Test configuration
TEST_CLUSTERS ?= kind,k3s
TEST_PARALLEL ?= false
TEST_CLEANUP ?= true
TEST_COVERAGE ?= true
TEST_PERFORMANCE ?= false

# Directories
BUILD_DIR := build
DIST_DIR := dist
CHARTS_DIR := charts
SCRIPTS_DIR := scripts

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

.PHONY: help
help: ## Display this help message
	@echo "$(BLUE)Kube-Policies Makefile$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
.PHONY: setup
setup: ## Set up development environment
	@echo "$(BLUE)Setting up development environment...$(NC)"
	go mod download
	go install github.com/onsi/ginkgo/v2/ginkgo@latest
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "$(GREEN)Development environment ready$(NC)"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -rf $(DIST_DIR)
	rm -rf $(BUILD_DIR)/bin
	rm -rf test-results
	rm -f coverage*.out coverage*.html
	@echo "$(GREEN)Clean completed$(NC)"

# Build targets
.PHONY: build
build: build-admission-webhook build-policy-manager ## Build all binaries

.PHONY: build-admission-webhook
build-admission-webhook: ## Build admission webhook binary
	@echo "$(BLUE)Building admission webhook...$(NC)"
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		$(BUILD_FLAGS) \
		-o $(DIST_DIR)/admission-webhook-$(GOOS)-$(GOARCH) \
		./cmd/admission-webhook
	@echo "$(GREEN)Admission webhook built: $(DIST_DIR)/admission-webhook-$(GOOS)-$(GOARCH)$(NC)"

.PHONY: build-policy-manager
build-policy-manager: ## Build policy manager binary
	@echo "$(BLUE)Building policy manager...$(NC)"
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		$(BUILD_FLAGS) \
		-o $(DIST_DIR)/policy-manager-$(GOOS)-$(GOARCH) \
		./cmd/policy-manager
	@echo "$(GREEN)Policy manager built: $(DIST_DIR)/policy-manager-$(GOOS)-$(GOARCH)$(NC)"

.PHONY: build-all-platforms
build-all-platforms: ## Build binaries for all platforms
	@echo "$(BLUE)Building for all platforms...$(NC)"
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ] && [ "$$arch" = "arm64" ]; then \
				continue; \
			fi; \
			echo "Building for $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch $(MAKE) build; \
		done; \
	done
	@echo "$(GREEN)Multi-platform build completed$(NC)"

# Container targets
.PHONY: docker-build
docker-build: docker-build-admission-webhook docker-build-policy-manager ## Build all container images

.PHONY: docker-build-admission-webhook
docker-build-admission-webhook: ## Build admission webhook container image
	@echo "$(BLUE)Building admission webhook image...$(NC)"
	docker build -f $(BUILD_DIR)/docker/admission-webhook.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(ADMISSION_WEBHOOK_IMAGE):$(IMAGE_TAG) \
		-t $(ADMISSION_WEBHOOK_IMAGE):latest .
	@echo "$(GREEN)Admission webhook image built: $(ADMISSION_WEBHOOK_IMAGE):$(IMAGE_TAG)$(NC)"

.PHONY: docker-build-policy-manager
docker-build-policy-manager: ## Build policy manager container image
	@echo "$(BLUE)Building policy manager image...$(NC)"
	docker build -f $(BUILD_DIR)/docker/policy-manager.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(POLICY_MANAGER_IMAGE):$(IMAGE_TAG) \
		-t $(POLICY_MANAGER_IMAGE):latest .
	@echo "$(GREEN)Policy manager image built: $(POLICY_MANAGER_IMAGE):$(IMAGE_TAG)$(NC)"

.PHONY: docker-push
docker-push: ## Push container images to registry
	@echo "$(BLUE)Pushing container images...$(NC)"
	docker push $(ADMISSION_WEBHOOK_IMAGE):$(IMAGE_TAG)
	docker push $(ADMISSION_WEBHOOK_IMAGE):latest
	docker push $(POLICY_MANAGER_IMAGE):$(IMAGE_TAG)
	docker push $(POLICY_MANAGER_IMAGE):latest
	@echo "$(GREEN)Container images pushed$(NC)"

# Testing targets
.PHONY: test
test: test-unit test-integration ## Run unit and integration tests

.PHONY: test-unit
test-unit: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	go test -v -race -coverprofile=coverage-unit.out -covermode=atomic ./internal/... ./pkg/...
	@if [ "$(TEST_COVERAGE)" = "true" ]; then \
		go tool cover -html=coverage-unit.out -o coverage-unit.html; \
		echo "$(GREEN)Unit test coverage report: coverage-unit.html$(NC)"; \
	fi

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(NC)"
	export KUBEBUILDER_ASSETS=$$(setup-envtest use 1.28.0 --bin-dir /tmp/envtest-bins -p path 2>/dev/null || echo ""); \
	go test -v -race -coverprofile=coverage-integration.out ./test/integration/...
	@if [ "$(TEST_COVERAGE)" = "true" ]; then \
		go tool cover -html=coverage-integration.out -o coverage-integration.html; \
		echo "$(GREEN)Integration test coverage report: coverage-integration.html$(NC)"; \
	fi

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "$(BLUE)Running E2E tests...$(NC)"
	go test -v ./test/e2e/... -ginkgo.v -ginkgo.progress

.PHONY: test-kind
test-kind: ## Run tests on Kind cluster
	@echo "$(BLUE)Running Kind cluster tests...$(NC)"
	$(SCRIPTS_DIR)/test/test-kind.sh

.PHONY: test-k3s
test-k3s: ## Run tests on k3s cluster (requires sudo)
	@echo "$(BLUE)Running k3s cluster tests...$(NC)"
	sudo $(SCRIPTS_DIR)/test/test-k3s.sh

.PHONY: test-eks
test-eks: ## Run tests on AWS EKS cluster
	@echo "$(BLUE)Running EKS cluster tests...$(NC)"
	$(SCRIPTS_DIR)/test/test-eks.sh

.PHONY: test-vanilla
test-vanilla: ## Run tests on vanilla Kubernetes (requires sudo)
	@echo "$(BLUE)Running vanilla Kubernetes tests...$(NC)"
	sudo $(SCRIPTS_DIR)/test/test-vanilla.sh

.PHONY: test-all
test-all: ## Run comprehensive test suite
	@echo "$(BLUE)Running comprehensive test suite...$(NC)"
	CLUSTERS=$(TEST_CLUSTERS) \
	PARALLEL=$(TEST_PARALLEL) \
	CLEANUP=$(TEST_CLEANUP) \
	COVERAGE=$(TEST_COVERAGE) \
	PERFORMANCE=$(TEST_PERFORMANCE) \
	$(SCRIPTS_DIR)/test/run-all-tests.sh

.PHONY: test-performance
test-performance: ## Run performance tests
	@echo "$(BLUE)Running performance tests...$(NC)"
	go test -bench=. -benchmem ./internal/... ./pkg/... > benchmark-results.txt
	@echo "$(GREEN)Performance test results: benchmark-results.txt$(NC)"

# Quality targets
.PHONY: lint
lint: ## Run linters
	@echo "$(BLUE)Running linters...$(NC)"
	golangci-lint run --timeout=5m
	@echo "$(GREEN)Linting completed$(NC)"

.PHONY: fmt
fmt: ## Format code
	@echo "$(BLUE)Formatting code...$(NC)"
	go fmt ./...
	goimports -w -local github.com/kube-policies .
	@echo "$(GREEN)Code formatted$(NC)"

.PHONY: vet
vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(NC)"
	go vet ./...
	@echo "$(GREEN)Vet completed$(NC)"

.PHONY: security
security: ## Run security scans
	@echo "$(BLUE)Running security scans...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "$(YELLOW)gosec not installed, skipping security scan$(NC)"; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "$(YELLOW)govulncheck not installed, skipping vulnerability check$(NC)"; \
	fi

.PHONY: check
check: lint vet security ## Run all quality checks

# Helm targets
.PHONY: helm-lint
helm-lint: ## Lint Helm charts
	@echo "$(BLUE)Linting Helm charts...$(NC)"
	helm lint $(CHARTS_DIR)/kube-policies
	@echo "$(GREEN)Helm chart linting completed$(NC)"

.PHONY: helm-template
helm-template: ## Generate Helm templates
	@echo "$(BLUE)Generating Helm templates...$(NC)"
	helm template kube-policies $(CHARTS_DIR)/kube-policies > helm-template-output.yaml
	@echo "$(GREEN)Helm templates generated: helm-template-output.yaml$(NC)"

.PHONY: helm-package
helm-package: ## Package Helm chart
	@echo "$(BLUE)Packaging Helm chart...$(NC)"
	mkdir -p $(DIST_DIR)
	helm package $(CHARTS_DIR)/kube-policies --destination $(DIST_DIR)
	@echo "$(GREEN)Helm chart packaged in $(DIST_DIR)$(NC)"

# Deployment targets
.PHONY: deploy
deploy: ## Deploy to Kubernetes cluster
	@echo "$(BLUE)Deploying to Kubernetes...$(NC)"
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f deployments/kubernetes/crds/
	helm upgrade --install kube-policies $(CHARTS_DIR)/kube-policies \
		--namespace $(NAMESPACE) \
		--set admissionWebhook.image.repository=$(ADMISSION_WEBHOOK_IMAGE) \
		--set admissionWebhook.image.tag=$(IMAGE_TAG) \
		--set policyManager.image.repository=$(POLICY_MANAGER_IMAGE) \
		--set policyManager.image.tag=$(IMAGE_TAG) \
		--wait
	@echo "$(GREEN)Deployment completed$(NC)"

.PHONY: undeploy
undeploy: ## Remove deployment from Kubernetes cluster
	@echo "$(BLUE)Removing deployment...$(NC)"
	helm uninstall kube-policies --namespace $(NAMESPACE) || true
	kubectl delete -f deployments/kubernetes/crds/ || true
	kubectl delete namespace $(NAMESPACE) || true
	@echo "$(GREEN)Undeployment completed$(NC)"

.PHONY: deploy-monitoring
deploy-monitoring: ## Deploy monitoring stack
	@echo "$(BLUE)Deploying monitoring stack...$(NC)"
	kubectl apply -f deployments/kubernetes/monitoring/
	@echo "$(GREEN)Monitoring stack deployed$(NC)"

# Development workflow targets
.PHONY: dev-setup
dev-setup: setup ## Set up development environment with Kind cluster
	@echo "$(BLUE)Setting up development environment with Kind...$(NC)"
	$(SCRIPTS_DIR)/test/test-kind.sh
	@echo "$(GREEN)Development environment ready$(NC)"

.PHONY: dev-deploy
dev-deploy: docker-build deploy ## Build and deploy for development
	@echo "$(GREEN)Development deployment completed$(NC)"

.PHONY: dev-test
dev-test: test-unit test-integration test-e2e ## Run development tests
	@echo "$(GREEN)Development testing completed$(NC)"

# Release targets
.PHONY: release-build
release-build: clean build-all-platforms docker-build helm-package ## Build release artifacts
	@echo "$(BLUE)Building release artifacts...$(NC)"
	@cd $(DIST_DIR) && sha256sum * > checksums.txt
	@echo "$(GREEN)Release artifacts built$(NC)"

.PHONY: release-test
release-test: test-all ## Run comprehensive tests for release
	@echo "$(GREEN)Release testing completed$(NC)"

.PHONY: release
release: release-build release-test ## Create a release
	@echo "$(GREEN)Release ready$(NC)"

# Utility targets
.PHONY: version
version: ## Display version information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"
	@echo "Go Version: $(shell go version)"

.PHONY: deps
deps: ## Display dependency information
	@echo "$(BLUE)Go module dependencies:$(NC)"
	go list -m all

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "$(BLUE)Updating dependencies...$(NC)"
	go get -u ./...
	go mod tidy
	@echo "$(GREEN)Dependencies updated$(NC)"

.PHONY: generate
generate: ## Run go generate
	@echo "$(BLUE)Running go generate...$(NC)"
	go generate ./...
	@echo "$(GREEN)Code generation completed$(NC)"

# Documentation targets
.PHONY: docs
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Starting godoc server on http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "$(YELLOW)godoc not installed$(NC)"; \
	fi

# Default target
.DEFAULT_GOAL := help

