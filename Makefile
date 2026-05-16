# Kube-Policies Makefile
# Provides comprehensive build, test, and deployment targets

# Project information
PROJECT_NAME := kube-policies
ORGANIZATION := github.com/Jibbscript
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse HEAD)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Go configuration
GO_VERSION := 1.25
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED ?= 0

# Build configuration
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BUILD_FLAGS := -ldflags="$(LDFLAGS)" -trimpath

# Container configuration
REGISTRY ?= ghcr.io/Jibbscript
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
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
	@# Prime the envtest binary cache so test-integration finds etcd/kube-apiserver.
	setup-envtest use 1.28.0 --bin-dir /tmp/envtest-bins -p path > /dev/null
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
build: build-admission-webhook build-policy-manager $(if $(WITH_UI),build-dashboard,) ## Build all binaries (set WITH_UI=1 to include dashboard)

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
		-t $(ADMISSION_WEBHOOK_IMAGE):$(IMAGE_TAG) .
	@echo "$(GREEN)Admission webhook image built: $(ADMISSION_WEBHOOK_IMAGE):$(IMAGE_TAG)$(NC)"

.PHONY: docker-build-policy-manager
docker-build-policy-manager: ## Build policy manager container image
	@echo "$(BLUE)Building policy manager image...$(NC)"
	docker build -f $(BUILD_DIR)/docker/policy-manager.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(POLICY_MANAGER_IMAGE):$(IMAGE_TAG) .
	@echo "$(GREEN)Policy manager image built: $(POLICY_MANAGER_IMAGE):$(IMAGE_TAG)$(NC)"

.PHONY: docker-push
docker-push: ## Push container images to registry
	@echo "$(BLUE)Pushing container images...$(NC)"
	docker push $(ADMISSION_WEBHOOK_IMAGE):$(IMAGE_TAG)
	docker push $(POLICY_MANAGER_IMAGE):$(IMAGE_TAG)
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
	@# Fail loudly if setup-envtest is missing or cannot fetch binaries — empty
	@# KUBEBUILDER_ASSETS would make envtest fall back to /usr/local/kubebuilder/bin
	@# and produce a confusing "no such file or directory" error mid-run.
	@command -v setup-envtest >/dev/null || { \
		echo "$(YELLOW)setup-envtest not found; run 'make setup' first$(NC)" >&2; exit 1; \
	}
	export KUBEBUILDER_ASSETS=$$(setup-envtest use 1.28.0 --bin-dir /tmp/envtest-bins -p path) && \
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

.PHONY: check-logger-wiring
check-logger-wiring: ## Verify no direct .SetLogger or ctrl-runtime/klog imports outside pkg/logger/
	bash scripts/check-logger-wiring.sh

.PHONY: check
check: lint vet security check-logger-wiring ## Run all quality checks

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

# === Dashboard / Svelte UI targets (M1) ===

WEB_DIR := web
DASHBOARD_IMAGE := $(REGISTRY)/dashboard
DASHBOARD_PORT ?= 8091

.PHONY: ui-deps
ui-deps: ## Install web dependencies (pnpm install)
	@echo "$(BLUE)Installing UI dependencies...$(NC)"
	cd $(WEB_DIR) && pnpm install --frozen-lockfile

.PHONY: ui-dev
ui-dev: ## Run cmd/dashboard on :$(DASHBOARD_PORT) then Vite dev server fg
	@echo "$(BLUE)Starting cmd/dashboard on :$(DASHBOARD_PORT)...$(NC)"
	@mkdir -p $(DIST_DIR)
	WITH_UI=1 $(MAKE) build-dashboard
	$(DIST_DIR)/dashboard-$(GOOS)-$(GOARCH) --port=$(DASHBOARD_PORT) &
	@./scripts/wait-for-healthz.sh http://localhost:$(DASHBOARD_PORT)/healthz 30
	cd $(WEB_DIR) && pnpm dev

.PHONY: ui-build
ui-build: ## Build SPA into web/dist/
	@echo "$(BLUE)Building SPA...$(NC)"
	cd $(WEB_DIR) && pnpm install --frozen-lockfile && pnpm build
	@echo "$(GREEN)SPA built into $(WEB_DIR)/dist/$(NC)"

.PHONY: ui-test
ui-test: ui-test-js ui-test-rego ## Run all UI tests (JS + Rego)

.PHONY: ui-test-js
ui-test-js: ## Run Vitest unit tests
	cd $(WEB_DIR) && pnpm test --run

.PHONY: ui-test-rego
ui-test-rego: ## Boot policy.Engine and assert 4 Playground sample verdicts
	go test -count=1 ./internal/policy/... -run TestBundledDefaults

.PHONY: ui-lint
ui-lint: ## Lint web/ — eslint + svelte-check + prettier --check
	cd $(WEB_DIR) && pnpm lint && pnpm svelte-check && pnpm exec prettier --check src tests

.PHONY: build-dashboard
build-dashboard: ## Build cmd/dashboard binary (requires ui-build first unless NO_UI=1)
	@if [ ! -d "$(WEB_DIR)/dist" ] && [ -z "$(NO_UI)" ]; then \
		echo "$(YELLOW)web/dist not found — running ui-build first$(NC)"; \
		$(MAKE) ui-build; \
	fi
	@# Refresh cmd/dashboard/web_dist from the freshly built SPA so //go:embed
	@# sees current assets. Preserves the .placeholder that keeps the embed
	@# directive valid even when ui-build has never run.
	@if [ -z "$(NO_UI)" ]; then \
		echo "$(BLUE)Syncing SPA assets into cmd/dashboard/web_dist/...$(NC)"; \
		find cmd/dashboard/web_dist -mindepth 1 ! -name .placeholder -exec rm -rf {} +; \
		cp -R $(WEB_DIR)/dist/. cmd/dashboard/web_dist/; \
	fi
	@echo "$(BLUE)Building dashboard binary...$(NC)"
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		$(BUILD_FLAGS) \
		$(if $(NO_UI),-tags=no_ui,) \
		-o $(DIST_DIR)/dashboard-$(GOOS)-$(GOARCH) \
		./cmd/dashboard
	@echo "$(GREEN)Dashboard built: $(DIST_DIR)/dashboard-$(GOOS)-$(GOARCH)$(NC)"

.PHONY: docker-dashboard
docker-dashboard: build-dashboard ## Build dashboard Docker image
	@echo "$(BLUE)Building dashboard image...$(NC)"
	docker build -f $(BUILD_DIR)/Dockerfile.dashboard \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(DASHBOARD_IMAGE):$(IMAGE_TAG) .
	@echo "$(GREEN)Dashboard image built: $(DASHBOARD_IMAGE):$(IMAGE_TAG)$(NC)"

DEMO_CLUSTER := kube-policies-demo
DEMO_PORTFORWARD_PIDFILE := /tmp/kube-policies-demo-portforward.pid

# Demo-only image namespace. Docker repository names must be all-lowercase,
# so we override the default REGISTRY (which uses the capital-J GitHub login)
# for local kind builds. Pushing to GHCR still works because GHCR maps
# usernames case-insensitively.
DEMO_REGISTRY  := ghcr.io/jibbscript
DEMO_AW_IMAGE  := $(DEMO_REGISTRY)/admission-webhook
DEMO_PM_IMAGE  := $(DEMO_REGISTRY)/policy-manager
DEMO_DB_IMAGE  := $(DEMO_REGISTRY)/dashboard

.PHONY: demo-up
demo-up: ## Boot kind + build/load 3 images + gen TLS cert + helm install + port-forward :8090
	@command -v kind    >/dev/null 2>&1 || { echo "$(RED)kind not installed. Install: brew install kind$(NC)"; exit 1; }
	@command -v docker  >/dev/null 2>&1 || { echo "$(RED)docker not installed$(NC)"; exit 1; }
	@command -v helm    >/dev/null 2>&1 || { echo "$(RED)helm not installed$(NC)"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "$(RED)kubectl not installed$(NC)"; exit 1; }
	@command -v openssl >/dev/null 2>&1 || { echo "$(RED)openssl not installed$(NC)"; exit 1; }
	@echo "$(BLUE)[1/6] Ensuring kind cluster '$(DEMO_CLUSTER)' exists...$(NC)"
	@kind get clusters 2>/dev/null | grep -qx $(DEMO_CLUSTER) || kind create cluster --name $(DEMO_CLUSTER) --wait 60s
	@kubectl config use-context kind-$(DEMO_CLUSTER) >/dev/null
	@echo "$(BLUE)[2/6] Building docker images (admission-webhook, policy-manager, dashboard)...$(NC)"
	@REGISTRY=$(DEMO_REGISTRY) $(MAKE) docker-build
	@REGISTRY=$(DEMO_REGISTRY) $(MAKE) docker-dashboard
	@echo "$(BLUE)[3/6] Loading images into kind cluster $(DEMO_CLUSTER)...$(NC)"
	@kind load docker-image $(DEMO_AW_IMAGE):$(IMAGE_TAG) --name $(DEMO_CLUSTER)
	@kind load docker-image $(DEMO_PM_IMAGE):$(IMAGE_TAG) --name $(DEMO_CLUSTER)
	@kind load docker-image $(DEMO_DB_IMAGE):$(IMAGE_TAG) --name $(DEMO_CLUSTER)
	@echo "$(BLUE)[4/6] Generating admission-webhook TLS Secret in namespace $(NAMESPACE)...$(NC)"
	@RELEASE_NAME=kube-policies SERVICE_NAME=kube-policies-admission-webhook \
		bash $(SCRIPTS_DIR)/gen-webhook-cert.sh $(NAMESPACE)
	@echo "$(BLUE)[5/6] Helm install kube-policies (single-replica webhook, dashboard enabled)...$(NC)"
	@helm upgrade --install kube-policies $(CHARTS_DIR)/kube-policies \
		--namespace $(NAMESPACE) --create-namespace \
		--set dashboard.enabled=true \
		--set dashboard.allowWrites=false \
		--set dashboard.image.repository=$(DEMO_DB_IMAGE) \
		--set dashboard.image.tag=$(IMAGE_TAG) \
		--set dashboard.image.pullPolicy=IfNotPresent \
		--set admissionWebhook.replicaCount=1 \
		--set admissionWebhook.image.registry=$(DEMO_REGISTRY) \
		--set admissionWebhook.image.repository=admission-webhook \
		--set admissionWebhook.image.tag=$(IMAGE_TAG) \
		--set admissionWebhook.image.pullPolicy=IfNotPresent \
		--set policyManager.image.registry=$(DEMO_REGISTRY) \
		--set policyManager.image.repository=policy-manager \
		--set policyManager.image.tag=$(IMAGE_TAG) \
		--set policyManager.image.pullPolicy=IfNotPresent \
		--wait --timeout=5m
	@echo "$(BLUE)[6/6] Port-forwarding :8090 → dashboard service (PID file: $(DEMO_PORTFORWARD_PIDFILE))...$(NC)"
	@if [ -f $(DEMO_PORTFORWARD_PIDFILE) ]; then kill $$(cat $(DEMO_PORTFORWARD_PIDFILE)) 2>/dev/null || true; fi
	@nohup kubectl -n $(NAMESPACE) port-forward svc/kube-policies-dashboard 8090:8090 >/tmp/kube-policies-pf.log 2>&1 &
	@echo $$! > $(DEMO_PORTFORWARD_PIDFILE)
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if curl -sf -o /dev/null http://localhost:8090/healthz; then \
			echo "$(GREEN)✓ Demo up. Open http://localhost:8090$(NC)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "$(YELLOW)port-forward not yet responsive on :8090 after 10s — see /tmp/kube-policies-pf.log$(NC)"; exit 1

.PHONY: demo-down
demo-down: ## Tear down demo kind cluster + stop port-forward
	@if [ -f $(DEMO_PORTFORWARD_PIDFILE) ]; then \
		kill $$(cat $(DEMO_PORTFORWARD_PIDFILE)) 2>/dev/null || true; \
		rm -f $(DEMO_PORTFORWARD_PIDFILE); \
	fi
	@kind delete cluster --name $(DEMO_CLUSTER) || true

# Default target
.DEFAULT_GOAL := help

