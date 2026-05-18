<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# kube-policies

## Purpose
Enterprise-grade Kubernetes policy enforcement system. Provides real-time admission control, policy lifecycle management, audit logging, and compliance reporting via two Go services (admission-webhook and policy-manager) backed by an OPA/Rego policy engine. Distributed via Helm chart and Kubernetes manifests; observed via Prometheus, Grafana, and Alertmanager.

## Key Files

| File | Description |
|------|-------------|
| `go.mod` | Go module definition (module `github.com/Jibbscript/kube-policies`, Go 1.25) |
| `go.sum` | Pinned dependency checksums |
| `Makefile` | Canonical entry point for build, test, lint, docker, helm, deploy targets |
| `.golangci.yml` | golangci-lint configuration |
| `.gitignore` | Git ignore rules |
| `LICENSE` | Apache License 2.0 |
| `README.md` | Project overview, quickstart, architecture summary |
| `CONTRIBUTING.md` | Contribution workflow and standards |
| `DEPLOYMENT.md` | Production deployment guide |
| `TESTING.md` | Testing strategy and execution guide |
| `PROJECT_SUMMARY.md` | High-level architecture and feature summary |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `cmd/` | Service entry points: `admission-webhook` and `policy-manager` (see `cmd/AGENTS.md`) |
| `internal/` | Private application packages: admission, audit, config, metrics, policy, policymanager (see `internal/AGENTS.md`) |
| `pkg/` | Public packages safe for import: logger (see `pkg/AGENTS.md`) |
| `charts/` | Helm chart for deploying both services (see `charts/AGENTS.md`) |
| `deployments/` | Raw Kubernetes manifests, CRDs, and monitoring stack (see `deployments/AGENTS.md`) |
| `monitoring/` | Prometheus, Grafana dashboards, Alertmanager configs (see `monitoring/AGENTS.md`) |
| `examples/` | Sample Policy and PolicyException manifests (see `examples/AGENTS.md`) |
| `demo/` | 60-second Remotion demo video pipeline (capture + render + verify) for the README (see `demo/AGENTS.md`) |
| `build/` | Dockerfiles for the two service images (see `build/AGENTS.md`) |
| `configs/` | Environment-specific runtime configs (see `configs/AGENTS.md`) |
| `scripts/` | Test orchestration shell scripts (see `scripts/AGENTS.md`) |
| `test/` | Integration, e2e, and shared test infrastructure (see `test/AGENTS.md`) |
| `.github/` | GitHub Actions workflows (`ci.yml`, `release.yml`) |

## For AI Agents

### Working In This Directory
- Module path is `github.com/Jibbscript/kube-policies` — use this prefix for all internal imports.
- Two binaries are produced from `cmd/`: `admission-webhook` (TLS webhook on `:8443`) and `policy-manager` (REST API on `:8080`). Both expose Prometheus metrics on a separate port.
- All build, lint, and test commands flow through `make`. Do not invent new commands; extend the Makefile if needed.
- Failure mode for the policy engine defaults to `fail-closed` — any change to fail-open semantics requires deliberate policy review.
- TLS minimum version is 1.3 (set in code and config); do not downgrade.

### Testing Requirements
- `make test` runs unit + integration. `make test-unit` covers `./internal/... ./pkg/...`. `make test-integration` exercises `./test/integration/...` against envtest.
- `make test-e2e` runs Ginkgo-based end-to-end tests in `test/e2e/`.
- Cluster-specific suites: `make test-kind`, `make test-k3s`, `make test-eks`, `make test-vanilla` (some require sudo).
- `make lint` runs golangci-lint with the repo `.golangci.yml`.

### Common Patterns
- Structured logging via `pkg/logger` (zap, JSON in production, console in development).
- Configuration loaded by `internal/config` using Viper from YAML + `KUBE_POLICIES_*` env vars.
- Prometheus metrics live in `internal/metrics`; new counters/histograms register there.
- HTTP servers use Gin in release mode with `/healthz`, `/readyz`, and dedicated metrics endpoints.

## Dependencies

### External
- `github.com/open-policy-agent/opa` — Rego policy evaluation engine
- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`, `sigs.k8s.io/controller-runtime` — Kubernetes API clients and admission types
- `github.com/gin-gonic/gin` — HTTP framework
- `github.com/prometheus/client_golang` — Prometheus instrumentation
- `go.uber.org/zap` — structured logging
- `github.com/spf13/viper` — configuration loading
- `github.com/onsi/ginkgo/v2`, `github.com/onsi/gomega`, `github.com/stretchr/testify` — test frameworks
- `github.com/google/uuid` — ID generation

<!-- MANUAL: Custom project notes can be added below -->
