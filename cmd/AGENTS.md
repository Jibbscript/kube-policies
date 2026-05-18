<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# cmd

## Purpose
Entry-point packages for the binaries produced by this repo. Each subdirectory contains a `package main` with a `main.go` that wires configuration, logging, metrics, and the relevant service into long-running HTTP servers with graceful shutdown.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `admission-webhook/` | TLS validating + mutating admission webhook server (see `admission-webhook/AGENTS.md`) |
| `policy-manager/` | REST API server for policy/exception/compliance management (see `policy-manager/AGENTS.md`) |
| `dashboard/` | Dashboard BFF and embedded SPA host (see `dashboard/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Each `main.go` should stay thin — wiring only. Business logic belongs in `internal/` packages.
- Both binaries register signal handlers for `SIGINT`/`SIGTERM` and perform a 30s graceful shutdown; preserve this pattern.
- Configuration is loaded from `--config` (default `/etc/config/config.yaml`) via `internal/config.LoadConfig`.
- Metrics live on a separate port from the main server; do not collapse them.

### Testing Requirements
- `cmd/dashboard` and `cmd/admission-webhook` have package-local unit tests and are included in `make test-unit`. Cluster behavior still comes from `test/e2e` and `test/integration`.

### Common Patterns
- Use `gin.SetMode(gin.ReleaseMode)` and `gin.New()` (without default middleware) plus `gin.Recovery()`.
- Health endpoints: `GET /healthz` and `GET /readyz` returning JSON status.
- Prometheus handler is mounted on `/metrics` of the dedicated metrics server.

## Dependencies

### Internal
- `internal/config` — configuration loading
- `internal/metrics` — Prometheus collector
- `internal/policy`, `internal/admission` — admission-webhook only
- `internal/policymanager` — policy-manager only
- `internal/audit` — audit-webhook only
- `pkg/logger`

### External
- `github.com/gin-gonic/gin` — HTTP routing
- `github.com/prometheus/client_golang/prometheus/promhttp` — `/metrics` handler
- `go.uber.org/zap` — logging

<!-- MANUAL: -->
