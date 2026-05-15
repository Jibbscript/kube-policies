<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# admission-webhook

## Purpose
`package main` for the validating + mutating admission webhook. Wires logger, config, metrics, audit logger, policy engine, and admission controller into a TLS HTTP server with a separate plain-HTTP metrics server. Both are torn down via signal-driven 30-second graceful shutdown.

## Key Files

| File | Description |
|------|-------------|
| `main.go` | Flag parsing, dependency wiring, server setup (TLS 1.3 webhook + metrics), and shutdown sequence |

## For AI Agents

### Working In This Directory
- Flags: `--cert-path` (`/etc/certs/tls.crt`), `--key-path` (`/etc/certs/tls.key`), `--port` (8443), `--metrics-port` (9090), `--config` (`/etc/config/config.yaml`).
- Webhook routes are `POST /validate` and `POST /mutate` on the TLS server; `GET /healthz` and `GET /readyz` are exposed on the same server. The metrics server exposes `GET /metrics` and `GET /healthz`.
- TLS config pins `MinVersion: tls.VersionTLS13` and a fixed cipher suite list — preserve this when modifying.
- All HTTP handler logic belongs in `internal/admission`; this file only registers handlers.

### Testing Requirements
- No tests live here; behavior is covered by `test/integration/admission_webhook_test.go` and `test/e2e/`.

### Common Patterns
- Build the controller via `admission.NewController(policyEngine, auditLogger, metricsCollector, logger)` and pass its handlers to Gin routes.
- Use `gin.SetMode(gin.ReleaseMode)` and `gin.New()` + `gin.Recovery()` (no default middleware).

## Dependencies

### Internal
- `internal/admission` — handler implementation
- `internal/audit` — audit logger
- `internal/config` — config loader
- `internal/metrics` — Prometheus collector
- `internal/policy` — engine
- `pkg/logger` — zap logger factory

### External
- `github.com/gin-gonic/gin`
- `github.com/prometheus/client_golang/prometheus/promhttp`
- `go.uber.org/zap`

<!-- MANUAL: -->
