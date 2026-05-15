<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# policy-manager

## Purpose
`package main` for the policy management REST API. Exposes versioned `/api/v1` endpoints for policy CRUD, validation, testing, deployment, status, bundles, exceptions, and compliance reporting. Runs background sync and exception-expiry monitoring goroutines via `policymanager.Manager.Start`.

## Key Files

| File | Description |
|------|-------------|
| `main.go` | Flag parsing, dependency wiring, API server + metrics server setup, route registration, graceful shutdown |

## For AI Agents

### Working In This Directory
- Flags: `--port` (8080, plain HTTP), `--metrics-port` (9091), `--config` (`/etc/config/config.yaml`). The policy manager API is intentionally non-TLS at the pod level — TLS termination is expected at an ingress or service mesh.
- A permissive CORS middleware adds `Access-Control-Allow-*` for any origin and short-circuits `OPTIONS` requests; tighten this if exposing the API publicly.
- All `/api/v1/*` route handlers are methods on `*policymanager.Manager` — add new routes alongside the existing `policies`, `bundles`, `exceptions`, `compliance` groups.
- Background work is started via `go policyManager.Start(ctx)`; cancel via `cancel()` before invoking server `Shutdown`.

### Testing Requirements
- Behavior covered by `test/integration/policy_manager_test.go`.

## Dependencies

### Internal
- `internal/config`, `internal/metrics`, `internal/policymanager`
- `pkg/logger`

### External
- `github.com/gin-gonic/gin`
- `github.com/prometheus/client_golang/prometheus/promhttp`
- `go.uber.org/zap`

<!-- MANUAL: -->
