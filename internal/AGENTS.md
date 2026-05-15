<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# internal

## Purpose
Private application packages — only importable from within this module. Houses the admission controller, configuration loader, Prometheus metrics, OPA-based policy engine, and policy management service.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `admission/` | Validating + mutating admission HTTP handlers, audit + metrics integration (see `admission/AGENTS.md`) |
| `audit/` | Asynchronous audit logger with file/stdout backends and structured drop telemetry (see `audit/AGENTS.md`) |
| `config/` | Viper-based configuration loader, defaults, and validation (see `config/AGENTS.md`) |
| `metrics/` | Prometheus collector with admission, policy, audit, compliance metrics (see `metrics/AGENTS.md`) |
| `policy/` | OPA Rego policy engine: types, evaluation, default policies (see `policy/AGENTS.md`) |
| `policymanager/` | REST handlers for policy/bundle/exception/compliance CRUD and lifecycle (see `policymanager/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Anything under `internal/` is invisible to external consumers — Go's module system enforces this. Use `pkg/` for code that must be importable.
- Cross-package coupling: `admission` depends on `policy` + `audit` + `metrics`; `policymanager` depends on `config` + `policy`; `audit` depends on `config` + `policy`. Avoid creating new cycles.
- Concurrency: shared mutable state (loaded policies, exceptions, etc.) is guarded by `sync.RWMutex` — keep this discipline when adding fields.

### Testing Requirements
- Unit tests live alongside code (`*_test.go`). Several packages already have `controller_test.go`, `collector_test.go`, `engine_test.go`.
- `make test-unit` runs `go test -race -coverprofile=...` against `./internal/...`.

### Common Patterns
- Structs accept dependencies via constructor functions returning `*T` and an error.
- Logging is structured zap with field arguments; no `fmt.Printf` for app code.
- Errors are wrapped with `fmt.Errorf("...: %w", err)`.

## Dependencies

### Internal
- `pkg/logger` — referenced by `cmd/*` for structured logging

### External
- `github.com/open-policy-agent/opa` — used by `policy`
- `github.com/prometheus/client_golang` — used by `metrics`
- `github.com/spf13/viper` — used by `config`
- `github.com/gin-gonic/gin` — used by `admission` and `policymanager`
- `k8s.io/api/admission/v1`, `k8s.io/apimachinery` — admission types

<!-- MANUAL: -->
