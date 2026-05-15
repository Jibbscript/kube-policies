<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# pkg

## Purpose
Public Go packages safe for import by other modules. Provides the structured logger and the audit logging framework with pluggable backends.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `audit/` | Audit logger with file/stdout/elasticsearch/webhook backends and async event buffering (see `audit/AGENTS.md`) |
| `logger/` | Zap-based structured logger factory: production JSON, development console, env-driven (see `logger/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- These packages must remain stable — they form the public API of the module. Breaking changes require a major-version consideration.
- Do not import from `internal/...` here; that defeats the purpose of `pkg/`. Note: `pkg/audit` currently imports `internal/config` and `internal/policy` for type aliases — that coupling predates strict separation and any new code should avoid widening it.
- Keep dependencies minimal — only what is strictly required for the public surface.

### Testing Requirements
- Each package has unit tests (`logger_test.go` is implicit via existing tests; `audit/logger_test.go` exists).
- Run via `make test-unit`.

### Common Patterns
- Constructor functions named `New*` return concrete pointer types.
- Async work uses `context.Context` for cancellation and a buffered channel for event passing.

## Dependencies

### External
- `go.uber.org/zap`, `go.uber.org/zap/zapcore` — `pkg/logger`
- `k8s.io/api/authentication/v1`, `k8s.io/apimachinery` — audit event types

<!-- MANUAL: -->
