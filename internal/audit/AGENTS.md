<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# audit

## Purpose
Asynchronous audit logging library. Buffers `Event` records in a channel and flushes them in batches to a `Backend` (`file` or `stdout`). Provides three logging entry points: policy decisions, configuration changes, and generic system events. Drops on a full buffer are observable via the supplied `Metrics` interface and a structured zap warning.

## Key Files

| File | Description |
|------|-------------|
| `logger.go` | `Logger`, `Backend` interface, `Event`, `Context`, `Metrics` interface + `NopMetrics`, `Option` (`WithLogger`, `WithMetrics`), file/stdout backends, lifecycle (`NewLogger`, `Close`, `processEvents`) |
| `logger_test.go` | Smoke unit tests for the logger |
| `logger_behavior_test.go` | Behavioral test that captures stdout and asserts a `LogDecision` event is actually flushed within the configured interval |

## For AI Agents

### Working In This Directory
- Construction is `audit.NewLogger(cfg, audit.WithLogger(z), audit.WithMetrics(m))`. `WithLogger` and `WithMetrics` accept nil and fall back to no-op implementations, so callers may pass either or both. New production callers MUST pass both.
- The buffer is a fixed-size channel (`config.BufferSize`). When full, `enqueue` records a `metrics.IncAuditEvents(eventType, "dropped")` and a structured `Warn`. Do not regress to silent drops.
- `processEvents` flushes on either a 100-event batch or the configured `flush_interval` (default 10s). On every tick it also publishes the current buffer depth via `Metrics.SetAuditBufferSize`.
- `createBackend` only supports `file` and `stdout`. The Elasticsearch and webhook backends were removed (they were stubs that silently dropped events). Re-add them only with real implementations and corresponding `internal/config.validateConfig` updates.
- `FileBackend` creates `filepath.Dir(filename)` for `MkdirAll`, so the filename in `config.Config["filename"]` is fully honored.
- When `config.Enabled` is false, `NewLogger` returns a stub that no-ops; keep this contract so callers can unconditionally invoke `LogDecision`.

### Testing Requirements
- Run via `go test ./internal/audit/...` or `make test-unit`.
- Behavioral tests rely on capturing `os.Stdout`; do not change the stdout backend to write elsewhere without updating the test.

### Common Patterns
- `LogDecision` is the hot path used by `internal/admission`. Keep it allocation-light and non-blocking.
- Background work uses `context.Context` for shutdown; `Close` calls `cancel()` and then closes the backend.

## Dependencies

### Internal
- `internal/config` — `AuditConfig`
- `internal/policy` — `PolicyViolation`, `JSONPatch` types embedded in events

### External
- `go.uber.org/zap` — structured diagnostic logging
- `k8s.io/api/authentication/v1` — `UserInfo`
- `k8s.io/apimachinery/pkg/apis/meta/v1` — `GroupVersionKind`
- `k8s.io/apimachinery/pkg/runtime` — `RawExtension`

<!-- MANUAL: -->
