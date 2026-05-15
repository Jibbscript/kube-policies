<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# audit

## Purpose
Asynchronous audit logging library. Buffers `Event` records in a channel and flushes them in batches to a pluggable `Backend` (file, stdout, elasticsearch, webhook). Provides three logging entry points: policy decisions, configuration changes, and generic system events.

## Key Files

| File | Description |
|------|-------------|
| `logger.go` | `Logger`, `Backend` interface, `Event`, `Context`, all backend implementations, lifecycle (`NewLogger`, `Close`, `processEvents`) |
| `logger_test.go` | Unit tests for the logger |

## For AI Agents

### Working In This Directory
- The buffer is a fixed-size channel (`config.BufferSize`). When full, events are **dropped** with a `fmt.Printf` to stderr — accept this loss rather than blocking the admission path. Re-evaluate this only with a written justification and an SLO.
- `processEvents` flushes on either a 100-event batch or the configured `flush_interval` (default 10s). Both paths reset the in-memory slice; do not return early without flushing.
- `createBackend` switches on `config.Backend`. `elasticsearch` and `webhook` backends are stubs — implement them before relying on them in production.
- `FileBackend` hardcodes the log directory to `/var/log/kube-policies` for `MkdirAll`. The actual filename is taken from `config.Config["filename"]` (default `/var/log/kube-policies/audit.log`). Be aware of this divergence if you change one.
- When `config.Enabled` is false, `NewLogger` returns a stub that no-ops; keep this contract so callers can unconditionally invoke `LogDecision`.

### Testing Requirements
- Unit tests in `logger_test.go`. Run via `go test ./pkg/audit/...` or `make test-unit`.

### Common Patterns
- `LogDecision` is the hot path used by `internal/admission`. Keep it allocation-light and non-blocking.
- Background work uses `context.Context` for shutdown; `Close` calls `cancel()` and then closes the backend.

## Dependencies

### Internal
- `internal/config` — `AuditConfig` (legacy coupling — see `pkg/AGENTS.md`)
- `internal/policy` — `PolicyViolation`, `JSONPatch` types embedded in events

### External
- `k8s.io/api/authentication/v1` — `UserInfo`
- `k8s.io/apimachinery/pkg/apis/meta/v1` — `GroupVersionKind`
- `k8s.io/apimachinery/pkg/runtime` — `RawExtension`

<!-- MANUAL: -->
