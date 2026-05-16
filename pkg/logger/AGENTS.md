<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# logger

## Purpose
Factory functions for zap-based structured loggers. Provides production (JSON, ISO8601 timestamps), development (console, color levels), and environment-driven variants. Every logger is decorated with a `service` field for downstream filtering.

## Key Files

| File | Description |
|------|-------------|
| `logger.go` | `NewLogger`, `NewDevelopmentLogger`, `NewLoggerFromEnv` constructors |

## For AI Agents

### Working In This Directory
- `NewLogger(service, level)` accepts levels `debug`, `info`, `warn`, `error`; anything else falls through to `info`. Keep this list aligned with operational expectations.
- The production encoder uses key names `timestamp`, `level`, `logger`, `caller`, `message`, `stacktrace`. Log-aggregation queries (e.g. in Grafana/Loki) depend on these — treat changes as breaking.
- `NewLoggerFromEnv` reads `LOG_LEVEL` and `ENVIRONMENT` (`development` or `dev` triggers the development logger). This is the path most appropriate for non-flag-driven processes.
- On configuration build failure the constructor falls back to `zap.NewNop()` — silent on purpose so logger init never panics, but this means a misconfiguration will not surface as an error. Add tests if extending the configuration.

### Testing Requirements
- No `_test.go` exists yet; safe to add unit tests asserting fields, levels, and encoding.

### Common Patterns
- Always `defer log.Sync()` after construction in `main`.
- Add per-call structured fields with `zap.String`, `zap.Int`, `zap.Error`, etc., never with `fmt.Sprintf` into the message.

## Dependencies

### External
- `go.uber.org/zap`
- `go.uber.org/zap/zapcore`

## Controller-runtime / klog bridge

`SetControllerRuntimeLogger(*zap.Logger)` wires the global `sigs.k8s.io/controller-runtime/pkg/log` and `k8s.io/klog/v2` loggers to route through the supplied zap logger via `go-logr/zapr`. Call once from each binary's `main()` after constructing the zap logger and before any controller-runtime / client-go code path runs.

### Idempotency contract
- Same `*zap.Logger` pointer on repeat: silent no-op.
- Different `*zap.Logger` pointer on repeat: panic, naming both call sites. (Loud-at-boot for the genuine misuse case.)

### V-level mapping (controller-runtime / klog -> zap)
| `LOG_LEVEL` | What you see from controller-runtime / klog |
|-------------|----------------------------------------------|
| `info` (default) | INFO from reconcilers, WARN/ERROR from reconcile failures, leader-election transitions. No V(1+) reflector chatter. |
| `debug` | Above + V(1)+ chatter: watch event details, list-and-watch lifecycle, lease renewals every ~10s. |
| `warn`/`error` | Suppresses INFO from controller startup; ERROR still appears. |

### Additive zapr JSON keys
zapr decorates controller-runtime-originated log lines with additive structured fields: `controller`, `reconciler group`, `reconciler kind`, `name`, `namespace`. The base schema (`timestamp`, `level`, `caller`, `message`, `stacktrace`, `service`) is preserved.

### main() pattern
All three binaries (`cmd/admission-webhook`, `cmd/policy-manager`, `cmd/dashboard`) use this pattern:
```go
log := logger.NewLoggerFromEnv("svc-name")
logger.SetControllerRuntimeLogger(log)
defer func() { _ = log.Sync() }()
```
Note: `NewLoggerFromEnv` replaced earlier hard-coded `NewLogger("svc", "info")` calls so the `LOG_LEVEL` env in pod specs actually takes effect.

<!-- MANUAL: -->
