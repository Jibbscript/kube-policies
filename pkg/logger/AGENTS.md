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

<!-- MANUAL: -->
