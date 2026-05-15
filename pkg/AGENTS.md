<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# pkg

## Purpose
Public Go packages safe for import by other modules. Currently houses only the structured logger factory.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `logger/` | Zap-based structured logger factory: production JSON, development console, env-driven (see `logger/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- These packages must remain stable — they form the public API of the module. Breaking changes require a major-version consideration.
- Do not import from `internal/...` here; that defeats the purpose of `pkg/`. The `audit` package previously lived here but was relocated to `internal/audit` because it depended on `internal/config` and `internal/policy`.
- Keep dependencies minimal — only what is strictly required for the public surface.

### Testing Requirements
- Run via `make test-unit`.

### Common Patterns
- Constructor functions named `New*` return concrete pointer types.

## Dependencies

### External
- `go.uber.org/zap`, `go.uber.org/zap/zapcore` — `pkg/logger`

<!-- MANUAL: -->
