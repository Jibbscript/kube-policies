<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# config

## Purpose
Centralized configuration schema, loader, defaults, and validator for both binaries. Reads YAML via Viper with environment-variable overrides under the `KUBE_POLICIES_` prefix. Exposes typed structs for server, policy, audit, metrics, security (TLS/RBAC/encryption/auth), and storage configuration.

## Key Files

| File | Description |
|------|-------------|
| `config.go` | `Config` and nested config structs, `LoadConfig`, `setDefaults`, `validateConfig`, `GetDefaultConfig` |

## For AI Agents

### Working In This Directory
- `LoadConfig` is forgiving: a missing config file is not an error (defaults + env vars fill in). Never change this without updating the deployment story (the chart may rely on running without a mounted config).
- All defaults live in `setDefaults`. New fields require: a struct field with `mapstructure` tag, a default in `setDefaults`, and (for enum-style fields) validation in `validateConfig`.
- `validateConfig` enforces enums: `policy.failure_mode` must be `fail-open` or `fail-closed`; `audit.backend` must be one of `file`, `elasticsearch`, `webhook`, `stdout`; `security.tls.min_version` must be `1.2` or `1.3`. Add to these lists when supporting new values.
- `GetDefaultConfig` is a Go-side mirror of `setDefaults`. Keep them in sync.

### Testing Requirements
- No `_test.go` exists in this package today. New behavior should land with tests; until then, integration tests exercise it indirectly.

### Common Patterns
- Wrap loader errors with `fmt.Errorf("...: %w", err)`.
- Field tags use `mapstructure:"snake_case"` exclusively (Viper's expectation).

## Dependencies

### External
- `github.com/spf13/viper`

<!-- MANUAL: -->
