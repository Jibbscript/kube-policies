<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# configs

## Purpose
Container directory for environment-specific YAML configurations consumed by both binaries via `--config /etc/config/config.yaml`. Schema is defined by `internal/config.Config`. Per-environment overlays should be added as siblings (e.g. `local.yaml`, `production.yaml`) when needed.

## For AI Agents

### Working In This Directory
- New config files must validate against `internal/config.validateConfig` — particularly `policy.failure_mode` ∈ {`fail-open`, `fail-closed`}, `audit.backend` ∈ {`file`, `stdout`, `elasticsearch`, `webhook`}, and `security.tls.min_version` ∈ {`1.2`, `1.3`}.
- All config keys are also overridable via `KUBE_POLICIES_*` environment variables.
- Helm `values.yaml` is the canonical source for production runtime configuration; prefer that path over hand-edited files here.

## Dependencies

### Internal
- `internal/config` — defines the schema, defaults, and validation

<!-- MANUAL: -->
