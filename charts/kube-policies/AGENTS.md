<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# kube-policies (chart)

## Purpose
The single Helm chart that installs kube-policies into a target cluster. Renders deployments, services, RBAC, and supporting resources for both the admission webhook and policy manager.

## Key Files

| File | Description |
|------|-------------|
| `Chart.yaml` | Chart metadata (apiVersion, version, appVersion, dependencies) |
| `values.yaml` | Default configuration values overridable via `--set` or `-f values.yaml` |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `templates/` | Go-templated Kubernetes manifests rendered by Helm (see `templates/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- New chart values must be reflected in `templates/` consumers and, where applicable, in `internal/config` runtime semantics — a value with no template binding is silently ignored.
- Bump `version` (chart) and `appVersion` (image tag) in `Chart.yaml` for any user-visible release; the Makefile derives image tags from `git describe`.

### Testing Requirements
- `make helm-lint` validates structure; `make helm-template` renders to `helm-template-output.yaml` for diffing.

## Dependencies

### External
- Helm 3.8+

<!-- MANUAL: -->
