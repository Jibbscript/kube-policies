<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# charts

## Purpose
Helm chart distribution for kube-policies. The chart packages both the admission webhook and policy manager along with their RBAC, services, and supporting resources.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `kube-policies/` | The single Helm chart shipped by this project (see `kube-policies/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- `make helm-lint` validates the chart; `make helm-template` renders it; `make helm-package` produces a tarball under `dist/`.
- Chart values intentionally mirror runtime configuration knobs in `internal/config` — keep the two consistent when adding new options.

### Testing Requirements
- Lint with `helm lint charts/kube-policies` (wrapped by `make helm-lint`).
- Render and inspect templates locally before publishing.

## Dependencies

### External
- Helm 3.8+
- Kubernetes 1.20+ target cluster

<!-- MANUAL: -->
