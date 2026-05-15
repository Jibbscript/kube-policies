<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# deployments

## Purpose
Raw deployment manifests as an alternative to the Helm chart. Includes Kubernetes-native manifests (CRDs, base deployments, monitoring stack) and reserved slots for Docker Compose and standalone Helm packaging.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `kubernetes/` | Kubernetes manifests: CRDs, base deployments, monitoring (see `kubernetes/AGENTS.md`) |
| `docker-compose/` | Reserved for local Docker Compose stack (currently empty) |
| `helm/` | Reserved for packaged Helm artifacts (currently empty; the chart source lives under `charts/`) |

## For AI Agents

### Working In This Directory
- `make deploy` applies CRDs from `kubernetes/crds/` and then `helm upgrade --install`. Plain manifests in `kubernetes/base/` are an alternative to the chart, not a replacement.
- Keep the manifests aligned with what `charts/kube-policies/templates/` renders — drift is the most common source of inconsistent installs.

### Testing Requirements
- `make test-kind`, `make test-k3s`, `make test-eks`, `make test-vanilla` exercise these manifests against real clusters.

## Dependencies

### External
- `kubectl` for raw manifest application
- Cluster supporting `admissionregistration.k8s.io/v1`

<!-- MANUAL: -->
