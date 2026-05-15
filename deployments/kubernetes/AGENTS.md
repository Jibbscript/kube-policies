<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# kubernetes

## Purpose
Plain Kubernetes manifests applied directly with `kubectl` as an alternative to (or alongside) the Helm chart. Includes CRD definitions, baseline workload manifests, and the monitoring stack.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `crds/` | Custom Resource Definitions for `policies.kube-policies.io` (see `crds/AGENTS.md`) |
| `base/` | Baseline workload manifests, e.g. admission webhook deployment (see `base/AGENTS.md`) |
| `monitoring/` | Prometheus, Grafana, and Alertmanager Deployments/Services (see `monitoring/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- `make deploy` applies `crds/` first, then `helm upgrade --install`. Manifests in `base/` are not applied automatically — use them when not using Helm.
- CRD schema changes require an OpenAPI v3 schema bump in `crds/policies.yaml`; ensure `internal/policy.Policy` and `internal/policymanager.Exception` Go types stay aligned.

### Testing Requirements
- Cluster-targeted tests (`make test-kind` etc.) apply these manifests as part of bring-up.

## Dependencies

### External
- `kubectl` against a Kubernetes 1.20+ cluster

<!-- MANUAL: -->
