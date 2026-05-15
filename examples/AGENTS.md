<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# examples

## Purpose
Example Custom Resource manifests demonstrating how to author Policies and PolicyExceptions for the kube-policies CRDs (`policies.kube-policies.io/v1`).

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `policies/` | Sample `Policy` resources, e.g. `security-baseline.yaml` (see `policies/AGENTS.md`) |
| `exceptions/` | Sample `PolicyException` resources, e.g. `emergency-deployment.yaml` (see `exceptions/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Examples must apply cleanly against the CRDs in `deployments/kubernetes/crds/policies.yaml` — keep field names and `apiVersion` aligned.
- Rego embedded in `Policy.spec.rules[].rego` should match the contract evaluated by `internal/policy/engine.go` (`data.kube_policies.evaluate` returning `{"allowed": bool, "message": string, "path": string, "patches": [...]}`).

### Testing Requirements
- `kubectl apply --dry-run=client -f examples/...` is a quick syntax check.
- E2E tests in `test/e2e/` may load fixtures from here.

## Dependencies

### External
- A cluster with the kube-policies CRDs installed.

<!-- MANUAL: -->
