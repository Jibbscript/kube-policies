<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# crds

## Purpose
Custom Resource Definitions for the `policies.kube-policies.io/v1` API group. Defines the `Policy` and `PolicyException` resources consumed by the policy manager and engine.

## Key Files

| File | Description |
|------|-------------|
| `policies.yaml` | CRDs for `Policy` and `PolicyException` with OpenAPI v3 schemas |

## For AI Agents

### Working In This Directory
- Schema changes must be matched by Go-side type updates: `Policy`/`Rule` in `internal/policy/engine.go`, `Exception`/`ExceptionScope` in `internal/policymanager/manager.go`.
- Removing or renaming fields is a breaking change for users — favor additive evolution and use `additionalPrinterColumns` for surface improvements.
- These CRDs must be applied **before** the workloads (`make deploy` enforces this order).

### Testing Requirements
- `kubectl apply --dry-run=server -f policies.yaml` against a test cluster catches schema regressions.

## Dependencies

### External
- Kubernetes 1.20+ (CRD `apiextensions.k8s.io/v1`)

<!-- MANUAL: -->
