<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# e2e

## Purpose
End-to-end test suite exercising kube-policies against a real cluster. Uses Ginkgo v2 BDD-style specs and a shared framework helper for cluster setup, manifest application, and resource introspection.

## Key Files

| File | Description |
|------|-------------|
| `e2e_test.go` | Ginkgo suite: admission webhook validation/mutation flows, policy manager API, exception lifecycle, end-to-end policy enforcement |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `framework/` | Shared cluster client, fixture helpers, and test setup utilities (see `framework/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Run via `make test-e2e` (which adds `-ginkgo.v -ginkgo.progress`). Tests assume a reachable cluster and the kube-policies CRDs/workloads are already installed.
- Specs are organized as `Describe` (component) → `Context` (scenario) → `It` (assertion). Reuse `BeforeEach`/`AfterEach` for setup so failures don't leak fixtures.
- When adding scenarios, factor cluster operations into the `framework` package; test files should read like prose.

### Testing Requirements
- Requires `KUBECONFIG` pointing at a cluster with kube-policies deployed. The `scripts/test/test-*.sh` scripts handle this for the supported cluster flavors.

## Dependencies

### External
- `github.com/onsi/ginkgo/v2`
- `github.com/onsi/gomega`
- `k8s.io/client-go`

<!-- MANUAL: -->
