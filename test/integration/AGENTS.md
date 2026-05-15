<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# integration

## Purpose
Integration tests exercising the admission webhook and policy manager against an envtest-provided control plane. Validates HTTP-level behavior, policy evaluation paths, and policy/exception lifecycle without requiring a full cluster.

## Key Files

| File | Description |
|------|-------------|
| `admission_webhook_test.go` | Integration tests for the validate/mutate admission flows, error paths, and audit emission |
| `policy_manager_test.go` | Integration tests for `/api/v1/policies`, `/exceptions`, `/bundles`, and `/compliance` handlers |

## For AI Agents

### Working In This Directory
- Tests rely on `KUBEBUILDER_ASSETS` produced by `setup-envtest` (`make setup` installs the tool; `make test-integration` invokes `setup-envtest use 1.28.0 ... -p path`).
- Use `httptest.NewRecorder` and Gin's router directly for handler-level tests; reserve full `httptest.Server` for cases that need real network plumbing.
- Tests must be self-contained — no shared state between cases. Reset the manager/engine inside each `t.Run`/`testify` setup.

### Testing Requirements
- `make test-integration` is the canonical entry point. Coverage profile is written to `coverage-integration.out`.

## Dependencies

### External
- `github.com/stretchr/testify`
- `sigs.k8s.io/controller-runtime/tools/setup-envtest` (provided binary path)
- `net/http/httptest`

<!-- MANUAL: -->
