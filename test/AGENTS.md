<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# test

## Purpose
Cross-cutting test code that does not naturally live alongside the package under test: integration tests using envtest, Ginkgo-based end-to-end tests, and reserved directories for fixtures, mocks, testdata, and additional unit suites.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `integration/` | Integration tests for admission webhook and policy manager against envtest (see `integration/AGENTS.md`) |
| `e2e/` | End-to-end tests + Ginkgo framework helpers (see `e2e/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Unit tests for production code should live next to that code (e.g. `internal/policy/engine_test.go`). Use this directory only for tests that genuinely need cross-package or cluster scaffolding.
- Integration tests rely on `KUBEBUILDER_ASSETS` provided by `setup-envtest` (`make setup` installs it).
- E2E tests use Ginkgo v2 and Gomega; favor `Describe`/`Context`/`It` blocks and run with `-ginkgo.v -ginkgo.progress`.

### Testing Requirements
- `make test-integration` and `make test-e2e` are the canonical entry points.
- Integration runs need a working envtest binary path; e2e runs need a real cluster.

## Dependencies

### External
- `github.com/onsi/ginkgo/v2`, `github.com/onsi/gomega`
- `sigs.k8s.io/controller-runtime/tools/setup-envtest`

<!-- MANUAL: -->
