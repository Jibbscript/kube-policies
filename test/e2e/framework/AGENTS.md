<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# framework

## Purpose
Reusable scaffolding for end-to-end tests. Wraps cluster client construction, namespace/resource lifecycle, manifest application, and waiting helpers so that spec files in `test/e2e` stay focused on behavior, not plumbing.

## Key Files

| File | Description |
|------|-------------|
| `framework.go` | `Framework` struct with cluster client, helpers for creating/deleting namespaces, applying CRDs and policies, polling for readiness |

## For AI Agents

### Working In This Directory
- Helpers should be idempotent and safe to call inside `BeforeEach`/`AfterEach`. Tests rely on this for parallel execution.
- Use polling helpers (`gomega.Eventually`) over fixed `time.Sleep` — flake reduction is the main reason this package exists.
- New helpers should accept a `*Framework` receiver so they compose with existing test setup. Avoid free-standing utility functions that duplicate state.

### Testing Requirements
- This package has no `_test.go` of its own; coverage comes from the e2e suite consumers.

## Dependencies

### External
- `github.com/onsi/gomega`
- `k8s.io/client-go`
- `k8s.io/apimachinery`
- `sigs.k8s.io/controller-runtime`

<!-- MANUAL: -->
