<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# test (scripts)

## Purpose
Shell-based test orchestration. Each script provisions a target Kubernetes flavor, deploys kube-policies, runs the test suite, and tears down. The aggregate `run-all-tests.sh` walks the matrix.

## Key Files

| File | Description |
|------|-------------|
| `run-all-tests.sh` | Aggregate runner honoring `CLUSTERS`, `PARALLEL`, `CLEANUP`, `COVERAGE`, `PERFORMANCE` env vars (driven by `make test-all`) |
| `test-kind.sh` | Spin up a Kind cluster, deploy, test, teardown |
| `test-k3s.sh` | Provision a local k3s install (requires sudo), test, teardown |
| `test-eks.sh` | Drive an AWS EKS cluster (assumes AWS CLI is configured) |
| `test-vanilla.sh` | Bring up a vanilla kubeadm cluster (requires sudo), test, teardown |

## For AI Agents

### Working In This Directory
- Scripts are referenced by Makefile targets — renaming or moving requires a Makefile update in lockstep.
- `test-k3s.sh` and `test-vanilla.sh` must be invoked under sudo because they manage system-level Kubernetes installs. Never silently strip the sudo expectation.
- Cleanup behavior is controlled by the `CLEANUP` env var read by `run-all-tests.sh`; preserve the convention so CI can opt out for diagnostics.

### Common Patterns
- Use `set -euo pipefail` and explicit error-handling traps for cleanup.
- Echo progress via `tput`/ANSI color blocks so logs are skim-friendly in CI.

## Dependencies

### External
- `kind`, `k3s`, `aws` CLI, `kubectl`, `helm`, `bash` 4+

<!-- MANUAL: -->
