<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# scripts

## Purpose
Shell automation supporting the test matrix invoked by the Makefile. All scripts live under `test/`; new helper scripts for non-test purposes should also land here in their own subdirectory rather than at the repo root.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `test/` | Cluster-specific test runners (Kind, k3s, EKS, vanilla) and the aggregate runner (see `test/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Scripts are referenced by Makefile targets (`test-kind`, `test-k3s`, `test-eks`, `test-vanilla`, `test-all`). Renaming requires a Makefile update.
- Scripts are executable shell files; preserve `#!/usr/bin/env bash` shebangs and `set -euo pipefail` discipline if present.

## Dependencies

### External
- `bash`, `kubectl`, `kind`, `k3s`, `aws` CLI (depending on the script)

<!-- MANUAL: -->
