<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# policies

## Purpose
Sample `Policy` Custom Resource manifests demonstrating Rego rule authoring against the kube-policies engine contract.

## Key Files

| File | Description |
|------|-------------|
| `security-baseline.yaml` | The default-on baseline rules (no privileged containers, no hostPath, no `:latest`, required securityContext), rebased onto the shared library |
| `image-provenance.yaml` | Opt-in registry allowlist + image-digest pinning (parameterized) |
| `registry-allowlist.yaml` | Standalone registry-allowlist illustration (POL-WU-13) |
| `image-digest.yaml` | Standalone require-image-digest illustration (POL-WU-14) |
| `automount-token.yaml` | Standalone automount-token-disabled illustration (POL-WU-15) |
| `governance-baseline.yaml` | Required-labels + deny-default-namespace illustration (POL-WU-20) |

These files are **illustrative copies** of bundled rules; the authoritative source
is `internal/policy` (`engine.go`, `bundled_rules.go`). The full catalog of every
shipped rule, with allow/deny examples and control mappings, is
`docs/policy-library.md`; enforcement profiles are in `docs/policy-profiles.md`.

## For AI Agents

### Working In This Directory
- Rego rules in `spec.rules[].rego` must declare `package kube_policies` and produce a result via `evaluate := result if { ... }` (OPA v1) containing `allowed`, optional `message`, optional `path`, and optional `patches`. See `internal/policy/engine.go` for the evaluation contract.
- Every rule is compiled WITH the shared library (`data.kube_policies.lib`, `internal/policy/rego/podspec.rego`); import it (`import data.kube_policies.lib as lib`) to evaluate the effective pod spec across workload controllers, initContainers, and ephemeralContainers instead of only `input.object.spec.containers`.
- Every example here is compile-tested against the engine contract by `internal/policy.TestExamplePoliciesCompile` — a syntactically broken or contract-violating example fails the build. Customer-authored Policy CRDs face the same gate at admission/reconcile (`policy.ValidateRuleRego`, POL-WU-24).
- Severity values used by the engine include `HIGH`, `MEDIUM`, `LOW` — keep new examples consistent so dashboards and alert routing behave correctly.
- Frameworks (`CIS`, `NIST`, etc.) tag rules for compliance reporting in `internal/policymanager`. Use the same identifiers across policies.

## Dependencies

### External
- A cluster with the `Policy` CRD installed.

<!-- MANUAL: -->
