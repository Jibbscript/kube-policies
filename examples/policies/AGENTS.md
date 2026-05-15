<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# policies

## Purpose
Sample `Policy` Custom Resource manifests demonstrating Rego rule authoring against the kube-policies engine contract.

## Key Files

| File | Description |
|------|-------------|
| `security-baseline.yaml` | Baseline security rules (e.g. no privileged containers) consumable by the policy engine |

## For AI Agents

### Working In This Directory
- Rego rules in `spec.rules[].rego` must declare `package kube_policies` and produce a result via `evaluate = result { ... }` containing `allowed`, optional `message`, optional `path`, and optional `patches`. See `internal/policy/engine.go` for the evaluation contract.
- Severity values used by the engine include `HIGH`, `MEDIUM`, `LOW` — keep new examples consistent so dashboards and alert routing behave correctly.
- Frameworks (`CIS`, `NIST`, etc.) tag rules for compliance reporting in `internal/policymanager`. Use the same identifiers across policies.

## Dependencies

### External
- A cluster with the `Policy` CRD installed.

<!-- MANUAL: -->
