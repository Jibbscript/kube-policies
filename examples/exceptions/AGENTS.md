<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# exceptions

## Purpose
Sample `PolicyException` Custom Resource manifests showing how to file time-bounded, justified, approver-gated exemptions from policy enforcement.

## Key Files

| File | Description |
|------|-------------|
| `emergency-deployment.yaml` | Example exception suspending a security rule for an emergency rollout, with duration and approval block |

## For AI Agents

### Working In This Directory
- Field shape must align with the `Exception` Go type in `internal/policymanager/manager.go` — particularly `policy_id`, `rule_id`, `scope`, `justification`, `approver`, `expires_at`, and `status`.
- Default policy lifecycle: a newly created exception starts with `status: pending`. Approval flows are managed by the policy manager service; do not assume an exception is enforced until reflected in the manager API.

## Dependencies

### External
- A cluster with the `PolicyException` CRD installed.

<!-- MANUAL: -->
