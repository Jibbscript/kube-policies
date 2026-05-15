<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# policymanager

## Purpose
Implements the policy-manager service: in-memory storage for policies, bundles, and exceptions; REST handlers for the `/api/v1/*` API; background goroutines for policy synchronization (ticker placeholder) and hourly exception-expiry monitoring.

## Key Files

| File | Description |
|------|-------------|
| `manager.go` | `Manager` struct, supporting types (`PolicyBundle`, `Exception`, `ExceptionScope`, `ComplianceReport`/`Summary`/`Violation`), all Gin HTTP handlers, validation, and background loops |

## For AI Agents

### Working In This Directory
- Storage is currently in-memory maps guarded by `sync.RWMutex`. There is no persistence layer — restart loses all state. When introducing one, abstract behind an interface and keep the in-memory implementation as the test default.
- `Manager.Start(ctx)` spawns `syncPolicies` (30s ticker — currently a no-op debug log) and `monitorExceptions` (1h ticker calling `checkExpiredExceptions`). Both terminate on context cancellation.
- Compliance handlers (`ListComplianceReports`, `GenerateComplianceReport`, `ListComplianceFrameworks`) currently return mocked data. Real implementations should populate `ComplianceReport` from audit log analysis.
- Validation in `validatePolicy` requires non-empty `Name`, at least one `Rule`, and each rule must have a `Name` and `Rego` body. Strengthen this when adding fields, not weaken it.
- Handler IDs default to `uuid.New().String()` if the client doesn't supply one; preserve this so callers can either choose IDs or accept generated ones.

### Testing Requirements
- Behavior covered by `test/integration/policy_manager_test.go`. No package-local `_test.go` exists today.

### Common Patterns
- HTTP handlers are methods on `*Manager` matching Gin signatures `(c *gin.Context)`.
- All handlers return JSON via `c.JSON(status, body)` and use the standard `gin.H` for ad-hoc error envelopes.
- Time fields use `time.Now()` for `CreatedAt`/`UpdatedAt`; preserve `CreatedAt` on update.

## Dependencies

### Internal
- `internal/config` — full `*config.Config` is held by the manager
- `internal/policy` — `policy.Policy` is the canonical type stored

### External
- `github.com/gin-gonic/gin`
- `github.com/google/uuid`
- `go.uber.org/zap`

<!-- MANUAL: -->
