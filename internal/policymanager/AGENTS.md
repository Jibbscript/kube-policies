<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-17 -->

# policymanager

## Purpose
Implements the policy-manager service: in-memory storage for policies, bundles, and exceptions; REST handlers for the `/api/v1/*` API; background goroutines for policy synchronization (ticker placeholder) and hourly exception-expiry monitoring. Also publishes the `ControllerOptions` plumbing (PolicyReconciler, PolicyExceptionReconciler, `PolicySink`, `ExceptionSink`) consumed by both the policy-manager binary and the admission-webhook binary.

## Key Files

| File | Description |
|------|-------------|
| `manager.go` | `Manager` struct, supporting types (`PolicyBundle`, `Exception`, `ExceptionScope`, `ComplianceReport`/`Summary`/`Violation`), all Gin HTTP handlers, validation, and background loops |
| `controller.go` | `ControllerOptions`, `StartControllers`, `PolicySink` + `ExceptionSink` interfaces, `PolicyReconciler` + `PolicyExceptionReconciler` (leader-elected by default; `LeaderlessReconcilers: true` for the webhook host). |
| `crd_sync.go` | `ExceptionFromCRD` — the canonical converter from `policiesv1.PolicyException` to the internal `Exception` value. Reused by both the policy-manager's reconciler and the admission-webhook's `exceptionSink`. |
| `decisions_handler.go` / `_test.go` | `/api/v1/decisions/internal` ingestion. Lenient JSON decode (no `DisallowUnknownFields()`); `suppressed_by` round-trips intact, asserted by `TestIngestInternal_SuppressedByRoundTrip`. |

## For AI Agents

### Working In This Directory
- Storage is currently in-memory maps guarded by `sync.RWMutex`. There is no persistence layer — restart loses all state. When introducing one, abstract behind an interface and keep the in-memory implementation as the test default.
- `Manager.Start(ctx)` spawns `syncPolicies` (30s ticker — currently a no-op debug log) and `monitorExceptions` (1h ticker calling `checkExpiredExceptions`). Both terminate on context cancellation.
- Compliance handlers (`ListComplianceReports`, `GenerateComplianceReport`, `ListComplianceFrameworks`) currently return `501 Not Implemented`. Real implementations should populate `ComplianceReport` from audit log analysis.
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

## ExceptionSink (write side) and the dual-interface pattern

`ExceptionSink` (`controller.go:39-53`) is the write-side counterpart of `PolicySink`. The `PolicyExceptionReconciler` calls `UpsertExceptionFromCRD` / `RemoveExceptionByID` whenever a `PolicyException` CR changes; the sink stores the exception however the caller chooses.

- The **policy-manager** binary passes its own `Manager` as the sink — exceptions feed the manager's in-memory store and the `/api/v1/exceptions` REST surface.
- The **admission-webhook** binary passes a leaderless `*exceptionSink` (at `cmd/admission-webhook/exception_sink.go`) that also satisfies `policy.ExceptionRegistry` — the engine reads the same store via `Suppresses(ctx, MatchKey)` on the hot path. The "Sink" name reflects only the write-side contract; the dual-interface comment on `controller.go:39-49` points to the webhook implementation as the canonical example. When extending the interface, **do not import `internal/policy`** here — the read-side contract lives in that package on purpose so neither side depends on the other.
- `ControllerOptions.ExceptionSink` is **optional**. Passing `nil` skips wiring the `PolicyExceptionReconciler` entirely; no informer is started for `policyexceptions`. The webhook only passes a non-nil sink when controllers are enabled (see `cmd/admission-webhook/AGENTS.md` for the conditional construction).
- Reconcile order: `PolicyExceptionReconciler.Reconcile` (`controller.go:301-330`) validates `Spec.PolicyID` is non-empty before calling the sink — this validation gate is the first line of defense against malformed CRs from pre-mortem §4.4 (reconciler-panic scenario). Controller-runtime's built-in `recover()` guard is the second line; do not wrap reconcile in a hand-rolled recover.

## Leader election

`ControllerOptions.DisableLeaderElection` uses an **inverted boolean**: the zero value (`false`) means leader election is **ON**. This makes multi-replica deployments safe by default — a caller that forgets to set the field gets election, not a racing pair of reconcilers.

- Set `DisableLeaderElection: true` only in single-process scenarios where contention is impossible (e.g. envtest unit suites, `--disable-controllers` code paths).
- When election is enabled, `LeaderElectionNamespace` is required. Obtain it via `ResolvePodNamespace("/var/run/secrets/kubernetes.io/serviceaccount/namespace")` at the binary's composition root; the call should live inside the `if !*disableControllers { ... }` block so `--disable-controllers` short-circuits cleanly.
- `LeaderElectionReleaseOnCancel: true` is always set by `StartControllers`. Combined with the binary's SIGTERM → context-cancel flow, this limits the rolling-deploy reconcile gap to ~2 s instead of the default ~15 s lease duration.
- A single-replica deployment still acquires the lease on startup, which adds up to ~10 s of initial delay before the first reconcile. The HTTP API server starts independently and continues to answer requests during this window.
- The Lease resource lives in the namespace resolved by `ResolvePodNamespace`. Both `cmd/admission-webhook` and `cmd/policy-manager` use distinct `LeaderElectionID` values so they never contend over the same lease.
- RBAC: the ServiceAccount must have `coordination.k8s.io/leases` (get, list, watch, create, update, patch, delete). See `charts/kube-policies/templates/rbac.yaml` and `deployments/kubernetes/base/rbac.yaml`.

<!-- MANUAL: -->
