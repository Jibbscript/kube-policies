<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-17 -->

# admission-webhook

## Purpose
`package main` for the validating + mutating admission webhook. Wires logger, config, metrics, audit logger, policy engine, and admission controller into a TLS HTTP server with a separate plain-HTTP metrics server. Optionally embeds the `Policy` and `PolicyException` CRD reconcilers (via `policymanager.StartControllers`) so the engine consults exceptions on the hot path. Both servers are torn down via signal-driven 30-second graceful shutdown.

## Key Files

| File | Description |
|------|-------------|
| `main.go` | Flag parsing, dependency wiring, conditional engine construction (`policy.NewEngine` vs `policy.NewEngineWithExceptions`), server setup (TLS 1.3 webhook + metrics), and shutdown sequence. |
| `crd_sink.go` | `engineSink` — the existing dual-role adapter satisfying `policymanager.PolicySink` (write side) and feeding the engine's policy store (read side). Template for `exception_sink.go`. |
| `exception_sink.go` | `*exceptionSink` — the dual-role adapter for `PolicyException` CRs. Satisfies `policymanager.ExceptionSink` (write side: `UpsertExceptionFromCRD`, `RemoveExceptionByID`) AND `policy.ExceptionRegistry` (read side: `Suppresses(ctx, MatchKey)`). Owns the security-sensitive `matches` predicate. |
| `exception_sink_test.go` | Fourteen `TestExceptionSink_*` cases covering the matcher's scope-presence rule, per-dimension allow-lists, case-sensitivity matrix, group-intersection semantics, expiry, and concurrent read/write safety. |

## For AI Agents

### Working In This Directory
- Flags: `--cert-path` (`/etc/certs/tls.crt`), `--key-path` (`/etc/certs/tls.key`), `--port` (8443), `--metrics-port` (9090), `--config` (`/etc/config/config.yaml`), `--disable-controllers` (skip CRD reconcilers and exception consumption), `--disable-default-policies` (skip the embedded `security-baseline` policy).
- Webhook routes are `POST /validate` and `POST /mutate` on the TLS server; `GET /healthz` and `GET /readyz` are exposed on the same server. The metrics server exposes `GET /metrics` and `GET /healthz`.
- TLS config pins `MinVersion: tls.VersionTLS13` and a fixed cipher suite list — preserve this when modifying.
- All HTTP handler logic belongs in `internal/admission`; this file only registers handlers.

### Conditional Engine Construction (Exception Wiring)
- Engine construction in `main.go` branches on `--disable-controllers`:
  - **`--disable-controllers=true`**: builds `policy.NewEngine(cfg, log)` — registry is `nil`, the suppression pass short-circuits in one pointer compare, behavior is identical to pre-PR (Principle 5). Startup log: `exception sink not wired (--disable-controllers set; bundled-only enforcement)`.
  - **`--disable-controllers=false`** (default): builds a single `*exceptionSink` via `newExceptionSink(log.Named("exception-sink"))` and passes it as BOTH:
    - the engine's `policy.ExceptionRegistry` (read side), via `policy.NewEngineWithExceptions(cfg, log, excSink)`;
    - the reconciler's `policymanager.ExceptionSink` (write side), via `ControllerOptions.ExceptionSink = excSink`.
    Startup log: `exception sink wired into engine (CRD reconciler enabled)`.
- **Do not** pass a non-nil registry to `NewEngine` (it ignores it) or a nil registry to `NewEngineWithExceptions` (it panics). The branching is the only correct way to wire this.
- The `*exceptionSink` is leaderless: the `ControllerOptions.LeaderlessReconcilers: true` flag (already set for the policy reconciler) means every webhook replica runs its own reconciler and updates its own in-process index. Status-patch races between replicas are benign — every replica writes the same `Status.Phase` for the same CR spec.
- The matcher predicate (`exception_sink.go::matches`) is **security-sensitive**. Any future field added to `policymanager.ExceptionSpec` / `PolicyExceptionScope` MUST come with (a) a `matches` branch, (b) a unit-test row, AND (c) a doc-comment clause in the predicate's godoc. Scope-presence rule: all four dimensions empty = wildcard match (operator's "blanket carve-out" intent); any populated dimension = strict allow-list, unset-but-populated dimensions are unconstrained but do not widen the match. Operators who want "match nothing" must omit the CR entirely.

### Testing Requirements
- Unit coverage for `*exceptionSink` lives in `exception_sink_test.go` (must pass `-race`). Compile-time `var _ policymanager.ExceptionSink = (*exceptionSink)(nil)` and `var _ policy.ExceptionRegistry = (*exceptionSink)(nil)` assertions live at the top of `exception_sink.go` and must remain — they are the trip-wire that catches future refactors breaking either contract.
- End-to-end behavior is covered by `test/integration/admission_webhook_test.go`, `test/integration/webhook_exception_suppression_test.go` (envtest), and the un-quarantined `should allow exceptions for specific resources` spec in `test/e2e/e2e_test.go`.

### Common Patterns
- Build the controller via `admission.NewController(policyEngine, auditLogger, metricsCollector, logger)` and pass its handlers to Gin routes.
- Use `gin.SetMode(gin.ReleaseMode)` and `gin.New()` + `gin.Recovery()` (no default middleware).
- The `engineSink` (`crd_sink.go`) and `*exceptionSink` (`exception_sink.go`) follow the same dual-interface pattern: one struct, two named interfaces from different packages, wired by `main.go`. Mimic this pattern for any future CRD whose read-side contract belongs in `internal/policy` and write-side contract belongs in `internal/policymanager`.

## Dependencies

### Internal
- `internal/admission` — handler implementation
- `internal/audit` — audit logger (carries `SuppressedBy []policy.ExceptionRef`)
- `internal/config` — config loader
- `internal/metrics` — Prometheus collector (now exposes `kube_policies_policy_exception_suppressions_total{policy_id, rule_id}`)
- `internal/policy` — engine + `ExceptionRegistry` interface
- `internal/policymanager` — `ExceptionSink` interface, `ExceptionFromCRD` converter, `StartControllers`, `ControllerOptions`
- `internal/policymanager/apis/policies/v1` — `PolicyException` typed CR
- `pkg/logger` — zap logger factory

### External
- `github.com/gin-gonic/gin`
- `github.com/prometheus/client_golang/prometheus/promhttp`
- `go.uber.org/zap`

<!-- MANUAL: -->
