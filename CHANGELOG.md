# Changelog

All notable changes to **kube-policies** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Engine-side `PolicyException` consumption.** The admission engine now consults a `policy.ExceptionRegistry` (new interface in `internal/policy/exception_registry.go`) during `Evaluate`; matching exceptions can downgrade a `deny` to an `allow` while preserving the original violations on `EvaluationResult.SuppressedBy` for audit. The new `policy.NewEngineWithExceptions(cfg, logger, registry)` constructor wires the registry; `NewEngine` is unchanged for the `--disable-controllers` path.
- **Dual-interface exception sink** at `cmd/admission-webhook/exception_sink.go`. A single `*exceptionSink` value implements BOTH `policymanager.ExceptionSink` (write side, fed by the leaderless `PolicyExceptionReconciler` watch) AND `policy.ExceptionRegistry` (read side, consulted by `Evaluate`). The matching predicate is security-sensitive: empty scope dimensions mean "no constraint on that dimension", but an exception with NO scope at all matches every request — the predicate is exhaustively documented inline and pinned by 14 unit tests.
- **Suppression observability.**
  - Prometheus counter `kube_policies_policy_exception_suppressions_total{policy_id, rule_id}` — labels deliberately bounded to two dimensions to avoid the high-cardinality outage class (per design `exception_id` is surfaced in audit logs, not metric labels).
  - Per-violation structured INFO log on suppression with `policy_id`, `rule_id`, `namespace`, `resource`, `user`, and `exception_refs`.
  - `audit.Context.SuppressedBy` populated by the admission controller before the audit log call; round-trips through `audit.Event` and `audit.PublicEvent` to the decisions publisher (`suppressed_by` JSON tag).
- **Integration suite** `TestWebhookExceptionSuppressionTestSuite` (`test/integration/`). Five envtest cases: matching suppression, non-matching preservation, deleted-exception restoration, expired-exception denial, and controller-runtime reconciler-panic recovery.
- **e2e quarantine release.** The previously `ginkgo.PIt`-quarantined `Policy Exceptions > should allow exceptions for specific resources` spec is now active; the suite reports `10 Passed, 0 Failed, 0 Pending` (was `9 Passed, 0 Failed, 1 Pending`).
- **CRD-typed e2e helper** `Framework.CreateTestPolicyException(name, policyID, ruleID, expiresAfter, scope)` replacing the prior helper that emitted the bogus `rules`/`duration`/`selector` JSON fields. Companion namespace helpers (`CreateNamespace`, `DeleteNamespace`, `CreatePodInNamespace`) added for sub-namespace scope tests.
- **Three `AGENTS.md` updates** (`internal/policy/`, `internal/policymanager/`, `cmd/admission-webhook/`) describing the new exception flow, dual-interface adapter pattern, and conditional engine construction.
- **README** gains an `Eventual-consistency note` and `Scope semantics` callout for the operator-facing `PolicyException` workflow; corrects the example YAML schema (previous example used non-existent `policy`/`rules`/`duration`/`approval` fields).

### Changed

- **Admission engine `Evaluate` (`internal/policy/engine.go`).** After the per-policy loop, a suppression pass runs when a non-nil registry is wired: per-violation `MatchKey` is built from the admission request (namespace, lowercased resource, user, groups), the registry is consulted via `Suppresses(ctx, key)`, and matching violations are removed from the surviving slice while `SuppressedBy` accumulates the `[]ExceptionRef`. A new `sawRegistryError` gate ensures the verdict flip to `Allow` requires zero registry errors during the pass — registry errors are fail-CLOSED (original deny stands, warn-level log). The reason/message block is now a three-case switch: `PolicyViolation`, `PolicyViolationSuppressedByException` (new; explicit `N policy violation(s) suppressed by M exception(s)` message), or `PolicyCompliant`.
- **Admission-webhook composition root (`cmd/admission-webhook/main.go`).** Conditional engine construction: under `--disable-controllers` the engine is built via the unchanged `policy.NewEngine` (no registry — preserves prior observable behavior); otherwise a single `*exceptionSink` is constructed and passed as BOTH `policymanager.ControllerOptions.ExceptionSink` AND the registry argument to `policy.NewEngineWithExceptions`. Both code paths log their wiring choice at startup.
- **Policy-manager decisions handler (`internal/policymanager/decisions_handler.go`).** Documented the lenient `json.Decoder` posture so future strict-decode migrations are deliberate. Added a round-trip test asserting `suppressed_by` payloads land intact in the in-memory ring.
- **`internal/policymanager/controller.go`** — `ExceptionSink` interface godoc gains a 6-line "NAMING NOTE" documenting the dual-interface pattern and pointing at `cmd/admission-webhook/exception_sink.go` as the canonical implementation.

### Security

- **`PolicyException` matching is single-sourced** in the dual-interface adapter. The `matches(MatchKey, Exception)` predicate documents the case-sensitivity matrix (resource: case-insensitive plural; namespace/user/group: case-sensitive), the scope-presence rule (`Scope` absent ⇒ matches all; `Scope` present with empty list per dimension ⇒ NOT a wildcard), RuleID semantics (empty ⇒ all rules of policy; non-empty ⇒ exact match), and group-intersection rules. Any future expansion MUST extend both the predicate and the table-driven test set together.
- **Fail-closed on registry error.** A non-nil error from `ExceptionRegistry.Suppresses` preserves the original deny verdict and emits a warn log; suppression is never silently applied on an error path.

### Internal

- New constructor `policy.NewEngineWithExceptions` panics on a nil registry argument (caller-bug detector — the `--disable-controllers` path uses the unchanged `NewEngine` constructor, so `NewEngineWithExceptions` callers are always feeding a real registry).
- `MatchKey.Resource` is lowercased by the engine before the registry call (the matcher uses `containsFold` against the scope's `Resources` list).
- The suppression pass uses a freshly-allocated `surviving` slice — no aliasing of `result.Violations` backing array with caller-retained references.

### Verified

- 12 acceptance criteria (`C1`-`C12`) green; full e2e suite `10 Passed, 0 Failed, 0 Pending` on a kind cluster; envtest integration suite `5/5`; unit suites `8` engine + `14` adapter race-clean; full `go test -race -count=1 ./...` green with no regressions in the pre-existing `internal/audit`, `internal/metrics`, `internal/admission`, `internal/policymanager`, or `internal/policy` suites.

[Unreleased]: https://github.com/Jibbscript/kube-policies/compare/main...HEAD
