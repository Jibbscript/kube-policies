<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-17 -->

# policy

## Purpose
OPA-based policy evaluation engine. Defines the in-memory policy/rule data model and evaluates Rego rules against `admissionv1.AdmissionRequest` inputs, returning allow/deny decisions, violation lists, and JSON patches for mutations. Loads built-in default policies on construction. Optionally consults an `ExceptionRegistry` to suppress matching denials per operator-authored `PolicyException` CRs.

## Key Files

| File | Description |
|------|-------------|
| `engine.go` | `Engine`, `Policy`, `Rule`, `EvaluationRequest`, `EvaluationResult`, `PolicyViolation`, `JSONPatch` types and engine methods. Hosts the conditional `NewEngineWithExceptions` constructor and the exception suppression pass inside `Evaluate`. |
| `exception_registry.go` | `ExceptionRegistry` interface (read-side contract), `MatchKey` (per-violation input), `ExceptionRef` (audit-friendly attribution handle). |
| `engine_test.go` | Unit tests for the engine's core evaluation paths (Rego execution, policy loading, mutation aggregation). |
| `engine_exceptions_test.go` | Eight `TestEngine_*` cases covering the suppression pass (nil-registry, match, mismatch, fail-closed-on-error, partial suppression, MatchKey population, mixed suppress+error, distinct-exception count). |

## For AI Agents

### Working In This Directory
- Each rule's Rego is compiled per evaluation via `rego.New(...).PrepareForEval(ctx)` and queried as `data.kube_policies.evaluate`. Rules must define `package kube_policies` and produce a result map with keys `allowed` (bool), `message` (string, optional), `path` (string, optional), and `patches` (list, optional). This is the contract — examples in `examples/policies/` follow it.
- The engine guards `policies` map with `sync.RWMutex`. Reads (`Evaluate`, `ListPolicies`) take RLock; writes (`LoadPolicy`, `RemovePolicy`) take Lock. Preserve this discipline.
- A rule that fails to evaluate is **logged and skipped**, not propagated as an error — preventing one bad policy from taking down admission control. Do not change this without a migration story.
- `loadDefaultPolicies` ships an embedded `security-baseline` policy denying `spec.securityContext.privileged: true`. Add to this list cautiously; default-deny rules can break clusters on upgrade.
- Mutations: rule-emitted `patches` are aggregated across all rules into `EvaluationResult.Patches` (a `[]JSONPatch`) and serialized by the admission handler. Rules that produce conflicting patches will produce ill-defined results — document and test any cross-rule mutation scenarios.

### Exception Suppression
- The engine is **the sole emitter of admission verdicts**; the registry contributes only suppression facts. A registered exception may downgrade `deny → allow`, never the inverse.
- Construct via `NewEngine(cfg, log)` for the no-registry path; via `NewEngineWithExceptions(cfg, log, registry)` for the suppression-enabled path. The `WithExceptions` constructor panics on a nil registry (caller bug); use `NewEngine` for the disabled-suppression code path.
- The suppression pass in `Evaluate` only runs when `e.exceptionRegistry != nil` AND `result.Allowed == false`. Nil-registry is the **live production code path** under `--disable-controllers` and during cache warmup — its absence-of-behavior is asserted by `TestEngine_NoRegistry_BehaviorUnchanged`.
- Per-violation the engine builds a `MatchKey{PolicyID, RuleID, Namespace, Resource (lowercased), User, Groups}` from the `AdmissionRequest` and calls `registry.Suppresses(ctx, key)`. The registry returns `(suppressed bool, refs []ExceptionRef, err error)`.
- **Fail-closed on registry error.** A non-nil error from `Suppresses` preserves the original deny: the violation stays in `result.Violations`, the engine logs a `warn` line with `policy_id`/`rule_id`/`err`, and a `sawRegistryError` gate prevents the verdict flip even if every other violation was suppressed cleanly. Live branch — tested by `TestEngine_RegistryError_FailClosed`.
- Suppressed violations move out of `result.Violations` and onto `result.SuppressedBy []ExceptionRef`. The replacement `Violations` slice is **freshly allocated** so any caller-retained reference to the original backing array is preserved untouched.
- `result.Allowed` flips to `true` **only when every violation was suppressed AND no registry error occurred** — partial suppression OR any error leaves the original `false`.
- The `Message`/`Reason` setter is a three-way switch: deny preserved → `Reason="PolicyViolation"`; allow with no suppressions → `Reason="PolicyCompliant"`, the existing happy-path message; allow because every violation was suppressed → `Reason="PolicyViolationSuppressedByException"` with `Message="N policy violation(s) suppressed by M exception(s); see suppressed_by for details"` (M is `distinctExceptionCount` over the refs). Downstream consumers reading only `Message` MUST be able to distinguish "compliant" from "suppressed."
- On suppression, the engine emits an `info`-level log line `"policy violation suppressed by exception"` carrying `policy_id`, `rule_id`, `namespace`, `resource`, `user`, and the full `exception_refs` slice. Per-exception attribution (ID, Name, Justification) lives in this log line and in `EvaluationResult.SuppressedBy`, never in metric labels.
- The `ExceptionRegistry` interface lives in this package on purpose — the engine owns the read-side contract. The webhook supplies the implementation (`cmd/admission-webhook/exception_sink.go`) via the composition root; the engine never imports `internal/policymanager`. Preserve this dependency direction.

### Testing Requirements
- Core engine unit tests in `engine_test.go`; suppression-pass coverage in `engine_exceptions_test.go`. End-to-end coverage exercises Rego evaluation through the admission handler.

### Common Patterns
- Inject configuration via `*config.PolicyConfig` and a `*zap.Logger` — no package globals.
- `prepareInput` unmarshals `req.AdmissionRequest.Object.Raw` into `interface{}` so Rego can navigate it freely.

## Dependencies

### Internal
- `internal/config` — `PolicyConfig`

### External
- `github.com/open-policy-agent/opa/rego`
- `github.com/open-policy-agent/opa/storage`, `.../storage/inmem`
- `go.uber.org/zap`
- `k8s.io/api/admission/v1`

<!-- MANUAL: -->
