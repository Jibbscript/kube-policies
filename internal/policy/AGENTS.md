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

## P10 Policy Library (POL-WU-*)

The bundled library was overhauled in P10. New structure:

| File | Description |
|------|-------------|
| `rego/podspec.rego` | Shared Rego library (`package kube_policies.lib`) embedded via `lib_loader.go` and compiled ALONGSIDE every rule in `preparedQueryFor`. Helpers: `pod_spec`, `all_containers`, `containers_with_paths` (container + kind-correct JSONPath), `volumes`, `pod_security_context`, `pod_meta`, `container_path_prefix`. Lets rules traverse workload-controller templates, initContainers, and ephemeralContainers (POL-WU-01). |
| `lib_loader.go` | `go:embed rego/*.rego`; `libModuleOptions()` (added to every compile) and `LibrarySources()` (for the validator + bundle digest). |
| `bundled_rules.go` | The opt-in rule packs: `pssBaselinePolicy`, `pssRestrictedPolicy`, `nsaHardeningPolicy`, `governanceBaselinePolicy`, `rbacBaselinePolicy`, `secretsBaselinePolicy`, `networkBaselinePolicy`, `mutatingHardeningPolicy`. All ship `Enabled:false`. |
| `profiles.go` | `EnforcementProfiles` (name → policy-ID set) + `applyProfiles` (POL-WU-23). Selected via `config.PolicyConfig.Profiles`. |
| `policy_validation.go` | `ValidateRuleRego`/`ValidatePolicy` — compile-with-lib + contract probe; the CRD compile gate delegates here (POL-WU-24). |
| `bundle_version.go` | `PolicyBundleVersion` (SemVer) + `ruleBundleVersions` (every rule → introduced-in version) (POL-WU-26). |
| `bundle_digest.go` | `ComputeBundleManifest`/`BundleDigest` — canonical, signable manifest of the library (POL-WU-27); emitted by `cmd/policybundle`. |
| `control_matrix.{yaml,go}` | Machine-checkable rule → numbered-control-ID matrix (POL-WU-28). |

Key invariants (all test-locked — see the `_test.go` files):
- **Kind routing (POL-WU-21):** a `Rule.TargetKinds` slice scopes which Kubernetes kinds a rule runs against. Empty = all kinds. `evaluatePolicy` skips non-matching rules, so a pod rule never evaluates (or errors and fail-closes) a ClusterRole, and the RBAC/Network/Secret packs coexist with pod rules. Pod-shaped rules use `podWorkloadKinds`.
- **Parameters:** `Policy.Parameters` (map[string]string) is exposed to that policy's rules at `input.parameters` (POL-WU-13/20). `evaluatePolicy` shallow-copies the base input only when a policy has parameters.
- **Single verdict per rule:** when several conditions can match, build an ordered list and emit the first (`list[0]` / `min(indices)`), and make helper functions return a single value (sorted) — multiple complete-value `evaluate` rules or multi-output functions raise an OPA conflict that errors evaluation.
- **Opt-in safety:** only `security-baseline` is enabled by default. Adding a rule? Add it to a pack, give it a `TargetKinds`, register it in `ruleBundleVersions` AND `control_matrix.yaml` AND a `ruleCoverage` fixture (allow+deny) AND `docs/policy-library.md` — each is enforced by a test that fails for an uncovered rule.

## For AI Agents

### Working In This Directory
- Each rule's Rego is compiled per evaluation via `rego.New(...).PrepareForEval(ctx)` — together with the shared library modules (`libModuleOptions()`) — and queried as `data.kube_policies.evaluate`. Rules must define `package kube_policies` and produce a result map with keys `allowed` (bool), `message` (string, optional), `path` (string, optional), and `patches` (list, optional). This is the contract — examples in `examples/policies/` follow it (and are compile-tested by `TestExamplePoliciesCompile`).
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
