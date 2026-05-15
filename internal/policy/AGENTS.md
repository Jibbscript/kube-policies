<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# policy

## Purpose
OPA-based policy evaluation engine. Defines the in-memory policy/rule data model and evaluates Rego rules against `admissionv1.AdmissionRequest` inputs, returning allow/deny decisions, violation lists, and JSON patches for mutations. Loads built-in default policies on construction.

## Key Files

| File | Description |
|------|-------------|
| `engine.go` | `Engine`, `Policy`, `Rule`, `EvaluationRequest`, `EvaluationResult`, `PolicyViolation`, `JSONPatch` types and engine methods |
| `engine_test.go` | Unit tests for the engine |

## For AI Agents

### Working In This Directory
- Each rule's Rego is compiled per evaluation via `rego.New(...).PrepareForEval(ctx)` and queried as `data.kube_policies.evaluate`. Rules must define `package kube_policies` and produce a result map with keys `allowed` (bool), `message` (string, optional), `path` (string, optional), and `patches` (list, optional). This is the contract — examples in `examples/policies/` follow it.
- The engine guards `policies` map with `sync.RWMutex`. Reads (`Evaluate`, `ListPolicies`) take RLock; writes (`LoadPolicy`, `RemovePolicy`) take Lock. Preserve this discipline.
- A rule that fails to evaluate is **logged and skipped**, not propagated as an error — preventing one bad policy from taking down admission control. Do not change this without a migration story.
- `loadDefaultPolicies` ships an embedded `security-baseline` policy denying `spec.securityContext.privileged: true`. Add to this list cautiously; default-deny rules can break clusters on upgrade.
- Mutations: rule-emitted `patches` are aggregated across all rules into `EvaluationResult.Patches` (a `[]JSONPatch`) and serialized by the admission handler. Rules that produce conflicting patches will produce ill-defined results — document and test any cross-rule mutation scenarios.

### Testing Requirements
- Unit tests in `engine_test.go`. End-to-end coverage exercises Rego evaluation through the admission handler.

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
