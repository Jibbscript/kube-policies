<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# admission

## Purpose
HTTP handlers for Kubernetes admission webhook requests. Decodes `admissionv1.AdmissionReview` payloads, invokes the policy engine, builds the response, emits an audit event, and records Prometheus metrics. Handles both validation and mutation flows with deliberately different fail-safe behavior.

## Key Files

| File | Description |
|------|-------------|
| `controller.go` | `Controller` struct + `ValidateHandler` and `MutateHandler` Gin handlers |
| `controller_test.go` | Unit tests for the controller |

## For AI Agents

### Working In This Directory
- Fail-safe semantics differ by handler: on policy-engine error, **validate denies** (HTTP 200 with `Allowed: false`) while **mutate allows without patches**. This is intentional — do not unify them.
- Mutations must be returned as a JSON-encoded `[]policy.JSONPatch` in `response.Patch` with `PatchType = admissionv1.PatchTypeJSONPatch`. If marshaling fails, fall back to allowing without mutation.
- Always emit audit events through `audit.Logger.LogDecision` regardless of decision (allow/deny/error) and always increment metrics — observability holes here are silent failures in production.
- Construct `admissionv1.AdmissionReview` responses with `UID: req.UID` echoed back; the API server requires this.

### Testing Requirements
- Unit tests in `controller_test.go`. Integration coverage in `test/integration/admission_webhook_test.go`.
- Run via `go test ./internal/admission/...` or `make test-unit`.

### Common Patterns
- Inject `*policy.Engine`, `*audit.Logger`, `*metrics.Collector`, and `*zap.Logger` via `NewController` — avoid package-level state.
- Use `time.Since(startTime)` to populate `auditCtx.ProcessingTime` and observe in the evaluation duration histogram.

## Dependencies

### Internal
- `internal/metrics` — request counter, evaluation duration histogram
- `internal/policy` — `Engine`, `EvaluationRequest`, `EvaluationResult`
- `pkg/audit` — `Logger`, `Context`

### External
- `github.com/gin-gonic/gin`
- `go.uber.org/zap`
- `k8s.io/api/admission/v1`
- `k8s.io/apimachinery/pkg/apis/meta/v1`

<!-- MANUAL: -->
