# Runbook — High Error Rate

> NIST SP 800-53 Rev 5: IR-4, SI-4 · IRM-WU-07
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

---

## Overview

`kube_policies_system_errors_total{component,error_type}` counts every admission-path error
emitted by the controller. A sustained high rate indicates a systemic problem and is the
proximate cause of fail-open events on the mutate path (see
[fail-open-event.md](fail-open-event.md)). Errors on the validate path cause denials, not
fail-open.

The four `error_type` values, their source in `internal/admission/controller.go`, and their
triage actions are enumerated below.

---

## Detection

**Alert:** `KubePoliciesHighErrorRate`

**PromQL — error rate by type (5-minute window):**

```promql
rate(kube_policies_system_errors_total[5m])
```

**PromQL — broken down by error_type:**

```promql
rate(kube_policies_system_errors_total{error_type=~"decode_error|nil_request|evaluation_error|patch_marshal_error"}[5m])
```

---

## Error types and triage

### `decode_error`

**What it means.** The admission webhook received a request body that could not be decoded
as a valid `AdmissionReview` JSON object. Emitted by both `ValidateHandler` and
`MutateHandler` before any policy evaluation occurs.

**Source:** `ctx.ShouldBindJSON(&admissionReview)` fails.

**Triage:**

```bash
# Check webhook logs for the raw decode error:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100 \
  | grep '"reason":"decode_error"'
```

**Likely causes:**
- An unexpected client (not the apiserver) is sending malformed requests to `:8443`.
- A proxy or load balancer is mangling the request body.
- The apiserver and webhook are running incompatible API versions.

**Action:**
1. Confirm the source IP of the malformed requests from the audit log or webhook logs.
2. If requests are coming from an unexpected source, review the `ValidatingWebhookConfiguration`
   `namespaceSelector` and `objectSelector` to ensure only the apiserver is calling the webhook.
3. If requests are from the apiserver, check for Kubernetes version skew.

---

### `nil_request`

**What it means.** The decoded `AdmissionReview` object has a `nil` `Request` field —
the outer envelope parsed but the inner request was absent. This should be extremely rare
in production (it indicates a malformed request from the apiserver or a test client).

**Source:** `admissionReview.Request == nil` check.

**Triage:**

```bash
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100 \
  | grep '"reason":"nil_request"'
```

**Likely causes:**
- A test harness or integration probe sending incomplete `AdmissionReview` objects.
- An incompatible apiserver version constructing requests without a `Request` field.

**Action:**
1. Identify the caller from the log source IP.
2. If from a test client or health-check probe: update the probe to use `/readyz` or `/healthz`
   instead of the admission endpoint.
3. If from the apiserver: check Kubernetes version compatibility.

---

### `evaluation_error`

**What it means.** The policy engine (`policy.Evaluator`) returned an error during
evaluation. This is the most common cause of fail-open events on the mutate path and of
denials (returning a 500) on the validate path.

**Source:** `c.policyEngine.Evaluate(...)` returns a non-nil error.

**Triage:**

```bash
# Find evaluation_error log lines with the error detail:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=200 \
  | grep '"reason":"evaluation_error"'

# Also check policy-manager for OPA/Rego compilation errors:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=policy-manager \
  --tail=100 \
  | grep -E 'error|compile|rego'
```

**Likely causes:**
- A newly deployed Policy CR contains invalid Rego that the engine cannot compile.
- The OPA/Rego bundle failed to load (missing data, malformed bundle).
- An in-memory registry inconsistency (e.g. after a rapid sequence of Policy upserts).
- A panic recovered by the engine that produces an error return.

**Action:**
1. Identify the failing policy from the error message in the logs.
2. Validate the Rego policy locally:
   ```bash
   opa check <policy-file.rego>
   opa test <policy-file.rego> <test-file.rego>
   ```
3. Roll back the offending Policy CR to its last known-good version:
   ```bash
   kubectl apply -f path/to/known-good-policy.yaml
   ```
4. If the error is in the bundled default policies, this is a code bug — file an issue and
   roll back the admission-webhook image to the previous digest.

---

### `patch_marshal_error`

**What it means.** The policy engine returned a set of JSON patches but `json.Marshal` on
the patch slice failed. The mutate handler fails open (admits without mutations) and
increments `kube_policies_admission_fail_open_total`.

**Source:** `json.Marshal(decision.Patches)` fails in `MutateHandler`.

**Triage:**

```bash
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100 \
  | grep '"reason":"patch_marshal_error"'
```

**Likely causes:**
- A policy is returning a patch value that contains a non-JSON-serialisable type (e.g. a
  Go `chan`, `func`, or `interface{}` holding a cyclic reference — unusual in Rego-generated
  patches but possible if the engine wraps them incorrectly).
- A bug in the Go bridge between the OPA evaluation result and the patch-slice construction.

**Action:**
1. Identify the policy and the specific patch from the log error.
2. If the patch is produced by a custom Policy CR, fix the Rego to produce valid JSON-patch
   operations (RFC 6902: `op`, `path`, `value` must all be JSON-serialisable).
3. If the patch is produced by a bundled default policy, this is a code bug — roll back the
   admission-webhook image to the previous digest and file an issue.
4. Monitor `kube_policies_admission_fail_open_total` to confirm fail-open events stop after
   the fix.

---

## Containment

If `evaluation_error` or `patch_marshal_error` rates are high and causing sustained
fail-open or denial storms:

1. Roll back the offending Policy CR (see above).
2. If the error is in the webhook binary itself, roll back the Deployment image:
   ```bash
   kubectl rollout undo deployment/kube-policies-admission-webhook \
     -n kube-policies-system
   ```
3. If the mutate path is producing fail-open events, follow
   [fail-open-event.md](fail-open-event.md) §Containment for escalation options.

---

## Recovery / Verification

1. Confirm error rate has returned to zero:

   ```promql
   rate(kube_policies_system_errors_total[5m]) == 0
   ```

2. Confirm `KubePoliciesHighErrorRate` has resolved in Alertmanager.

3. Confirm `kube_policies_admission_fail_open_total` is no longer incrementing (if mutate
   was affected):

   ```promql
   rate(kube_policies_admission_fail_open_total[5m]) == 0
   ```

4. Run a smoke test:

   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

5. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- Fail-open runbook: [fail-open-event.md](fail-open-event.md)
- Deny-rate-spike runbook: [deny-rate-spike.md](deny-rate-spike.md)
- `internal/admission/controller.go` — error_type emission points
- NIST SP 800-53 Rev 5: IR-4, SI-4; FedRAMP Moderate baseline.
