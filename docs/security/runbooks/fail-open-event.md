# Runbook — Fail-Open Event (Mutate Path Bypassed)

> NIST SP 800-53 Rev 5: IR-4, SI-4, SI-7 · IRM-WU-03
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

---

## Security implication

The KP admission webhook **mutate path fails open by design**: when the policy engine returns
an error (or patch serialization fails), the `MutateHandler` admits the request WITHOUT
applying mutations, and increments `kube_policies_admission_fail_open_total`. This is
intentional — the `MutatingWebhookConfiguration` also uses `failurePolicy: Ignore` — so a
broken mutate webhook never blocks cluster operations.

**The security consequence is that mutation-based controls are bypassed.** Objects are
admitted in their original, un-mutated form. Depending on which mutations are configured
(label injection, security-context defaults, image-digest pinning), this may mean:

- Security labels or annotations are absent.
- Security-context defaults (runAsNonRoot, readOnlyRootFilesystem, etc.) are not injected.
- Image references are not pinned to digest.

The **validate path is NOT affected**: validation uses `failurePolicy: Fail` at the
`ValidatingWebhookConfiguration` level and fails closed (denies) in-process on engine
error. Only mutation is bypassed.

> **Important accuracy note:** `KUBE_POLICIES_POLICY_FAILURE_MODE` (the `policy.failure_mode`
> config field) governs the policy _engine_'s per-rule error handling and applies equally to
> both paths during normal evaluation. It does NOT override the hard-coded mutate
> fail-open behavior in `MutateHandler`; that behavior is locked by
> `TestMutateHandler_FailSafeOnEngineError`. Setting `failure_mode=fail-closed` does NOT
> prevent fail-open events on the mutate path. The correct containment is to fix the engine
> error (root cause) and/or tighten the `MutatingWebhookConfiguration` `failurePolicy`.

---

## Detection

**Alert:** `KubePoliciesFailOpenActive`

**PromQL (fail-open events firing in the last 5 minutes):**

```promql
rate(kube_policies_admission_fail_open_total[5m]) > 0
```

Check which operation is failing:

```promql
rate(kube_policies_admission_fail_open_total{operation="mutate"}[5m])
```

Check accompanying engine errors (the fail-open is always caused by an underlying error):

```promql
rate(kube_policies_system_errors_total[5m])
```

---

## Triage

### 1. Quantify the fail-open rate

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_admission_fail_open_total
```

### 2. Identify the underlying engine error

Every fail-open event is caused by a prior engine error. Check `kube_policies_system_errors_total`
for the `error_type`:

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_system_errors_total
```

Also check the webhook logs for the error detail:

```bash
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100 \
  | grep -E '"level":"error"|evaluation_error|patch_marshal_error'
```

See [high-error-rate.md](high-error-rate.md) for the triage action mapped to each
`error_type`.

### 3. Assess which objects were admitted without mutation

```bash
# Audit log — look for decisions recorded as ERROR with operation=mutate:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=200 \
  | grep '"operation":"mutate"' | grep '"decision":"ERROR"'
```

Identify the affected namespaces, resource kinds, and requestors. Determine which mutations
were bypassed (image-digest pinning? security-context injection?) and assess the security
impact.

### 4. Assess impact severity

- Is the fail-open rate sustained or a transient spike?
- Are critical namespaces (production, `kube-system`) affected?
- Are security-context or image-pinning mutations being bypassed?

If the answer to any of these is yes and the rate is sustained, treat as **SEV2** and
escalate to the Security Responder.

---

## Containment

The fail-open behavior cannot be overridden by `policy.failure_mode` configuration.
Containment options, in order of invasiveness:

### Option A — Fix the engine error (preferred)

Identify and fix the root cause of `kube_policies_system_errors_total`. See
[high-error-rate.md](high-error-rate.md) for per-error-type remediation. Once the engine
error is resolved, fail-open events stop.

### Option B — Restart the admission-webhook pods

If the error is transient (e.g. a one-time OPA bundle parse failure), a rolling restart
clears it:

```bash
kubectl rollout restart deployment/kube-policies-admission-webhook \
  -n kube-policies-system
kubectl rollout status deployment/kube-policies-admission-webhook \
  -n kube-policies-system
```

### Option C — Scale up to isolate a bad replica

If only one replica is producing errors:

```bash
# Identify the failing pod:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --prefix \
  | grep -E 'evaluation_error|patch_marshal_error'

# Delete the failing pod — the Deployment replaces it:
kubectl delete pod <failing-pod-name> -n kube-policies-system
```

### Option D — Tighten MutatingWebhookConfiguration failurePolicy (last resort)

Changing `failurePolicy` from `Ignore` to `Fail` on the `MutatingWebhookConfiguration`
stops unevaluated objects from being admitted, at the cost of blocking all mutation
requests when the engine is broken. This is a **deviation** — document it in the POA&M.

```bash
# CAUTION: this will block admission if the mutate engine is unhealthy.
# Document as a deviation in the POA&M before executing.
kubectl patch mutatingwebhookconfiguration kube-policies-webhook \
  --type='json' \
  -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Fail"}]'
```

Revert to `Ignore` immediately after the engine error is resolved:

```bash
kubectl patch mutatingwebhookconfiguration kube-policies-webhook \
  --type='json' \
  -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
```

---

## Recovery / Verification

1. Confirm `kube_policies_admission_fail_open_total` has stopped incrementing:

   ```promql
   rate(kube_policies_admission_fail_open_total[5m]) == 0
   ```

2. Confirm `kube_policies_system_errors_total` has returned to baseline:

   ```promql
   rate(kube_policies_system_errors_total[5m]) == 0
   ```

3. Confirm the `KubePoliciesFailOpenActive` alert has resolved.

4. Run a smoke test to confirm the mutate path is functioning:

   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

5. Review objects admitted without mutation during the event. If security-context or
   image-pinning mutations were skipped, assess whether those objects need to be deleted
   and re-admitted, or whether a compensating control (e.g. PSS enforcement, image policy)
   already covers the gap.

6. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).
   Record the engine error type, duration, affected objects, and any compensating controls
   confirmed active during the event.

---

## Post-incident review checklist

- [ ] Root cause of engine error identified and fixed.
- [ ] All objects admitted without mutation reviewed; remediation taken where needed.
- [ ] `MutatingWebhookConfiguration failurePolicy` restored to `Ignore` (if Option D was used).
- [ ] POA&M updated if a new gap was identified.
- [ ] Runbook or alert threshold updated if the detection delay was unacceptable.

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- High-error-rate runbook (per error_type triage): [high-error-rate.md](high-error-rate.md)
- `internal/admission/controller.go` — `MutateHandler` fail-open logic
- NIST SP 800-53 Rev 5: IR-4, SI-4, SI-7; FedRAMP Moderate baseline.
