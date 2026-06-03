# Runbook — Webhook Outage

> NIST SP 800-53 Rev 5: IR-4, CP-10, SI-4 · IRM-WU-05
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

---

## Blast radius

KP's **validate webhook** uses `failurePolicy: Fail` (fail-closed). When the webhook is
down or unreachable:

- **All new admission requests to the cluster are denied.** Existing running workloads are
  unaffected (admission is evaluated only on create/update operations).
- Operators cannot deploy new workloads, apply ConfigMaps, create Secrets, or perform any
  operation that triggers admission review.
- The `KubePoliciesDown` alert fires immediately when the webhook's `up` metric equals 0.

The **mutate webhook** uses `failurePolicy: Ignore`: if the mutate endpoint is down, objects
are admitted without mutations (same security implication as a fail-open event — see
[fail-open-event.md](fail-open-event.md)).

---

## Detection

**Alerts:**

| Alert | Condition | Meaning |
|---|---|---|
| `KubePoliciesDown` | `up{job="kube-policies-admission-webhook"} == 0` | No webhook replicas are scrape-reachable — likely all pods down |
| `KubePoliciesWebhookNotReady` | Readiness probe failures | Pods exist but are not ready to serve |
| `KubePoliciesNoTraffic` | `rate(kube_policies_admission_requests_total[10m]) == 0` | No admission traffic for 10 minutes (may indicate webhook removed or no workload activity) |

**PromQL — confirm scrape target is down:**

```promql
up{job="kube-policies-admission-webhook"}
```

---

## Triage

### 1. Check pod state

```bash
kubectl get pods -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook
```

Look for: `Running`, `CrashLoopBackOff`, `ImagePullBackOff`, `Pending`, `OOMKilled`.

### 2. Describe pods for events

```bash
kubectl describe pods -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  | grep -A10 "Events:"
```

### 3. Check logs of the most recent pod (including previous containers)

```bash
# Current container logs:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100

# Previous container if CrashLoopBackOff:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --previous --tail=100
```

### 4. Check rollout status

```bash
kubectl rollout status deployment/kube-policies-admission-webhook \
  -n kube-policies-system
kubectl rollout history deployment/kube-policies-admission-webhook \
  -n kube-policies-system
```

### 5. Check readiness probe

The admission webhook serves a TLS-aware `/readyz` endpoint (set atomically after the TLS
listener binds). If the readiness probe is failing:

```bash
# Check whether /readyz is responding inside the pod:
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- --no-check-certificate 'https://localhost:8443/readyz'
```

### 6. Check the ValidatingWebhookConfiguration

```bash
kubectl get validatingwebhookconfiguration kube-policies-webhook \
  -o jsonpath='{.webhooks[0].failurePolicy}'
# Expected: Fail

kubectl get validatingwebhookconfiguration kube-policies-webhook \
  -o jsonpath='{.webhooks[0].clientConfig}'
```

Verify the `service` reference and `caBundle` are correct, and that the `namespaceSelector`
matches the `kube-policies-system` namespace.

---

## Recovery

### Option A — Rollout restart (transient crash / OOM)

```bash
kubectl rollout restart deployment/kube-policies-admission-webhook \
  -n kube-policies-system
kubectl rollout status deployment/kube-policies-admission-webhook \
  -n kube-policies-system --timeout=5m
```

### Option B — Roll back a bad deployment

```bash
# Identify the last known-good revision:
kubectl rollout history deployment/kube-policies-admission-webhook \
  -n kube-policies-system

# Roll back to it:
kubectl rollout undo deployment/kube-policies-admission-webhook \
  -n kube-policies-system
kubectl rollout status deployment/kube-policies-admission-webhook \
  -n kube-policies-system --timeout=5m
```

### Option C — Helm upgrade with corrected values

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --values your-corrected-values.yaml \
  --wait
```

### Option D — Full reinstall (all replicas lost, image unavailable)

Follow [docs/runbooks/disaster-recovery.md#all-replicas-loss](../../runbooks/disaster-recovery.md#all-replicas-loss).

---

## Break-glass: safely disabling the ValidatingWebhookConfiguration

> **This is a break-glass procedure.** Disabling the validate webhook removes
> fail-closed admission control. It MUST be documented as a deviation in the POA&M
> before execution and MUST be reverted as soon as KP is recovered. Notify the
> Incident Commander and ISSO before proceeding.

If the cluster must continue accepting workloads and KP cannot be recovered quickly, the
validate webhook can be temporarily relaxed or removed:

**Step 1 — Annotate the configuration to mark it as deliberately disabled:**

```bash
kubectl annotate validatingwebhookconfiguration kube-policies-webhook \
  kube-policies.io/temporarily-disabled="true" \
  kube-policies.io/disabled-by="$(kubectl config current-context)" \
  --overwrite
```

**Step 2 — Change failurePolicy to Ignore (soft disable — webhook still called if up):**

```bash
kubectl patch validatingwebhookconfiguration kube-policies-webhook \
  --type='json' \
  -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
```

**Step 3 — If complete removal is required (hard disable):**

```bash
# CAUTION: saves the current configuration first.
kubectl get validatingwebhookconfiguration kube-policies-webhook \
  -o yaml > /tmp/kube-policies-webhook-backup.yaml

kubectl delete validatingwebhookconfiguration kube-policies-webhook
```

**Step 4 — Record the deviation in the POA&M immediately.**

**Step 5 — After KP recovery, restore the webhook:**

```bash
# If failurePolicy was relaxed (Step 2):
kubectl patch validatingwebhookconfiguration kube-policies-webhook \
  --type='json' \
  -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Fail"}]'

# If the webhook was deleted (Step 3):
kubectl apply -f /tmp/kube-policies-webhook-backup.yaml
# Or re-apply via Helm:
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values --wait
```

---

## Recovery / Verification

1. Confirm all pods are running and ready:

   ```bash
   kubectl get pods -n kube-policies-system \
     -l app.kubernetes.io/component=admission-webhook
   kubectl rollout status deployment/kube-policies-admission-webhook \
     -n kube-policies-system
   ```

2. Confirm the `up` metric is 1:

   ```promql
   up{job="kube-policies-admission-webhook"}
   ```

3. Confirm `KubePoliciesDown` has resolved in Alertmanager.

4. Confirm `failurePolicy: Fail` is restored on the validate webhook:

   ```bash
   kubectl get validatingwebhookconfiguration kube-policies-webhook \
     -o jsonpath='{.webhooks[0].failurePolicy}'
   ```

5. Run a smoke test:

   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

6. Confirm `kube_policies_admission_requests_total` is incrementing.

7. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).
   Record any break-glass deviations taken and confirm the POA&M entry is opened.

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- Disaster recovery runbook: [docs/runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md)
- Cert expiry runbook (if TLS caused the outage): [cert-expiry.md](cert-expiry.md)
- Fail-open runbook (if mutate path was also affected): [fail-open-event.md](fail-open-event.md)
- Contingency plan: [docs/contingency-plan.md](../../contingency-plan.md)
- NIST SP 800-53 Rev 5: IR-4, CP-10, SI-4; FedRAMP Moderate baseline.
