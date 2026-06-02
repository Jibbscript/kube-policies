# Runbook — TLS Certificate Expiry

> NIST SP 800-53 Rev 5: IR-4, SC-12, SC-17 · IRM-WU-04
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

---

## Impact

When a KP TLS certificate expires the apiserver cannot establish a TLS connection to the
admission webhook. The result depends on the `ValidatingWebhookConfiguration` `failurePolicy`:

- **Validate webhook** (`failurePolicy: Fail`): all new admission requests to the cluster
  are **denied** — the cluster is effectively locked out of new workloads.
- **Mutate webhook** (`failurePolicy: Ignore`): mutation calls fail open; objects are
  admitted without mutations.

A certificate expiry on the policy-manager or dashboard does not directly affect admission,
but it breaks the management API and dashboard TLS endpoint.

---

## Detection

**Alerts (in order of urgency):**

| Alert | Condition | Severity |
|---|---|---|
| `KubePoliciesCertExpiringSoon` | `kube_policies_tls_cert_expiry_seconds - time() < 7 * 86400` | Warning |
| `KubePoliciesCertExpiringCritical` | `kube_policies_tls_cert_expiry_seconds - time() < 1 * 86400` | Critical |
| `KubePoliciesCertExpired` | `kube_policies_tls_cert_expiry_seconds - time() <= 0` | Critical |

**PromQL — time remaining on each component's served certificate (seconds):**

```promql
kube_policies_tls_cert_expiry_seconds{component=~"admission-webhook|policy-manager|dashboard"} - time()
```

A value ≤ 0 means the certificate is already expired.

---

## Triage

### 1. Check which component is affected

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_tls_cert_expiry_seconds
```

### 2. Inspect the mounted certificate directly

```bash
# Admission webhook:
kubectl -n kube-policies-system exec \
  deploy/kube-policies-admission-webhook -- \
  cat /etc/certs/tls.crt \
  | openssl x509 -noout -enddate -subject

# Policy manager:
kubectl -n kube-policies-system exec \
  deploy/kube-policies-policy-manager -- \
  cat /etc/certs/tls.crt \
  | openssl x509 -noout -enddate -subject
```

### 3. Check if cert-manager is managing renewal

```bash
kubectl get certificate -n kube-policies-system
kubectl describe certificate kube-policies-webhook-cert \
  -n kube-policies-system
```

If the `Certificate` object shows `Ready: False` with a reason of `Expired` or
`RenewalFailed`, cert-manager renewal has failed and manual intervention is required.

### 4. Check the webhook caBundle matches the current CA

```bash
kubectl get validatingwebhookconfiguration kube-policies-webhook \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' \
  | base64 -d | openssl x509 -noout -enddate -subject
```

If the caBundle cert is different from the mounted cert, the webhook configuration is stale.

---

## Rotation

For the full certificate rotation procedure (cert-manager automatic renewal, manual
regeneration via the chart `certgen` Job, and CA bundle patching), follow the dedicated
runbook:

**[docs/runbooks/cert-rotation.md](../../runbooks/cert-rotation.md)**

The webhook TLS certificate is managed through the chart template at:
`charts/kube-policies/templates/admission-webhook-tls.yaml`

Emergency path summary (if the certificate is already expired):

```bash
# 1. Force cert-manager renewal (if cert-manager is in use):
kubectl -n kube-policies-system delete secret kube-policies-webhook-tls
# cert-manager recreates the Secret automatically.

# 2. If cert-manager is NOT in use — trigger chart certgen Job:
kubectl delete job kube-policies-certgen -n kube-policies-system
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values

# 3. Patch the caBundle in the ValidatingWebhookConfiguration:
CA_BUNDLE=$(kubectl get secret kube-policies-webhook-tls \
  -n kube-policies-system \
  -o jsonpath='{.data.ca\.crt}')
kubectl patch validatingwebhookconfiguration kube-policies-webhook \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\
\"value\":\"${CA_BUNDLE}\"}]"
```

---

## Recovery / Verification

1. Confirm the certificate expiry gauge has jumped forward (value should be > 7 days in
   seconds = 604800):

   ```promql
   kube_policies_tls_cert_expiry_seconds{component="admission-webhook"} - time()
   ```

2. Verify the served certificate end-date directly:

   ```bash
   kubectl -n kube-policies-system exec \
     deploy/kube-policies-admission-webhook -- \
     cat /etc/certs/tls.crt \
     | openssl x509 -noout -enddate
   ```

3. Confirm the `KubePoliciesCertExpired` / `KubePoliciesCertExpiringCritical` alerts have
   resolved in Alertmanager (may take up to one evaluation interval — typically 1 minute).

4. Run a smoke test to confirm the webhook is accepting admission requests:

   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

5. If the certificate was expired long enough that admission was blocked, check whether any
   emergency `failurePolicy` changes were made and revert them:

   ```bash
   kubectl get validatingwebhookconfiguration kube-policies-webhook \
     -o jsonpath='{.webhooks[0].failurePolicy}'
   # Expected: Fail
   ```

6. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- Full cert rotation runbook: [docs/runbooks/cert-rotation.md](../../runbooks/cert-rotation.md)
- Webhook outage runbook (if admission was blocked): [webhook-outage.md](webhook-outage.md)
- Webhook TLS chart template: `charts/kube-policies/templates/admission-webhook-tls.yaml`
- NIST SP 800-53 Rev 5: IR-4, SC-12, SC-17; FedRAMP Moderate baseline.
