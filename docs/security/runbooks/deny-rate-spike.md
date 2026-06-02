# Runbook — High Deny-Rate Spike

> NIST SP 800-53 Rev 5: IR-4, SI-4 · IRM-WU-02
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

A sudden spike in denied admission requests can indicate a newly deployed or modified policy
that is too restrictive, a misconfigured workload rollout, or — in the worst case — an
attacker injecting a policy designed to block legitimate operations. This runbook covers
triage, containment, and recovery.

---

## Detection

**Alert:** `KubePoliciesHighDenyRate`

**PromQL (rate of denied requests across all operations, 5-minute window):**

```promql
rate(kube_policies_admission_requests_total{status="denied"}[5m]) > 0.1
```

Check the deny rate broken down by operation and reason:

```promql
rate(kube_policies_admission_requests_total{status="denied"}[5m])
```

---

## Triage

### 1. Confirm the alert and quantify scope

```bash
# How many denials in the last 10 minutes?
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_admission_requests_total

# Or query Prometheus directly:
# rate(kube_policies_admission_requests_total{status="denied"}[10m])
```

### 2. Identify which policies are denying

The `reason` label on `kube_policies_admission_requests_total` carries the policy reason
string. Query for the top reasons:

```promql
topk(10, rate(kube_policies_admission_requests_total{status="denied"}[5m]))
```

### 3. Query the audit log for denied request details

```bash
# Tail the admission-webhook audit log (file backend):
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100 \
  | grep '"decision":"DENY"'

# Filter by namespace if the spike is namespace-scoped:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=200 \
  | grep '"decision":"DENY"' | grep '"namespace":"<target-ns>"'
```

### 4. Identify recently changed policies

```bash
# List policies ordered by last modification time:
kubectl get policies -A \
  --sort-by='.metadata.creationTimestamp' -o wide

# Check if a policy was recently created or updated:
kubectl get policies -A \
  -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.metadata.resourceVersion}{"\n"}{end}'
```

### 5. Check policy-manager reconcile logs

```bash
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=policy-manager \
  --tail=100 \
  | grep -E "UPSERT|DELETE|reconcile"
```

### 6. Assess security context

- Are the denials affecting workloads that _should_ be allowed? → probable policy
  misconfiguration.
- Are the denials blocking a rollout that involves a new image or namespace? → probable
  supply-chain or namespace-isolation policy conflict.
- Are the denials affecting previously stable workloads with no corresponding policy change?
  → escalate to Security Responder; possible policy tampering or injection.

---

## Containment

**Option A — Roll back the offending policy to a known-good version**

```bash
# Identify the policy name from audit logs or the metric reason label:
POLICY_NAME=<policy-name>
NAMESPACE=<namespace-or-cluster-scoped>

# Describe the current policy to see its spec:
kubectl describe policy "${POLICY_NAME}" -n "${NAMESPACE}"

# Apply the last known-good version from version control:
kubectl apply -f path/to/known-good-policy.yaml

# Or delete the policy if it should not exist:
kubectl delete policy "${POLICY_NAME}" -n "${NAMESPACE}"
```

**Option B — Create a scoped PolicyException for the affected workload**

Use this when the policy is correct but the workload needs a temporary exception while the
root cause is investigated. Scope the exception as narrowly as possible.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: kube-policies.io/v1alpha1
kind: PolicyException
metadata:
  name: temp-exception-<ticket-id>
  namespace: <affected-namespace>
spec:
  policyId: <policy-id>
  resources:
    - apiGroups: [""]
      kinds: ["Pod"]
      namespaces: ["<affected-namespace>"]
  justification: "Temporary exception pending investigation of INC-XXXX — expires <date>"
EOF
```

**Document any exception in the POA&M immediately.**

---

## Recovery / Verification

1. Confirm the deny rate has returned to baseline:

   ```bash
   # PromQL — should drop to near zero or pre-spike level:
   rate(kube_policies_admission_requests_total{status="denied"}[5m])
   ```

2. Confirm the blocked workloads are now being admitted:

   ```bash
   kubectl apply -f <previously-failing-manifest> --dry-run=server
   ```

3. Confirm the `KubePoliciesHighDenyRate` alert has resolved in Alertmanager.

4. If a PolicyException was created, schedule its removal and create a POA&M entry tracking
   the root-cause fix.

5. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).

6. If the spike was caused by policy tampering or an unexpected policy injection, escalate to
   SEV1/SEV2 and notify the Security Responder.

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- Audit runbook (if audit records were also affected): [audit-pipeline-loss.md](audit-pipeline-loss.md)
- NIST SP 800-53 Rev 5: IR-4, SI-4; FedRAMP Moderate baseline.
