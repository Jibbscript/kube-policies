# Runbook — Load / DoS Response

> NIST SP 800-53 Rev 5: IR-4, SC-5, SI-4 · NET-WU-14/15, RES-WU-17
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

---

## Overview

KP's admission webhook sits on the cluster's critical admission path. A request flood — from
a runaway controller, a misconfigured CI pipeline, or a deliberate DoS — can exhaust webhook
CPU and memory, cause `kube_policies_admission_evaluation_duration_seconds_bucket` latency
spikes, and eventually degrade admission throughput for the entire cluster.

KP ships a configurable rate-limiting / DoS-protection middleware
(`internal/middleware/ratelimit.go`) applied to all three gin routers. Limits are
**per-process (per replica)**: the effective cluster-wide ceiling is approximately
`limit × replicaCount`. Default values:

| Parameter | Default | Config key |
|---|---|---|
| Requests per second (token bucket) | 50 req/s | `security.ratelimit.requests_per_second` |
| Burst depth | 100 requests | `security.ratelimit.burst` |
| Max concurrent in-flight | 100 | `security.ratelimit.max_concurrent` |
| Max body bytes | 3 MiB (3145728) | `security.ratelimit.max_body_bytes` |
| Max stream connections (SSE) | 100 | `security.ratelimit.max_stream_connections` |

Requests that exceed these limits receive HTTP 429. Oversized bodies receive HTTP 413.

---

## Detection

**Alerts (DoS / load):**

| Alert | Meaning |
|---|---|
| `KubePoliciesHighAdmissionRequestRate` | Admission request rate significantly above baseline |
| `RateLimitSurge` | HTTP 429 rate-limit responses rising — limiter is active |
| `AdmissionLatencyHigh` / `AdmissionLatencyCritical` | `kube_policies_admission_evaluation_duration_seconds_bucket` p99 above threshold |

**PromQL — overall admission request rate:**

```promql
rate(kube_policies_admission_requests_total[1m])
```

**PromQL — rate-limited requests (429 responses):**

```promql
rate(kube_policies_http_rate_limited_total[1m])
```

**PromQL — admission evaluation latency (p99, 5-minute window):**

```promql
histogram_quantile(0.99,
  rate(kube_policies_admission_evaluation_duration_seconds_bucket[5m])
)
```

---

## Triage

### 1. Confirm the rate-limiter is active

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_http_rate_limited_total
```

A rising counter confirms the middleware is enforcing limits. If the counter is zero but
latency is high, the flood is within the rate limit — see §Triage step 4.

### 2. Identify the source of the flood

Check the admission-webhook access logs for the source IP and user-agent of high-volume
callers:

```bash
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=200 \
  | grep -E '"operation":"(validate|mutate)"' \
  | jq -r '.sourceIP' \
  | sort | uniq -c | sort -rn | head -20
```

> Note: `sourceIP` in the admission audit log is the apiserver / kube-proxy hop, not the
> originating client. Use the Kubernetes apiserver audit log (`docs/audit/cluster-audit-policy.md`)
> to trace the originating `userInfo` for high-volume requestors.

### 3. Identify which operation is flooding

```bash
rate(kube_policies_admission_requests_total{operation="validate"}[1m])
rate(kube_policies_admission_requests_total{operation="mutate"}[1m])
```

A flood exclusively on `mutate` may indicate a runaway controller reconcile loop.

### 4. Check pod resource consumption

```bash
kubectl top pods -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook
kubectl describe pods -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  | grep -A5 "Limits:"
```

If CPU is pegged at the container limit, the webhook may be OOM-killed shortly — check the
HPA status if enabled:

```bash
kubectl get hpa -n kube-policies-system
```

### 5. Check for concurrent-connection saturation

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep -E 'concurrent|stream'
```

---

## Containment

### Option A — Tighten rate limits (reduce tokens/burst)

Reduce the per-replica request rate and burst to lower the ceiling of admitted load. This
change requires a Helm upgrade and a rolling restart.

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values \
  --set security.ratelimit.requests_per_second=20 \
  --set security.ratelimit.burst=40 \
  --set security.ratelimit.max_concurrent=50
```

### Option B — Scale out replicas

Add replicas to distribute load. Each replica has its own independent rate limiter; the
effective cluster-wide ceiling scales proportionally.

```bash
kubectl scale deployment kube-policies-admission-webhook \
  --replicas=4 \
  -n kube-policies-system
```

Or via Helm (if HPA is not enabled):

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values \
  --set admissionWebhook.replicaCount=4
```

### Option C — Enable or tune the HPA

If HPA is configured but not scaling fast enough:

```bash
kubectl describe hpa kube-policies-admission-webhook \
  -n kube-policies-system
```

Adjust `minReplicas` / `maxReplicas` / target CPU via `helm upgrade --set hpa.*`.

### Option D — Identify and stop the flood source

If the flood source is a specific workload or controller:

```bash
# Identify the namespace and resource generating the most admission events:
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=500 \
  | jq -r '.namespace' \
  | sort | uniq -c | sort -rn | head -10
```

If a specific controller is caught in a reconcile loop, consider temporarily pausing it:

```bash
kubectl scale deployment <runaway-controller> \
  --replicas=0 \
  -n <controller-namespace>
```

Document as a deviation if this affects a production workload.

---

## Recovery / Verification

1. Confirm the admission request rate has returned to baseline:

   ```promql
   rate(kube_policies_admission_requests_total[1m])
   ```

2. Confirm admission latency p99 is within SLO:

   ```promql
   histogram_quantile(0.99,
     rate(kube_policies_admission_evaluation_duration_seconds_bucket[5m])
   )
   ```

3. Confirm `kube_policies_http_rate_limited_total` has stopped rising rapidly.

4. Confirm all DoS-related alerts have resolved in Alertmanager.

5. If rate limits were tightened in Option A, evaluate whether the tighter limits are safe
   for normal operation and revert or make them permanent as appropriate:

   ```bash
   # Revert to defaults if the flood has stopped:
   helm upgrade kube-policies charts/kube-policies \
     --namespace kube-policies-system \
     --reuse-values \
     --set security.ratelimit.requests_per_second=50 \
     --set security.ratelimit.burst=100 \
     --set security.ratelimit.max_concurrent=100
   ```

6. Run a smoke test:

   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

7. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).
   If the flood was from a deliberate external source, escalate to Security Responder and
   assess whether a CISA / US-CERT report is warranted.

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- Webhook outage runbook (if load caused an outage): [webhook-outage.md](webhook-outage.md)
- Rate-limit config: `internal/config/config.go` `RateLimitConfig`
- Rate-limit middleware: `internal/middleware/ratelimit.go`
- DoS alert rules: `monitoring/prometheus/rules/kube-policies-dos.yml`
- NIST SP 800-53 Rev 5: IR-4, SC-5, SI-4; FedRAMP Moderate baseline.
