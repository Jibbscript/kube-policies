# Runbook — Audit Pipeline Loss

> NIST SP 800-53 Rev 5: IR-4, AU-5, AU-9, AU-11 · IRM-WU-06
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: Ops / SRE Responder (TBD — assign before assessment)

**Back to plan:** [docs/security/incident-response-plan.md](../incident-response-plan.md)

---

## AU-9 compliance impact

Audit record loss is a direct AU-5 (Response to Audit Processing Failures) and AU-9
(Protection of Audit Information) finding. Under FedRAMP Moderate (AU-11), audit records
must be retained for a minimum of 90 days online. Any gap in audit coverage — whether from
dropped records, a saturated buffer, a failed forwarder, or a write error — must be
assessed for compliance impact and documented in the POA&M.

If records were lost during an interval of high security activity (e.g., coincident with a
`KubePoliciesHighDenyRate` spike or a `KubePoliciesFailOpenActive` event), treat the
combined incident as at least **SEV2** and escalate to the Security Responder.

---

## Detection

**Alerts:**

| Alert | Metric / Condition | Meaning |
|---|---|---|
| `KubePoliciesAuditEventsDropped` | `rate(kube_policies_audit_events_total{status="dropped"}[5m]) > 0` | Records silently dropped because the in-memory buffer was full and `overflowPolicy=drop` |
| `KubePoliciesAuditWriteErrors` | `rate(kube_policies_audit_events_total{status="write_error"}[5m]) > 0` | Backend write failures (disk full, file-backend error) |
| `KubePoliciesAuditBufferSaturated` | `kube_policies_audit_buffer_size / <configured_buffer_size> > 0.9` | Buffer ≥ 90% full — drops imminent |
| `KubePoliciesDecisionPublishDrops` | `rate(kube_policies_webhook_decision_publish_dropped_total[5m]) > 0` | Decision-publish channel drops (SIEM / SSE stream backpressure) |

**PromQL — dropped and write-error rates:**

```promql
rate(kube_policies_audit_events_total{status="dropped"}[5m])
rate(kube_policies_audit_events_total{status="write_error"}[5m])
rate(kube_policies_audit_events_total{status="chain_error"}[5m])
```

**PromQL — buffer fill level:**

```promql
kube_policies_audit_buffer_size
```

Compare to the configured `audit.buffer_size` value (default: 1000).

---

## Triage

### 1. Quantify the loss

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_audit_events_total
```

Note the cumulative `dropped`, `write_error`, and `chain_error` counters. Compare to the
`written` counter to estimate the loss fraction.

### 2. Check the buffer size

```bash
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  wget -qO- 'http://localhost:9090/metrics' \
  | grep kube_policies_audit_buffer_size
```

If the buffer is at or near its configured maximum, records are being produced faster than
the backend can consume them.

### 3. Check the audit backend health

```bash
# Audit logs (file backend):
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=admission-webhook \
  --tail=100 \
  | grep -E 'audit|write_error|chain_error|forward'
```

Look for:
- Disk-full errors (`no space left on device`).
- File-permission errors.
- Forward-backend connection failures (TLS handshake errors, connection refused).

### 4. Check the SIEM forwarder health (if `audit.backend=forward`)

```bash
# Check forwarder pod logs (if a separate forwarder is deployed):
kubectl logs -n kube-policies-system \
  -l app.kubernetes.io/component=siem-forwarder \
  --tail=100

# Verify the forward_address is reachable from the webhook pod:
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  nc -zv <forward_address_host> <forward_address_port>
```

See [docs/security/siem-integration.md](../siem-integration.md) for the SIEM forwarder
architecture and troubleshooting.

### 5. Check the overflow policy

```bash
kubectl get configmap kube-policies-config \
  -n kube-policies-system \
  -o jsonpath='{.data.config\.yaml}' \
  | grep -A5 audit
```

The default `overflowPolicy: drop` silently discards records when the buffer is full.
`overflowPolicy: block` applies backpressure (slows the admission path) but ensures no
record is silently lost.

---

## Containment

### Option A — Increase audit buffer size

Increasing `audit.bufferSize` reduces drop frequency by giving the backend more headroom.
This does not fix a slow backend but buys time for root-cause remediation.

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values \
  --set audit.bufferSize=5000
```

### Option B — Switch overflowPolicy to block

Setting `overflowPolicy: block` prevents silent drops by applying backpressure to the
admission path. **This will slow admission processing if the backend cannot keep up.**
Use only if record completeness is more important than admission latency in the current
incident context.

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values \
  --set audit.overflowPolicy=block
```

### Option C — Restore SIEM forwarding

If the `forward` backend is the bottleneck, restore connectivity to the SIEM receiver and
verify TLS certificates on the forwarding path. Follow
[docs/security/siem-integration.md](../siem-integration.md) for the forwarder
reconfiguration procedure.

### Option D — Address disk capacity (file backend)

```bash
# Check disk usage on the audit PVC (if audit PVC is enabled):
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  df -h /var/log/kube-policies/

# Rotate or archive old log files to free space:
kubectl exec -n kube-policies-system \
  deploy/kube-policies-admission-webhook -- \
  ls -lh /var/log/kube-policies/
```

If the PVC is undersized, expand it or reduce `audit.maxSizeMB` to trigger rotation sooner.

---

## Recovery / Verification

1. Confirm `kube_policies_audit_events_total{status="dropped"}` has stopped incrementing:

   ```promql
   rate(kube_policies_audit_events_total{status="dropped"}[5m]) == 0
   ```

2. Confirm `kube_policies_audit_events_total{status="written"}` is rising:

   ```promql
   rate(kube_policies_audit_events_total{status="written"}[5m]) > 0
   ```

3. Confirm `kube_policies_audit_buffer_size` is well below the configured maximum.

4. Confirm all four audit alerts have resolved in Alertmanager.

5. Verify HMAC chain integrity is intact on the audit log (AU-9). If `chain_error` was
   non-zero, the integrity chain may have a gap that must be investigated:

   ```bash
   kubectl logs -n kube-policies-system \
     -l app.kubernetes.io/component=admission-webhook \
     | grep chain_error
   ```

6. Assess the duration and volume of the loss event. If the loss window overlapped with
   any security-significant event, escalate and document in the POA&M.

7. Complete an incident record using
   [../templates/incident-record-template.md](../templates/incident-record-template.md).
   Record the number of records lost, the duration, the root cause, and whether AU-11
   retention is at risk.

---

## References

- Incident Response Plan: [../incident-response-plan.md](../incident-response-plan.md)
- SIEM integration: [docs/security/siem-integration.md](../siem-integration.md)
- High-error-rate runbook: [high-error-rate.md](high-error-rate.md)
- POA&M: [docs/compliance/POAM.md](../../compliance/POAM.md)
- NIST SP 800-53 Rev 5: IR-4, AU-5, AU-9, AU-11; FedRAMP Moderate baseline.
