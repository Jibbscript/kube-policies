---
title: "Incident Response Procedures (IR) — Kube-Policies (KP)"
control_family: "IR — Incident Response"
controls: "IR-1, IR-4, IR-6, IR-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Incident Response Procedures (IR) — Kube-Policies (KP)

These are the operational procedures that implement the Incident Response policy
([../policies/IR-policy.md](../policies/IR-policy.md)) for the Kube-Policies system (KP).
They provide step-by-step guidance for detecting, handling, reporting, and learning from
security incidents affecting the KP admission-control system.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**). These procedures describe what is *actually implemented*
and what an operator or assessor can run to verify it. Where a control is Partial or has a
residual, the procedure says so; open weaknesses are tracked in [../POAM.md](../POAM.md).
All `@kube-policies.io` contacts below are **placeholders** pending role assignment.

**Annual review.** These procedures are reviewed and updated at least **annually** (last
review **2026-06-01**; next review **2027-06-01**) and after any significant incident,
tabletop finding, or runbook change. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the incident categories and components in
[IR-policy.md §1](../policies/IR-policy.md#1-purpose-and-applicability): all KP
authorization-boundary components in the `kube-policies-system` namespace, and the
vulnerability disclosure process in [SECURITY.md](../../../SECURITY.md).

## 2 Detection sources and initial triage (IR-4)

### 2.1 Automated detection signals

KP exposes the following detection signals. Each maps to a runbook and an incident category
per [IR-policy.md §3](../policies/IR-policy.md#3-kp-specific-incident-categories-ir-4).

| Alert / metric | Incident category | Runbook |
|---|---|---|
| `KubePoliciesDown` | Webhook outage | [webhook-outage.md](../../security/runbooks/webhook-outage.md) |
| `KubePoliciesWebhookNotReady` | Webhook outage | [webhook-outage.md](../../security/runbooks/webhook-outage.md) |
| `KubePoliciesNoTraffic` | Webhook outage | [webhook-outage.md](../../security/runbooks/webhook-outage.md) |
| `KubePoliciesFailOpenActive` | Fail-open event | [fail-open-event.md](../../security/runbooks/fail-open-event.md) |
| `KubePoliciesAuditEventsDropped` | Audit pipeline loss | [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) |
| `KubePoliciesAuditWriteErrors` | Audit pipeline loss | [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) |
| `KubePoliciesCertExpiringCritical` / `KubePoliciesCertExpired` | Certificate expiry | [cert-expiry.md](../../security/runbooks/cert-expiry.md) |
| `KubePoliciesErrorBudgetBurnFast` (critical) | High error rate | [high-error-rate.md](../../security/runbooks/high-error-rate.md) |
| `KubePoliciesDenyRateSpike` | Policy bypass / misconfiguration | [deny-rate-spike.md](../../security/runbooks/deny-rate-spike.md) |
| Audit `VerifyChain` failure | CRD tampering / audit pipeline loss | [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) |
| External report via [SECURITY.md](../../../SECURITY.md) | Varies — triage per §2.3 | Per category above |

Verify alert rules are installed and firing correctly:

```console
# Validate Prometheus alert rule syntax
helm template kube-policies charts/kube-policies \
  --set monitoring.enabled=true \
  | promtool check rules /dev/stdin

# Confirm ServiceMonitor and PrometheusRule templates render
helm template kube-policies charts/kube-policies \
  --set monitoring.enabled=true \
  | grep -E "kind: (PrometheusRule|ServiceMonitor)"
```

### 2.2 Manual detection inputs

- **Audit log review** (ISSO, weekly): anomalous admission deny patterns, unexpected CRD
  mutations, or unredacted payloads in the audit log.
- **Hash-chain verification** (Operator, weekly): `VerifyChainFiles` failure on the audit
  HMAC chain ([`internal/audit/integrity.go`](../../../internal/audit/integrity.go)).
- **Vulnerability disclosure** (external reporter via [SECURITY.md](../../../SECURITY.md)).
- **On-call observation**: any anomalous behavior observed during routine operations.

### 2.3 Initial triage

On receiving an alert or report, the on-call operator:

1. Acknowledges the alert within the SLA in
   [IR-policy.md §4.3](../policies/IR-policy.md#43-escalation-timelines).
2. Opens the incident record using the template at
   [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md).
3. Assigns an initial severity (SEV1–SEV4) per the severity matrix in §2 of the
   [operational IR plan](../../security/incident-response-plan.md).
4. Classifies the incident by category per
   [IR-policy.md §3](../policies/IR-policy.md#3-kp-specific-incident-categories-ir-4).
5. Notifies the ISSO within the SLA.

## 3 Incident handling lifecycle (IR-4)

Each incident follows the five-phase lifecycle. For each phase, the on-call operator
executes the applicable runbook and records actions in the incident record.

### 3.1 Phase 1 — Containment

Immediate actions to limit blast radius. Runbook-specific containment steps take
precedence; the examples below are common patterns:

```console
# Check current webhook replica count and readiness
kubectl get pods -n kube-policies-system -l app.kubernetes.io/component=admission-webhook

# Check current failurePolicy on the validate webhook (must remain Fail except during break-glass)
kubectl get validatingwebhookconfiguration kube-policies-webhook \
  -o jsonpath='{.webhooks[*].failurePolicy}'

# Check fail-open counter (must be zero in steady state)
kubectl exec -n kube-policies-system deploy/kube-policies-admission-webhook \
  -- wget -qO- http://localhost:9090/metrics \
  | grep kube_policies_admission_fail_open_total
```

For **webhook outage**: follow the break-glass procedure in
[webhook-outage.md §Break-glass](../../security/runbooks/webhook-outage.md). Document the
break-glass action as an incident record entry; notify the ISSO immediately.

For **fail-open event**: follow [fail-open-event.md §Containment](../../security/runbooks/fail-open-event.md).
Consider setting `failurePolicy: Fail` on the MutatingWebhookConfiguration to block
unmitigated workloads until the root cause is resolved.

For **CRD tampering**: immediately snapshot the current CRD state for forensics before any
remediation:

```console
kubectl get policy,policyexception -A -o yaml > /tmp/crd-forensic-snapshot-$(date +%Y%m%dT%H%M%SZ).yaml
```

### 3.2 Phase 2 — Eradication

Remove the root cause:

- **Policy bypass**: identify and patch the OPA/Rego logic or webhook configuration that
  permitted the bypass; validate with `go test ./internal/admission/...`.
- **CRD tampering**: restore the CRD state from the last verified backup (see
  [docs/backup-restore.md](../../backup-restore.md)); revoke the RBAC grant that permitted
  the unauthorized mutation.
- **Exception abuse**: delete or scope-reduce the offending PolicyException CRD; confirm
  that the exception-expiry audit event fires correctly:

  ```console
  go test ./internal/policymanager/ -run 'TestExceptionExpiry'
  ```

- **Audit pipeline loss**: restore audit integrity per
  [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md); re-verify the
  hash chain after restoration:

  ```console
  go test ./internal/audit/ -run 'TestVerifyChain_Untampered|TestVerifyChain_DetectsByteFlip'
  ```

### 3.3 Phase 3 — Recovery

Restore the affected component to its known-good operating state:

```console
# Restart affected component (example: admission-webhook)
kubectl rollout restart deploy/kube-policies-admission-webhook -n kube-policies-system

# Confirm rollout completes and readiness probe passes
kubectl rollout status deploy/kube-policies-admission-webhook -n kube-policies-system

# Confirm fail-open counter is zero after recovery
kubectl exec -n kube-policies-system deploy/kube-policies-admission-webhook \
  -- wget -qO- http://localhost:9090/metrics \
  | grep kube_policies_admission_fail_open_total
```

Run the full test suite to confirm no regression was introduced by the eradication patch:

```console
go test ./...
```

### 3.4 Phase 4 — Lessons learned

Within **5 business days** of incident closure:

1. ISSO convenes a post-incident review with the on-call operator and relevant maintainers.
2. Findings are recorded in the incident record.
3. Runbook gaps are filed as GitHub issues and remediated before the next review cycle.
4. Control weaknesses exposed by the incident are added to the [POA&M](../POAM.md).
5. If the incident reveals a previously unknown failure mode, a new entry is added to
   [IR-policy.md §3](../policies/IR-policy.md#3-kp-specific-incident-categories-ir-4).

## 4 Incident reporting procedure (IR-6)

### 4.1 Internal reporting

For every incident with severity SEV1 or SEV2, the ISSO files an incident record within 24
hours of detection. The record uses the template at
[docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md)
and includes:

- Detection time and source
- Assigned severity and category
- Component(s) affected
- Timeline of containment, eradication, and recovery actions
- Root cause (preliminary or confirmed)
- Notification timestamps (on-call, ISSO, AO)

### 4.2 External reporting (IR-6 / FedRAMP)

When an incident involves confirmed or suspected unauthorized access to government data or a
material violation of FedRAMP Moderate controls:

1. ISSO notifies the AO within the timeline in
   [IR-policy.md §4.3](../policies/IR-policy.md#43-escalation-timelines).
2. ISSO files an incident report to US-CERT/CISA per OMB M-17-12 and the agency's incident
   reporting procedures. For FedRAMP-authorized deployments, the 3PAO and FedRAMP PMO are
   also notified per the FedRAMP IR template.
3. All external communications are coordinated with the System Owner and AO before
   transmission.

### 4.3 Vulnerability disclosure triage

When an external report is received via [SECURITY.md](../../../SECURITY.md):

```
Receipt → ISSO acknowledges within 5 business days (Critical/High) or 10 business days (Moderate/Low)
  → Classify: active exploitation (IR-4 track) or latent vulnerability (RA-5/SI-2 track)
  → Active: escalate immediately to IR lifecycle (§3 above)
  → Latent: open POA&M entry; remediate within SLA
     Critical/High: 30 days · Moderate: 90 days · Low: 180 days
```

## 5 IR plan maintenance procedure (IR-8)

### 5.1 Annual review

The ISSO reviews the following IR artifacts at least annually (next review: 2027-06-01):

| Artifact | Action |
|---|---|
| [IR-policy.md](../policies/IR-policy.md) | Update incident categories, escalation timelines, role assignments; bump `last_reviewed` |
| These IR procedures | Verify runbook cross-references resolve; update cadence table; bump `last_reviewed` |
| [Operational IR plan](../../security/incident-response-plan.md) | Verify roles, contacts, severity matrix; incorporate lessons learned |
| [Compliance IR plan](../plans/incident-response-plan.md) | Align with operational plan; verify control mappings |
| [Runbooks](../../security/runbooks/) | Verify commands still work; update for any system change |

### 5.2 Annual tabletop exercise

The ISSO conducts at least one tabletop exercise per year. The most recent exercise record
is at [docs/security/ir-tabletop-2026.md](../../security/ir-tabletop-2026.md). Exercise
findings are fed into the post-incident review process (§3.4) and the POA&M.

## 6 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| Acknowledge alerts within SLA | Per alert (real-time) | Primary on-call |
| Review audit log for anomalies | Weekly | ISSO |
| Run hash-chain verification | Weekly | Operator |
| Review open incident records | Monthly | ISSO |
| Update POA&M with IR findings | Monthly | ISSO |
| IR plan review (all artifacts) | Annually (next: 2027-06-01) | ISSO |
| Tabletop exercise | Annually | ISSO |
| IR policy and procedures review | Annually (next: 2027-06-01) | ISSO |

## 7 Records and evidence

Evidence produced by these procedures is retained as IR assessment evidence:

- Incident records (using the template at
  [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md)).
- Alert firing history (Alertmanager / SIEM).
- Hash-chain verification output.
- Post-incident review notes and lessons-learned documents.
- Tabletop exercise record ([docs/security/ir-tabletop-2026.md](../../security/ir-tabletop-2026.md)).
- External reporting timestamps and acknowledgement records.
- POA&M entries created from IR findings.

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), IR family).

## 8 References

- IR policy: [../policies/IR-policy.md](../policies/IR-policy.md)
- Operational IR plan: [docs/security/incident-response-plan.md](../../security/incident-response-plan.md)
- Compliance IR plan (IR-8): [docs/compliance/plans/incident-response-plan.md](../plans/incident-response-plan.md)
- Runbooks: [docs/security/runbooks/webhook-outage.md](../../security/runbooks/webhook-outage.md) · [fail-open-event.md](../../security/runbooks/fail-open-event.md) · [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) · [cert-expiry.md](../../security/runbooks/cert-expiry.md) · [deny-rate-spike.md](../../security/runbooks/deny-rate-spike.md) · [high-error-rate.md](../../security/runbooks/high-error-rate.md) · [dos-response.md](../../security/runbooks/dos-response.md)
- Tabletop exercise: [docs/security/ir-tabletop-2026.md](../../security/ir-tabletop-2026.md)
- On-call escalation: [docs/security/on-call-escalation.md](../../security/on-call-escalation.md)
- Incident record template: [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md)
- Vulnerability disclosure: [SECURITY.md](../../../SECURITY.md)
- Audit integrity: [`internal/audit/integrity.go`](../../../internal/audit/integrity.go)
- Backup / restore: [docs/backup-restore.md](../../backup-restore.md)
- Alert rules: `charts/kube-policies/files/alerts/security.yaml` · `charts/kube-policies/files/alerts/availability.yaml`
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (IR-1, IR-4, IR-6, IR-8); FedRAMP Moderate baseline; OMB M-17-12.
