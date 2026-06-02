---
title: "Tabletop Exercise Report — Fail-Open Trip During Malicious Deployment (2026-06-01)"
controls: "IR-3, IR-3(2)"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "System Owner (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Tabletop Exercise Report — Fail-Open Trip During Malicious Deployment

> IRM-WU-21 · NIST SP 800-53 Rev 5: IR-3, IR-3(2) · FedRAMP Moderate baseline
> Exercise date: **2026-06-01** · Report status: Draft
> Owner: ISSO (TBD — assign before assessment) · Approver: System Owner (TBD — assign before assessment)

## 1 Exercise overview

| Field | Value |
|---|---|
| **Exercise date** | 2026-06-01 |
| **Exercise type** | Tabletop (discussion-based, no live cluster changes) |
| **Duration** | Approximately 2 hours |
| **Scenario** | Fail-open trip during a malicious deployment attempt |
| **Facilitator** | ISSO (TBD — assign before assessment) |
| **Scribe** | Operator / SRE (TBD — assign before assessment) |
| **Reference** | [docs/security/incident-response-plan.md](incident-response-plan.md), [docs/security/on-call-escalation.md](on-call-escalation.md) |

## 2 Participants

| Role | Participant | Department |
|---|---|---|
| Facilitator / ISSO | TBD — assign before assessment | Security |
| System Owner | TBD — assign before assessment | Engineering |
| Authorizing Official (observer) | TBD — assign before assessment | Compliance |
| Primary On-Call Operator | TBD — assign before assessment | Platform SRE |
| Secondary On-Call Operator | TBD — assign before assessment | Platform SRE |
| Policy Maintainer | TBD — assign before assessment | Engineering |
| Scribe | TBD — assign before assessment | Platform SRE |

All role names carry the qualifier "TBD — assign before assessment". This report uses role
titles; actual names are populated when roles are staffed.

## 3 Scenario description

**Premise.** An external threat actor has obtained write access to a CI/CD pipeline that
deploys workloads to the production cluster. The actor injects a malicious container image
into a Deployment manifest and triggers a pipeline run. Simultaneously — either by
coincidence or as part of the attack — the policy-manager replica holding a high-memory
policy bundle crashes under an OOM condition, causing a brief period during which
policy-evaluation errors propagate to the admission webhook. The webhook's fail-open
mutate path (`failurePolicy: Ignore` on the mutating webhook) admits the Deployment
without successful policy evaluation. The validating webhook (`failurePolicy: Fail`)
continues to operate, but the policy-evaluation engine error causes the engine to return an
error response rather than a policy-driven allow/deny — depending on error handling, this
may also manifest as a fail-open on the validate path for a subset of requests during the
degraded window.

**Objective.** Walk the team through detection, containment, and recovery to identify:
- How quickly the fail-open condition is detected by the new alerting.
- Whether runbooks provide sufficient guidance.
- Whether AO notification requirements are clear.
- Gaps in the response procedure.

## 4 Scenario timeline

All times are relative to T=0 (simulated start of the OOM event).

| T+ | Simulated event | Expected detection / action |
|---|---|---|
| T+00:00 | OOM kills one policy-manager replica. The surviving replica continues reconciling (leaderless design). | Kubernetes restarts the OOM'd pod; `KubePoliciesReplicaShortfall` (warning) fires within 10 minutes. |
| T+00:02 | The engine error rate on the fail-open mutate path spikes as the surviving replica's memory pressure causes evaluation timeouts. `kube_policies_admission_fail_open_total` increments. | **`KubePoliciesFailOpenActive` (critical) fires within 1 minute** (alert `for: 1m`). PagerDuty page to primary on-call. |
| T+00:03 | Primary on-call receives the page. | On-call acknowledges within 5 minutes per [on-call-escalation.md](on-call-escalation.md) §4 SEV1 SLA. |
| T+00:05 | On-call checks Grafana: `kube_policies_admission_fail_open_total` graph confirms increasing fail-opens. `KubePoliciesDown` is not firing — the webhook is up but erroring. | On-call opens [docs/security/runbooks/fail-open-event.md](runbooks/fail-open-event.md). |
| T+00:07 | On-call notifies ISSO per the fail-open fast-path (15 min deadline from alert). | ISSO engages. |
| T+00:10 | The malicious Deployment is admitted through the mutate path (fail-open). The validate path — because the engine error returns an HTTP 500, not a policy deny — also fails open for this request class (observed gap: see §6 gap G-001). | **`KubePoliciesFailOpenActive` confirms the count.** SIEM receives the `PolicyDecision` audit event with `decision: error` (if the audit backend wrote before the fail-open path suppressed it). |
| T+00:12 | `KubePoliciesErrorBudgetBurnFast` (critical) fires: the error ratio exceeds 14.4× the 0.001 error budget over 1 h and 5 m windows. | Second critical page (same on-call); ISSO now tracking both alerts. |
| T+00:15 | ISSO notifies AO: fail-open confirmed, duration > 10 minutes, potential unchecked workload admitted. | AO notification within 1 hour deadline (SEV1 posture-impacting event per [on-call-escalation.md](on-call-escalation.md) §5). |
| T+00:20 | On-call identifies the OOM'd replica in pod logs. Memory pressure confirmed. Scales up the surviving replica's memory limit via Helm upgrade. | `helm upgrade kube-policies ... --set policyManager.resources.limits.memory=512Mi` |
| T+00:25 | Second policy-manager replica becomes Ready. Fail-open rate drops. `KubePoliciesFailOpenActive` resolves. | On-call monitors for 5 minutes to confirm resolution. |
| T+00:30 | On-call and ISSO audit the SIEM for `decision: error` events during the T+00:02 to T+00:25 window. Identifies the malicious Deployment by `request_uid` and `name`. | `kubectl delete deployment <malicious-name> -n <namespace>`. |
| T+00:35 | Malicious Deployment deleted. Cluster admission control fully restored. | All alerts resolved. |
| T+00:40 | ISSO drafts the incident record. Identifies gaps (§6). | Post-incident review scheduled. |

**Simulated outcome.** The fail-open was detected within 2–3 minutes by `KubePoliciesFailOpenActive`.
The malicious workload was contained within 30 minutes of detection. Total incident duration
from T+00:02 to T+00:35 = **33 minutes**, within the 30-minute RTO from [contingency-plan.md](../contingency-plan.md)
if measured from the first alert — though the AO notification timeline (T+00:15) is tight.

## 5 Detection efficacy of the new alerts

| Alert | Fired? | Delay from event | Assessment |
|---|---|---|---|
| `KubePoliciesFailOpenActive` | Yes (simulated) | ~2 minutes (T+00:02) | **Effective.** The 1-minute `for` clause catches any increment in the 5-minute window. This is the primary detection signal for this scenario. |
| `KubePoliciesReplicaShortfall` | Yes (simulated) | ~10 minutes (T+00:10) | **Useful context** but fires after the fail-open alert. Not the primary signal. |
| `KubePoliciesErrorBudgetBurnFast` | Yes (simulated) | ~12 minutes (T+00:12) | **Confirms severity escalation** but arrives after on-call is already engaged. The latency (burn must accumulate over 1h+5m windows) means it is a confirming signal, not the primary detector. |
| `KubePoliciesAuditEventsDropped` | No (simulated) | — | The audit backend continued writing `decision: error` events during the fail-open; the buffer was not saturated. This is the expected behavior. |
| `KubePoliciesMemoryUsage` | Yes — late (simulated) | ~8 minutes | Useful pre-cursor signal (memory above 80% before OOM). **Gap:** this alert did not page — it is `severity: warning`. Consider adding a `critical` tier at 95% (see §6 gap G-003). |
| Falco `kube-policies unexpected exec` | No (simulated) | — | The malicious Deployment ran in a separate namespace, not inside the KP pods. Falco correctly did not fire on KP pods. The malicious image itself would need a separate Falco rule (out of scope for the KP ruleset). |

## 6 Runbook gaps found

The following gaps were identified during the tabletop. Each is tracked as a follow-up action
in §7 and will generate a POA&M entry if not remediated before assessment.

### G-001 — Validate-path fail-open behavior under engine errors not fully documented

**Observation.** The [fail-open-event.md](runbooks/fail-open-event.md) runbook focuses on
the mutate-path fail-open (`failurePolicy: Ignore`). During this scenario the team debated
whether engine errors on the validate path also result in fail-open behavior (they can, if
the error is a 5xx returned to the apiserver with `failurePolicy: Fail`, causing the
apiserver to reject rather than allow — but if the webhook returns an HTTP 200 with a
rejection that is then bypassed by a code bug, the behavior is different). The runbook does
not clearly distinguish these paths.

**Impact.** Responders may apply the wrong containment action (deleting the mutating webhook
configuration instead of the validating webhook configuration).

**Follow-up.** Update [docs/security/runbooks/fail-open-event.md](runbooks/fail-open-event.md)
to explicitly distinguish mutate-path fail-open (engine error, `failurePolicy: Ignore`,
result: workload admitted unchecked) from validate-path behavior (engine error vs. policy deny
vs. webhook unavailable). Reference the relevant code path in `cmd/admission-webhook/`.

### G-002 — AO notification runbook step is missing from fail-open-event.md

**Observation.** The fail-open runbook ([fail-open-event.md](runbooks/fail-open-event.md))
does not include an explicit step for AO notification. Participants had to consult
[on-call-escalation.md](on-call-escalation.md) §5 separately, which added friction during
the exercise.

**Impact.** AO notification may be delayed or missed under real incident pressure.

**Follow-up.** Add an explicit "Notify AO within 1 hour if fail-open is confirmed and
duration > 10 minutes or if any workload was admitted unchecked" step to the fail-open
runbook, with a reference to [on-call-escalation.md](on-call-escalation.md) §5 for the
notification template.

### G-003 — Memory-pressure alerting has no critical tier

**Observation.** `KubePoliciesMemoryUsage` is `severity: warning` at > 80% of the memory
limit. By the time the OOM kills the pod, no critical alert has been sent and the on-call
is not paged. The warning fires ~8 minutes before the OOM but is only visible in Slack,
not in PagerDuty.

**Impact.** OOM events that precede a fail-open are not proactively paged; responders must
correlate the warning after the fact.

**Follow-up.** Add a second `KubePoliciesMemoryPressureCritical` alert at `severity: critical`
for > 95% of memory limit, sustained for 2 minutes. Add to
`charts/kube-policies/files/alerts/availability.yaml`. Run `promtool` tests.

### G-004 — SIEM query procedure not documented in the runbook

**Observation.** The step "audit the SIEM for `decision: error` events during the fail-open
window" (T+00:30 in §4) was not documented. Participants had to infer the SIEM query.
Without a documented query template, this step is slow and error-prone under incident
conditions.

**Impact.** Delay in identifying admitted workloads; risk of missing unchecked admissions.

**Follow-up.** Add a SIEM query template section to [docs/security/siem-integration.md](siem-integration.md)
covering: (1) query for `decision: error` events by time window, (2) query for all
`decision: allow` events during a fail-open window (to identify workloads admitted
unchecked), (3) query to verify integrity hash chain continuity.

### G-005 — No documented procedure for deleting a suspected malicious workload under fail-open

**Observation.** After identifying the malicious Deployment by `request_uid`, participants
were unsure whether to delete it immediately (potential data loss) or cordon it first. No
runbook step covers this decision.

**Impact.** Delay in containment; risk of either premature deletion (destroying forensic
evidence) or delayed containment (malicious workload runs longer).

**Follow-up.** Add a containment decision tree to the fail-open runbook: (1) cordon the
node running the malicious workload, (2) capture logs and describe output for forensics,
(3) delete the workload, (4) document in the incident record.

## 7 Follow-up action table

Each gap from §6 maps to a follow-up action. Open items will be tracked as POA&M entries
until closed.

| Action ID | Gap | Follow-up action | Owner | Due date | POA&M reference |
|---|---|---|---|---|---|
| **TA-2026-001** | G-001 | Update fail-open-event.md to distinguish mutate vs. validate path fail-open behavior with code references | Operator / SRE (TBD) | 2026-07-01 | [docs/compliance/POAM.md](../compliance/POAM.md) — open POA&M entry if not closed by due date |
| **TA-2026-002** | G-002 | Add AO notification step to fail-open-event.md with template and timing requirement | ISSO (TBD) | 2026-07-01 | [docs/compliance/POAM.md](../compliance/POAM.md) |
| **TA-2026-003** | G-003 | Add `KubePoliciesMemoryPressureCritical` alert (>95%, 2m, critical) to availability.yaml; update promtool tests | Operator / SRE (TBD) | 2026-07-15 | [docs/compliance/POAM.md](../compliance/POAM.md) |
| **TA-2026-004** | G-004 | Add SIEM query template section to siem-integration.md covering fail-open investigation queries | Operator / SRE (TBD) | 2026-07-15 | [docs/compliance/POAM.md](../compliance/POAM.md) |
| **TA-2026-005** | G-005 | Add containment decision tree (cordon → capture → delete → document) to fail-open runbook | Operator / SRE (TBD) | 2026-07-15 | [docs/compliance/POAM.md](../compliance/POAM.md) |

All actions are tracked against [docs/compliance/POAM.md](../compliance/POAM.md). The ISSO
is responsible for opening a formal POA&M entry for any action not closed by its due date.

## 8 Lessons learned

1. **`KubePoliciesFailOpenActive` is the right primary detector for this scenario.** It
   fires within 2 minutes and provides the actionable signal before error-budget burn
   alerts accumulate. No changes needed to the alert definition.
2. **Multi-alert correlation needs a documented playbook.** When `KubePoliciesFailOpenActive`,
   `KubePoliciesReplicaShortfall`, and `KubePoliciesErrorBudgetBurnFast` fire simultaneously,
   responders need a triage order. Update the incident-response-plan.md to document the
   triage priority: fail-open first, then containment, then root-cause.
3. **Leaderless policy-manager design was validated.** The surviving replica continued
   reconciling correctly during the OOM event. No operator action was needed to maintain
   policy state.
4. **AO notification timing is tight under a real incident.** The 1-hour deadline from
   confirmation to AO notification requires the ISSO to engage within minutes of the SEV1
   page. The runbook gap (G-002) must be closed before assessment.

## 9 Annual review

This report is filed for the 2026-06-01 tabletop exercise. The next tabletop exercise is
scheduled for **2027-06-01** (annually, per NIST IR-3 and the
[contingency plan](../contingency-plan.md) §6 tabletop checklist). This document is
reviewed and updated after each exercise.

## 10 References

- Incident response plan: [docs/security/incident-response-plan.md](incident-response-plan.md)
- On-call escalation: [docs/security/on-call-escalation.md](on-call-escalation.md)
- Fail-open runbook: [docs/security/runbooks/fail-open-event.md](runbooks/fail-open-event.md)
- Audit pipeline runbook: [docs/security/runbooks/audit-pipeline-loss.md](runbooks/audit-pipeline-loss.md)
- SLO and burn-rate alerts: [docs/observability/slo.md](../observability/slo.md)
- SIEM integration: [docs/security/siem-integration.md](siem-integration.md)
- Continuous monitoring plan: [docs/security/continuous-monitoring-plan.md](continuous-monitoring-plan.md)
- Contingency plan (tabletop checklist §6): [docs/contingency-plan.md](../contingency-plan.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- Alert definitions: `charts/kube-policies/files/alerts/security.yaml`, `charts/kube-policies/files/alerts/availability.yaml`
- NIST SP 800-53 Rev 5: IR-3, IR-3(2); FedRAMP Moderate baseline.
