---
title: "On-Call & Escalation Matrix — Kube-Policies (KP)"
controls: "IR-6, IR-8"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "System Owner (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# On-Call & Escalation Matrix — Kube-Policies (KP)

> IRM-WU-17 · NIST SP 800-53 Rev 5: IR-6, IR-8 · FedRAMP Moderate baseline
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: ISSO (TBD — assign before assessment) · Approver: System Owner (TBD — assign before assessment)

This document defines the on-call rotation, the severity classification scheme, and the
escalation matrix for Kube-Policies. It is the operational companion to the
[Incident Response Plan](incident-response-plan.md), which governs detection, containment,
and post-incident activities. Alertmanager routing (severity → receiver) is the automated
delivery mechanism for the contacts defined here.

Named roles carry the qualifier "TBD — assign before assessment". All `@kube-policies.io`
addresses are **placeholders** pending role staffing.

## 1 Severity classification

Kube-Policies uses a four-level severity scale. All Alertmanager-fired alerts map to either
`critical` or `warning` labels, which map to SEV1 and SEV2/SEV3 respectively.

| Level | Name | Definition | Response mode |
|---|---|---|---|
| **SEV1** | Critical | Admission control is degraded or bypassed; error budget burning fast (14.4×); fail-open active; cert expired; all replicas down. Immediate risk to cluster integrity or FedRAMP authorization posture. | **Immediate page**; on-call responds within 5 minutes. |
| **SEV2** | High | Error budget burning slowly (6×); audit drops; latency SLO breached; TLS cert expiring within 7 days; policy-manager down. Controls degraded but not fully bypassed. | **Chat alert + ticket**; on-call acknowledges within 30 minutes. |
| **SEV3** | Moderate | Replica shortfall; PDB at limit; audit buffer saturated; exception suppression spike; cert expiring within 30 days; no-traffic watchdog. Reduced headroom but no immediate impact on enforcement. | **Ticket**; on-call reviews within 2 hours. |
| **SEV4** | Low | Informational findings, ConMon drift detected outside alerting window, POA&M reminders. | **Ticket**; addressed in next business day. |

## 2 Alertmanager severity mapping

Alertmanager routes alerts based on the `severity` label set in the PrometheusRule. The
single-source alert definitions are in `charts/kube-policies/files/alerts/`.

| Alertmanager severity label | Receiver | SEV level | Example alerts |
|---|---|---|---|
| `critical` | PagerDuty / paging channel | SEV1 | `KubePoliciesErrorBudgetBurnFast`, `KubePoliciesFailOpenActive`, `KubePoliciesCertExpired`, `KubePoliciesDown`, `KubePoliciesAuditEventsDropped`, `KubePoliciesAuditWriteErrors` |
| `warning` | Slack `#kube-policies-alerts` | SEV2/SEV3 | `KubePoliciesErrorBudgetBurnSlow`, `KubePoliciesLatencySLOBreach`, `KubePoliciesCertExpiringCritical` (7d), `KubePoliciesCertExpiringSoon` (30d), `KubePoliciesReplicaShortfall`, `KubePoliciesAuditBufferSaturated`, `KubePoliciesNoTraffic` |
| `none` | Heartbeat / dead-man's-switch | — | `KubePoliciesWatchdog` (always-firing heartbeat; absence pages) |

The Alertmanager configuration (routing tree, receivers) is maintained in
`monitoring/alertmanager/`. The dead-man's-switch heartbeat consuming `KubePoliciesWatchdog`
is configured under the heartbeat receiver; if Prometheus or Alertmanager itself dies, the
absence of the heartbeat triggers an external page.

## 3 On-call rotation

| Tier | Role | Holder | Contact | Schedule |
|---|---|---|---|---|
| Primary on-call | Operator / SRE | TBD — assign before assessment | sre-primary@kube-policies.io (placeholder) | Weekly rotation |
| Secondary on-call | Senior Operator / SRE | TBD — assign before assessment | sre-secondary@kube-policies.io (placeholder) | Weekly rotation, offset by 3 days |
| ISSO escalation | ISSO | TBD — assign before assessment | isso@kube-policies.io (placeholder) | Available during business hours; paged for SEV1 after 30 min |
| System Owner escalation | System Owner | TBD — assign before assessment | system-owner@kube-policies.io (placeholder) | Paged for active SEV1 incidents involving fail-open, auth posture, or AO notification |

Rotation scheduling and contact details are managed in the team's incident-management
platform (PagerDuty / OpsGenie — TBD). This document records the roles; the live schedule
lives in that platform.

## 4 Escalation matrix

The table below defines the escalation path for each severity level. Timeouts are measured
from the initial alert or first contact attempt.

| SEV | Initial receiver | Initial timeout | First escalation | Second escalation | AO notification required |
|---|---|---|---|---|---|
| **SEV1** | Primary on-call (page) | **5 min** (no acknowledgement) | Secondary on-call (page) | **15 min** → ISSO (page) | Yes — within **1 hour** of confirmed SEV1 for fail-open or posture-impacting events; within **24 hours** for all other SEV1 |
| **SEV2** | Primary on-call (Slack + ticket) | **30 min** (no acknowledgement) | Secondary on-call (Slack) | **2 hours** → ISSO (Slack) | No (unless budget exhausted — see SLO doc) |
| **SEV3** | Primary on-call (ticket) | **2 hours** | Secondary on-call (ticket) | **Next business day** → ISSO | No |
| **SEV4** | Ticket queue | Next business day | ISSO (if overdue) | — | No |

**Fail-open (KubePoliciesFailOpenActive) fast-path.** Any firing of
`KubePoliciesFailOpenActive` is treated as SEV1 regardless of the alert duration. The
primary on-call must:
1. Acknowledge within 5 minutes.
2. Engage the fail-open runbook at
   [docs/security/runbooks/fail-open-event.md](runbooks/fail-open-event.md) immediately.
3. Notify the ISSO within 15 minutes.
4. Notify the AO if the fail-open persists beyond 30 minutes or if any unchecked workload
   was admitted.

## 5 External and agency notification responsibilities

FedRAMP requires that the Authorizing Official (AO) and, in some cases, US-CERT / CISA be
notified of significant incidents.

| Event | Who notifies | Target | Deadline |
|---|---|---|---|
| SEV1 confirmed — fail-open, auth-bypass, or cert-expired causing admission failure | ISSO | AO | Within 1 hour of confirmation |
| SEV1 confirmed — error budget exhausted | ISSO | AO | Within 24 hours |
| Significant incident (meets FedRAMP incident threshold) | ISSO + System Owner | AO → US-CERT / CISA | Per FedRAMP IR reporting requirements (typically within 1 hour for major incidents) |
| Monthly ConMon summary with SLO burn data | ISSO | AO | Monthly, per ConMon plan |
| Customer / agency cluster impact | System Owner | Affected agency POC | As soon as impact is confirmed; within 1 hour for active SEV1 |

The definition of a "significant incident" requiring US-CERT / CISA notification follows
the FedRAMP Incident Communications Procedure (FedRAMP.gov). The ISSO is responsible for
making that determination with guidance from the AO.

## 6 Runbook index

Each alert category has a corresponding runbook under `docs/security/runbooks/`:

| Category | Runbook |
|---|---|
| Webhook outage / replica loss | [docs/security/runbooks/webhook-outage.md](runbooks/webhook-outage.md) |
| Fail-open event | [docs/security/runbooks/fail-open-event.md](runbooks/fail-open-event.md) |
| High error rate / SLO burn | [docs/security/runbooks/high-error-rate.md](runbooks/high-error-rate.md) |
| Audit pipeline loss | [docs/security/runbooks/audit-pipeline-loss.md](runbooks/audit-pipeline-loss.md) |
| Cert expiry | [docs/security/runbooks/cert-expiry.md](runbooks/cert-expiry.md) |
| Deny-rate spike | [docs/security/runbooks/deny-rate-spike.md](runbooks/deny-rate-spike.md) |

## 7 Annual review

This document is reviewed at least **annually** (next review: **2027-06-01**), after every
SEV1 post-incident review, and whenever role assignments or contact details change. Reviews
are recorded by updating the front-matter dates and incrementing the version.

## 8 References

- Incident response plan: [docs/security/incident-response-plan.md](incident-response-plan.md)
- SLO and burn-rate alerts: [docs/observability/slo.md](../observability/slo.md)
- Alertmanager config: `monitoring/alertmanager/`
- Alert definitions: `charts/kube-policies/files/alerts/`
- Continuous monitoring plan: [docs/security/continuous-monitoring-plan.md](continuous-monitoring-plan.md)
- DR runbook: [docs/runbooks/disaster-recovery.md](../runbooks/disaster-recovery.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- NIST SP 800-53 Rev 5: IR-6 (Incident Reporting), IR-8 (Incident Response Plan); FedRAMP Moderate baseline.
