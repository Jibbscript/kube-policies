---
title: "Incident Response Plan — Kube-Policies (KP)"
control_family: "IR — Incident Response"
controls: "IR-4, IR-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign before assessment)"
approver: "Authorizing Official (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Incident Response Plan — Kube-Policies (KP)

> NIST SP 800-53 Rev 5: IR-4, IR-8 · IRM-WU-01
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: System Owner (TBD — assign before assessment)

Kube-Policies (KP) is a Kubernetes admission-control and policy-management system
(`github.com/Jibbscript/kube-policies`) being driven toward FedRAMP-Moderate authorization.
This is its **Incident Response Plan (IRP)**: the document that defines how KP identifies,
contains, eradicates, and recovers from security incidents, and how lessons learned are
captured and fed back into the program.

**Honest status.** KP is a Proof-of-Concept with no ATO and no production deployment.
Named roles are **TBD — assign before assessment**. Contact addresses (e.g.,
`security@kube-policies.io`) are **placeholders**. This plan describes the program being
stood up; it does not claim the program is operating at steady state.

---

## 1 Scope and system description

KP components within the incident-response authorization boundary:

| Asset ID | Component | Ports |
|---|---|---|
| AST-WH | Admission webhook (validate + mutate) | :8443 (TLS), :9090 (metrics) |
| AST-PM | Policy manager | :8080, :9091 (metrics) |
| AST-DB / AST-SPA | Dashboard BFF / SPA | :8090, :9092 (metrics) |
| AST-CRD-POL | `Policy` CRD (etcd-backed) | — |
| AST-CRD-EXC | `PolicyException` CRD (etcd-backed) | — |
| AST-CHART | Helm chart | — |
| AST-OPA | Embedded OPA/Rego engine | — |

All components run in the `kube-policies-system` namespace. The admission webhook is
fail-closed on validate (`failurePolicy: Fail`) and fail-open on mutate
(`failurePolicy: Ignore` at the MutatingWebhookConfiguration level, fail-open in-process by
design — see §4.2). Policy state is stored as CRDs in etcd; in-memory registries are
reconstructed on every pod start from etcd.

---

## 2 Severity matrix

Assign severity at detection time. Escalate if new information changes the picture. All
SEV1/SEV2 incidents require immediate notification (see §6).

| Severity | Definition | KP examples | Initial response |
|---|---|---|---|
| **SEV1 — Critical** | Active compromise or control failure with immediate cluster-wide impact | Confirmed policy-enforcement bypass allowing unauthorized workloads; attacker-controlled admission webhook; wildcard policy deletion; credentials extracted from `kube-policies-system` | Immediate: page incident commander + security; consider break-glass (§5.4 in [webhook-outage runbook](runbooks/webhook-outage.md)) |
| **SEV2 — High** | Security control significantly degraded; real risk of harm; SLA breach imminent | `KubePoliciesFailOpenActive` firing (mutate path admitting unevaluated requests); `KubePoliciesDown` with fail-closed causing cluster-wide admission denial; audit pipeline completely silent; cert expired (`KubePoliciesCertExpired`) blocking admission | Page incident commander within 15 min; escalate to security team |
| **SEV3 — Medium** | Degraded but not failed; risk contained; response required within hours | `KubePoliciesHighDenyRate` spike suggesting misconfigured policy or rollout failure; `KubePoliciesCertExpiringSoon` (<7 days); `KubePoliciesAuditEventsDropped`; sustained `KubePoliciesHighErrorRate` | Acknowledge within 1 h; assign owner; work during business hours |
| **SEV4 — Low** | Minor anomaly; no immediate risk; tracked to closure | Single isolated error burst; transient latency spike resolving naturally; informational alert investigation | Acknowledge within 4 h; log and monitor; resolve at next opportunity |

---

## 3 IR lifecycle phases

KP follows the NIST SP 800-61 Rev 2 incident-response lifecycle. Each phase is described
below with KP-specific guidance.

### Phase 1 — Preparation

**Goal:** ensure KP-specific IR capabilities are in place before an incident occurs.

- Alert rules are deployed from `monitoring/prometheus/rules/` and verified with `promtool
  test rules`.
- Runbooks (§5) are maintained under `docs/security/runbooks/` and linked from alert
  `runbook_url` annotations.
- On-call schedules, escalation paths, and role assignments (§4) are populated before
  assessment.
- Tabletop exercises are conducted at least annually using the checklist in
  [docs/contingency-plan.md](../contingency-plan.md) §6.
- The incident record template ([templates/incident-record-template.md](templates/incident-record-template.md))
  is pre-staged for immediate use.
- Break-glass procedures (webhook disable, policy rollback) are documented in the runbooks
  and understood by all on-call responders.
- The POA&M ([docs/compliance/POAM.md](../compliance/POAM.md)) is current so that any
  exploitation of a known weakness is immediately recognizable.

### Phase 2 — Detection and Analysis

**Goal:** determine that an incident is occurring, classify its severity, and gather initial
evidence.

Detection sources:

| Source | Signal | Alert / metric |
|---|---|---|
| Prometheus alerting | Threshold breach | All `KubePolicies*` alert names (§2, §5) |
| Admission deny spike | Policy misconfiguration or attack | `KubePoliciesHighDenyRate` |
| Fail-open counter | Mutate controls bypassed | `KubePoliciesFailOpenActive` / `kube_policies_admission_fail_open_total` |
| Certificate expiry | apiserver cannot reach webhook | `KubePoliciesCertExpiringSoon` / `KubePoliciesCertExpiringCritical` / `KubePoliciesCertExpired` |
| Webhook down | Admission denied cluster-wide | `KubePoliciesDown` |
| Audit pipeline | Record loss / buffer saturation | `KubePoliciesAuditEventsDropped` / `KubePoliciesAuditBufferSaturated` |
| Error rate | Engine decode/nil/eval/patch errors | `KubePoliciesHighErrorRate` |
| Manual reports | SECURITY.md coordinated disclosure | GitHub private advisory / `security@TBD` |

Initial analysis steps:

1. Retrieve the firing alert and its labels/annotations from Alertmanager or the SIEM.
2. Open the linked runbook (§5) and follow the **Triage** section.
3. Record initial findings in a new incident record
   ([templates/incident-record-template.md](templates/incident-record-template.md)).
4. Assign severity (§2) and notify roles (§4) per the notification timeline (§6).
5. Preserve evidence: save relevant log excerpts, metric snapshots, and audit records
   before any remediation action that might overwrite them.

### Phase 3 — Containment

**Goal:** limit the blast radius. Prefer short-term containment that preserves evidence over
destructive remediation.

Short-term containment options (KP-specific):

- **Policy rollback:** `kubectl apply` the last known-good Policy CR (see
  [deny-rate-spike runbook](runbooks/deny-rate-spike.md) §Containment).
- **PolicyException:** create a scoped exception for the affected namespace/workload while
  investigating (see [deny-rate-spike runbook](runbooks/deny-rate-spike.md) §Containment).
- **Break-glass webhook disable:** if the webhook itself is causing cluster harm, temporarily
  set `failurePolicy: Ignore` or delete the `ValidatingWebhookConfiguration` (see
  [webhook-outage runbook](runbooks/webhook-outage.md) §Break-glass). **Document as a
  deviation in the POA&M immediately.**
- **Tighten MutatingWebhookConfiguration failurePolicy:** during a fail-open event, change
  the mutating webhook `failurePolicy` from `Ignore` to `Fail` to stop unevaluated requests
  from being admitted (see [fail-open-event runbook](runbooks/fail-open-event.md)
  §Containment). Note that this does NOT fix the underlying engine error — it stops
  admission of unevaluated objects at the cost of potentially blocking some mutations.
- **Scale / restart:** force a pod restart to clear transient engine state (see
  [fail-open-event runbook](runbooks/fail-open-event.md) §Containment).
- **Audit pipeline:** switch `overflowPolicy` from `drop` to `block` to prevent further
  record loss (see [audit-pipeline-loss runbook](runbooks/audit-pipeline-loss.md)
  §Containment).

### Phase 4 — Eradication

**Goal:** remove the root cause.

- Fix the defect (engine bug, misconfigured policy, broken SIEM forwarder, expired cert).
- Validate the fix against tests and linting before redeployment.
- Remove any attacker-placed artifacts (rogue Policy/PolicyException CRs, modified images).
- Rotate credentials or secrets if compromise is suspected.
- Validate HMAC audit-chain integrity after any potential tampering (AU-9).

### Phase 5 — Recovery

**Goal:** restore KP to a known-good operational state.

- Redeploy from a verified image digest (see supply-chain controls in
  [docs/supply-chain/](../supply-chain/)).
- Restore Policy/PolicyException CRs from the CRD backup if CRs were corrupted or deleted
  (see [docs/runbooks/disaster-recovery.md](../runbooks/disaster-recovery.md)).
- Re-enable any temporarily disabled webhook configurations; confirm `failurePolicy: Fail`
  is restored on the validate webhook.
- Verify the admission pipeline end-to-end with the smoke test:
  ```bash
  kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
  ```
- Monitor `kube_policies_admission_requests_total` and error counters for at least 30
  minutes after recovery.
- Confirm audit pipeline is delivering records: check
  `kube_policies_audit_events_total{status="written"}` is rising.
- Document recovery actions and timestamps in the incident record.

### Phase 6 — Post-Incident Activity

**Goal:** prevent recurrence; satisfy FedRAMP reporting requirements.

- Complete the incident record (§7) within 5 business days of closure.
- Conduct a blameless post-mortem with all responders present.
- Capture action items with owners and due dates; open POA&M entries for any new weaknesses
  found.
- Update runbooks if any procedure was unclear or incorrect during the incident.
- Update alert thresholds if the signal-to-noise ratio was poor.
- Report to US-CERT / FedRAMP per the notification timeline (§6) if reporting criteria are
  met.
- Schedule a follow-up tabletop exercise if the incident exposed a preparedness gap.
- Increment the plan version and update `last_reviewed` in the front-matter.

---

## 4 Roles and responsibilities

| Role | Holder | IR responsibility |
|---|---|---|
| **Incident Commander (IC)** | TBD — assign before assessment | Declares incident and severity; coordinates all responders; owns the incident record; makes escalation and break-glass decisions; approves post-mortem findings. |
| **Ops / SRE Responder** | TBD — assign before assessment | Executes runbook procedures; gathers metric and log evidence; performs containment and recovery actions; reports status to IC. |
| **Security Responder** | TBD — assign before assessment | Assesses security impact; determines whether a privacy or reportable breach has occurred; coordinates with US-CERT / FedRAMP JAB if required; performs forensic evidence preservation. |
| **Communications Lead** | TBD — assign before assessment | Manages internal and external notifications per the timeline in §6; drafts stakeholder communications; coordinates with PR/legal if required. |
| **ISSO** | TBD — assign before assessment | Owns the POA&M; updates it during and after the incident; signs off on post-mortem; triggers annual review updates to this plan. |
| **System Owner / AO** | TBD — assign before assessment | Notified of SEV1/SEV2; approves break-glass deviations; approves re-authorization if recovery introduced significant configuration changes. |

All `@kube-policies.io` contacts are **placeholders** pending role assignment.

---

## 5 Runbooks

Each scenario below has a dedicated runbook. Alert `runbook_url` annotations reference these
anchored paths directly.

| Scenario | Alert(s) | Runbook |
|---|---|---|
| High deny-rate spike | `KubePoliciesHighDenyRate` | [runbooks/deny-rate-spike.md](runbooks/deny-rate-spike.md) |
| Fail-open event (mutate bypassed) | `KubePoliciesFailOpenActive` | [runbooks/fail-open-event.md](runbooks/fail-open-event.md) |
| TLS certificate expiry | `KubePoliciesCertExpiringSoon`, `KubePoliciesCertExpiringCritical`, `KubePoliciesCertExpired` | [runbooks/cert-expiry.md](runbooks/cert-expiry.md) |
| Webhook outage | `KubePoliciesDown`, `KubePoliciesWebhookNotReady`, `KubePoliciesNoTraffic` | [runbooks/webhook-outage.md](runbooks/webhook-outage.md) |
| Audit pipeline loss | `KubePoliciesAuditEventsDropped`, `KubePoliciesAuditWriteErrors`, `KubePoliciesAuditBufferSaturated`, `KubePoliciesDecisionPublishDrops` | [runbooks/audit-pipeline-loss.md](runbooks/audit-pipeline-loss.md) |
| High error rate | `KubePoliciesHighErrorRate` | [runbooks/high-error-rate.md](runbooks/high-error-rate.md) |
| Load / DoS | `KubePoliciesHighAdmissionRequestRate`, `RateLimitSurge`, `AdmissionLatency*` | [runbooks/dos-response.md](runbooks/dos-response.md) |
| Full webhook outage / DR | `KubePoliciesDown` (sustained) | [docs/runbooks/disaster-recovery.md](../runbooks/disaster-recovery.md) |

---

## 6 Notification timeline

FedRAMP requires reporting of security incidents per the **FedRAMP Incident Communications
Procedure** and **US-CERT** reporting requirements (IR-6). The timelines below are targets;
actual reporting requirements depend on the incident classification and agency SLA.

| Event | Target | Recipient | Method |
|---|---|---|---|
| SEV1 detected | Immediately (< 15 min) | Incident Commander, Security Responder, System Owner | Phone / pager |
| SEV2 detected | < 15 min | Incident Commander, Security Responder | Phone / pager |
| SEV3 detected | < 1 hour | Ops on-call, ISSO (notification) | Ticketing / chat |
| SEV4 detected | < 4 hours | Ops on-call | Ticketing |
| US-CERT / FedRAMP initial report (if reportable) | **Within 1 hour** of US-CERT determination | US-CERT (`https://www.cisa.gov/report`), FedRAMP PMO, Agency AO | US-CERT portal + email |
| Agency / JAB notification (SEV1/SEV2 reportable) | **Within 1 hour** of confirmed reportable incident | Agency CISO/COR (TBD — assign before assessment) | Secure email |
| Status updates (open SEV1/SEV2) | Every 2 hours | Incident Commander → stakeholders | Incident channel |
| Incident closure report | Within 5 business days of closure | ISSO, System Owner, Agency CISO (TBD) | Written incident record |

> **Reportability determination.** Not every SEV1/SEV2 event is a reportable incident under
> FedRAMP/US-CERT criteria. The Security Responder makes the initial determination; the ISSO
> confirms. When in doubt, report.

**Contacts (all placeholders — assign before assessment):**

- Incident Commander: `ic@kube-policies.io` (TBD)
- Security team: `security@kube-policies.io` / GitHub private advisory
- ISSO: `isso@kube-policies.io` (TBD)
- Agency AO / CISO: TBD
- US-CERT: <https://www.cisa.gov/report> / `soc@cisa.dhs.gov`
- FedRAMP PMO: <https://www.fedramp.gov/agency-authorization/>

For vulnerability disclosure specifically, follow [SECURITY.md](../../SECURITY.md) (GitHub
private reporting or `security@TBD`).

---

## 7 Incident record

All incidents (SEV1–SEV4) shall produce a completed incident record. Use the template at
[templates/incident-record-template.md](templates/incident-record-template.md). Records are
retained for the duration required by AU-11 (minimum 3 years for FedRAMP Moderate). Records
are stored in a location accessible to the ISSO and System Owner and referenced from the
POA&M for any incident that revealed a new weakness.

---

## 8 Plan maintenance

This plan is reviewed and updated at least **annually**. The last review was **2026-06-01**;
the next review is **2027-06-01**. It is also reviewed after every SEV1 or SEV2 incident,
after a tabletop exercise that reveals gaps, and whenever a significant change is made to
the KP alert ruleset, runbooks, or system architecture.

Reviews are recorded by updating the front-matter dates and the version field.

---

## 9 References

- Runbooks: [docs/security/runbooks/](runbooks/)
- Incident record template: [templates/incident-record-template.md](templates/incident-record-template.md)
- Contingency plan (DR): [docs/contingency-plan.md](../contingency-plan.md)
- DR runbook: [docs/runbooks/disaster-recovery.md](../runbooks/disaster-recovery.md)
- TLS cert rotation runbook: [docs/runbooks/cert-rotation.md](../runbooks/cert-rotation.md)
- Security disclosure policy: [SECURITY.md](../../SECURITY.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- SSP: [docs/compliance/ssp/SSP.md](../compliance/ssp/SSP.md)
- Alert rules: `monitoring/prometheus/rules/`
- Webhook TLS template: `charts/kube-policies/templates/admission-webhook-tls.yaml`
- SIEM integration: [docs/security/siem-integration.md](siem-integration.md)
- NIST SP 800-53 Rev 5: IR-4, IR-6, IR-8; NIST SP 800-61 Rev 2; FedRAMP Moderate baseline.
