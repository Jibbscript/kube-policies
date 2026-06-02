---
title: "Incident Response Policy (IR) — Kube-Policies (KP)"
control_family: "IR — Incident Response"
controls: "IR-1, IR-4, IR-6, IR-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Incident Response Policy (IR) — Kube-Policies (KP)

This policy establishes the Incident Response requirements for the Kube-Policies system (KP),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It implements control **IR-1 (Policy and Procedures)** and anchors the IR controls
that govern how KP detects, handles, reports, and learns from security incidents: **IR-4**
(Incident Handling), **IR-6** (Incident Reporting), and **IR-8** (Incident Response Plan).
The operational steps live in the companion [IR procedures](../procedures/IR-procedures.md).
The operational IR plan is at
[docs/security/incident-response-plan.md](../../security/incident-response-plan.md); the
compliance-artifact IR plan (IR-8) is at
[docs/compliance/plans/incident-response-plan.md](../plans/incident-response-plan.md).
Runbooks for specific scenarios are under
[docs/security/runbooks/](../../security/runbooks/).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This policy documents the
incident-response *discipline* the program operates under. Per-control status is tracked in
the [control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../POAM.md),
with remediation phases (P0–P12) defined in
`../plans/remediation-roadmap.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review
was **2026-06-01**; the **next review is 2027-06-01**. It is also reviewed after any
significant incident, after a tabletop exercise finding, or whenever the system's security
surface materially changes. Reviews are recorded by updating the `last_reviewed`/`next_review`
front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that every security incident affecting KP is detected
promptly, contained to limit damage, eradicated with root-cause analysis, reported to
required parties, and used to improve the program's posture through lessons-learned
integration. It applies to:

- All KP authorization-boundary components: admission-webhook (`AST-WH`), policy-manager
  (`AST-PM`), dashboard (`AST-DB`/`AST-SPA`), Policy and PolicyException CRDs
  (`AST-CRD-POL`, `AST-CRD-EXC`), Helm chart (`AST-CHART`), and the embedded OPA/Rego
  engine (`AST-OPA`) — all running in the `kube-policies-system` namespace.
- The vulnerability disclosure process in
  [SECURITY.md](../../../SECURITY.md).
- All personnel filling the System Owner, ISSO, Operator, and Maintainer roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts referenced in
procedures are **placeholders**.

## 2 IR-1 — Incident Response Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this IR policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the procedures are in
[../procedures/IR-procedures.md](../procedures/IR-procedures.md).

### 2.2 IR-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Maintainers, and all repository contributors by being maintained in version
control under [`docs/compliance/policies/`](.) and referenced from the SSP
([../ssp/SSP.md](../ssp/SSP.md), IR family) and the [CRM](../CRM.md).

### 2.3 IR-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing.

### 2.4 IR-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This IR policy (IR-1) | ISSO | At least annually (next: 2027-06-01) | Significant incident; tabletop finding; significant system change; assessor finding |
| IR procedures ([IR-procedures.md](../procedures/IR-procedures.md)) | ISSO | At least annually (next: 2027-06-01) | Procedure drift; new incident category; runbook change |
| Operational IR plan ([docs/security/incident-response-plan.md](../../security/incident-response-plan.md)) | ISSO | At least annually; post-incident | Lessons learned; role/contact change; new failure scenario |
| Compliance IR plan ([plans/incident-response-plan.md](../plans/incident-response-plan.md)) | ISSO | Aligned with operational plan | Operational plan update |
| Runbooks ([docs/security/runbooks/](../../security/runbooks/)) | Operator | Per system change; post-incident | Procedure drift; new scenario; tool change |

## 3 KP-specific incident categories (IR-4)

KP's role as an admission-control gate creates incident categories specific to its function.
Every incident is classified by the ISSO into one of the following categories at detection
time. Severity is assigned per the matrix in §4 of the
[operational IR plan](../../security/incident-response-plan.md).

| Category | Description | Example indicators | Primary runbook |
|---|---|---|---|
| **Policy bypass** | An admission decision is rendered inconsistently with the active policy set — workloads admitted that should be denied, or policy logic subverted | Unexpected workload in a restricted namespace; compliance report discrepancy; OPA/Rego engine anomaly | [webhook-outage.md](../../security/runbooks/webhook-outage.md) §Break-glass |
| **Webhook outage** | The validate webhook is unavailable, causing all new admissions to be denied (fail-closed) | `KubePoliciesDown` alert; `KubePoliciesNoTraffic` alert; `KubePoliciesWebhookNotReady` alert | [webhook-outage.md](../../security/runbooks/webhook-outage.md) |
| **Fail-open event** | The mutate webhook failurePolicy has triggered a fail-open path, allowing workloads that should have been mutated to pass without mutation | `KubePoliciesFailOpenActive` alert; `kube_policies_admission_fail_open_total` counter increments | [fail-open-event.md](../../security/runbooks/fail-open-event.md) |
| **CRD tampering** | Policy or PolicyException CRDs are modified outside the authorized management plane — unauthorized `kubectl edit`, direct etcd write, or RBAC misconfiguration | Audit record of CRD mutation by unexpected principal; `observed_generation` drift; integrity chain failure | [webhook-outage.md](../../security/runbooks/webhook-outage.md); [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) |
| **Exception abuse** | A PolicyException is created or extended to grant a workload persistent exemption from a control it should not be exempt from | Exception created without ISSO approval; exception expiry event not generated on schedule; exception scope broader than authorized | [fail-open-event.md](../../security/runbooks/fail-open-event.md) |
| **Audit pipeline loss** | Audit records are being dropped, corrupted, or not forwarded — the tamper-evident chain is broken or the forwarder has stalled | `KubePoliciesAuditEventsDropped` alert; `KubePoliciesAuditWriteErrors` alert; `VerifyChain` failure | [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) |
| **Credential / secret exposure** | A secret, HMAC key, or credential is exposed through a log, metric, or API response | Unredacted payload in audit log; secret value visible in a Prometheus label | [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) |
| **Certificate expiry** | A TLS certificate used by KP components is expired or about to expire, causing admission failures or TLS errors | `KubePoliciesCertExpiringCritical` alert; `KubePoliciesCertExpired` alert | [cert-expiry.md](../../security/runbooks/cert-expiry.md) |

This category list is reviewed at least annually and updated when new failure modes are
identified.

## 4 IR-4 — Incident Handling

### 4.1 Handling lifecycle

KP incident handling follows the phases defined in §3 of the
[operational IR plan](../../security/incident-response-plan.md):

1. **Detection and initial triage** — alert fires or report received; on-call acknowledges
   within SLA; severity assigned.
2. **Containment** — immediate action to limit blast radius (e.g., failurePolicy change,
   workload quarantine, break-glass procedure, network policy tightening).
3. **Eradication** — root cause removed (patched binary, revoked credential, corrected CRD,
   restored policy set).
4. **Recovery** — affected component restored to known-good state; monitoring confirms
   baseline restored.
5. **Lessons learned** — post-incident review within 5 business days of closure; findings
   fed into POA&M and runbook updates.

### 4.2 Fail-closed admission behavior

The validate webhook uses `failurePolicy: Fail`. During any incident in which the webhook is
unavailable, all new admission requests to the cluster are **denied**. This is a documented
contingency behavior. On-call must follow the break-glass procedure in
[webhook-outage.md §Break-glass](../../security/runbooks/webhook-outage.md) and notify the
ISSO immediately. The mutate webhook uses `failurePolicy: Ignore`; a fail-open event in the
mutate path is itself an incident category (see §3).

### 4.3 Escalation timelines

| Severity | On-call acknowledgement | ISSO notification | AO notification | US-CERT/FedRAMP reporting |
|---|---|---|---|---|
| SEV1 — Critical | Immediate (page) | Within 15 minutes | Within 1 hour | Within 1 hour of confirmed incident (IR-6) |
| SEV2 — High | Within 15 minutes | Within 1 hour | Within 4 hours | Within 24 hours |
| SEV3 — Moderate | Within 1 hour | Within 4 hours | Not required unless escalated | Within 72 hours if government data affected |
| SEV4 — Low | Next business day | Next business day | Not required | Per POA&M |

Timelines align with FedRAMP Moderate incident-reporting requirements and the
[operational IR plan](../../security/incident-response-plan.md) §6.

## 5 IR-6 — Incident Reporting

### 5.1 Internal reporting

All incidents with severity SEV1 or SEV2 are reported internally to the System Owner, ISSO,
and AO per the escalation timelines in §4.3. The ISSO maintains an incident record for each
event using the template at
[docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md).

### 5.2 External reporting

Incidents involving a confirmed or suspected breach of government data, unauthorized access,
or a material violation of FedRAMP Moderate controls are reported to:

- **US-CERT / CISA** per [OMB M-17-12](https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2017/m-17-12_0.pdf) and the FedRAMP incident communications procedure.
- **The AO and agency ISSO** within the timelines in §4.3.

The disclosure process for externally reported vulnerabilities follows
[SECURITY.md](../../../SECURITY.md).

### 5.3 Reconciliation with SECURITY.md

The [SECURITY.md](../../../SECURITY.md) disclosure process governs how external reporters
submit vulnerabilities. Upon receipt:
1. ISSO acknowledges receipt within the response SLA (within 5 business days for Critical/High).
2. ISSO classifies the reported issue as a vulnerability (RA-5 / SI-2 track) or an active
   incident (IR-4 track).
3. Vulnerabilities that are not actively exploited enter the RA-5 / SI-2 remediation track
   with the SLAs in §6.3 of the [SECURITY.md](../../../SECURITY.md) (Critical/High: 30
   days; Moderate: 90 days; Low: 180 days) and are tracked in the
   [POA&M](../POAM.md).
4. Actively exploited vulnerabilities are immediately escalated to the incident-handling
   lifecycle (§4.1).

## 6 IR-8 — Incident Response Plan

KP shall maintain an up-to-date incident response plan that covers:

- System description, authorization boundary, and component inventory.
- Severity matrix and incident categories (§3 of this policy and the operational IR plan).
- Detection sources (Prometheus alerts, audit log anomalies, external reports).
- Handling lifecycle (§4.1).
- Escalation timelines and contact list (populated before assessment).
- Post-incident review and lessons-learned procedure.
- Annual test (tabletop exercise).

The plan is maintained at two levels:
- **Operational IR plan** — [docs/security/incident-response-plan.md](../../security/incident-response-plan.md):
  the authoritative operational document with full scenario detail, runbook cross-references,
  and the tabletop exercise record.
- **Compliance IR plan (IR-8 artifact)** — [docs/compliance/plans/incident-response-plan.md](../plans/incident-response-plan.md):
  the structured CP/IR compliance artifact that maps controls, defines ISSO roles, and
  establishes reporting timelines for the SSP reference.

## 7 Roles and responsibilities (summary)

| Role | Holder | IR responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for IR program adequacy; approves this policy; notified of SEV1/SEV2; authorizes break-glass procedures. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures/plan; classifies incidents; coordinates escalation; files external reports; leads lessons-learned; maintains POA&M for IR findings. |
| Primary on-call / Operator | TBD — assign | First responder; acknowledges alerts within SLA; executes runbook procedures; escalates to ISSO. |
| Maintainers / CODEOWNERS | TBD — assign | Produce and review patches for eradication; update runbooks post-incident. |
| Authorizing Official (AO) | TBD — assign before assessment | Notified of SEV1/SEV2; may direct break-glass or emergency configuration change; approves re-authorization if recovery introduced significant change. |

Contacts (e.g., `security@kube-policies.io`, `isso@kube-policies.io`) are **placeholders**
pending role assignment.

## 8 Compliance, exceptions, and enforcement

- Failing to notify the ISSO within the escalation timeline for a SEV1/SEV2 event is a
  reportable deviation requiring POA&M documentation.
- Failing to file an external incident report within the required timeline when government
  data is involved is a material compliance failure requiring immediate AO notification.
- A new alert rule or runbook that does not have a corresponding incident category entry in
  §3 of this policy requires an ISSO review before merge.
- Modifying `failurePolicy` on the validate webhook to `Ignore` outside of the documented
  break-glass procedure requires ISSO approval and a POA&M entry.
- Skipping the annual IR plan test (tabletop exercise) requires ISSO and System Owner
  approval and a POA&M entry.

## 9 References

- IR procedures: [../procedures/IR-procedures.md](../procedures/IR-procedures.md)
- Operational IR plan: [docs/security/incident-response-plan.md](../../security/incident-response-plan.md)
- Compliance IR plan (IR-8): [docs/compliance/plans/incident-response-plan.md](../plans/incident-response-plan.md)
- Runbooks: [docs/security/runbooks/](../../security/runbooks/) — `webhook-outage.md`, `fail-open-event.md`, `audit-pipeline-loss.md`, `cert-expiry.md`, `deny-rate-spike.md`, `high-error-rate.md`, `dos-response.md`
- Tabletop exercise record: [docs/security/ir-tabletop-2026.md](../../security/ir-tabletop-2026.md)
- On-call escalation: [docs/security/on-call-escalation.md](../../security/on-call-escalation.md)
- Incident record template: [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md)
- Vulnerability disclosure: [SECURITY.md](../../../SECURITY.md)
- Monitoring alerts: `charts/kube-policies/files/alerts/security.yaml` · `charts/kube-policies/files/alerts/availability.yaml`
- AU policy (audit integrity): [AU-policy.md](AU-policy.md)
- CP policy (continuity): [CP-policy.md](CP-policy.md)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (IR-1, IR-4, IR-6, IR-8); FedRAMP Moderate baseline; FIPS-199; OMB M-17-12.
