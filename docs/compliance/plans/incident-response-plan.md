---
title: "Incident Response Plan — Compliance Artifact (IR-8) — Kube-Policies (KP)"
control_family: "IR — Incident Response"
controls: "IR-4, IR-6, IR-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Incident Response Plan — Compliance Artifact (IR-8) — Kube-Policies (KP)

This is the **compliance-artifact Incident Response Plan (IR-8)** for the Kube-Policies
system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP
**Moderate** baseline). It is the structured IR-8 artifact referenced by the
[IR policy](../policies/IR-policy.md) and the [SSP](../ssp/SSP.md).

**Do not duplicate operational content here.** The authoritative operational plan — including
the full severity matrix, scenario playbooks, containment procedures, and tabletop exercise
checklist — is at:

> **[docs/security/incident-response-plan.md](../../security/incident-response-plan.md)**

This document provides the structured IR-8 compliance fields: control mappings, ISSO role
definitions, reporting timelines, and the evidence trace required for the SSP and assessment.
All operational detail is cross-referenced to the documents listed above rather than
reproduced here.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. Named roles are **TBD —
assign before assessment**. Contact addresses are **placeholders**.

---

## 1 Plan identification and scope (IR-8(a))

| Field | Value |
|---|---|
| System name | Kube-Policies (KP) |
| System identifier | `github.com/Jibbscript/kube-policies` |
| FIPS-199 categorization | Moderate (Confidentiality M, Integrity M, Availability M) |
| Authorization boundary | `kube-policies-system` namespace: AST-WH, AST-PM, AST-DB/SPA, AST-CRD-POL, AST-CRD-EXC, AST-CHART, AST-OPA |
| Plan version | 0.1.0 |
| Plan status | Draft — not yet assessed |
| Last reviewed | 2026-06-01 |
| Next review | 2027-06-01 |

---

## 2 Control mappings

This plan satisfies the following NIST SP 800-53 Rev 5 controls:

| Control | Title | Implementation | Status |
|---|---|---|---|
| IR-4 | Incident Handling | Operational IR plan §§3–5; runbooks under [docs/security/runbooks/](../../security/runbooks/) | Planned (P9) |
| IR-4(1) | Automated Incident Handling | Prometheus/Alertmanager alert pipeline; [docs/security/siem-integration.md](../../security/siem-integration.md) | Planned (P9) |
| IR-6 | Incident Reporting | Escalation timelines in [IR-policy.md §4.3](../policies/IR-policy.md#43-escalation-timelines); external reporting per SECURITY.md | Planned (P9) |
| IR-6(1) | Automated Reporting | SIEM forwarding via [docs/security/siem-integration.md](../../security/siem-integration.md) | Planned (P9) |
| IR-8 | Incident Response Plan | This document + [docs/security/incident-response-plan.md](../../security/incident-response-plan.md) | Planned (P9) |

Per-control implementation status is tracked in the [control matrix](../control-matrix.csv)
and open weaknesses in the [POA&M](../POAM.md).

---

## 3 Roles and responsibilities (IR-8(b))

| Role | Title | IR responsibility |
|---|---|---|
| ISSO | TBD — assign before assessment | IR plan owner; incident classifier; escalation coordinator; external reporting authority; lessons-learned lead; POA&M curator for IR findings |
| System Owner | TBD — assign before assessment | IR program accountable executive; approves break-glass procedures; notified of SEV1/SEV2; authorizes reauthorization if recovery introduced significant change |
| Primary on-call / Operator | TBD — assign | First responder; alert acknowledgement within SLA; runbook executor; ISSO notification |
| Maintainers / CODEOWNERS | TBD — assign | Eradication patch authors; runbook maintainers; post-incident code review |
| Authorizing Official (AO) | TBD — assign before assessment | Notified of SEV1/SEV2; receives external reporting coordination; approves re-authorization |
| Independent Assessor | TBD — assign before assessment | Assesses IR control effectiveness; reviews tabletop exercise record |

All contacts (e.g., `isso@kube-policies.io`, `security@kube-policies.io`) are
**placeholders** pending role assignment per [roles-raci.md](../roles-raci.md).

---

## 4 Incident categories specific to KP (IR-4)

The KP admission-control function creates the following system-specific incident categories.
Full definitions, indicators, and runbook references are in
[IR-policy.md §3](../policies/IR-policy.md#3-kp-specific-incident-categories-ir-4):

1. **Policy bypass** — unauthorized workload admitted through the validate webhook
2. **Webhook outage** — validate webhook unavailable; all admissions denied (fail-closed)
3. **Fail-open event** — mutate webhook fail-open path triggered; workloads pass without mutation
4. **CRD tampering** — Policy/PolicyException CRDs modified outside the authorized management plane
5. **Exception abuse** — PolicyException created or extended without authorization
6. **Audit pipeline loss** — audit records dropped, corrupted, or not forwarded; hash chain broken
7. **Credential/secret exposure** — secret or HMAC key leaked through log, metric, or API
8. **Certificate expiry** — TLS certificate expired or about to expire

---

## 5 Reporting timelines (IR-6)

| Severity | On-call acknowledgement | ISSO notification | AO notification | US-CERT/FedRAMP |
|---|---|---|---|---|
| SEV1 — Critical | Immediate (page) | ≤ 15 minutes | ≤ 1 hour | ≤ 1 hour of confirmed incident |
| SEV2 — High | ≤ 15 minutes | ≤ 1 hour | ≤ 4 hours | ≤ 24 hours |
| SEV3 — Moderate | ≤ 1 hour | ≤ 4 hours | Not required unless escalated | ≤ 72 hours if government data affected |
| SEV4 — Low | Next business day | Next business day | Not required | Per POA&M |

External reporting to US-CERT/CISA follows OMB M-17-12 and the agency's incident reporting
procedures. For FedRAMP-authorized deployments the 3PAO and FedRAMP PMO are also notified.

---

## 6 Operational procedures cross-reference

For each operational activity, the authoritative source is:

| Activity | Authoritative source |
|---|---|
| Severity matrix and escalation | [docs/security/incident-response-plan.md §2–3](../../security/incident-response-plan.md) |
| Detection sources and triage | [docs/compliance/procedures/IR-procedures.md §2](../procedures/IR-procedures.md) |
| Containment, eradication, recovery | [docs/compliance/procedures/IR-procedures.md §3](../procedures/IR-procedures.md) |
| Scenario-specific runbooks | [docs/security/runbooks/](../../security/runbooks/) |
| External reporting | [docs/compliance/procedures/IR-procedures.md §4.2](../procedures/IR-procedures.md) |
| Lessons-learned process | [docs/compliance/procedures/IR-procedures.md §3.4](../procedures/IR-procedures.md) |
| Tabletop exercise | [docs/security/ir-tabletop-2026.md](../../security/ir-tabletop-2026.md) |
| Vulnerability disclosure triage | [SECURITY.md](../../../SECURITY.md) |

---

## 7 Plan maintenance (IR-8)

This compliance artifact and the operational IR plan are reviewed and updated:

- At least **annually** (next review: 2027-06-01).
- After any significant incident (within 30 days of lessons-learned completion).
- After a tabletop exercise finding that reveals a gap in this plan.
- When roles, contacts, or the authorization boundary change.

Reviews are recorded by updating the `last_reviewed`/`next_review` front-matter and the
version in both this artifact and the operational IR plan.

---

## 8 References

- Operational IR plan: [docs/security/incident-response-plan.md](../../security/incident-response-plan.md)
- IR policy: [docs/compliance/policies/IR-policy.md](../policies/IR-policy.md)
- IR procedures: [docs/compliance/procedures/IR-procedures.md](../procedures/IR-procedures.md)
- Runbooks: [docs/security/runbooks/](../../security/runbooks/)
- Tabletop exercise: [docs/security/ir-tabletop-2026.md](../../security/ir-tabletop-2026.md)
- On-call escalation: [docs/security/on-call-escalation.md](../../security/on-call-escalation.md)
- Incident record template: [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md)
- SIEM integration: [docs/security/siem-integration.md](../../security/siem-integration.md)
- Vulnerability disclosure: [SECURITY.md](../../../SECURITY.md)
- CP policy: [docs/compliance/policies/CP-policy.md](../policies/CP-policy.md)
- AU policy (audit integrity): [docs/compliance/policies/AU-policy.md](../policies/AU-policy.md)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · SSP: [../ssp/SSP.md](../ssp/SSP.md)
- NIST SP 800-53 Rev 5 (IR-4, IR-6, IR-8); FedRAMP Moderate baseline; FIPS-199; OMB M-17-12.
