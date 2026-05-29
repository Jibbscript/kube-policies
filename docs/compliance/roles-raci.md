---
title: "ATO Roles & RACI Matrix"
control_family: "PL, PM, CA, PS (cross-cutting)"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# ATO Roles & RACI Matrix — Kube-Policies (KP)

This matrix is the authoritative responsibility assignment for the roles that bring the
Kube-Policies (KP) system (**FIPS-199 Moderate**; FedRAMP Moderate baseline) through Authorization
to Operate (ATO) and continuous operation. It is referenced by the [SSP](ssp/SSP.md) §5 and aligns
with the responsibility split in the [CRM](CRM.md).

> **Roles are not yet staffed.** Named individuals are **TBD — assign before assessment**. The
> staffing action is tracked as POA&M item **POAM-ORG-ROLES** (see [POA&M](poam.csv) and the
> [FIPS-199 categorization](categorization/FIPS-199.md)). This document assigns *responsibility by
> role title*, not by person.

## Annual review

This matrix is reviewed at least **annually** (next scheduled review **2027-05-29**) and whenever a
role is staffed or re-assigned, the authorization boundary changes, or the hosting CSP changes. The
review is performed by the ISSO and re-approved by the Authorizing Official (both TBD — assign
before assessment).

## Roles

| Role | Abbrev. | Holder | Definition / scope |
|---|---|---|---|
| **System Owner** | SO | TBD — assign before assessment | Overall accountability for the Kube-Policies system: resourcing, SSP maintenance, control-implementation oversight, and operational risk acceptance within the AO's delegation. Owns this repository's compliance artifacts. |
| **Information System Security Officer** | ISSO | TBD — assign before assessment | Day-to-day security operations: control-implementation oversight, POA&M tracking and evidence custody, ConMon execution, and first responder for system incidents. |
| **Authorizing Official** | AO | TBD — assign before assessment | Senior official who makes the risk-based **authorization (ATO) decision** and accepts residual risk on behalf of the organization. Approves the SSP and this matrix. |
| **Independent Assessor** | IA / 3PAO | TBD — assign before assessment | Independent party (or 3PAO) that performs the security control **assessment** and produces the SAR; must be independent of implementation. |
| **Cluster Operator (customer)** | CO | TBD — customer organization | The adopting organization that operates the Kubernetes cluster: implements Customer-Responsibility controls (cluster RBAC, OIDC/IdP, CNI/NetworkPolicy, etcd backup/encryption, organizational programs) per the [CRM](CRM.md). |
| **Cloud Service Provider** | CSP | TBD — hosting provider | FedRAMP-authorized hosting provider whose PE/infrastructure controls are **inherited** (see [PE policy](policies/PE-policy.md)). |

## RACI legend

**R** = Responsible (does the work) · **A** = Accountable (owns the outcome; one per activity) ·
**C** = Consulted (provides input) · **I** = Informed (kept up to date).

## RACI matrix

| Activity | Control(s) | System Owner | ISSO | AO | Independent Assessor | Cluster Operator (customer) | CSP |
|---|---|---|---|---|---|---|---|
| **Categorization approval** (FIPS-199) | RA-2 | R | C | **A** | C | C | I |
| **SSP maintenance** | PL-2 | **A**/R | R | C | C | C | I |
| **Control implementation** (System part) | CM-2, SC-7, AC-2, AU-2, IA-2, SI-2 (System portions) | **A** | R | I | C | C (cluster part) | I |
| **Control implementation** (Customer/cluster part) | AC-2, SC-7/SC-28, IA-2, CP-9 (cluster portions) | C | C | I | C | **A**/R | C (infra) |
| **Security assessment** (SAR) | CA-2 | C | C (evidence) | I | **A**/R | C | I |
| **POA&M** (creation, tracking, closure) | CA-5, PM-4 | A | **R** | I | C | C (cluster items) | I |
| **Continuous Monitoring (ConMon)** | CA-7, SI-4, AU-6 | A | **R** | I | C | R (cluster monitoring) | I |
| **Incident Response** | IR-4, IR-6, IR-8 | C | **R** (System detection) | I | I | **A**/R (org IR program & reporting) | C (infra incidents) |
| **Authorization (ATO) decision** | CA-6 | C | C | **A**/R | I | I | I |

### Notes on the matrix

- **One Accountable per activity.** Where a row shows two **A** entries, they apply to *distinct
  scopes* (e.g., the System portion of control implementation is Accountable to the System Owner,
  while the cluster portion is Accountable to the Cluster Operator). These scopes do not overlap.
- **Independent Assessor independence.** The Independent Assessor is **A/R** for the assessment and
  must not have implemented the controls it assesses (CA-2 independence). The System Owner and ISSO
  are Consulted (evidence providers), not Accountable, for the assessment.
- **AO sole authority.** Only the AO is Accountable for the **categorization approval** and the
  **ATO decision**; these are not delegable to the System Owner or ISSO.
- **CSP scope.** The CSP is **Informed** on system-level activities and **Consulted** on
  infrastructure-impacting ones; its substantive responsibility is the inherited PE/infrastructure
  posture documented in the [CRM](CRM.md) and [PE policy](policies/PE-policy.md), not
  the per-activity ATO workflow.

## Cross-references

- [SSP](ssp/SSP.md) §5 — roles & responsibilities summary (consistent with this matrix).
- [CRM](CRM.md) — System / CSP / Customer / Shared responsibility allocation by control family.
- [PS policy](policies/PS-policy.md) — personnel-security treatment of these roles (PS-2 position
  risk designation references them).
- [PE policy](policies/PE-policy.md) — CSP inheritance basis for the CSP role.
- [POA&M](poam.csv) — **POAM-ORG-ROLES** (role staffing).
- [control matrix](control-matrix.csv) — per-control `responsible_party` aligned to these roles.
