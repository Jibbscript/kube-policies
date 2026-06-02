---
title: "Awareness and Training Policy (AT) — Kube-Policies (KP)"
control_family: "AT — Awareness and Training"
controls: "AT-1, AT-2, AT-3"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Awareness and Training Policy (AT) — Kube-Policies (KP)

This policy establishes the security awareness and training requirements for the Kube-Policies
system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP
**Moderate** baseline). It implements control **AT-1 (Policy and Procedures)** and anchors the AT
controls that govern security literacy and role-based training: **AT-2 (Literacy Training and
Awareness)** and **AT-3 (Role-Based Training)**. It is the AT-family anchor; per-control status is
tracked in the [control matrix](../control-matrix.csv) and open weaknesses in the
[POA&M](../POAM.md), with remediation phases (P0–P12) defined in
`../plans/remediation-roadmap.md`.

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is **not
yet authorized** (**no ATO**) and not in production use. The AT family is overwhelmingly an
**organizational / inherited program** — the repository can author this AT-1 policy and define
role-based training requirements, but it **cannot** deliver or record security training; those
require a **human program owner** in the adopting organization. Most AT controls are therefore
**Customer-Responsibility** (see the [CRM AT allocation](../CRM.md)), and the System portion is
limited to policy authorship and role-based training requirements definition.

**Annual review.** This policy is reviewed and updated at least **annually** (next review
**2027-06-01**) and whenever a significant change to the system, the role assignments, the threat
environment, or the applicable standards occurs. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that all personnel with roles related to the Kube-Policies
system receive appropriate security awareness training and role-specific security training before
being granted access and on a recurring basis thereafter.

This policy applies to:

- All personnel filling defined KP roles: **System Owner**, **ISSO**, **Authorizing Official
  (AO)**, **Independent Assessor**, **Cluster Operator (customer)**, and **Repository Maintainer**
  (any individual with commit or release authority over `github.com/Jibbscript/kube-policies` and
  its CI/CD pipeline).
- All KP authorization-boundary components in the `kube-policies-system` namespace
  (`AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`, `AST-OPA`, `AST-CRD-POL`, `AST-CRD-EXC`,
  `AST-CHART`, and the backing images `AST-IMG-WH`/`AST-IMG-PM`/`AST-IMG-DB`), as defined in
  the [system facts sheet](../system-facts.md) and [inventory](../inventory.csv), insofar as their
  operators are covered by this policy.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals. Role staffing is tracked as
**POAM-ORG-ROLES** in the [POA&M](../POAM.md).

## 2 AT-1 — Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate an awareness and training policy and the
procedures needed to implement it; shall designate an official to manage the policy; and shall
review and update both on a defined frequency. This document is that policy.

### 2.2 AT-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System Owner,
ISSO, AO, Independent Assessor, and all repository contributors by being maintained in version
control under `docs/compliance/policies/` and referenced from the [SSP](../ssp/SSP.md) (AT
family) and the [CRM](../CRM.md) (AT — Awareness and Training).

### 2.3 AT-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update this
policy, with the **System Owner (TBD — assign before assessment)** accountable for its adequacy
and resourcing. The **AO (TBD — assign before assessment)** approves the authorization package
that this policy supports. Responsibilities are summarized in §6 and in the roles RACI referenced
by the [SSP](../ssp/SSP.md).

### 2.4 AT-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This AT policy (AT-1) | ISSO | At least annually | Significant system or role change; new/changed standard; assessor finding |
| Training curriculum and completion records (AT-2/AT-3) | ISSO / System Owner | At least annually | New threat; role change; post-incident finding; new personnel |
| Role-based training content (AT-3) | ISSO | At least annually | New component, capability, or role; significant architectural change |

### 2.5 AT-1 procedures

1. **Authoring.** This policy is maintained in Markdown under `docs/compliance/policies/`,
   carrying the standard YAML front-matter, and referencing the canonical role titles from the
   [roles & RACI matrix](../roles-raci.md).
2. **Review.** The designated official (ISSO) reviews this policy on the schedule in §2.4 and
   coordinates with the adopting organization's training program owner on curriculum currency.
3. **Approval.** This policy is approved by the System Owner; training curricula and completion
   records are approved by the ISSO.
4. **Versioning and dissemination.** Changes are committed to version control; the `version` and
   `last_reviewed`/`next_review` front-matter are updated; reviewers and approvers are recorded
   in the commit history, which serves as the review record.

## 3 AT-2 — Literacy Training and Awareness

### 3.1 Policy statement

All individuals with access to the KP system shall complete **basic security awareness training**
before being granted access and at least **annually** thereafter. The training shall cover, at
minimum:

- Insider threat awareness (AT-2(2)) — recognizing and reporting indicators of malicious insider
  activity.
- Social engineering and phishing (AT-2(3)) — recognizing and avoiding social-engineering and
  mining attacks.
- Acceptable use of KP system resources and the organization's rules of behavior (cross-reference
  PL-4; see [SSP](../ssp/SSP.md)).
- Responsibilities for protecting sensitive data and reporting security incidents.

### 3.2 Allocation and system boundary

**Allocation: Customer-Responsibility (organizational training program).** The System (this
repository) defines the requirement and the minimum curriculum topics; the adopting organization
designs, delivers, and records the training. The ISSO is responsible for confirming that the
adopting organization's training program satisfies these requirements before granting system access.

### 3.3 AT-2 procedures (organizational obligation)

1. The adopting organization shall maintain a documented security awareness training program that
   covers the topics in §3.1.
2. Training completion shall be recorded and the records retained for the period required by the
   organization's record-retention policy (minimum: duration of access plus one year).
3. The ISSO shall obtain evidence of training completion for all in-scope KP personnel before each
   annual review and before granting access to new personnel.

## 4 AT-3 — Role-Based Training

### 4.1 Policy statement

Personnel filling **security-significant roles** for KP shall complete **role-based training**
specific to their responsibilities before assuming those responsibilities and at least **annually**
thereafter. Role-based training supplements (not replaces) the general awareness training in §3.

### 4.2 Role-based training requirements

The following roles and their minimum training scope are defined. The adopting organization is
responsible for sourcing or developing training materials that meet these requirements.

| Role | Holder | Minimum role-based training scope |
|---|---|---|
| System Owner | TBD — assign before assessment | NIST RMF/FedRAMP system ownership; SSP maintenance; POA&M oversight; risk acceptance. |
| ISSO | TBD — assign before assessment | NIST SP 800-53 Rev 5 control implementation and assessment; FedRAMP ConMon; incident response; POA&M management; audit log review. |
| Authorizing Official (AO) | TBD — assign before assessment | Risk-based authorization decisions; FedRAMP ATO process; reviewing 3PAO findings. |
| Independent Assessor | TBD — assign before assessment | Security assessment methodology (NIST SP 800-53A); FedRAMP 3PAO requirements; independence requirements. |
| Cluster Operator (customer) | TBD — customer organization | Kubernetes RBAC; NetworkPolicy; etcd encryption and backup; cluster hardening (CIS Kubernetes Benchmark); incident reporting to KP ISSO. |
| Repository Maintainer | TBD — assign before assessment | Secure software development (NIST SP 800-218 SSDF); supply-chain integrity (signing, attestation, SBOM — see [SR-policy](SR-policy.md)); code review security; dependency and vulnerability management; CI/CD pipeline security. |

### 4.3 Allocation and system boundary

**Allocation: Customer-Responsibility (organizational training program) with System-defined
requirements.** The System defines the role-based training requirements in §4.2; the adopting
organization designs or procures and delivers the training content, and records completion.

### 4.4 AT-3 procedures (organizational obligation)

1. The ISSO shall confirm that role-based training has been completed and recorded for each
   individual before they assume a security-significant KP role.
2. Refresher training shall be completed at least annually or whenever the role scope, the system
   architecture, or the applicable standards change materially.
3. The ISSO shall retain training completion records for the duration of the role assignment plus
   one year, as evidence for the assessment (CA-2) and ConMon.
4. Post-incident reviews (IR family) may identify training gaps; the ISSO shall update the
   role-based training curriculum to close identified gaps and track updates in the
   [POA&M](../POAM.md).

## 5 Related controls

- **AT-4 (Training Records)** — Customer-Responsibility (organizational). The organization shall
  maintain training completion records and make them available to the ISSO and Independent
  Assessor on request. Status: Planned (Customer); see [control matrix](../control-matrix.csv).
- **PL-4 (Rules of Behavior)** — governed by the PL policy ([PL-policy](PL-policy.md)); the rules
  of behavior are a pre-condition for access and are incorporated into the AT-2 awareness
  training.
- **PS-3 (Personnel Screening)** — governed by the PS policy ([PS-policy](PS-policy.md));
  screening is a prerequisite for access, complementing training.
- **IR-2 (Incident Response Training)** — role-based IR training is addressed in the IR family
  and cross-referenced from the AT-3 curriculum in §4.2.

## 6 Compliance, exceptions, and enforcement

- Deviations from this policy (e.g., granting access before training completion) require
  documented risk acceptance by the System Owner and are recorded in the [POA&M](../POAM.md).
- Failure to complete required training is a condition for access suspension; the ISSO is
  responsible for enforcing this requirement and coordinating with the System Owner on
  remediation.
- The Independent Assessor will verify training records and compliance with this policy during the
  security assessment (CA-2).

## 7 Roles and responsibilities (summary)

| Role | Holder | Training responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for training program adequacy and resourcing; approves this policy; ensures training budget and scheduling. |
| ISSO | TBD — assign before assessment | Designated official managing this policy; confirms training completion before access; tracks training records and POA&M. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the authorization package supported by this policy; receives evidence of training program adequacy. |
| Independent Assessor | TBD — assign before assessment | Independently assesses training controls during the SAR; reviews completion records. |
| Cluster Operator (customer) | TBD — customer organization | Completes awareness and role-based training per §3 and §4; provides completion evidence to ISSO. |
| Repository Maintainer | TBD — assign before assessment | Completes secure development and supply-chain training per §4.2; maintains training currency annually. |

## 8 References

- [System Security Plan (SSP)](../ssp/SSP.md)
- [Customer Responsibility Matrix (CRM)](../CRM.md) — AT family allocation
- [Roles & RACI Matrix](../roles-raci.md)
- [Control Matrix](../control-matrix.csv) · [POA&M](../POAM.md) · [Inventory](../inventory.csv)
- [System Facts Sheet](../system-facts.md)
- [PL Policy (PL-4 Rules of Behavior)](PL-policy.md)
- [PS Policy (PS-3 Personnel Screening)](PS-policy.md)
- [SR Policy (Supply Chain — Maintainer training scope)](SR-policy.md)
- NIST SP 800-53 Rev 5 (AT-1, AT-2, AT-2(2), AT-2(3), AT-3, AT-4); FedRAMP Moderate baseline;
  NIST SP 800-218 (SSDF); NIST SP 800-53A Rev 5 (assessment procedures).
