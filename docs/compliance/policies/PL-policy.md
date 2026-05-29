---
title: "Planning Policy & Procedures (PL) — Kube-Policies (KP)"
control_family: "PL — Planning"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Planning Policy & Procedures — Kube-Policies (KP)

This policy establishes the planning requirements for the Kube-Policies system (KP),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It implements control **PL-1 (Policy and Procedures)** and **PL-2 (System
Security and Privacy Plans)**, and governs the related planning artifacts including the
**PL-8 (Security and Privacy Architectures)** description at
[security-architecture.md](../security-architecture.md).

Kube-Policies is presently a Proof-of-Concept being driven to assessment readiness. Most
controls are **Planned** or **Partial**; this policy documents the planning *discipline*
the program will operate under, not a claim that all planning artifacts are final.
Per-control status is tracked in the [control matrix](../control-matrix.csv) and open
weaknesses in the [POA&M](../poam.csv); remediation phases (P0–P12) are defined in
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually** (next review
**2027-05-29**) and whenever a significant change to the system, its boundary, its
interconnections, the threat environment, or the applicable standards occurs. Reviews are
recorded by updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that security and privacy planning for KP is
performed deliberately, documented consistently, kept current, and made available to the
roles that need it. It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace
  (`AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`, `AST-OPA`, `AST-CRD-POL`, `AST-CRD-EXC`,
  `AST-CHART`, and the backing images `AST-IMG-WH`/`AST-IMG-PM`/`AST-IMG-DB`), as defined
  in the [system facts sheet](../system-facts.md) and [inventory](../inventory.csv).
- All personnel filling the System Owner, ISSO, Authorizing Official (AO), and Independent
  Assessor roles, plus any contributors who change the system or its compliance artifacts.

Named roles are **not yet staffed**; this policy refers to them by title with the
qualifier "TBD — assign before assessment" and does not name individuals.

## 2 PL-1 — Planning Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate a planning policy and the
procedures needed to implement it; shall designate an official to manage the policy; and
shall review and update both on a defined frequency. This document is that policy.

### 2.2 PL-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Independent Assessor, and all repository contributors by being maintained
in version control under `docs/compliance/policies/` and referenced from the
[SSP](../ssp/SSP.md) (§7.12, PL family) and the [CRM](../CRM.md) (PL — Planning).

### 2.3 PL-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy, with the **System Owner (TBD — assign before assessment)** accountable for its
adequacy and resourcing. The **AO (TBD — assign before assessment)** approves the
system-level plans that this policy governs. Responsibilities are summarized in §6 and in
the roles RACI referenced by the [SSP](../ssp/SSP.md).

### 2.4 PL-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This planning policy (PL-1) | ISSO | At least annually | Significant system change; new/changed standard; assessor finding |
| [SSP](../ssp/SSP.md) (PL-2) | System Owner / ISSO | At least annually | Significant change; boundary or interconnection change; control-status change |
| [Security architecture (PL-8)](../security-architecture.md) | System Owner / ISSO | At least annually | Architecture, boundary, or data-flow change |
| Rules of behavior (PL-4) | ISSO | At least annually | Onboarding cycle; policy change |

"Significant change" includes any change to the authorization boundary
([authorization-boundary diagram](../diagrams/authorization-boundary.md)), the
interconnections (`ICX-01..06`, [interconnection register](../interconnections.md)), the
component inventory, the FIPS-199 categorization, or a material shift in the threat
environment.

### 2.5 PL-1 procedures

1. **Authoring.** Planning artifacts are authored in Markdown under `docs/compliance/`,
   carry the standard YAML front-matter (`title`, `control_family`, `version`, `status`,
   `owner`, `approver`, `last_reviewed`, `next_review`), and use the canonical asset IDs,
   ports, trust zones, and interconnection IDs from the
   [system facts sheet](../system-facts.md) verbatim.
2. **Review.** The designated official (ISSO) reviews each artifact on the schedule in
   §2.4, confirming consistency with the facts sheet, the boundary/data-flow diagrams, the
   [control matrix](../control-matrix.csv), and the [POA&M](../poam.csv).
3. **Approval.** System-level plans (SSP and its appendices) are approved by the AO; this
   policy and procedures are approved by the System Owner.
4. **Versioning and dissemination.** Changes are committed to version control; the
   `version` and `last_reviewed`/`next_review` front-matter are updated; reviewers and
   approvers are recorded in the commit history, which serves as the review record.
5. **Authority to operate.** Nothing in these artifacts constitutes an authorization to
   operate; ATO is a separate AO decision made against the finalized SSP and assessment
   results.

## 3 PL-2 — System Security and Privacy Plan

### 3.1 Policy statement

KP shall develop and maintain a System Security Plan that describes the system, its
authorization boundary, the operational and environmental context, the security
categorization, and the implementation (or planned implementation) of each applicable
control. The KP SSP is maintained at [ssp/SSP.md](../ssp/SSP.md).

### 3.2 PL-2 content requirements (and where they live)

The SSP shall, at minimum, contain or reference:

| PL-2 element | KP artifact |
|---|---|
| System identification and categorization | [SSP §1](../ssp/SSP.md); [FIPS-199 categorization](../categorization/FIPS-199.md) |
| System description and components | [SSP §2](../ssp/SSP.md); [system facts sheet](../system-facts.md); [inventory](../inventory.csv) |
| Authorization boundary and environment | [SSP §3](../ssp/SSP.md); [authorization-boundary diagram](../diagrams/authorization-boundary.md); [data-flow diagram](../diagrams/data-flow.md) |
| Interconnections | [interconnection register](../interconnections.md) (`ICX-01..06`) |
| Ports, protocols, and services | [PPS register](../ssp/ports-protocols-services.md) |
| Roles and responsibilities | [SSP §5](../ssp/SSP.md) (roles by title; TBD — assign before assessment) |
| Control implementation and status | [SSP §7](../ssp/SSP.md); [control matrix](../control-matrix.csv) |
| Security architecture (PL-8) | [security-architecture.md](../security-architecture.md) |
| Open weaknesses and remediation | [POA&M](../poam.csv); phases P0–P12 |

### 3.3 PL-2 procedures

1. **Maintain currency.** The SSP is updated on the schedule in §2.4 and on any significant
   change. The authoritative facts (asset IDs, ports, zones, `ICX` IDs) are sourced from the
   [system facts sheet](../system-facts.md); divergence between the SSP and the facts sheet
   is a defect to be reconciled, not a parallel source of truth.
2. **Honesty of "current" descriptions.** The SSP describes the as-built PoC accurately,
   including known foundational gaps (no validated FIPS module, unauthenticated planes, no
   NetworkPolicy, audit on `emptyDir`, untrustworthy CI). Aspirational or
   marketing-grade claims (e.g., in `PROJECT_SUMMARY.md`) are not carried into the SSP
   except as reconciled and scoped in [security-architecture.md](../security-architecture.md)
   under work unit **DOC-WU-30**.
3. **Plan-to-control linkage.** Every control narrative in the SSP cross-references its row
   in the [control matrix](../control-matrix.csv) (status one of
   Implemented|Partial|Planned|Inherited|Customer|Not-Applicable) and, where the control is
   not yet met, the remediating phase and POA&M entry.
4. **Distribution and protection.** The SSP and its appendices are distributed to the
   System Owner, ISSO, AO, and Independent Assessor via the version-controlled repository;
   access follows the same least-privilege model applied to the codebase.
5. **Review and approval.** The ISSO reviews; the AO approves. SSP narrative finalization
   (assessment-grade detail) is scheduled in phase **P12**.

## 4 Related planning controls (referenced, not fully specified here)

This policy is the PL family anchor. The following related planning artifacts are governed
by it and maintained alongside the SSP:

- **PL-4 Rules of Behavior** — authored as a separate artifact; reviewed annually.
- **PL-8 Security and Privacy Architectures** — the defense-in-depth architecture
  description at [security-architecture.md](../security-architecture.md), kept consistent
  with the [authorization-boundary](../diagrams/authorization-boundary.md) and
  [data-flow](../diagrams/data-flow.md) diagrams.

## 5 Compliance, exceptions, and enforcement

- Deviations from this policy require documented risk acceptance by the System Owner (within
  delegated authority) or the AO, and are recorded in the [POA&M](../poam.csv) where they
  represent an open weakness.
- Failure to maintain current planning artifacts is itself a finding; the corrective action
  is tracked through the POA&M and the remediation phases.

## 6 Roles and responsibilities (summary)

| Role | Holder | Planning responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for planning adequacy and resourcing; approves this policy; owns SSP maintenance. |
| ISSO | TBD — assign before assessment | Designated official managing this policy; authors/reviews planning artifacts; tracks POA&M. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP and renders the authorization decision. |
| Independent Assessor | TBD — assign before assessment | Independently assesses planning controls during the SAR. |

## 7 References

- [System Security Plan (SSP)](../ssp/SSP.md)
- [Security Architecture (PL-8)](../security-architecture.md)
- [Authorization Boundary Diagram](../diagrams/authorization-boundary.md)
- [Data Flow Diagram](../diagrams/data-flow.md)
- [Interconnection Register](../interconnections.md)
- [Customer Responsibility Matrix (CRM)](../CRM.md)
- [Control Matrix](../control-matrix.csv) · [POA&M](../poam.csv) · [Inventory](../inventory.csv)
- [System Facts Sheet](../system-facts.md) · [FIPS-199 Categorization](../categorization/FIPS-199.md)
- NIST SP 800-53 Rev 5 (PL-1, PL-2, PL-4, PL-8); FedRAMP Moderate baseline; FIPS-199.
