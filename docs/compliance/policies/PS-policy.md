---
title: "Personnel Security Policy (PS)"
control_family: "PS"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Personnel Security Policy (PS) — Kube-Policies (KP)

This policy addresses the NIST SP 800-53 Rev 5 **Personnel Security (PS)** family for the
Kube-Policies (KP) system (**FIPS-199 Moderate**; FedRAMP Moderate baseline). It establishes the
PS-1 policy artifact and records how the PS family is allocated for this system. The authoritative
responsibility split is in the [CRM](../CRM.md) (PS family) and the per-control status is in the
[control matrix](../control-matrix.csv); this document is the family policy that those artifacts
reference.

> **Scope honesty note.** Personnel Security is overwhelmingly an **organizational / HR program**,
> not a software control. The Kube-Policies repository can author this PS-1 policy and define
> roles, but it **cannot** implement screening, position-risk designation, or third-party
> personnel agreements — those require a **human program owner** in the adopting organization.
> Most PS controls are therefore **Customer-Responsibility** (see the
> [CRM PS allocation](../CRM.md)), and the System portion is limited to policy authorship.

## Annual review

This policy is reviewed and updated at least **annually** (next scheduled review **2027-05-29**)
and whenever the personnel program, the role assignments, or the system's authorization boundary
materially changes. The review is performed by the ISSO (TBD — assign before assessment) and
re-approved by the Authorizing Official (TBD — assign before assessment), consistent with PS-1.

## PS-1 — Policy and Procedures

- **Purpose.** Define personnel-security expectations for everyone with logical or administrative
  access to the Kube-Policies system and its hosting cluster, and assign ownership of the
  organizational PS program.
- **Allocation.** **System-authored policy; Customer-operated program.** The System (this
  repository) maintains this PS-1 artifact and the [roles & RACI matrix](../roles-raci.md). The
  adopting organization (Customer / cluster operator) owns and operates the PS program.
- **Program owner (must be a human).** A named personnel-security program owner — typically the
  organization's HR/security function in coordination with the System Owner and ISSO — must be
  assigned. Until staffed, the named ATO roles (System Owner, ISSO, AO, Independent Assessor) are
  carried as **"TBD — assign before assessment"** and the staffing action is tracked as POA&M item
  **POAM-ORG-ROLES** (see [POA&M](../poam.csv) and the
  [FIPS-199 categorization](../categorization/FIPS-199.md), which also references POAM-ORG-ROLES).
- **Procedures.** Position-risk designation (PS-2), screening (PS-3), termination and transfer
  (PS-4/PS-5), access agreements (PS-6), and third-party personnel controls (PS-7) are implemented
  by the organization's documented procedures; this policy points to them rather than restating
  them, because they are not repository-resolvable.
- **Status:** Planned → P0/P12 (policy authored in P0; finalized and approved at assessment in
  P12). See [control matrix](../control-matrix.csv).

## PS-2 — Position Risk Designation

- **Requirement.** Assign a risk designation (e.g., low / moderate / high) to every position that
  has access to the system, review designations periodically, and use them to drive the screening
  level under PS-3.
- **Allocation.** **Customer-Responsibility (organizational / HR).** Kube-Policies cannot
  designate position risk; the adopting organization must.
- **Reference positions for designation.** The organization should designate, at minimum, the
  roles that operate or assess this system — **System Owner**, **ISSO**, **Cluster Operator
  (customer)**, and any developers with commit/release authority over the
  `github.com/Jibbscript/kube-policies` repository and its CI. Privileged cluster operators with
  write access to the `kube-policies-system` namespace, the `Policy`/`PolicyException` CRDs
  (`AST-CRD-POL`, `AST-CRD-EXC`), or `ALLOW_WRITES`-enabled dashboard access should carry an
  elevated designation.
- **Status:** Planned (Customer). See [control matrix](../control-matrix.csv).

## PS-3 — Personnel Screening

- **Requirement.** Screen individuals before authorizing access and rescreen per the position-risk
  designation (PS-2) and organizational policy.
- **Allocation.** **Customer-Responsibility (organizational / HR).**
- **Status:** Planned (Customer).

## PS-4 / PS-5 — Personnel Termination and Transfer

- **Requirement.** On termination or transfer, revoke logical access (cluster RBAC, OIDC/IdP
  accounts, repository and CI credentials), recover system-related property, and conduct exit
  procedures within organization-defined timeframes.
- **System touchpoint.** When OIDC login (P3) and least-privilege ServiceAccount scoping land, the
  organization's de-provisioning must remove dashboard/API and cluster access; until then, access
  removal is handled at the cluster RBAC / IdP layer the Customer operates.
- **Allocation.** **Customer-Responsibility (organizational / HR), with a System touchpoint for
  access revocation.**
- **Status:** Planned (Customer).

## PS-6 — Access Agreements

- **Requirement.** Require and maintain signed access agreements (e.g., acceptable-use, rules of
  behavior) before granting access, and review them periodically. The system rules of behavior are
  authored under the PL family (see [SSP](../ssp/SSP.md)).
- **Allocation.** **Customer-Responsibility (organizational).**
- **Status:** Planned (Customer).

## PS-7 — External / Third-Party Personnel Security

- **Requirement.** Establish personnel-security requirements (screening, agreements, notification
  of transfers/terminations) for **third-party providers** and monitor their compliance.
- **Applicability to Kube-Policies.** Third-party personnel in scope include: the **hosting CSP's**
  staff who operate the underlying infrastructure (covered by that CSP's own FedRAMP-authorized PS
  program and inherited via the customer's ATO package — see [CRM](../CRM.md)); any **managed-service
  or contractor** operators of the customer's cluster; and external contributors with
  commit/release rights to the repository or its supply chain (cross-reference the SR family).
- **Allocation.** **Customer-Responsibility (organizational), with CSP-inherited coverage for the
  hosting provider's own staff.** The customer must obtain and verify the CSP's PS attestations and
  impose PS-7 requirements on any third-party cluster operators.
- **Status:** Planned (Customer).

## Roles

This policy uses the role titles defined in the [roles & RACI matrix](../roles-raci.md):
**System Owner**, **ISSO**, **Authorizing Official (AO)**, **Independent Assessor**, **Cluster
Operator (customer)**, and **CSP**. Named individuals are **not yet staffed**; assign before
assessment (tracked as **POAM-ORG-ROLES**).

## Cross-references

- [CRM](../CRM.md) — PS family allocation (Customer-Responsibility; System provides PS-1 only).
- [control matrix](../control-matrix.csv) — per-control PS status and responsible party.
- [POA&M](../poam.csv) — POAM-ORG-ROLES (role staffing) and other open PS-program items.
- [roles & RACI matrix](../roles-raci.md) — authoritative responsibility assignment.
- [SSP](../ssp/SSP.md) — system roles & responsibilities and rules of behavior (PL).
- [system facts](../system-facts.md) — component, asset, and boundary identifiers.
