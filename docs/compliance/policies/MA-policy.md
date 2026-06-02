---
title: "Maintenance Policy (MA) — Kube-Policies (KP)"
control_family: "MA — Maintenance"
controls: "MA-1, MA-2, MA-4"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Maintenance Policy (MA) — Kube-Policies (KP)

This policy establishes the maintenance requirements for the Kube-Policies system (KP), categorized
**FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate** baseline). It implements
control **MA-1 (Policy and Procedures)** and anchors the MA controls that govern controlled
maintenance of KP components: **MA-2 (Controlled Maintenance)** and **MA-4 (Nonlocal
Maintenance)**. It is the MA-family anchor; per-control status is tracked in the
[control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../POAM.md), with
remediation phases (P0–P12) defined in
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is **not
yet authorized** (**no ATO**) and not in production use. The MA family is **Shared** between the
System and the Customer/CSP: at the application layer (container images, Go module dependencies,
Helm chart), the System is responsible; at the infrastructure layer (physical hosts, etcd cluster
hardware, networking gear), maintenance is **Inherited from the hosting CSP** or is
**Customer-Responsibility** for the Kubernetes cluster. The authoritative allocation split is in
the [CRM MA allocation](../CRM.md); this document is the family policy that those artifacts
reference.

> **Scope honesty note.** Physical and infrastructure-layer maintenance (MA-3, MA-5) is wholly
> inherited from the CSP or is Customer-Responsibility and is **not** implemented in this
> repository. This policy documents only the System-layer maintenance controls: patch cadence for
> container images and Go dependencies (MA-2 application layer) and the remote-access posture for
> KP cluster interactions (MA-4). Claims are limited to what is actually implemented.

**Annual review.** This policy is reviewed and updated at least **annually** (next review
**2027-06-01**) and whenever a significant change to the system, its component inventory, the
build/release pipeline, the threat environment, or the applicable standards occurs. Reviews are
recorded by updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that maintenance of KP system components is performed in
a controlled, authorized, and documented manner; that patching of container images and Go
dependencies follows a defined cadence; and that any remote (nonlocal) maintenance access to the
KP system is authenticated, encrypted, and authorized.

This policy applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace
  (`AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`, `AST-OPA`, `AST-CRD-POL`, `AST-CRD-EXC`,
  `AST-CHART`, and the backing images `AST-IMG-WH`/`AST-IMG-PM`/`AST-IMG-DB`), as defined in
  the [system facts sheet](../system-facts.md) and [inventory](../inventory.csv).
- The KP Helm chart (`AST-CHART`) and all Go module dependencies declared in `go.mod`.
- The CI/CD pipeline (`.github/workflows/`) insofar as it performs automated maintenance
  (dependency scanning, image builds, release signing).
- All personnel who perform or authorize maintenance activities on KP components, including the
  System Owner, ISSO, and Repository Maintainers.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment." Role staffing is tracked as **POAM-ORG-ROLES** in the
[POA&M](../POAM.md).

## 2 MA-1 — Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate a maintenance policy and the procedures
needed to implement it; shall designate an official to manage the policy; and shall review and
update both on a defined frequency. This document is that policy.

### 2.2 MA-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System Owner,
ISSO, AO, Independent Assessor, and all repository contributors by being maintained in version
control under `docs/compliance/policies/` and referenced from the [SSP](../ssp/SSP.md) (MA
family) and the [CRM](../CRM.md) (MA — Maintenance).

### 2.3 MA-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update this
policy, with the **System Owner (TBD — assign before assessment)** accountable for its adequacy
and resourcing. Responsibilities are summarized in §6 and in the roles RACI referenced by the
[SSP](../ssp/SSP.md).

### 2.4 MA-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This MA policy (MA-1) | ISSO | At least annually | Significant system or pipeline change; new/changed standard; assessor finding |
| Patch cadence procedure (MA-2) | ISSO / System Owner | At least annually | New CVE disclosure; base-image EOL; Go toolchain update |
| Nonlocal maintenance authorization records (MA-4) | ISSO | At least annually; per-session | New remote-access method; architecture change; credential rotation |

### 2.5 MA-1 procedures

1. **Authoring.** This policy is maintained in Markdown under `docs/compliance/policies/`,
   carrying the standard YAML front-matter, and referencing the canonical asset IDs from the
   [system facts sheet](../system-facts.md) verbatim.
2. **Review.** The designated official (ISSO) reviews this policy on the schedule in §2.4,
   confirming consistency with the [control matrix](../control-matrix.csv), the
   [POA&M](../POAM.md), and the current CI/CD pipeline state.
3. **Approval.** This policy is approved by the System Owner. Session-level maintenance
   authorization records are approved by the ISSO before each maintenance window.
4. **Versioning and dissemination.** Changes are committed to version control; the `version` and
   `last_reviewed`/`next_review` front-matter are updated; reviewers and approvers are recorded
   in the commit history, which serves as the review record.

## 3 MA-2 — Controlled Maintenance

### 3.1 Policy statement

All maintenance of KP authorization-boundary components shall be **planned, authorized, and
documented**. At the application layer (container images, Go dependencies, Helm chart), maintenance
is delivered via the CI/CD GitOps pipeline. At the infrastructure layer, maintenance is inherited
from the CSP or delegated to the Cluster Operator per the [CRM](../CRM.md).

### 3.2 Scope of System-layer controlled maintenance

KP system-layer maintenance encompasses:

1. **Container image patching.** Base images for `AST-IMG-WH`, `AST-IMG-PM`, and `AST-IMG-DB`
   are rebuilt on a defined cadence using the release pipeline
   ([`.github/workflows/release.yml`](../../../.github/workflows/release.yml)) and whenever a
   critical or high-severity CVE is disclosed for a base image layer. Rebuilt images are signed
   and attested per the supply-chain controls in the
   [SR policy](SR-policy.md) and the
   [supply-chain control narrative](../supply-chain.md).
2. **Go module dependency updates.** Go module dependencies declared in `go.mod` are reviewed and
   updated on a defined cadence and whenever `govulncheck` (executed in the CI workflow
   [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)) or Dependabot flags a
   vulnerability. Dependency updates follow the flaw-remediation schedule in §3.4 and cross-
   reference the supply-chain integrity controls in the [SR policy](SR-policy.md).
3. **Helm chart updates.** Maintenance updates to the KP Helm chart (`AST-CHART`) are staged in
   a feature branch, reviewed via pull request, and merged only after CI passes (linting,
   kubeconform validation, conftest policy checks per
   [`.github/workflows/compliance.yml`](../../../.github/workflows/compliance.yml)).
4. **Policy and configuration updates.** Changes to OPA/Rego policies (`AST-OPA`), CRD schemas
   (`AST-CRD-POL`, `AST-CRD-EXC`), and admission-webhook configuration (`AST-WH`) are treated
   as maintenance events subject to the same GitOps branch/review/merge discipline.

### 3.3 Maintenance authorization

- All maintenance changes to KP components shall be introduced via a **pull request** to the
  `github.com/Jibbscript/kube-policies` repository.
- Pull requests require **at least one approving review** by a Repository Maintainer before merge.
- **Emergency patches** (critical CVE, active exploit) may follow an expedited review but must
  still have a pull request, a minimum review, and a post-hoc ISSO notification within 24 hours.
- The ISSO maintains the maintenance authorization record in version control (PR merge history
  plus this policy); no separate paper record is required for routine maintenance.

### 3.4 Patch cadence and flaw-remediation schedule

| Severity (CVSS v3) | Maximum remediation window | Mechanism |
|---|---|---|
| Critical (9.0–10.0) | 30 days | Emergency patch; expedited PR review |
| High (7.0–8.9) | 30 days | Scheduled patch release; standard PR review |
| Medium (4.0–6.9) | 90 days | Next scheduled release cycle |
| Low / Informational | 180 days or next major release | Deferred to planned maintenance window |

These windows are consistent with FedRAMP Moderate continuous-monitoring requirements. Open
vulnerabilities outside the remediation window are tracked in the [POA&M](../POAM.md).

Automated vulnerability scanning is executed in every CI run via `govulncheck` and Trivy (image
scanning) in [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml). Scan results are
reviewed by the ISSO at each ConMon cycle.

### 3.5 Infrastructure-layer maintenance (inherited / Customer)

Physical and infrastructure-layer maintenance of the hosting cluster — including etcd node
maintenance, underlying OS patching, hardware replacement, and physical media handling — is
**Inherited from the hosting CSP** (MA-2 at infrastructure layer) or is **Customer-Responsibility**
for the Kubernetes cluster operator. The Cluster Operator must confirm that their CSP's maintenance
program is active and that inherited controls are documented in their ATO package. See the
[CRM](../CRM.md) (MA — Maintenance) for the full allocation.

## 4 MA-4 — Nonlocal Maintenance

### 4.1 Policy statement

All **nonlocal (remote) maintenance** of KP components — including any `kubectl exec` session,
remote debugging, or interactive cluster access — shall be performed only over **authenticated,
encrypted channels** and only by **authorized personnel** during an approved maintenance window.

### 4.2 Nonlocal maintenance posture

KP's operational posture for remote maintenance is as follows:

1. **Transport encryption.** All remote access to the cluster API server (including `kubectl`,
   GitOps operator calls, and CI/CD pipeline interactions) is over **TLS 1.2 or higher**.
   Unauthenticated or plaintext remote access is prohibited. This aligns with the SC family
   controls in [SC-policy](SC-policy.md).
2. **Authentication.** Remote access requires authentication against the cluster's OIDC/IdP
   integration (P3) or, prior to P3 completion, certificate-based kubeconfig credentials bound
   to least-privilege RBAC roles. Shared or static credentials for remote access are prohibited.
3. **Authorization.** Remote maintenance sessions are scoped to the minimum RBAC permissions
   required for the maintenance task. No direct `exec` into production KP pods is permitted
   except for an approved, time-boxed, ISSO-authorized session; the ISSO records the session
   purpose, the authorizing individual, and the actual commands executed, in the
   [POA&M](../POAM.md) or a linked maintenance log.
4. **Termination.** Remote maintenance sessions are terminated immediately upon completion of
   the maintenance task; long-lived interactive sessions are prohibited.
5. **Audit.** Remote maintenance sessions are logged by the cluster audit log (Kubernetes API
   server audit) and the KP audit subsystem (`internal/audit/`). Session audit records are
   retained per the AU policy ([AU-policy](../AU-controls.md)).

### 4.3 Allocation

**Allocation: Shared.** The System defines the nonlocal maintenance posture and enforces TLS/RBAC
controls at the KP application layer (P3 OIDC; webhook TLS; RBAC). The **Cluster Operator
(Customer)** enforces cluster-level network controls, API-server authentication configuration,
and CSP VPN/bastion requirements that govern the network path used for remote access. Physical
nonlocal maintenance infrastructure (VPN, jump hosts, out-of-band management) is Inherited from
the CSP or Customer-operated. See the [CRM](../CRM.md) (MA — Maintenance) for the full split.

### 4.4 MA-4 procedures

1. **Before a remote session.** The Repository Maintainer or Cluster Operator documents the
   maintenance purpose and obtains ISSO authorization (email or tracked issue suffices for
   routine windows; formal change-request for significant changes).
2. **During a session.** Work is limited to the authorized scope. All commands are executed under
   the authorized kubeconfig identity; `kubectl exec` sessions are minimized and time-boxed.
3. **After a session.** The maintainer confirms session termination and provides a brief
   post-session summary (what was done, any anomalies) to the ISSO within 24 hours.
4. **Emergency remote access.** If an emergency requires unplanned remote access, the maintainer
   notifies the ISSO as soon as possible and files a post-hoc record within 24 hours.

## 5 Related MA controls (referenced, not fully specified here)

| Control | Allocation | Notes |
|---|---|---|
| MA-3 (Maintenance Tools) | Inherited from CSP | Physical tool inspection; not System-implementable. See [CRM](../CRM.md). |
| MA-5 (Maintenance Personnel) | Inherited / Customer | Personnel vetting for physical maintenance inherited from CSP/operator. See [CRM](../CRM.md). |
| MA-6 (Timely Maintenance) | Shared / Customer | Spares and support-availability via container orchestration (System); physical spare parts (CSP-Inherited). |

## 6 Compliance, exceptions, and enforcement

- Deviations from this policy (e.g., a patch that exceeds the remediation window, an
  unapproved remote session) require documented risk acceptance by the System Owner (within
  delegated authority) or the AO, and are recorded in the [POA&M](../POAM.md).
- Unpatched vulnerabilities outside the remediation schedule in §3.4 are findings tracked in
  the [POA&M](../POAM.md) with a corrective-action plan and milestone.
- The Independent Assessor will verify the patch cadence, maintenance authorization records,
  and nonlocal maintenance controls during the security assessment (CA-2).

## 7 Roles and responsibilities (summary)

| Role | Holder | Maintenance responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for maintenance program adequacy and resourcing; approves this policy; accepts residual risk for open vulnerabilities beyond remediation windows. |
| ISSO | TBD — assign before assessment | Designated official managing this policy; authorizes remote maintenance sessions; reviews patch cadence compliance; tracks open vulnerabilities in POA&M. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves deviations beyond the System Owner's delegated authority; receives ConMon evidence of patch cadence compliance. |
| Independent Assessor | TBD — assign before assessment | Independently assesses MA controls during the SAR; reviews maintenance authorization records and patch cadence evidence. |
| Cluster Operator (customer) | TBD — customer organization | Enforces cluster-level network controls governing remote maintenance paths; performs CSP-inherited infrastructure maintenance; confirms CSP MA attestations. |
| Repository Maintainer | TBD — assign before assessment | Authors and merges maintenance PRs; executes patch cadence; files remote-session records with ISSO; maintains `go.mod` and base-image currency. |

## 8 References

- [System Security Plan (SSP)](../ssp/SSP.md)
- [Customer Responsibility Matrix (CRM)](../CRM.md) — MA family allocation
- [Roles & RACI Matrix](../roles-raci.md)
- [Control Matrix](../control-matrix.csv) · [POA&M](../POAM.md) · [Inventory](../inventory.csv)
- [System Facts Sheet](../system-facts.md)
- [SR Policy (Supply Chain Risk Management — image signing and attestation)](SR-policy.md)
- [SC Policy (System and Communications Protection — TLS/encryption)](SC-policy.md)
- [Supply-Chain Control Narrative](../supply-chain.md)
- CI workflow: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
- Release pipeline: [`.github/workflows/release.yml`](../../../.github/workflows/release.yml)
- Compliance gate: [`.github/workflows/compliance.yml`](../../../.github/workflows/compliance.yml)
- NIST SP 800-53 Rev 5 (MA-1, MA-2, MA-3, MA-4, MA-5, MA-6); FedRAMP Moderate baseline;
  FedRAMP Continuous Monitoring Strategy Guide.
