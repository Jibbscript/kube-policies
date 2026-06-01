---
title: "Configuration Management Policy (CM) — Kube-Policies (KP)"
control_family: "CM — Configuration Management"
controls: "CM-1, CM-2, CM-3, CM-6, CM-7, CM-7(1), CM-8, CM-9"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Configuration Management Policy — Kube-Policies (KP)

This policy establishes the Configuration Management requirements for the Kube-Policies system
(KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It implements control **CM-1 (Policy and Procedures)** and anchors the CM controls that
keep KP baselined, change-controlled, inventoried, and least-functional: **CM-2 (Baseline
Configuration)**, **CM-3 (Configuration Change Control)**, **CM-6 (Configuration Settings)**,
**CM-7 / CM-7(1) (Least Functionality / Periodic Review)**, **CM-8 (System Component Inventory)**,
and **CM-9 (Configuration Management Plan)**. It is the CM-family anchor; the operational steps live
in the companion [CM procedures](../procedures/CM-procedures.md), the baseline lives in
[secure-configuration-baseline.md](../secure-configuration-baseline.md), and the program is governed
by the canonical [Configuration Management Plan](../plans/configuration-management-plan.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is **not
yet authorized** (**no ATO**) and not in production use. This policy documents the CM *discipline* the
program operates under and the controls that are *actually implemented* in the shipped code, Helm
chart, and CI — it is not a claim that every CM control is fully met. Per-control status is tracked in
the [control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../poam.csv), with
remediation phases (P0–P12) defined in `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually** (next review
**2027-06-01**) and whenever a significant change to the system, its baseline, its change-control
process, the CI gates, the container images, or the applicable standards occurs. Reviews are recorded
by updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that the configuration of KP is documented as a baseline,
that changes to that baseline are controlled and tested, that the component inventory is current, and
that the system runs with the least functionality necessary. It applies to:

- All KP configuration items (CIs): the Helm chart (`AST-CHART`,
  [`charts/kube-policies`](../../../charts/kube-policies)), the CRDs (`AST-CRD-POL`, `AST-CRD-EXC`),
  the static base manifests, the runtime configuration validated by `internal/config`, the container
  images (`AST-IMG-WH/PM/DB`), and the compliance artifacts that record them.
- All personnel filling the System Owner, ISSO, Authorizing Official (AO), Maintainer/CODEOWNERS, and
  CCB roles, plus any contributor who changes a CI.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see [roles-raci.md](../roles-raci.md)).

## 2 CM-1 — Configuration Management Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this CM policy and the procedures needed to
implement it; shall designate an official to manage them; and shall review and update both on a
defined frequency. This document is that policy; the procedures are in
[../procedures/CM-procedures.md](../procedures/CM-procedures.md) and the plan in
[../plans/configuration-management-plan.md](../plans/configuration-management-plan.md).

### 2.2 CM-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System Owner, ISSO,
AO, Maintainers, and all repository contributors by being maintained in version control under
[`docs/compliance/policies/`](.) and referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), CM
family) and the [CRM](../CRM.md).

### 2.3 CM-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update this policy,
its procedures, and the CM plan, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing and chairing the **Configuration Control Board (CCB)**.

### 2.4 CM-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This CM policy (CM-1) | ISSO | At least annually | Baseline/process change; new CI; tooling/CI-gate change; assessor finding |
| CM procedures ([CM-procedures.md](../procedures/CM-procedures.md)) | ISSO | At least annually | Procedure drift; new component/port; gate change |
| CM plan ([configuration-management-plan.md](../plans/configuration-management-plan.md)) | System Owner / ISSO | At least annually | Significant configuration change; CCB-process change |
| Secure configuration baseline (CM-2/CM-6) | System Owner / ISSO | At least annually | Setting change; new image; CIS update |
| Component inventory (CM-8) | ISSO | At least annually + per release | Component/image/port change |

"Significant change" includes any change to the authorization boundary, the baseline settings, RBAC,
NetworkPolicy, the TLS/crypto configuration, the CRD schema, or the listening ports/protocols
([../ssp/ports-protocols-services.md](../ssp/ports-protocols-services.md)).

## 3 CM-2 / CM-6 — Baseline configuration and settings

KP shall maintain a current, documented **baseline configuration** and a record of the **configuration
settings** for its CIs. The authoritative record is the
[secure configuration baseline](../secure-configuration-baseline.md); it is **configuration as code**
(the chart `values.yaml` + templates are the machine-readable expression of every required setting),
versioned and retained in **git** (CM-2(3)), and **automatically verified** by the CI gates that
render the chart and assert the settings (CM-6(1), §5).

The container-image baseline is recorded in the [inventory](../inventory.md). The `kube-policies.image`
helper accepts a **digest-pinned reference**; the shipped values still use floating tags, so images are
**not digest-pinned by default** — a documented residual (**POAM-023**, CM-2), not a claim of full
compliance.

## 4 CM-3 — Configuration change control

KP shall control changes to its CIs. All changes flow through a **pull request** with the
[change-control checklist](../../../.github/pull_request_template.md) (CM-3), Maintainer/CODEOWNERS
review, security-impact assessment for security-relevant changes (CM-4), and the **blocking CI gates**
(§5). Significant changes additionally require **CCB** review. The merge commit + PR is the change
record; deviations are recorded in the [POA&M](../poam.csv). The full process, Helm/CRD specifics, and
CCB roles are in the [CM plan](../plans/configuration-management-plan.md) §3.

## 5 CM-3(2) / CM-6(1) — Change-control enforcement (CI gates)

Change testing and baseline verification are **enforced in CI**, not by convention. The gating jobs in
[`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) — `manifest-hardening-gate`,
`helm-unittest`, `network-posture-gate`, `rbac-sa-gate`, and the **gating Trivy** filesystem + image
scans (`CRITICAL,HIGH` → build fail) — assert the baseline on the rendered manifests and block a merge
that weakens it. This is the CM-3 enforcement mechanism (and strengthens RA-5 / SI-2). The gate
inventory is in the [CM plan](../plans/configuration-management-plan.md) §3.2.

## 6 CM-7 / CM-7(1) — Least functionality and periodic review

KP shall run with the least functionality necessary: distroless images, dropped capabilities,
read-only root filesystem, the **enumerated** [ports/protocols register](../ssp/ports-protocols-services.md)
(each port justified), and the dashboard and its listeners **off by default**. The enabled functions
and open ports are **reviewed at least annually** and on any listener change (CM-7(1); procedure in
[CM-procedures.md](../procedures/CM-procedures.md)).

## 7 CM-8 — System component inventory

KP shall maintain a current inventory of its components ([inventory.md](../inventory.md) /
[inventory.csv](../inventory.csv)), including per-component images and digest support, reviewed at
least annually and per release. SBOM-driven auto-update and unauthorized-component detection
(CM-8(1)/CM-8(3)) are remediation phase P6.

## 8 CM-9 — Configuration Management Plan

The CM program is governed by the canonical
[Configuration Management Plan](../plans/configuration-management-plan.md) (CM-9), which this policy
adopts. Named CCB members remain **TBD — assign before assessment**.

## 9 Roles and responsibilities (summary)

| Role | Holder | CM responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for CM adequacy/resourcing; approves this policy + baseline; chairs the CCB. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures/plan; reviews change-control evidence; security-impact analysis (CM-4); maintains the POA&M. |
| Maintainers / CODEOWNERS | TBD — assign | Review/approve PRs; enforce green CI before merge. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP; renders the authorization decision; approves out-of-delegation deviations. |
| CCB | System Owner (chair), ISSO, lead Maintainer | Reviews/approves significant changes and deviations. |

## 10 Compliance, exceptions, and enforcement

- Deviations from a baseline setting marked **Enforced (current)** require a documented, time-bound
  exception per the [baseline §6 deviation process](../secure-configuration-baseline.md#6-deviation--exception-process)
  and the [CM plan](../plans/configuration-management-plan.md); approved deviations are recorded in the
  [POA&M](../poam.csv).
- A change that lowers the TLS 1.3 floor, weakens the fail-closed posture, or removes a hardening
  control fails fast (at config load, or at a CI gate) — that is a defect to fix, not a deviation to
  accept silently.

## 11 References

- CM procedures: [../procedures/CM-procedures.md](../procedures/CM-procedures.md) · CM plan: [../plans/configuration-management-plan.md](../plans/configuration-management-plan.md)
- Secure configuration baseline (CM-2/CM-6): [../secure-configuration-baseline.md](../secure-configuration-baseline.md)
- Inventory (CM-8): [../inventory.md](../inventory.md) / [../inventory.csv](../inventory.csv) · PPS register (CM-7): [../ssp/ports-protocols-services.md](../ssp/ports-protocols-services.md)
- Drift detection: [../drift-detection.md](../drift-detection.md) · Change-control checklist: [`.github/pull_request_template.md`](../../../.github/pull_request_template.md) · CI gates: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · POA&M: [../poam.csv](../poam.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CM-1, CM-2, CM-3, CM-6, CM-7, CM-7(1), CM-8, CM-9); FedRAMP Moderate baseline; CIS Kubernetes Benchmark; FIPS-199.
