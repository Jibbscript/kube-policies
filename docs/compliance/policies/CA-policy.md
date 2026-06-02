---
title: "Security Assessment and Authorization Policy (CA) — Kube-Policies (KP)"
control_family: "CA — Security Assessment and Authorization"
controls: "CA-1, CA-2, CA-5, CA-6, CA-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Security Assessment and Authorization Policy (CA) — Kube-Policies (KP)

This policy establishes the Security Assessment and Authorization requirements for the
Kube-Policies system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5**
(FedRAMP **Moderate** baseline). It implements control **CA-1 (Policy and Procedures)** and
anchors the CA controls that govern how KP is assessed, authorized, and continuously
monitored: **CA-2** (Control Assessments), **CA-5** (Plan of Action and Milestones), **CA-6**
(Authorization), and **CA-7** (Continuous Monitoring). The operational steps live in the
companion [CA procedures](../procedures/CA-procedures.md). The per-control implementation and
evidence trace is in the [control matrix](../control-matrix.csv) and [POA&M](../POAM.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This policy documents the
assessment and authorization *discipline* the program operates under. It does not claim that
every CA control is operating or has been assessed. Per-control status is tracked in the
[control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../POAM.md), with
remediation phases (P0–P12) defined in `../plans/remediation-roadmap.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review
was **2026-06-01**; the **next review is 2027-06-01**. It is also reviewed whenever a
significant change occurs to the system boundary, authorization decision, continuous-monitoring
strategy, or interconnection register. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that KP undergoes rigorous control assessment before
authorization, maintains an active authorization to operate through ongoing continuous
monitoring, and tracks open weaknesses to closure through a Plan of Action and Milestones. It
applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace: the
  admission-webhook (`AST-WH`), policy-manager (`AST-PM`), and dashboard
  (`AST-DB`/`AST-SPA`).
- All interconnections documented in
  [`docs/compliance/interconnections.md`](../interconnections.md) (ICX-01 through ICX-06).
- All personnel filling the System Owner, ISSO, Authorizing Official (AO), and Assessor roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts referenced in procedures
are **placeholders**.

## 2 CA-1 — Security Assessment and Authorization Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this CA policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the procedures are in
[CA procedures](../procedures/CA-procedures.md).

### 2.2 CA-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Maintainers, and all repository contributors by being maintained in version
control under [`docs/compliance/policies/`](.) and referenced from the SSP
([../ssp/SSP.md](../ssp/SSP.md), CA family) and the [CRM](../CRM.md).

### 2.3 CA-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing.

### 2.4 CA-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This CA policy (CA-1) | ISSO | At least annually (next: 2027-06-01) | Authorization decision; new interconnection; significant system change; assessor finding |
| CA procedures ([CA-procedures.md](../procedures/CA-procedures.md)) | ISSO | At least annually (next: 2027-06-01) | Procedure drift; ConMon frequency change; POA&M process change |
| Continuous monitoring plan ([docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)) | ISSO | At least annually (next: 2027-06-01) | New monitored signal; frequency change; reporting-path change |
| POA&M ([POAM.md](../POAM.md) / [poam.csv](../poam.csv)) | ISSO | Monthly | New finding; remediation closure; milestone slip |

"Significant change" includes any change to the system boundary, addition or removal of an
interconnection, change to the authorization decision or ATO conditions, or a major control
implementation change that affects the continuous-monitoring baseline.

## 3 CA-2 — Control Assessments

### 3.1 Assessment requirement

KP shall conduct control assessments to determine the effectiveness of implemented security
controls prior to authorization and on a periodic basis thereafter. The assessment plan is
maintained as the [Security Assessment Plan (SAP)](../assessment/SAP.md); assessment results
are documented in the Security Assessment Report (SAR, TBD — produced at assessment time).

### 3.2 Assessment scope and depth

The CA-2 assessment shall cover, at minimum:

- **All FedRAMP Moderate baseline controls** applicable to KP within the system boundary
  defined in the [SSP](../ssp/SSP.md) and [FIPS-199 categorization](../categorization/FIPS-199.md).
- **Independent assessor involvement (CA-2(1)).** The assessment shall be conducted by, or
  reviewed by, an independent assessor (TBD — assign before assessment) who is not a KP
  maintainer or operator.
- **Specialized assessment (CA-2(2)).** Penetration testing and specialized vulnerability
  assessment are planned for P12 (see [POA&M](../POAM.md)).

### 3.3 Evidence basis

Control effectiveness is substantiated by:
1. Automated test suites (`go test ./...`) cited in the control narrative and procedures.
2. CI gate results (the `ci-gate` job in `.github/workflows/ci.yml` that requires all
   security, scan, and hardening gates to pass).
3. Chart renders validated by `kubeconform -strict` and `conftest` (restricted-PSS, RBAC,
   SA-token policies).
4. POA&M entries with documented residuals and remediation milestones.

## 4 CA-5 — Plan of Action and Milestones

KP shall maintain an active POA&M that:

- Records every control weakness, deficiency, or residual identified during development,
  assessment, or continuous monitoring.
- Assigns a responsible role (TBD), a remediation milestone (P0–P12), and a target date.
- Is reviewed and updated at least **monthly** by the ISSO.

The POA&M is maintained in machine-readable form at [poam.csv](../poam.csv) and in
human-readable form at [POAM.md](../POAM.md). The phased remediation plan is in
`../plans/remediation-roadmap.md`.

## 5 CA-6 — Authorization

### 5.1 Authorization decision

KP shall not be placed into production use without a formal authorization decision rendered by
the Authorizing Official (AO, TBD — assign before assessment). The authorization decision
shall be based on the completed SSP, SAR, and POA&M, and shall establish ATO conditions and
an authorization termination date.

**Current status.** KP has **no ATO**. It is a Proof-of-Concept in active development toward
assessment readiness. Nothing in this policy or any compliance artifact constitutes
authorization to operate.

### 5.2 Reauthorization triggers

The AO shall be notified and a reauthorization assessment initiated when any of the following
occur:

- A significant change to the authorization boundary, system architecture, or security
  categorization.
- A major control implementation change not covered by the continuous-monitoring baseline.
- An interconnection added or removed (see [interconnections.md](../interconnections.md)).
- A security incident assessed as impacting the authorization basis (see
  [IR policy](IR-policy.md)).

## 6 CA-7 — Continuous Monitoring

### 6.1 Continuous monitoring strategy

KP shall maintain an ongoing awareness of the system's security posture through continuous
monitoring. The strategy is documented in the
[Continuous Monitoring Plan](../../security/continuous-monitoring-plan.md), which defines:

- **Monitored signals** — availability metrics, security-signal alerts, audit log integrity,
  vulnerability scan results, and configuration drift (see §2 of the ConMon Plan).
- **Review cadences** — real-time alerting via Prometheus/Alertmanager; monthly ISSO review;
  quarterly POA&M status report to the AO.
- **Reporting path** — monitoring findings that cannot be resolved within one review cycle
  are escalated to a POA&M entry; POA&M status is reported quarterly to the AO.
- **Automation.** Prometheus scrapes KP metrics; Alertmanager routes alerts on the rules
  in `charts/kube-policies/files/alerts/` (availability, security, TLS, capacity, DoS,
  watchdog). The ServiceMonitor (`charts/kube-policies/templates/servicemonitor.yaml`) and
  PrometheusRule (`charts/kube-policies/templates/prometheusrule.yaml`) templates provide
  the collection infrastructure.

### 6.2 Continuous monitoring artifacts

| Artifact | Path | Frequency |
|---|---|---|
| Continuous Monitoring Plan | [docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md) | Reviewed annually; updated on strategy change |
| Security Assessment Plan | [docs/compliance/assessment/SAP.md](../assessment/SAP.md) | Updated per assessment cycle |
| POA&M | [docs/compliance/POAM.md](../POAM.md) | Updated monthly |
| SLO report | [docs/observability/slo.md](../../observability/slo.md) | Monthly |

### 6.3 Interconnection monitoring

All interconnections in [interconnections.md](../interconnections.md) (ICX-01 through ICX-06)
shall be included in the continuous-monitoring scope. Changes to interconnection security
properties trigger ISSO review and potential reauthorization (§5.2).

## 7 Roles and responsibilities (summary)

| Role | Holder | CA responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for authorization decision basis; approves this policy; authorizes significant changes; ensures POA&M resourcing. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures; maintains the POA&M; oversees the continuous-monitoring program; coordinates assessment activities; reports to AO. |
| Authorizing Official (AO) | TBD — assign before assessment | Renders the authorization decision; receives quarterly POA&M status; approves or denies reauthorization on significant change. |
| Independent Assessor | TBD — assign before assessment | Conducts or reviews CA-2 control assessment; produces the SAR. |
| Maintainers / CODEOWNERS | TBD — assign | Ensure PRs that change the control implementation surface include updated evidence; flag significant changes to ISSO. |

Contacts referenced operationally (e.g., `isso@kube-policies.io`) are **placeholders**
pending role assignment.

## 8 Compliance, exceptions, and enforcement

- Placing KP into production use without an AO authorization decision is prohibited.
- A significant change to the system boundary or security categorization that is not reported
  to the AO is a finding requiring ISSO escalation and a POA&M entry.
- Allowing a POA&M entry to slip past its milestone date without an updated remediation
  timeline requires ISSO acknowledgement and AO notification.
- Disabling any CI security gate (`security-scan`, `govulncheck`) on the main branch without
  ISSO approval is a deviation requiring a POA&M entry.

## 9 References

- CA procedures: [../procedures/CA-procedures.md](../procedures/CA-procedures.md)
- Continuous Monitoring Plan: [docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)
- Security Assessment Plan: [docs/compliance/assessment/SAP.md](../assessment/SAP.md)
- POA&M: [../POAM.md](../POAM.md) · [../poam.csv](../poam.csv)
- Interconnections: [../interconnections.md](../interconnections.md)
- System categorization: [../categorization/FIPS-199.md](../categorization/FIPS-199.md)
- SSP: [../ssp/SSP.md](../ssp/SSP.md) · CRM: [../CRM.md](../CRM.md)
- SLO: [docs/observability/slo.md](../../observability/slo.md)
- Monitoring chart: `charts/kube-policies/templates/prometheusrule.yaml` · `charts/kube-policies/templates/servicemonitor.yaml`
- Alert rules: `charts/kube-policies/files/alerts/`
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CA-1, CA-2, CA-5, CA-6, CA-7); FedRAMP Moderate baseline; FIPS-199.
