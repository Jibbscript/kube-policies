---
title: "Risk Assessment Policy (RA) — Kube-Policies (KP)"
control_family: "RA — Risk Assessment"
controls: "RA-1, RA-3, RA-5, RA-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Risk Assessment Policy (RA) — Kube-Policies (KP)

This policy establishes the Risk Assessment requirements for the Kube-Policies system (KP),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It implements control **RA-1 (Policy and Procedures)** and anchors the RA
controls that govern how KP identifies, assesses, and responds to risk: **RA-3** (Risk
Assessment), **RA-5** (Vulnerability Monitoring and Scanning), and **RA-7** (Risk Response).
The operational steps live in the companion [RA procedures](../procedures/RA-procedures.md).
The system threat model is at
[docs/compliance/threat-model.md](../threat-model.md) (canonical) and
[docs/security/threat-model.md](../../security/threat-model.md) (pointer).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This policy documents the
risk-assessment *discipline* the program operates under and the controls that are *actually
implemented* — it does not claim that every RA control is operating at steady state. Per-control
status is tracked in the [control matrix](../control-matrix.csv) and open weaknesses in the
[POA&M](../POAM.md), with remediation phases (P0–P12) defined in
`../plans/remediation-roadmap.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review
was **2026-06-01**; the **next review is 2027-06-01**. It is also reviewed whenever the
threat model is updated, a new scanner is added to CI, the vulnerability-remediation SLAs
change, or an assessor finding is received. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that KP's risks are systematically identified,
assessed against a credible threat model, and addressed through timely remediation and
risk-response decisions. It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace:
  the admission-webhook (`AST-WH`), policy-manager (`AST-PM`), and dashboard
  (`AST-DB`/`AST-SPA`).
- All container images and Go dependencies that compose the KP binaries.
- All interconnections documented in [docs/compliance/interconnections.md](../interconnections.md)
  (ICX-01 through ICX-06).
- All personnel filling the System Owner, ISSO, Maintainer/CODEOWNERS, and Operator roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts referenced in
procedures are **placeholders**.

## 2 RA-1 — Risk Assessment Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this RA policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the procedures are in
[RA procedures](../procedures/RA-procedures.md).

### 2.2 RA-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Maintainers, and all repository contributors by being maintained in version
control under [`docs/compliance/policies/`](.) and referenced from the SSP
([../ssp/SSP.md](../ssp/SSP.md), RA family) and the [CRM](../CRM.md).

### 2.3 RA-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing.

### 2.4 RA-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This RA policy (RA-1) | ISSO | At least annually (next: 2027-06-01) | Threat model update; SLA change; new scanner added; assessor finding |
| RA procedures ([RA-procedures.md](../procedures/RA-procedures.md)) | ISSO | At least annually (next: 2027-06-01) | Procedure drift; scanner cadence change; new CVE triage workflow |
| Threat model ([threat-model.md](../threat-model.md)) | ISSO | At least annually; on architecture change | New trust-boundary crossing; new attack vector identified; new interconnection |
| Vulnerability scan configuration | Maintainer | Per scanner update; on new CVE suppression | New `.trivyignore` entry; new `govulncheck` exception |

## 3 RA-3 — Risk Assessment

### 3.1 Initial risk assessment

KP's initial risk assessment is the 12-dimension FedRAMP/CIS gap analysis at
`.omc/research/fedramp-cis-gap-analysis.json`, conducted at P0. It established the phased
remediation plan (P0–P12). A formal risk assessment per NIST SP 800-30 Rev 1 is planned for
P12 prior to the authorization decision.

### 3.2 Threat model

The canonical threat model at [docs/compliance/threat-model.md](../threat-model.md)
documents:

- **STRIDE analysis per trust-boundary crossing** (ICX-01 through ICX-06 from the
  [data flow diagram](../diagrams/data-flow.md)).
- **STRIDE → mitigation → control ID → POA&M** mapping, reconciled to the
  [control matrix](../control-matrix.csv) and [poam.csv](../poam.csv).
- **Deep-dive attack scenarios**: admission bypass (including `spec.template.spec`
  enforcement blindness with attack tree), PolicyException abuse, unauthenticated
  API/dashboard, plaintext decision-publish token, and supply-chain entry points.

The threat model shall be reviewed at least annually and updated whenever the architecture,
authorization boundary, or an interconnection materially changes.

### 3.3 Risk assessment cadence

| Assessment type | Frequency | Owner |
|---|---|---|
| Threat model review | Annually (next: 2027-05-29) + on architecture change | ISSO |
| Vulnerability scan (CI — automated) | Every push and pull request | CI (automated) |
| Vulnerability scan (scheduled — authenticated) | Monthly (planned — P11) | Operator |
| Formal risk assessment (NIST SP 800-30) | Prior to authorization (P12) | ISSO + Independent Assessor |
| Supply-chain risk assessment (RA-3(1)) | Per release | Maintainer |

## 4 RA-5 — Vulnerability Monitoring and Scanning

### 4.1 Scanning scope

KP shall scan for known vulnerabilities across two surfaces:

1. **Container images**: all three KP component images (`admission-webhook`,
   `policy-manager`, `dashboard`) built from `gcr.io/distroless/static`.
2. **Go dependencies**: all modules in `go.mod` and their transitive dependencies.
3. **Filesystem / source** (CI Trivy `fs` mode): source code and build artifacts.

### 4.2 Scanning tools and CI integration

Vulnerability scanning is automated in CI and is a **gating check** on all pushes and pull
requests:

| Tool | Mode | CI job | Scope | Gating behavior |
|---|---|---|---|---|
| Trivy | `fs` | `security-scan` (`.github/workflows/ci.yml`) | Filesystem + all three images | Fixable CRITICAL/HIGH → exit 1 (fails build); unfixable → SARIF upload only |
| Trivy | `image` | `security-scan` | `admission-webhook`, `policy-manager`, `dashboard` images | Same gating as above; `.trivyignore` carries dated, justified suppressions |
| govulncheck | — | `govulncheck` (`.github/workflows/ci.yml`) | All Go modules (`./...`) | Fails build on known vulnerable dependencies |

The `security-scan` and `govulncheck` CI jobs are required by the `ci-gate` job; a failure
in either blocks merge.

Locally, the equivalent scan is:

```console
make security
```

### 4.3 Vulnerability suppression policy

Vulnerabilities suppressed via `.trivyignore` shall:
- Carry a dated comment with the suppression rationale and a review date no more than 90
  days in the future.
- Be reviewed at each monthly scan review and removed when a fix becomes available.
- Be reflected in a POA&M entry when the suppressed vulnerability is CRITICAL or HIGH.

### 4.4 Remediation SLAs

Remediation timelines are aligned to the FedRAMP Moderate continuous-monitoring requirements
and the timelines in [SECURITY.md](../../../SECURITY.md). SLA clocks start from the
**discovery date** (CI scan or external report receipt).

| Severity (CVSS v3) | CVSS score range | Remediation SLA |
|---|---|---|
| Critical | 9.0 – 10.0 | **30 days** |
| High | 7.0 – 8.9 | **30 days** |
| Moderate | 4.0 – 6.9 | **90 days** |
| Low | 0.1 – 3.9 | **180 days** |

Vulnerabilities that cannot be remediated within the SLA are tracked in the
[POA&M](../POAM.md) with a documented rationale and compensating controls.

### 4.5 SARIF upload and Security tab review

Trivy scan results are uploaded to the GitHub Security tab as SARIF artifacts by the
`security-scan` CI job. The ISSO reviews the Security tab monthly for new or recurring
findings. The `govulncheck` job output is available in the CI run logs.

## 5 RA-7 — Risk Response

When a vulnerability or risk is identified — through CI scanning, threat model review, or
external report — the ISSO determines the appropriate risk response:

| Response | When applicable |
|---|---|
| **Remediate** (patch image or dependency) | Preferred response for all CRITICAL/HIGH within SLA |
| **Mitigate** (compensating control) | When a patch is not available within the SLA; document in POA&M with compensating control description |
| **Transfer** | Not applicable for self-operated KP components |
| **Accept** (with AO concurrence) | Only for LOW findings where cost of remediation exceeds risk; requires AO approval and POA&M entry |

Risk-response decisions for CRITICAL/HIGH findings require ISSO acknowledgement. Risk
acceptance for any severity requires a POA&M entry.

## 6 Roles and responsibilities (summary)

| Role | Holder | RA responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for risk-program adequacy; approves risk-acceptance decisions for HIGH/CRITICAL; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures; owns the threat model; reviews monthly scan results; determines risk response; maintains the POA&M for RA findings. |
| Maintainers / CODEOWNERS | TBD — assign | Maintain `.trivyignore` suppressions with dated justifications; patch vulnerable dependencies; review PRs that modify scanner configuration. |
| Operator | TBD — assign | Runs scheduled authenticated scans (when enabled); reports new findings to ISSO. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves risk-acceptance decisions; receives quarterly POA&M status; approves the formal risk assessment at P12. |

Contacts referenced operationally are **placeholders** pending role assignment.

## 7 Compliance, exceptions, and enforcement

- Merging a PR that introduces a new CRITICAL or HIGH vulnerability (as reported by the
  `security-scan` or `govulncheck` CI gate) is prohibited without ISSO approval and a
  POA&M entry.
- Adding a suppression to `.trivyignore` without a dated comment and review date is a
  finding requiring correction before merge.
- Allowing a CRITICAL or HIGH finding to exceed its 30-day SLA without a POA&M entry and
  ISSO acknowledgement is a material compliance failure.
- Disabling the `security-scan` or `govulncheck` CI job on the main branch requires ISSO
  and System Owner approval and a POA&M entry.

## 8 References

- RA procedures: [../procedures/RA-procedures.md](../procedures/RA-procedures.md)
- Threat model (canonical): [../threat-model.md](../threat-model.md)
- Threat model (pointer): [docs/security/threat-model.md](../../security/threat-model.md)
- FIPS-199 categorization: [../categorization/FIPS-199.md](../categorization/FIPS-199.md)
- Vulnerability disclosure SLAs: [SECURITY.md](../../../SECURITY.md)
- CI workflow: `.github/workflows/ci.yml` (jobs: `security-scan`, `govulncheck`)
- Trivy suppression: `.trivyignore`
- Supply-chain risk management: [../supply-chain-risk-management.md](../supply-chain-risk-management.md)
- SI policy (flaw remediation): [SI-policy.md](SI-policy.md)
- POA&M: [../POAM.md](../POAM.md) · [../poam.csv](../poam.csv)
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (RA-1, RA-3, RA-5, RA-7); NIST SP 800-30 Rev 1; FedRAMP Moderate baseline; FIPS-199.
