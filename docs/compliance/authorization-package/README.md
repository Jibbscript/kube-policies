# Kube-Policies — FedRAMP-Moderate Authorization Package (Readiness)

| | |
|---|---|
| **System** | Kube-Policies (KP) — Kubernetes admission-control policy enforcement |
| **Baseline** | NIST SP 800-53 Rev 5, FedRAMP-Moderate |
| **Package version** | 0.1.0-readiness (P12) |
| **Status** | **Self-attested readiness — PRE-3PAO. NOT authorized; no ATO has been granted.** |
| **Owner / Approver** | System Owner / Authorizing Official (TBD — assign before assessment) |
| **Assembled** | 2026-06-02 |

> **Read this first — what this package is and is not.**
> This is the assembled **Readiness Assessment Report (RAR) package** for an
> **internal, self-attested** FedRAMP-Moderate readiness review of a **proof-of-concept**
> system. It bundles the as-built System Security Plan, assessment plan, internal
> self-assessment, internal independent-review reports, POA&M, CRM, boundary/data-flow
> diagrams, inventory, and supporting plans/policies so they can be handed to a **3PAO**
> for an **independent** assessment and to an **Authorizing Official** for an authorization
> decision. It does **not** constitute, and must not be represented as, an executed 3PAO
> assessment or a granted Authorization to Operate. The independent assessment, the
> external penetration test, and the AO decision remain open, human-owned activities
> (tracked as POAM-050..057 in the [POA&M](../POAM.md)).

## How to navigate

The authoritative artifacts live in their home directories under `docs/compliance/`
(and `docs/security/`); this package indexes and cross-references them rather than
duplicating them, so there is a single source of truth for each.

## Package components (FedRAMP-Moderate completeness checklist)

| # | FedRAMP package component | Artifact | Present |
|---|---|---|---|
| 1 | Security categorization (FIPS-199) | [categorization/FIPS-199.md](../categorization/FIPS-199.md) | ✅ |
| 2 | System Security Plan (SSP), as-built control narratives | [ssp/SSP.md](../ssp/SSP.md) | ✅ |
| 3 | Ports, protocols & services | [ssp/ports-protocols-services.md](../ssp/ports-protocols-services.md) | ✅ |
| 4 | Control implementation matrix (every control + status + evidence) | [control-matrix.md](../control-matrix.md) / [control-matrix.csv](../control-matrix.csv) | ✅ |
| 5 | Customer Responsibility Matrix (CRM) | [CRM.md](../CRM.md) | ✅ |
| 6 | Authorization boundary diagram | [diagrams/authorization-boundary.md](../diagrams/authorization-boundary.md) | ✅ |
| 7 | Data-flow diagram | [diagrams/data-flow.md](../diagrams/data-flow.md) | ✅ |
| 8 | Component / asset inventory | [inventory.md](../inventory.md) / [inventory.csv](../inventory.csv) | ✅ |
| 9 | Security Assessment Plan (SAP) | [assessment/SAP.md](../assessment/SAP.md) | ✅ |
| 10 | Internal self-assessment results (pre-SAR) | [assessment/self-assessment-results.md](../assessment/self-assessment-results.md) | ✅ |
| 11 | Penetration-test plan & rules of engagement | [../../security/pen-test-plan.md](../../security/pen-test-plan.md) | ✅ |
| 12 | Internal pre-assessment pen-test report (illustrative, pre-3PAO) | [assessment/pentest-report.md](../assessment/pentest-report.md) | ✅ |
| 13 | Internal independent code-review report (pre-3PAO) | [assessment/independent-code-review.md](../assessment/independent-code-review.md) | ✅ |
| 14 | CIS Kubernetes Benchmark conformance results | [assessment/cis-benchmark-results.md](../assessment/cis-benchmark-results.md) | ✅ |
| 15 | CIS / NIST 800-190 self-assessment mapping | [cis-k8s-800-190-mapping.md](../cis-k8s-800-190-mapping.md) | ✅ |
| 16 | Plan of Action & Milestones (POA&M) | [POAM.md](../POAM.md) / [poam.csv](../poam.csv) | ✅ |
| 17 | Continuous Monitoring plan | [conmon/conmon-plan.md](../conmon/conmon-plan.md) / [conmon/cadence.md](../conmon/cadence.md) | ✅ |
| 18 | Incident Response plan | [plans/incident-response-plan.md](../plans/incident-response-plan.md) | ✅ |
| 19 | Contingency plan (CP) | [plans/contingency-plan.md](../plans/contingency-plan.md) | ✅ |
| 20 | Configuration Management plan | [plans/configuration-management-plan.md](../plans/configuration-management-plan.md) | ✅ |
| 21 | Family policies & procedures (-1 controls) | [policies/](../policies/) / [procedures/](../procedures/) | ✅ |
| 22 | Roles & responsibilities (RACI) | [roles-raci.md](../roles-raci.md) | ✅ |
| 23 | Remediation roadmap (phase model) | [plans/remediation-roadmap.md](../plans/remediation-roadmap.md) | ✅ |
| 24 | Supply-chain risk management plan | [supply-chain-risk-management.md](../supply-chain-risk-management.md) | ✅ |
| 25 | Cryptographic / key-management inventory | [crypto-inventory.md](../crypto-inventory.md) / [key-management-plan.md](../key-management-plan.md) | ✅ |
| — | **3PAO Security Assessment Report (SAR)** | _not present — produced by the independent assessor_ | ⏳ POAM-051 |
| — | **Authorization decision letter (ATO)** | _not present — issued by the AO_ | ⏳ POAM-057 |

All repository components above are present and cross-referenced; the two ⏳ rows are
the deliverables of the human-owned independent assessment and authorization activities.

## Readiness recommendation

See the [Readiness Assessment Report](readiness-assessment-report.md) for the
self-attested readiness recommendation, residual-risk summary, and the explicit
list of activities that must complete before an authorization decision.
