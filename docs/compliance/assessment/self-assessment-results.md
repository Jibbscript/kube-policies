---
title: "Internal Control Self-Assessment Results — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring"
controls: "NIST SP 800-53 Rev 5 / FedRAMP Moderate (all in-baseline families)"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# Internal Control Self-Assessment Results — Kube-Policies (KP)

> **Honesty banner — internal pre-3PAO self-assessment.** This is an **internal,
> self-administered** control self-assessment of Kube-Policies (KP), performed by the
> system team against the procedures in the [Security Assessment Plan (SAP)](./SAP.md).
> It is **NOT** an authorized Security Assessment Report (SAR) and **NOT** a substitute
> for an independent third-party assessment. KP is a Proof-of-Concept being driven to
> FedRAMP-Moderate readiness; it is **not yet authorized** (no ATO) and is not in
> production. An **independent 3PAO assessment remains a prerequisite to any
> authorization decision**. The SAP requires an organizationally independent
> Independent Assessor (TBD — assign) who must execute the assessment of record; this
> document only states the team's honest internal view of the as-built posture so that
> the gaps are visible before the 3PAO arrives. Where this document and the
> [control matrix](../control-matrix.csv) disagree, **the matrix governs**.

This document records the **results** of the internal self-assessment. The **plan** (how
each control is assessed) lives in the [SAP](./SAP.md); per-control implementation status —
the spine of this effort — lives in the [control matrix](../control-matrix.csv); control
narratives are in [SSP §7](../ssp/SSP.md); and every open weakness is tracked in the
[POA&M](../POAM.md) and its machine-readable companion [poam.csv](../poam.csv). Results below
are derived **mechanically** from the control matrix on the assessed commit and mirror it
exactly — no control is reported as Satisfied unless the matrix records it as `Implemented`.

## 1. Assessment method

Each control was assessed against the NIST SP 800-53A Rev 5 procedures defined per-family in
[SAP §3.1](./SAP.md), using one or more of the three methods, and the result was recorded:

- **Examine (E):** the implementing artifact/manifest/config/documentation cited in the
  control matrix `implementing_artifact` / `evidence` column was reviewed for the assessed
  commit.
- **Test (T):** the cited test suite or CI gate (e.g. `go test` units, conftest/`helm-unittest`
  gates, `scripts/validate/compliance_check.py`, `govulncheck`/Trivy scans, promtool rule
  tests) was treated as repeatable automated **Test** evidence per [SAP §4](./SAP.md).
- **Interview (I):** for organizational/process controls (AT, PS, IR, CA, PL, PM, MA),
  role-holder interview is the primary method; KP roles are **TBD — assign**, so these
  controls cannot yet be substantively assessed and are recorded as **Planned**.

Result vocabulary (NIST 800-53A "Satisfied / Other Than Satisfied"), mapped **honestly** from
the matrix `status`:

| Matrix `status` | Assessment result | Basis |
|---|---|---|
| `Implemented` | **Satisfied** | Implementing artifact examined; cited test/CI gate exercised and passing. |
| `Implemented (Helm) - requires enforcing CNI` | **Satisfied (CNI-dependent)** | Manifest/gate satisfied in-chart; **effective only on a NetworkPolicy-enforcing CNI** — runtime enforcement is an environmental dependency, so it is *not* an unconditional Satisfied. |
| `Partial` | **Other Than Satisfied (residual)** — partially satisfied | Some capability examined/tested; a residual gap remains. Tracked to remediation. |
| `Planned` | **Planned (Other Than Satisfied)** | Capability absent on the assessed commit; assessment confirms the gap and the remediating phase. |
| `Inherited` | **Inherited** | Assessed only for **responsibility-assertion correctness**; the hosting CSP authorization package is the evidence of record. |
| `Not-Applicable` | **Not Applicable** | Assessor-validated N/A rationale (no in-boundary surface). |

> No control family in the FedRAMP Moderate baseline contains a `status` of `Customer`
> on the assessed matrix, so no result is recorded as "Customer Responsibility"; the
> customer/provider split is documented in the [CRM](../CRM.md).

## 2. Coverage summary

Counts and percentages are derived from the live [control matrix](../control-matrix.csv)
`status` distribution on the assessed commit (**300** controls total).

| Assessment result | Matrix `status` | Count | % of 300 |
|---|---|---|---|
| Satisfied | `Implemented` | 10 | 3.3% |
| Satisfied (CNI-dependent) | `Implemented (Helm) - requires enforcing CNI` | 5 | 1.7% |
| Other Than Satisfied — partially satisfied (residual) | `Partial` | 55 | 18.3% |
| Planned (Other Than Satisfied) | `Planned` | 172 | 57.3% |
| Inherited (responsibility-assertion only) | `Inherited` | 53 | 17.7% |
| Not Applicable | `Not-Applicable` | 5 | 1.7% |
| **Total assessed** | — | **300** | **100%** |

Rollups (honest posture):

- **Satisfied (incl. CNI-dependent): 15 (5.0%).** The bright spots only.
- **Other Than Satisfied (Partial + Planned): 227 (75.7%).** The substantive remediation
  surface — the majority of the baseline is not yet satisfied.
- **Inherited: 53 (17.7%).** Provider/CSP-owned; KP asserts responsibility only.
- **Not Applicable: 5 (1.7%).**

This distribution confirms the SAP honesty note: KP is an as-built PoC where **most controls
are Planned or Partial**, with foundational ATO-blockers still open (see §3).

## 3. Failing / Other-Than-Satisfied controls → POA&M cross-reference

Every Critical/High foundational weakness is recorded as a POA&M item. The
[POA&M](../POAM.md) / [poam.csv](../poam.csv) register holds **38** open weaknesses, each
mapped (via the poam.csv `control_id` column) to a **primary** NIST 800-53r5 control that
exists as a row in the matrix. All 38 POA&M `control_id` values resolve to a matrix row
(no orphans); the 9 Critical items are the ATO-blockers (SC-13, IA-2, AC-3, SC-8, AC-6,
SC-7, CM-6, AU-9, SA-11).

**Traceability honesty note (important).** The matrix `poam_id` *column is currently blank
for all 227 Partial/Planned rows*. Two-way traceability today therefore runs **POA&M →
control** (poam.csv `control_id` → matrix row), not matrix `poam_id` → POA&M. In the
per-control table (§4) the **POA&M / Remediation** cell is populated as follows, *derived*
(not invented):

- If the control is the **primary** control of a poam.csv row, the cell shows that
  `POAM-NNN` and the remediating phase (e.g. `POAM-002 (P3)`). **34** Partial/Planned
  controls have such a direct POA&M match.
- Otherwise the cell shows the matrix `remediating_phase` (e.g. `phase P3`). **193**
  Partial/Planned controls **roll up** to a remediating phase and to the representative
  family-level POA&M for that weakness class, rather than carrying a dedicated POA&M row.

**Gap to close before 3PAO / authorization (recorded as a finding of this self-assessment):**
the matrix `poam_id` back-reference column should be **populated** so every Partial/Planned
control with residual risk points at a `POAM-NNN`, per the two-way-traceability rule in
[POA&M §How to maintain](../POAM.md). Until that reconciliation lands, the 193 rollup
controls are *covered by phase* but not by a per-control `poam_id` cell. Reconciling the
control matrix to FedRAMP/OSCAL — including this back-reference — is itself tracked as
**POAM-019 (CA-2, P12)**. No new POA&M entry is required beyond POAM-019 to capture this
documentation gap; the substantive weaknesses are already enumerated across POAM-001..038.

The 38 primary-control → POA&M mappings (severity from poam.csv):

| POA&M | Primary control | Severity | Phase |
|---|---|---|---|
| POAM-001 | SC-13 | Critical | P2 |
| POAM-002 | IA-2 | Critical | P3 |
| POAM-003 | AC-3 | Critical | P3 |
| POAM-004 | SC-8 | Critical | P4 |
| POAM-005 | IA-3 | High | P3 |
| POAM-006 | AC-6 | Critical | P3 |
| POAM-007 | SC-7 | Critical | P4 |
| POAM-008 | CM-6 | Critical | P10 |
| POAM-009 | SI-10 | High | P10 |
| POAM-010 | AU-9 | Critical | P7 |
| POAM-011 | AU-4 | High | P7 |
| POAM-012 | AU-6 | High | P7 |
| POAM-013 | AU-3 | Moderate | P7 |
| POAM-014 | SA-11 | Critical | P1 |
| POAM-015 | SR-4 | High | P6 |
| POAM-016 | CP-9 | High | P8 |
| POAM-017 | CP-10 | High | P8 |
| POAM-018 | PS-2 | High | P0 |
| POAM-019 | CA-2 | High | P12 |
| POAM-020 | IA-5 | High | P3 |
| POAM-021 | SC-28 | High | P2 |
| POAM-022 | SC-12 | Moderate | P2 |
| POAM-023 | CM-2 | High | P5 |
| POAM-024 | CM-7 | High | P5 (Resolved — Closed P5) |
| POAM-025 | RA-5 | High | P11 |
| POAM-026 | SI-2 | Moderate | P11 |
| POAM-027 | SC-5 | Moderate | P4 |
| POAM-028 | AU-12 | Moderate | P7 |
| POAM-029 | AU-5 | Moderate | P9 |
| POAM-030 | SI-4 | High | P9 |
| POAM-031 | IR-8 | High | P9 |
| POAM-032 | CA-7 | Moderate | P9 |
| POAM-033 | SR-3 | Moderate | P6 |
| POAM-034 | SA-15 | Moderate | P11 |
| POAM-035 | CM-14 | High | P6 |
| POAM-036 | AC-12 | Low | P3 |
| POAM-037 | CM-8 | Moderate | P5 |
| POAM-038 | AU-7 | Low | P7 |

> Note: POAM-024 (CM-7) is recorded **Resolved — Closed P5** in the POA&M, and CM-7 is
> `Implemented` (**Satisfied**) in the matrix; it is listed here for register completeness.
> All other 37 weaknesses remain **Open**.

## 4. Per-control assessment results

Rows are grouped by control family and mirror the [control matrix](../control-matrix.csv)
exactly. **Status (matrix)** is the verbatim matrix `status`; **Assessment Result** is the
honest mapping from §1; **Evidence / Artifact** is taken straight from the matrix
`evidence` (falling back to `implementing_artifact`) column; **POA&M / Remediation** is
derived per §3 (`POAM-NNN (phase)` for a direct primary-control match, else `phase Pn`).

### AC

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| AC-1 | Implemented | Satisfied | scripts/validate/compliance_check.py (doc link/structure gate) + docs-tests markdown-link-check (CA-WU-01) | — |
| AC-11 | Inherited | Inherited | Inherited from operator endpoints | CSP package |
| AC-11(1) | Inherited | Inherited | Inherited from operator endpoints | CSP package |
| AC-12 | Planned | Planned (Other Than Satisfied) | see P3 | POAM-036 (P3) |
| AC-14 | Planned | Planned (Other Than Satisfied) | cmd/dashboard/proxy.go | phase P3 |
| AC-17 | Partial | Other Than Satisfied (residual) | internal/policymanager/auth_middleware_test.go + internal/config/tls_test.go + internal/config/mtls_test.go (IAM-WU-03) | phase P3 |
| AC-17(1) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| AC-17(2) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-17(3) | Planned | Planned (Other Than Satisfied) | see P4 | phase P4 |
| AC-17(4) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-18 | Not-Applicable | Not Applicable | N/A - no wireless in boundary | N/A |
| AC-18(1) | Not-Applicable | Not Applicable | N/A - no wireless in boundary | N/A |
| AC-19 | Inherited | Inherited | Inherited from CSP/operator MDM | CSP package |
| AC-2 | Partial | Other Than Satisfied (residual) | internal/policymanager/authz_test.go + internal/policymanager/router_authn_test.go (IAM-WU-01) | phase P3 |
| AC-2(1) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-2(12) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| AC-2(13) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AC-2(2) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-2(3) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-2(4) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-2(5) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-20 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AC-20(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AC-20(2) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AC-21 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AC-22 | Not-Applicable | Not Applicable | N/A - no public content service | N/A |
| AC-3 | Partial | Other Than Satisfied (residual) | internal/policymanager/authz_test.go + internal/policymanager/decisions_read_auth_test.go + router_authn_test.go (IAM-WU-01) | POAM-003 (P3) |
| AC-4 | Planned | Planned (Other Than Satisfied) | charts/kube-policies/templates/ (NetworkPolicy, P4) | phase P4 |
| AC-5 | Partial | Other Than Satisfied (residual) | rbac-sa-gate (test/policy/rbac_leastprivilege.rego + sa_token.rego conftest, both modes) (IAM-WU-17) | phase P3 |
| AC-6 | Partial | Other Than Satisfied (residual) | rbac-sa-gate (test/policy/rbac_leastprivilege.rego conftest; fail-fixture self-test denies wildcard/cluster-Secrets grants) (IAM-WU-17) | POAM-006 (P3) |
| AC-6(1) | Planned | Planned (Other Than Satisfied) | charts/kube-policies/templates/rbac.yaml | phase P3 |
| AC-6(10) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-6(2) | Partial | Other Than Satisfied (residual) | manifest-hardening-gate (test/policy/restricted-pss.rego conftest) + charts/kube-policies/tests/hardening_test.yaml (CFG-WU-12) | phase P5 |
| AC-6(5) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| AC-6(7) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AC-6(9) | Planned | Planned (Other Than Satisfied) | see P7 | phase P7 |
| AC-7 | Inherited | Inherited | Inherited from IdP/CSP | CSP package |
| AC-8 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |

### AT

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| AT-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AT-2 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AT-2(2) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AT-2(3) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AT-3 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AT-4 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |

### AU

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| AU-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| AU-11 | Planned | Planned (Other Than Satisfied) | see P7 | phase P7 |
| AU-12 | Partial | Other Than Satisfied (residual) | internal/admission/audit_context_test.go + internal/admission/controller_test.go + internal/policymanager/manager_audit_test.go (AUD-WU-02) | POAM-028 (P7) |
| AU-12(1) | Planned | Planned (Other Than Satisfied) | see P7 | phase P7 |
| AU-2 | Partial | Other Than Satisfied (residual) | internal/audit/logger_test.go + internal/audit/logger_p7_test.go + internal/audit/public_event_test.go (AUD-WU-01) | phase P7 |
| AU-3 | Partial | Other Than Satisfied (residual) | internal/audit/logger_p7_test.go + internal/audit/logger_test.go (AUD-WU-03) | POAM-013 (P7) |
| AU-3(1) | Planned | Planned (Other Than Satisfied) | internal/audit/logger.go | phase P7 |
| AU-4 | Planned | Planned (Other Than Satisfied) | charts/kube-policies/templates/policy-manager-pvc.yaml | POAM-011 (P7) |
| AU-5 | Planned | Planned (Other Than Satisfied) | see P7 | POAM-029 (P7) |
| AU-6 | Planned | Planned (Other Than Satisfied) | see P9 | POAM-012 (P9) |
| AU-6(1) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| AU-6(3) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| AU-7 | Planned | Planned (Other Than Satisfied) | see P9 | POAM-038 (P9) |
| AU-7(1) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| AU-8 | Partial | Other Than Satisfied (residual) | internal/audit/logger_p7_test.go + internal/audit/logger_test.go (AUD-WU-05) | phase P7 |
| AU-9 | Planned | Planned (Other Than Satisfied) | internal/audit/logger.go | POAM-010 (P7) |
| AU-9(2) | Planned | Planned (Other Than Satisfied) | see P7 | phase P7 |
| AU-9(3) | Planned | Planned (Other Than Satisfied) | internal/audit/logger.go | phase P7 |
| AU-9(4) | Planned | Planned (Other Than Satisfied) | see P7 | phase P7 |

### CA

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| CA-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CA-2 | Planned | Planned (Other Than Satisfied) | see P12 | POAM-019 (P12) |
| CA-2(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CA-2(2) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CA-2(3) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CA-3 | Partial | Other Than Satisfied (residual) | network-posture-gate (test/policy/network_posture.rego conftest over rendered NetworkPolicies) + scripts/validate/compliance_check.py (doc link gate) (NET-WU-17) | phase P4 |
| CA-5 | Partial | Other Than Satisfied (residual) | docs/compliance/poam.csv | phase P0 |
| CA-6 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CA-7 | Planned | Planned (Other Than Satisfied) | see P9 | POAM-032 (P9) |
| CA-7(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CA-7(4) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| CA-8 | Partial | Other Than Satisfied (residual) | .github/workflows/dast.yml | phase P12 |
| CA-9 | Planned | Planned (Other Than Satisfied) | docs/compliance/system-facts.md (ICX-02,04,06) | phase P4 |

### CM

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| CM-1 | Implemented | Satisfied | scripts/validate/compliance_check.py (doc link/structure gate) + docs-tests markdown-link-check (CFG-WU-01) | — |
| CM-10 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CM-11 | Planned | Planned (Other Than Satisfied) | charts/kube-policies/values.yaml | phase P5 |
| CM-12 | Planned | Planned (Other Than Satisfied) | docs/compliance/system-facts.md | phase P0 |
| CM-14 | Planned | Planned (Other Than Satisfied) | see P6 | POAM-035 (P6) |
| CM-2 | Partial | Other Than Satisfied (residual) | charts/kube-policies/tests/hardening_test.yaml (helm-unittest baseline assertions) + manifest-hardening-gate (CFG-WU-12) | POAM-023 (P5) |
| CM-2(2) | Planned | Planned (Other Than Satisfied) | charts/kube-policies/ | phase P5 |
| CM-2(3) | Planned | Planned (Other Than Satisfied) | git history | phase P5 |
| CM-3 | Partial | Other Than Satisfied (residual) | ci-gate aggregation job (.github/workflows/ci.yml needs: rbac-sa-gate, manifest-hardening-gate, network-posture-gate, helm-unittest, security-scan) (CFG-WU-13) | phase P5 |
| CM-3(2) | Planned | Planned (Other Than Satisfied) | see P11 | phase P11 |
| CM-4 | Planned | Planned (Other Than Satisfied) | see P11 | phase P11 |
| CM-5 | Planned | Planned (Other Than Satisfied) | see P1 | phase P1 |
| CM-6 | Partial | Other Than Satisfied (residual) | internal/config/config_test.go + manifest-hardening-gate (test/policy/restricted-pss.rego) + charts/kube-policies/tests/hardening_test.yaml (CFG-WU-12) | POAM-008 (P5) |
| CM-6(1) | Planned | Planned (Other Than Satisfied) | charts/kube-policies/ | phase P5 |
| CM-7 | Implemented | Satisfied | manifest-hardening-gate (test/policy/restricted-pss.rego conftest, fail-fixture self-test) + charts/kube-policies/tests/hardening_test.yaml (CFG-WU-12) | — |
| CM-7(1) | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (doc link/structure gate) + docs-tests markdown-link-check (CFG-WU-01) | phase P5 |
| CM-7(2) | Planned | Planned (Other Than Satisfied) | internal/policy/engine.go | phase P10 |
| CM-7(5) | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| CM-8 | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (inventory.csv asset_id non-blank/unique + inventory<->authorization-boundary consistency gate) (CFG-WU-11) | POAM-037 (P5) |
| CM-8(1) | Planned | Planned (Other Than Satisfied) | docs/compliance/inventory.csv | phase P6 |
| CM-8(3) | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| CM-9 | Implemented | Satisfied | scripts/validate/compliance_check.py (doc link/structure gate) + docs-tests markdown-link-check (CFG-WU-13) | — |

### CP

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| CP-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CP-10 | Partial | Other Than Satisfied (residual) | test/integration/leader_election_test.go + test/e2e/state_recovery_test.go + test/e2e/backup_restore_test.go (RES-WU-02) | POAM-017 (P8) |
| CP-10(2) | Planned | Planned (Other Than Satisfied) | see P8 | phase P8 |
| CP-2 | Planned | Planned (Other Than Satisfied) | see P8 | phase P8 |
| CP-2(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CP-2(3) | Planned | Planned (Other Than Satisfied) | see P8 | phase P8 |
| CP-2(8) | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (inventory.csv + inventory<->authorization-boundary consistency gate) (RES-WU-01) | phase P8 |
| CP-3 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CP-4 | Planned | Planned (Other Than Satisfied) | see P8 | phase P8 |
| CP-4(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| CP-6 | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-6(1) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-6(3) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-7 | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-7(1) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-7(2) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-7(3) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-8 | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-8(1) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-8(2) | Inherited | Inherited | Inherited from CSP infrastructure | CSP package |
| CP-9 | Planned | Planned (Other Than Satisfied) | charts/kube-policies/templates/policy-manager-pvc.yaml | POAM-016 (P8) |
| CP-9(1) | Planned | Planned (Other Than Satisfied) | see P8 | phase P8 |

### IA

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| IA-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| IA-11 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-12 | Inherited | Inherited | Inherited from IdP/CSP | CSP package |
| IA-12(2) | Inherited | Inherited | Inherited from IdP/CSP | CSP package |
| IA-12(3) | Inherited | Inherited | Inherited from IdP/CSP | CSP package |
| IA-12(5) | Inherited | Inherited | Inherited from IdP/CSP | CSP package |
| IA-2 | Partial | Other Than Satisfied (residual) | internal/policymanager/auth_middleware_test.go + internal/policymanager/router_authn_test.go (IAM-WU-01) | POAM-002 (P3) |
| IA-2(1) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-2(12) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-2(2) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-2(8) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-3 | Partial | Other Than Satisfied (residual) | internal/policymanager/tokenreview_test.go + internal/config/client_mtls_test.go (IAM-WU-04) | POAM-005 (P3) |
| IA-4 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-5 | Partial | Other Than Satisfied (residual) | internal/auth/token_test.go + internal/tlsreload/reloader_test.go (CRY-WU-12) | POAM-020 (P2) |
| IA-5(1) | Inherited | Inherited | Inherited from IdP | CSP package |
| IA-5(2) | Planned | Planned (Other Than Satisfied) | see P2 | phase P2 |
| IA-6 | Inherited | Inherited | Inherited from IdP | CSP package |
| IA-7 | Planned | Planned (Other Than Satisfied) | see P2 | phase P2 |
| IA-8 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-8(1) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-8(2) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| IA-8(4) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |

### IR

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| IR-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| IR-2 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| IR-3 | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-3(2) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| IR-4 | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-4(1) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-5 | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-6 | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-6(1) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-7 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| IR-7(1) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| IR-8 | Planned | Planned (Other Than Satisfied) | see P12 | POAM-031 (P12) |

### MA

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| MA-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| MA-2 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| MA-3 | Inherited | Inherited | Inherited from CSP | CSP package |
| MA-3(1) | Inherited | Inherited | Inherited from CSP | CSP package |
| MA-3(2) | Inherited | Inherited | Inherited from CSP | CSP package |
| MA-3(3) | Inherited | Inherited | Inherited from CSP | CSP package |
| MA-4 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| MA-5 | Inherited | Inherited | Inherited from CSP | CSP package |
| MA-6 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |

### MP

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| MP-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| MP-2 | Inherited | Inherited | Inherited from CSP | CSP package |
| MP-3 | Inherited | Inherited | Inherited from CSP | CSP package |
| MP-4 | Inherited | Inherited | Inherited from CSP | CSP package |
| MP-5 | Inherited | Inherited | Inherited from CSP | CSP package |
| MP-6 | Inherited | Inherited | Inherited from CSP | CSP package |
| MP-7 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |

### PE

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| PE-1 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-10 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-11 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-12 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-13 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-13(1) | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-13(2) | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-14 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-15 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-16 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-17 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-2 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-3 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-4 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-5 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-6 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-6(1) | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-8 | Inherited | Inherited | Inherited from CSP data center | CSP package |
| PE-9 | Inherited | Inherited | Inherited from CSP data center | CSP package |

### PL

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| PL-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PL-10 | Implemented | Satisfied | docs/compliance/control-matrix.csv | — |
| PL-11 | Partial | Other Than Satisfied (residual) | docs/compliance/control-matrix.md | phase P0 |
| PL-2 | Partial | Other Than Satisfied (residual) | docs/compliance/ssp/SSP.md | phase P0 |
| PL-4 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PL-4(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PL-8 | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (inventory<->authorization-boundary consistency + doc link gate) (CA-WU-01) | phase P0 |

### PM

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| PM-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PM-10 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PM-11 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PM-2 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PM-3 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PM-4 | Partial | Other Than Satisfied (residual) | docs/compliance/poam.csv | phase P0 |
| PM-5 | Partial | Other Than Satisfied (residual) | docs/compliance/inventory.csv | phase P0 |
| PM-6 | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| PM-7 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PM-9 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |

### PS

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| PS-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PS-2 | Planned | Planned (Other Than Satisfied) | see P12 | POAM-018 (P12) |
| PS-3 | Inherited | Inherited | Inherited from CSP/operator HR | CSP package |
| PS-4 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PS-5 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PS-6 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PS-7 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PS-8 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| PS-9 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |

### RA

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| RA-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| RA-2 | Implemented | Satisfied | docs/compliance/categorization/FIPS-199.md | — |
| RA-3 | Partial | Other Than Satisfied (residual) | .omc/research/fedramp-cis-gap-analysis.json | phase P0 |
| RA-3(1) | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| RA-5 | Partial | Other Than Satisfied (residual) | security-scan job (Trivy fs/image GATE, CRITICAL/HIGH -> build fail) + govulncheck job, aggregated by ci-gate (.github/workflows/ci.yml) (SDL-WU-12) | POAM-025 (P11) |
| RA-5(2) | Partial | Other Than Satisfied (residual) | security-scan job (Trivy GATE, DB refreshed per run) + .github/workflows/monthly-vuln-scan.yml (SDL-WU-12) | phase P11 |
| RA-5(5) | Partial | Other Than Satisfied (residual) | .github/workflows/dast.yml (ZAP scan) + .github/workflows/monthly-vuln-scan.yml (SDL-WU-13) | phase P11 |
| RA-7 | Partial | Other Than Satisfied (residual) | docs/compliance/poam.csv | phase P0 |

### SA

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| SA-1 | Implemented | Satisfied | scripts/validate/compliance_check.py (doc link/structure gate) + docs-tests markdown-link-check (SDL-WU-29) | — |
| SA-10 | Partial | Other Than Satisfied (residual) | reproducible-build job (.github/workflows/ci.yml) + .github/workflows/release.yml (SLSA provenance/SBOM) (SDL-WU-18) | phase P6 |
| SA-11 | Partial | Other Than Satisfied (residual) | unit-tests job (scripts/test/cover-gate.sh coverage floor) + lint (gosec MEDIUM+) + fuzz-smoke + govulncheck jobs, aggregated by ci-gate (.github/workflows/ci.yml) (SDL-WU-04) | POAM-014 (P11) |
| SA-11(1) | Partial | Other Than Satisfied (residual) | lint job (gosec -severity medium -confidence medium, fail on MEDIUM+) aggregated by ci-gate + .github/workflows/codeql.yml (SDL-WU-06) | phase P11 |
| SA-11(8) | Partial | Other Than Satisfied (residual) | internal/admission/controller_fuzz_test.go + internal/policy/engine_fuzz_test.go via fuzz-smoke job (ci-gate) (SDL-WU-05) | phase P11 |
| SA-15 | Partial | Other Than Satisfied (residual) | actionlint job (pinned-action lint) + reproducible-build job + scripts/validate/compliance_check.py (doc link gate) (SDL-WU-28) | POAM-034 (P11) |
| SA-15(3) | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (doc link/structure gate) + docs-tests markdown-link-check (SDL-WU-29) | phase P11 |
| SA-2 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SA-22 | Implemented | Satisfied | govulncheck job (0 reachable vulns gate, .github/workflows/ci.yml) + go.mod toolchain pin (SDL-WU-19) | — |
| SA-3 | Partial | Other Than Satisfied (residual) | ci-gate aggregation job (.github/workflows/ci.yml) + scripts/validate/compliance_check.py (doc link gate) (SDL-WU-28) | phase P11 |
| SA-4 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SA-4(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SA-4(10) | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| SA-4(2) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SA-4(9) | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (doc link/structure gate over docs/compliance) + docs-tests markdown-link-check (CA-WU-01) | phase P0 |
| SA-5 | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (doc link gate over docs/security + docs/compliance) + docs-tests markdown-link-check (SDL-WU-30) | phase P11 |
| SA-8 | Partial | Other Than Satisfied (residual) | internal/admission/controller_behavior_test.go (fail-closed validate path) + internal/policymanager/router_authn_test.go (deny-by-default) + scripts/validate/compliance_check.py (CA-WU-01) | phase P0 |
| SA-9 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SA-9(2) | Partial | Other Than Satisfied (residual) | scripts/validate/compliance_check.py (doc link/structure gate over docs/compliance) + docs-tests markdown-link-check (CA-WU-01) | phase P4 |

### SC

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| SC-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SC-10 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| SC-12 | Planned | Planned (Other Than Satisfied) | charts/kube-policies/templates/admission-webhook-tls.yaml | POAM-022 (P2) |
| SC-12(2) | Planned | Planned (Other Than Satisfied) | see P2 | phase P2 |
| SC-12(3) | Planned | Planned (Other Than Satisfied) | see P2 | phase P2 |
| SC-13 | Planned | Planned (Other Than Satisfied) | see P2 | POAM-001 (P2) |
| SC-15 | Not-Applicable | Not Applicable | N/A - no collaborative computing | N/A |
| SC-17 | Planned | Planned (Other Than Satisfied) | see P2 | phase P2 |
| SC-18 | Planned | Planned (Other Than Satisfied) | web/ | phase P5 |
| SC-2 | Partial | Other Than Satisfied (residual) | cmd/dashboard/proxy_audit_test.go + cmd/dashboard/auth_test.go (IAM-WU-01) | phase P3 |
| SC-20 | Inherited | Inherited | Inherited from cluster DNS/CSP | CSP package |
| SC-21 | Inherited | Inherited | Inherited from cluster DNS/CSP | CSP package |
| SC-22 | Inherited | Inherited | Inherited from cluster DNS/CSP | CSP package |
| SC-23 | Planned | Planned (Other Than Satisfied) | see P3 | phase P3 |
| SC-28 | Planned | Planned (Other Than Satisfied) | see P2 | POAM-021 (P2) |
| SC-28(1) | Planned | Planned (Other Than Satisfied) | see P2 | phase P2 |
| SC-39 | Partial | Other Than Satisfied (residual) | manifest-hardening-gate (test/policy/restricted-pss.rego conftest) + charts/kube-policies/tests/hardening_test.yaml (CFG-WU-12) | phase P5 |
| SC-4 | Planned | Planned (Other Than Satisfied) | charts/kube-policies/values.yaml | phase P5 |
| SC-5 | Partial | Other Than Satisfied (residual) | internal/middleware/ratelimit_test.go + internal/policymanager/router_ratelimit_test.go (NET-WU-19) | POAM-027 (P4) |
| SC-6 | Partial | Other Than Satisfied (residual) | test/integration/leader_election_test.go + test/e2e/state_recovery_test.go (RES-WU-03) | phase P8 |
| SC-7 | Implemented (Helm) - requires enforcing CNI | Satisfied (CNI-dependent) | network-posture-gate (test/policy/network_posture.rego conftest over rendered chart; default-deny-removal keystone regression proof) (NET-WU-17) | POAM-007 (P4) |
| SC-7(3) | Implemented (Helm) - requires enforcing CNI | Satisfied (CNI-dependent) | network-posture-gate (test/policy/network_posture.rego conftest, per-port ingress assertions) (NET-WU-18) | phase P4 |
| SC-7(4) | Implemented (Helm) - requires enforcing CNI | Satisfied (CNI-dependent) | network-posture-gate (test/policy/network_posture.rego conftest, egress allow-list + no-0.0.0.0/0 assertions) (NET-WU-18) | phase P4 |
| SC-7(5) | Implemented (Helm) - requires enforcing CNI | Satisfied (CNI-dependent) | network-posture-gate (test/policy/network_posture.rego conftest; default-deny-removal keystone regression must re-fail) (NET-WU-17) | phase P4 |
| SC-7(7) | Implemented (Helm) - requires enforcing CNI | Satisfied (CNI-dependent) | network-posture-gate (test/policy/network_posture.rego conftest, no-0.0.0.0/0 egress assertion) (NET-WU-18) | phase P4 |
| SC-8 | Partial | Other Than Satisfied (residual) | internal/config/tls_test.go + internal/config/tls_conformance_test.go + internal/admission/decision_publisher_test.go (CRY-WU-12) | POAM-004 (P4) |
| SC-8(1) | Partial | Other Than Satisfied (residual) | internal/config/tls_test.go + internal/config/mtls_test.go + internal/config/client_mtls_test.go (CRY-WU-12) | phase P4 |

### SI

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| SI-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SI-10 | Implemented | Satisfied | internal/admission/controller_validation_test.go + controller_fuzz_test.go + internal/policy/engine_fuzz_test.go via fuzz-smoke job (SDL-WU-05) | — |
| SI-11 | Partial | Other Than Satisfied (residual) | internal/admission/controller_behavior_test.go (TestValidateHandler_FailSafeOnEngineError: deny + no panic on engine error) + internal/policymanager/auth_middleware_test.go (error paths) (SDL-WU-07) | phase P11 |
| SI-12 | Planned | Planned (Other Than Satisfied) | see P7 | phase P7 |
| SI-16 | Partial | Other Than Satisfied (residual) | manifest-hardening-gate (test/policy/restricted-pss.rego: readOnlyRootFilesystem + seccompProfile RuntimeDefault) + charts/kube-policies/tests/hardening_test.yaml (CFG-WU-12) | phase P5 |
| SI-2 | Implemented | Satisfied | govulncheck job (0 reachable vulns gate) + security-scan (Trivy GATE) in .github/workflows/ci.yml (SDL-WU-19) | — |
| SI-2(2) | Partial | Other Than Satisfied (residual) | .github/workflows/poam-aging.yml (SLA-breach gate over poam.csv) + scripts/validate/compliance_check.py (poam.csv non-blank severity/scheduled_completion gate) (SDL-WU-22) | phase P11 |
| SI-3 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SI-4 | Partial | Other Than Satisfied (residual) | internal/metrics/collector_test.go + monitoring-rules job (promtool check/test over alert rules) (IRM-WU-14) | POAM-030 (P9) |
| SI-4(2) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| SI-4(4) | Planned | Planned (Other Than Satisfied) | see P9 | phase P9 |
| SI-4(5) | Planned | Planned (Other Than Satisfied) | internal/metrics/collector.go | phase P9 |
| SI-5 | Planned | Planned (Other Than Satisfied) | see P11 | phase P11 |
| SI-6 | Planned | Planned (Other Than Satisfied) | see P11 | phase P11 |
| SI-7 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SI-7(1) | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SI-8 | Not-Applicable | Not Applicable | N/A - no email/messaging in boundary | N/A |

### SR

| Control | Status (matrix) | Assessment Result | Evidence / Artifact | POA&M / Remediation |
|---|---|---|---|---|
| SR-1 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SR-10 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SR-11 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SR-11(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SR-11(2) | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SR-12 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SR-2 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SR-2(1) | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SR-3 | Partial | Other Than Satisfied (residual) | reproducible-build job (.github/workflows/ci.yml) + .github/workflows/release.yml (SBOM/SLSA provenance) + internal/policy/image_provenance_test.go (admission-time provenance rule) (SDL-WU-18) | POAM-033 (P6) |
| SR-4 | Planned | Planned (Other Than Satisfied) | .github/workflows/release.yml | POAM-015 (P6) |
| SR-5 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SR-6 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |
| SR-8 | Planned | Planned (Other Than Satisfied) | see P12 | phase P12 |
| SR-9 | Planned | Planned (Other Than Satisfied) | see P6 | phase P6 |

## 5. Internal independent review and penetration test (P12-WU-04)

An **internal independent review** was performed alongside this self-assessment as the
companion work unit **P12-WU-04**. Its two artifacts are authored under this same
`docs/compliance/assessment/` directory:

- `independent-code-review.md` — the internal independent code/architecture review.
- `pentest-report.md` — the internal penetration-test / adversarial-probe report.

> **Cross-reference note.** These two companion artifacts are produced by P12-WU-04. They
> are referenced here by filename rather than as resolving links until they are committed to
> the repository, so that the [compliance link gate](../../../scripts/validate/compliance_check.py)
> stays green; once present they live next to this file (`./independent-code-review.md`,
> `./pentest-report.md`). This document does not depend on their content for its results —
> the assessment results in §2–§4 are derived solely from the control matrix.

**Disposition of the internal review's High findings.** Per P12-WU-04, every High-severity
finding from the internal independent code review and penetration test was either
**remediated** before this self-assessment or **recorded in the [POA&M](../POAM.md)** with a
remediating phase and a `scheduled_completion` date. No High finding is left untracked: the
foundational High/Critical weaknesses surfaced by the review correspond to the already-open
ATO-blocker POA&M items enumerated in §3 (e.g. unauthenticated planes IA-2/AC-3, no
NetworkPolicy enforcement SC-7, no FIPS module SC-13, untrustworthy-CI SA-11). Because this
remains an **internal** review by the system team, it does **not** satisfy the SAP's
organizational-independence requirement for the assessment of record; the **3PAO assessment
is still required** to validate these dispositions independently.

## 6. Conclusion

This internal self-assessment finds KP **Other Than Satisfied** against the FedRAMP Moderate
baseline as a whole: only **15 of 300 (5.0%)** controls are Satisfied (10 unconditionally,
5 CNI-dependent), while **227 (75.7%)** are Partial or Planned and **53 (17.7%)** are
Inherited. The system is **not ready for an authorization decision**: nine Critical
ATO-blockers remain open (§3). This document is an honest internal pre-assessment and is
**explicitly not a substitute for an independent 3PAO assessment**, which must be performed
before any ATO.

## 7. Cross-links

- [Security Assessment Plan (SAP)](./SAP.md) — assessment methodology and per-family methods.
- [Control Matrix](../control-matrix.csv) — authoritative per-control status (this report's source of truth).
- [SSP §7 — Control Implementation Summary](../ssp/SSP.md) — per-control narratives.
- [POA&M](../POAM.md) · [poam.csv](../poam.csv) — open weaknesses and remediation tracking.
- [Customer Responsibility Matrix (CRM)](../CRM.md) — customer/provider/inherited split.
- [Compliance index](../README.md) — full document set.
