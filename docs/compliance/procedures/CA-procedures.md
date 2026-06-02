---
title: "Security Assessment and Authorization Procedures (CA) — Kube-Policies (KP)"
control_family: "CA — Security Assessment and Authorization"
controls: "CA-1, CA-2, CA-5, CA-6, CA-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Security Assessment and Authorization Procedures (CA) — Kube-Policies (KP)

These are the operational procedures that implement the Security Assessment and Authorization
policy ([../policies/CA-policy.md](../policies/CA-policy.md)) for the Kube-Policies system
(KP). They map each CA control to concrete, verifiable steps — what to run, what to review,
and how to escalate findings.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**). These procedures describe what is *actually implemented*
in the shipped code and what an operator or assessor can run to verify it. Where a control is
Partial or has a residual, the procedure says so; open weaknesses are tracked in
[../POAM.md](../POAM.md). All `@kube-policies.io` contacts below are **placeholders**
pending role assignment.

**Annual review.** These procedures are reviewed and updated at least **annually** (last
review **2026-06-01**; next review **2027-06-01**) and on any significant change to the
assessment process, authorization decision, or continuous-monitoring strategy. Reviews are
recorded by updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the assessment, authorization, and continuous-monitoring activities
described in [CA-policy.md §1](../policies/CA-policy.md#1-purpose-and-applicability): all
KP authorization-boundary components, all interconnections (ICX-01 through ICX-06), and all
personnel filling CA-relevant roles.

## 2 Control assessment procedure (CA-2)

### 2.1 Pre-assessment evidence collection

Before initiating a formal assessment, the ISSO assembles the evidence package:

```console
# 1. Run the full test suite to capture unit + integration + e2e results
go test ./... 2>&1 | tee /tmp/kp-test-results.txt

# 2. Run chart validation (kubeconform -strict on all value profiles)
helm template kube-policies charts/kube-policies -f charts/kube-policies/values.yaml \
  | kubeconform -strict -summary

# 3. Run conftest policy gates (restricted-PSS, RBAC, SA-token)
helm template kube-policies charts/kube-policies | conftest test -p policy/ -

# 4. Run security scan (Trivy + govulncheck, mirrors CI security-scan + govulncheck jobs)
make security

# 5. Collect CI gate status for the current HEAD commit
#    Verify all required jobs passed in .github/workflows/ci.yml (ci-gate job)
```

The test-result artifact (`/tmp/kp-test-results.txt`) and CI gate screenshot/log are
retained as CA-2 assessment evidence referenced in the SSP
([../ssp/SSP.md](../ssp/SSP.md)).

### 2.2 Control-by-control assessment

The assessor works through the [control matrix](../control-matrix.csv) and [CRM](../CRM.md)
family by family, verifying each control's implementation status against the evidence
collected in §2.1. For each control:

1. Read the implementation claim in the control narrative or policy.
2. Execute the cited verification command or inspect the cited code path.
3. Record the result: **Implemented**, **Partial**, or **Not Implemented**.
4. For Partial or Not Implemented: create or update a POA&M entry (§4).

### 2.3 Independent assessor review (CA-2(1))

The ISSO coordinates with the independent assessor (TBD — assign before assessment) to
review the evidence package and the control-by-control results. The assessor produces a
Security Assessment Report (SAR). The SAR is the input to the AO authorization decision
(§3).

## 3 Authorization procedure (CA-6)

### 3.1 Authorization package assembly

The System Owner assembles the authorization package:

| Document | Location | Status |
|---|---|---|
| System Security Plan (SSP) | [../ssp/SSP.md](../ssp/SSP.md) | Draft — finalize before assessment |
| FIPS-199 Categorization | [../categorization/FIPS-199.md](../categorization/FIPS-199.md) | Complete |
| Security Assessment Plan (SAP) | [../assessment/SAP.md](../assessment/SAP.md) | Draft |
| Security Assessment Report (SAR) | TBD — produced at assessment | Not yet available |
| POA&M | [../POAM.md](../POAM.md) / [../poam.csv](../poam.csv) | Active |

### 3.2 AO review and authorization decision

1. System Owner submits the authorization package to the AO (TBD — assign before
   assessment).
2. AO reviews the package, the SAR, and the POA&M.
3. AO renders one of: **Authorization to Operate (ATO)**, **Interim ATO**, or **Denial**.
4. The authorization decision, conditions, and termination date are recorded in the SSP
   and communicated to the ISSO.

### 3.3 Significant-change notification

When any of the reauthorization triggers in [CA-policy.md §5.2](../policies/CA-policy.md#52-reauthorization-triggers)
occur, the ISSO notifies the AO within **5 business days** and initiates a reauthorization
assessment if required by the AO.

## 4 Plan of Action and Milestones procedure (CA-5)

### 4.1 Creating a POA&M entry

When a control weakness is identified (during development, assessment, CI failure, or
continuous monitoring), the ISSO creates an entry in both [poam.csv](../poam.csv) and
[POAM.md](../POAM.md) with:

- **POAM-ID** (next sequential integer)
- **Control** (NIST control ID)
- **Finding** (what is weak or missing)
- **Responsible role** (TBD — assign)
- **Remediation milestone** (phase P0–P12 or calendar date)
- **Target completion date**
- **Current status** (Open / In Progress / Closed)

### 4.2 Monthly POA&M review

The ISSO reviews all open POA&M entries monthly:

1. Verify each entry's milestone date has not slipped. If slipped, update the target date
   and document the reason.
2. For entries marked closed, verify the remediation evidence (test result, CI pass, or
   operator confirmation).
3. Produce a monthly POA&M status summary and share it with the System Owner.

### 4.3 Quarterly AO status report

The ISSO produces a quarterly POA&M status report for the AO summarizing:
- Total open / in-progress / closed entries
- Entries at risk of milestone slip
- New entries since the last report
- Entries closed since the last report

## 5 Continuous monitoring procedure (CA-7)

### 5.1 Monitored signals and review cadences

The full signal inventory with collection mechanisms, alert rules, and cadences is in the
[Continuous Monitoring Plan](../../security/continuous-monitoring-plan.md). The table below
summarizes the reporting path for each cadence tier.

| Cadence | Activities | Owner |
|---|---|---|
| Real-time (automated) | Prometheus/Alertmanager fires on availability, fail-open, audit-drop, cert-expiry, DoS alerts | Primary on-call → ISSO (within 15 min for SEV1) |
| Weekly | Review admission deny-rate spikes; confirm audit hash-chain (`VerifyChainFiles`) passed; confirm forwarder delivery | Operator; ISSO |
| Monthly | SLO burn-rate review; vulnerability scan result review; POA&M entry review; configuration drift check | ISSO |
| Quarterly | POA&M status report to AO; ConMon plan adequacy review | ISSO |
| Annually | Full ConMon plan review; CA policy + procedures review | ISSO |

### 5.2 Collecting and reviewing vulnerability scan results

CI automatically runs the `security-scan` job (Trivy filesystem and image scans) and the
`govulncheck` job on every push and pull request. To replicate locally:

```console
# Trivy filesystem scan (mirrors CI security-scan job)
make security

# govulncheck (mirrors CI govulncheck job — pinned to v1.3.0 in CI)
govulncheck ./...
```

Scan results are uploaded to the GitHub Security tab as SARIF artifacts. The ISSO reviews
the Security tab monthly for new findings and creates POA&M entries for unmitigated
findings. See [RA procedures](RA-procedures.md) §3 for the full vulnerability-triage
workflow.

### 5.3 Configuration drift detection

The ISSO verifies monthly that the deployed Helm release matches the chart in version
control:

```console
# Diff the current release manifest against a fresh chart render
helm get manifest kube-policies -n kube-policies-system > /tmp/deployed.yaml
helm template kube-policies charts/kube-policies -f charts/kube-policies/values.yaml \
  > /tmp/expected.yaml
diff /tmp/deployed.yaml /tmp/expected.yaml
```

Unexplained diffs are escalated to the System Owner and may trigger reauthorization.

### 5.4 Monitoring finding → POA&M escalation

Any monitoring finding that cannot be resolved within the current review cycle is escalated
to a POA&M entry per §4.1. The escalation path is:

```
Alert fires → on-call acknowledges within SLA → ISSO reviews → POA&M entry created
  → monthly review tracks to closure → quarterly report to AO
```

## 6 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| Real-time Prometheus/Alertmanager monitoring | Continuous | On-call / Operator |
| Review Security tab (Trivy/govulncheck SARIF) | Monthly | ISSO |
| SLO burn-rate review | Monthly | ISSO |
| Configuration drift check | Monthly | ISSO |
| POA&M entry review and update | Monthly | ISSO |
| Quarterly AO status report | Quarterly | ISSO |
| ConMon plan review | Annually (next: 2027-06-01) | ISSO |
| CA policy and procedures review | Annually (next: 2027-06-01) | ISSO |

## 7 Records and evidence

Evidence produced by these procedures is retained as CA assessment evidence:

- Test suite output (`go test ./...`) and CI gate pass/fail records.
- Trivy SARIF uploads in the GitHub Security tab.
- `govulncheck` output from CI.
- Chart validation output (`kubeconform -strict`, `conftest`).
- Monthly POA&M review records.
- Quarterly AO status reports.
- SAP and SAR (produced at assessment time).

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), CA family).

## 8 References

- CA policy: [../policies/CA-policy.md](../policies/CA-policy.md)
- Continuous Monitoring Plan: [docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)
- Security Assessment Plan: [docs/compliance/assessment/SAP.md](../assessment/SAP.md)
- SLO plan: [docs/observability/slo.md](../../observability/slo.md)
- POA&M: [../POAM.md](../POAM.md) · [../poam.csv](../poam.csv)
- Interconnections: [../interconnections.md](../interconnections.md)
- RA procedures (vuln-scan workflow): [RA-procedures.md](RA-procedures.md)
- CI workflow: `.github/workflows/ci.yml` (jobs: `security-scan`, `govulncheck`, `ci-gate`)
- Alert rules: `charts/kube-policies/files/alerts/`
- Monitoring templates: `charts/kube-policies/templates/prometheusrule.yaml` · `charts/kube-policies/templates/servicemonitor.yaml`
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CA-1, CA-2, CA-5, CA-6, CA-7); FedRAMP Moderate baseline.
