---
title: "Risk Assessment Procedures (RA) — Kube-Policies (KP)"
control_family: "RA — Risk Assessment"
controls: "RA-1, RA-3, RA-5, RA-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Risk Assessment Procedures (RA) — Kube-Policies (KP)

These are the operational procedures that implement the Risk Assessment policy
([../policies/RA-policy.md](../policies/RA-policy.md)) for the Kube-Policies system (KP).
They provide step-by-step guidance for running vulnerability scans, triaging findings,
maintaining the threat model, and escalating risks to the POA&M.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**). These procedures describe what is *actually implemented*
in CI and what an operator or assessor can run to verify it. Where a control is Partial or
has a residual, the procedure says so; open weaknesses are tracked in [../POAM.md](../POAM.md).
All `@kube-policies.io` contacts below are **placeholders** pending role assignment.

**Annual review.** These procedures are reviewed and updated at least **annually** (last
review **2026-06-01**; next review **2027-06-01**) and on any change to the scanner tooling,
CI job configuration, or vulnerability-triage workflow. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the vulnerability-scanning and risk-assessment activities in
[RA-policy.md §1](../policies/RA-policy.md#1-purpose-and-applicability): all KP
authorization-boundary components, all container images, and all Go module dependencies.

## 2 Threat model review procedure (RA-3)

### 2.1 Annual threat model review

The ISSO reviews the canonical threat model at
[docs/compliance/threat-model.md](../threat-model.md) at least annually (next review:
2027-05-29) and whenever the architecture, authorization boundary, or an interconnection
materially changes. The review:

1. Confirms that all trust-boundary crossings (ICX-01 through ICX-06 in
   [interconnections.md](../interconnections.md)) are still represented in the STRIDE table.
2. Verifies that each identified threat has a mitigation mapped to an implemented control or
   a POA&M entry.
3. Checks the attack-tree for admission bypass and PolicyException abuse for new attack
   paths introduced by recent changes.
4. Updates `last_reviewed`/`next_review` in the threat model front-matter and files a
   POA&M entry for any newly identified risk.

### 2.2 Architecture-triggered review

Any PR that changes the system boundary, adds or removes an interconnection, introduces a
new trust-boundary crossing, or significantly changes a component's authentication/authorization
model triggers an ISSO threat-model review before merge. The reviewer flags the PR with a
threat-model-review label and comments with the outcome.

## 3 Vulnerability scanning procedure (RA-5)

### 3.1 CI-automated scan (every push and PR)

The `security-scan` job in `.github/workflows/ci.yml` runs automatically. To replicate
locally:

```console
# Trivy filesystem scan (mirrors the CI 'fs' scan step)
make security
```

`make security` runs both `gosec` (static analysis) and `govulncheck` (Go module
vulnerability check) when the tools are installed, matching the CI behavior. To run just
the Trivy image and filesystem scans as CI does:

```console
# Trivy filesystem scan
trivy fs --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed .

# Trivy image scans (replace <tag> with your local build tag)
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
  --ignorefile .trivyignore kube-policies/admission-webhook:<tag>
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
  --ignorefile .trivyignore kube-policies/policy-manager:<tag>
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
  --ignorefile .trivyignore kube-policies/dashboard:<tag>
```

```console
# govulncheck — mirrors the CI govulncheck job (pinned to v1.3.0 in CI)
govulncheck ./...
```

A non-zero exit code means at least one fixable CRITICAL or HIGH vulnerability was found.
The CI `ci-gate` job requires both `security-scan` and `govulncheck` to pass before merge.

### 3.2 Reviewing SARIF results in the Security tab

1. Navigate to the repository's **Security → Code scanning alerts** tab on GitHub.
2. Filter by tool: **Trivy** to see image/fs results.
3. For each new alert, follow the triage workflow in §3.4.

### 3.3 Scheduled authenticated scan (planned — P11)

A monthly scheduled scan with authenticated registry access and an updated scanner database
is a P11 deliverable (POAM-008). Until P11, the ISSO reviews the Security tab monthly as
the primary periodic scan review.

### 3.4 Vulnerability triage workflow

For each finding identified by CI or the Security tab review:

```
1. Identify CVE ID, CVSS score, affected package, and fix version (if any).
2. Determine severity tier: Critical (9.0–10.0) · High (7.0–8.9) · Moderate (4.0–6.9) · Low (0.1–3.9)
3. Determine fix availability:
   a. Fix available → open a remediation PR; target completion within SLA.
   b. No fix available → add a dated .trivyignore suppression entry; create POA&M entry.
4. If SLA deadline is within 7 days and no fix is available, notify ISSO and System Owner.
5. Record in POA&M if the finding cannot be remediated within the SLA.
```

Remediation SLAs (clock starts at discovery date):

| Severity | SLA |
|---|---|
| Critical | 30 days |
| High | 30 days |
| Moderate | 90 days |
| Low | 180 days |

### 3.5 Managing `.trivyignore` suppressions

Each suppression entry in `.trivyignore` must follow this format:

```
# CVE-YYYY-NNNNN — <justification> — Review by: YYYY-MM-DD
CVE-YYYY-NNNNN
```

The ISSO reviews all suppression entries monthly and:
- Removes entries where a fix has since become available.
- Extends the review date (with a new justification comment) if no fix is yet available.
- Confirms each active suppression has a corresponding POA&M entry if it is CRITICAL or HIGH.

### 3.6 govulncheck false-positive and known-CVE management

If `govulncheck` reports a vulnerability in a standard library version (e.g., from a pinned
`go` directive in `go.mod`):

```console
# Identify the affected module and its fix version
govulncheck -json ./... | jq '.vulnerability | {id, details, affected}'

# Update go.mod toolchain directive to a fixed version
# (separate hygiene PR; do not mix with feature changes)
go get golang.org/toolchain@<fixed-version>
go mod tidy
```

Track unresolvable `govulncheck` findings (e.g., stdlib CVEs with no upstream patch) in the
POA&M with a `govulncheck` label.

## 4 Risk response procedure (RA-7)

### 4.1 Remediate

For CRITICAL/HIGH findings with a fix available:

1. Open a patch PR targeting the fix version.
2. CI `security-scan` and `govulncheck` must pass on the PR.
3. Maintainer review and merge within the SLA.
4. If the finding had a POA&M entry, close it with the fix commit reference.

### 4.2 Mitigate with compensating control

When a patch is not available within the SLA:

1. Document the compensating control in the POA&M entry (e.g., network policy restricting
   exposure, admission policy denying the affected workload pattern).
2. Add a dated `.trivyignore` suppression (§3.5).
3. ISSO reviews the compensating control adequacy at the next monthly review.

### 4.3 Risk acceptance

Risk acceptance (for LOW findings only) requires:

1. ISSO recommendation documenting the residual risk and rationale.
2. System Owner and AO concurrence.
3. POA&M entry marked "Risk Accepted" with the acceptance date and AO reference.

## 5 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| CI vulnerability scan (Trivy + govulncheck) | Every push / PR (automated) | CI |
| Review Security tab (SARIF results) | Monthly | ISSO |
| Review `.trivyignore` suppressions | Monthly | ISSO |
| POA&M entry review for RA findings | Monthly | ISSO |
| Threat model review | Annually (next: 2027-05-29) + on architecture change | ISSO |
| RA policy and procedures review | Annually (next: 2027-06-01) | ISSO |
| Formal risk assessment (NIST SP 800-30) | Prior to authorization (P12) | ISSO + Assessor |
| Scheduled authenticated scan | Monthly (planned — P11) | Operator |

## 6 Records and evidence

Evidence produced by these procedures is retained as RA assessment evidence:

- CI `security-scan` and `govulncheck` job logs and pass/fail records.
- SARIF uploads in the GitHub Security tab.
- `.trivyignore` file (version-controlled; each entry carries a dated justification).
- Monthly Security tab review notes.
- POA&M entries for unresolved or accepted vulnerabilities.
- Threat model review records (front-matter `last_reviewed` updates with PR references).
- Formal risk assessment report (produced at P12).

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), RA family).

## 7 References

- RA policy: [../policies/RA-policy.md](../policies/RA-policy.md)
- Threat model (canonical): [../threat-model.md](../threat-model.md)
- Threat model (pointer): [docs/security/threat-model.md](../../security/threat-model.md)
- Vulnerability disclosure SLAs: [SECURITY.md](../../../SECURITY.md)
- CI workflow: `.github/workflows/ci.yml` (jobs: `security-scan`, `govulncheck`, `ci-gate`)
- Trivy suppression: `.trivyignore`
- Supply-chain risk management: [../supply-chain-risk-management.md](../supply-chain-risk-management.md)
- SI procedures (flaw remediation patch cadence): [SI-procedures.md](SI-procedures.md)
- CA procedures (ConMon integration): [CA-procedures.md](CA-procedures.md)
- POA&M: [../POAM.md](../POAM.md) · [../poam.csv](../poam.csv)
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (RA-1, RA-3, RA-5, RA-7); NIST SP 800-30 Rev 1; FedRAMP Moderate baseline.
