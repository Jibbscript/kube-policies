---
title: "System and Information Integrity Procedures (SI) — Kube-Policies (KP)"
control_family: "SI — System and Information Integrity"
controls: "SI-1, SI-2, SI-4, SI-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# System and Information Integrity Procedures (SI) — Kube-Policies (KP)

These are the operational procedures that implement the System and Information Integrity
policy ([../policies/SI-policy.md](../policies/SI-policy.md)) for the Kube-Policies system
(KP). They provide verifiable, step-by-step guidance for patching flaws, verifying audit
integrity, and operating the monitoring stack.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**). These procedures describe what is *actually implemented*
in the shipped code and CI and what an operator or assessor can run to verify it. Where a
control is Partial or has a residual, the procedure says so; open weaknesses are tracked in
[../POAM.md](../POAM.md). All `@kube-policies.io` contacts below are **placeholders**
pending role assignment.

**Annual review.** These procedures are reviewed and updated at least **annually** (last
review **2026-06-01**; next review **2027-06-01**) and on any change to the scanning tools,
alert rules, or audit integrity mechanism. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the components, images, dependencies, monitoring signals, and
integrity mechanisms in
[SI-policy.md §1](../policies/SI-policy.md#1-purpose-and-applicability).

## 2 Flaw remediation procedure (SI-2)

### 2.1 Identify flaws via CI gates

The `security-scan` and `govulncheck` CI jobs run automatically on every push and PR. To
replicate the full CI scan locally:

```console
# Mirror the CI security-scan job: Trivy fs + image scans + gosec + govulncheck
make security

# govulncheck alone (mirrors the CI govulncheck job, pinned to v1.3.0 in CI)
govulncheck ./...
```

A non-zero exit from either command means at least one fixable CRITICAL or HIGH finding was
detected. The CI `ci-gate` job requires both to pass before any merge to main.

### 2.2 Triage a finding

For each finding from CI or the GitHub Security tab (SARIF upload from `security-scan`):

1. Note the CVE ID, CVSS v3 base score, affected component (image or Go module), and
   whether a fix version is available.
2. Apply the severity-to-SLA mapping:

   | Severity | CVSS range | Patch SLA |
   |---|---|---|
   | Critical | 9.0 – 10.0 | **30 days** |
   | High | 7.0 – 8.9 | **30 days** |
   | Moderate | 4.0 – 6.9 | **90 days** |
   | Low | 0.1 – 3.9 | **180 days** |

3. If a fix is available → proceed to §2.3 (image) or §2.4 (dependency).
4. If no fix is available → add a `.trivyignore` suppression (§2.5) and open a POA&M entry.

### 2.3 Patch a container image

KP images are built `FROM gcr.io/distroless/static`. When a base-image CVE is identified:

```console
# 1. Identify the fixed base image digest
docker pull gcr.io/distroless/static:nonroot
docker inspect gcr.io/distroless/static:nonroot \
  --format '{{index .RepoDigests 0}}'

# 2. Update the FROM line in the Dockerfile to the new digest
#    e.g.: FROM gcr.io/distroless/static@sha256:<new-digest>

# 3. Rebuild and re-scan
docker build -t kube-policies/admission-webhook:dev \
  -f cmd/admission-webhook/Dockerfile .
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
  kube-policies/admission-webhook:dev

# 4. Confirm finding is resolved, then open a PR
# 5. CI security-scan and govulncheck must pass before merge
go test ./...
```

### 2.4 Patch a Go dependency

```console
# 1. Identify the vulnerable module and fix version
govulncheck -json ./... | jq '.vulnerability | {id, details, affected}'

# 2. Update to the fixed version
go get <module>@<fixed-version>
go mod tidy

# 3. Confirm the finding is resolved
govulncheck ./...

# 4. Run the full test suite — confirm no regression
go test ./...

# 5. Open a PR; CI security-scan and govulncheck must pass
```

For stdlib CVEs from a pinned `go` toolchain directive in `go.mod`:

```console
# Bump the toolchain directive to the fixed Go version
go get golang.org/toolchain@<fixed-version>
go mod tidy
govulncheck ./...
go test ./...
```

### 2.5 Manage `.trivyignore` suppressions

When a fix is not available within the SLA:

```console
# Add a dated, justified suppression entry to .trivyignore
# Format: comment with CVE, justification, and review-by date; then the CVE ID on the next line
# Example:
# CVE-2024-99999 — no fix available in distroless:nonroot as of 2026-06-01;
#   compensating: network policy limits exposure. Review by: 2026-09-01.
# CVE-2024-99999
```

The ISSO reviews all active `.trivyignore` entries monthly:

```console
# List all suppressed CVEs and their review dates
grep -E "^#|^CVE" .trivyignore
```

Any suppression whose review date has passed must be re-evaluated: remove if a fix is
available; extend with a new dated comment if not.

### 2.6 Flaw-remediation completion verification

Before closing a POA&M entry for a patched finding:

```console
# Full test suite (no regressions)
go test ./...

# Confirm vulnerability is resolved
make security
govulncheck ./...

# Confirm CI gates pass on the patched branch (check GitHub Actions or run locally)
```

## 3 System monitoring procedure (SI-4)

### 3.1 Deploy and verify the monitoring stack

The monitoring stack (ServiceMonitor, PrometheusRule, SLO PrometheusRule) is deployed as
part of the Helm chart. Confirm it is deployed and alert rules are loaded:

```console
# Confirm PrometheusRule and ServiceMonitor are present in the cluster
kubectl get prometheusrule,servicemonitor -n kube-policies-system

# Validate alert rule syntax locally (mirrors CI monitoring-rules job)
helm template kube-policies charts/kube-policies \
  --set monitoring.enabled=true \
  | promtool check rules /dev/stdin
```

### 3.2 Verify security-relevant alert rules are active

The following alert rules from `charts/kube-policies/files/alerts/security.yaml` and
`availability.yaml` must be active in Prometheus:

```console
# Query Prometheus for active alert rules (requires kubectl port-forward or cluster access)
kubectl exec -n monitoring deploy/prometheus \
  -- promtool query rules | grep -E "KubePoliciesFailOpen|KubePoliciesAudit|KubePoliciesCert"
```

Expected rules present:
- `KubePoliciesFailOpenActive` (security.yaml)
- `KubePoliciesAuditEventsDropped` (security.yaml)
- `KubePoliciesAuditWriteErrors` (security.yaml)
- `KubePoliciesAuditBufferSaturated` (security.yaml)
- `KubePoliciesCertExpiringSoon` / `KubePoliciesCertExpiringCritical` / `KubePoliciesCertExpired` (tls.yaml)
- `KubePoliciesDown` / `KubePoliciesWebhookNotReady` (availability.yaml)
- `KubePoliciesErrorBudgetBurnFast` / `KubePoliciesErrorBudgetBurnSlow` (slo-prometheusrule.yaml)

### 3.3 Respond to a security-relevant alert

On receiving a security-relevant alert:

1. Acknowledge within the SLA per
   [IR-policy.md §4.3](../policies/IR-policy.md#43-escalation-timelines).
2. Open the incident record using
   [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md).
3. Execute the applicable runbook:
   - `KubePoliciesFailOpenActive` → [fail-open-event.md](../../security/runbooks/fail-open-event.md)
   - `KubePoliciesAuditEventsDropped` / `KubePoliciesAuditWriteErrors` →
     [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md)
   - `KubePoliciesDown` / `KubePoliciesWebhookNotReady` →
     [webhook-outage.md](../../security/runbooks/webhook-outage.md)
   - `KubePoliciesCertExpiringCritical` / `KubePoliciesCertExpired` →
     [cert-expiry.md](../../security/runbooks/cert-expiry.md)
4. Notify the ISSO within the escalation SLA.

### 3.4 Confirm fail-open counter is zero (steady-state check)

In steady state the fail-open counter must be zero. Verify:

```console
kubectl exec -n kube-policies-system deploy/kube-policies-admission-webhook \
  -- wget -qO- http://localhost:9090/metrics \
  | grep kube_policies_admission_fail_open_total
# Expected output: kube_policies_admission_fail_open_total 0
```

A non-zero counter is an active incident (category: Fail-open event). Escalate immediately.

## 4 Audit integrity verification procedure (SI-7)

### 4.1 Weekly hash-chain verification

The operator runs `VerifyChainFiles` weekly and immediately on any indication of log
tampering:

```console
# Unit-level verification that the chain detection guarantees hold
go test ./internal/audit/ \
  -run 'TestVerifyChain_Untampered|TestVerifyChain_DetectsByteFlip|TestVerifyChain_DetectsDeletedRecord|TestVerifyChain_WrongKey|TestFileBackend_RotationPreservesChain'
```

For a live audit log file, `VerifyChainFiles` is called programmatically via the audit
subsystem (`internal/audit/integrity.go`). A verification failure means:

- Preserve the log files immediately (do not rotate or delete).
- Notify the ISSO (`isso@kube-policies.io`, placeholder) — this is a security incident
  (IR category: Audit pipeline loss / CRD tampering).
- Follow [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md).

### 4.2 Confirm integrity-chain tests pass after any audit-subsystem change

Any PR that changes [`internal/audit/integrity.go`](../../../internal/audit/integrity.go),
the audit schema, or the logger must pass:

```console
go test ./internal/audit/ -run 'TestVerifyChain|TestFileBackend'
```

### 4.3 Confirm redaction before seal (AU-3(1) / SI-7)

Audit records must be redacted before being sealed into the HMAC chain — no Secret data or
credential-like keys in the sealed record:

```console
go test ./internal/audit/ \
  -run 'TestMaybeRedact_SecretData|TestFileBackend_RedactionBeforeSeal|TestMaybeRedact_SensitiveKeys'
```

## 5 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| CI vulnerability scan (Trivy + govulncheck) | Every push / PR (automated) | CI |
| Review Security tab (SARIF) + govulncheck CI logs | Monthly | ISSO |
| Review `.trivyignore` suppressions | Monthly | ISSO |
| POA&M entry review for SI findings | Monthly | ISSO |
| Confirm fail-open counter is zero | Weekly | Operator |
| Run audit hash-chain verification | Weekly | Operator |
| Confirm alert rules are active and syntax-valid | Monthly | Operator |
| SI policy and procedures review | Annually (next: 2027-06-01) | ISSO |

## 6 Records and evidence

Evidence produced by these procedures is retained as SI assessment evidence:

- CI `security-scan` and `govulncheck` job logs and pass/fail records.
- SARIF uploads in the GitHub Security tab.
- `.trivyignore` file (version-controlled; each entry carries a dated justification).
- Monthly Security tab review notes.
- Hash-chain verification output (pass/fail, date, and operator).
- Fail-open counter readings (steady-state confirmation logs).
- Alert rule validation output (`promtool check rules`).
- Unit-test output proving integrity-chain, redaction, and monitoring guarantees
  (the `*_test.go` suites cited above).
- POA&M entries for unresolved findings.

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), SI family).

## 7 References

- SI policy: [../policies/SI-policy.md](../policies/SI-policy.md)
- Audit integrity: [`internal/audit/integrity.go`](../../../internal/audit/integrity.go)
- Audit logger: [`internal/audit/logger.go`](../../../internal/audit/logger.go)
- Audit forward backend: [`internal/audit/forward_backend.go`](../../../internal/audit/forward_backend.go)
- CRD controller audit: [`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go)
- Alert rules: `charts/kube-policies/files/alerts/security.yaml` · `availability.yaml` · `tls.yaml` · `capacity.yaml` · `dos.yaml` · `watchdog.yaml`
- Monitoring templates: `charts/kube-policies/templates/prometheusrule.yaml` · `charts/kube-policies/templates/servicemonitor.yaml` · `charts/kube-policies/templates/slo-prometheusrule.yaml`
- Continuous Monitoring Plan: [docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)
- SIEM integration: [docs/security/siem-integration.md](../../security/siem-integration.md)
- Runtime detection: [docs/security/runtime-detection.md](../../security/runtime-detection.md)
- Runbooks: [docs/security/runbooks/fail-open-event.md](../../security/runbooks/fail-open-event.md) · [audit-pipeline-loss.md](../../security/runbooks/audit-pipeline-loss.md) · [webhook-outage.md](../../security/runbooks/webhook-outage.md) · [cert-expiry.md](../../security/runbooks/cert-expiry.md)
- Incident record template: [docs/security/templates/incident-record-template.md](../../security/templates/incident-record-template.md)
- RA procedures (vuln-scan detail): [RA-procedures.md](RA-procedures.md)
- AU procedures (audit overflow / integrity): [AU-procedures.md](AU-procedures.md)
- IR procedures (alert → incident): [IR-procedures.md](IR-procedures.md)
- Vulnerability disclosure SLAs: [SECURITY.md](../../../SECURITY.md)
- CI workflow: `.github/workflows/ci.yml` (jobs: `security-scan`, `govulncheck`, `monitoring-rules`, `ci-gate`)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (SI-1, SI-2, SI-4, SI-7); FedRAMP Moderate baseline; FIPS-199.
