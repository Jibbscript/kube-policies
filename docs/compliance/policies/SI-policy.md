---
title: "System and Information Integrity Policy (SI) — Kube-Policies (KP)"
control_family: "SI — System and Information Integrity"
controls: "SI-1, SI-2, SI-4, SI-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# System and Information Integrity Policy (SI) — Kube-Policies (KP)

This policy establishes the System and Information Integrity requirements for the
Kube-Policies system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5**
(FedRAMP **Moderate** baseline). It implements control **SI-1 (Policy and Procedures)** and
anchors the SI controls that govern how KP detects and remediates flaws, monitors for
anomalies, and protects the integrity of admission decisions: **SI-2** (Flaw Remediation),
**SI-4** (System Monitoring), and **SI-7** (Software, Firmware, and Information Integrity).
The operational steps live in the companion [SI procedures](../procedures/SI-procedures.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This policy documents the
integrity *discipline* the program operates under and the controls that are *actually
implemented* in code — it is not a claim that every SI control is operating or has been
assessed. Per-control status is tracked in the [control matrix](../control-matrix.csv) and
open weaknesses in the [POA&M](../POAM.md), with remediation phases (P0–P12) defined in
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review
was **2026-06-01**; the **next review is 2027-06-01**. It is also reviewed whenever patch
cadence timelines change, a new monitoring signal is added, the audit integrity mechanism
changes, or an assessor finding is received. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that KP components are kept free of known flaws
through timely patching, that anomalous behavior is detected through continuous monitoring,
and that the integrity of admission decisions is protected through a tamper-evident
hash-chain. It applies to:

- All KP authorization-boundary components: admission-webhook (`AST-WH`), policy-manager
  (`AST-PM`), dashboard (`AST-DB`/`AST-SPA`).
- All container images (`gcr.io/distroless/static`-based) and Go module dependencies.
- The audit integrity subsystem
  ([`internal/audit/integrity.go`](../../../internal/audit/integrity.go)) that protects
  the tamper-evidence of admission decisions.
- The Prometheus/Alertmanager/Grafana monitoring stack (ServiceMonitor, PrometheusRule,
  alert rules in `charts/kube-policies/files/alerts/`).
- All personnel filling the System Owner, ISSO, Maintainer/CODEOWNERS, and Operator roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts referenced in
procedures are **placeholders**.

## 2 SI-1 — System and Information Integrity Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this SI policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the procedures are in
[SI procedures](../procedures/SI-procedures.md).

### 2.2 SI-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Maintainers, and all repository contributors by being maintained in version
control under [`docs/compliance/policies/`](.) and referenced from the SSP
([../ssp/SSP.md](../ssp/SSP.md), SI family) and the [CRM](../CRM.md).

### 2.3 SI-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing.

### 2.4 SI-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This SI policy (SI-1) | ISSO | At least annually (next: 2027-06-01) | Patch cadence change; new monitoring signal; integrity mechanism change; assessor finding |
| SI procedures ([SI-procedures.md](../procedures/SI-procedures.md)) | ISSO | At least annually (next: 2027-06-01) | Procedure drift; new alert rule; scanner change |
| Alert rules (`charts/kube-policies/files/alerts/`) | Maintainer | Per alert-rule change | New metric exposed; SLO threshold change |
| Audit integrity mechanism ([`internal/audit/integrity.go`](../../../internal/audit/integrity.go)) | Maintainer | Per integrity-subsystem change | HMAC algorithm change; chain format change |

## 3 SI-2 — Flaw Remediation

### 3.1 Flaw identification

Flaws are identified through:

1. **CI vulnerability gates** — the `security-scan` CI job (Trivy filesystem and image
   scans) and the `govulncheck` job run on every push and PR; both are required by the
   `ci-gate` job. A fixable CRITICAL or HIGH finding fails the build.
2. **Monthly Security tab review** — the ISSO reviews SARIF results uploaded to the GitHub
   Security tab by the `security-scan` job.
3. **External reports** — submitted via [SECURITY.md](../../../SECURITY.md) and triaged
   per the [IR policy](IR-policy.md) and [RA policy](RA-policy.md).

### 3.2 Patch cadence by severity

Patch timelines are aligned to the FedRAMP Moderate continuous-monitoring remediation
requirements and the [SECURITY.md](../../../SECURITY.md) SLAs. SLA clocks start from the
**discovery date** (CI scan or external report receipt).

| Severity (CVSS v3) | CVSS range | Image patch SLA | Dependency patch SLA |
|---|---|---|---|
| Critical | 9.0 – 10.0 | **30 days** | **30 days** |
| High | 7.0 – 8.9 | **30 days** | **30 days** |
| Moderate | 4.0 – 6.9 | **90 days** | **90 days** |
| Low | 0.1 – 3.9 | **180 days** | **180 days** |

Findings that cannot be patched within the SLA are tracked in the [POA&M](../POAM.md) with
a documented rationale and compensating controls.

### 3.3 Image patching

KP component images are based on `gcr.io/distroless/static`. When a base-image CVE is
identified:
1. Update the base image digest pin in the relevant `Dockerfile` to a fixed version.
2. Rebuild and re-scan with Trivy.
3. The `security-scan` CI job must pass before merge.
4. Tag and release a new chart version per the release process.

### 3.4 Go dependency patching

When a vulnerable Go module is identified by `govulncheck` or Trivy:

```console
# Identify the vulnerable module and available fix
govulncheck ./...

# Update to the fixed version
go get <module>@<fixed-version>
go mod tidy

# Verify the fix resolves the finding
govulncheck ./...
go test ./...
```

The `govulncheck` CI job must pass on the patched PR before merge.

### 3.5 Flaw-remediation verification

```console
# Full test suite — confirms no regression from the patch
go test ./...

# Re-run CI-equivalent scans to confirm the finding is resolved
make security
govulncheck ./...
```

## 4 SI-4 — System Monitoring

### 4.1 Monitoring infrastructure

KP's monitoring infrastructure is chart-deployed and single-source:

- **ServiceMonitor** (`charts/kube-policies/templates/servicemonitor.yaml`): configures
  Prometheus to scrape KP metrics endpoints (`:9090` webhook, `:9091` policy-manager,
  `:9092` dashboard).
- **PrometheusRule** (`charts/kube-policies/templates/prometheusrule.yaml`): loads the
  alert rules from `charts/kube-policies/files/alerts/`.
- **SLO PrometheusRule** (`charts/kube-policies/templates/slo-prometheusrule.yaml`):
  error-budget burn-rate rules.
- **Alert rule files** (`charts/kube-policies/files/alerts/`):
  - `availability.yaml` — component availability, error-budget burn, latency SLO
  - `security.yaml` — fail-open events, audit drops/write-errors, audit buffer saturation
  - `tls.yaml` — certificate expiry (30-day warn, 7-day critical, 0-day critical)
  - `capacity.yaml` — resource utilization
  - `dos.yaml` — denial-of-service indicators
  - `watchdog.yaml` — dead-man's switch

The Continuous Monitoring Plan at
[docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)
is the authoritative inventory of all monitored signals, cadences, and reviewers.

### 4.2 Security-relevant monitoring signals

The following signals are specifically relevant to SI-4 (system monitoring for anomalous
behavior and security events):

| Signal | Metric | Alert | Significance |
|---|---|---|---|
| Fail-open events | `kube_policies_admission_fail_open_total` | `KubePoliciesFailOpenActive` (critical) | Mutate controls bypassed — potential policy bypass |
| Audit events dropped | `kube_policies_audit_events_total{status="dropped"}` | `KubePoliciesAuditEventsDropped` (critical) | Silent audit loss — integrity risk |
| Audit write errors | `kube_policies_audit_events_total{status="write_error"}` | `KubePoliciesAuditWriteErrors` (critical) | Audit pipeline failure |
| Deny-rate spike | Admission deny rate | `KubePoliciesDenyRateSpike` | Possible misconfiguration or policy bypass attempt |
| Error-budget burn (fast) | Error ratio | `KubePoliciesErrorBudgetBurnFast` (critical) | Admission availability degradation |
| TLS cert expiry | `kube_policies_tls_cert_expiry_seconds` | `KubePoliciesCertExpiringCritical` / `KubePoliciesCertExpired` | Certificate failure risks admission outage |
| Dead-man's switch | Alertmanager watchdog | `KubePoliciesWatchdogHeartbeatMissing` | Monitoring pipeline itself has failed |

### 4.3 Monitoring alert syntax verification

Alert rules are validated in CI by the `monitoring-rules` CI job. To verify locally:

```console
helm template kube-policies charts/kube-policies \
  --set monitoring.enabled=true \
  | promtool check rules /dev/stdin
```

### 4.4 SI-4 and SIEM integration

The [SIEM integration guide](../../security/siem-integration.md) describes how KP audit
records are forwarded off-host to a SIEM for correlation and automated analysis. The
in-process `ForwardBackend`
([`internal/audit/forward_backend.go`](../../../internal/audit/forward_backend.go)) ships
records over TLS; the DaemonSet forwarder
(`charts/kube-policies/templates/audit-forwarder-daemonset.yaml`) is the deployment path.
Both are default-off (POAM-012).

### 4.5 Runtime detection

Runtime anomaly detection via Falco/Tetragon is documented in
[docs/security/runtime-detection.md](../../security/runtime-detection.md). This is a
complementary layer to the Prometheus/Alertmanager monitoring; it is not yet integrated
with the KP alert rules (POAM — P9).

## 5 SI-7 — Software, Firmware, and Information Integrity

### 5.1 Admission-decision integrity (audit hash-chain)

KP protects the integrity of admission decisions through a tamper-evident HMAC hash-chain
in the audit subsystem. When integrity is enabled, every persisted audit record is sealed as
`{"record":<event>,"hmac":<hex>}` by `Chainer.Seal`
([`internal/audit/integrity.go`](../../../internal/audit/integrity.go)). The chain links
each record to the previous via `Sequence` and `PrevHash` fields; `VerifyChain` /
`VerifyChainFiles` detect byte-flips, deleted or reordered records, wrong-key tampering, and
cross-rotation breaks.

**What the chain protects.** Each record captures the admission decision outcome (allow/deny),
the matched policy, the requesting principal, and dual UTC timestamps — the facts that
constitute "what was decided, about what, and when." Tampering with any of these fields
breaks the chain and is detected on the next verification run.

```console
# Verify the integrity guarantee is tested
go test ./internal/audit/ -run 'TestVerifyChain_Untampered|TestVerifyChain_DetectsByteFlip|TestVerifyChain_DetectsDeletedRecord|TestVerifyChain_WrongKey|TestFileBackend_RotationPreservesChain'
```

### 5.2 Supply-chain integrity

Container image and supply-chain integrity is governed by the
[supply-chain risk management policy](../supply-chain-risk-management.md) and the
[SR policy](SR-policy.md): images are signed, attested, and referenced by digest; the
`security-scan` CI job validates images before promotion. Admission webhook images used in
production shall be pinned by digest, not mutable tag.

### 5.3 Configuration integrity (CRD state)

Policy and PolicyException CRDs in etcd are the single source of truth for admission
decisions. The management-plane audit log records every mutation (UPSERT/DELETE) attributed
to the initiating principal
([`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go)
`auditReconcile`). Any CRD mutation by an unexpected principal is an IR-4 finding (see
[IR policy](IR-policy.md) §3 — CRD tampering).

## 6 Roles and responsibilities (summary)

| Role | Holder | SI responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for flaw-remediation program; approves risk-acceptance for CRITICAL/HIGH that cannot be patched within SLA; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures; reviews monthly scan results; tracks flaw-remediation SLAs; reviews monitoring alerts; maintains the POA&M for SI findings. |
| Maintainers / CODEOWNERS | TBD — assign | Patch vulnerable images and dependencies within SLA; maintain alert rules; review PRs that change the integrity mechanism or audit schema. |
| Operator | TBD — assign | Deploys chart with monitoring enabled; responds to alerts per runbooks; runs weekly hash-chain verification; reports anomalies to ISSO. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves risk-acceptance for unresolvable CRITICAL/HIGH findings; receives quarterly POA&M status. |

Contacts referenced operationally are **placeholders** pending role assignment.

## 7 Compliance, exceptions, and enforcement

- A PR that introduces a new fixable CRITICAL or HIGH vulnerability (as gated by the
  `security-scan` or `govulncheck` CI jobs) shall not be merged without ISSO approval and
  a POA&M entry.
- Allowing a CRITICAL or HIGH finding to exceed its 30-day patch SLA without a POA&M
  entry and ISSO acknowledgement is a material compliance failure.
- Disabling audit integrity (the HMAC hash-chain) in an assessed environment requires ISSO
  approval and a POA&M entry.
- Disabling or removing a security-relevant alert rule (fail-open, audit-drop, cert-expiry)
  without ISSO approval is a finding requiring remediation before merge.
- Running the admit path with `overflow_policy: drop` and no alert on the drop metric is a
  deviation requiring ISSO acknowledgement (see [AU policy](AU-policy.md) §6).

## 8 References

- SI procedures: [../procedures/SI-procedures.md](../procedures/SI-procedures.md)
- Audit integrity: [`internal/audit/integrity.go`](../../../internal/audit/integrity.go)
- Audit logger: [`internal/audit/logger.go`](../../../internal/audit/logger.go)
- SIEM integration: [docs/security/siem-integration.md](../../security/siem-integration.md)
- Runtime detection: [docs/security/runtime-detection.md](../../security/runtime-detection.md)
- Continuous Monitoring Plan: [docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)
- Alert rules: `charts/kube-policies/files/alerts/security.yaml` · `availability.yaml` · `tls.yaml` · `capacity.yaml` · `dos.yaml` · `watchdog.yaml`
- Monitoring templates: `charts/kube-policies/templates/prometheusrule.yaml` · `charts/kube-policies/templates/servicemonitor.yaml` · `charts/kube-policies/templates/slo-prometheusrule.yaml`
- Supply-chain risk management: [../supply-chain-risk-management.md](../supply-chain-risk-management.md)
- SR policy: [SR-policy.md](SR-policy.md)
- AU policy (audit integrity / overflow): [AU-policy.md](AU-policy.md)
- RA policy (vulnerability scanning): [RA-policy.md](RA-policy.md)
- IR policy (CRD tampering / fail-open): [IR-policy.md](IR-policy.md)
- Vulnerability disclosure SLAs: [SECURITY.md](../../../SECURITY.md)
- CI workflow: `.github/workflows/ci.yml` (jobs: `security-scan`, `govulncheck`, `monitoring-rules`)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (SI-1, SI-2, SI-4, SI-7); FedRAMP Moderate baseline; FIPS-199.
