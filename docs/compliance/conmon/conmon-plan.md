---
title: "Continuous Monitoring (ConMon) Plan — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring"
controls: "CA-7, CA-7(1), CA-5, RA-5, SI-2, SI-4, AU-6"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "Authorizing Official (TBD — assign before assessment)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# Continuous Monitoring (ConMon) Plan — Kube-Policies (KP)

> P12-WU-06 · NIST SP 800-53 Rev 5: CA-7, CA-7(1), CA-5, RA-5, SI-2, SI-4, AU-6 · FedRAMP-Moderate ConMon
> Status: Draft · Last reviewed: 2026-06-02 · Next review: 2027-06-02
> Owner: ISSO (TBD — assign before assessment) · Approver: Authorizing Official (TBD — assign before assessment)

This is the **canonical** Continuous Monitoring (ConMon) plan for the Kube-Policies (KP)
system. It is the assessment-package home for the KP ConMon strategy and supersedes, as the
authoritative source, the earlier draft at
[docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md),
which now redirects here. It defines the continuous-monitoring strategy required by NIST
**CA-7 / CA-7(1)** and the FedRAMP-Moderate ConMon requirements: the monitored-signal
inventory, the review cadence and named owners, the path from a monitoring finding to a
POA&M entry, the monthly authenticated-scan and POA&M-update cadence, the significant-change
process, and the security-metrics review meeting.

Kube-Policies is an **honestly-scoped Proof-of-Concept being driven to FedRAMP-Moderate
readiness**. It is **not yet authorized** (**no ATO**), is not in production use, and has no
sustained operating history. Cadences in this plan are **design targets** to be staffed
before assessment; named owners are **role placeholders** (no individuals are designated
until **POAM-018** closes). The §8 "First ConMon cycle" record is an honest, single-cycle
initial entry — not a mature operating record.

## 1 Purpose and scope

Continuous monitoring provides ongoing visibility into the security posture of KP by
collecting, correlating, and reviewing:

- **Availability and latency metrics** (SLO burn rates, error budget)
- **Security-signal alerts** (fail-open events, audit drops, policy-update failures)
- **Audit log completeness** (PolicyDecision event stream, integrity hash chain)
- **Vulnerability and image scan results** (container image CVEs, Go dependency `govulncheck`)
- **Configuration drift** (Helm chart vs. cluster state, CRD schema drift)
- **POA&M aging** (open-weakness SLA tracking and remediation milestones)

Findings that cannot be resolved within their normal review cycle are escalated to a POA&M
entry (see §5). The CA control policy that governs this plan is
[CA-policy.md](../policies/CA-policy.md); the operational steps are in
[CA-procedures.md](../procedures/CA-procedures.md).

## 2 The live monitoring pipeline (P9)

The KP ConMon program is built on the **single-source alerting and SIEM pipeline delivered
in P9**. ConMon does not re-define alerts; it consumes the rules that ship with the chart.

- **Alert definitions (single source of truth).** All Prometheus alert rules are authored
  under `charts/kube-policies/files/alerts/*.yaml`
  ([availability.yaml](../../../charts/kube-policies/files/alerts/availability.yaml),
  [security.yaml](../../../charts/kube-policies/files/alerts/security.yaml),
  [tls.yaml](../../../charts/kube-policies/files/alerts/tls.yaml),
  [capacity.yaml](../../../charts/kube-policies/files/alerts/capacity.yaml),
  [dos.yaml](../../../charts/kube-policies/files/alerts/dos.yaml),
  [watchdog.yaml](../../../charts/kube-policies/files/alerts/watchdog.yaml)).
- **SLO objectives and burn-rate rules.** Authored under
  [charts/kube-policies/files/slo/slo.yaml](../../../charts/kube-policies/files/slo/slo.yaml)
  and documented in [docs/observability/slo.md](../../observability/slo.md). These render
  the `KubePoliciesErrorBudgetBurnFast` / `KubePoliciesErrorBudgetBurnSlow` /
  `KubePoliciesLatencySLOBreach` alerts and the
  `kube_policies:admission_error_ratio:rate` recording rule.
- **Collection and routing.** Prometheus scrapes KP metrics via the chart ServiceMonitor;
  the chart PrometheusRule renders the alert/SLO files; Alertmanager performs
  severity-routed delivery (PagerDuty for critical, Slack for warning) with a dead-man's
  switch consuming the always-firing `KubePoliciesWatchdog` heartbeat.
- **SIEM forwarding.** Audit `PolicyDecision` events are shipped off-cluster by the opt-in
  Fluent Bit forwarder over TLS, as described in
  [docs/security/siem-integration.md](../../security/siem-integration.md). Runtime anomaly
  detection (Falco, NetworkPolicy) is in
  [docs/security/runtime-detection.md](../../security/runtime-detection.md).

A concise cadence-only view of the signals below is maintained in
[cadence.md](cadence.md).

## 3 Monitored signals inventory

The tables below are the authoritative inventory of all monitored signals, each with its
collection mechanism, review cadence, and reviewer. "Automated" means the signal fires an
alert or generates a CI report without manual action; "Manual" means a human reviews the
data on the stated cadence.

### 3.1 Metrics and alerting

| Signal | Collection mechanism | Alert | Cadence | Reviewer |
|---|---|---|---|---|
| Availability SLI (error ratio) | Prometheus scrape of `kube_policies_admission_requests_total` | `KubePoliciesErrorBudgetBurnFast` (critical), `KubePoliciesErrorBudgetBurnSlow` (warning) | Automated real-time; **monthly** manual SLO review | Operator / SRE (alert); ISSO (monthly) |
| Latency SLI (p95 evaluation duration) | `kube_policies_admission_evaluation_duration_seconds_bucket` | `KubePoliciesLatencySLOBreach` (warning) | Automated real-time; monthly | Operator / SRE |
| Admission webhook availability | `up{job="kube-policies-admission-webhook"}` | `KubePoliciesDown` (critical) | Automated real-time | Primary on-call |
| Policy-manager availability | `up{job="kube-policies-policy-manager"}` | `KubePoliciesPolicyManagerDown` (critical) | Automated real-time | Primary on-call |
| Fail-open events | `kube_policies_admission_fail_open_total` | `KubePoliciesFailOpenActive` (critical) | Automated real-time (any increment) | Primary on-call → ISSO within 15 min |
| Audit events dropped | `kube_policies_audit_events_total{status="dropped"}` | `KubePoliciesAuditEventsDropped` (critical) | Automated real-time | Primary on-call |
| Audit write errors | `kube_policies_audit_events_total{status="write_error"}` | `KubePoliciesAuditWriteErrors` (critical) | Automated real-time | Primary on-call |
| Audit buffer saturation | `kube_policies_audit_buffer_size` > 800 | `KubePoliciesAuditBufferSaturated` (warning) | Automated real-time | Operator / SRE |
| TLS certificate expiry | `kube_policies_tls_cert_expiry_seconds` | `KubePoliciesCertExpiringSoon` (30d warn), `KubePoliciesCertExpiringCritical` (7d crit), `KubePoliciesCertExpired` (crit) | Automated real-time | Operator (warn); Primary on-call (critical) |
| Replica shortfall | `kube_deployment_status_replicas_available` vs. desired | `KubePoliciesReplicaShortfall` (warning) | Automated real-time | Operator / SRE |
| PDB headroom | `kube_poddisruptionbudget_status_pod_disruptions_allowed` | `KubePoliciesPodDisruptionBudgetAtLimit` (warning) | Automated real-time | Operator / SRE |
| Policy update failures | `kube_policies_policy_updates_total{status="error"}` | `KubePoliciesPolicyUpdateFailures` (warning) | Automated real-time | Operator / SRE |
| Exception suppression spike | `kube_policies_policy_exception_suppressions_total` | `KubePoliciesExceptionSuppressionSpike` (warning) | Automated real-time | Operator / SRE |
| Monitoring heartbeat | `KubePoliciesWatchdog` (always-firing) | Absence pages via dead-man's-switch | Automated continuous | External watchdog (Dead Man's Snitch / healthchecks.io) |
| No-traffic watchdog | `absent(rate(kube_policies_admission_requests_total[10m]))` | `KubePoliciesNoTraffic` (warning) | Automated real-time | Operator / SRE |
| Error budget status | SLO burn-rate recording rules | Burn alerts above | **Monthly** manual review against 30-day window | ISSO |
| Backup staleness | `kube_cronjob_status_last_successful_time{cronjob=~".*backup.*"}` | `KubePoliciesBackupStale` (RES-WU-11, P9) | Automated real-time | Operator / SRE |

Alert definitions are the single source of truth at
`charts/kube-policies/files/alerts/*.yaml`. SLO objectives and burn-rate math are
documented in [docs/observability/slo.md](../../observability/slo.md).

### 3.2 Audit log completeness

| Signal | Collection mechanism | Cadence | Reviewer |
|---|---|---|---|
| Audit event stream (PolicyDecision) | Fluent Bit forwarder → SIEM (`audit.forwarder.enabled: true`) | Continuous (automated); **daily** gap check in SIEM | Operator / SRE |
| Tamper-evident hash chain | `integrity_hash` field in each JSON-lines record | **Weekly** integrity verification (`VerifyChainFiles`, or automated SIEM query) | ISSO |
| Audit log retention | SIEM index age vs. required retention period (AU-11) | **Monthly** | ISSO |
| SIEM forwarding health | Forwarder Fluent Bit metrics + `kube_policies_audit_events_total` | Automated (via alerts); **weekly** forwarder log review | Operator / SRE |

SIEM integration details: [docs/security/siem-integration.md](../../security/siem-integration.md).

### 3.3 Vulnerability and image scans

| Signal | Collection mechanism | Cadence | Reviewer |
|---|---|---|---|
| Container image CVEs | Trivy image scans (build-from-HEAD) in CI | Every PR + **monthly** scheduled scan (`monthly-vuln-scan.yml`) | Operator / SRE; ISSO (monthly) |
| Go dependency vulnerabilities | `govulncheck ./...` in CI (`govulncheck` job, pinned `v1.3.0`) | Every PR + **monthly** | Operator / SRE; ISSO (monthly) |
| Filesystem / config CVEs | Trivy filesystem scan → GitHub Security tab (SARIF) | Every PR + **monthly** | ISSO |
| Image signature verification | Cosign verify at admission (P6, `imageVerification.enabled`) | Continuous at admission | Automated |
| SBOM freshness | CI SBOM attestation (P6) | Every release | Maintainer |

The monthly scheduled scan is automated by
[.github/workflows/monthly-vuln-scan.yml](../../../.github/workflows/monthly-vuln-scan.yml)
(VUL-WU-15; NIST RA-5, RA-5(2), RA-5(5), CA-7). It runs on the 1st of each month at 06:00
UTC (and on manual dispatch), produces a dated consolidated report artifact
(`vuln-report-<YYYY-MM-DD>.md` + `all-vulns.csv` + Trivy/govulncheck outputs, 90-day
retention), and opens or updates a single tracking GitHub Issue with findings grouped by
severity and the FedRAMP SLA due-dates (Critical/High +30d, Moderate +90d, Low +180d).

**Authenticated scanning is the target.** FedRAMP-Moderate ConMon requires monthly
**authenticated/credentialed** vulnerability scanning of the operating environment. The
current automated scans in `monthly-vuln-scan.yml` are **build-artifact and dependency
scans** (Trivy filesystem + image, `govulncheck`) of the source and the images built from
HEAD — they are not authenticated scans of a deployed cluster. Standing up authenticated
host/cluster scanning against a live deployment is **PENDING** for full ConMon operation and
is tracked under **POAM-025 (RA-5)** / **POAM-026 (SI-2)**.

### 3.4 Configuration drift

| Signal | Collection mechanism | Cadence | Reviewer |
|---|---|---|---|
| Helm chart vs. cluster state | `helm diff` or GitOps reconciler (ArgoCD/Flux) | **Daily** (automated reconciler) or **weekly** manual diff | Operator / SRE |
| CRD schema drift | `kubectl diff` of installed CRDs vs. chart CRDs | **Weekly** | Operator / SRE |
| PSS / restricted-PSS compliance | `conftest` restricted-PSS OPA policy in CI (P5) | Every PR | Automated |
| RBAC least-privilege drift | `conftest` RBAC policy in CI | Every PR | Automated |
| CIS benchmark | `kube-bench` or equivalent | **Monthly** | ISSO |

## 4 Review cadence summary

The full cadence reference (signal → owner → tool/artifact) is maintained separately in
[cadence.md](cadence.md). The tier summary is:

| Cadence | Activities |
|---|---|
| **Continuous / real-time** | All Prometheus alerts via Alertmanager → PagerDuty (critical) / Slack (warning). Monitoring heartbeat via dead-man's-switch. Cosign verify at admission. |
| **Daily** | SIEM gap check for audit event stream continuity. Automated drift reconciler (if GitOps is active). |
| **Weekly** | Forwarder log review. Audit hash-chain integrity verification. Helm/CRD drift diff. POA&M aging report (`poam-aging.yml`, Monday 07:00 UTC). |
| **Monthly** | Authenticated vulnerability scan + result review (`monthly-vuln-scan.yml`, 1st 06:00 UTC). POA&M update/triage. SLO error-budget review (30-day window) at the security-metrics meeting. Audit log retention check. CIS benchmark run. ISSO ConMon report to AO. |
| **Annually** | Full control assessment review. POA&M re-baseline. SLO target review. This plan reviewed and updated. |

### 4.1 Monthly POA&M update cadence

The POA&M ([POAM.md](../POAM.md) / [poam.csv](../poam.csv)) is reviewed and updated on a
**monthly** cadence, combining automation and manual triage:

1. **Automated aging (weekly input).**
   [.github/workflows/poam-aging.yml](../../../.github/workflows/poam-aging.yml)
   (VUL-WU-17 / VUL-WU-18; NIST CA-5, PM-4, RA-5, SI-2, SI-4) runs every Monday at 07:00
   UTC, enumerates open `vuln`-labelled GitHub Issues, computes age versus the SLA due-date,
   writes a dated aging-report artifact (`poam-aging-<YYYY-MM-DD>.md`, 365-day retention),
   and posts a Slack alert when any item is past its SLA (guarded by `SLACK_WEBHOOK`).
2. **Manual triage (monthly).** The ISSO reviews the latest aging report and the monthly
   vulnerability-scan issue, re-ranks severity/risk, advances milestones, escalates slipped
   `scheduled_completion` dates, and reconciles the Markdown register with the authoritative
   `poam.csv` (the CSV governs on disagreement).
3. **Reporting.** The ISSO includes a POA&M status summary in the monthly ConMon report to
   the AO; new Critical/High findings are reported to the AO within 24 hours of opening the
   entry.

The "from finding to POA&M" mechanics are in §5; the POA&M maintenance discipline is in
[POAM.md](../POAM.md) ("How to maintain this POA&M").

### 4.2 Significant-change process

A **significant change** re-triggers assessment and may require ConMon re-baselining and AO
reauthorization. Per [CA-policy.md §5.2](../policies/CA-policy.md) and
[CA-procedures.md §3.3](../procedures/CA-procedures.md), a significant change includes any
of:

- A change to the authorization boundary, system architecture, or FIPS-199 security
  categorization.
- A major control-implementation change not covered by the existing continuous-monitoring
  baseline (for example, adding a new monitored signal, renaming a metric, or changing the
  alert/SLO source files under `charts/kube-policies/files/`).
- An interconnection added or removed (ICX-01 through ICX-06).
- A change to the SIEM destination, audit schema, or forwarder configuration.
- A security incident assessed as impacting the authorization basis.

Process: the maintainer flags the change to the ISSO; the ISSO assesses ConMon impact,
updates this plan and [cadence.md](cadence.md) (recording the change in the front-matter
dates/version), and notifies the AO within **5 business days**. If the AO requires it, a
reauthorization assessment is initiated. Adding or changing a monitored signal also triggers
a review of this plan per §7.

### 4.3 Security-metrics review meeting

A monthly **security-metrics review meeting** is the manual control point that complements
the automated alerting. Standing agenda:

| Item | Source | Owner |
|---|---|---|
| SLO error-budget burn (30-day window) | [docs/observability/slo.md](../../observability/slo.md); SLO recording rules from `slo.yaml` | ISSO |
| Open alert review / alert fatigue | Alertmanager history; `charts/kube-policies/files/alerts/*.yaml` | Operator / SRE |
| Vulnerability-scan findings | Monthly scan issue (`monthly-vuln-scan.yml`) + GitHub Security tab | ISSO |
| POA&M aging and SLA breaches | Weekly aging report (`poam-aging.yml`) + [POAM.md](../POAM.md) | ISSO |
| Audit-pipeline health and retention | `kube_policies_audit_events_total`; SIEM index age | Operator / SRE; ISSO |
| Configuration / CIS drift | `helm diff`; `kube-bench` | Operator / SRE; ISSO |
| Decisions and ConMon report to AO | This meeting's record | ISSO → System Owner / AO |

**Owners.** Meeting chaired by the **ISSO**; **Operator / SRE** presents the operational
signals; the **System Owner** receives the outcome and resources remediation; the **AO**
receives the resulting monthly ConMon report. All four are role placeholders pending
**POAM-018**.

## 5 From finding to POA&M

Any monitoring finding that cannot be fully remediated within its normal review cycle is
escalated to a POA&M entry:

1. **Detection.** Alert fires, scheduled review identifies a gap, or a scan produces a
   finding that is not immediately patched.
2. **Triage.** The on-call operator classifies the finding by severity (SEV1–SEV4) using the
   criteria in [docs/security/on-call-escalation.md](../../security/on-call-escalation.md).
   Critical findings are escalated to the ISSO within 1 hour.
3. **Incident handling.** If the finding is an active incident, follow
   [docs/security/incident-response-plan.md](../../security/incident-response-plan.md).
4. **POA&M entry.** If the finding is a weakness that cannot be remediated immediately, the
   ISSO opens a new row in [docs/compliance/POAM.md](../POAM.md) / [poam.csv](../poam.csv)
   with `poam_id` (next sequential `POAM-NNN`), `control_id` (primary NIST 800-53r5 control),
   `severity` and `risk_rating`, `weakness_description`, `remediation` (planned fix and
   phase), and `scheduled_completion` (target date).
5. **Tracking.** Open POA&M entries are reviewed monthly (§4.1). The weekly aging workflow
   (`poam-aging.yml`) tracks SLA compliance; closed entries are updated with the close date
   and evidence artifact.
6. **AO reporting.** The ISSO includes a POA&M status summary in the monthly ConMon report
   to the AO. Any new Critical or High finding is reported to the AO within 24 hours of
   opening the entry.

## 6 Roles and responsibilities

| Role | Holder | ConMon responsibility |
|---|---|---|
| ISSO | TBD — assign before assessment | Owns this plan; chairs the monthly security-metrics meeting; reviews monthly ConMon data; reports to AO; opens and maintains POA&M entries; triggers annual plan review and significant-change assessment. |
| System Owner | TBD — assign before assessment | Approves this plan; allocates resources for remediation; makes AO notifications for significant findings. |
| Operator / SRE | TBD — assign before assessment | Responds to real-time alerts; performs weekly and daily checks; presents operational signals at the metrics meeting; escalates to ISSO per the escalation matrix. |
| Authorizing Official (AO) | TBD — assign before assessment | Receives monthly ConMon report; approves continued authorization; notified of Critical/High findings within 24 hours; renders reauthorization decision on significant change. |

Named ATO roles are not yet staffed; all holders are **role placeholders** until **POAM-018**
closes. All `@kube-policies.io` contacts referenced operationally are **placeholders**.

## 7 Annual review

This plan is reviewed at least **annually** (next review: **2027-06-02**) and whenever a
new monitoring signal is added, a metric name changes, the ConMon cadence is adjusted, or a
significant change (§4.2) occurs. Reviews are recorded by updating the front-matter dates and
version, and by updating the companion [cadence.md](cadence.md).

## 8 First ConMon cycle (initial record)

> **Honest scope.** This is the **initial** ConMon cycle for a **pre-authorization PoC**. It
> is a single, first-of-program record — **not** a mature operating history, and **not**
> evidence of a sustained monthly cadence. Subsequent cycles will accrue as the program is
> staffed and the system is deployed.

**Cycle date:** 2026-06-02 · **Recorded by:** ISSO (TBD — placeholder) · **Cycle type:**
Initial / first-cycle (pre-ATO).

**Reviewed in this cycle (evidence available at the recorded date):**

- **Vulnerability posture.** Reviewed the CI `security-scan` (Trivy filesystem + image) and
  `govulncheck` job results from `.github/workflows/ci.yml`, plus the
  [monthly-vuln-scan.yml](../../../.github/workflows/monthly-vuln-scan.yml) workflow
  definition and its report/issue mechanics. Following the P11 toolchain pin
  (`toolchain go1.25.10`), `govulncheck` reports **0 reachable** stdlib CVEs (down from the
  ~26 previously attributable to the `go 1.25.0` pin). RA-5/SI-2 gaps remain tracked under
  **POAM-025 / POAM-026**.
- **POA&M aging.** Reviewed the [poam-aging.yml](../../../.github/workflows/poam-aging.yml)
  workflow and the current [POAM.md](../POAM.md) register. Per its
  [Severity rollup](../POAM.md#severity-rollup-current), the register holds **55 open items
  (9 Critical, 18 High, 24 Moderate, 4 Low)** plus 2 closed (POAM-024, POAM-049) — 57 total.
  No live `vuln`-labelled issues have aged yet — the automated aging report has no production
  history at this date.
- **SLO / error-budget review.** Reviewed the SLO objectives and burn-rate rules in
  [docs/observability/slo.md](../../observability/slo.md) and
  [slo.yaml](../../../charts/kube-policies/files/slo/slo.yaml). No live burn data exists (no
  deployed cluster); the review confirmed the rules and alerts are wired and the metrics
  meeting agenda (§4.3) is defined.
- **Alerting / SIEM pipeline.** Confirmed the P9 single-source alert files
  (`charts/kube-policies/files/alerts/*.yaml`) and the SIEM forwarding path in
  [docs/security/siem-integration.md](../../security/siem-integration.md) are present and
  consumed by this plan (§2).

**Explicitly PENDING for full ConMon operation:**

- **Real authenticated scans.** Monthly authenticated/credentialed vulnerability scanning of
  a live, deployed cluster (not just build-artifact + dependency scans of source/images).
  Tracked under **POAM-025 (RA-5)** / **POAM-026 (SI-2)**.
- **AO monthly report.** A real monthly ConMon report delivered to a designated Authorizing
  Official. Blocked on role assignment (**POAM-018, PS-2**).
- **Sustained cadence.** A demonstrated, multi-month operating history of the monthly scan,
  monthly POA&M triage, and monthly security-metrics meeting against a live deployment.
- **Live pipeline proof.** Prometheus/Alertmanager firing on real traffic, SIEM receiving
  real `PolicyDecision` events, and the dead-man's-switch exercised — none of which can be
  demonstrated without a deployed cluster and an ATO.

Until these PENDING items close, KP has **no ATO** and this ConMon program is in a
**pre-operational** state. ConMon go-live is a P12 deliverable (see
[remediation-roadmap.md](../plans/remediation-roadmap.md), P12) and is gated on the AO
authorization decision.

## 9 References

- Canonical pointer (legacy path): [docs/security/continuous-monitoring-plan.md](../../security/continuous-monitoring-plan.md)
- Cadence reference: [cadence.md](cadence.md)
- SLO and burn-rate alerts: [docs/observability/slo.md](../../observability/slo.md)
- Alert definitions (single source): `charts/kube-policies/files/alerts/*.yaml`
- SLO source: [charts/kube-policies/files/slo/slo.yaml](../../../charts/kube-policies/files/slo/slo.yaml)
- SIEM integration: [docs/security/siem-integration.md](../../security/siem-integration.md)
- Incident response plan: [docs/security/incident-response-plan.md](../../security/incident-response-plan.md)
- On-call escalation matrix: [docs/security/on-call-escalation.md](../../security/on-call-escalation.md)
- Runtime detection: [docs/security/runtime-detection.md](../../security/runtime-detection.md)
- Monthly vulnerability scan: [.github/workflows/monthly-vuln-scan.yml](../../../.github/workflows/monthly-vuln-scan.yml)
- POA&M aging: [.github/workflows/poam-aging.yml](../../../.github/workflows/poam-aging.yml)
- CI workflow: [.github/workflows/ci.yml](../../../.github/workflows/ci.yml)
- POA&M: [docs/compliance/POAM.md](../POAM.md) · [poam.csv](../poam.csv)
- CA policy: [docs/compliance/policies/CA-policy.md](../policies/CA-policy.md)
- CA procedures: [docs/compliance/procedures/CA-procedures.md](../procedures/CA-procedures.md)
- Remediation roadmap: [docs/compliance/plans/remediation-roadmap.md](../plans/remediation-roadmap.md)
- Control matrix: [docs/compliance/control-matrix.csv](../control-matrix.csv)
- SSP: [docs/compliance/ssp/SSP.md](../ssp/SSP.md)
- NIST SP 800-53 Rev 5: CA-7, CA-7(1), CA-5, RA-5, SI-2, SI-4, AU-6; FedRAMP-Moderate ConMon requirements.
