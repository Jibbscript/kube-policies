---
title: "Continuous Monitoring Plan — Kube-Policies (KP)"
controls: "CA-7, CA-7(1)"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "Authorizing Official (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Continuous Monitoring Plan — Kube-Policies (KP)

> IRM-WU-19 · NIST SP 800-53 Rev 5: CA-7, CA-7(1) · FedRAMP ConMon
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: ISSO (TBD — assign before assessment) · Approver: Authorizing Official (TBD — assign before assessment)

This plan defines the continuous monitoring strategy for Kube-Policies (KP). It inventories
every monitored signal, maps each to a review cadence and a responsible reviewer, and
establishes the path from a monitoring finding to a POA&M entry. It is the operational
implementation of NIST CA-7 and the FedRAMP ConMon requirements for the KP system.

This is a Proof-of-Concept being driven to FedRAMP-Moderate readiness; it is **not yet
authorized** (**no ATO**) and not in production use. Cadences are design targets to be
staffed before assessment.

## 1 Purpose and scope

Continuous monitoring provides ongoing visibility into the security posture of KP by
collecting, correlating, and reviewing:

- **Availability and latency metrics** (SLO burn rates, error budget)
- **Security-signal alerts** (fail-open events, audit drops, policy-update failures)
- **Audit log completeness** (PolicyDecision event stream, integrity hash chain)
- **Vulnerability and image scan results** (container image CVEs, dependency govulncheck)
- **Configuration drift** (Helm chart vs. cluster state, CRD schema drift)

Findings that cannot be resolved within the review cycle are escalated to a POA&M entry
(see §4).

## 2 Monitored signals inventory

The table below is the authoritative inventory of all monitored signals, each with its
collection mechanism, review cadence, and reviewer. "Automated" means the signal fires an
alert or generates a CI report without manual action; "Manual" means a human reviews the
data on the stated cadence.

### 2.1 Metrics and alerting

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
documented in [docs/observability/slo.md](../observability/slo.md).

### 2.2 Audit log completeness

| Signal | Collection mechanism | Cadence | Reviewer |
|---|---|---|---|
| Audit event stream (PolicyDecision) | Fluent Bit forwarder → SIEM (`audit.forwarder.enabled: true`) | Continuous (automated); **daily** gap check in SIEM | Operator / SRE |
| Tamper-evident hash chain | `integrity_hash` field in each JSON-lines record | **Weekly** integrity verification (or automated SIEM query) | ISSO |
| Audit log retention | SIEM index age vs. required retention period (AU-11) | **Monthly** | ISSO |
| SIEM forwarding health | Forwarder Fluent Bit metrics + `kube_policies_audit_events_total` | Automated (via alerts); **weekly** forwarder log review | Operator / SRE |

SIEM integration details: [docs/security/siem-integration.md](siem-integration.md).

### 2.3 Vulnerability and image scans

| Signal | Collection mechanism | Cadence | Reviewer |
|---|---|---|---|
| Container image CVEs | Trivy / Grype in CI (supply-chain gate, P6) | Every PR + **weekly** scheduled scan | Operator / SRE |
| Go dependency vulnerabilities | `govulncheck ./...` in CI | Every PR + **weekly** | Operator / SRE |
| Image signature verification | Cosign verify at admission (P6, `imageVerification.enabled`) | Continuous at admission | Automated |
| SBOM freshness | CI SBOM attestation (P6) | Every release | Maintainer |

**Note.** `govulncheck` currently flags approximately 26 stdlib CVEs attributable to
`go 1.25.0` pinning in `go.mod` (fixes in 1.25.2). This is a tracked gap in the
[POA&M](../compliance/POAM.md).

### 2.4 Configuration drift

| Signal | Collection mechanism | Cadence | Reviewer |
|---|---|---|---|
| Helm chart vs. cluster state | `helm diff` or GitOps reconciler (ArgoCD/Flux) | **Daily** (automated reconciler) or **weekly** manual diff | Operator / SRE |
| CRD schema drift | `kubectl diff` of installed CRDs vs. chart CRDs | **Weekly** | Operator / SRE |
| PSS / restricted-PSS compliance | `conftest` restricted-PSS OPA policy in CI (P5) | Every PR | Automated |
| RBAC least-privilege drift | `conftest` RBAC policy in CI | Every PR | Automated |
| CIS benchmark | `kube-bench` or equivalent | **Monthly** | ISSO |

## 3 Review cadence summary

| Cadence | Activities |
|---|---|
| **Continuous / real-time** | All Prometheus alerts via Alertmanager → PagerDuty (critical) / Slack (warning). Monitoring heartbeat via dead-man's-switch. |
| **Daily** | SIEM gap check for audit event stream continuity. Automated drift reconciler (if GitOps is active). |
| **Weekly** | Forwarder log review. Audit hash-chain integrity verification. Helm/CRD drift diff. Image/dep vulnerability scan review. |
| **Monthly** | SLO error-budget review (30-day window). Audit log retention check. CIS benchmark run. ISSO ConMon report to AO. |
| **Annually** | Full control assessment review. POA&M milestone review. SLO target review. This plan reviewed and updated. |

## 4 From finding to POA&M

Any monitoring finding that cannot be fully remediated within its normal review cycle is
escalated to a POA&M entry:

1. **Detection.** Alert fires, scheduled review identifies a gap, or a scan produces a
   finding that is not immediately patched.
2. **Triage.** The on-call operator classifies the finding by severity (SEV1–SEV4) using the
   criteria in [docs/security/on-call-escalation.md](on-call-escalation.md). Critical
   findings are escalated to the ISSO within 1 hour.
3. **Incident handling.** If the finding is an active incident, follow
   [docs/security/incident-response-plan.md](incident-response-plan.md).
4. **POA&M entry.** If the finding is a weakness that cannot be remediated immediately, the
   ISSO opens a new row in [docs/compliance/POAM.md](../compliance/POAM.md) with:
   - `poam_id` (next sequential `POAM-NNN`),
   - `control_id` (primary NIST 800-53r5 control),
   - `severity` and `risk_rating`,
   - `weakness_description` (what was found and how),
   - `remediation` (planned fix and phase),
   - `scheduled_completion` (target date).
5. **Tracking.** Open POA&M entries are reviewed monthly in the ConMon report. Closed
   entries are updated with the close date and evidence artifact.
6. **AO reporting.** The ISSO includes a POA&M status summary in the monthly ConMon report
   to the AO. Any new Critical or High finding is reported to the AO within 24 hours of
   opening the entry.

## 5 Roles and responsibilities

| Role | Holder | ConMon responsibility |
|---|---|---|
| ISSO | TBD — assign before assessment | Owns this plan; reviews monthly ConMon data; reports to AO; opens and maintains POA&M entries; triggers annual plan review. |
| System Owner | TBD — assign before assessment | Approves this plan; allocates resources for remediation; makes AO notifications for significant findings. |
| Operator / SRE | TBD — assign before assessment | Responds to real-time alerts; performs weekly and daily checks; escalates to ISSO per the escalation matrix. |
| Authorizing Official (AO) | TBD — assign before assessment | Receives monthly ConMon report; approves continued authorization; notified of Critical/High findings within 24 hours. |

## 6 Annual review

This plan is reviewed at least **annually** (next review: **2027-06-01**) and whenever a
new monitoring signal is added, a metric name changes, or the ConMon cadence is adjusted.
Reviews are recorded by updating the front-matter dates and version.

## 7 References

- SLO and burn-rate alerts: [docs/observability/slo.md](../observability/slo.md)
- Alert definitions (single source): `charts/kube-policies/files/alerts/*.yaml`
- SIEM integration: [docs/security/siem-integration.md](siem-integration.md)
- Incident response plan: [docs/security/incident-response-plan.md](incident-response-plan.md)
- On-call escalation matrix: [docs/security/on-call-escalation.md](on-call-escalation.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- Runtime detection: [docs/security/runtime-detection.md](runtime-detection.md)
- Metrics source: `internal/metrics/collector.go`
- NIST SP 800-53 Rev 5: CA-7, CA-7(1); FedRAMP Moderate ConMon requirements.
