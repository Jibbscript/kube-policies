---
title: "Service Level Objectives — Kube-Policies (KP)"
controls: "CA-7, SI-4"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign before assessment)"
approver: "Authorizing Official (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Service Level Objectives — Kube-Policies (KP)

> IRM-WU-18 · NIST SP 800-53 Rev 5: CA-7, SI-4 · FedRAMP ConMon
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: System Owner (TBD — assign before assessment) · Approver: Authorizing Official (TBD — assign before assessment)

This document defines the **Service Level Indicators (SLIs)**, **Service Level Objectives
(SLOs)**, and **error budget policy** for Kube-Policies. These commitments are the formal
observability contract for FedRAMP Continuous Monitoring (ConMon) and the basis for
determining when an incident must be declared and escalated (see
[docs/security/incident-response-plan.md](../security/incident-response-plan.md)).

The **machine-readable implementation** — PrometheusRule recording rules and burn-rate
alerts, tested with `promtool` in CI — is the single source of truth at
[charts/kube-policies/files/slo/slo.yaml](../../charts/kube-policies/files/slo/slo.yaml).
This document is the human-readable specification and rationale behind that file.

## 1 SLI definitions

An SLI is the measured ratio that tells us how well the system is serving its users.

### 1.1 Availability SLI

**What we measure.** The fraction of admission requests that complete without a server-side
error, computed over a rolling window.

```
availability_SLI = 1 - (
  sum(rate(kube_policies_admission_requests_total{status="error"}[window]))
  /
  sum(rate(kube_policies_admission_requests_total[window]))
)
```

**Good event.** An admission request that returns a non-error response (allowed or denied
by policy — both are correct outcomes; a policy deny is not an error).

**Bad event.** An admission request that the webhook fails to evaluate and returns an
internal server error, or that the webhook drops.

**Counters.** Both series are emitted by `internal/metrics/collector.go` (namespace
`kube_policies`, subsystem `admission`). Recording rules at four windows (5 m, 30 m, 1 h,
6 h) are defined in
[charts/kube-policies/files/slo/slo.yaml](../../charts/kube-policies/files/slo/slo.yaml).

### 1.2 Latency SLI

**What we measure.** The 95th-percentile (p95) admission-evaluation duration — the time
from when the webhook receives an `AdmissionReview` to when policy evaluation completes and
a response is returned.

```
latency_SLI = histogram_quantile(
  0.95,
  sum by (le) (rate(kube_policies_admission_evaluation_duration_seconds_bucket[window]))
)
```

**Counter.** `kube_policies_admission_evaluation_duration_seconds_bucket` (histogram),
emitted by `internal/metrics/collector.go`.

## 2 SLO targets

| SLO | Objective | Window | Error budget |
|---|---|---|---|
| **Availability** | **99.9 %** of admission requests succeed (non-error) | **30 days** | **0.1 %** ≈ 43.2 minutes of allowed errors per 30-day window |
| **Latency** | p95 admission evaluation **< 0.5 s** | 30 minutes (rolling alert window) | Breach → `warning` alert; no explicit budget consumed |

These numbers are the authoritative, code-level values from
[charts/kube-policies/files/slo/slo.yaml](../../charts/kube-policies/files/slo/slo.yaml).
Do not change them without updating that file and re-running `make validate-monitoring-rules`.

## 3 Multi-window burn-rate alerting

Kube-Policies uses the **Google SRE Workbook multi-window, multi-burn-rate** method. The
key insight is that a single threshold on a single window is either too slow to page (misses
a short severe spike) or too noisy (pages on transient blips). Two windows are evaluated
simultaneously: a **long window** detects sustained burns; a **short window** confirms the
burn is still active right now (not a historical artifact).

### 3.1 Burn-rate math

| Burn rate | Meaning |
|---|---|
| 1× | Error budget consumed at exactly the rate that exhausts it in 30 days |
| 14.4× | Budget exhausted in ~2 days (30 days ÷ 14.4) |
| 6× | Budget exhausted in ~5 days (30 days ÷ 6) |

**Error ratio thresholds** (error budget = 0.1 % = 0.001):

| Alert | Burn rate | Threshold ratio |
|---|---|---|
| Fast burn (critical) | 14.4× | 0.001 × 14.4 = **0.0144** |
| Slow burn (warning) | 6× | 0.001 × 6 = **0.006** |

### 3.2 Availability burn alerts

Both alerts are defined in
[charts/kube-policies/files/slo/slo.yaml](../../charts/kube-policies/files/slo/slo.yaml).

#### KubePoliciesErrorBudgetBurnFast (critical)

```
kube_policies:admission_error_ratio:rate1h > (14.4 × 0.001)
  AND
kube_policies:admission_error_ratio:rate5m > (14.4 × 0.001)
```

- **Severity:** `critical` → pages on-call immediately (see
  [docs/security/on-call-escalation.md](../security/on-call-escalation.md)).
- **Windows:** 1 h (long) and 5 m (short). Both must be above threshold simultaneously.
- **Meaning:** The 30-day error budget will be exhausted in approximately 2 days at the
  current error rate. This is a SEV1 event.
- **`for` duration:** 2 minutes (suppresses sub-minute transients).

#### KubePoliciesErrorBudgetBurnSlow (warning)

```
kube_policies:admission_error_ratio:rate6h > (6 × 0.001)
  AND
kube_policies:admission_error_ratio:rate30m > (6 × 0.001)
```

- **Severity:** `warning` → routes to the chat/ticket receiver.
- **Windows:** 6 h (long) and 30 m (short).
- **Meaning:** The error budget is draining at 6× — budget exhausted in ~5 days. Investigate
  and remediate before escalating to a page.
- **`for` duration:** 15 minutes.

### 3.3 Latency SLO alert

#### KubePoliciesLatencySLOBreach (warning)

```
histogram_quantile(0.95,
  sum by (le) (rate(kube_policies_admission_evaluation_duration_seconds_bucket[30m]))
) > 0.5
```

- **Severity:** `warning`.
- **Meaning:** p95 admission evaluation latency exceeds 0.5 s over the last 30 minutes,
  breaching the latency SLO. Sustained latency risks apiserver webhook timeouts.
- **`for` duration:** 15 minutes.

## 4 Error budget policy

The error budget is a shared resource. The following rules govern its use.

| Budget remaining | Action |
|---|---|
| > 50 % | Normal operations; deployments and experiments are unrestricted. |
| 25–50 % | Slow down risky changes; require a second approver for Helm upgrades that touch the webhook path. |
| < 25 % | Freeze non-emergency changes; ISSO reviews all deployments; open a POA&M entry if the shortfall is not attributed to a known maintenance window. |
| 0 % (exhausted) | Declare a SEV1 incident (see [incident-response-plan.md](../security/incident-response-plan.md)); AO notification required for FedRAMP ConMon; post-incident review mandatory. |

**Budget accounting period.** 30 calendar days, rolling. Budget resets continuously —
there is no fixed monthly boundary.

**Attribution.** Planned maintenance that will burn error budget must be pre-approved by
the ISSO and documented as a deviation in the [POA&M](../compliance/POAM.md).

## 5 Continuous monitoring integration

SLO burn-rate alerts feed directly into FedRAMP Continuous Monitoring (CA-7) reporting:

- `KubePoliciesErrorBudgetBurnFast` firing → ConMom status: **At Risk**; notify AO within
  24 hours.
- `KubePoliciesErrorBudgetBurnSlow` firing → ConMon status: **Elevated**; investigate and
  report in next monthly ConMon report.
- Budget exhausted → mandatory AO notification and POA&M update.

Monthly ConMon cadence and responsible reviewer are defined in
[docs/security/continuous-monitoring-plan.md](../security/continuous-monitoring-plan.md).

## 6 Annual review

This document is reviewed at least **annually** (next review: **2027-06-01**) and whenever
the numeric objectives, alert thresholds, or the machine-readable SLO file change.
Reviews are recorded by updating the front-matter dates.

## 7 References

- Machine-readable SLO / burn-rate alerts: [charts/kube-policies/files/slo/slo.yaml](../../charts/kube-policies/files/slo/slo.yaml)
- Availability alerts: [charts/kube-policies/files/alerts/availability.yaml](../../charts/kube-policies/files/alerts/availability.yaml)
- Continuous monitoring plan: [docs/security/continuous-monitoring-plan.md](../security/continuous-monitoring-plan.md)
- On-call escalation: [docs/security/on-call-escalation.md](../security/on-call-escalation.md)
- Incident response plan: [docs/security/incident-response-plan.md](../security/incident-response-plan.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- Metrics source: `internal/metrics/collector.go`
- NIST SP 800-53 Rev 5: CA-7, SI-4; FedRAMP Moderate ConMon requirements.
