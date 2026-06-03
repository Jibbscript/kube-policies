---
title: "ConMon Cadence Reference — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring"
controls: "CA-7, CA-7(1), CA-5, RA-5, SI-2, SI-4"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "Authorizing Official (TBD — assign before assessment)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# ConMon Cadence Reference — Kube-Policies (KP)

> P12-WU-06 · NIST SP 800-53 Rev 5: CA-7, CA-7(1) · FedRAMP-Moderate ConMon
> Status: Draft · Last reviewed: 2026-06-02 · Next review: 2027-06-02

This is the concise cadence reference for the KP continuous-monitoring program — a quick
"signal → owner → tool/artifact" view extracted from the canonical
[conmon-plan.md](conmon-plan.md). The plan governs on any disagreement. Cadences are
**design targets** for a pre-authorization PoC (no ATO); owners are **role placeholders**.

## Continuous / real-time

| Signal | Owner | Tool / artifact |
|---|---|---|
| Availability + latency SLI alerts | Operator / SRE | Prometheus → Alertmanager; `slo.yaml`, `availability.yaml` |
| Fail-open events | Primary on-call → ISSO (15 min) | `kube_policies_admission_fail_open_total`; `security.yaml` |
| Audit drop / write-error / buffer | Primary on-call; Operator | `kube_policies_audit_events_total`; `security.yaml` |
| Webhook / policy-manager down | Primary on-call | `up{...}`; `availability.yaml` |
| TLS certificate expiry | Operator (warn); on-call (crit) | `kube_policies_tls_cert_expiry_seconds`; `tls.yaml` |
| DoS / rate-limit surge | Operator / SRE | `dos.yaml`, `capacity.yaml` |
| Monitoring heartbeat (dead-man's-switch) | External watchdog | `KubePoliciesWatchdog`; `watchdog.yaml` |
| Image signature verification | Automated | Cosign verify at admission (`imageVerification.enabled`) |

## Daily

| Signal | Owner | Tool / artifact |
|---|---|---|
| Audit event-stream gap check | Operator / SRE | SIEM query over `PolicyDecision` events |
| Configuration drift reconciler | Operator / SRE | GitOps reconciler (ArgoCD/Flux), if active |

## Weekly

| Signal | Owner | Tool / artifact |
|---|---|---|
| Audit hash-chain integrity | ISSO | `VerifyChainFiles` (`integrity_hash`) |
| SIEM forwarder health / log review | Operator / SRE | Fluent Bit metrics; `kube_policies_audit_events_total` |
| Helm / CRD drift diff | Operator / SRE | `helm diff`, `kubectl diff` |
| POA&M aging report | ISSO | [.github/workflows/poam-aging.yml](../../../.github/workflows/poam-aging.yml) (Mon 07:00 UTC) |

## Monthly

| Signal | Owner | Tool / artifact |
|---|---|---|
| Authenticated vulnerability scan + review | ISSO; Operator / SRE | [.github/workflows/monthly-vuln-scan.yml](../../../.github/workflows/monthly-vuln-scan.yml) (1st 06:00 UTC); GitHub Security tab |
| POA&M update / triage | ISSO | [POAM.md](../POAM.md) / [poam.csv](../poam.csv); aging report |
| SLO error-budget review (30-day) | ISSO | Security-metrics meeting; [docs/observability/slo.md](../../observability/slo.md) |
| Audit log retention check (AU-11) | ISSO | SIEM index age |
| CIS benchmark | ISSO | `kube-bench` or equivalent |
| ConMon report to AO | ISSO → AO | Security-metrics meeting record |

## Annually

| Signal | Owner | Tool / artifact |
|---|---|---|
| Full control assessment review | ISSO; Independent Assessor | [Security Assessment Plan](../assessment/SAP.md) |
| POA&M re-baseline | ISSO | [POAM.md](../POAM.md) |
| SLO target review | ISSO | [docs/observability/slo.md](../../observability/slo.md) |
| ConMon plan + cadence review | ISSO | [conmon-plan.md](conmon-plan.md); this file |

## References

- Canonical ConMon plan: [conmon-plan.md](conmon-plan.md)
- Alert source files: `charts/kube-policies/files/alerts/*.yaml` ·
  [security.yaml](../../../charts/kube-policies/files/alerts/security.yaml)
- SLO source: [charts/kube-policies/files/slo/slo.yaml](../../../charts/kube-policies/files/slo/slo.yaml)
- SIEM integration: [docs/security/siem-integration.md](../../security/siem-integration.md)
- CA policy / procedures: [CA-policy.md](../policies/CA-policy.md) · [CA-procedures.md](../procedures/CA-procedures.md)
