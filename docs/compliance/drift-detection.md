---
title: "Configuration Drift Detection — Kube-Policies (KP)"
control_family: "CM — Configuration Management"
controls: "CM-2, CM-3, CM-6"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Configuration Drift Detection — Kube-Policies (KP)

This document describes the **configuration drift detection** mechanism for the Kube-Policies system
(KP) and the **remediation runbook** for handling detected drift. It supports **CM-2 (Baseline
Configuration)**, **CM-3 (Configuration Change Control)**, and **CM-6 (Configuration Settings)** by
giving operators a way to confirm that the running cluster still matches the chart-rendered baseline
(the CM-2 baseline-as-code). It complements the build-time gates (which prevent baseline-weakening
changes from merging) with a **deploy-time** check (which detects divergence in a live cluster).

Kube-Policies is a **Proof-of-Concept being driven to readiness**; it is **not yet authorized**
(**no ATO**). This is an operational tool and runbook, not an authorized continuous-monitoring
control; continuous, scheduled drift monitoring is part of the ConMon program (P9).

## Mechanism

The detector is [`scripts/ops/drift-detect.sh`](../../scripts/ops/drift-detect.sh). It renders the
`kube-policies` Helm chart (the deployable baseline, `--include-crds`) and compares it against either
the live cluster or a saved baseline. **On divergence it prints the diff and exits non-zero.**

| Mode | What it does | Cluster needed? |
|---|---|---|
| `cluster` (default) | Renders the chart, then `kubectl diff` against the running cluster. | Yes (kubeconfig) |
| `baseline` | Renders the chart and `diff`s it against a previously saved baseline file (`--baseline FILE`). | No |
| `save` | Renders the chart and writes the (normalized) baseline file for later comparison. | No |

**Exit codes:** `0` = no drift · `2` = **drift detected** (non-zero, gate-able) · `1` = error
(bad args / render failure) · `127` = required tool missing.

### Determinism — what is normalized

The chart's demo `autoGenerate` TLS path emits **fresh certificates on every render**
(`genCA`/`genSignedCert`) and a content-hash pod-template annotation (`checksum/*`). Those rotate
legitimately and are **not** baseline configuration drift, so the detector blanks the following keys to
a stable placeholder before comparison: `tls.crt`, `tls.key`, `ca.crt`, `caBundle`, and
`checksum/*` annotations. The check therefore reflects **structural / configuration** drift (replica
counts, securityContext, RBAC, NetworkPolicy, images, ConfigMap data, etc.) — exactly the CM-2/CM-6
baseline — and does not false-positive on rotating TLS material.

> For a fully reproducible render including TLS, deploy with `certManager.enabled=true` (or supply
> static cert material and `admissionWebhook.tls.autoGenerate=false`) and pass the same
> `--values`/`--set` to `drift-detect.sh` so the rendered baseline matches the deployed values.

### Matching your deployment

Pass the same release name, namespace, and values you deployed with, so the rendered baseline matches
the running release:

```bash
scripts/ops/drift-detect.sh \
  --release kube-policies \
  --namespace kube-policies-system \
  --values my-prod-values.yaml \
  --set dashboard.enabled=true
```

## Usage

```bash
# 1) Detect drift against the live cluster (CI/cron-friendly; exits 2 on drift):
scripts/ops/drift-detect.sh --release kube-policies --namespace kube-policies-system

# 2) Save a baseline now, compare later (no cluster required):
scripts/ops/drift-detect.sh --mode save     --baseline /var/lib/kp/baseline.yaml
scripts/ops/drift-detect.sh --mode baseline --baseline /var/lib/kp/baseline.yaml
```

## Remediation runbook

When the detector exits **2 (drift detected)**, the printed diff identifies the diverging objects.
Triage and remediate:

1. **Read the diff.** Lines prefixed `-`/`<` are the baseline (expected) state; `+`/`>` are the live
   (or newly-rendered) state. Identify which object(s) and field(s) diverged.
2. **Classify the drift.**
   - **Unauthorized live change** (someone `kubectl edit`-ed a Deployment, an RBAC role widened, a
     NetworkPolicy was deleted): this is a **finding**. Treat per the incident/CM process.
   - **Authorized change not yet in the chart** (a deliberate change applied to the cluster but not
     captured in `values.yaml`/templates): the baseline is stale and must be updated through change
     control.
   - **Expected rotation** (only TLS material / checksums) should already be filtered; if it shows,
     re-run after confirming `autoGenerate`/values alignment (see *Determinism* above).
3. **Remediate.**
   - For an **unauthorized live change**: re-apply the baseline to restore the approved state —
     `helm upgrade kube-policies charts/kube-policies <same values>` (or `kubectl apply` the rendered
     baseline) — and record the event. Re-run `drift-detect.sh` to confirm exit 0.
   - For an **authorized-but-uncaptured change**: open a **pull request** updating the chart
     `values.yaml`/templates and the [secure configuration baseline](secure-configuration-baseline.md),
     completing the [change-control checklist](../../.github/pull_request_template.md) (CM-3). The
     blocking CI gates must pass before merge.
4. **Record.** Note the drift, its classification, and the remediation in the change record (PR /
   incident ticket). If the drift represents an open weakness, add a [POA&M](poam.csv) entry.
5. **Verify.** Re-run `drift-detect.sh`; a clean **exit 0** is the evidence that the running state
   matches the baseline again.

## Honest scope and limitations

- **Deploy-time, on-demand.** This is an operator/CI tool; **scheduled** continuous drift monitoring
  and alerting are part of the ConMon program (P9), not yet implemented.
- **Render-vs-live, not policy.** It detects divergence from the chart-rendered baseline; it does not
  evaluate runtime behavior or in-cluster admission decisions.
- **Values must match the deployment** for the comparison to be meaningful (see *Matching your
  deployment*).
- **TLS material is intentionally not compared** (it rotates legitimately).

## References

- Detector: [`scripts/ops/drift-detect.sh`](../../scripts/ops/drift-detect.sh)
- CM plan (§5 Drift detection): [plans/configuration-management-plan.md](plans/configuration-management-plan.md)
- CM procedures (§5): [procedures/CM-procedures.md](procedures/CM-procedures.md) · CM policy: [policies/CM-policy.md](policies/CM-policy.md)
- Secure configuration baseline (CM-2/CM-6): [secure-configuration-baseline.md](secure-configuration-baseline.md)
- Change-control checklist: [`.github/pull_request_template.md`](../../.github/pull_request_template.md) · CI gates: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
- Control matrix: [control-matrix.csv](control-matrix.csv) · POA&M: [poam.csv](poam.csv) · Compliance index: [README.md](README.md)
- NIST SP 800-53 Rev 5 (CM-2, CM-3, CM-6); FedRAMP Moderate baseline.
