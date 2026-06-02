---
title: "Configuration Management Procedures (CM) — Kube-Policies (KP)"
control_family: "CM — Configuration Management"
controls: "CM-1, CM-2, CM-3, CM-6, CM-7, CM-7(1), CM-8, CM-9, RA-5, SI-2"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Configuration Management Procedures — Kube-Policies (KP)

These are the operational procedures that implement the Configuration Management policy
([../policies/CM-policy.md](../policies/CM-policy.md)) and the
[Configuration Management Plan](../plans/configuration-management-plan.md) for the Kube-Policies
system (KP). They cover how a change is proposed and gated, how the baseline is rendered and verified,
how drift is detected, how the inventory is kept current, and how the least-functionality periodic
review is performed.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is **not yet
authorized** (**no ATO**). These procedures describe what is *actually implemented* in the shipped
code, Helm chart, and CI and what an assessor or operator can run to verify it. Where a control is
Partial or has a residual, the procedure says so; open weaknesses are tracked in
[../poam.csv](../poam.csv) and the phased plan `../plans/remediation-roadmap.md`.

**Annual review.** These procedures are reviewed and updated at least **annually** (next review
**2027-06-01**) and on any significant change to the system, its baseline, its change process, or the
CI gates. Reviews are recorded by updating the `last_reviewed`/`next_review` front-matter and the
version.

## 1 Scope

These procedures apply to the configuration items in
[CM-policy.md §1](../policies/CM-policy.md#1-purpose-and-applicability): the Helm chart, CRDs, static
base manifests, runtime configuration, container images, and the compliance artifacts that record
them.

## 2 Change procedure (CM-3)

1. **Branch + change.** Create a branch and make the change to the CI.
2. **Open a PR + complete the checklist.** The
   [pull-request template](../../../.github/pull_request_template.md) presents the CM-3 change-control
   checklist — confirm: baseline ([../secure-configuration-baseline.md](../secure-configuration-baseline.md))
   and [inventory](../inventory.md) updated if a setting/component/port changed; policy + hardening
   gates green; images digest-pinned where applicable; security impact noted (CM-4).
3. **Review.** A Maintainer/CODEOWNER reviews; the ISSO assesses security impact for
   security-relevant changes.
4. **Wait for green CI (blocking).** All gating jobs (§4) must pass; the `CI Gate` aggregation job in
   [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) enforces this.
5. **CCB for significant changes.** Boundary / baseline-setting / RBAC / NetworkPolicy / TLS-crypto /
   CRD-schema changes go to the CCB (System Owner chair, ISSO, lead Maintainer).
6. **Merge + record.** On approval + green CI, merge. The PR + merge commit is the change record;
   deviations are added to [../poam.csv](../poam.csv) and noted in [../control-matrix.csv](../control-matrix.csv).

> **Residual (honest).** Named CCB members, **signed commits**, and **branch protection** are
> **TBD** to be staffed/configured; until then CM-3 is **Partial** (the PR + checklist + gating CI
> exist; enforcement of reviewer identity is not yet locked down).

## 3 Render and verify the baseline (CM-2 / CM-6)

Render the chart to produce the deployable baseline and inspect the hardened settings:

```console
# Render the full baseline (control-plane on, dashboard on, namespace managed):
helm template kube-policies charts/kube-policies \
  --set namespace.create=true \
  --set dashboard.enabled=true > /tmp/rendered.yaml

# Confirm the namespace carries the PSA-restricted labels (when chart-managed):
grep -A4 'kind: Namespace' /tmp/rendered.yaml | grep pod-security.kubernetes.io
# Confirm a digest-pinned image deploy option renders a valid ref:
helm template kube-policies charts/kube-policies \
  --set admissionWebhook.image.tag='1.0.0@sha256:<digest>' | grep -m1 'image:'
# -> docker.io/kube-policies/admission-webhook:1.0.0@sha256:<digest>
```

> **Honest residual.** `namespace.create` defaults **false**, so by default the operator owns the
> namespace and must apply the PSA labels (or install with `--create-namespace`). The
> `seccompProfile: RuntimeDefault` and non-root `runAsGroup` are now **`values.yaml` defaults on all
> three workloads** (admission-webhook/policy-manager `runAsGroup` 65534, dashboard 65532) and the
> dashboard `securityContext` is **values-driven** — CM-7 hardening (POAM-024) is **closed (P5)**.
> Images still ship with **floating tags** unless the operator pins them (POAM-023). The example
> monitoring manifests remain demo-grade (`emptyDir`, no persistence — an availability concern, AU
> durability is P7), not a hardening gap.

## 4 Verify the change-control gates (CM-3(2) / CM-6(1) / RA-5 / SI-2)

The gates run in CI; an assessor/operator can run them locally:

```console
# Restricted-PSS hardening gate (all three workloads) + helm-unittest.
# seccompProfile=RuntimeDefault + non-root runAsGroup ship as values.yaml
# defaults, so no --set overrides are needed for the gate to pass; enabling
# the dashboard exercises its (now values-driven) securityContext too:
helm template kube-policies charts/kube-policies --set dashboard.enabled=true | \
  conftest test --policy test/policy --namespace restricted.pss -
helm unittest charts/kube-policies

# RBAC / SA-token + network-posture gates (see scripts/validate/manifests.sh):
bash scripts/validate/manifests.sh

# Gating vulnerability scan (CRITICAL,HIGH fail the build):
trivy fs --severity CRITICAL,HIGH --exit-code 1 .
```

A green run of these is the CM-3 change-control evidence. The full gate inventory is in the
[CM plan §3.2](../plans/configuration-management-plan.md#32-change-control-enforcement--the-ci-gates-cm-3--cm-32--cm-61).

## 5 Drift detection (CM)

Run the drift detector against the target cluster:

```console
scripts/ops/drift-detect.sh --release kube-policies --namespace kube-policies-system
# Exit 0 = no drift; exit non-zero = the running state diverged from the chart-rendered baseline.
```

It renders the chart and `kubectl diff`s it against the live cluster (or compares against a saved
baseline). On divergence it prints the diff and **exits non-zero**. Triage detected drift: if it is an
**unauthorized** change, raise a finding and reconcile (re-apply the baseline or open a change PR); if
it is an **approved** change not yet in the chart, open a PR to update the baseline. Full mechanism and
runbook: [../drift-detection.md](../drift-detection.md).

## 6 Inventory currency (CM-8)

At each release and at least annually, reconcile [../inventory.md](../inventory.md) /
[../inventory.csv](../inventory.csv) against the as-built chart: every `AST-*` component, its image,
ports, and **digest-support** status. Update the [PPS register](../ssp/ports-protocols-services.md) if
a listener changed.

## 7 Least-functionality periodic review (CM-7(1))

At least annually (and on any listener/feature change), review:

- the enabled functions and the **enumerated ports** in the
  [PPS register](../ssp/ports-protocols-services.md) — confirm each is still required and justified;
- that the dashboard and metrics planes remain off-by-default unless an operator opted in;
- that no new listener or capability was added without a corresponding baseline + inventory update.

Record the review by updating the `last_reviewed`/`next_review` front-matter of the PPS register, the
baseline, and this procedure.

## 8 Records and review

Evidence produced by these procedures (PR + checklist, green CI gate logs, render captures, drift-run
output, inventory reconciliation) is retained as CM assessment evidence and referenced from the SSP
([../ssp/SSP.md](../ssp/SSP.md)). These procedures are reviewed at least annually (next review
**2027-06-01**) and on any significant change.

## 9 References

- CM policy: [../policies/CM-policy.md](../policies/CM-policy.md) · CM plan: [../plans/configuration-management-plan.md](../plans/configuration-management-plan.md)
- Secure configuration baseline: [../secure-configuration-baseline.md](../secure-configuration-baseline.md) · Inventory: [../inventory.md](../inventory.md) / [../inventory.csv](../inventory.csv) · PPS: [../ssp/ports-protocols-services.md](../ssp/ports-protocols-services.md)
- Drift detection: [../drift-detection.md](../drift-detection.md) · script: [`scripts/ops/drift-detect.sh`](../../../scripts/ops/drift-detect.sh)
- Change-control checklist: [`.github/pull_request_template.md`](../../../.github/pull_request_template.md) · CI gates: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) · manifest validators: [`scripts/validate/manifests.sh`](../../../scripts/validate/manifests.sh)
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · POA&M: [../poam.csv](../poam.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CM-1, CM-2, CM-3, CM-6, CM-7, CM-7(1), CM-8, CM-9, RA-5, SI-2); FedRAMP Moderate baseline; CIS Kubernetes Benchmark.
