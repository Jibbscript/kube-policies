---
title: "Configuration Management Plan (CM-1 / CM-2 / CM-3 / CM-9) — Kube-Policies (KP)"
control_family: "CM — Configuration Management"
controls: "CM-1, CM-2, CM-3, CM-6, CM-7, CM-7(1), CM-8, CM-9, RA-5, SI-2"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Configuration Management Plan — Kube-Policies (KP)

This is the **Configuration Management Plan (CM-9)** for the Kube-Policies system (KP),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It is the canonical CM plan referenced by the
[secure configuration baseline](../secure-configuration-baseline.md), the
[CM policy](../policies/CM-policy.md), and the [CM procedures](../procedures/CM-procedures.md).
It establishes: the **baseline** (CM-2), the **change-control process** (CM-3) enforced by the
`.github/workflows` CI gates and the pull-request checklist, the **Helm/CRD change process**, the
**CCB / approval roles**, and the **annual review** statement.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is **not
yet authorized** (**no ATO**) and not in production use. This plan documents the CM discipline the
program operates under and the controls that are *actually implemented* in the shipped code, Helm
chart, and CI — it is not a claim that every CM control is fully met. Per-control status is tracked
in the [control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../poam.csv), with
remediation phases (P0–P12) defined in `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This plan is reviewed and updated at least **annually** (next review
**2027-06-01**) and whenever a significant change occurs to the system, its baseline, its change
process, the CI gates, or the applicable standards. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose, scope, and roles

### 1.1 Purpose (CM-1)

The purpose of this plan is to ensure that the configuration of KP is **baselined, change-controlled,
inventoried, and least-functional**, so that the as-built system matches the documented, assessed
state and unauthorized or untested changes cannot silently reach a deployment.

### 1.2 Scope

The configuration items (CIs) under CM are:

- the **Helm chart** (`AST-CHART`, [`charts/kube-policies`](../../../charts/kube-policies)) — its
  `values.yaml`, templates, and the rendered RBAC / Services / ConfigMap / TLS / NetworkPolicy /
  Namespace objects;
- the **CRDs** (`AST-CRD-POL`, `AST-CRD-EXC`,
  [`deployments/kubernetes/crds/`](../../../deployments/kubernetes/crds));
- the **static base manifests** ([`deployments/kubernetes/base/`](../../../deployments/kubernetes/base));
- the **runtime configuration** validated by `internal/config` (TLS floor, `failure_mode`, audit
  backend);
- the **container images** (`AST-IMG-WH/PM/DB`, [inventory](../inventory.csv)); and
- the **compliance artifacts** under [`docs/compliance/`](../) that record the above.

The optional monitoring manifests
([`deployments/kubernetes/monitoring/`](../../../deployments/kubernetes/monitoring)) are
**demo/Kind-grade** (ephemeral `emptyDir`, no persistence) and are out of the authorization
boundary; they are CM-tracked only as example artifacts (see
[secure-configuration-baseline.md §5A](../secure-configuration-baseline.md#5a-monitoring-stack-demokind-grade--not-a-production-ci)).

### 1.3 Roles and Configuration Control Board (CCB)

Named roles are **not yet staffed**; this plan refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see [roles-raci.md](../roles-raci.md)).

| Role | Holder | CM responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for CM adequacy and resourcing; approves this plan and the baseline; chairs the CCB. |
| ISSO | TBD — assign before assessment | Designated official managing this plan, the policy, and the procedures; reviews change-control evidence; assesses security impact (CM-4); maintains the POA&M. |
| Maintainers / CODEOWNERS | TBD — assign | Review and approve pull requests; enforce that the CI gates pass before merge. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP; renders the authorization decision; approves deviations beyond the System Owner's delegated authority. |
| Configuration Control Board (CCB) | System Owner (chair), ISSO, lead Maintainer | Reviews and approves significant configuration changes and deviations; meets on demand for significant changes and at each annual review. |

## 2 Baseline configuration (CM-2 / CM-6)

The authoritative **CM-2 baseline configuration** and **CM-6 configuration settings** record is the
[secure configuration baseline](../secure-configuration-baseline.md). The baseline is **configuration
as code**: the Helm chart `values.yaml` + templates are the machine-readable expression of every
required setting, and the rendered manifests are the deployable baseline.

- **Versioning / retention (CM-2(3)).** The baseline, chart, CRDs, and compliance artifacts are
  retained in **git**; previous configurations are recoverable from history. Chart releases are
  versioned (`Chart.yaml` `version`/`appVersion`).
- **Image baseline (CM-2).** The [inventory](../inventory.md) records each in-boundary image. The
  `kube-policies.image` Helm helper accepts a **digest-pinned reference** (`tag@sha256:…`), giving a
  digest-deploy option; the shipped `values.yaml` still uses **floating tags**, so images are **not
  digest-pinned by default** (residual **POAM-023**; digest-by-default is P6).
- **Automated baseline verification (CM-6(1)).** The CI gates in §3.2 render the chart and assert the
  baseline settings on the rendered manifests, failing the build on drift.

## 3 Configuration change control (CM-3)

### 3.1 Change process

All changes to a CI in §1.2 flow through a **pull request** against the repository:

1. **Propose.** The contributor opens a PR and completes the
   [change-control checklist in the pull-request template](../../../.github/pull_request_template.md)
   (CM-3): baseline/inventory updated if settings changed, policy/hardening gates green, images
   digest-pinned where applicable, security impact noted (CM-4).
2. **Review.** Maintainers / CODEOWNERS review the change; the ISSO assesses security impact for
   security-relevant changes (CM-4).
3. **Automated gate.** The CI gates (§3.2) must pass; they are **blocking** via the `CI Gate`
   aggregation job in [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml).
4. **Approve / merge.** On approval + green CI, a Maintainer merges. **Significant** changes
   (boundary, baseline-setting, RBAC, NetworkPolicy, TLS/crypto, CRD schema) additionally require
   **CCB** review (§1.3).
5. **Record.** The merge commit + PR is the change record; deviations are recorded in the
   [POA&M](../poam.csv) and noted in the [control matrix](../control-matrix.csv).

### 3.2 Change-control enforcement — the CI gates (CM-3 / CM-3(2) / CM-6(1))

Change testing/validation is enforced by the now-**gating** jobs in
[`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) (all required by the `CI Gate`
aggregation job):

| Gate (job) | What it enforces | Control |
|---|---|---|
| `manifest-hardening-gate` | conftest `restricted.pss` over the rendered chart (seccomp, drop-ALL, no-priv-esc, readOnlyRootFs, non-root UID/GID, resources), plus a dead-gate proof that a seccomp-stripped render is **denied** | CM-6, CM-7, CIS 5.2.x |
| `helm-unittest` | `charts/kube-policies/tests/hardening_test.yaml` asserts the restricted control set per control-plane pod/container | CM-6, CM-7 |
| `network-posture-gate` | default-deny + per-component ingress + PSA-restricted namespace labels; dead-gate proof on a default-deny-removed render | SC-7, CM-7 |
| `rbac-sa-gate` | RBAC least-privilege + SA-token automount + no shared component SA | AC-6, CM-7 |
| Trivy GATE (in `security-scan`) | filesystem + image scans; **`CRITICAL,HIGH` → exit 1**, fails the build (in addition to the non-gating SARIF upload) | RA-5, SI-2 |
| `actionlint`, `govulncheck`, `unit-tests`, `fips-verify` | workflow lint, vulnerable-dependency scan, unit/conformance tests, FIPS build marker | SA-11, RA-5, SC-13 |

Together these are the **CM-3 change-control enforcement mechanism**: a change that weakens the
baseline (e.g. removing `seccompProfile`, a NetworkPolicy, an RBAC scope) fails a gate and cannot
merge.

### 3.3 Helm / CRD change process

- **Helm chart.** Changes to `values.yaml`/templates are reviewed for baseline impact; `helm-tests`
  (chart-testing lint/install) plus the hardening/network/RBAC gates run on every PR. The chart
  `version` is bumped per change; release packaging is in
  [`.github/workflows/release.yml`](../../../.github/workflows/release.yml).
- **CRDs.** Schema changes to `Policy`/`PolicyException`
  ([`deployments/kubernetes/crds/`](../../../deployments/kubernetes/crds)) are treated as
  **significant** (they alter the data contract) and require CCB review and a compatibility note.
  CRD changes are versioned in git and validated by the e2e jobs.
- **Static base manifests.** Kept in lockstep with the chart for the raw-`kubectl` path; the
  NetworkPolicy base mirrors the chart's policy set.

## 4 Configuration inventory and least functionality (CM-7 / CM-8)

- **Inventory (CM-8).** [inventory.md](../inventory.md) / [inventory.csv](../inventory.csv) enumerate
  every `AST-*` component and image (with digest support), reviewed per release.
- **Least functionality (CM-7).** Distroless images, dropped capabilities, read-only root
  filesystem, and the enumerated [ports/protocols register](../ssp/ports-protocols-services.md)
  (each port justified) keep the attack surface minimal; the dashboard and its listeners are **off by
  default**. Periodic review (CM-7(1)) is defined in the [CM procedures](../procedures/CM-procedures.md).

## 5 Drift detection

Drift between the running cluster state and the chart-rendered baseline is detected by
[`scripts/ops/drift-detect.sh`](../../../scripts/ops/drift-detect.sh) (see
[drift-detection.md](../drift-detection.md)), which renders the chart and diffs it against the live
cluster (or a saved baseline) and **exits non-zero on divergence**. Detected drift is triaged per the
[CM procedures](../procedures/CM-procedures.md) and, if it represents an unauthorized change, raised
as a finding.

## 6 Honest scope and residual gaps

This plan claims only what is implemented:

- **No ATO**; PoC on the path to readiness.
- **Implemented:** CM-1 (this plan + [policy](../policies/CM-policy.md)/[procedures](../procedures/CM-procedures.md)),
  CM-9 (this plan). CM-3 is **Partial** — PR + checklist + gating CI exist, but **named CCB members,
  signed commits, and branch protection are TBD** to be staffed/configured.
- **Implemented:** CM-7 least functionality (POAM-024 **closed P5, 2026-06-01**) —
  `seccompProfile: RuntimeDefault` and a non-root `runAsGroup` ship as `values.yaml` **defaults** on
  all three workloads (admission-webhook/policy-manager `runAsGroup` 65534, dashboard 65532), the
  dashboard `securityContext` is **values-driven**, and the gating `restricted.pss` conftest +
  `helm-unittest` cover the control plane, the dashboard, and the bundled monitoring workloads.
- **Partial / residual:** CM-2 (digest-deploy supported but images not pinned by default — POAM-023);
  CM-6 (the policy engine does not yet traverse `spec.template.spec`, so workload-controller settings
  are unenforced — POAM-008, P10). `namespace.create` defaults `false`, so the operator must opt in
  or use `--create-namespace` for the PSA-restricted labels.
- **Demo-only:** the monitoring stack (`emptyDir`, no persistence) — an availability concern (AU
  durability is P7), not a CM-7 hardening gap.

## 7 References

- CM policy: [../policies/CM-policy.md](../policies/CM-policy.md) · CM procedures: [../procedures/CM-procedures.md](../procedures/CM-procedures.md)
- Secure configuration baseline (CM-2/CM-6): [../secure-configuration-baseline.md](../secure-configuration-baseline.md)
- Inventory (CM-8): [../inventory.md](../inventory.md) / [../inventory.csv](../inventory.csv) · PPS register (CM-7): [../ssp/ports-protocols-services.md](../ssp/ports-protocols-services.md)
- Drift detection (CM): [../drift-detection.md](../drift-detection.md) · script: [`scripts/ops/drift-detect.sh`](../../../scripts/ops/drift-detect.sh)
- Change-control checklist: [`.github/pull_request_template.md`](../../../.github/pull_request_template.md) · CI gates: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
- CIS benchmark / gaps: [../cis-benchmark-results.md](../cis-benchmark-results.md)
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · POA&M: [../poam.csv](../poam.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CM-1, CM-2, CM-3, CM-4, CM-6, CM-7, CM-8, CM-9, RA-5, SI-2); FedRAMP Moderate baseline; CIS Kubernetes Benchmark.
