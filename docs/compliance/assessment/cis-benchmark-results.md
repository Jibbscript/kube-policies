---
title: "CIS Kubernetes Benchmark — Recorded Findings Report — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring; CM — Configuration Management"
controls: "CIS 1.x, 2.x, 3.x, 4.x, 5.1.x, 5.2.x, 5.3.x, 5.4.x; NIST CA-2, CM-6, CM-7, RA-5, SC-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# CIS Kubernetes Benchmark — Recorded Findings Report — Kube-Policies (KP)

> **Posture / honesty note.** Kube-Policies (KP) is a Proof-of-Concept being
> driven to FedRAMP-Moderate readiness; it is **not yet authorized** (no ATO) and
> is not in production use. This is a **recorded findings report** (CA-2 / RA-5
> evidence) for a **`kind`-cluster assessment run executed by CI**, **not a
> production certification**. The numeric counts below are **illustrative of the
> expected posture**; the authoritative, dated artifact is the one produced by
> the CI `cis-benchmark` job (`test-results/cis-benchmark/kube-bench-results.json`
> and `pss-restricted-conftest.txt`) on a given run. A `kind` node is not a
> production node, so a CIS "PASS" here means only that the assessed control was
> satisfied on the assessment cluster.

This report records the findings and their disposition for the CIS Kubernetes
Benchmark assessment of KP. It complements — and does not replace — the
[CIS control-ownership map](../cis-benchmark-results.md) (which defines *who owns*
each control class) and the [CIS + NIST 800-190 self-assessment mapping](../cis-k8s-800-190-mapping.md)
(which maps controls to NIST families). It is part of the assessment evidence
package referenced by the [Security Assessment Plan (SAP)](SAP.md); resulting
findings are tracked in the [POA&M](../poam.csv) and per-control status lives in
the [control matrix](../control-matrix.csv). See the
[compliance index](../README.md) for the full document set.

## 1. Assessment method

Two complementary methods produce the CIS conformance evidence, both driven from
a single entrypoint — `scripts/validate/cis-conformance.sh` — invoked by the CI
`cis-benchmark` job (`needs: [e2e-kind]`) against the `kind` e2e cluster:

1. **kube-bench (node / control-plane).** Aqua `kube-bench` runs as an
   in-cluster `Job` (the shape shipped in
   `deployments/kubernetes/conformance/kube-bench-job.yaml`) with
   `--targets node,master --json`, capturing
   `test-results/cis-benchmark/kube-bench-results.{json,txt}`. This step is
   **non-gating** by design: most node and control-plane controls are operator-
   or CSP-owned and cannot be remediated from within the chart or on an ephemeral
   `kind` node. NIST 800-53A method: **Test** (automated), **Examine** (review of
   the artifact during the assessment cadence).

2. **Pod Security Standard (restricted) — chart-owned CIS 5.2.x.** The same
   script renders the KP Helm chart (`helm template`, with subchart deps resolved
   via `scripts/ci/helm-deps.sh`) and runs the `conftest` `restricted.pss` policy
   (`test/policy/restricted-pss.rego`) over the rendered output, writing
   `test-results/cis-benchmark/pss-restricted-conftest.txt`. This is the
   chart-owned half of CIS 5.x: it is **independently GATING** in the
   `manifest-hardening-gate` job (`scripts/test/lint-manifests.sh`) and is
   **reported clearly** here. NIST 800-53A method: **Test** (policy-as-code).

Run locally against a live cluster:

```bash
KIND_CLUSTER_NAME=kube-policies-test scripts/validate/cis-conformance.sh
# -> test-results/cis-benchmark/kube-bench-results.{json,txt}
# -> test-results/cis-benchmark/pss-restricted-conftest.txt
```

> kube-bench requires host access to the kubelet/apiserver config files
> (`/var/lib/kubelet`, `/etc/kubernetes`, `/etc/systemd`). On managed clusters
> (EKS/GKE/AKS) those paths and the control plane are not exposed, so the
> node/master sections are partial — that is expected and recorded as
> CSP-inherited below.

## 2. Summary of findings (illustrative of expected posture)

The counts below reflect the expected disposition on the `kind` assessment
cluster. They are **not a certification tally**; the live, dated counts are in
the CI artifact for each run.

| Section | Scope | Owner | Expected disposition |
|---|---|---|---|
| 1.x — control-plane (apiserver, controller-mgr, scheduler) | apiserver flags, audit, profiling | Control plane / operator / CSP | **CSP-inherited.** Out of KP boundary; assessed by `kube-bench --targets master`. `kind` reports FAILs/WARNs here — expected, not a KP defect. |
| 2.x — etcd | peer/client TLS, auto-TLS | Control plane / operator / CSP | **CSP-inherited.** Depends on customer/CSP etcd. |
| 3.x — control-plane configuration | audit policy, encryption provider | Control plane / operator / CSP | **CSP-inherited.** Encryption-at-rest sample lives in `deployments/kubernetes/encryption/`; enabling it is operator-owned. |
| 4.1.x / 4.2.x — worker node, kubelet | file perms, `--anonymous-auth=false`, `--read-only-port=0`, RuntimeDefault default | Node / operator | **CSP-inherited / out-of-boundary.** Assessed by `kube-bench --targets node`. FAILs on a `kind` node are expected. |
| 5.1.x — RBAC & service accounts | wildcard roles, default SA token automount | **Chart** | **PASS — remediated & gated.** `rbac-sa-gate` (conftest `rbac.leastprivilege`, `sa.token`, `sa.shared`). |
| 5.2.x — Pod Security Standards | seccomp, drop ALL, no priv-esc, readOnlyRootFs, runAsNonRoot, non-root runAsGroup | **Chart** | **PASS — remediated & gated.** `manifest-hardening-gate` (conftest `restricted.pss`) + the PSS-restricted step of this assessment. |
| 5.3.x — Network policies & PSA | default-deny NetworkPolicy, PSA-restricted labels | **Chart** | **PASS — remediated & gated.** `network-posture-gate` (conftest `network.posture`) + `restricted.pss` PSA labels. |
| 5.4.x — Secrets management | prefer mounted secrets over env | **Chart / operator** | **Partial — waived with justification.** TLS material is mounted; remaining cluster-wide secret handling is operator-owned. See [secrets-at-rest](../secrets-at-rest.md). |
| 5.7.x — General policies | namespace seccomp default, per-namespace NetworkPolicy | **Chart / operator** | **Partial — split.** Chart ships per-component NetworkPolicies + PSA labels for its own namespace; cluster-wide defaults are operator-owned. |

### 2.1 Pod Security Standard (restricted) — chart workloads

The restricted Pod Security Standard **PASSES for all three shipped chart
workloads** — `admission-webhook`, `policy-manager`, and `dashboard` — plus the
bundled monitoring workloads. `seccompProfile: RuntimeDefault` and a non-root
`runAsGroup` ship as `values.yaml` defaults (no `--set` injection needed), so the
`restricted.pss` policy gates all three by default. This is asserted two ways:

- **Helm unit tests:** `charts/kube-policies/tests/hardening_test.yaml` asserts
  the restricted securityContext fields on each workload.
- **Policy-as-code, gating:** the `manifest-hardening-gate` job runs
  `conftest --namespace restricted.pss` over the rendered chart and the
  chart-owned base + monitoring manifests; a regression fails the build before
  merge. The PSS-restricted step of `scripts/validate/cis-conformance.sh`
  re-runs the same policy and records `pss-restricted-conftest.txt` as
  assessment evidence.

## 3. Finding disposition by FAIL category

Every FAIL category is classified as **remediated**, **waived (with
justification)**, or **CSP-inherited**:

| FAIL category (CIS) | Disposition | Justification / evidence |
|---|---|---|
| 1.x apiserver / controller-mgr / scheduler | **CSP-inherited** | Control-plane flags are not configurable by KP; on managed control planes they are not exposed. Owned by the CSP/operator authorization package. |
| 2.x etcd | **CSP-inherited** | etcd is operated by the CSP/customer; KP neither deploys nor flags etcd. |
| 3.x audit policy / encryption-at-rest | **CSP-inherited** | Operator enables apiserver audit + encryption provider; KP ships a sample in `deployments/kubernetes/encryption/` only. |
| 4.1.x / 4.2.x node & kubelet | **CSP-inherited** | Node OS, kubelet flags, and file perms are node/operator-owned; FAILs on an ephemeral `kind` node are expected and out-of-boundary. The webhook still enforces mTLS to the apiserver (IAM-WU-06) regardless. |
| 5.1.x RBAC / SA token automount | **Remediated** | `rbac-sa-gate` fails the build on RBAC wildcards, cluster-wide Secrets grants, token automount, or a shared component SA (IAM-WU-17). |
| 5.2.x Pod Security Standards | **Remediated** | `manifest-hardening-gate` (`restricted.pss`) + `helm-unittest` (`hardening_test.yaml`) + the PSS-restricted step here. |
| 5.3.x NetworkPolicy / PSA labels | **Remediated** | `network-posture-gate` (`network.posture`) requires fail-closed default-deny + per-component ingress; `restricted.pss` requires PSA-restricted Namespace labels (NET-WU-20, CFG-WU-12). |
| 5.4.x secrets in env | **Waived (with justification)** | TLS material is mounted, not env-injected; remaining cluster-wide secret handling is operator-owned. Tracked in the [POA&M](../poam.csv); see [secrets-at-rest](../secrets-at-rest.md). |

A FAIL attributable to a **Chart**-owned control (5.1.x / 5.2.x / 5.3.x) is a
**defect**, not an inherited finding, and is independently caught by the gating
conftest jobs above before merge. A FAIL in a node/operator or control-plane/
operator section is **expected** on the `kind` assessment cluster and is recorded
here as CSP-inherited (see the [control-ownership map](../cis-benchmark-results.md)
for the authoritative owner of each class).

## 4. Limitations & next steps

- This is a **pre-authorization PoC** assessment on a `kind` cluster. It does not
  certify the product and is not a substitute for an independent assessor's
  examination on a production-representative cluster.
- The numeric counts are **illustrative**; the dated, authoritative artifact is
  produced per-run by the CI `cis-benchmark` job and attached as the
  `cis-benchmark-report` artifact.
- CSP-inherited findings will be reconciled against the CSP authorization package
  and the [CRM](../CRM.md) during assessment; waived findings carry POA&M entries.
- Re-baselined on any significant change and reviewed at least **annually**
  (next review **2027-06-02**).

## 5. Cross-references

- [CIS control-ownership map](../cis-benchmark-results.md) — who owns each CIS control class.
- [CIS + NIST 800-190 self-assessment mapping](../cis-k8s-800-190-mapping.md) — control → NIST family mapping.
- [Security Assessment Plan (SAP)](SAP.md) — assessment scope, method, and schedule.
- [POA&M](../poam.csv) — destination for waived / open findings.
- [Control Matrix](../control-matrix.csv) — per-control implementation status.
- [Compliance index](../README.md).
