---
title: "CIS Kubernetes Benchmark — Assessment & Control Ownership — Kube-Policies (KP)"
control_family: "CM — Configuration Management; CA — Assessment"
controls: "CIS 1.2.x, 4.2.x, 5.2.x, 5.3.x; NIST CM-6, CM-7, CA-2, SC-7, SC-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# CIS Kubernetes Benchmark — Assessment & Control Ownership — Kube-Policies (KP)

> **Posture:** Kube-Policies is a Proof-of-Concept being driven to
> FedRAMP-Moderate readiness; it is **not yet authorized** (no ATO) and not in
> production use. This document is an **assessment artifact** (CA-2 evidence),
> **not a pass/fail certification**. A CIS benchmark "PASS" here means the
> assessed control was satisfied on the assessment cluster (a `kind` e2e
> cluster), which is not a production node and does not imply the shipped
> product certifies the control.

This document records how the CIS Kubernetes Benchmark controls map to
ownership boundaries for Kube-Policies, and how the `kube-bench` assessment is
produced. It is part of the compliance evidence package
([compliance index](README.md)) and complements
[Cluster TLS Prerequisites](cluster-tls-prereqs.md).

## How the assessment is produced

`scripts/validate/cis-conformance.sh` runs Aqua `kube-bench` as an in-cluster `Job`
against the `kind` e2e cluster that the CI `e2e-kind` job already stands up, and
writes `kube-bench-results.json` / `.txt` as a CI artifact (job
`cis-benchmark`, which `needs: [e2e-kind]`). The script is **non-gating**: many
controls below are node/operator responsibilities that cannot be remediated from
within the chart or on an ephemeral `kind` node, so a `FAIL` there must not break
the build. The artifact is reviewed during the assessment cadence.

Run it locally against a live cluster:

```bash
KIND_CLUSTER_NAME=kube-policies-test scripts/validate/cis-conformance.sh
# -> test-results/cis-benchmark/kube-bench-results.{json,txt}
```

> kube-bench requires host access to the kubelet/apiserver config files
> (`/var/lib/kubelet`, `/etc/kubernetes`, `/etc/systemd`). On managed clusters
> (EKS/GKE/AKS) those paths and the control-plane are not exposed, so the
> node/master sections will be partial — that is expected and is captured in the
> ownership table below.

## Control ownership mapping

Each control class is owned by one of:

- **Node / operator** — the cluster administrator or cloud provider configures
  the kubelet, container runtime, and node OS. Kube-Policies cannot remediate.
- **Control plane / operator** — the apiserver / controller-manager / scheduler
  / etcd flags. Out of the Kube-Policies system boundary.
- **Chart** — Kube-Policies' own Helm chart and shipped manifests own the
  control for the workloads it deploys.

| CIS section | Examples | Owner | Kube-Policies evidence / gate |
|---|---|---|---|
| 1.2.x — API server | `--anonymous-auth`, `--tls-cert-file`, audit flags | Control plane / operator | Out of boundary. Assessed by `kube-bench --targets master`; see [Cluster TLS Prerequisites](cluster-tls-prereqs.md). |
| 1.3.x / 1.4.x — controller-manager, scheduler | bind-address, profiling | Control plane / operator | Out of boundary; assessment artifact only. |
| 2.x — etcd | peer/client TLS, auto-TLS | Control plane / operator | Out of boundary; depends on customer etcd. Related: [secrets-at-rest](secrets-at-rest.md). |
| 3.x — control-plane config | audit policy, encryption provider | Control plane / operator | Out of boundary; encryption-at-rest sample in `deployments/kubernetes/encryption/`. |
| 4.1.x — worker node files | kubelet config file perms/ownership | Node / operator | Out of boundary; assessed by `kube-bench --targets node`. |
| 4.2.x — kubelet | `--anonymous-auth=false`, `--read-only-port=0`, client-cert rotation, RuntimeDefault seccomp default | Node / operator | Out of boundary. The webhook still enforces mTLS to the apiserver (IAM-WU-06) regardless; see [Cluster TLS Prerequisites](cluster-tls-prereqs.md). |
| 5.1.x — RBAC & Service Accounts | wildcard roles, default SA token automount | **Chart** | **Gated.** `rbac-sa-gate` (conftest `rbac.leastprivilege`, `sa.token`, `sa.shared`) fails the build on RBAC wildcards, cluster-wide Secrets grants, token automount, or a shared component SA (IAM-WU-17). |
| 5.2.x — Pod Security Standards | seccomp, drop ALL, no priv-esc, readOnlyRootFs, runAsNonRoot, non-root runAsGroup | **Chart** | **Gated.** `manifest-hardening-gate` (conftest `restricted.pss`) + `helm-unittest` assert the restricted profile on **all three** chart workloads (admission-webhook, policy-manager, dashboard) and the bundled monitoring workloads; `seccompProfile`+`runAsGroup` ship as `values.yaml` defaults (CFG-WU-12 / CFG-WU-22). |
| 5.3.x — Network policies & PSA | default-deny NetworkPolicy, PSA-restricted namespace labels | **Chart** | **Gated.** `network-posture-gate` (conftest `network.posture`) requires a fail-closed default-deny + per-component ingress; `restricted.pss` requires PSA-restricted Namespace labels (NET-WU-20, CFG-WU-12). |
| 5.4.x — Secrets management | prefer mounted secrets over env | **Chart / operator** | Partial: TLS material is mounted; see [secrets-at-rest](secrets-at-rest.md). |
| 5.7.x — General policies | namespace seccomp default, NetworkPolicy per namespace | **Chart / operator** | Chart ships per-component NetworkPolicies + PSA labels for its own namespace; cluster-wide defaults are operator-owned. |

## Chart-side hardening — closed in P5 (2026-06-01)

The chart-side hardening findings the earlier P5 gates surfaced are now **closed**;
they are recorded here for traceability:

1. **Dashboard security context — RESOLVED.** The dashboard pod/container
   `securityContext` is now **values-driven** (`dashboard.podSecurityContext` /
   `dashboard.securityContext` in `values.yaml`, rendered via `toYaml`) and ships
   `seccompProfile: RuntimeDefault` plus a non-root `runAsGroup` (`65532`) as
   `values.yaml` **defaults** — matching admission-webhook/policy-manager. The
   `restricted.pss` gate now covers the dashboard and the `helm-unittest` dashboard
   suite asserts `seccompProfile`+`runAsGroup`. POAM-024 (CM-7) is closed.
2. **Monitoring namespace PSA labels — RESOLVED.** The
   `kube-policies-monitoring` Namespace now carries the
   `pod-security.kubernetes.io/{enforce,audit,warn}: restricted` labels, and the
   monitoring *workloads* (prometheus/grafana/alertmanager) pass `restricted.pss`.
   **Caveat (unchanged):** these example monitoring manifests remain demo-grade
   (`emptyDir`, no persistence) — an availability concern (AU durability is P7),
   not a least-functionality hardening gap.

## Interpreting a `FAIL`

A `FAIL` in `kube-bench-results.json` for a **node/operator** or **control
plane/operator** control is expected on a `kind` assessment cluster and is **not
a Kube-Policies defect** — it is documented here as out-of-boundary. A `FAIL`
attributable to a **Chart**-owned control (5.1.x / 5.2.x / 5.3.x) is a defect
and is independently caught by the gating conftest jobs above before merge.
