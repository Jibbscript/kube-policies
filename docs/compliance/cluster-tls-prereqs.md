---
title: "Cluster TLS Prerequisites & Conformance Checklist — Kube-Policies (KP)"
control_family: "SC — System and Communications Protection"
controls: "CIS 4.2.x, NIST SC-8, SC-12, CA-2"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Cluster TLS Prerequisites & Conformance Checklist — Kube-Policies (KP)

This document enumerates the cluster-level TLS controls that Kube-Policies
**depends on but does not control**, and provides a conformance checklist that
maps each item to its CIS Kubernetes Benchmark control ID and to a `kube-bench`
verification step. It is part of the compliance evidence package
([compliance index](README.md)).

> **Posture:** Kube-Policies is a Proof-of-Concept being driven to
> FedRAMP-Moderate readiness; it is **not yet authorized** (no ATO) and not in
> production use. The controls below are **out of the system boundary** — they
> belong to the Kubernetes control plane and worker nodes operated by the
> customer (or, for managed clusters, the cloud service provider). Kube-Policies
> cannot enforce them; it can only state them as prerequisites and provide the
> verification tooling whose output the System Owner records as ATO evidence.

This document is reviewed at least **annually** (next review **2027-05-31**) and
on any material change to the cluster baseline or to the upstream CIS
Kubernetes Benchmark version this checklist tracks.

## Scope: what KP controls vs. what it depends on

Kube-Policies serves its own listeners over TLS 1.3 (admission webhook,
policy-manager API, dashboard, and — when enabled — metrics), with the in-app
floor enforced and tested in code (`internal/config/tls.go` `BuildServerTLSConfig`,
and the build-gating conformance test `internal/config/tls_conformance_test.go`).
That is the **in-boundary** TLS posture and is documented in
`crypto-standards.md` and `secure-configuration-baseline.md`.

The controls in this document are **different**: they govern the TLS posture of
the *cluster* into which KP is deployed — the kube-apiserver and the kubelets on
each node. KP's admission webhook is only as trustworthy as the apiserver that
calls it and the kubelets that run its pods, so these are documented as
deployment prerequisites and verified independently. Allocation of these
controls is captured in `CRM.md` (Customer-Responsibility / CSP-Inherited).

| Layer | Owner | Controlled by KP? | Evidence source |
|---|---|---|---|
| KP listeners (webhook / policy-manager / dashboard / metrics) TLS 1.3 | System | **Yes** | `internal/config/tls.go`, `tls_conformance_test.go`, `crypto-standards.md` |
| kube-apiserver TLS version / cipher floor | Customer / CSP | No (prerequisite) | `kube-bench` (this doc) |
| apiserver→kubelet client TLS | Customer / CSP | No (prerequisite) | `kube-bench` (this doc) |
| kubelet serving certificate + rotation | Customer / CSP | No (prerequisite) | `kube-bench` (this doc) |
| kubelet client certificate rotation | Customer / CSP | No (prerequisite) | `kube-bench` (this doc) |

## Why these are prerequisites for Kube-Policies

- **apiserver→webhook path (`ICX-01`).** The apiserver originates the admission
  `AdmissionReview` call to the KP webhook. If the apiserver's own TLS stack is
  weak (≤TLS 1.2 floor, or unverified upstream connections) the integrity of the
  enforcement decision is undermined regardless of how KP's listener is hardened
  (SC-8).
- **apiserver→kubelet path.** KP pods (webhook, policy-manager, dashboard) run on
  worker nodes whose kubelets the apiserver reaches over TLS. A kubelet that
  serves with a self-signed/unrotated cert, or accepts anonymous/unauthenticated
  control-plane connections, is an integrity and confidentiality gap for the
  workloads KP relies on (SC-8, SC-12).
- **kubelet certificate rotation.** Long-lived or unrotated kubelet certificates
  defeat key-lifetime hygiene (SC-12) and are a standing CIS finding.

These are assessed (CA-2) using the upstream CIS Kubernetes Benchmark via
`kube-bench`; expected results are recorded as ATO evidence (below).

## Conformance checklist

Each row maps a prerequisite to its CIS Kubernetes Benchmark control ID, the
expected setting, and how to verify it with `kube-bench`. CIS control numbering
follows the upstream CIS Kubernetes Benchmark; confirm the exact section numbers
against the benchmark version your `kube-bench` build targets (numbering shifts
slightly across benchmark releases) before recording results — `REQUIRES
VERIFICATION` against the pinned benchmark version.

### kube-apiserver TLS (CIS §1.2.x)

| CIS ID | Control | Expected | NIST | How to verify |
|---|---|---|---|---|
| CIS 1.2.x — apiserver TLS cert/key | `--tls-cert-file` and `--tls-private-key-file` set | apiserver serves with an operator-provided cert/key | SC-8, SC-12 | `kube-bench run --targets master` — apiserver TLS file checks |
| CIS 1.2.x — apiserver→kubelet client cert | `--kubelet-client-certificate` and `--kubelet-client-key` set | apiserver authenticates to kubelets with a client cert (mutual trust) | SC-8 | `kube-bench run --targets master` |
| CIS 1.2.x — apiserver→kubelet CA | `--kubelet-certificate-authority` set | apiserver **verifies** the kubelet serving cert (no skip-verify) | SC-8, SC-12 | `kube-bench run --targets master` |
| CIS 1.2.x — apiserver TLS cipher floor | `--tls-cipher-suites` restricted to strong AEAD/PFS suites; min version ≥ TLS 1.2 (prefer 1.3) | weak/CBC/RC4/3DES suites excluded | SC-8, SC-13 | `kube-bench run --targets master` |

> The exact CIS IDs in §1.2 for the four apiserver items above vary by benchmark
> version (they are the apiserver TLS / kubelet-client / cipher-suite checks).
> Map them to the precise numbers from the pinned benchmark when recording
> evidence; do not assert a specific sub-number here that the benchmark version
> may have renumbered.

### kubelet TLS & certificate rotation (CIS §4.2.x)

| CIS ID | Control | Expected | NIST | How to verify |
|---|---|---|---|---|
| CIS 4.2.1 | Anonymous auth disabled | `--anonymous-auth=false` (kubelet config `authentication.anonymous.enabled: false`) | SC-8, AC-3 | `kube-bench run --targets node` |
| CIS 4.2.2 | Authorization mode not `AlwaysAllow` | `--authorization-mode=Webhook` | AC-3 | `kube-bench run --targets node` |
| CIS 4.2.3 | Client CA configured | `--client-ca-file` set | SC-8, SC-12 | `kube-bench run --targets node` |
| CIS 4.2.x | Read-only port disabled | `--read-only-port=0` | SC-8 | `kube-bench run --targets node` |
| CIS 4.2.x | Kubelet serving certificate | `--tls-cert-file` / `--tls-private-key-file` set (no self-signed serving cert) | SC-8, SC-12 | `kube-bench run --targets node` |
| CIS 4.2.x | Kubelet serving-cert rotation | `RotateKubeletServerCertificate=true` / `serverTLSBootstrap: true` | SC-12 | `kube-bench run --targets node` |
| CIS 4.2.x | Kubelet client-cert rotation | `--rotate-certificates=true` (kubelet config `rotateCertificates: true`) | SC-12 | `kube-bench run --targets node` |
| CIS 4.2.x | Strong kubelet TLS cipher suites | `--tls-cipher-suites` restricted to strong AEAD/PFS suites | SC-8, SC-13 | `kube-bench run --targets node` |

> Within §4.2 the early items (anonymous auth, authorization mode, client CA) are
> stably numbered 4.2.1–4.2.3 across recent benchmarks; the read-only-port,
> serving-certificate, rotation, and cipher-suite items have shifted numbers
> across versions and are shown as `4.2.x`. Bind each to its exact number from
> the benchmark version your `kube-bench` build targets before recording results.

## Verification tooling — kube-bench

A ready-to-apply `kube-bench` Job manifest is provided at
`deployments/kubernetes/conformance/kube-bench-job.yaml` (authored separately).
It runs Aqua Security `kube-bench` in-cluster against the CIS Kubernetes
Benchmark and writes results to the Job's logs.

> The Job is the **assessment** mechanism (CA-2). It does not change cluster
> configuration — it reports conformance. Remediation of any failing check is a
> Customer / CSP responsibility (see `CRM.md`); KP cannot remediate
> control-plane or node settings from within its own boundary.

Typical invocation (the manifest pins targets and benchmark version; adjust to
match your distribution):

```console
kubectl apply -f deployments/kubernetes/conformance/kube-bench-job.yaml
kubectl logs job/kube-bench -n <conformance-namespace>
```

For a quick local/manual run on a control-plane node and on a worker node:

```console
# Control-plane (apiserver TLS, §1.2.x):
kube-bench run --targets master

# Worker node (kubelet TLS & rotation, §4.2.x):
kube-bench run --targets node
```

## Expected results (ATO evidence)

For this checklist to support the deployment's authorization, the System Owner
records, per assessed cluster, evidence that:

- Every kube-apiserver TLS check in §1.2.x relevant to this document returns
  **PASS** (apiserver serves TLS with an operator cert, verifies kubelets with a
  CA, authenticates to kubelets with a client cert, and uses a strong cipher
  floor with min version ≥ TLS 1.2 — prefer 1.3).
- Every kubelet check in §4.2.x relevant to this document returns **PASS**
  (anonymous auth disabled, authorization mode not `AlwaysAllow`, client CA set,
  read-only port disabled, serving cert configured, serving-cert and client-cert
  rotation enabled, strong cipher suites).
- Any **FAIL** or **WARN** is triaged: either remediated by the Customer / CSP, or
  recorded as an open weakness in the POA&M (`poam.csv` / `POAM.md`) with a
  scheduled completion. A residual control-plane/node finding that the customer
  accepts is documented as a Customer-Responsibility risk in `CRM.md`, not as a
  KP-owned control.

Retain the raw `kube-bench` output (Job logs or `--outputfile` JSON) as the
dated assessment artifact (CA-2). For **managed** clusters (EKS/GKE/AKS) where
`kube-bench` cannot inspect the control-plane flags, record the provider's CIS
Benchmark attestation for the apiserver items in place of the §1.2.x checks, and
run the §4.2.x node checks where node access permits.

## Related artifacts (cited by path, not linked)

- `CRM.md` — allocation of these controls as Customer-Responsibility / CSP-Inherited.
- `crypto-standards.md` — approved TLS protocol floor and cipher/key strengths (the in-boundary standard these cluster controls must also meet).
- `secure-configuration-baseline.md` — the in-boundary secure-configuration baseline (CM-2/CM-6), including KP's own TLS 1.3 floor.
- `secrets-at-rest.md` — cluster-inherited secret encryption-at-rest (SC-28), the companion inherited control.
- `deployments/kubernetes/conformance/kube-bench-job.yaml` — the in-cluster `kube-bench` assessment Job (authored separately).
- `internal/config/tls.go`, `internal/config/tls_conformance_test.go` — KP's own (in-boundary) TLS floor and its build-gating conformance test.
