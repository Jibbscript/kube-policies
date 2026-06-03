---
title: "Audit Storage & Stream Access-Control Model — Kube-Policies (KP)"
control_family: "AU / AC — Audit and Accountability & Access Control"
controls: "AU-9, AC-3, AC-6"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Audit Storage & Stream Access-Control Model — Kube-Policies (KP)

This document describes how Kube-Policies (KP) protects access to **audit
information** — both the at-rest audit log and the live decision feeds — mapped to
NIST SP 800-53 Rev 5 **AU-9 (Protection of Audit Information)**, **AC-3 (Access
Enforcement)**, and **AC-6 (Least Privilege)**. It complements the
[IAM control narrative](../compliance/iam-control-narrative.md) and the
[control matrix](../compliance/control-matrix.csv).

Kube-Policies is **not yet authorized** (no ATO). This document claims only what the
shipped code and chart enforce; forward-looking items (a SIEM/log-forwarder
identity) are labeled as such and are **not** presented as done.

## 1 At-rest audit log protection (AU-9)

The file audit backend writes records to a pod-private file with restrictive
permissions:

- The audit **file** is opened `0600` (owner read/write only) —
  `internal/audit/logger.go:420`:
  `os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)`.
- The containing **directory** is created `0750` —
  `internal/audit/logger.go:416`: `os.MkdirAll(filepath.Dir(filename), 0o750)`.
- The default path is `/var/log/kube-policies/audit.log`
  (`internal/audit/logger.go`), on a **pod-private volume**. There is **no
  API-level read surface** for this file: KP exposes no HTTP/gRPC endpoint that
  serves the audit log, and no Kubernetes resource maps to it.

Tamper-evidence over the at-rest records (HMAC-SHA256 chaining,
`internal/audit/integrity.go`, AU-9(3)) is documented in the IA policy
(`../compliance/policies/IA-policy.md` §4.4) and the crypto inventory.

**Consequence for access control.** Because the audit log has **no API-exposed
read resource**, there is **no separate Kubernetes "audit-reader" RBAC role** —
there is nothing for such a role to authorize access to. Read access to the file is
governed by **pod/node-level controls** (the `0600` file mode, the pod's filesystem
isolation, and the cluster's node-access controls), not by an application RBAC role.
Claiming an audit-reader RBAC role here would overstate the design; none exists by
intent.

## 2 Live decision-feed protection (AC-3, Inc7 Stream A)

The decision/SSE endpoints are part of the service-to-service decisions plane and,
as of Inc7 Stream A, **all require authentication** — none is unauthenticated
(`internal/policymanager/router.go`, `internal/policymanager/decisions_handler.go`):

| Endpoint | Method | Authenticated identity | Mechanism |
|---|---|---|---|
| `/api/v1/decisions/internal` | `POST` | the **webhook SA** | audience+subject-bound TokenReview pinned to the webhook SA (`IngestInternal` → `m.internalReviewer`) |
| `/api/v1/decisions/stream` | `GET` (SSE) | the **dashboard SA** | `DecisionsReadAuth` middleware → audience+subject-bound TokenReview pinned to the dashboard SA (`m.decisionsReadReviewer`) |
| `/api/v1/decisions/recent` | `GET` | the **dashboard SA** | same `DecisionsReadAuth` middleware |

Authentication properties (`internal/policymanager/tokenreview.go`,
`decisions_handler.go`):

- The TokenReview is created with the expected **audience** in `Spec.Audiences`; a
  verdict is accepted only when the apiserver authenticated the token **and** echoed
  the expected audience back **and** (when configured) the `Status.User.Username`
  matches the expected SA subject. An empty `Status.Audiences` cannot wildcard-match.
- A **missing bearer** is rejected `401`; a **TokenReview API error fails closed**
  (rejected, never falling through to the static path).
- The static internal token (`internal/auth/token.go`, constant-time `Verify`) is an
  **opt-in fallback for non-cluster/demo (`mode=static`)** deployments only, reached
  on a clean negative verdict or when no reviewer is configured.

This closes the previously unauthenticated read feeds: a caller without a valid
dashboard-SA (or static) credential cannot read the live or recent decision stream.

## 3 Least privilege over audit access (AC-6)

- The **read feeds** are pinned to the **dashboard SA** specifically (not "any
  authenticated SA"), so only the intended consumer can subscribe.
- The **ingest** endpoint is pinned to the **webhook SA** specifically.
- The dashboard's Kubernetes Role grants **no** audit/CRD/Secret access
  (`charts/kube-policies/templates/dashboard-rbac.yaml`); its access to decision
  data is solely via the authenticated stream above, not via cluster RBAC.

## 4 Forward-looking: SIEM / log-forwarder identity (not yet implemented)

A future centralized audit pipeline (forwarding the `0600` file or the live stream
to a SIEM, AU-9(2)/AU-9(4)) **would** receive a **dedicated, least-privilege
identity** — its own ServiceAccount/credential scoped to read-only consumption,
separate from the webhook and dashboard SAs. This is **forward-looking design, not a
claimed control**; it is tracked for a later phase in the
[control matrix](../compliance/control-matrix.csv) and
[POA&M](../compliance/poam.csv) (AU-9(2)/(4), audit forwarding). No SIEM-reader
identity ships today.

## 5 Control mapping

| Control | Coverage | Enforcing artifact |
|---|---|---|
| **AU-9** Protection of Audit Information | At-rest `0600` file, `0750` dir, no API read surface | `internal/audit/logger.go:416`, `internal/audit/logger.go:420` |
| **AC-3** Access Enforcement | Decision feeds require service-token auth (Inc7); fail-closed | `internal/policymanager/decisions_handler.go`, `internal/policymanager/router.go` |
| **AC-6** Least Privilege | Read feed pinned to dashboard SA; ingest pinned to webhook SA; dashboard Role has no audit access | `internal/policymanager/tokenreview.go`, `charts/kube-policies/templates/dashboard-rbac.yaml` |

## 6 References

- IAM control narrative: [../compliance/iam-control-narrative.md](../compliance/iam-control-narrative.md)
- IA policy (audit-chain key, §4.4): [../compliance/policies/IA-policy.md](../compliance/policies/IA-policy.md)
- Control matrix / POA&M: [../compliance/control-matrix.csv](../compliance/control-matrix.csv), [../compliance/poam.csv](../compliance/poam.csv)
- Audit code: `internal/audit/logger.go`, `internal/audit/integrity.go`
- Decision-plane code: `internal/policymanager/decisions_handler.go`, `internal/policymanager/tokenreview.go`, `internal/policymanager/router.go`
- Dashboard RBAC: `charts/kube-policies/templates/dashboard-rbac.yaml`
- NIST SP 800-53 Rev 5 (AU-9, AU-9(2), AU-9(3), AU-9(4), AC-3, AC-6); FedRAMP Moderate baseline.
