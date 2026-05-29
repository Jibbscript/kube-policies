---
title: "Interconnection Register"
control_family: "CA-3 / SC-7 — Interconnections & Boundary Protection"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Interconnection Register — Kube-Policies (KP)

This register enumerates every interconnection (`ICX-01..06`) of the Kube-Policies (KP) system
(**FIPS-199 Moderate**; NIST SP 800-53 Rev 5 / FedRAMP Moderate baseline), per CA-3 and SC-7.
It is derived verbatim from the [System Facts Sheet](system-facts.md) and is the tabular
companion to the [Authorization Boundary Diagram](diagrams/authorization-boundary.md) and the
[Data Flow Diagram](diagrams/data-flow.md). Referenced from the [SSP](ssp/SSP.md).

**Annual review.** This register is reviewed at least annually (next review **2027-05-29**) and
whenever an interconnection, its sensitivity, or its protection mechanism materially changes.

## Scope and classification

- **Trust zones.** `ZONE-EXT` = outside the boundary (kube-apiserver, Prometheus, operators/
  users, CSP). `ZONE-SYS` = inside the boundary (`kube-policies-system` namespace workloads and
  CRDs).
- **Boundary-crossing interconnections** (`ZONE-EXT` ↔ `ZONE-SYS`): `ICX-01`, `ICX-03`,
  `ICX-05`, `ICX-06`.
- **Internal interconnections** (`ZONE-SYS` only): `ICX-02`, `ICX-04`. Listed for completeness;
  they remain in scope for SC-7/SC-8 because they currently traverse unauthenticated/cleartext
  HTTP within the namespace.
- **Information types.** IT-1 configuration & policy data, IT-2 admission decision audit records,
  IT-3 operational metrics (see facts sheet).

## Register

| ICX ID | From → To | Boundary crossing | Data type (IT) | Sensitivity | Protocol (current) | Protection mechanism (current) | Target protection |
|---|---|---|---|---|---|---|---|
| `ICX-01` | kube-apiserver (`ZONE-EXT`) → `AST-WH:8443` | Yes (EXT→SYS) | AdmissionReview request/response — object specs (IT-1) | **Moderate** | TLS 1.3 | **TLS 1.3, server-auth only** (no client-cert) | + apiserver **mTLS** (P3) |
| `ICX-02` | `AST-WH` → `AST-PM:8080` `/api/v1/decisions/internal` | No (SYS internal) | Admission decision records + bearer token (IT-2) | **Moderate** | HTTP | **Cleartext HTTP + static bearer token** | TLS + audience-bound token (P3/P4) |
| `ICX-03` | Prometheus (`ZONE-EXT`) → `:9090` / `:9091` / `:9092` | Yes (EXT→SYS) | Operational metrics exposition (IT-3) | **Low–Moderate** | HTTP | **Unauthenticated cleartext HTTP** | TLS + authn (P3) |
| `ICX-04` | `AST-DB` → `AST-PM:8080` (`/api/v1`, decisions stream) | No (SYS internal) | Policy data + decision feed (IT-1/IT-2) | **Moderate** | HTTP | **Cleartext HTTP** | TLS (P4) |
| `ICX-05` | Operators/Users (`ZONE-EXT`) → `AST-DB:8090` | Yes (EXT→SYS) | Dashboard UI / API (IT-1/IT-2) | **Moderate** | HTTP | **Cleartext HTTP, no user authn** (writes gated by `ALLOW_WRITES`) | TLS + OIDC login (P3) |
| `ICX-06` | `AST-PM` ↔ kube-apiserver (`ZONE-EXT`) | Yes (SYS↔EXT) | `Policy`/`PolicyException` CRD reconcile + Lease (IT-1) | **Moderate** | In-cluster TLS | **kubeconfig / ServiceAccount token over in-cluster TLS** | least-privilege SA (P3) |

## Risk notes per interconnection

- **`ICX-01`** — Strongest current control: TLS 1.3 is pinned (`internal/config`). Residual gap
  is the absence of client-certificate (mutual) authentication of the apiserver, so the webhook
  cannot cryptographically verify the caller. Remediated in **P3**.
- **`ICX-02`** — Decision audit records (IT-2, attributable allow/deny) traverse cleartext HTTP
  protected only by a **static** bearer token. Within-namespace, but token replay and disclosure
  are the residual risks. Remediated in **P3/P4**.
- **`ICX-03`** — Metrics are unauthenticated cleartext; lowest data sensitivity but exposes
  operational signal and is reachable by any in-cluster peer absent a NetworkPolicy. Remediated
  in **P3**.
- **`ICX-04`** — Internal dashboard feed over cleartext HTTP carries policy and decision data
  (Moderate). Remediated in **P4**.
- **`ICX-05`** — The only human-facing external plane: cleartext HTTP with **no user
  authentication**. Writes are gated by `ALLOW_WRITES` (default read-only), which limits
  integrity exposure but not confidentiality. Remediated in **P3** (TLS + OIDC).
- **`ICX-06`** — Uses the platform's in-cluster TLS and SA token; residual risk is an overly
  broad ServiceAccount. Least-privilege RBAC scoping is a **P3** target.

All residual weaknesses above are tracked in the [POA&M](poam.csv) and mapped to controls in the
[control matrix](control-matrix.csv); remediation phases reference
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md` (P1–P12).
