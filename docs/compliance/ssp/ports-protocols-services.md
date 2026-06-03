---
title: "Ports, Protocols & Services (PPS)"
control_family: "CM / SC"
version: "0.2.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Ports, Protocols & Services (PPS)

Authoritative listening-port register for Kube-Policies (KP), derived verbatim from the
[system facts sheet](../system-facts.md). FIPS-199 categorization: **Moderate**. Standard:
NIST SP 800-53 Rev 5, FedRAMP Moderate baseline.

This register is referenced by [SSP §4 Ports, Protocols & Services](SSP.md#4-ports-protocols--services)
and is the source of truth for control families CM-7 (least functionality) and SC-7 (boundary
protection). It is reviewed at least **annually** and on any change to a service listener.

> Transport notes below describe the **current** PoC state. Most planes are unauthenticated
> plaintext HTTP today; target hardening (TLS/mTLS, OIDC, authn on metrics) is tracked in the
> [POA&M](../poam.csv) and the [control matrix](../control-matrix.csv) across remediation phases
> P2–P4. Do not read "current" as "authorized".

## Listening ports

| Port | Asset ID | Service | Transport (current) | Protocol | Direction | Purpose | Target state / phase |
|---|---|---|---|---|---|---|---|
| `8443/tcp` | `AST-WH` | admission-webhook AdmissionReview endpoint | TLS 1.3, server-auth only (no client-cert auth) | HTTPS | Inbound from kube-apiserver (`ZONE-EXT`) via `ICX-01` | Serves `/validate` and `/mutate` AdmissionReview requests | apiserver mTLS (P3) |
| `9090/tcp` | `AST-WH` | admission-webhook metrics | HTTP, unauthenticated | HTTP | Inbound from Prometheus (`ZONE-EXT`) via `ICX-03` | Prometheus metrics exposition for the webhook | TLS + authn (P3) |
| `8080/tcp` | `AST-PM` | policy-manager REST API | TLS 1.3 (server-auth); OIDC authN/authZ config-gated (`auth.enabled`, default off) | HTTPS | Inbound from `AST-WH` (`ICX-02`) and `AST-DB` (`ICX-04`) | REST API `/api/v1/*`: policy CRUD, decision intake (`/decisions/internal`), decision feed | TLS 1.3 served (P2); OIDC authZ available, off by default (P3) |
| `9091/tcp` | `AST-PM` | policy-manager metrics | HTTP, unauthenticated | HTTP | Inbound from Prometheus (`ZONE-EXT`) via `ICX-03` | Prometheus metrics exposition for the policy-manager | TLS + authn (P3) |
| `8090/tcp` | `AST-DB` | dashboard BFF (SPA + `/api` + reverse-proxy) | HTTP, no user authn (write-gated by `ALLOW_WRITES`) | HTTP | Inbound from operators/users (`ZONE-EXT`) via `ICX-05` | Serves the `AST-SPA` Svelte dashboard, BFF `/api`, and reverse-proxy `/api/v1`→`AST-PM:8080` | TLS + OIDC login (P3) |
| `9092/tcp` | `AST-DB` | dashboard metrics | HTTP, unauthenticated | HTTP | Inbound from Prometheus (`ZONE-EXT`) via `ICX-03` | Prometheus metrics exposition for the dashboard | TLS + authn (P3) |

## Least-functionality justification (CM-7)

Each listening port below is **required** for the system to function; no other listeners
are opened (CM-7 least functionality). This register is the authoritative enumeration —
any port not listed here is a deviation and is caught by the rendered-manifest gates
(`network-posture-gate` asserts the per-component ingress flows; `restricted.pss` /
`rbac-sa-gate` constrain the workloads).

| Port | Asset ID | Why it must exist (least-functionality justification) | What disables / scopes it |
|---|---|---|---|
| `8443/tcp` | `AST-WH` | **Required.** The validating/mutating AdmissionReview endpoint the kube-apiserver calls (`ICX-01`); without it the webhook performs no admission control. Only `/validate` and `/mutate` are served. | TLS 1.3 server-auth always on; optional client-cert mTLS (`--client-ca-path`); `network-posture-gate` requires apiserver-scoped ingress; `failurePolicy` defaults `Fail`. |
| `9090/tcp` | `AST-WH` | **Required for observability** (SI-4). Prometheus metrics exposition for the webhook; no business logic. Plain HTTP unauthenticated by default. | Optional TLS + bearer authn (`metrics.tls.enabled`); scoped to scraper ingress by NetworkPolicy; can be left unscraped. |
| `8080/tcp` | `AST-PM` | **Required.** The policy-manager REST `/api/v1` (policy/exception CRUD, decision intake `/decisions/internal`, decision feed) consumed by `AST-WH` (`ICX-02`) and `AST-DB` (`ICX-04`). | Serves TLS 1.3 via `BuildServerTLSConfig`; OIDC/authZ config-gated (`security.authentication.enabled`, default off — dev gap); ingress scoped to webhook+dashboard by NetworkPolicy. |
| `9091/tcp` | `AST-PM` | **Required for observability** (SI-4). Prometheus metrics exposition for the policy-manager; no business logic. | Optional TLS + bearer authn (`metrics.tls.enabled`); scoped to scraper ingress. |
| `8090/tcp` | `AST-DB` | **Optional — OFF by default** (`dashboard.enabled=false`). When enabled, serves the `AST-SPA` SPA + BFF `/api` + reverse-proxy `/api/v1`→`AST-PM:8080`. Least-functionality: the whole component is disabled unless the operator opts in, and is **read-only** unless `dashboard.allowWrites=true`. | `dashboard.enabled` gate; `ALLOW_WRITES` write gate; optional in-pod TLS + HSTS; user OIDC login is P3 (config-gated). |
| `9092/tcp` | `AST-DB` | **Optional — OFF by default** (tied to `dashboard.enabled`). Prometheus metrics exposition for the dashboard; no business logic. | Disabled with the dashboard; TLS-gated on `dashboard.tls.enabled`; **not** bearer-authenticated (tracked gap). |

No component opens any listener beyond the six above; `AST-OPA` (embedded), the CRDs, and
`AST-CHART` expose none. This enumeration is reviewed at least annually and on any change to
a service listener (CM-7(1) periodic review; see
[CM-procedures.md](../procedures/CM-procedures.md)).

## Notes

- All listeners run inside the `kube-policies-system` namespace (`ZONE-SYS`). The hosting cluster,
  kube-apiserver, Prometheus scraper, and CSP infrastructure are outside the boundary (`ZONE-EXT`).
- `AST-OPA`, `AST-CRD-POL`, and `AST-CRD-EXC` expose **no** listening ports of their own; the OPA
  evaluator is an embedded library and the CRDs are stored by the kube-apiserver.
- P4 added default-deny + least-privilege-allow NetworkPolicies in the chart and the static base
  manifest that constrain east-west traffic between these listeners (SC-7); **enforcement requires a
  NetworkPolicy-enforcing CNI** (Calico/Cilium/Antrea) and is inert on a non-enforcing CNI (kindnet) —
  see [network-architecture.md](../network-architecture.md).
- Egress: `AST-PM` reaches the kube-apiserver (`ICX-06`) for CRD reconcile and Lease-based leader
  election using its in-cluster ServiceAccount token over TLS.
