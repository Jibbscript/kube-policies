---
title: "Ports, Protocols & Services (PPS)"
control_family: "CM / SC"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
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
| `8080/tcp` | `AST-PM` | policy-manager REST API | HTTP, unauthenticated | HTTP | Inbound from `AST-WH` (`ICX-02`) and `AST-DB` (`ICX-04`) | REST API `/api/v1/*`: policy CRUD, decision intake (`/decisions/internal`), decision feed | TLS 1.3 + OIDC/authZ (P2/P3) |
| `9091/tcp` | `AST-PM` | policy-manager metrics | HTTP, unauthenticated | HTTP | Inbound from Prometheus (`ZONE-EXT`) via `ICX-03` | Prometheus metrics exposition for the policy-manager | TLS + authn (P3) |
| `8090/tcp` | `AST-DB` | dashboard BFF (SPA + `/api` + reverse-proxy) | HTTP, no user authn (write-gated by `ALLOW_WRITES`) | HTTP | Inbound from operators/users (`ZONE-EXT`) via `ICX-05` | Serves the `AST-SPA` Svelte dashboard, BFF `/api`, and reverse-proxy `/api/v1`→`AST-PM:8080` | TLS + OIDC login (P3) |
| `9092/tcp` | `AST-DB` | dashboard metrics | HTTP, unauthenticated | HTTP | Inbound from Prometheus (`ZONE-EXT`) via `ICX-03` | Prometheus metrics exposition for the dashboard | TLS + authn (P3) |

## Notes

- All listeners run inside the `kube-policies-system` namespace (`ZONE-SYS`). The hosting cluster,
  kube-apiserver, Prometheus scraper, and CSP infrastructure are outside the boundary (`ZONE-EXT`).
- `AST-OPA`, `AST-CRD-POL`, and `AST-CRD-EXC` expose **no** listening ports of their own; the OPA
  evaluator is an embedded library and the CRDs are stored by the kube-apiserver.
- No NetworkPolicy currently constrains east-west traffic between these listeners; ingress filtering
  is a tracked gap (SC-7, remediated in P3).
- Egress: `AST-PM` reaches the kube-apiserver (`ICX-06`) for CRD reconcile and Lease-based leader
  election using its in-cluster ServiceAccount token over TLS.
