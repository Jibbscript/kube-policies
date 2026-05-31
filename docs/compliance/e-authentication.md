---
title: "e-Authentication Determination — Kube-Policies (KP)"
control_family: "IA — Identification and Authentication"
controls: "IA-2, IA-5, IA-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# e-Authentication Determination — Kube-Policies (KP)

This is the FedRAMP **e-authentication determination** for the Kube-Policies (KP) system
(**FIPS-199 Moderate**; FedRAMP Moderate baseline). It assigns an **authenticator-assurance
posture** to **each** electronic interface KP exposes, following the intent of NIST SP
800-63 (digital identity / authenticator assurance, AAL) as applied to FedRAMP. Part of the
[compliance evidence package](README.md). The governing policy is
`docs/compliance/policies/IA-policy.md` and the operational steps are
`docs/compliance/procedures/IA-procedures.md`.

> **Honesty note.** Kube-Policies is a **Proof-of-Concept, not yet authorized** (no ATO).
> KP performs **no interactive human-user authentication** on any of its own interfaces
> today. The only authenticated identities are **service identities** (the inter-service
> calls), via a shared internal bearer token, optional webhook mutual TLS, and a TLS 1.3
> transport floor. **Per-user OIDC authentication is Planned (phase P3)** and is **not**
> implemented; the assurance levels below for interactive *user* access are therefore
> **inherited from the cluster's RBAC / IdP**, which is **Customer-Responsibility** (see
> `docs/compliance/CRM.md`). Where a user-facing AAL is asserted, it is asserted of the
> **inherited cluster IdP**, not of KP itself.

## Annual review

This determination is reviewed and updated at least **annually** (next scheduled review
**2027-05-31**) and whenever a new interactive interface is added, the OIDC capability
(P3) lands, the transport posture changes, or the authorization boundary changes. The ISSO
(TBD — assign before assessment) performs the review; the AO (TBD — assign before
assessment) re-approves the determination.

## 1 Method

For each electronic interface KP exposes we record: who/what authenticates, the
authenticator and its lifecycle management, the transport, and an assurance posture.
Because KP itself does not authenticate human users yet, interfaces are classified as one
of:

- **Service-to-service (M2M):** machine identity authenticated by KP today.
- **Interactive (user):** human access — currently **inherited** from cluster RBAC / IdP;
  native OIDC is **Planned (P3)**.

"Assurance posture" is expressed against the spirit of NIST SP 800-63 authenticator
assurance levels (AAL); it is **not** a claim of a completed 800-63 assessment.

## 2 Interface determinations

### 2.1 Dashboard BFF (`AST-DB` / `AST-SPA`)

- **Class:** Interactive (user-facing UI + `/api/v1/*` reverse proxy).
- **Interactive user authentication (KP-native):** **None implemented.** There is no
  login, session, or cookie code path in the dashboard. Native **OIDC** user login is
  **Planned (P3)** and tracked in `docs/compliance/poam.csv`.
- **Effective user identity / assurance:** **Inherited** from the cluster RBAC / IdP that
  fronts access to the namespace and the dashboard (Customer-Responsibility;
  `docs/compliance/CRM.md`). The AAL of interactive access is therefore the AAL of the
  **customer's IdP**, not of KP. The customer must front the dashboard with an
  authenticating ingress/IdP to reach **AAL2** for a Moderate system; KP makes no AAL claim
  on its own behalf.
- **Authorization guard-rail KP provides:** **read-only by default** — write verbs
  (POST/PUT/PATCH/DELETE) return **403** unless `ALLOW_WRITES=true` is explicitly set
  (`cmd/dashboard/proxy.go`, `cmd/dashboard/config.go`). This is an authorization gate, not
  user authentication.
- **Transport:** optional TLS 1.3 with optional **HSTS** (`DASHBOARD_HSTS_ENABLED`,
  `cmd/dashboard/config.go`); the dashboard's outbound metrics endpoint can be served over
  TLS 1.3 with bearer auth when `metrics.tls.enabled`.
- **Determination:** **KP-native user AAL: not applicable (no native user auth).
  Inherited from cluster IdP; native OIDC Planned (P3).**

### 2.2 Policy-manager API (`AST-PM`)

- **Class:** mixed — a **service-to-service** internal decision API plus an
  administrative/read API surface.
- **Service authentication (KP-native, Implemented/Partial):** the internal decision path
  (`POST /api/v1/decisions/internal`) is authenticated with the **shared internal bearer
  token**, verified **constant-time** and **fail-closed** (`internal/auth/token.go`,
  `internal/auth/middleware.go`). The token is FIPS-CSPRNG-generated and rotatable via a
  two-token window (IA-5(1)). This is a **shared service credential** — equivalent to a
  single M2M authenticator, **not** a per-user identity.
- **Interactive user authentication (KP-native):** **None implemented.** Per-user **OIDC**
  on the API is **Planned (P3)**; until then human/admin access is mediated by cluster
  RBAC / IdP (inherited; `docs/compliance/CRM.md`).
- **Transport:** serves **TLS 1.3**; metrics endpoint optional TLS 1.3 + bearer auth
  (`metrics.tls.enabled`, CRY-WU-08).
- **Determination:** **Service identity: shared bearer token (single M2M authenticator),
  constant-time + FIPS-CSPRNG + rotation window. User AAL: not applicable (no native user
  auth); inherited from cluster IdP; native OIDC Planned (P3).**

### 2.3 Admission-webhook mutual TLS / TLS 1.3 client-auth (`AST-WH`)

- **Class:** Service-to-service (M2M) — the API server (or other client) calls the webhook.
- **Authentication posture:**
  - **Server authentication (always):** the webhook presents a serving certificate over a
    **TLS 1.3** floor (config-driven; floor enforced at load,
    `internal/config/tls.go`). Production certs are **ECDSA P-256** via cert-manager; the
    DEMO-ONLY path is self-signed RSA-2048.
  - **Client (mutual) authentication (optional):** when started with a client-CA bundle
    (`--client-ca-path` / `security.tls.client_ca_path`) **and** `client_auth=require`,
    the listener enforces `RequireAndVerifyClientCert`
    (`internal/config/tls.go`, `BuildServerTLSConfig`), authenticating the **caller's
    certificate**. With **no** client-CA bundle the listener falls back to
    **server-auth-only (permissive)** — this is **not** mTLS, and the binary warns
    (`mtls_enforced=false`) when `client_auth=require` is set without a bundle.
- **Authenticator management:** serving certs rotate automatically under cert-manager (hot
  reload, no restart; `docs/runbooks/cert-rotation.md`); the client-CA bundle is managed
  per `docs/compliance/procedures/IA-procedures.md` (controlled restart to load a changed
  client CA).
- **Determination:** **M2M. Server-auth TLS 1.3 always; certificate-based client auth
  (mTLS) when a client-CA bundle is supplied with `client_auth=require`, otherwise
  permissive server-auth-only (a documented, risk-acceptable default).**

### 2.4 Metrics endpoints

- **Class:** Service-to-service (Prometheus scrape).
- **Authentication:** when `metrics.tls.enabled`, the **webhook (`:9090`) and policy-manager
  (`:9091`)** `/metrics` are served over **TLS 1.3** and wrapped with the **constant-time
  bearer-token** check (`auth.RequireBearer`, CRY-WU-08); health probes (`/healthz`,
  `/readyz`) are intentionally unauthenticated for kubelet. The **dashboard `/metrics`
  (`:9092`)** is served over TLS only when `dashboard.tls.enabled` and is **not**
  bearer-authenticated (a tracked gap — the dashboard binary has no metrics-auth wiring yet).
- **Determination:** **M2M. Optional TLS 1.3 + shared bearer token on the webhook/PM metrics;
  off by default. Dashboard metrics is TLS-optional, unauthenticated.**

## 3 Summary table

| Interface | Class | KP-native authentication today | Effective assurance posture | OIDC user auth |
|---|---|---|---|---|
| Dashboard BFF (`AST-DB`/`AST-SPA`) | Interactive | None (read-only by default; `ALLOW_WRITES` gate only) | User AAL **inherited** from cluster IdP (Customer); KP makes no AAL claim | **Planned (P3)** |
| Policy-manager API (`AST-PM`) | M2M + admin | Shared internal bearer token (constant-time, FIPS-CSPRNG, rotation window); TLS 1.3 | M2M: single shared authenticator. User AAL **inherited** | **Planned (P3)** |
| Webhook mTLS / TLS 1.3 client-auth (`AST-WH`) | M2M | Server-auth TLS 1.3 always; cert-based client auth (mTLS) when client-CA + `client_auth=require` | Server-auth always; mutual auth when configured, else permissive | n/a (M2M) |
| Metrics endpoints | M2M | Optional TLS 1.3 + bearer token (`metrics.tls.enabled`) | M2M shared authenticator; off by default | n/a (M2M) |

## 4 Conclusion

KP today provides **machine-to-machine** authentication (shared bearer token, optional
webhook mTLS) over a **TLS 1.3** floor, with FIPS-CSPRNG-generated, rotatable
authenticators. KP performs **no native interactive user authentication**; user-level
assurance for the dashboard and policy-manager API is **inherited from the customer's
cluster RBAC / IdP** and must be configured by the customer to meet the Moderate baseline.
Native **OIDC** user authentication is **Planned (phase P3)** and tracked in the POA&M
(`docs/compliance/poam.csv`); when it lands, this determination will be revised to assert a
KP-native user AAL and re-reviewed.

## 5 References

- IA policy: `docs/compliance/policies/IA-policy.md`
- IA procedures: `docs/compliance/procedures/IA-procedures.md`
- Auth / TLS code: `internal/auth/token.go`, `internal/auth/middleware.go`, `internal/config/tls.go`
- Dashboard write gate / HSTS: `cmd/dashboard/proxy.go`, `cmd/dashboard/config.go`
- Crypto module: `docs/compliance/crypto-module.md`; secrets: `docs/compliance/secrets-at-rest.md`
- CRM (inherited / customer responsibilities): `docs/compliance/CRM.md`; system facts: `docs/compliance/system-facts.md`; POA&M: `docs/compliance/poam.csv`
- Compliance index: [README](README.md)
- NIST SP 800-63 (digital identity / AAL); NIST SP 800-53 Rev 5 (IA-2, IA-5, IA-8); FedRAMP Moderate baseline; FIPS-199.
