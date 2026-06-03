---
title: "Identification & Authentication Procedures (IA) — Kube-Policies (KP)"
control_family: "IA — Identification and Authentication"
controls: "IA-1, IA-2, IA-5"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Identification & Authentication Procedures (IA) — Kube-Policies (KP)

These are the operational procedures that implement the KP Identification &
Authentication policy (`docs/compliance/policies/IA-policy.md`) for the **FIPS-199
Moderate** Proof-of-Concept. They are the **how-to** companion to the IA-1 policy and cover
the authenticators KP actually manages today: the **shared internal bearer token**, the
**TLS serving certificates**, and the **webhook client-CA (mTLS) bundle**. Part of the
[compliance evidence package](../README.md).

Kube-Policies is **not yet authorized** (no ATO). Steps below reflect the **as-built**
chart and binaries; where a step is not yet wired into the chart it is flagged **(gap —
tracked in POA&M)** rather than presented as complete. Per-user OIDC login is **Planned
(phase P3)** and has **no operational procedure yet**.

## Annual review

These procedures are reviewed and updated at least **annually** (next scheduled review
**2027-05-31**) and whenever the token tooling, the certificate issuance path, the
client-CA management, or the set of interfaces materially changes. The ISSO (TBD — assign
before assessment) performs the review; the AO (TBD — assign before assessment) re-approves
as part of the IA posture.

## 1 Internal bearer-token procedures (IA-5, IA-5(1))

### 1.1 Generating a token

Generate the token from a **FIPS-validated CSPRNG** — never from a template-time RNG such
as Helm's `randAlphaNum`. Acceptable sources:

- the project tooling calling `auth.GenerateToken` (`internal/auth/token.go`), which reads
  `crypto/rand` (the validated DRBG under the GOFIPS140 build; see
  `docs/compliance/crypto-module.md`); or
- `openssl rand -base64 32` on a FIPS-enabled host.

The generated token carries **256 bits** of entropy (`DefaultTokenBytes = 32`).

### 1.2 Storing and injecting the token

The token is stored in the Kubernetes Secret `<release>-internal-token` and injected into
the admission-webhook (sender), policy-manager, and dashboard via environment variables.
The verifier **fails closed**: an empty/unset token disables the endpoint entirely (every
request returns 401), so an empty value must never be treated as "auth off but allow".

### 1.3 Zero-downtime rotation (the two-token window)

The verifier accepts a **current** and a **previous** token simultaneously
(`internal/auth/token.go`). Full step-by-step rotation — including the environment-variable
mapping per service (`POLICY_MANAGER_INTERNAL_TOKEN` / `..._PREVIOUS`, `INTERNAL_TOKEN` /
`INTERNAL_TOKEN_PREVIOUS`), the pod-roll sequence, and verification (a `204` from
`POST /api/v1/decisions/internal`) — is in the runbook
`docs/runbooks/internal-token-rotation.md`. The summary:

1. Set the **previous**-token variables on the verifying services to the in-use token, so
   both old and new are accepted during the window.
2. Set the **new current** token everywhere that holds it and update the
   `<release>-internal-token` Secret.
3. Roll the pods; both tokens are accepted, so no in-flight caller is rejected.
4. Close the window: clear the previous-token variables and roll again — only the new
   token is now accepted.

### 1.4 Key-compromise response

If the token is believed compromised, **skip the window**: set the new token everywhere,
leave the previous-token variables empty, and roll immediately. The compromised token is
rejected as soon as each pod restarts. Record the event and any risk acceptance in the
POA&M (`docs/compliance/poam.csv`).

### 1.5 Known gap

Chart-side CSPRNG generation of the token (a Job replacing the demo-only `randAlphaNum`
autogeneration) and surfacing the previous-token Secret key are the **remaining Helm
portion** and are **(gap — tracked in POA&M)** (`docs/compliance/poam.csv`).

## 2 TLS serving-certificate procedures (IA-5(2))

### 2.1 Production (cert-manager)

With `certManager.enabled=true`, certificates are **ECDSA P-256** issued by a cert-manager
Issuer/Certificate from a shared root-CA bootstrap, each in its own Secret
(`<release>-admission-webhook-certs`, `<release>-policy-manager-certs`,
`<release>-dashboard-certs`). Renewal is **automatic** (`renewBefore` expiry) and picked up
**without a restart** by the hot reloader (`internal/tlsreload`). No operator action is
required unless renewal fails.

### 2.2 Demo / self-signed (DEMO-ONLY)

With `certManager.enabled=false`, a self-signed **RSA-2048** certificate is generated for
demonstration only; it must **not** be used in an authorized deployment. Regenerate with
`scripts/gen-webhook-cert.sh <namespace>` (ECDSA P-256); the reloader serves the new
certificate with no restart.

### 2.3 Expiry monitoring and rotation verification

Each TLS server publishes `kube_policies_tls_cert_expiry_seconds{component=...}`, alerted
by `KubePoliciesCertExpiringSoon` (<7 days) and `KubePoliciesCertExpired`. The full
diagnose/rotate/verify procedure is in `docs/runbooks/cert-rotation.md`. After rotation,
confirm the expiry gauge jumps forward and the reloader logged `certificate reloaded`.

## 3 Webhook client-CA (mTLS) management (IA-2, IA-3)

mTLS on the admission-webhook is **optional** and **off by default**. When enabled it
authenticates the calling client (e.g. the API server) by certificate.

### 3.1 Enabling mTLS

1. Obtain the CA bundle that signs the clients you intend to accept (for the API server,
   the cluster's apiserver client CA). Mount it into the webhook pod.
2. Start the webhook with `--client-ca-path=<bundle path>` (the flag wins over any
   config-file value) **and** set `security.tls.client_auth=require`. With a non-nil CA
   pool present, the listener enforces `RequireAndVerifyClientCert`
   (`internal/config/tls.go`, `BuildServerTLSConfig`).
3. Confirm enforcement: the startup log emits `mtls_enforced=true`. If the bundle is
   **absent** while `client_auth=require`, the binary **warns** and falls back to
   **server-auth-only (permissive)** mode (`mtls_enforced=false`) — it does **not** silently
   claim mTLS. Treat that state as a deviation to risk-accept and track in the POA&M.

### 3.2 Rotating the client-CA bundle

When the client CA rotates, replace the mounted bundle (Secret/ConfigMap) with the new CA;
the reloader does **not** watch the client-CA bundle the way it watches the serving cert,
so a controlled restart/roll of the webhook is required to load a changed client CA.
Validate that `LoadClientCAPool` parsed at least one certificate (a bundle that parses to
zero certs is a **hard error** by design, preventing an empty pool from rejecting every
client). Record CA changes alongside the certificate inventory.

### 3.3 Empty-bundle safety

`LoadClientCAPool` (`internal/config/tls.go`) returns an error rather than an empty pool, so
a misconfigured bundle fails fast at startup instead of breaking every handshake under
`RequireAndVerifyClientCert`. Do not work around this by disabling client_auth in
production; fix the bundle.

## 4 Interactive user authentication (Planned — P3)

There is **no** operational user-login procedure today: KP performs no per-user
authentication and ships no login/session/cookie path. Until OIDC (P3) lands, interactive
access is governed by **cluster RBAC / the cluster IdP** (Customer-Responsibility;
`docs/compliance/CRM.md`), and the dashboard remains **read-only by default** (`ALLOW_WRITES`
must be explicitly enabled for write verbs; `cmd/dashboard/proxy.go`). When OIDC is
implemented, this section will be expanded with provisioning, MFA, and de-provisioning
steps and re-reviewed.

## 5 Records

- Token rotations and compromise responses: recorded per `docs/runbooks/internal-token-rotation.md`; risk acceptances in `docs/compliance/poam.csv`.
- Certificate rotations / renewal failures: recorded per `docs/runbooks/cert-rotation.md`.
- Client-CA changes: recorded alongside the certificate inventory and the system facts (`docs/compliance/system-facts.md`).

## 6 References

- IA policy: `docs/compliance/policies/IA-policy.md`
- e-authentication determination: `docs/compliance/e-authentication.md`
- Internal token rotation runbook: `docs/runbooks/internal-token-rotation.md`
- TLS certificate rotation runbook: `docs/runbooks/cert-rotation.md`
- Auth / TLS code: `internal/auth/token.go`, `internal/auth/middleware.go`, `internal/config/tls.go`, `internal/tlsreload`
- Cert tooling: `scripts/gen-webhook-cert.sh`
- Secrets: `<release>-internal-token`, `<release>-admission-webhook-certs`, `<release>-policy-manager-certs`, `<release>-dashboard-certs`, `<release>-audit-integrity`
- Compliance index: [README](../README.md)
- NIST SP 800-53 Rev 5 (IA-2, IA-3, IA-5, IA-5(1), IA-5(2)); FedRAMP Moderate baseline.
