---
title: "Identification & Authentication Policy (IA) — Kube-Policies (KP)"
control_family: "IA — Identification and Authentication"
controls: "IA-1, IA-2, IA-5"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Identification & Authentication Policy (IA) — Kube-Policies (KP)

This policy addresses the NIST SP 800-53 Rev 5 **Identification and Authentication
(IA)** family for the Kube-Policies (KP) system, categorized **FIPS-199 Moderate**
under the FedRAMP **Moderate** baseline. It establishes the **IA-1** policy artifact
and documents how **IA-2** (identification and authentication of organizational users
and processes) and **IA-5** (authenticator management) are currently implemented for
KP's interfaces and inter-service traffic. Part of the [compliance evidence
package](../README.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**;
it is **not yet authorized** (no ATO). The management and enforcement planes are
actively being hardened. This policy claims **only what the shipped code and chart
implement**, and marks everything else **Planned**. Per-control status is tracked in the
control matrix (`docs/compliance/control-matrix.csv`) and open weaknesses in the POA&M
(`docs/compliance/poam.csv`); operational steps live in the companion procedures
(`docs/compliance/procedures/IA-procedures.md`).

> **Scope honesty note.** KP does **not** yet implement interactive *human-user*
> authentication on any of its own interfaces. The identities KP authenticates today are
> **service identities** (the inter-service calls between the admission webhook,
> policy-manager, and dashboard) using a shared internal bearer token, optional webhook
> mutual TLS (mTLS), and a TLS 1.3 transport floor. **Per-user OIDC login** on the
> dashboard and policy-manager API is **Planned (phase P3)** and is **not** wired into any
> login, session, or token-verification code path. A configuration stanza for
> authentication providers exists in `internal/config/config.go` (`AuthProvider.Type`
> enumerating `"oidc"`, `"ldap"`, `"cert"`), but it is a **declared-but-unimplemented**
> structure — it does not authenticate anyone. Human access to the cluster, and therefore
> to KP's namespaced resources, is governed by **Kubernetes RBAC and the cluster's IdP**,
> which are **Customer-Responsibility / inherited** (see `docs/compliance/CRM.md`).

## Annual review

This policy is reviewed and updated at least **annually** (next scheduled review
**2027-05-31**) and whenever the authentication architecture, the authorization boundary,
the set of interfaces, the threat environment, or the applicable standards materially
change. Reviews are performed by the ISSO (TBD — assign before assessment) and re-approved
by the Authorizing Official (TBD — assign before assessment), consistent with IA-1.

## 1 Purpose and applicability

The purpose of this policy is to ensure every identity that interacts with KP — whether a
KP service process or, in the future, an interactive user — is **uniquely identified** and
**authenticated** before it is granted access, and that the authenticators used are
**managed** over their full lifecycle (issuance, protection, rotation, revocation).

It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace
  (`AST-WH` admission webhook, `AST-PM` policy-manager, `AST-DB`/`AST-SPA` dashboard),
  as defined in the system facts sheet (`docs/compliance/system-facts.md`).
- The inter-service calls between those components and the authenticators that protect
  them (the internal bearer token, the serving certificates, and any client-CA bundle).
- All personnel filling the System Owner, ISSO, AO, and Independent Assessor roles, plus
  any contributors who change the system's authentication code, chart, or this artifact.

Named roles are **not yet staffed**; this policy refers to them by title with the
qualifier "TBD — assign before assessment" and does not name individuals.

## 2 IA-1 — Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate an identification-and-
authentication policy and the procedures needed to implement it; shall designate an
official to manage them; and shall review and update both on a defined frequency. This
document is that policy; the operational procedures are
`docs/compliance/procedures/IA-procedures.md`.

### 2.2 IA-1(a) — Scope and recipients

This policy applies to the scope in §1. It is disseminated to the System Owner, ISSO, AO,
Independent Assessor, and all repository contributors by being maintained in version
control under `docs/compliance/policies/` and referenced from the SSP
(`docs/compliance/ssp/SSP.md`, IA family) and the CRM (`docs/compliance/CRM.md`).

### 2.3 IA-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing. The **AO (TBD — assign before assessment)**
approves the authentication posture as part of the authorization decision.

### 2.4 IA-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This IA policy (IA-1) | ISSO | At least annually | Significant change; new/changed standard; assessor finding |
| IA procedures (`docs/compliance/procedures/IA-procedures.md`) | ISSO | At least annually | Token/cert process change; new interface; rotation tooling change |
| e-authentication determination (`docs/compliance/e-authentication.md`) | ISSO | At least annually | New interactive interface; OIDC (P3) landing; assurance-level change |

## 3 IA-2 — Identification and Authentication (organizational users and processes)

### 3.1 Policy statement

KP shall uniquely identify and authenticate organizational users (or processes acting on
their behalf) before granting access to its interfaces. Where KP does not itself perform
user authentication, it shall rely on an explicitly named external authority (Kubernetes
RBAC / the cluster IdP) and document that reliance.

### 3.2 Current implementation — service-to-service identity (Implemented / Partial)

The identities KP authenticates **today** are service processes, not interactive users:

- **Shared internal bearer token.** Inter-service calls — admission-webhook → policy-
  manager (`POST /api/v1/decisions/internal`) and the dashboard ingest path — are
  authenticated with a shared bearer token. Verification is **constant-time** over
  fixed-length SHA-256 digests (`internal/auth/token.go`, `TokenVerifier.Verify` using
  `crypto/subtle.ConstantTimeCompare`), so neither the token contents nor its length leak
  through timing. The verifier **fails closed**: an unconfigured verifier (no token set)
  rejects every request rather than acting as a wildcard
  (`internal/auth/middleware.go`, `RequireBearer` → 401). The token is stored in the
  Kubernetes Secret `<release>-internal-token`. This is a **shared service credential**,
  not a per-user identity, and is documented as such.
- **Metrics endpoint authentication.** When `metrics.tls.enabled` is set, the webhook
  (`:9090`) and policy-manager (`:9091`) `/metrics` endpoints are served over TLS 1.3 and
  wrapped with the same constant-time bearer-token check (`auth.RequireBearer`, CRY-WU-08);
  the dashboard `/metrics` (`:9092`) is not bearer-authenticated (tracked gap). Health
  probes (`/healthz`, `/readyz`) are intentionally **not** wrapped because kubelet probes carry no
  Authorization header.
- **Optional webhook mutual TLS (mTLS).** When the admission-webhook is started with a
  client-CA bundle (`--client-ca-path`, or `security.tls.client_ca_path`) and
  `client_auth=require`, the listener enforces `RequireAndVerifyClientCert`
  (`internal/config/tls.go`, `BuildServerTLSConfig`), authenticating the calling
  API server (or other client) by its certificate. When **no** client-CA bundle is
  supplied the listener falls back to **server-auth-only (permissive)** mode — this is the
  honest default; it is **not** mTLS, and the binary emits a warning when `client_auth=
  require` is configured without a CA bundle.
- **TLS 1.3 transport floor.** All KP listeners are pinned to a **TLS 1.3 minimum**;
  configuring a lower floor is **rejected at config load** (`internal/config/tls.go`,
  `TLSConfig.Validate`). This authenticates the *server* to every caller and is the
  transport substrate for the credentials above.

### 3.3 Interactive user authentication — Planned (P3)

KP's own interfaces (dashboard BFF, policy-manager API) **do not** authenticate individual
human users today. There is no login flow, session, or cookie in the dashboard code path.
Interactive user identity is therefore obtained from the **cluster's RBAC / IdP** layer
(Customer-Responsibility / inherited; `docs/compliance/CRM.md`). The dashboard is **read-
only by default**: write verbs (POST/PUT/PATCH/DELETE) return **403** unless `ALLOW_WRITES`
is explicitly enabled (`cmd/dashboard/proxy.go`, `cmd/dashboard/config.go`). Native
per-user **OIDC** authentication on the dashboard and policy-manager API is **Planned
(phase P3)** and tracked in the POA&M (`docs/compliance/poam.csv`); the assurance-level
determination per interface is in `docs/compliance/e-authentication.md`.

## 4 IA-5 — Authenticator Management

### 4.1 Policy statement

KP shall manage authenticators across their lifecycle: generate them from approved
sources, protect them at rest and in transit, support rotation, and revoke compromised
authenticators. The authenticators KP manages today are the **internal bearer token** and
the **TLS serving / client certificates**.

### 4.2 Internal bearer token (IA-5, IA-5(1)) — Partial

- **Generation (approved source).** Tokens are generated from a **FIPS-validated CSPRNG**:
  `auth.GenerateToken` (`internal/auth/token.go`) reads `crypto/rand`, which is served by
  the validated DRBG when the binary is built with the Go FIPS 140-3 module (GOFIPS140 +
  `GODEBUG=fips140=on`; see `docs/compliance/crypto-module.md`). The default token carries
  **256 bits** of entropy. Generation from template-time RNGs (e.g. Helm `randAlphaNum`)
  is explicitly **prohibited** by the rotation procedure.
- **Protection.** The token is stored only in the Secret `<release>-internal-token` and
  injected via environment variables; verification never logs or echoes it, and comparison
  is constant-time (§3.2). At-rest confidentiality is inherited from the cluster's
  encryption-at-rest configuration (`docs/compliance/secrets-at-rest.md`, SC-28).
- **Rotation (IA-5(1)).** The verifier accepts **two** tokens at once — a *current* and a
  *previous* — enabling **zero-downtime rotation**: during the rotation window callers
  presenting either token are accepted (`internal/auth/token.go`,
  `NewTokenVerifier(tokens...)`; unit-tested as `TestTokenVerifier_RotationWindow`). The
  step-by-step procedure, environment-variable mapping, and key-compromise (skip-the-
  window) response are in the runbook `docs/runbooks/internal-token-rotation.md`.
- **Honest gap.** Wiring the Helm chart to generate the token from a CSPRNG Job (replacing
  the demo-only `randAlphaNum` autogeneration) and to surface the previous-token Secret key
  is the **remaining Helm portion** of this control and is tracked in the POA&M
  (`docs/compliance/poam.csv`).

### 4.3 PKI-based authenticators — TLS certificates (IA-5(2)) — Partial

- **Production issuance.** With `certManager.enabled=true`, serving certificates are issued
  by a cert-manager Issuer/Certificate as **ECDSA P-256** keys from a shared root-CA
  bootstrap. Each serving cert lives in its **own** Secret
  (`<release>-admission-webhook-certs`, `<release>-policy-manager-certs`,
  `<release>-dashboard-certs`).
- **Demo issuance (DEMO-ONLY).** With `certManager.enabled=false`, a self-signed RSA-2048
  certificate is generated for demonstration only and must not be used for an authorized
  deployment.
- **Rotation / renewal.** cert-manager renews each Certificate `renewBefore` expiry and the
  components pick up the new material **without a restart** via the hot reloader
  (`internal/tlsreload`); the manual / demo path uses `scripts/gen-webhook-cert.sh`
  (ECDSA P-256). Expiry is monitored and alerted; see `docs/runbooks/cert-rotation.md`.
- **Client-CA (mTLS) authenticators.** When webhook mTLS is enabled, the client-CA bundle
  is the authenticator that identifies accepted clients; its management (sourcing the
  apiserver CA, mounting, and rotation) is covered in
  `docs/compliance/procedures/IA-procedures.md`.

### 4.4 Audit-chain integrity key (supporting IA-5 protection of authenticators)

The audit tamper-evidence HMAC-SHA256 chaining key (`internal/audit/integrity.go`, AU-9)
is itself an authenticator-grade secret stored in the Secret `<release>-audit-integrity`;
it is generated and protected on the same basis as the internal token and is in scope for
the rotation discipline in §4.2.

## 5 Compliance, exceptions, and enforcement

- Deviations from this policy require documented risk acceptance by the System Owner
  (within delegated authority) or the AO and are recorded in the POA&M
  (`docs/compliance/poam.csv`) where they represent an open weakness.
- Running webhook mTLS in permissive (server-auth-only) mode in an environment that
  requires client authentication, or deploying the DEMO-ONLY self-signed path, are
  deviations to be risk-accepted and tracked, not silent defaults.
- Nothing in this artifact constitutes an authorization to operate.

## 6 Roles and responsibilities (summary)

| Role | Holder | IA responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for IA posture and resourcing; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official; maintains this policy, the procedures, and the e-authentication determination; tracks POA&M. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the authentication posture as part of the authorization decision. |
| Independent Assessor | TBD — assign before assessment | Independently assesses IA controls during the SAR. |
| Cluster Operator (customer) | TBD (Customer) | Operates cluster RBAC / IdP that provides interactive user identity until OIDC (P3) lands; performs token and certificate rotation per the procedures. |

## 7 References

- IA procedures: `docs/compliance/procedures/IA-procedures.md`
- e-authentication determination: `docs/compliance/e-authentication.md`
- Internal token rotation runbook: `docs/runbooks/internal-token-rotation.md`
- TLS certificate rotation runbook: `docs/runbooks/cert-rotation.md`
- Auth implementation: `internal/auth/token.go`, `internal/auth/middleware.go`
- TLS configuration: `internal/config/tls.go`; auth provider stanza: `internal/config/config.go`
- Crypto module / standards: `docs/compliance/crypto-module.md`, `docs/compliance/crypto-standards.md`
- Secrets at rest: `docs/compliance/secrets-at-rest.md`
- System facts / CRM / control matrix / POA&M: `docs/compliance/system-facts.md`, `docs/compliance/CRM.md`, `docs/compliance/control-matrix.csv`, `docs/compliance/poam.csv`
- Compliance index: [README](../README.md)
- NIST SP 800-53 Rev 5 (IA-1, IA-2, IA-5, IA-5(1), IA-5(2)); FedRAMP Moderate baseline; FIPS-199.
