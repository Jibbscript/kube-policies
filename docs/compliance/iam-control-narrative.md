---
title: "IAM Control Narrative (AC / IA) — Kube-Policies (KP)"
control_family: "AC / IA — Access Control & Identification and Authentication"
controls: "AC-2, AC-3, AC-5, AC-6, AC-17, IA-2, IA-3, IA-5, IA-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# IAM Control Narrative (AC / IA) — Kube-Policies (KP)

This narrative documents how Kube-Policies (KP) identifies, authenticates, and
authorizes the identities that interact with its planes, for the NIST SP 800-53
Rev 5 **Access Control (AC)** and **Identification and Authentication (IA)**
families. The system is categorized **FIPS-199 Moderate** under the FedRAMP
**Moderate** baseline. It is the connective tissue between the IA policy/procedures
(`policies/IA-policy.md`, `procedures/IA-procedures.md`), the AC policy/procedures
([policies/AC-policy.md](policies/AC-policy.md),
[procedures/AC-procedures.md](procedures/AC-procedures.md)), and the
[control matrix](control-matrix.csv). Part of the
[compliance evidence package](README.md).

> **Authorization-state honesty note (read first).** Kube-Policies is a
> **Proof-of-Concept being driven to assessment readiness**; it is **not yet
> authorized** (no ATO). The management-plane OIDC + RBAC enforcement described
> below is **config-gated**: the router only mounts the OIDC and RBAC middleware
> when `security.authentication.enabled == true` **and** a non-nil verifier is
> constructed (`internal/policymanager/router.go`, `NewAPIRouter`, the
> `if authCfg.Enabled && verifier != nil` guard). The **chart default is
> `auth.enabled: false`** (`charts/kube-policies/values.yaml`), which means a
> default-values install serves the `/api/v1` management plane **UNAUTHENTICATED**.
> That is a **dev-only posture and a tracked gap**; `cmd/policy-manager/main.go`
> emits a startup `Warn` ("OIDC authentication is DISABLED … served
> UNAUTHENTICATED … production deployments MUST set
> security.authentication.enabled=true") and the production chart values fail to
> render unless issuer/jwks_url/audience are set
> (`charts/kube-policies/templates/configmap.yaml`). Every AC/IA row that depends
> on that flag is therefore marked **Partial** (not Implemented) in the control
> matrix. Human access to the **cluster** (and thus to KP's namespaced resources
> via `kubectl`) is governed by **Kubernetes RBAC and the cluster IdP**, which are
> **inherited / out-of-boundary** (see `CRM.md`). Named ATO roles
> (System Owner, ISSO, AO, Independent Assessor) are **not yet staffed** and are
> referred to by title with "TBD — assign before assessment".

## Annual review

This narrative is reviewed and updated at least **annually** (next scheduled
review **2027-06-01**) and whenever the authentication architecture, the
authorization boundary, the RBAC model, the set of interfaces, or the applicable
standards materially change. Reviews are performed by the ISSO (TBD — assign) and
re-approved by the AO (TBD — assign).

## 1 Purpose and applicability

The purpose of this narrative is to give an assessor a single, code-grounded view
of **who** can reach **which** KP plane, **how** they are authenticated, **what**
authorization decision is applied, and **which file enforces it**. It claims only
what the shipped code and chart enforce; config-gated and forward-looking items are
labeled as such.

It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace:
  the admission webhook (`AST-WH`), the policy-manager (`AST-PM`), and the dashboard
  (`AST-DB`/`AST-SPA`), as defined in `system-facts.md`.
- The four authenticators inventoried in §2 and the identities they bind.
- The application-layer role model (viewer/editor/admin) and the Kubernetes
  ServiceAccount/RBAC identities that run the workloads.

## 2 Identity & authenticator inventory

KP authenticates **four** distinct authenticators across its planes. Cluster
human-user authenticators (kubeconfig credentials, cluster IdP) are **inherited /
out-of-boundary** and are not in this inventory.

| # | Authenticator | Who it identifies | Where enforced (file) | Issuance | Rotation | Revocation |
|---|---|---|---|---|---|---|
| 1 | **Human OIDC bearer (ID token)** — IAM-WU-01 | An interactive operator on the policy-manager management API (and, upstream, the dashboard session) | `internal/policymanager/auth_middleware.go` (`OIDCAuthMiddleware`, `NewOIDCVerifier`) | Issued by the **external/cluster OIDC IdP** (inherited); KP verifies signature against `jwks_url`, issuer, and audience | IdP-managed token lifetime; KP holds no token, re-verifies every request | Revoked at the IdP (key rotation / token revocation); KP picks up JWKS key changes via the lazy `RemoteKeySet` |
| 2 | **mTLS client certificate** — IAM-WU-03 / IAM-WU-06 | The calling client on a TLS listener: the apiserver to the webhook (IAM-WU-06), and the dashboard to the policy-manager API/SSE (IAM-WU-03) | `internal/config/tls.go` (`BuildServerTLSConfig`, `RequireAndVerifyClientCert`); chart client-cert SAs | cert-manager Issuer/Certificate (production), or the apiserver client CA; demo path self-signed (CRY-WU-05/09) | cert-manager `renewBefore`; serving certs hot-reloaded (`internal/tlsreload`); client-CA bundle requires a controlled restart | Remove/rotate the CA bundle; cert-manager revokes by reissue |
| 3 | **Audience+subject-bound projected SA token** — IAM-WU-11 / Inc7 | A KP workload to the decisions plane: the **webhook SA** → `POST /api/v1/decisions/internal`; the **dashboard SA** → `GET /api/v1/decisions/stream` + `/recent` | `internal/policymanager/tokenreview.go` (`InternalTokenAuthenticator`), `decisions_handler.go` (`authenticateServiceBearer`, `DecisionsReadAuth`) | kubelet-projected `serviceAccountToken` volume, bound to a dedicated audience (default `policy-manager`); validated via the Kubernetes **TokenReview** API | kubelet rotates the projected token before expiry (`expirationSeconds`, default 3600); subscriber re-reads the file per connect | Delete/rotate the SA or its bindings; TokenReview verdict flips to unauthenticated on the next request (no cached trust) |
| 4 | **Static internal bearer token (fallback)** — CRY-WU-14 / IAM-WU-07 | A KP service-to-service caller in **non-cluster / demo** deployments where TokenReview is unavailable | `internal/policymanager/decisions_handler.go` (`authenticateServiceBearer` static branch) → `internal/auth/token.go` (`TokenVerifier.Verify`, constant-time) | Generated from a FIPS-validated CSPRNG; stored in the `<release>-internal-token` Secret | Two-token (current + previous) zero-downtime rotation window (`NewTokenVerifier(tokens...)`) | Clear the previous-token slot and roll pods; fail-closed when unconfigured |

**Authenticator selection per plane.** The decisions plane prefers authenticator
#3 (TokenReview); a **TokenReview API error fails closed** — the request is
rejected and never falls through to #4 — so a transient apiserver outage cannot
widen what is admitted (`decisions_handler.go`, `authenticateServiceBearer`). #4 is
reached only on a *clean negative* verdict or when no reviewer is configured
(`mode=static`).

## 3 AC-2 — Account Management

KP does **not** maintain its own human-user account store. Interactive identities
are **federated from the cluster/external OIDC IdP** (inherited; `CRM.md`); KP
never provisions, stores, or disables a password or a user record. The "accounts"
KP itself defines are:

- **Application authorization roles** — `viewer` / `editor` / `admin`
  (`internal/policymanager/authz.go`). These are not accounts; they are roles
  *mapped from* the IdP groups carried on a verified OIDC token, via the
  configured `RoleBindings` (`internal/config/config.go`, `RBACConfig`).
- **Kubernetes ServiceAccounts** — the webhook, policy-manager, and dashboard SAs
  (`charts/kube-policies/templates/rbac.yaml`, `dashboard-rbac.yaml`). These are
  workload identities managed declaratively by Helm/GitOps; creation, modification,
  and removal happen through chart apply, and disablement is deletion of the SA or
  its binding.

**Status: Partial (config-gated).** Group→role mapping is enforced only when
authentication is enabled (see the honesty note). Automated account
lifecycle, inactivity logout, and account-monitoring (AC-2(1)/(3)/(5)/(12)) are
IdP- or future-phase responsibilities and remain **Planned**.

## 4 AC-3 — Access Enforcement

KP enforces access on two planes, with two distinct mechanisms:

### 4.1 Management plane — OIDC + deny-by-default RBAC (config-gated)

When `security.authentication.enabled` is true and a verifier is present, the
`/api/v1` management group is wrapped by `OIDCAuthMiddleware` then `RBACMiddleware`
(`internal/policymanager/router.go`). `RBACMiddleware`
(`internal/policymanager/authz.go`) consults an **explicit, deny-by-default**
table (`requiredRoles`): a route absent from the table is denied **403**, and a
principal whose effective role is below the route's required role is denied **403**.
There is no wildcard allow.

**Status: Partial (config-gated).** With the chart default `auth.enabled: false`,
this middleware is **not mounted** and the management plane is unauthenticated
(dev-only, tracked gap).

### 4.2 Decision plane — service authentication (Inc7, unconditional)

The decisions endpoints are authenticated **regardless** of the management-plane
auth flag (they are not OIDC-gated; they are service-to-service):

- `POST /api/v1/decisions/internal` — pinned to the **webhook SA** via
  audience+subject-bound TokenReview (`IngestInternal` → `m.internalReviewer`).
- `GET /api/v1/decisions/stream` and `/recent` — pinned to the **dashboard SA**
  via the `DecisionsReadAuth` middleware (`m.decisionsReadReviewer`), the Inc7
  Stream A change that closed the previously unauthenticated read feeds.

A missing bearer is **401**; a TokenReview API error **fails closed**
(`decisions_handler.go`, `authenticateServiceBearer`). Because this enforcement is
**unconditional** (it does not read `authentication.enabled`), the decision-plane
portion of AC-3 is the strongest part of this control — but AC-3 as a whole is
**Partial** because the management plane it shares a row with is config-gated.

## 5 AC-5 — Separation of Duties

The three KP planes run under **three distinct ServiceAccounts** bound to
**three distinct (Cluster)Roles**, so no single workload identity holds another's
privileges (`charts/kube-policies/templates/rbac.yaml`,
`charts/kube-policies/templates/dashboard-rbac.yaml`):

- The **webhook SA** and **policy-manager SA** each have their **own**
  ClusterRole — deliberately separate objects even though their CRD rule sets
  match — so the two enforcement/management planes are independently bindable and
  revocable.
- The **TokenReview create** grant is added to the **policy-manager** ClusterRole
  **only** (and only in `tokenreview` mode); the webhook does not carry it.
- The **dashboard SA** has a tightly scoped namespaced Role (read `get` on two
  named Services only) and **no** CRD, Secret, or TokenReview access.

At the application layer, the **viewer/editor/admin** ordering separates read,
mutate, and privileged operations (deploy, compliance-report generation) into
distinct authorization tiers (`internal/policymanager/authz.go`).

**Status: Partial** — the workload-identity split is enforced unconditionally in
the chart (a solid bright spot), but the app-layer role separation is
**config-gated** on `security.authentication.enabled`, so the control as a whole
does not meet the Implemented bar. Matches the single `Partial` status in the
control matrix.

## 6 AC-6 — Least Privilege

- **Webhook / policy-manager ClusterRoles** grant only `get,list,watch` on
  `policies`/`policyexceptions` and `get,update,patch` on their `/status`
  subresources — no core/apps/rbac/networking/admissionregistration access
  (`charts/kube-policies/templates/rbac.yaml`). The TokenReview grant is
  `create`-only (write-only subresource; nothing persisted).
- **Leader-election** is a **namespaced Role** on `coordination.k8s.io/leases`
  plus `events` `create,patch` — not a ClusterRole — because the Lease lives only
  in the release namespace.
- **Dashboard Role** is read-only `get` on two named Services; it touches no CRDs,
  Secrets, or other namespace resources (`dashboard-rbac.yaml`).
- **App-layer**: the deny-by-default `requiredRoles` table grants each route the
  *minimum* role; read-only evaluation RPCs are `viewer`, mutations are `editor`,
  privileged operations are `admin` (`internal/policymanager/authz.go`).

**Status: Partial.** The Kubernetes RBAC least-privilege is enforced unconditionally
in the chart (a bright spot); the app-layer least-privilege tiering is config-gated.

## 7 AC-17 — Remote Access

KP exposes no general-purpose remote-access service (no SSH, no VPN). The only
remotely reachable surfaces are the TLS-served HTTP planes:

- The webhook serves TLS 1.3 and, when a client-CA bundle is supplied, enforces
  mTLS on the apiserver connection (IAM-WU-06; `internal/config/tls.go`).
- The policy-manager API can require client-cert mTLS (IAM-WU-03) and, when
  enabled, OIDC bearer authN for human callers.
- The dashboard authenticates operators with **OIDC + server-side sessions**
  (IAM-WU-04/16) and forwards per-user identity to the policy-manager.

Confidentiality/integrity of the channel is the **SC** family's TLS 1.3 floor
(`internal/config/tls.go`, `TLSConfig.Validate`). **Status: Partial** — remote
access to the *management* plane is protected only when its config gate is on;
remote-access monitoring (AC-17(1)) is a future ConMon/SIEM responsibility.

## 8 IA-2 / IA-8 — Identification & Authentication of Users

- **IA-2 (organizational users).** Interactive operators are authenticated by a
  **verified OIDC ID token** (`OIDCAuthMiddleware`): the verifier checks the
  issuer, the JWKS signature against a **FIPS-approved signing-algorithm
  allow-list** (`SupportedAlgs`, IAM-WU-13), and the audience is enforced manually
  to support multiple accepted audiences (`audienceIntersects`). The derived
  `Principal` (subject, username, groups) drives RBAC and is recorded on audit
  events (§audit attribution, IAM-WU-14). MFA, PIV, and replay-resistance
  (IA-2(1)/(2)/(8)/(12)) are **inherited from the federated IdP**.
- **IA-8 (non-organizational users).** No anonymous or external-user interface is
  exposed by KP; non-org-user authentication, where applicable, is delegated to
  the federated IdP. Likely **N/A** post-scoping.

**Status: Partial (config-gated)** for IA-2; **Planned** for IA-8.

## 9 IA-3 — Device / Service Identification and Authentication

KP authenticates **non-human service identities** by cryptographic credential, not
by shared secret alone:

- **mTLS** binds a client device/service to its certificate
  (`internal/config/tls.go`, `RequireAndVerifyClientCert`) — the apiserver→webhook
  and dashboard→policy-manager connections.
- **Audience+subject-bound projected SA tokens** bind a workload to its specific
  ServiceAccount identity: the TokenReview must echo back the expected audience
  **and** match the expected SA username (`internal/policymanager/tokenreview.go`),
  so a different SA that merely obtained an `audience=policy-manager` token is
  rejected.

**Status: Partial** — service identity is enforced in `tokenreview` mode (the
chart default) and when mTLS is configured; the static fallback (#4) is a
shared-secret escape hatch for demo/non-cluster use.

## 10 IA-5 — Authenticator Management

Authenticator lifecycle is owned by the IA policy/procedures
(`policies/IA-policy.md` §4, `procedures/IA-procedures.md`). In summary, mapped to
the §2 inventory:

- **#1 OIDC bearer** — issued/rotated/revoked at the IdP; KP holds no secret and
  re-verifies each request against a cached, auto-refreshing JWKS.
- **#2 mTLS certs** — cert-manager issuance (ECDSA P-256), `renewBefore` rotation,
  hot reload of serving certs; client-CA changes need a controlled restart.
- **#3 projected SA tokens** — kubelet-issued, short-TTL, audience-bound, rotated
  automatically before expiry; revoked by removing the SA/binding.
- **#4 static internal token** — FIPS CSPRNG generation, constant-time verification,
  two-token rotation window, fail-closed when unset.

**Status: Partial** — the bearer-token and certificate lifecycles are implemented;
the remaining Helm portion (chart-side CSPRNG generation of the static token) is a
tracked gap in the POA&M (`poam.csv`).

## 11 Role → permission matrix

### 11.1 Application-layer roles (OIDC principals → API authorization)

Source: `internal/policymanager/authz.go` (`requiredRoles`, deny-by-default).

| Role | Integer | Grants (representative routes) |
|---|---|---|
| `viewer` | 1 | `GET` policies/bundles/exceptions/compliance reports & frameworks; read-only evaluation RPCs (`POST /policies/:id/test`, `/policies/validate`, `/policies/evaluate`) |
| `editor` | 2 | viewer **plus** create/update/delete of policies, bundles, exceptions |
| `admin` | 3 | editor **plus** privileged operations: `POST /policies/:id/deploy`, `POST /compliance/reports` |
| (none) | 0 | a route absent from the table, or an unmatched principal with no `DefaultRole`, is denied **403** |

A principal's effective role is the **highest** role across all `RoleBindings`
whose IdP groups intersect the principal's groups, or the configured `DefaultRole`
when none match (`roleForPrincipal`).

### 11.2 Kubernetes workload identities (ServiceAccounts → cluster RBAC)

Source: `charts/kube-policies/templates/rbac.yaml`,
`charts/kube-policies/templates/dashboard-rbac.yaml`.

| Identity (ServiceAccount) | Bound role(s) | Cluster/API permissions |
|---|---|---|
| `<release>-admission-webhook` | ClusterRole `…-admission-webhook` + namespaced leader-election Role | `get,list,watch` policies/policyexceptions; `get,update,patch` their `/status`; leases `get,list,watch,create,update,patch`; events `create,patch` |
| `<release>-policy-manager` | ClusterRole `…-policy-manager` + namespaced leader-election Role | same CRD/status grants as the webhook **plus** (tokenreview mode only) `tokenreviews` `create`; leases + events as above |
| `<release>-dashboard` | namespaced Role `…-dashboard` | `get` on the two named Services only; **no** CRDs/Secrets/TokenReview |

All three SAs default `automountServiceAccountToken: false` at the SA level
(IAM-WU-10, CIS 5.1.5/5.1.6); the webhook and policy-manager Deployments opt the
token back in at pod level for the controller-runtime client.

## 12 Control → Artifact map

Each AC/IA control mapped to a concrete enforcing artifact (`file:line` where a
single line is load-bearing).

| Control | Status | Enforcing artifact |
|---|---|---|
| **AC-2** Account Management | Partial (gated) | `internal/policymanager/authz.go` (`roleForPrincipal`); `internal/config/config.go` (`RBACConfig`) |
| **AC-3** Access Enforcement | Partial (gated mgmt; unconditional decision plane) | `internal/policymanager/authz.go` (`RBACMiddleware`, `requiredRoles`); `internal/policymanager/router.go:53`; `internal/policymanager/decisions_handler.go` (`authenticateServiceBearer`, `DecisionsReadAuth`) |
| **AC-5** Separation of Duties | Partial (workload split enforced unconditionally; app roles gated on `security.authentication.enabled`) | `charts/kube-policies/templates/rbac.yaml`; `charts/kube-policies/templates/dashboard-rbac.yaml`; `internal/policymanager/authz.go` |
| **AC-6** Least Privilege | Partial | `charts/kube-policies/templates/rbac.yaml`; `charts/kube-policies/templates/dashboard-rbac.yaml`; `internal/policymanager/authz.go` (`requiredRoles`) |
| **AC-17** Remote Access | Partial (gated) | `internal/config/tls.go` (`BuildServerTLSConfig`); `internal/policymanager/auth_middleware.go` (`OIDCAuthMiddleware`) |
| **IA-2** I&A (org users) | Partial (gated) | `internal/policymanager/auth_middleware.go:68` (`OIDCAuthMiddleware`); `internal/config/config.go` (`AuthConfig`) |
| **IA-3** Device/Service I&A | Partial | `internal/config/tls.go` (`RequireAndVerifyClientCert`); `internal/policymanager/tokenreview.go` (`InternalTokenAuthenticator.Authenticate`) |
| **IA-5** Authenticator Management | Partial | `internal/auth/token.go` (`GenerateToken`, `TokenVerifier`); `internal/tlsreload`; `policies/IA-policy.md` §4 |
| **IA-8** I&A (non-org users) | Planned (likely N/A) | delegated to federated IdP (`CRM.md`) |

## 13 References

- IA policy / procedures: `policies/IA-policy.md`, `procedures/IA-procedures.md`
- AC policy / procedures: [policies/AC-policy.md](policies/AC-policy.md), [procedures/AC-procedures.md](procedures/AC-procedures.md)
- Audit access-control model (AU-9 / AC-3 / AC-6): `docs/audit/access-control.md`
- Control matrix (spine): [control-matrix.csv](control-matrix.csv)
- System Security Plan (§7.1 AC, §7.7 IA): [ssp/SSP.md](ssp/SSP.md)
- CRM (inherited cluster RBAC / IdP): `CRM.md`
- Enforcing code: `internal/policymanager/auth_middleware.go`, `internal/policymanager/authz.go`, `internal/policymanager/tokenreview.go`, `internal/policymanager/decisions_handler.go`, `internal/policymanager/router.go`, `internal/policymanager/manager.go`, `internal/config/config.go`, `internal/config/tls.go`, `internal/auth/token.go`, `internal/audit/logger.go`
- Enforcing manifests: `charts/kube-policies/templates/rbac.yaml`, `charts/kube-policies/templates/dashboard-rbac.yaml`, `charts/kube-policies/templates/policy-manager-deployment.yaml`, `charts/kube-policies/values.yaml`
- Compliance index: [README](README.md)
- NIST SP 800-53 Rev 5 (AC-2/3/5/6/17, IA-2/3/5/8); FedRAMP Moderate baseline; FIPS-199.
