# Dashboard authentication & authorization

This document describes how the kube-policies dashboard authenticates users and
how per-user authorization is enforced. It covers controls **IA-2, IA-8, AC-3,
AC-6, AC-12, AC-17, IA-11, SC-23** and the work units **IAM-WU-04, IAM-WU-05,
IAM-WU-16, NET-WU-18**.

The dashboard is a thin Backend-for-Frontend (BFF): a Go server (`cmd/dashboard`)
serving a Svelte SPA and reverse-proxying the policy-manager management API at
`/api/v1/*`. Authentication is implemented in `cmd/dashboard/auth.go`; the
reverse proxy and its authorization layering are in `cmd/dashboard/proxy.go`.

## Modes

Selected by `DASHBOARD_AUTH_MODE` (Helm: `dashboard.auth.mode`):

| Mode | Behaviour |
| --- | --- |
| `disabled` (default) | No user authentication. The read/proxy endpoints are served unauthenticated. This is a **development-only posture** and a tracked gap; the server logs a loud warning at startup. Existing default deployments are unchanged. |
| `oidc` | Full OpenID Connect **Authorization Code + PKCE** login in the BFF, with a stateless encrypted session cookie. |
| `forward-auth` | Trust identity headers set by an upstream identity-aware proxy (oauth2-proxy, Pomerium, Traefik forwardAuth, cloud IAP). |

## OIDC mode

### Flow

1. An unauthenticated request to a protected route is challenged: a top-level
   browser navigation receives `302` to `/auth/login`; an XHR/`fetch`/SSE request
   receives `401` with an `X-Login-URL` hint (a cross-origin `302` cannot drive a
   `fetch`, and `EventSource` cannot send an `Authorization` header).
2. `/auth/login` mints `state` (CSRF), `nonce` (replay), and a PKCE
   `code_verifier`, seals them in a short-lived `__Host-` temp cookie, and
   redirects to the identity provider with the **S256** challenge.
3. `/auth/callback` verifies `state`, exchanges the code with the PKCE verifier,
   verifies the ID token (issuer, `aud` = client ID, and a FIPS-approved
   asymmetric signing-algorithm allow-list), and **checks the `nonce`** — go-oidc
   deliberately does not, so the callback does it. It then establishes the
   session cookie and redirects back into the SPA.
4. `/auth/logout` clears the session cookie. `/auth/userinfo` reports the current
   identity for the SPA without challenging.

### Session cookie

The session is **stateless**: it is sealed with **AES-256-GCM** (a FIPS 140-3
approved AEAD — confidentiality and integrity in one pass) and stored entirely in
the cookie, so any replica serves any request with no shared store, sticky
sessions, or Redis. A key ring (current + previous key) allows zero-downtime key
rotation: values are sealed with the current key and opened by trying each key.

Cookie attributes: `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` prefixed, and
`Path=/`. `SameSite=Lax` is **required** (not `Strict`) so the identity provider's
redirect back to `/auth/callback` carries the temp cookie; CSRF is defended by the
`state` parameter, not by the cookie's `SameSite` alone.

The cookie carries the verified ID token so it can be forwarded upstream (see
**Authorization** below). The server enforces a size ceiling and fails the login
loudly (`HTTP 500`) rather than emitting an over-limit cookie that the browser
would silently drop; very large group claim sets are the realistic trigger.

### Session lifecycle (AC-11 / AC-12)

Bounded to FedRAMP-Moderate values, both enforced statelessly from the cookie:

- **Idle / inactivity timeout** — default 15 minutes, sliding (refreshed on each
  authenticated request). `DASHBOARD_SESSION_IDLE_TIMEOUT` / `dashboard.auth.session.idleTimeout`.
- **Absolute / maximum lifetime** — default 12 hours, anchored at login and not
  sliding; after it the user must re-authenticate. `DASHBOARD_SESSION_ABSOLUTE_TIMEOUT` /
  `dashboard.auth.session.absoluteTimeout`.
- **Logout** — `POST /auth/logout` clears the cookie.

### Configuration

| Env var | Helm value | Notes |
| --- | --- | --- |
| `DASHBOARD_AUTH_MODE` | `dashboard.auth.mode` | `oidc` |
| `DASHBOARD_OIDC_ISSUER` | `dashboard.auth.oidc.issuer` | OIDC discovery issuer URL (required) |
| `DASHBOARD_OIDC_CLIENT_ID` | `dashboard.auth.oidc.clientID` | required |
| `DASHBOARD_OIDC_CLIENT_SECRET` | (Secret key `client-secret`) | required |
| `DASHBOARD_OIDC_REDIRECT_URL` | `dashboard.auth.oidc.redirectURL` | the public `/auth/callback` URL (required) |
| `DASHBOARD_OIDC_SCOPES` | `dashboard.auth.oidc.scopes` | default `openid profile email groups` |
| `DASHBOARD_OIDC_USERNAME_CLAIM` | `dashboard.auth.oidc.usernameClaim` | default `sub` |
| `DASHBOARD_OIDC_GROUPS_CLAIM` | `dashboard.auth.oidc.groupsClaim` | default `groups` |
| `DASHBOARD_SESSION_KEY` | (Secret key `session-key`) | base64 of 32 random bytes (required) |
| `DASHBOARD_SESSION_KEY_PREVIOUS` | (Secret key `session-key-previous`) | optional, for rotation |
| `DASHBOARD_SESSION_COOKIE_INSECURE` | — | drops `Secure`/`__Host-` for plaintext local dev only |

The OIDC client secret and the session key are **sensitive** and are read from an
existing Kubernetes Secret named by `dashboard.auth.oidc.existingSecret`, with keys
`client-secret`, `session-key`, and optionally `session-key-previous`. **The chart
does not create this Secret — create it yourself before (or alongside) install;**
the pod will not start until it exists (the `client-secret` and `session-key` keys
are required). The Helm chart fails the render (`helm template`) when
`dashboard.auth.mode=oidc` and any of `issuer`, `clientID`, `redirectURL`, or
`existingSecret` is unset.

Create the Secret (the session key is base64 of 32 random bytes):

```sh
kubectl create secret generic dash-oidc \
  --from-literal=client-secret="$OIDC_CLIENT_SECRET" \
  --from-literal=session-key="$(openssl rand -base64 32)"
```

## forward-auth mode

The dashboard trusts identity from upstream headers (defaults match oauth2-proxy):
`X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups`, and
`X-Forwarded-Access-Token` (configurable via `dashboard.auth.forwardAuth.*`). A
request with no user header is rejected.

**SECURITY (required deployment control):** forwarded identity headers are
spoofable if a client can reach the dashboard directly. forward-auth mode is only
safe when the dashboard is reachable **exclusively** through the proxy and the
proxy strips client-supplied copies of these headers. Enforce this with a
NetworkPolicy that admits traffic to the dashboard only from the proxy. (The
NetworkPolicy itself is delivered with the network-segmentation phase.)

## Authorization (IAM-WU-05)

Authorization is layered:

- **Primary — per-user, enforced upstream by the policy-manager.** On every
  proxied `/api/v1/*` call the dashboard forwards the authenticated user's bearer
  token as `Authorization: Bearer <token>` so the policy-manager authenticates the
  real user and applies its own OIDC + RBAC. A viewer's mutation is therefore
  rejected `403` by the policy-manager **even when `ALLOW_WRITES=true`**. The
  dashboard always strips any client-supplied `Authorization` header first, so a
  browser cannot smuggle a credential of its choosing to the policy-manager.
- **Kill-switch / defense-in-depth — `ALLOW_WRITES`.** When `false`, write verbs
  are rejected `403` at the dashboard before any upstream contact. This is a coarse
  cluster-wide off switch, **not** a substitute for per-user authorization; it is
  retained so writes can be globally disabled regardless of role. The
  `isReadOnlyRPC` exemption (`/policies/validate`, `/policies/evaluate`,
  `/policies/<id>/test`) only bypasses this verb gate — those requests are still
  authenticated and authorized upstream.

**Audience requirement (oidc mode):** the forwarded token is the user's OIDC
**ID token**, whose `aud` is the dashboard's client ID. For the policy-manager to
accept it, the policy-manager's configured `security.authentication.audience` must
include the dashboard's client ID.

**forward-auth mode:** the forwarded credential is instead the upstream proxy's
`X-Forwarded-Access-Token` — an OAuth2 **access token** whose audience and format
are set by the proxy / identity provider, generally **not** the dashboard's client
ID and not necessarily a token the policy-manager's ID-token verifier accepts. For
upstream per-user authorization to work in this mode, the proxy must be configured
to forward a JWT whose `aud` is in the policy-manager's
`security.authentication.audience`; otherwise treat policy-manager verification of
forwarded access tokens as a deployment responsibility.

## Endpoint protection (NET-WU-18)

When auth is enabled, these require an authenticated user:
`/api/metrics/summary`, `/api/decisions/recent`, `/api/decisions/stream`, and the
`/api/v1/*` reverse proxy. These stay public: `/healthz`, `/readyz`,
`/api/decisions/internal` (the machine ingest plane, gated by its own symmetric
internal token — a separate trust domain), `/auth/*`, and the SPA static assets.

## SPA integration note

The browser SPA must, on receiving `401` from an `/api/*` call, perform a
top-level redirect to `/auth/login` (a cross-origin `302` cannot be followed by
`fetch`/`EventSource`). The backend enforces authentication correctly regardless;
the SPA-side `401`→login handling and a login/logout affordance are a follow-up to
this change.
