# Configuration reference

This is the authoritative, per-key reference for the kube-policies runtime
configuration. It is sourced directly from the Go configuration structs in
[`internal/config/config.go`](../internal/config/config.go) and
[`internal/config/tls.go`](../internal/config/tls.go) — those types are the
single source of truth, and this document describes exactly what they consume.

The configuration is loaded by `config.LoadConfig` (YAML file +
environment-variable overrides) and validated at startup; an invalid value
fails the process before any listener opens, so a misconfiguration is caught
immediately rather than at first request.

## How configuration is loaded

1. **Defaults** are set in code (`setDefaults`).
2. **A YAML file** (path passed via `--config`, default `/etc/config/config.yaml`)
   overrides the defaults. A missing file is not an error — defaults stand.
3. **Environment variables** override the file. The prefix is `KUBE_POLICIES_`
   and nested keys join with `_` (a `.` → `_` replacer). For example
   `security.tls.min_version` is overridden by
   `KUBE_POLICIES_SECURITY_TLS_MIN_VERSION`. (Canonical env-key names are
   enumerated in `clearConfigEnv` in
   [`internal/config/config_test.go`](../internal/config/config_test.go).)
4. **OIDC auth defaults** that depend on `authentication.enabled` are applied
   after unmarshalling (`applyAuthDefaults`).
5. **Validation** (`validateConfig`) runs last and fails closed.

Some values are also driven by **command-line flags** on the binaries; where a
flag overrides a config key, that is called out below (notably
`--require-client-cert` and `--client-ca-path`).

---

## `server`

API/HTTP server settings.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `server.port` | int | `8443` | Primary listener port. Validated to be 1–65535. (The policy-manager binary defaults its own `--port` to `8080`.) |
| `server.metrics_port` | int | `9090` | Metrics listener port. Validated to be 1–65535. |
| `server.tls_cert_path` | string | `/etc/certs/tls.crt` | Path to the serving TLS certificate. |
| `server.tls_key_path` | string | `/etc/certs/tls.key` | Path to the serving TLS private key. |
| `server.log_level` | string | `info` | Log verbosity. |

---

## `policy`

Policy-engine behavior.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `policy.failure_mode` | string | `fail-closed` | Behavior when evaluation cannot complete. Must be `fail-open` or `fail-closed`; any other value fails validation. |
| `policy.disable_defaults` | bool | `false` | Skip loading the bundled default policies. (Also settable via the `--disable-default-policies` flag on the webhook.) |

---

## `audit`

Audit logging. Audit events include policy decisions and — for the
policy-manager management API — `ConfigurationChange` events attributing every
persisting policy/bundle/exception mutation to the authenticated caller
(IAM-WU-14).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `audit.enabled` | bool | `true` | Master switch. When false, audit logging is a no-op. |
| `audit.backend` | string | `file` | Sink. Must be `file` or `stdout`; any other value fails validation. |
| `audit.config` | map[string]string | — | Backend-specific options. For `file`, `filename` sets the log path (default `/var/log/kube-policies/audit.log`, created `0600` in a `0750` dir). `integrity_key_path`, when present and non-empty, enables the tamper-evident HMAC chain (AUD-WU-04/05); an empty-but-present value fails validation rather than silently disabling the chain. |
| `audit.buffer_size` | int | `1000` | In-memory event buffer; overflow drops events and increments a metric. |
| `audit.flush_interval` | string (duration) | `10s` | How often the background processor flushes to the backend. |
| `audit.retention` | string | `90d` | Retention hint (informational). |

### Honesty note — `source_ip` in ConfigurationChange events

`ConfigurationChange` events record a `source_ip` field (inside
`metadata.changes`) extracted via gin's `c.ClientIP()`. The router calls
`SetTrustedProxies(nil)` so `ClientIP()` always returns the **direct peer
address** from `RemoteAddr` — it is not influenced by `X-Forwarded-For` or
other proxy headers, making it non-spoofable by an in-cluster client.

In a typical deployment this is the calling pod's in-cluster IP (e.g. the
dashboard or the admission webhook), **not** the end-user's workstation
address. The authenticated **user identity** (username, uid, groups) comes from
the cryptographically-verified OIDC principal, not from `source_ip`. Treat
`source_ip` as transport-layer attribution (which pod called the API) and the
`user_info` fields as identity attribution.

---

## `metrics`

Prometheus metric naming.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `metrics.enabled` | bool | `true` | Master switch for metric collection. |
| `metrics.namespace` | string | `kube_policies` | Prometheus metric namespace. |
| `metrics.subsystem` | string | `admission` | Prometheus metric subsystem. |

---

## `security.tls`

Transport security for the serving listeners. These values are read by
`config.BuildServerTLSConfig` (used by both binaries).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `security.tls.min_version` | string | `1.3` | Minimum TLS version. Accepted map keys are `1.2` and `1.3`, **but only `1.3` passes validation** — the product mandates a TLS 1.3 floor, so a configured `1.2` (or any lower/unknown value) fails `LoadConfig`. |
| `security.tls.cipher_suites` | []string | — | Allow-listed TLS 1.2 AEAD/PFS suites by IANA name; unknown/weak names fail validation. **See honesty note 1 below — this has no effect on the TLS 1.3 handshake.** |
| `security.tls.client_auth` | string | `require` | Base client-certificate mode. Accepted: `none`, `request`, `require_any`, `verify_if_given`, `require` (and `require_and_verify` as an alias for `require`). Maps to a `crypto/tls.ClientAuthType` via `ClientAuthType()`. **See honesty note 2 below — the `--require-client-cert` flag overrides the final enforcement.** |
| `security.tls.client_ca_path` | string | — | PEM bundle of client-certificate CAs. When empty, client-cert verification is disabled even if `client_auth=require` (permissive mode). The `--client-ca-path` flag overrides this value on both binaries. |

### Honesty note 1 — `cipher_suites` does not affect the TLS 1.3 handshake

`security.tls.cipher_suites` is validated and loaded into `tls.Config.CipherSuites`,
but the Go runtime **ignores `CipherSuites` for TLS 1.3** — the 1.3 cipher suites
are fixed by the runtime and are not configurable. With the mandated TLS 1.3
floor (`min_version` must be `1.3`), this setting therefore has **no handshake
effect** today. It is still validated so that a non-approved or weak suite name
fails fast at load (SC-8/SC-13), and so a config that names the secure 1.3
suites validates rather than erroring. It would only take effect on a TLS-1.2
listener, which this product does not permit.

### Honesty note 2 — `client_auth` is overridden by `--require-client-cert`

`security.tls.client_auth` sets the **base** client-auth mode that
`BuildServerTLSConfig` starts from. The **final** enforcement on each server is
decided by the `--require-client-cert` flag:

- **admission-webhook** (`cmd/admission-webhook`): enforces client-cert mTLS
  **by default** (IAM-WU-06); `--require-client-cert=false` opts out.
- **policy-manager** (`cmd/policy-manager`): mTLS is **optional by default**
  (IAM-WU-03). `--require-client-cert=true` forces
  `RequireAndVerifyClientCert` (and fails closed if no client-CA bundle is
  supplied). `--require-client-cert=false` with a CA bundle present downgrades
  to `VerifyClientCertIfGiven` so the OIDC/bearer-authenticated human operators
  are not locked out by the shipped `client_auth=require` default.

In both cases the flag is authoritative over the `client_auth` string for the
final `ClientAuth` value. The string still drives `ClientAuthType()` (verified
by `TestLoadConfig_ClientAuthDrivesClientAuthType`); the flag layers the
deployment-specific override on top in `buildAPITLSConfig`
(`cmd/policy-manager`) / `setupWebhookServer` (`cmd/admission-webhook`).

---

## `security.authentication`

OIDC bearer-token authentication for the **policy-manager management API**
(`/api/v1` policies/bundles/exceptions/compliance). When enabled, the
management plane is protected by OIDC authN (IAM-WU-01) plus group-to-role RBAC
(IAM-WU-02, see `security.rbac`).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `security.authentication.enabled` | bool | `false` | When false, the management API is served **UNAUTHENTICATED** — a dev-only posture and a tracked gap. Production must set this true. |
| `security.authentication.issuer` | string | — | OIDC issuer URL; the token `iss` claim must match. **Required when enabled** (validation fails otherwise). |
| `security.authentication.jwks_url` | string | — | JWKS endpoint (explicit; no discovery round-trip). **Required when enabled.** |
| `security.authentication.audience` | []string | — | Accepted `aud` values; a token's audience set must intersect this list. **At least one entry required when enabled.** |
| `security.authentication.username_claim` | string | `sub` (when enabled) | Claim used for the principal username. Default applied by `applyAuthDefaults` when enabled and unset. |
| `security.authentication.groups_claim` | string | `groups` (when enabled) | Claim used for the principal groups (drives RBAC). Default applied when enabled and unset. |
| `security.authentication.supported_algs` | []string | FIPS asymmetric allow-list (when enabled) | Accepted JWS signing algorithms. **Code-derived, not an operator/chart key — see note below.** |

When `authentication.enabled=false`, the entire stanza is left at its zero value
and stays inert (verified by `TestLoadConfig_AuthDisabledLeavesZeroValue`). When
enabled, the claim and `supported_algs` defaults are applied and the
issuer/jwks_url/audience validation is enforced (verified by
`TestLoadConfig_AuthEnabledDefaultsSupportedAlgsToFIPSAsymmetricSet` and
`TestLoadConfig_AuthEnabledMissingFieldsFailValidation`).

### `supported_algs` is code-derived (not a chart key)

`supported_algs` defaults to the FIPS-approved **asymmetric** allow-list
(`RS256/384/512`, `PS256/384/512`, `ES256/384/512`) defined as
`fipsAsymmetricAlgs` in `config.go`. Symmetric (HMAC) algorithms and the `none`
algorithm are deliberately excluded so a token cannot be downgraded to an
unapproved or unsigned algorithm (CRY-WU-14). This list is **not** exposed as a
Helm value — it is a security invariant of the product, not an operator knob —
which is why the chart's `configmap.yaml` does not emit it.

---

## `security.rbac`

Maps authenticated OIDC groups to API roles. RBAC is mounted together with OIDC
authN (it is gated by `security.authentication.enabled`); there is intentionally
**no separate enable flag**.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `security.rbac.default_role` | string | `""` | Role for an authenticated principal with no matching binding. `""` means "deny mutations" for such principals. When set, must be `viewer`, `editor`, or `admin` (validated unconditionally). |
| `security.rbac.role_bindings` | []object | — | Each entry binds a `role` to a list of OIDC `groups`. |
| `security.rbac.role_bindings[].role` | string | — | One of `viewer`, `editor`, `admin`. An invalid value fails validation so a typo can never silently grant or withhold access. |
| `security.rbac.role_bindings[].groups` | []string | — | OIDC groups granted this role. |

Roles are ordered: `viewer` < `editor` < `admin`. A principal's effective role
is the highest role among bindings whose groups intersect the principal's
groups, falling back to `default_role`. Read routes require `viewer`, mutating
CRUD routes require `editor`, and privileged operations (deploy, compliance
report generation) require `admin`. This resolution is verified end-to-end by
`TestRoleBindingDrivesEditorGate` (an editor-bound group passes the
`POST /api/v1/policies` editor gate; a viewer-only principal is denied).

---

## `storage`

Backing store selection.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `storage.type` | string | `memory` | Storage backend. **Only `memory` is implemented.** |
| `storage.config` | map[string]string | — | Backend-specific options (unused today). |

### Honesty note — only `memory` is implemented

`storage.type` accepts the value `memory` and **nothing else**. The comment in
`StorageConfig` (config.go) mentions `redis` and `etcd` as future intent, but
neither is implemented: `validateConfig` enforces `storage.type == "memory"` at
load, and the policy-manager's maps (`Manager.policies`, `.bundles`,
`.exceptions`) are always in-process Go maps regardless of this setting. The
Helm chart does not render `storage.*` into the ConfigMap at all — the default
`memory` applies unconditionally. Configuring any other value fails
`LoadConfig`.

---

## A note on encryption-at-rest

There is intentionally **no** `security.encryption` (or encryption-at-rest)
field. The webhook and policy-manager do not encrypt at rest in-process;
secret/etcd at-rest protection is a **cluster** concern, provided by a
Kubernetes `EncryptionConfiguration` + KMS (CRY-WU-15), not by an in-app config
key. A previously-declared, never-consumed `security.encryption` stanza was
removed so the configuration never claims an in-app control that does not exist.
See `deployments/kubernetes/encryption/` and
[`docs/compliance/secrets-at-rest.md`](compliance/secrets-at-rest.md).

---

## Helm mapping

The Helm chart renders a subset of these keys into a ConfigMap
(`charts/kube-policies/templates/configmap.yaml`): `policy.*`, `audit.*`,
`security.authentication.*`, and `security.rbac.*`. TLS parameters
(`security.tls.*`) are **not** rendered into the ConfigMap — they are driven by
container arguments (cert/key paths, `--client-ca-path`,
`--require-client-cert`) plus the code defaults — and `supported_algs` is
code-derived (see above). This keeps the chart from advertising keys that would
not actually control behavior.
