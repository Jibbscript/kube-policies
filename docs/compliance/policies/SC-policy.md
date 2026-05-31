---
title: "System & Communications Protection Policy (SC) — Kube-Policies (KP)"
control_family: "SC — System and Communications Protection"
controls: "SC-1, SC-7, SC-8, SC-8(1), SC-12, SC-13"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# System & Communications Protection Policy — Kube-Policies (KP)

This policy establishes the System and Communications Protection requirements for the
Kube-Policies system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53
Rev 5** (FedRAMP **Moderate** baseline). It implements control **SC-1 (Policy and
Procedures)** and the SC controls that protect KP at its boundary and in transit:
**SC-7 (Boundary Protection)**, **SC-8 / SC-8(1) (Transmission Confidentiality and
Integrity)**, **SC-12 (Cryptographic Key Establishment and Management)**, and
**SC-13 (Cryptographic Protection)**. It is the SC-family anchor; the operational
verification and rotation steps live in the companion `docs/compliance/procedures/SC-procedures.md`.

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**;
it is **not yet authorized** (no ATO) and not in production use. This policy documents the
protection *discipline* the program operates under and the controls that are *actually
implemented* in the shipped code and Helm chart — it is not a claim that every SC control
is fully met. Several boundary protections (apiserver-side mutual TLS for `ICX-01`,
NetworkPolicy, authentication of the metrics and management planes) are **Partial** or
**Planned**; per-control status is tracked in the control matrix (`control-matrix.csv`)
and open weaknesses in the POA&M (`poam.csv`), with remediation phases (P0–P12) defined
in `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually** (next review
**2027-05-31**) and whenever a significant change to the system, its boundary, its
interconnections, the cryptographic module, the threat environment, or the applicable
standards occurs. Reviews are recorded by updating the `last_reviewed`/`next_review`
front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that information transmitted to, from, and within
KP is protected for confidentiality and integrity; that the authorization boundary is
defended; and that all cryptography uses a FIPS-validated module with approved algorithms
and managed keys. It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace —
  `AST-WH` (admission-webhook), `AST-PM` (policy-manager), `AST-DB`/`AST-SPA` (dashboard +
  SPA), `AST-OPA`, `AST-CRD-POL`, `AST-CRD-EXC`, and `AST-CHART` — and their serving
  endpoints, as pinned in `system-facts.md` and `inventory.csv`.
- The external interconnections `ICX-01..06` defined in `interconnections.md`.
- All personnel filling the System Owner, ISSO, Authorizing Official (AO), and Independent
  Assessor roles, plus any contributor who changes the system, its TLS/crypto
  configuration, or its certificate management.

Named roles are **not yet staffed**; this policy refers to them by title with the
qualifier "TBD — assign before assessment" and does not name individuals.

## 2 SC-1 — System and Communications Protection Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this SC policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the procedures are in
`docs/compliance/procedures/SC-procedures.md`.

### 2.2 SC-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Independent Assessor, and all repository contributors by being maintained
in version control under `docs/compliance/policies/` and referenced from the SSP
(`ssp/SSP.md`, SC family) and the CRM (`CRM.md`).

### 2.3 SC-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing. Cryptographic-module selection and the CMVP
certificate confirmation (SC-13) are the System Owner's accountability (see §6).

### 2.4 SC-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This SC policy (SC-1) | ISSO | At least annually | Boundary/interconnection change; new TLS or crypto standard; assessor finding |
| SC procedures (`SC-procedures.md`) | ISSO | At least annually | Procedure drift; new component or port; tooling change |
| Cryptographic module record (`crypto-module.md`, SC-13) | System Owner / ISSO | At least annually | Module version change; CMVP status change |
| Cryptographic standards (`crypto-standards.md`, SC-12/13/17) | ISSO | At least annually | Algorithm deprecation; key-strength change |

"Significant change" includes any change to the authorization boundary
(`diagrams/authorization-boundary.md`), the interconnections (`ICX-01..06`,
`interconnections.md`), the listening ports/protocols (`ssp/ports-protocols-services.md`),
the FIPS-validated module, or a material shift in the threat environment.

## 3 SC-7 — Boundary Protection

### 3.1 Policy statement

KP shall define, document, and protect its authorization boundary. All component services
run inside the single `kube-policies-system` namespace (`ZONE-SYS`); everything outside —
the kube-apiserver, the Prometheus scraper, cluster operators/users, and the hosting CSP
control plane — is external (`ZONE-EXT`). External communication crosses the boundary only
at the published managed interfaces `ICX-01..06` (`interconnections.md`) and the listening
ports enumerated in `ssp/ports-protocols-services.md`.

### 3.2 Implemented boundary controls (current, honest)

- **Defined, minimal interfaces.** Each component exposes only the ports recorded in
  `system-facts.md`: `AST-WH` on `8443/tcp` (TLS 1.3 `/validate`,`/mutate`) plus `9090/tcp`
  metrics; `AST-PM` on `8080/tcp` REST `/api/v1` plus `9091/tcp` metrics; `AST-DB` on
  `8090/tcp` plus `9092/tcp` metrics. No other listeners are opened.
- **Fail-closed admission.** The webhook `failurePolicy` defaults to `Fail` and the
  in-process admission `failure_mode` defaults to **fail-closed**, so a boundary component
  that cannot evaluate a request denies rather than admits it.
- **Webhook scoping.** The `ValidatingWebhookConfiguration` rendered by
  `charts/kube-policies/templates/admission-webhook-tls.yaml` excludes the control-plane
  namespaces (`kube-system`, `kube-public`, `kube-node-lease`, the release namespace) via a
  `namespaceSelector`, narrowing the request surface that crosses `ICX-01`.
- **Optional mutual TLS at the boundary (SC-7 + SC-8(1)).** The webhook can require and
  verify a client certificate on `8443/tcp` when an apiserver client-CA bundle is supplied
  (`--client-ca-path`, sourced from Secret `<release>-admission-webhook-client-ca` /
  `admissionWebhook.tls.clientCA`); see §5.

### 3.3 Known boundary gaps (Partial / Planned — do not overstate)

The following boundary protections are **not** yet implemented and are tracked in
`poam.csv` and the phased plan:

- **No NetworkPolicy** restricting east-west traffic to/from the namespace (Planned).
- **Management and metrics planes are unauthenticated by default.** The policy-manager
  REST API on `8080/tcp`, the dashboard on `8090/tcp`, and the `9090/9091/9092` metrics
  endpoints ship without user/peer authentication unless the optional TLS/bearer features
  in §4 are enabled; OIDC/authZ is Planned (P2/P3).
- **`ICX-01` apiserver-side mutual TLS** (the apiserver presenting a client cert) depends
  on cluster configuration and is Planned (P3); the webhook side supports it today (§5).

No boundary control may be reported as Implemented in the SSP beyond what this section
states.

## 4 SC-8 / SC-8(1) — Transmission Confidentiality and Integrity (TLS in transit)

### 4.1 Policy statement

KP shall protect the **confidentiality and integrity** of information in transit using
TLS, with a **TLS 1.3 floor** on every listener it controls. Cryptographic mechanisms (the
FIPS module of §5/SC-13) provide both confidentiality and integrity protection, satisfying
SC-8 and the SC-8(1) cryptographic-protection enhancement on the interfaces where it is
enabled.

### 4.2 Implemented TLS posture (current, honest)

- **TLS 1.3 floor, config-driven, fail-fast.** TLS parameters are validated and built by
  `internal/config/tls.go` (`BuildServerTLSConfig`). A configured `min_version` below
  **1.3** is **rejected at load** (not at first handshake), and the cipher allow-list
  excludes all CBC/RC4/3DES/non-PFS suites. TLS 1.2 and below are unconfigurable. This
  floor is build-gated by the conformance test (see §4.4 of `SC-procedures.md`).
- **Admission webhook `8443/tcp` (`ICX-01`).** Serves TLS 1.3 for `/validate` and
  `/mutate`; server-authentication is always on, with optional client-certificate
  verification (SC-8(1), §5).
- **policy-manager `8080/tcp` (`ICX-02`).** The REST `/api/v1` listener serves **TLS 1.3**
  via `BuildServerTLSConfig`; the internal bearer token (§5) that authenticates
  `AST-WH → AST-PM` no longer needs to cross a plaintext hop once TLS is configured. (The
  `system-facts.md` "Transport (current)" column still records the pre-TLS plaintext target
  state for `ICX-02`; this listener supports TLS 1.3 today and the facts sheet is reconciled
  as that transport is enabled in the deployment.)
- **dashboard `8090/tcp` (`ICX-05`).** Optional in-pod TLS 1.3 termination plus an optional
  HSTS (`Strict-Transport-Security`) response header, both gated by configuration
  (`dashboard.tls` / `DASHBOARD_HSTS_*`); HSTS is emitted only when explicitly enabled so it
  does not conflict with an Ingress that already terminates TLS.
- **Metrics `9090/9091` (`ICX-03`).** Optional TLS 1.3 + bearer-token authentication on the
  webhook and policy-manager metrics endpoints (`metrics.tls.enabled` / `--metrics-tls`);
  HTTP-without-auth is the default and is a documented gap (§3.3). The dashboard `/metrics`
  (`9092`) is TLS-gated on `dashboard.tls.enabled` and is **not** bearer-authenticated
  (tracked gap).
- **Hot certificate reload.** Served certificates are reloaded without a restart
  (`internal/tlsreload`), so rotation (§5) does not break in-transit protection.

### 4.3 Integrity beyond transit

Transmission integrity (SC-8) is reinforced at the data layer by tamper-evident audit
records: each persisted audit line is sealed in an **HMAC-SHA256 hash chain**
(`internal/audit/integrity.go`), keyed from Secret `<release>-audit-integrity`, so
post-transmission modification of the audit log is detectable (AU-9). The HMAC is computed
by the FIPS module (§5).

## 5 SC-12 / SC-13 — Cryptographic Key Management and Cryptographic Protection

### 5.1 SC-13 — Cryptographic protection (FIPS-validated module)

**Policy.** All cryptographic operations KP performs in-process — TLS handshakes
(`crypto/tls`), the bearer-token CSPRNG (`crypto/rand`), and audit HMAC (`crypto/hmac`,
`crypto/sha256`) — shall be performed by a **FIPS 140-3 validated cryptographic module**.
KP does not generate X.509 certificates in-process today (issuance is out-of-process via
cert-manager or `scripts/gen-webhook-cert.sh`); should in-process issuance ever be added,
it is likewise bound by this policy.

**Implemented posture (honest).** KP binaries are built with the **Go Cryptographic
Module** selected at build time via `GOFIPS140=v1.0.0` and run with `GODEBUG=fips140=on`;
when production Helm values set `REQUIRE_FIPS=true`, the startup self-test in
`internal/cryptofips` (`MustEnforce`) logs the effective FIPS state and **aborts the
process** (`log.Fatal`) if the module is required but not active, so a misbuilt or
misconfigured image fails fast instead of serving traffic on non-validated crypto. The
build/CI/runtime evidence is recorded in `crypto-module.md`.

> **CMVP certificate is `REQUIRES VERIFICATION`.** The exact CMVP certificate number (or
> Modules-In-Process entry) for the Go Cryptographic Module v1.0.0 has **not** yet been
> confirmed against the authoritative NIST database. Per `crypto-module.md`, the System
> Owner must record the verified certificate before this is submitted as SC-13 evidence;
> stating a specific number now would be an overstated compliance claim.

### 5.2 SC-12 — Key establishment and management

**Policy.** Cryptographic keys and certificates shall be established and managed with
approved algorithms and key strengths, distinct per service, and rotatable without
downtime.

**Implemented posture (honest).**

- **Approved algorithms / key strengths** are defined in `crypto-standards.md`: ECDSA P-256
  (preferred) or RSA ≥3072 for serving and client keys; RSA-2048 is not an approved
  production strength.
- **Production certificate path (cert-manager).** When `certManager.enabled=true`, a shared
  in-cluster root CA is bootstrapped (`charts/kube-policies/templates/issuer.yaml`) and each
  component `Certificate` (`charts/kube-policies/templates/certificate.yaml`) issues an
  **ECDSA P-256** leaf (`privateKey.algorithm=ECDSA size=256`) into its own serving Secret;
  cert-manager renews automatically and the hot reloader picks the new material up without a
  restart.
- **Demo / bootstrap path (DEMO-ONLY).** The Helm `admissionWebhook.tls.autoGenerate=true`
  path uses sprig `genCA`/`genSignedCert`, which emit a **fixed RSA-2048 / SHA-256** key
  pair with no algorithm knob — this is below the FedRAMP-Moderate bar and is **never** the
  production path. `scripts/gen-webhook-cert.sh` generates an ECDSA P-256 cert for dev/demo.
  Production values set `certManager.enabled=true` and `autoGenerate=false`.
- **Per-service key isolation.** Each serving certificate lives in its own Secret —
  `<release>-admission-webhook-certs`, `<release>-policy-manager-certs`,
  `<release>-dashboard-certs` — so a compromise of one service's key does not expose the
  others. The webhook client-CA bundle for mTLS is a separate Secret
  (`<release>-admission-webhook-client-ca`) holding only a public CA cert.
- **Internal bearer token (SC-12).** The token authenticating `AST-WH → AST-PM` is
  generated from the FIPS CSPRNG (`crypto/rand`), verified in **constant time**
  (`crypto/subtle.ConstantTimeCompare`, `internal/auth`), supports a **two-token rotation
  window**, and is stored in Secret `<release>-internal-token`.
- **Audit-integrity HMAC key (SC-12).** Loaded from Secret `<release>-audit-integrity`,
  never hard-coded (`internal/audit`).

> **SC-12 / SC-17 cross-reference.** Public Key Infrastructure (SC-17) — the cert-manager
> issuing CA, the shared root-CA bootstrap, and the per-key inventory/rotation detail — is
> governed by `crypto-standards.md` and the SC procedures (`SC-procedures.md`), and the
> per-key inventory and key-management plan are authored under CRY-WU-18
> (`crypto-inventory.md`, `key-management-plan.md`).

### 5.3 SC-28 — Protection of information at rest (cluster-inherited)

KP does **not** encrypt at rest in-process. Every KP secret is a Kubernetes Secret / etcd
object, so at-rest confidentiality (SC-28) is **inherited** from the cluster's API-server
encryption-at-rest configuration (`EncryptionConfiguration` + KMS). A ready-to-edit example
ships at `deployments/kubernetes/encryption/encryption-config.yaml`, and the full at-rest
inventory and verification steps are documented in `secrets-at-rest.md`. KP claims SC-28
only as an **inherited** control; it implements no in-app at-rest encryption.

## 6 Roles and responsibilities (summary)

| Role | Holder | SC responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for SC adequacy and resourcing; approves this policy; confirms the FIPS module CMVP certificate (SC-13). |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures; reviews TLS, boundary, and key-management evidence; tracks POA&M. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP and renders the authorization decision. |
| Independent Assessor | TBD — assign before assessment | Independently assesses SC controls during the SAR. |

## 7 Compliance, exceptions, and enforcement

- Deviations from this policy (e.g., enabling a non-cert-manager cert path in production, or
  running without `REQUIRE_FIPS=true`) require documented risk acceptance by the System Owner
  (within delegated authority) or the AO, and are recorded in `poam.csv` where they
  represent an open weakness.
- A configuration that would lower the TLS floor below 1.3, or supply a below-strength key,
  fails fast at load (`internal/config/tls.go`) or at build (the conformance test); such a
  failure is a defect to be fixed, not a deviation to be accepted silently.

## 8 References

- SC procedures: `docs/compliance/procedures/SC-procedures.md`
- Cryptographic module (SC-13): `crypto-module.md` · Cryptographic standards (SC-12/13/17): `crypto-standards.md`
- Secrets at rest (SC-28): `secrets-at-rest.md` · Secure configuration baseline: `secure-configuration-baseline.md`
- System facts: `system-facts.md` · Interconnections (`ICX-01..06`): `interconnections.md` · PPS register: `ssp/ports-protocols-services.md`
- Implementing code/templates (cited by path): `internal/config/tls.go`, `internal/cryptofips/fips.go`, `internal/tlsreload`, `internal/auth`, `internal/audit/integrity.go`, `charts/kube-policies/templates/admission-webhook-tls.yaml`, `charts/kube-policies/templates/certificate.yaml`, `charts/kube-policies/templates/issuer.yaml`, `scripts/gen-webhook-cert.sh`
- Control matrix: `control-matrix.csv` · POA&M: `poam.csv` · Compliance index: [README](../README.md)
- NIST SP 800-53 Rev 5 (SC-1, SC-7, SC-8, SC-8(1), SC-12, SC-13, SC-17, SC-28); FedRAMP Moderate baseline; FIPS 140-3; FIPS-199.
