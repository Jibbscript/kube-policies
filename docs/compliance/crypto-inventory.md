---
title: "Cryptographic Inventory — Keys, Secrets & Validated Modules (Kube-Policies)"
control_family: "SC — System and Communications Protection"
controls: "SC-12, SC-13, SC-17, SC-28"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Cryptographic Inventory — Keys, Secrets & Validated Modules

This document enumerates **every** cryptographic key and secret the
Kube-Policies system generates, stores, or consumes, and maps each to its
algorithm, validated module, storage location, owner, rotation interval, and
controls (SC-12, SC-13, SC-17, SC-28). It is the per-key companion to the
approved-algorithm matrix in `crypto-standards.md` and the FIPS 140-3 module
record in `crypto-module.md`, and is referenced by the key-management procedure
in `key-management-plan.md` (all CRY-WU-18). It is part of the
[compliance evidence package](README.md).

> **Posture:** Kube-Policies is a Proof-of-Concept being driven to
> FedRAMP-Moderate readiness; it is **not yet authorized**. This inventory
> records what the chart and binaries actually implement today, including the
> **demo-only** generation paths that production must replace. Rows whose
> validated-module backing depends on the CMVP certificate are gated on the
> `REQUIRES VERIFICATION` item in `crypto-module.md`.

This inventory is reviewed at least **annually** (next review **2027-05-31**)
and on any material change to a key, algorithm, storage location, or rotation
practice. The System Owner is accountable for the review; the named key owner
column reflects assignable roles that are **TBD until assigned**.

## Validated module reference

All in-process cryptographic operations below (TLS handshakes, the bearer-token
CSPRNG, the audit HMAC, and any in-process key/X.509 generation) route through
the **Go Cryptographic Module** built with `GOFIPS140=v1.0.0` and run with
`GODEBUG=fips140=on`, as recorded in `crypto-module.md` (SC-13). The CMVP
certificate number for that module is **`REQUIRES VERIFICATION`** — the System
Owner must confirm it against the NIST CMVP database before this inventory is
submitted as ATO evidence. Items marked **cluster-inherited** are **out of the
in-process module's boundary**: their crypto is provided by the Kubernetes
control plane / CSP and is not performed by a Kube-Policies binary.

## Key & secret inventory

| # | Key / secret | Purpose | Algorithm + length | Validated module | Storage (Secret) | Key owner (TBD) | Rotation interval | CRY work unit | Controls |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Webhook serving TLS key | TLS 1.3 server identity for the admission-webhook listener (`:8443`) | ECDSA P-256 (cert-manager default `algorithm=ECDSA size=256`); RSA ≥3072 alternative per `crypto-standards.md` | Go FIPS 140-3 module (TLS handshake); cert-manager performs issuance out-of-process | `<release>-admission-webhook-certs` (`tls.crt`/`tls.key`/`ca.crt`) | System Owner / Platform | cert-manager leaf `duration=8760h` (1y), `renewBefore=720h` (30d), `rotationPolicy=Always` | CRY-WU-09 | SC-12, SC-13, SC-17 |
| 2 | policy-manager serving TLS key | TLS 1.3 server identity for the policy-manager API | ECDSA P-256 (cert-manager `size=256`); RSA ≥3072 alt | Go FIPS 140-3 module (handshake) | `<release>-policy-manager-certs` | System Owner / Platform | leaf `duration=8760h`, `renewBefore=720h`, `rotationPolicy=Always` | CRY-WU-07 | SC-12, SC-13, SC-17 |
| 3 | dashboard serving TLS key | Optional in-pod TLS 1.3 for the dashboard (off by default; HSTS when terminating in-pod) | ECDSA P-256 (cert-manager `size=256`); RSA ≥3072 alt | Go FIPS 140-3 module (handshake) | `<release>-dashboard-certs` | System Owner / Platform | leaf `duration=8760h`, `renewBefore=720h`, `rotationPolicy=Always` | CRY-WU-08 | SC-12, SC-13, SC-17 |
| 4 | mTLS client-CA bundle (webhook) | Verifies kube-apiserver client certs when mutual TLS is enabled (`RequireAndVerifyClientCert`); set via `admissionWebhook.tls.clientCA` | X.509 CA **certificate** bundle — **public cert, no private key/secret material** | Go FIPS 140-3 module (cert-chain verification) | `<release>-admission-webhook-client-ca` (`ca.crt`) | System Owner / Platform | follows the apiserver client-CA's own lifecycle (operator-supplied) | CRY-WU-04 | SC-13, SC-17, SC-8(1) |
| 5 | Internal bearer token | Service-to-service auth: admission-webhook → policy-manager and TLS+bearer metrics scraping | 256-bit random secret. **Production/approved:** `GenerateToken` draws 32 bytes (256 bits) from `crypto/rand`. **Chart default (DEMO):** `randAlphaNum 48` is sprig/template-time RNG — **NOT** a FIPS CSPRNG | Go FIPS 140-3 module **only for the `GenerateToken` (operator-supplied) path**; the chart-default path does not use the module. Verify is constant-time SHA-256 digest compare (`internal/auth`) | `<release>-internal-token` (`token`) | System Owner / Platform | rotate via two-token window (current + previous accepted during propagation); no fixed interval pinned in code — operator-driven | CRY-WU-14 | SC-12, SC-13 |
| 6 | Audit-integrity HMAC key | Keys the tamper-evidence hash chain over audit records (each record's HMAC chains to the prior; AU-9) | HMAC-SHA256 key. **Production:** operator supplies `audit.integrity.key` (or external Secret). **Chart default (DEMO):** `randAlphaNum 64`, explicitly template-time RNG — **NOT** a CSPRNG | Go FIPS 140-3 module for the HMAC computation/verification (`internal/audit/integrity.go`); key material itself is operator- or chart-generated | `<release>-audit-integrity` (`key`) | System Owner / ISSO | no fixed interval in code; operator-driven. Note: rotating the key starts a **new** chain segment — verify/retain prior key for old records | CRY-WU-18 (key mgmt); AUD-WU-05 (impl) | SC-12, SC-13, SC-17 |
| 7 | cert-manager root CA (shared) | Self-signed in-cluster root CA that signs all three leaf serving certs (1–3) so they chain to one `ca.crt` (`issuerType=selfsigned` bootstrap) | ECDSA P-256 (inherits `certManager.privateKey`); RSA ≥3072 alt | Go FIPS 140-3 module is **not** the issuing module — cert-manager performs CA key generation and signing out-of-process | `<release>-ca` (`tls.crt`/`tls.key`) | System Owner / Platform | root `duration=43800h` (5y), `renewBefore=720h`; root rotation is rare (invalidates all leaves) | CRY-WU-09 | SC-12, SC-13, SC-17 |
| 8 | Demo self-signed CA + leaf (`scripts/gen-webhook-cert.sh`) | Demo/dev-only webhook cert chain for kind clusters; regenerated each `make demo-up` | ECDSA P-256 / `ecdsa-with-SHA256` (script) | OpenSSL on the operator workstation — **not** the in-pod Go FIPS module; **DEMO-ONLY**, never production | `<release>-admission-webhook-certs` (overwrites row 1 in demo) | Developer (demo) | per `make demo-up`; not a production rotation control | CRY-WU-09 (demo path) | SC-13, SC-17 |
| 9 | Helm `autoGenerate` demo cert (sprig) | Turnkey self-signed webhook cert when `admissionWebhook.tls.autoGenerate=true` | **RSA-2048 / SHA-256 (fixed)** — sprig `genCA`/`genSignedCert` exposes no key-spec knob; below the FedRAMP-Moderate bar | sprig template-time generation — **not** the Go FIPS module; **DEMO-ONLY** | `<release>-admission-webhook-certs` | Developer (demo) | regenerated on `helm upgrade` per template logic; not a production control | CRY-WU-11 (demo path) | SC-13 |
| 10 | Secret encryption-at-rest key (KMS) | Encrypts all Kube-Policies Secrets/CRs in etcd at rest | AES via the apiserver `EncryptionConfiguration` provider — **KMS v2 preferred** (key in external HSM/KMS); `secretbox` (XSalsa20-Poly1305) software fallback | **Cluster-inherited** — apiserver/CSP crypto, **outside** the Kube-Policies in-process module boundary | apiserver `EncryptionConfiguration` (`deployments/kubernetes/encryption/encryption-config.yaml`) / CSP-managed KMS | Cluster Operator / CSP | per CSP/KMS policy (external) — see `secrets-at-rest.md` | inherited (CRY-WU-15) | SC-28, SC-28(1), SC-12 |

### Notes on the demo vs. production paths (honesty)

- **Rows 5 and 6 chart defaults are demo-grade.** The `randAlphaNum` Helm/sprig
  paths run at template-render time and are **not** FIPS CSPRNG output.
  Production must supply `internalToken` / `audit.integrity.key` (out-of-band,
  generated by a FIPS CSPRNG such as `auth.GenerateToken`) or mount an external
  Secret. This distinction is the difference between an implemented control and
  an overstated one.
- **Rows 8 and 9 are demo-only cert paths** and must never be the production
  serving cert source; production sets `certManager.enabled=true` and
  `admissionWebhook.tls.autoGenerate=false` (see `values-production.yaml`).
- **Row 10 is inherited**, not implemented in-process. Kube-Policies stores its
  secrets as Kubernetes Secrets; at-rest confidentiality is the cluster's
  responsibility (SC-28). See `secrets-at-rest.md`.
- `<release>` is the Helm release name (`kube-policies.fullname`); substitute the
  actual release name when reading live Secrets.

## Control mapping summary

| Control | Coverage in this inventory |
|---|---|
| **SC-12** (key establishment & management) | Rows 1–10 — generation source, owner, and rotation per key (detailed procedure in `key-management-plan.md`). |
| **SC-13** (FIPS-validated crypto use) | Rows 1–6 in-process operations route through the Go FIPS 140-3 module (`crypto-module.md`), gated on CMVP `REQUIRES VERIFICATION`; rows 7–10 are out-of-process/inherited and called out as such. |
| **SC-17** (PKI certificates) | Rows 1–4, 7, 8 — X.509 issuance, the shared root CA, and the mTLS client-CA trust anchor. |
| **SC-28** (protection at rest) | Row 10 — inherited apiserver/KMS encryption; every Secret in rows 1–6 inherits it (`secrets-at-rest.md`). |

## Related artifacts (cited by path, not linked)

- `crypto-standards.md` — approved algorithm / key-length matrix every row must satisfy.
- `crypto-module.md` — the FIPS 140-3 validated module and CMVP `REQUIRES VERIFICATION` gate.
- `key-management-plan.md` — generation, distribution, rotation schedule, and key-compromise response (CRY-WU-18).
- `secrets-at-rest.md` — SC-28 at-rest protection for every Secret above.
- Implementing code/manifests: `internal/auth/token.go`, `internal/audit/integrity.go`, `internal/config/tls.go`, `internal/tlsreload`, `internal/cryptofips`, `charts/kube-policies/templates/certificate.yaml`, `charts/kube-policies/templates/issuer.yaml`, `charts/kube-policies/templates/internal-token-secret.yaml`, `charts/kube-policies/templates/audit-integrity-secret.yaml`, `charts/kube-policies/templates/admission-webhook-client-ca.yaml`, `scripts/gen-webhook-cert.sh`, `deployments/kubernetes/encryption/encryption-config.yaml`.
