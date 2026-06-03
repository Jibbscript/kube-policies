---
title: "Cryptographic Standards — Approved Algorithms & Key Strengths (Kube-Policies)"
control_family: "SC — System and Communications Protection"
controls: "SC-12, SC-12(3), SC-13, SC-17"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Cryptographic Standards — Approved Algorithms & Key Strengths

This document defines the approved cryptographic algorithms, key lengths, and
signature algorithms for all X.509 material the Kube-Policies system produces or
consumes (CRY-WU-11). It is the key-strength companion to the
[cryptographic module](crypto-module.md) record (which establishes the FIPS
140-3 validated module) and is part of the
[compliance evidence package](README.md).

> **Posture:** Kube-Policies is a Proof-of-Concept being driven to
> FedRAMP-Moderate readiness; it is **not yet authorized**. Every algorithm
> below must be one the selected FIPS 140-3 module (`crypto-module.md`)
> implements; the System Owner confirms module coverage before this is used as
> ATO evidence.

## Approved algorithm / key-length matrix

| Use | Approved (preferred) | Approved (alternative) | Prohibited | Control |
|---|---|---|---|---|
| TLS server key (webhook / policy-manager / dashboard leaf) | ECDSA P-256 | RSA ≥3072 | RSA <3072, P-192, any <128-bit-equivalent | SC-12(3), SC-13 |
| TLS client key (mTLS, CRY-WU-04) | ECDSA P-256 | RSA ≥3072 | RSA <3072, P-192 | SC-12(3), SC-13, SC-8(1) |
| Issuing CA key (cert-manager / demo CA) | ECDSA P-256 | RSA ≥3072 | RSA-2048 in production | SC-12, SC-17 |
| Certificate signature algorithm | ecdsa-with-SHA256 | sha256WithRSAEncryption (SHA-384 acceptable) | SHA-1, MD5, any non-SHA-2/3 | SC-13, SC-17 |
| Hash for signatures / HMAC | SHA-256 | SHA-384 | SHA-1, MD5 | SC-13 |
| TLS protocol floor | TLS 1.3 | — | TLS ≤1.2 | SC-8, SC-23 |

**Rationale.** ECDSA P-256 and RSA-3072 each provide ~128-bit security; RSA-2048
provides only ~112-bit and is **not** an approved production strength for a new
FedRAMP-Moderate system. Ed25519 is intentionally **excluded** from the approved
list until its status in the selected FIPS 140-3 module is confirmed by the
System Owner (`REQUIRES VERIFICATION`) — recording it as approved without that
confirmation would be an overstated claim.

## Demo vs. production

| Path | Algorithm | Status |
|---|---|---|
| Helm `admissionWebhook.tls.autoGenerate=true` (sprig `genCA`/`genSignedCert`) | **RSA-2048 / SHA-256 (fixed)** | **DEMO-ONLY** — sprig exposes no key-spec knob; never the production path |
| `scripts/gen-webhook-cert.sh` | ECDSA P-256 / SHA-256 | Demo/dev, approved strength |
| cert-manager `Certificate` (`certManager.enabled=true`) | ECDSA P-256 (`privateKey.algorithm=ECDSA size=256`) | **Production default** |
| Inline `tls.caCert/cert/key` | operator-supplied | must meet this matrix |

Production deployments (`values-production.yaml`) set `certManager.enabled=true`
and `admissionWebhook.tls.autoGenerate=false`, so the fixed-RSA-2048 sprig path
is never used in production.

## Verification

```console
# X.509 key algorithm, curve, and signature algorithm
openssl x509 -in tls.crt -text -noout | grep -E 'Public Key Algorithm|NIST CURVE|Public-Key|Signature Algorithm'
# Expected (approved): id-ecPublicKey / NIST CURVE: P-256 / ecdsa-with-SHA256
#   (or: Public-Key: (3072 bit) / sha256WithRSAEncryption)
```

For a cert-manager-issued Secret:

```console
kubectl get secret <fullname>-admission-webhook-certs -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -text -noout | grep -E 'NIST CURVE|Signature Algorithm'
```

## Related artifacts

- [crypto-module.md](crypto-module.md) — the FIPS 140-3 validated module backing all of the above (SC-13).
- [secure-configuration-baseline.md](secure-configuration-baseline.md) — security-relevant defaults including TLS.
- Implementing code/templates (cited by path, not linked): `scripts/gen-webhook-cert.sh`, `charts/kube-policies/templates/certificate.yaml`, `charts/kube-policies/templates/admission-webhook-tls.yaml`, `internal/config/tls.go`.
- Per-key inventory and rotation detail are authored under CRY-WU-18 (`crypto-inventory.md`, `key-management-plan.md`).
