---
title: "Secrets at Rest — Kube-Policies (KP)"
control_family: "SC — System and Communications Protection"
controls: "SC-28, SC-28(1), SC-12, CIS 1.2.31, CIS 1.2.32, CIS 1.2.33"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Secrets at Rest — Kube-Policies (KP)

This document enumerates every secret Kube-Policies stores and how each is
protected at rest (SC-28). Part of the [compliance evidence package](README.md);
the cryptographic algorithms it relies on are defined in
[crypto-standards.md](crypto-standards.md) and backed by the validated module in
[crypto-module.md](crypto-module.md).

> **Posture:** Kube-Policies does **not** encrypt at rest in-process. All KP
> secrets are Kubernetes Secrets / etcd objects, so at-rest confidentiality is
> **inherited** from the cluster's API-server encryption-at-rest configuration.
> A previously-declared in-app `security.encryption` config stanza that did
> nothing was removed (CRY-WU-15) to avoid implying an in-app control.

## At-rest inventory

| Stored item | Where | Source | At-rest protection |
|---|---|---|---|
| Internal bearer token | Secret `<release>-internal-token` | chart / operator | etcd encryption-at-rest (below) |
| Webhook serving TLS key | Secret `<release>-admission-webhook-certs` | cert-manager / chart | etcd encryption-at-rest; private key never leaves the cluster |
| policy-manager serving TLS key | Secret `<release>-policy-manager-certs` | cert-manager / chart | etcd encryption-at-rest |
| dashboard serving TLS key | Secret `<release>-dashboard-certs` | cert-manager / chart | etcd encryption-at-rest |
| Audit-integrity HMAC key | Secret `<release>-audit-integrity` | chart / operator | etcd encryption-at-rest |
| Webhook client-CA bundle (mTLS) | Secret `<release>-admission-webhook-client-ca` | operator | public CA cert (no secret material) |
| Policy / PolicyException CRs | etcd | kubectl / API | etcd encryption-at-rest (optionally include the CRD resources) |
| Audit log records | file (emptyDir/PVC) or stdout | runtime | host/PV encryption (CSP) + tamper-evidence (AU-9, see [crypto-module.md](crypto-module.md)) |

## Enabling encryption-at-rest

Apply a Kubernetes `EncryptionConfiguration` on the control plane and re-encrypt
existing secrets. A ready-to-edit example (KMS v2 preferred, secretbox fallback,
`identity` for migration) ships at
`deployments/kubernetes/encryption/encryption-config.yaml`, with operator steps
in its header. In managed clusters (EKS/GKE/AKS) secret encryption (often
KMS-backed) is frequently a provider setting — record the provider's attestation
as the SC-28 evidence in that case.

Approved at-rest algorithm: a KMS v2 provider (keys in an external HSM/KMS) is
preferred; `secretbox` (XSalsa20-Poly1305) or `aescbc` are acceptable
software-key fallbacks. `aesgcm` is **not** used (nonce-reuse risk on key
rotation). See [crypto-standards.md](crypto-standards.md).

## Verification (ATO evidence)

```console
# A stored secret must be ciphertext, not readable JSON, in etcd:
ETCDCTL_API=3 etcdctl get /registry/secrets/<ns>/<name> | hexdump -C | head
# Expect a k8s:enc:kms:v2:... (or :secretbox:) prefix, not "{\"apiVersion\"...".
```

## CIS mapping

- **CIS 1.2.31** — apiserver `--encryption-provider-config` set.
- **CIS 1.2.32 / 1.2.33** — encryption providers configured appropriately (KMS preferred; `identity` not first/only).
