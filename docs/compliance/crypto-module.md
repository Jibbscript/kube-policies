---
title: "Cryptographic Module — Kube-Policies (KP)"
control_family: "SC — System and Communications Protection"
controls: "SC-13, SC-12, SC-8, SC-8(1)"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-31"
next_review: "2027-05-31"
---

# Cryptographic Module — Kube-Policies (KP)

This document records the FIPS 140-3 validated cryptographic module that backs
all cryptographic operations in the Kube-Policies binaries (admission-webhook,
policy-manager, dashboard) and the evidence that the shipped binaries actually
use it (SC-13). It is part of the [compliance evidence package](README.md) and
is referenced by the [System and Communications Protection narrative](#).

> **Posture:** Kube-Policies is a Proof-of-Concept being driven to
> FedRAMP-Moderate readiness; it is **not yet authorized**. The crypto-module
> selection below is implemented in the build, but the CMVP certificate number
> must be confirmed by the System Owner against the authoritative NIST database
> before it is used as ATO evidence (see [CMVP certificate](#cmvp-certificate)).

## Selected module

| Attribute | Value |
|---|---|
| Module name | Go Cryptographic Module |
| Version | `v1.0.0` (selected at build time via `GOFIPS140=v1.0.0`) |
| Standard | FIPS 140-3 |
| Vendor | The Go Authors / Google |
| Embodiment | Software module statically linked into each Go binary (`crypto/internal/fips140`) |
| Runtime control | `GODEBUG=fips140=on` (baked in as `DefaultGODEBUG` by the `GOFIPS140` build) |
| Approved-only enforcement | `GODEBUG=fips140=only` (optional hardening: non-approved algorithms error/panic) |

The Go native FIPS 140-3 module is the cryptographic boundary. When a binary is
built with `GOFIPS140` and run with `fips140=on`, the standard library crypto
packages (`crypto/tls`, `crypto/rand`, `crypto/ecdsa`, `crypto/hmac`, …) route
through the validated module. Application code does **not** call a separate
crypto library; using the Go standard library *is* using the module.

## CMVP certificate

The CMVP validation for the Go Cryptographic Module v1.0.0 must be cited from
the authoritative NIST source, **not** transcribed from secondary material:

- NIST CMVP validated-modules search: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules>
- Search term: **"Go Cryptographic Module"**, version **v1.0.0**

**CMVP certificate #: `REQUIRES VERIFICATION` —** the System Owner must record
the exact certificate (or the Modules-In-Process / MIP-list entry if validation
is still pending) here and in the crypto inventory (`crypto-inventory.md`,
CRY-WU-18) before this artifact is submitted as SC-13 evidence. Recording an
unverified number would be an overstated compliance claim; this placeholder is
intentional until the certificate is confirmed.

## How FIPS mode is built and proven

1. **Build** — every binary is compiled with `GOFIPS140=v1.0.0`:
   - `make build` / `make verify-fips` (`GOFIPS140 ?= v1.0.0`)
   - `build/docker/admission-webhook.Dockerfile`, `build/docker/policy-manager.Dockerfile`, `build/Dockerfile.dashboard` (`ARG GOFIPS140=v1.0.0`)
2. **In-build assertion** — each Dockerfile and `make verify-fips` run
   `go version -m <binary> | grep GOFIPS140=v1.0.0` and fail the build if the
   marker is absent.
3. **CI gate** — the `fips-verify` job in `.github/workflows/ci.yml` runs
   `make verify-fips` and is a required check in `ci-gate`, so a binary that
   loses the FIPS marker cannot merge.
4. **Runtime** — containers set `ENV GODEBUG=fips140=on`; the
   [`internal/cryptofips`](../../internal/cryptofips/fips.go) startup self-test
   logs the effective FIPS state and **aborts** (`log.Fatal`) when
   `REQUIRE_FIPS=true` but the module is not active (CRY-WU-02). Production Helm
   values set `REQUIRE_FIPS=true`.

### Verifying a shipped binary

```console
$ go version -m dist/admission-webhook-linux-amd64 | grep GOFIPS140
        build   GOFIPS140=v1.0.0
        build   -tags=fips140v1.0
        build   DefaultGODEBUG=fips140=on
```

The presence of `GOFIPS140=v1.0.0` proves the binary was built against the
validated module; `DefaultGODEBUG=fips140=on` proves it defaults to FIPS mode at
runtime.

## Scope and boundaries

- **In scope:** TLS server/client handshakes, the internal bearer-token CSPRNG
  (`internal/auth`), audit-record HMAC (planned, AUD-WU-04), and any X.509 / key
  generation performed in-process.
- **Out of scope (inherited):** Kubernetes apiserver↔etcd encryption, the
  kubelet/apiserver TLS stack, and cert-manager's own crypto are cluster/CSP
  responsibilities documented separately (see CRY-WU-15 / CRY-WU-19).

## Related controls and work units

| Control | Implementation | Work unit |
|---|---|---|
| SC-13 | FIPS 140-3 validated module for all crypto | CRY-WU-01, CRY-WU-02 |
| SC-12 | FIPS-CSPRNG token generation; cert key strength | CRY-WU-14, CRY-WU-11 |
| SC-8 / SC-8(1) | TLS 1.3 in transit, config-driven cipher policy | CRY-WU-03 |

The approved algorithm/key-length matrix that every certificate and key must
meet is defined in [crypto-standards.md](crypto-standards.md) (CRY-WU-11).

See the key-management plan (`key-management-plan.md`) and crypto inventory
(`crypto-inventory.md`), both authored under CRY-WU-18, for the per-key detail.
