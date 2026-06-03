---
title: "Supply-Chain Cryptographic Signing & Verification — Kube-Policies (KP)"
control_family: "SC — System and Communications Protection; SI — System and Information Integrity; SR — Supply Chain Risk Management"
controls: "SC-12, SI-7, SR-4, SR-11; NIST SP 800-190; SLSA Build L3"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Supply-Chain Cryptographic Signing & Verification — Kube-Policies (KP)

This document describes the **keyless signing model**, the **exact verification identity**,
**how to verify a release locally**, the **admission-time enforcement** mechanism, and the
**CI verify gate** that together implement NIST **SC-12**, **SI-7**, **SR-4**, and **SR-11**
for Kube-Policies.  It is a focused companion to the broader supply-chain control narrative
([supply-chain.md](supply-chain.md)) and the SR policy ([policies/SR-policy.md](policies/SR-policy.md)).

> **Honesty note.** KP is a **pre-1.0 Proof-of-Concept being driven to FedRAMP-Moderate
> readiness**; it is **not yet authorized** (**no ATO**) and not in production use.  The
> signing pipeline is **implemented and statically verified** on branch
> `feat/p0-compliance-foundation`.  The branch has not been pushed; there is **no published
> signed release yet**, so live Rekor inclusion proofs are **PENDING** the first `v*` tag
> push.  Once live, all `cosign verify` and `gh attestation verify` commands below will
> succeed against real artifacts.

---

## 1. Keyless Fulcio/Rekor signing model

KP uses **keyless cosign** (Sigstore public-good instance) for all artifact signing.  There
is **no long-lived private key** — no KMS key to rotate, no secret to leak, no key escrow.

### 1.1 How keyless signing works

At release time the GitHub Actions runner presents its **OIDC workload-identity token** to
**Sigstore Fulcio**, which issues an **ephemeral X.509 signing certificate** valid for
approximately 10 minutes.  The certificate's Subject Alternative Name (SAN) encodes the
exact workflow identity that requested it.  cosign uses this certificate to sign the artifact
digest, then records both the signature and the certificate in the **Sigstore Rekor**
transparency log before the ephemeral certificate expires.

Verification does not require the private key — it requires only:

1. The public Fulcio root certificate (bundled with cosign).
2. A Rekor inclusion proof that the signature was logged before the certificate expired.
3. The **signing identity** (issuer + subject regexp) to assert that the signer was
   specifically this repo's release workflow running on a tag ref.

### 1.2 Key management statement

| Property | Value |
|---|---|
| Long-lived private key | **None** — signing key is ephemeral (Fulcio-issued, ~10 min TTL) |
| KMS / HSM | **Not used** — GitHub OIDC token is the root credential |
| Key rotation | **Not applicable** — ephemeral keys cannot persist to require rotation |
| Secret storage | No signing secret in repository secrets, Vault, or any external store |
| Revocation | Rekor inclusion proof is the trust anchor; no CRL/OCSP for short-lived certs |
| Transparency | Every signature produces a tamper-evident **Rekor** log entry (publicly auditable) |

This approach implements **NIST SC-12** (cryptographic key establishment and management) via
the Sigstore trust model: the public Fulcio root is the CA; the Rekor log is the audit trail.

### 1.3 Rekor transparency log

Every cosign signature, SBOM attestation, and SLSA provenance attestation produces a
**Rekor log entry** containing:

- The artifact digest that was signed.
- The Fulcio signing certificate (including the OIDC identity SAN).
- The signature itself.
- A signed tree-head inclusion proof.

The log is append-only and publicly auditable at `https://rekor.sigstore.dev`.  Log entries
are retained indefinitely by the Sigstore public-good instance.  Consumers can independently
verify the inclusion proof without trusting KP's infrastructure.

---

## 2. Signing identity

All artifact signatures produced by the `sign-attest-provenance` job in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) share a single,
consumer-verifiable OIDC identity:

| Field | Value |
|---|---|
| **Certificate identity regexp** | `^https://github\.com/Jibbscript/kube-policies/\.github/workflows/release\.yml@refs/tags/v\.\*\$` |
| **OIDC issuer** | `https://token.actions.githubusercontent.com` |
| **Certificate authority** | Sigstore Fulcio (public instance) |
| **Transparency log** | Sigstore Rekor (public instance) |

The identity is intentionally narrow:

- The **subject** must match the `release.yml` workflow file in *this* repository — not a
  fork, not a different workflow.
- The **ref** must be `refs/tags/v*` — not a branch (`refs/heads/…`) and not a
  `workflow_dispatch` on an arbitrary ref.

A signature from a fork, a branch build, or any workflow other than `release.yml@refs/tags/v*`
will fail verification even if it was produced with cosign, because the Fulcio certificate
SAN will not match the regexp.

---

## 3. What is signed

The `sign-attest-provenance` job (release.yml, gated `if: startsWith(github.ref, 'refs/tags/v')`)
signs and attests every artifact produced by a release:

| Artifact | Signing mechanism | Verification tool |
|---|---|---|
| `admission-webhook` container image | `cosign sign` by immutable digest | `cosign verify` |
| `policy-manager` container image | `cosign sign` by immutable digest | `cosign verify` |
| SPDX-JSON SBOM (per image, by digest) | `cosign attest --type spdxjson` | `cosign verify-attestation --type spdxjson` |
| SLSA provenance (images + binaries) | `actions/attest-build-provenance` | `gh attestation verify` |
| Release binaries, Helm chart, checksums | `cosign sign-blob` (`.sig` + `.pem`) | `cosign verify-blob` |

All image operations are performed against **immutable digests** (`image@sha256:…`), not
mutable tags.  A moved tag cannot swap an artifact out from under its attestation.

---

## 4. Verifying a release locally

### 4.1 Prerequisites

```bash
# Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/)
brew install cosign          # macOS
# or
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Install the GitHub CLI (for SLSA provenance via gh attestation verify)
brew install gh
gh auth login
```

### 4.2 Verify a container image signature

Replace `<version>` with the release tag (e.g. `v1.0.0`) and `<image>` with
`admission-webhook` or `policy-manager`:

```bash
IMAGE="ghcr.io/jibbscript/kube-policies/<image>:<version>"

cosign verify \
  --certificate-identity-regexp \
    '^https://github\.com/Jibbscript/kube-policies/\.github/workflows/release\.yml@refs/tags/v\.\*\$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${IMAGE}"
```

A successful verification prints the signing certificate details and exits 0.  Any failure
(unsigned image, tampered manifest, wrong identity) exits non-zero with a descriptive error.

### 4.3 Verify the SPDX-JSON SBOM attestation

```bash
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp \
    '^https://github\.com/Jibbscript/kube-policies/\.github/workflows/release\.yml@refs/tags/v\.\*\$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${IMAGE}"
```

On success, cosign prints the SBOM attestation payload (SPDX-JSON) to stdout.

### 4.4 Verify SLSA provenance via the GitHub attestations API

```bash
# For a container image (by digest):
gh attestation verify oci://ghcr.io/jibbscript/kube-policies/<image>@<digest> \
  --owner Jibbscript

# For a release binary:
gh attestation verify ./admission-webhook-linux-amd64 \
  --owner Jibbscript
```

### 4.5 Verify a release binary blob signature

```bash
# Download the binary, its .sig, and its .pem from the GitHub release assets, then:
cosign verify-blob \
  --certificate-identity-regexp \
    '^https://github\.com/Jibbscript/kube-policies/\.github/workflows/release\.yml@refs/tags/v\.\*\$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature admission-webhook-linux-amd64.sig \
  --certificate admission-webhook-linux-amd64.pem \
  admission-webhook-linux-amd64
```

A convenience wrapper for all of the above is available at
[`scripts/verify-release.sh`](../../scripts/verify-release.sh).

---

## 5. Admission-time enforcement (ClusterImagePolicy)

At runtime, the chart ships an optional **Sigstore policy-controller ClusterImagePolicy**
([`charts/kube-policies/templates/image-verification-policy.yaml`](../../charts/kube-policies/templates/image-verification-policy.yaml))
that enforces signature verification **before any KP image is admitted to the cluster**.

The policy is **disabled by default** (`imageVerification.enabled: false`) and requires the
Sigstore policy-controller to be installed as a prerequisite.  Enable it after the first
signed release is published:

```yaml
# values.yaml override
imageVerification:
  enabled: true
  mode: enforce        # enforce = reject unsigned/untrusted images; warn = audit only
  oidcIssuer: "https://token.actions.githubusercontent.com"
  identityRegexp: "^https://github\\.com/Jibbscript/kube-policies/\\.github/workflows/release\\.yml@refs/tags/v\\.\\*\\$"
  imagePatterns:
    - "ghcr.io/jibbscript/kube-policies/admission-webhook*"
    - "ghcr.io/jibbscript/kube-policies/policy-manager*"
```

When enabled in `enforce` mode, the policy-controller rejects any pod whose image does not
carry a valid cosign signature from the documented OIDC identity.  This closes the loop
between the pipeline signing gate and runtime enforcement (NIST CM-14 / SP 800-190 §4.3).

---

## 6. CI verify gate (verify-supply-chain.yml)

The workflow [`.github/workflows/verify-supply-chain.yml`](../../.github/workflows/verify-supply-chain.yml)
provides an automated **post-release verification gate** (CRY-WU-20):

| Trigger | Behavior |
|---|---|
| `release: published` | Verifies both images for the published release tag |
| `push: tags: v*` | Verifies both images immediately after the release pipeline signs them |
| `workflow_dispatch` | Accepts an optional `image-ref` input for ad-hoc spot-checks |

The job fails if either image is unsigned, has a tampered manifest, or was signed by an
identity that does not match the documented regexp.  It also verifies the SPDX-JSON SBOM
attestation for each image.

This gate is intentionally **separate** from the release pipeline so that the signing job
(`release.yml`) and the verification job (`verify-supply-chain.yml`) run in independent
workflow contexts — a signing-job compromise cannot suppress its own verification.

---

## 7. Control mapping

| Control | Requirement | Implementation |
|---|---|---|
| **SC-12** | Cryptographic key establishment and management | Keyless Fulcio model — no long-lived keys; §1 |
| **SI-7** | Software, firmware, and information integrity | cosign signature + SLSA provenance per artifact; CI verify gate; §3, §6 |
| **SR-4** | Provenance | SLSA provenance attestation via `actions/attest-build-provenance`; SPDX SBOM attestation via `cosign attest`; §3 |
| **SR-11** | Component authenticity | All images and blobs signed by documented OIDC identity; §2, §3 |
| **SP 800-190 §4.3** | Image provenance and integrity | Digest-pinned images; cosign signature; optional ClusterImagePolicy; §5 |
| **SLSA Build L3** | Provenance authenticity, isolation, non-falsifiability | Ephemeral runners + Fulcio ephemeral cert + Rekor log; [supply-chain.md](supply-chain.md) §3 |

---

## 8. References

- Supply-chain control narrative: [supply-chain.md](supply-chain.md) (SR-1/SR-3/SR-4/SR-11)
- SR policy: [policies/SR-policy.md](policies/SR-policy.md)
- SR procedures: [procedures/SR-procedures.md](procedures/SR-procedures.md)
- Release pipeline (signing): [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
- Verify gate (CI): [`.github/workflows/verify-supply-chain.yml`](../../.github/workflows/verify-supply-chain.yml)
- Admission-time policy: [`charts/kube-policies/templates/image-verification-policy.yaml`](../../charts/kube-policies/templates/image-verification-policy.yaml)
- Consumer verification script: [`scripts/verify-release.sh`](../../scripts/verify-release.sh)
- POA&M: [POAM.md](POAM.md)
- NIST SP 800-53 Rev 5: SC-12, SI-7, SR-4, SR-11; NIST SP 800-190 §4.3; SLSA Build L3 specification; Sigstore cosign documentation; FedRAMP Moderate baseline.
