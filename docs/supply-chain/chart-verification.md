# Helm Chart Verification (SUP-WU-14)

Controls: NIST SR-4, CM-14

This document explains how the Helm chart is signed at release time and how
operators can verify the chart's integrity before running `helm install` or
`helm upgrade`.

---

## How the chart is signed

The `sign-attest-provenance` job in `release.yml` signs the packaged Helm chart
with a keyless cosign signature after the `security-scan` gate passes. For each
artifact (binaries, checksums, and the Helm chart `.tgz`) the job runs:

```bash
cosign sign-blob --yes \
  --output-signature "${artifact}.sig" \
  --output-certificate "${artifact}.pem" \
  "${artifact}"
```

The signing identity is the GitHub Actions OIDC token issued to the
`sign-attest-provenance` job in `release.yml` running on the release tag. The
resulting Fulcio certificate embeds the workflow identity as the Subject
Alternative Name (SAN):

```
^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$
```

Both the `.sig` and `.pem` files ship as release assets alongside the chart
`.tgz`. There is no static public key to distribute — trust is anchored to
the GitHub Actions OIDC issuer and the workflow identity regexp above.

---

## Release assets

For a release `v1.2.3` the following chart-related assets are attached to the
GitHub release:

| File | Description |
|------|-------------|
| `kube-policies-1.2.3.tgz` | Packaged Helm chart |
| `kube-policies-1.2.3.tgz.sig` | Detached cosign signature |
| `kube-policies-1.2.3.tgz.pem` | Fulcio certificate bundle |
| `chart-checksums.txt` | SHA-256 checksum of the `.tgz` |
| `chart-checksums.txt.sig` | Signature over the checksum file |
| `chart-checksums.txt.pem` | Certificate bundle for the checksum signature |

---

## Verifying the chart before install

Download the three chart files (`*.tgz`, `*.sig`, `*.pem`) from the GitHub
release assets, then run:

```bash
VERSION=v1.2.3
ASSET="kube-policies-${VERSION#v}.tgz"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
IDENTITY_REGEXP="^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/${VERSION}$"

cosign verify-blob \
  --certificate "${ASSET}.pem" \
  --signature "${ASSET}.sig" \
  --certificate-identity-regexp "${IDENTITY_REGEXP}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${ASSET}"
```

A successful verification prints:

```
Verified OK
```

If the chart has been tampered with, or the signature was produced by a
different workflow or identity, cosign exits non-zero with an error.

### Using verify-release.sh

`scripts/verify-release.sh <version>` automates this check. If the chart
`.tgz`, `.sig`, and `.pem` are present in the current working directory when
the script runs, it verifies them automatically as part of the blob-signature
pass:

```bash
# Download assets alongside the script, then:
scripts/verify-release.sh v1.2.3
```

---

## Cross-checking the SHA-256 checksum

After signature verification, confirm the chart matches the published checksum:

```bash
sha256sum --check chart-checksums.txt
```

---

## Installing the verified chart

After verification, install normally with Helm. Pin the chart to its immutable
digest if your Helm client supports OCI:

```bash
# Standard install from GitHub release
helm install kube-policies ./kube-policies-1.2.3.tgz \
  --namespace kube-policies-system \
  --create-namespace
```

For production deployments, also set image digests in your values override to
pin the container images immutably (see `values.yaml`:
`admissionWebhook.image.digest` and `policyManager.image.digest`).

---

## Pre-1.0 notice

No signed release has been published yet. The workflow and signing
infrastructure are in place; the commands above will work once the first
release tag is cut and the pipeline runs. Until then, `cosign verify-blob`
will report that the assets are not found — that is expected, not a failure of
the tooling.
