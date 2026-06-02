# Verifying the Signed Policy Bundle

`kube-policies` ships a bundled policy library — the Rego rules the admission
engine actually enforces (`internal/policy`). To let deployers verify the
**integrity and origin** of that rule set independently of the container images
and binaries, each release produces a signed, SLSA-attested **policy bundle
manifest** (POL-WU-27).

## What is signed

- **`policy-bundle-manifest.json`** — the canonical, deterministic description of
  the shipped library: the bundle SemVer (`policy.PolicyBundleVersion`), the
  shared library module sources (`internal/policy/rego/*.rego`), and every
  bundled rule's stable ID, owning policy, target kinds, and Rego body, in a
  fixed order.
- **`policy-bundle.sha256`** — the SHA-256 digest of that manifest.

The manifest is a pure function of the source tree, so the digest is
**reproducible**: anyone can regenerate it from a checkout and confirm it matches
the released, signed value.

```bash
# Reproduce the digest from source
go run ./cmd/policybundle digest
# or
make policy-bundle-digest
```

## How it is signed

The release workflow (`.github/workflows/release.yml`):

1. `build-policy-bundle` generates `policy-bundle-manifest.json` and
   `policy-bundle.sha256`.
2. `sign-attest-provenance` keyless-signs both with cosign (Fulcio certificate +
   Rekor transparency log) and attaches an in-toto **SLSA provenance**
   attestation over the manifest.

Signatures are bound to the workflow's OIDC identity:
`https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v*`.

## Verifying a release

```bash
# 1. Verify the cosign signature over the manifest (keyless).
cosign verify-blob \
  --certificate policy-bundle-manifest.json.pem \
  --signature   policy-bundle-manifest.json.sig \
  --certificate-identity-regexp '^https://github.com/.+/.github/workflows/release.yml@refs/tags/v.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  policy-bundle-manifest.json

# 2. Verify the SLSA provenance attestation.
gh attestation verify policy-bundle-manifest.json --repo <owner>/<repo>

# 3. Confirm the manifest matches the source you build from.
test "$(sha256sum policy-bundle-manifest.json | cut -d' ' -f1)" = "$(cat policy-bundle.sha256)"
go run ./cmd/policybundle digest   # must equal policy-bundle.sha256
```

A mismatch in step 3 means the deployed rule set differs from the signed,
released library — treat it as a supply-chain integrity failure.

## CI guard

The `policy-library` CI job re-derives the digest twice and fails if it is not
reproducible, so a non-deterministic change to the rule set is caught before
release. The full `./internal/policy/...` suite (per-rule allow/deny coverage,
control-traceability matrix, the customer-policy compile gate, and profile
selection) runs in the same job.
