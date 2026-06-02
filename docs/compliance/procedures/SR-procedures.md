---
title: "Supply Chain Risk Management Procedures (SR) — Kube-Policies (KP)"
control_family: "SR — Supply Chain Risk Management"
controls: "SR-1, SR-3, SR-4, SR-11, RA-5, SI-2, SI-7"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Supply Chain Risk Management Procedures — Kube-Policies (KP)

These are the operational procedures that implement the Supply Chain Risk Management policy
([../policies/SR-policy.md](../policies/SR-policy.md)) for the Kube-Policies system (KP). They
cover how SBOMs are produced and attested, how artifacts are signed, how vulnerability suppressions
are handled, how dependency updates are reviewed, and the cadence for recurring supply-chain
activities.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is **not yet
authorized** (**no ATO**). These procedures describe what is *actually implemented* in the shipped
pipeline and what an assessor or operator can run to verify it. Where a control is Partial or has a
residual, the procedure says so; open weaknesses are tracked in [../POAM.md](../POAM.md) and the
phased plan `../plans/remediation-roadmap.md`.

**Annual review.** These procedures are reviewed and updated at least **annually** (next review
**2027-06-01**) and on any significant change to the build pipeline, the signing/attestation
toolchain, the SBOM generator, or the vulnerability-gate configuration. Reviews are recorded by
updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the artifacts and components in
[SR-policy.md §1](../policies/SR-policy.md#1-purpose-and-applicability): container images, Go
binaries, the Helm chart, Go module and frontend dependencies, third-party GitHub Actions, and
container base images.

## 2 Release pipeline overview

The supply-chain controls execute in the following job sequence within
[`.github/workflows/release.yml`](../../../.github/workflows/release.yml):

```
validate-release
  └─ test-suite (reuses ci.yml)
       ├─ build-release      (reproducible Go binaries; checksums)
       ├─ package-helm       (chart .tgz)         [sibling]
       └─ build-images       (multi-arch; provenance:mode=max; sbom:true; by digest)
            ├─ generate-sbom (SPDX-JSON by digest; anchore/sbom-action)
            └─ security-scan (Trivy CRITICAL,HIGH gate; ignore-unfixed; .trivyignore)
                 └─ sign-attest-provenance  ← HARD GATE (needs generate-sbom + security-scan)
                      └─ create-release     ← tag-only (refs/tags/v*); if !failure()
                           └─ update-helm-repo / notify
```

`sign-attest-provenance` will not run if `security-scan` fails. `create-release` will not run if
`sign-attest-provenance` fails (or is skipped). A release cannot be published without passing the
vulnerability gate and completing signing/attestation.

> **Honest status.** The pipeline is implemented and statically verified on the working branch
> (`feat/p0-compliance-foundation`). The branch has not been pushed and **no live CI run or
> published signed release exists yet**. Live attestation verification is PENDING the first signed
> tag push to the remote.

## 3 SBOM production and attestation (SR-3 / SR-4)

### 3.1 How SBOMs are produced

The `generate-sbom` job runs after `build-images` and generates SPDX-JSON SBOMs against the
**immutable image digests** (not mutable tags) for both images:

- `ghcr.io/jibbscript/kube-policies/admission-webhook@<digest>` →
  `admission-webhook-sbom.spdx.json`
- `ghcr.io/jibbscript/kube-policies/policy-manager@<digest>` →
  `policy-manager-sbom.spdx.json`

Tool: `anchore/sbom-action` (SHA-pinned in release.yml). Format: `spdx-json`.

In addition, the `build-images` job emits an OCI-native BuildKit SBOM attestation inline alongside
each image (`sbom: true`). This is a complementary record, not the authoritative one.

### 3.2 How SBOMs are attested

The `sign-attest-provenance` job attests each SBOM to its image digest using
`cosign attest --type spdxjson --predicate <sbom-file> <image>@<digest>`. This:

- cryptographically binds the SBOM to the exact immutable artifact;
- records the attestation in the Sigstore Rekor transparency log;
- makes the SBOM verifiable independently of the GitHub release-assets.

The loose SPDX-JSON files are also attached as GitHub release assets for consumer convenience, but
the **authoritative, cryptographically-bound SBOM** is the cosign attestation.

### 3.3 Verifying an SBOM attestation

```console
# Retrieve and verify the cosign SBOM attestation for a given image digest:
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp \
    '^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/jibbscript/kube-policies/admission-webhook@<digest> \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

Replace `admission-webhook` with `policy-manager` and supply the appropriate digest.

## 4 Artifact signing and provenance (SR-4 / SR-11 / SI-7)

### 4.1 Container image signing

The `sign-attest-provenance` job signs each image by its immutable digest:

```bash
cosign sign --yes "${IMAGE}@${DIGEST}"
```

- **Keyless OIDC**: no static private key; the signing certificate is issued by Sigstore Fulcio
  using the GitHub Actions workflow OIDC token.
- **No `COSIGN_EXPERIMENTAL`**: the flag is not set; the standard keyless flow is used.
- Signatures and certificates are recorded in Rekor and pushed alongside the image in GHCR.

Signing identity (OIDC subject regexp):
```
^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$
```
OIDC issuer: `https://token.actions.githubusercontent.com`

### 4.2 Verifying an image signature

```console
cosign verify \
  --certificate-identity-regexp \
    '^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/jibbscript/kube-policies/admission-webhook@<digest>
```

### 4.3 SLSA provenance attestation

`actions/attest-build-provenance` generates a signed in-toto SLSA provenance attestation per image
digest and per binary artifact. Image attestations are pushed to GHCR; binary attestations are
stored in the GitHub attestations API.

Verify image provenance:
```console
gh attestation verify \
  --repo Jibbscript/kube-policies \
  oci://ghcr.io/jibbscript/kube-policies/admission-webhook@<digest>
```

Verify binary provenance:
```console
gh attestation verify --repo Jibbscript/kube-policies ./admission-webhook-linux-amd64
```

### 4.4 Blob signing (Helm chart, binaries, checksums)

`cosign sign-blob` produces a `.sig` signature file and a `.pem` Fulcio certificate bundle for each
binary, Helm chart `.tgz`, and checksum file. These are attached as GitHub release assets.

Verify a blob signature:
```console
cosign verify-blob \
  --certificate-identity-regexp \
    '^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature ./admission-webhook-linux-amd64.sig \
  --certificate ./admission-webhook-linux-amd64.pem \
  ./admission-webhook-linux-amd64
```

### 4.5 Consumer verification script

The end-to-end verification procedure for a published release is encapsulated in:

```console
scripts/verify-release.sh <version>
```

Full step-by-step instructions are in
[docs/supply-chain/verification.md](../../supply-chain/verification.md).

## 5 Vulnerability suppression handling (RA-5 / SI-2)

Suppressions are entered in `.trivyignore` at the repository root. Each suppression entry must
conform to the following rules:

1. **Comment block required.** Immediately above the CVE ID, include a comment block with:
   - `# CVE: <ID>`
   - `# Justification: <reason the CVE is accepted>` (e.g., not reachable in distroless runtime,
     upstream fix not yet released)
   - `# Added: YYYY-MM-DD`
   - `# Expires: YYYY-MM-DD` (maximum 90 days from `Added`; exceptions require ISSO approval)
   - `# Approved-by: <role, e.g., ISSO TBD>`
2. **ISSO review.** All new suppressions require ISSO review on the introducing PR.
3. **Expiry enforcement.** Expired suppressions are removed on the next working-day pass; if the
   underlying vulnerability is still unresolved, a new suppression with updated justification and a
   new expiry must be opened.
4. **Re-scan after removal.** When a suppression expires or is removed, re-run the Trivy gate
   locally to confirm the build still passes before merging.

```console
# Run the gating Trivy scan locally (mirrors the CI gate):
trivy image --severity CRITICAL,HIGH --ignore-unfixed \
  --ignorefile .trivyignore --exit-code 1 \
  ghcr.io/jibbscript/kube-policies/admission-webhook@<digest>
```

All active suppressions are change-controlled via PR and referenced in the
[POA&M](../POAM.md) as open risk-accepted findings.

## 6 Dependency update review (SR-3)

### 6.1 Automated updates (Dependabot)

Dependabot is configured in [`.github/dependabot.yml`](../../../.github/dependabot.yml) for the
`gomod`, `npm`, `docker`, and `github-actions` ecosystems. Dependabot PRs:

- are subject to the same PR + gating-CI review as any change (CM-3);
- must not be merged if any gating job fails;
- for `github-actions` updates, the Maintainer must confirm the new SHA is authentic (e.g.,
  `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`).

### 6.2 Manual dependency review cadence

| Dependency class | Review cadence | Trigger |
|---|---|---|
| Go modules (`go.mod`) | Per PR adding/updating a dep + quarterly | CVE advisory; Dependabot PR; Go toolchain update |
| Frontend (`pnpm-lock.yaml`) | Per PR adding/updating a dep + quarterly | CVE advisory; Dependabot PR |
| Container base images | Per release + quarterly | New upstream digest; CVE advisory |
| GitHub Actions (SHA pins) | Per PR updating a pin + quarterly | Dependabot PR; upstream release with security fix |

### 6.3 Go module integrity check

```console
# Verify all cached modules match go.sum:
go mod verify

# Detect go.sum drift:
go mod tidy && git diff --exit-code go.sum
```

### 6.4 Refreshing base image digests

```console
scripts/pin-base-images.sh --write
# Review and commit the updated @sha256: pins; open a PR.
```

## 7 Reproducible build verification (SI-7 / SLSA)

The `build-release` job uses `SOURCE_DATE_EPOCH` (from `git log -1 --pretty=%ct`) rather than
wall-clock time, `-trimpath`, `CGO_ENABLED=0`, and `GOTOOLCHAIN=local` to produce a build that is
a deterministic function of `(commit, GOOS, GOARCH)`.

To verify reproducibility locally:

```console
scripts/verify-reproducible-build.sh
```

This script builds the binaries twice independently and compares the SHA-256 hashes.

> **Residual.** Full bit-for-bit reproducibility (including binary-identical across different Go
> build caches) is verified by `scripts/verify-reproducible-build.sh`. Container-image
> reproducibility is not claimed; the build uses BuildKit layer caching (`cache-from: type=gha`),
> which means image layer hashes are not guaranteed to be identical across independent runs. This is
> a documented gap tracked in the POA&M.

## 8 Third-party component acceptance procedure (SR-3 / SR-11)

When a PR introduces or updates a third-party component (action, base image, Go module, npm
package):

1. **Confirm it is maintained.** Check the upstream repository for recent activity and an active
   security policy. End-of-life or archived components require ISSO review.
2. **Pin to an immutable reference.** Go modules: use an exact `vX.Y.Z` version pinned in
   `go.sum`. Actions: pin to a 40-character commit SHA with a version comment. Base images: pin to
   `@sha256:<digest>`. npm: `pnpm-lock.yaml` records the exact resolved version.
3. **Record in the PR.** The PR description must note the component, its version/SHA, the upstream
   source, and whether a CVE check was performed.
4. **Run the full gate locally** before requesting review:
   ```console
   trivy fs --severity CRITICAL,HIGH --exit-code 1 .
   go mod verify
   ```
5. **Maintainer approval required.** At least one Maintainer/CODEOWNER approves before merge.

## 9 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| Review `.trivyignore` for expired entries | Monthly | ISSO |
| Reconcile component inventory against shipped release | Per release | Release engineer |
| Review Dependabot PRs | As generated (target: within 5 business days) | Maintainer |
| Full dependency review (all classes) | Quarterly | ISSO + Maintainer |
| Update base-image digest pins | Per release + on advisory | Release engineer |
| Review this procedures document | Annually (next: 2027-06-01) | ISSO |
| Review SR policy | Annually (next: 2027-06-01) | ISSO |

## 10 Records and evidence

Evidence produced by these procedures is retained as SR/SI assessment evidence:

- Pipeline run logs (GitHub Actions): signing step output, Trivy gate results, SBOM artifact
  checksums.
- Cosign attestations recorded in Rekor: permanent, publicly verifiable.
- GitHub attestations API entries: binary provenance records.
- GitHub release assets: loose SBOM files, `.sig` + `.pem` bundles per artifact.
- `.trivyignore` history (git log): time-boxed suppression audit trail.
- Dependabot PR merge history: dependency update evidence.

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), SR family).

## 11 References

- SR policy: [../policies/SR-policy.md](../policies/SR-policy.md)
- Supply-chain control narrative: [../supply-chain.md](../supply-chain.md)
- Build integrity (P1): [../../supply-chain/build-integrity.md](../../supply-chain/build-integrity.md)
- Consumer verification: [`scripts/verify-release.sh`](../../../scripts/verify-release.sh) · [docs/supply-chain/verification.md](../../supply-chain/verification.md)
- Release pipeline: [`.github/workflows/release.yml`](../../../.github/workflows/release.yml) · CI gates: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
- Dependabot config: [`.github/dependabot.yml`](../../../.github/dependabot.yml) · Base-image pin script: [`scripts/pin-base-images.sh`](../../../scripts/pin-base-images.sh)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- CM procedures (change-control anchor): [CM-procedures.md](CM-procedures.md)
- NIST SP 800-53 Rev 5 (SR-1, SR-3, SR-4, SR-11, RA-5, SI-2, SI-7); NIST SP 800-161r1 (C-SCRM); NIST SP 800-218 (SSDF); FedRAMP Moderate baseline; SLSA Build L3 specification.
