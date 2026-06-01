---
title: "Supply Chain Control Narrative — Kube-Policies (KP)"
control_family: "SR — Supply Chain Risk Management"
controls: "SR-1, SR-3, SR-4, SR-11, SI-7, RA-5"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Supply Chain Control Narrative — Kube-Policies (KP)

This document is the SSP-style control narrative for the supply-chain family. It maps the
implemented release pipeline ([`.github/workflows/release.yml`](../../.github/workflows/release.yml))
to NIST SP 800-53 Rev 5 controls SR-1, SR-3, SR-4, and SR-11 and to the SLSA Build L3 framework.
It states the **TARGET SLSA level** (L3), the **honest gap** between the implemented pipeline and
a demonstrated L3 attestation, and the status of each control.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is **not yet
authorized** (**no ATO**) and not in production use. This narrative describes controls that are
*implemented in the pipeline and statically verified* on the working branch
`feat/p0-compliance-foundation`. The branch has **not been pushed** to the remote; there is **no
live CI run** and **no published signed release** yet. Live attestation verification is PENDING the
first signed tag push. Open items are tracked in the [POA&M](POAM.md).

**Policy and procedures.** The governing SR policy is at
[policies/SR-policy.md](policies/SR-policy.md); operational procedures are at
[procedures/SR-procedures.md](procedures/SR-procedures.md); build-integrity notes from phase P1 are
at [../supply-chain/build-integrity.md](../supply-chain/build-integrity.md).

---

## 1 System and pipeline facts

| Fact | Value |
|---|---|
| Repository | `github.com/Jibbscript/kube-policies` |
| Container images | `ghcr.io/jibbscript/kube-policies/admission-webhook` · `ghcr.io/jibbscript/kube-policies/policy-manager` |
| Binary targets | linux/darwin/windows × amd64/arm64 (5 combinations) |
| Helm chart | `charts/kube-policies` |
| Release pipeline | `.github/workflows/release.yml` |
| Go toolchain | Go 1.25 (`go 1.25.0` in `go.mod`; `GOTOOLCHAIN=local`) |
| Signing method | Keyless cosign — workflow OIDC; no static key |
| OIDC subject (signing) | `^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| SBOM format | SPDX-JSON (per image, by digest) |
| Provenance tool | `actions/attest-build-provenance` (images + binaries) |
| Vulnerability gate | Trivy CRITICAL,HIGH; fixable only (`ignore-unfixed`); `.trivyignore` for time-boxed suppressions |
| Consumer verification | `scripts/verify-release.sh <version>`; [docs/supply-chain/verification.md](../supply-chain/verification.md) |

---

## 2 Control implementation summary

| Control | Title | Implementation status | Notes |
|---|---|---|---|
| SR-1 | Policy and Procedures | **Implemented** | [SR-policy.md](policies/SR-policy.md) + [SR-procedures.md](procedures/SR-procedures.md) |
| SR-3 | Supply Chain Controls and Plans | **Partial** | Dependency pinning + vuln gate + harden-runner implemented; egress block mode pending |
| SR-4 | Provenance | **Implemented (pipeline)** | SLSA provenance + SBOM attestation implemented; live tag not yet run |
| SR-11 | Component Authenticity | **Implemented (pipeline)** | Keyless signing implemented; live tag not yet run |
| SI-7 | Software, Firmware, and Information Integrity | **Partial** | Reproducible builds + signing implemented; admission-time enforcement opt-in only |
| RA-5 | Vulnerability Monitoring and Scanning | **Implemented** | Trivy gate in CI and release; SARIF upload to GitHub Security tab |

---

## 3 SLSA Build L3 — target level and gap analysis

### 3.1 Target level

The KP release pipeline is designed to reach **SLSA Build L3**: the build runs in an isolated,
ephemeral GitHub-hosted runner; provenance is signed by the build platform (Sigstore Fulcio +
Rekor via `actions/attest-build-provenance`); no persistent build credentials are used; and the
signing identity is bound to the specific workflow file and tag ref, not a long-lived secret.

### 3.2 SLSA Build L3 requirements and current status

| SLSA L3 requirement | Implemented | Evidence / notes |
|---|---|---|
| Scripted build | Yes | All build steps in `release.yml`; no manual intervention in the build itself |
| Build service | Yes | GitHub Actions hosted runners (ephemeral, isolated) |
| Isolated build | Yes | Each job runs in a fresh ephemeral runner; `step-security/harden-runner` monitors egress |
| Parameterless top-level build | Partial | Tag push triggers are parameter-free; `workflow_dispatch` input allows a version override — acceptable for L3 per SLSA spec |
| Provenance — available | Yes | `actions/attest-build-provenance` per image digest and per binary |
| Provenance — authenticated | Yes | Signed by Fulcio certificate bound to workflow OIDC; recorded in Rekor |
| Provenance — service generated | Yes | Provenance generated by GitHub's attestation service, not by the build script |
| Provenance — non-falsifiable | Yes | Signing key is ephemeral OIDC-derived; no long-lived private key in the repo |
| No secret parameters in provenance | Yes | No secrets embedded in build steps that generate provenance |
| Hermetic build | **Partial** | `harden-runner` in `audit` mode (not `block`); Go module download occurs at build time. Full hermetic block mode is a documented gap (see §4) |
| Reproducible build | **Partial** | Binaries: `SOURCE_DATE_EPOCH` + `-trimpath` + pinned toolchain. Container images: not claimed reproducible (BuildKit GHA cache) |

**Conclusion.** The pipeline satisfies the core L3 requirements for provenance authenticity,
isolation, and non-falsifiability. The two partial items (hermetic egress and image reproducibility)
do not disqualify L3 provenance per the SLSA specification but are honest gaps documented here and
in the POA&M.

### 3.3 Live attestation gap

**The pipeline is implemented and statically verified. No live signed tag has been pushed and no
published attestation exists.** L3 provenance is a property of a running pipeline producing a real
artifact; until the first `v*` tag is pushed and the full `release.yml` run completes successfully,
SLSA L3 is the *target* level, not the *demonstrated* level. This is the primary open item for the
SR control family.

Tracking: POA&M (see [POAM.md](POAM.md)) — open item SUP-WU pending live run.

---

## 4 SR-3 — Supply Chain Controls and Plans

### 4.1 Dependency pinning

| Component class | Pinning mechanism | Integrity verification |
|---|---|---|
| Go modules | Exact `vX.Y.Z` in `go.mod`; hash in `go.sum` | `go mod verify`; CI `GOFLAGS=-mod=readonly` |
| Frontend (web/) | `pnpm-lock.yaml` lockfile | `pnpm install --frozen-lockfile` in CI |
| GitHub Actions | 40-char commit SHA + version comment | Maintainer review on every update PR |
| Container base images | `@sha256:<digest>` in Dockerfile FROM lines | `scripts/pin-base-images.sh --write` + PR review |
| Dependabot | `.github/dependabot.yml` (gomod, npm, docker, github-actions) | PR + gating CI before merge |

### 4.2 Build isolation (harden-runner)

Build jobs (`build-release`, `build-images`, `generate-sbom`, `security-scan`,
`sign-attest-provenance`) run `step-security/harden-runner` (SHA-pinned:
`ab7a9404c0f3da075243ca237b5fac12c98deaa5`) with `egress-policy: audit`. This monitors outbound
network access and records egress events in the job log.

**Gap.** `egress-policy: audit` logs but does not block unexpected outbound connections. Full
`egress-policy: block` mode (with an explicit allow-list for required egress: GHCR, `pkg.go.dev`,
`sum.golang.org`, `sigstore.dev`, `rekor.sigstore.dev`, `fulcio.sigstore.dev`) is the next
hardening step. Until then, SR-3 build-isolation is **Partial**.

### 4.3 Vulnerability gate (RA-5 / SI-2)

The `security-scan` job scans the exact built image digests with Trivy:

- Severity: `CRITICAL,HIGH`
- `ignore-unfixed: true` (suppresses findings with no available fix)
- `.trivyignore`: time-boxed, dated suppressions with justification comments
- Exit code: `1` on findings (release-blocking gate)
- Non-gating SARIF pass: uploads full finding set to GitHub Security tab for visibility

The `sign-attest-provenance` job has `needs: security-scan` so a vulnerable image is **never
signed, attested, or published**.

---

## 5 SR-4 — Provenance

### 5.1 SBOM generation (generate-sbom job)

`anchore/sbom-action` (SHA-pinned: `e22c389904149dbc22b58101806040fa8d37a610`) generates SPDX-JSON
SBOMs for:

- `ghcr.io/jibbscript/kube-policies/admission-webhook@<digest>`
- `ghcr.io/jibbscript/kube-policies/policy-manager@<digest>`

SBOMs are generated against immutable digests (not tags), uploaded as workflow artifacts, and
attached as GitHub release assets.

In addition, `docker/build-push-action` is invoked with `provenance: mode=max` and `sbom: true`,
emitting OCI-native BuildKit provenance and an inline SBOM attestation alongside each image.

### 5.2 SBOM attestation (sign-attest-provenance job)

`cosign attest --type spdxjson --predicate <sbom> <image>@<digest>` records each SBOM in the
Sigstore Rekor transparency log, bound to the image digest by the signing certificate. This is the
authoritative SBOM record; the loose SPDX-JSON release assets are a convenience copy.

### 5.3 SLSA provenance attestation

`actions/attest-build-provenance` (SHA-pinned: `e8998f949152b193b063cb0ec769d69d929409be`) generates
signed in-toto SLSA provenance attestations for:

- `ghcr.io/jibbscript/kube-policies/admission-webhook@<digest>` (pushed to GHCR)
- `ghcr.io/jibbscript/kube-policies/policy-manager@<digest>` (pushed to GHCR)
- Release binaries `artifacts/binaries-*/admission-webhook-*` and `artifacts/binaries-*/policy-manager-*`
  (stored in GitHub attestations API)

### 5.4 Reproducible builds (SI-7)

`build-release` job:

```bash
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export SOURCE_DATE_EPOCH
go build -trimpath -ldflags="-s -w -X main.version=... -X main.commit=... -X main.date=..."
```

`CGO_ENABLED=0`, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`. Verified by
`scripts/verify-reproducible-build.sh`.

---

## 6 SR-11 — Component Authenticity

### 6.1 Image signing (sign-attest-provenance job)

```bash
cosign sign --yes "${IMAGE}@${DIGEST}"
```

- Keyless OIDC: no static private key; Fulcio ephemeral certificate; Rekor entry.
- Signatures pushed to GHCR alongside the image (OCI referrers API).
- Both images signed: `admission-webhook` and `policy-manager`.

### 6.2 Blob signing

`cosign sign-blob` over all binary artifacts, the Helm chart `.tgz`, and checksum files:

```bash
cosign sign-blob --yes \
  --output-signature "${f}.sig" \
  --output-certificate "${f}.pem" \
  "${f}"
```

`.sig` and `.pem` files are uploaded as GitHub release assets. Consumers can verify with
`cosign verify-blob` (see [SR procedures](procedures/SR-procedures.md) §4.4).

### 6.3 Admission-time verification (opt-in)

KP ships two optional admission-time signature-verification mechanisms:

1. **Bundled policy** (`internal/policy/engine.go`): an image-provenance policy that can enforce
   cosign signature presence at admission. Requires `imageVerification.enabled=true` in chart
   values (default `false`).
2. **ClusterImagePolicy** (chart value `imageVerification.enabled`, default `false`): deploys a
   Sigstore policy-controller `ClusterImagePolicy` referencing the KP OIDC signing identity.

These are **operator opt-in**; they are not enforced by the default chart installation. Enabling
them in production for the KP images themselves requires the images to already be signed — which
depends on at least one live signed release having been published. Default-off is appropriate for a
pre-1.0 PoC; turning it on is a post-ATO hardening step.

### 6.4 Signing identity

All artifact signatures (images and blobs) share the same OIDC identity:

| Field | Value |
|---|---|
| Subject regexp | `^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate authority | Sigstore Fulcio (public instance) |
| Transparency log | Sigstore Rekor (public instance) |

---

## 7 Gap register and POA&M cross-reference

| Gap ID | Description | Control | Severity | Remediation |
|---|---|---|---|---|
| SR-GAP-01 | No live signed release exists; SLSA L3 is target, not demonstrated | SR-4, SR-11 | High | Push branch; run first `v*` tag through release pipeline |
| SR-GAP-02 | `harden-runner` in `audit` mode; egress not blocked | SR-3 | Medium | Define egress allowlist; switch to `block` mode |
| SR-GAP-03 | Container image reproducibility not claimed | SI-7 | Low | Evaluate BuildKit determinism options; document scope |
| SR-GAP-04 | Admission-time signing enforcement default off | SR-11, SI-7 | Low (PoC) | Enable after first signed release is published |
| SR-GAP-05 | Named SR roles (ISSO, release engineer) not yet staffed | SR-1 | Medium | Assign before assessment; update roles-raci.md |

Open items are tracked in [POAM.md](POAM.md). Remediation of SR-GAP-01 (first live signed tag) is
the highest-priority SR action item.

---

## 8 References

- SR policy: [policies/SR-policy.md](policies/SR-policy.md)
- SR procedures: [procedures/SR-procedures.md](procedures/SR-procedures.md)
- Build integrity (P1): [../supply-chain/build-integrity.md](../supply-chain/build-integrity.md)
- Release pipeline: [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
- CI gates: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
- Consumer verification: [`scripts/verify-release.sh`](../../scripts/verify-release.sh) · [docs/supply-chain/verification.md](../supply-chain/verification.md)
- POA&M: [POAM.md](POAM.md) · Control matrix: [control-matrix.csv](control-matrix.csv) · Compliance index: [README.md](README.md)
- NIST SP 800-53 Rev 5 (SR-1, SR-3, SR-4, SR-11, SI-7, RA-5); NIST SP 800-161r1 (C-SCRM); NIST SP 800-218 (SSDF); FedRAMP Moderate baseline; SLSA Build L3 specification; Sigstore cosign documentation.
