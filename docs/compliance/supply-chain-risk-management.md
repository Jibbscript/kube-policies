---
title: "Supply-Chain Risk Management (SCRM) Plan — Kube-Policies (KP)"
control_family: "SR / SA — Supply Chain Risk Management & System & Services Acquisition"
controls: "SR-1, SR-2, SR-3, SR-4, SR-5, SR-11, SA-12, SA-15; NIST SP 800-218 PO.1/PO.2/PO.3/PS.1"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Supply-Chain Risk Management (SCRM) Plan — Kube-Policies (KP)

This is the **canonical SCRM plan** for the Kube-Policies (KP) system (work unit **SUP-WU-17**),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate** baseline).
It realizes the **SR-2 (Supply Chain Risk Management Plan)** requirement, and is the traceability
artifact ATO reviewers consume to confirm that **every produced release artifact** is tied to a
specific NIST **SR/SA** control and **NIST SP 800-218 (SSDF)** practice.

It is the **planning** companion to the supply-chain **control narrative**
([supply-chain.md](supply-chain.md), SSP-style SR-1/SR-3/SR-4/SR-11), the **SR policy**
([policies/SR-policy.md](policies/SR-policy.md)), the **SR procedures**
([procedures/SR-procedures.md](procedures/SR-procedures.md)), the **build-pipeline threat model**
([build-threat-model.md](build-threat-model.md)), and the phase-P1 **build-integrity** notes
([../supply-chain/build-integrity.md](../supply-chain/build-integrity.md)). It is driven entirely
by the **real pipeline** ([`.github/workflows/release.yml`](../../.github/workflows/release.yml)
and [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) — every artifact, action pin,
base-image digest, and gate named below is taken **verbatim** from those workflows.

> **Honesty note.** KP is a **pre-1.0 Proof-of-Concept being driven to assessment readiness**;
> it is **not authorized** (**NO ATO**) and not in production use. The controls below are
> **IMPLEMENTED in the pipeline and statically verified** on the working branch
> `feat/p0-compliance-foundation`. That branch has **not been pushed**; there is **no live CI
> run** and **no published signed release** yet, so **live attestation/provenance verification is
> PENDING the first signed `v*` tag**. Throughout, "**implemented**" means the control exists in
> the workflow/source and was statically verified; it is distinguished from "**operating /
> assessed**", which requires the first signed tag and an independent assessment. Open weaknesses
> are tracked in the [POA&M](POAM.md) and are cross-referenced inline.
>
> **Annual review.** This plan is reviewed at least **annually** (next review **2027-06-01**) and
> whenever the build pipeline, the artifact set, the trust list, or a root-of-trust anchor
> materially changes — consistent with **SR-1**.

---

## 1. Scope, methodology, and conventions

**Scope.** The SCRM boundary is the **software supply chain that produces the KP release** —
from first-party source through the GitHub Actions build pipeline to the published, signed
artifacts a consumer installs. In scope: the build toolchain, third-party GitHub Actions, base
container images, the SBOM/scan/sign/attest gates, and the produced artifacts. Out of scope (and
**Inherited** from the platform, modeled as trust anchors in §6 / the
[build-threat model](build-threat-model.md)): the GitHub-hosted runner OS image, the Sigstore
public good instances (Fulcio/Rekor), and the GHCR registry control plane.

**System facts (from the real pipeline).**

| Fact | Value |
|---|---|
| Repository | `github.com/Jibbscript/kube-policies` |
| Container images | `ghcr.io/jibbscript/kube-policies/admission-webhook` · `ghcr.io/jibbscript/kube-policies/policy-manager` |
| Binary targets | linux/darwin/windows × amd64/arm64 (windows/arm64 excluded → 5 combinations) |
| Helm chart | `charts/kube-policies` (chart `1.3.0`, appVersion `1.0.0`) |
| Release pipeline | [`.github/workflows/release.yml`](../../.github/workflows/release.yml) |
| CI pipeline | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) |
| Go toolchain | Go 1.25 (`go 1.25.0` in `go.mod`; `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`) |
| Signing method | Keyless cosign — workflow OIDC; **no static private key** |
| OIDC signing identity (regexp) | `^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| SBOM format | SPDX-JSON, per image, **by digest** |
| Provenance | `actions/attest-build-provenance` (images + binaries); buildkit `provenance: mode=max` |
| Vulnerability gate | Trivy `CRITICAL,HIGH`, `ignore-unfixed=true`, `.trivyignore` dated suppressions; **gates signing via `needs:`** |
| Reproducibility | `SOURCE_DATE_EPOCH` + `-trimpath` + `CGO_ENABLED=0` (`scripts/verify-reproducible-build.sh`; CI `reproducible-build` job) |

**Methodology.** This plan applies **NIST SP 800-161r1 (C-SCRM)** layered with the
**NIST SP 800-218 Secure Software Development Framework (SSDF)** and the **SLSA Build L3** model.
The core artifact is the **artifact → control → SSDF practice** map in §3: every byte that leaves
the pipeline is enumerated and tied to the SR/SA control and SSDF practice that protects it.

**Mapping rule.** Each row maps **artifact → producing pipeline step → SR/SA control → SSDF
practice → status**. `status` is `Implemented` (in pipeline, statically verified) or
`Implemented (verify pending live tag)` where the *control* is implemented but its *operating
evidence* (a Rekor entry, a registry-pushed attestation) only materializes on the first signed
tag. Where an SR/SA objective is **not yet met**, the row carries the open [POA&M](POAM.md) id.

---

## 2. SCRM control objectives and SSDF crosswalk

| Control | Title | What it requires here | Status | Evidence / POA&M |
|---|---|---|---|---|
| **SR-1** | Policy & Procedures | An SR policy + procedures + this plan, reviewed annually | **Implemented** | [SR-policy.md](policies/SR-policy.md), [SR-procedures.md](procedures/SR-procedures.md), this plan |
| **SR-2** | SCRM Plan | A plan mapping artifacts→controls and a trust list | **Implemented** (this document) | this plan; **POAM-033** (governance close-out) |
| **SR-3** | Supply Chain Controls & Plans | Pinned deps, vuln gate, build-isolation/egress audit | **Partial** | trust list §4; harden-runner audit (egress block pending) — **POAM-033** |
| **SR-4** | Provenance | Signed SLSA provenance + attested SBOM per artifact, by digest | **Implemented (verify pending live tag)** | §3; `attest-build-provenance`, cosign attest — **POAM-015** |
| **SR-5** | Acquisition Strategies / Tools / Methods | Digest/SHA pinning + Dependabot keeps trust list current | **Implemented** | §4; [dependabot.yml](../../.github/dependabot.yml) — **POAM-023** |
| **SR-11** | Component Authenticity | Keyless signatures verifiable by consumers against a documented identity | **Implemented (verify pending live tag)** | §3, §5; `scripts/verify-release.sh` — **POAM-015** |
| **SA-12** | Supply Chain Protection *(legacy; → SR family in Rev 5)* | End-to-end protection of the build/delivery chain | **Partial** | realized by SR-3/SR-4/SR-11 + [build-threat-model.md](build-threat-model.md) |
| **SA-15** | Development Process, Standards & Tools | Secure-SDLC quality gates in CI (lint, vet, govulncheck, reproducible build, conftest gates) | **Partial** | [`ci.yml`](../../.github/workflows/ci.yml) `ci-gate` — **POAM-034** |

**SSDF (NIST SP 800-218) crosswalk** — the SSDF practices this plan and pipeline realize:

| SSDF practice | Meaning | Where realized in KP |
|---|---|---|
| **PO.1** | Define security requirements for software development | this plan + [SR-policy.md](policies/SR-policy.md); SR/SA control set in §2 |
| **PO.2** | Implement roles and responsibilities | [roles-raci.md](roles-raci.md); SR roles **TBD-assign** (**POAM-018**) |
| **PO.3** | Implement supporting toolchains | pinned toolchain §1; trust list §4; SHA-pinned actions + digest-pinned bases |
| **PO.5** | Implement and maintain secure environments | GitHub-hosted ephemeral runner + harden-runner egress audit (§4, §6) |
| **PS.1** | Protect all forms of code from unauthorized access/tampering | branch protection (target), `GOFLAGS=-mod=readonly`, `go mod verify` (CI `lint`) |
| **PS.2** | Provide a mechanism for verifying software release integrity | keyless cosign sign/attest + SLSA provenance + checksums (§3, §5) |
| **PS.3** | Archive and protect each software release | release assets + Rekor transparency entries + GitHub attestations API (§5) |
| **PW.4** | Reuse existing, well-secured software | digest-pinned distroless base; Dependabot SCA across all ecosystems (§4) |
| **RV.1** | Identify and confirm vulnerabilities on an ongoing basis | Trivy gate + govulncheck + gosec + Dependabot (§4) — **POAM-025/026** |

---

## 3. Artifact → control → SSDF map (the traceability core)

Every artifact the [release pipeline](../../.github/workflows/release.yml) emits, the step that
produces it, the protections applied, and the SR/SA control + SSDF practice that govern it. All
signing/attestation is performed **by immutable digest**, keyless via workflow OIDC, in the
`sign-attest-provenance` job, which **`needs: security-scan`** (a fixable CRITICAL/HIGH fails the
release before anything is signed) and is itself a **hard gate** on `create-release`.

| # | Artifact | Producing step (job) | Integrity protection produced | SR/SA control | SSDF | Status |
|---|---|---|---|---|---|---|
| A-1 | **admission-webhook image** (`linux/amd64,arm64`, multi-arch) | `build-images` → `build-push-action` (push **by digest**, `provenance: mode=max`, `sbom: true`) | cosign keyless **signature** by digest; **SLSA provenance** attestation; **SPDX SBOM** attestation; buildkit OCI provenance+SBOM | SR-4, SR-11, SI-7 | PS.2, PS.3 | Implemented (verify pending live tag) |
| A-2 | **policy-manager image** (`linux/amd64,arm64`, multi-arch) | `build-images` → `build-push-action` (push **by digest**, `provenance: mode=max`, `sbom: true`) | cosign signature by digest; SLSA provenance; SPDX SBOM attestation; buildkit OCI provenance+SBOM | SR-4, SR-11, SI-7 | PS.2, PS.3 | Implemented (verify pending live tag) |
| A-3 | **release binaries** (admission-webhook + policy-manager × linux/darwin/windows × amd64/arm64, 5 combos) | `build-release` (matrix; `-trimpath`, `SOURCE_DATE_EPOCH`, `CGO_ENABLED=0`) | reproducible build; cosign **sign-blob** (`.sig`+`.pem`); **SLSA provenance** via `attest-build-provenance` | SR-4, SR-11, SI-7 | PS.2, PS.3 | Implemented (verify pending live tag) |
| A-4 | **Helm chart** `kube-policies-<ver>.tgz` | `package-helm` (`helm package`) | cosign **sign-blob** (`.sig`+`.pem`); chart checksum manifest | SR-4, SR-11 | PS.2 | Implemented (verify pending live tag) |
| A-5 | **SBOMs** `*-sbom.spdx.json` (per image, **by digest**) | `generate-sbom` → `anchore/sbom-action` (SPDX-JSON by digest) | **cosign attest --type spdxjson** binds the SBOM to the image digest in Rekor (the authoritative, cryptographically-bound SBOM); loose file is convenience only | SR-4, SR-3, CM-14 | PW.4, RV.1 | Implemented (verify pending live tag) |
| A-6 | **SLSA provenance attestations** (in-toto, per image digest + per binary) | `sign-attest-provenance` → `actions/attest-build-provenance` (`push-to-registry: true`) | Fulcio-signed in-toto provenance; Rekor entry; GitHub attestations API | SR-4 (SLSA L3 target) | PS.2, PS.3 | Implemented (verify pending live tag) |
| A-7 | **cosign signatures + Fulcio cert bundles** (`.sig` / `.pem`) | `sign-attest-provenance` → `cosign sign` (images) + `cosign sign-blob` (binaries/chart/checksums) | keyless signature + short-lived Fulcio cert recorded in Rekor; enables **offline** verify | SR-11, SR-4 | PS.2 | Implemented (verify pending live tag) |
| A-8 | **checksums** `checksums.txt` / `chart-checksums.txt` | `build-release` (`sha256sum`) + `package-helm` | SHA-256 manifest; **also cosign sign-blob'd** (`.sig`+`.pem`) so the manifest itself is signed | SR-11, SI-7 | PS.2 | Implemented (verify pending live tag) |
| A-9 | **GitHub Release** (assets bundle) | `create-release` → `softprops/action-gh-release` (**hard gate**: `needs: sign-attest-provenance`, `if: always() && !failure()`) | release notes pin images **by digest**; bundles binaries, chart, SBOMs, `.sig`/`.pem`; points to `verify-release.sh` | SR-11, PS.3 | PS.3 | Implemented (verify pending live tag) |

**Reading the map.** Two structural guarantees make this map assessable rather than aspirational:

1. **Everything is bound to a digest, not a tag.** Images are pushed *by digest*; SBOMs, scans,
   signatures, and provenance all reference `@sha256:…`. A moved tag cannot swap the artifact out
   from under its attestation.
2. **The scan gates the signature, and the signature gates the release.** `sign-attest-provenance`
   `needs: security-scan` and `create-release` `needs: sign-attest-provenance` with
   `if: always() && !failure() && !cancelled()` — so a vulnerable image is **never** signed, and a
   signing/attestation failure **fails the release** (no `if: always()` masks it on the signing
   job). This is the structural difference from the prior "signing theater" weakness
   (**POAM-015**, closing in P6).

**Residual (verify-pending).** Items A-1…A-9 are marked *verify pending live tag* because the
operating evidence (a Rekor inclusion proof, a registry-pushed `.att`/`.sig`, a `gh attestation
verify` success) only exists once the first `v*` tag runs the pipeline. The *controls* are
implemented and statically verified; the *assessment* of operating effectiveness is **POAM-015**
(P6) / **SR-GAP-01** in [supply-chain.md](supply-chain.md).

---

## 4. Third-party / build-tool trust list

Every external component the build trusts, with its **pinning reference**. **All GitHub Actions
are SHA-pinned** to a 40-character commit SHA with a human-readable version comment; **all base
images are digest-pinned** (`@sha256:`). [Dependabot](../../.github/dependabot.yml) (gomod,
npm `/web`, docker `/build/docker`, github-actions) keeps each pin **current** by rewriting the
SHA/digest in place — so pinning does not become pin-rot (**SR-5 / SR-3 / PO.3 / PW.4**).

### 4.1 GitHub Actions (SHA-pinned)

| Action | Pinning reference (commit SHA) | Role in pipeline | Control |
|---|---|---|---|
| `actions/checkout` | `34e114876b0b11c390a56381ad16ebd13914f8d5` (v4) | fetch source | SR-3, PS.1 |
| `actions/setup-go` | `40f1582b2485089dde7abd97c1529aa768e1baff` (v5) | install Go 1.25 toolchain | SR-3, PO.3 |
| `docker/setup-buildx-action` | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` (v3) | buildkit builder | SR-3 |
| `docker/login-action` | `c94ce9fb468520275223c153574b00df6fe4bcc9` (v3) | GHCR auth (GITHUB_TOKEN) | SR-3, AC-6 |
| `docker/build-push-action` | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8` (v6) | build+push by digest, provenance/sbom | SR-4, SI-7 |
| `docker/metadata-action` | `c299e40c65443455700f0fdfc63efafe5b349051` (v5) | OCI tags/labels | SR-3 |
| `anchore/sbom-action` | `e22c389904149dbc22b58101806040fa8d37a610` (v0.24.0) | SPDX SBOM by digest | SR-4, RV.1 |
| `aquasecurity/trivy-action` | `ed142fd0673e97e23eac54620cfb913e5ce36c25` (v0.36.0) | vuln scan + **CRITICAL/HIGH gate** | RA-5, SI-2 |
| `sigstore/cosign-installer` | `398d4b0eeef1380460a10c8013a76f728fb906ac` (v3) | keyless sign/attest | SR-11, SR-4 |
| `actions/attest-build-provenance` | `e8998f949152b193b063cb0ec769d69d929409be` (v2) | SLSA provenance (images+binaries) | SR-4 |
| `step-security/harden-runner` | `ab7a9404c0f3da075243ca237b5fac12c98deaa5` (v2) | egress audit on build jobs | SR-3, PO.5, SC-7 |
| `softprops/action-gh-release` | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` (v2) | publish signed release | SR-11, PS.3 |

> The same SHA-pinning discipline applies to **every** third-party action across both workflows
> (e.g. `actions/cache`, `actions/upload-artifact`, `actions/download-artifact`,
> `github/codeql-action/upload-sarif`, `golangci/golangci-lint-action`, `securego/gosec`,
> `azure/setup-helm`). No `@master`, `@main`, `@latest`, or bare `@vN` remain on third-party
> actions (verified in P1; see [../supply-chain/build-integrity.md](../supply-chain/build-integrity.md)).
> CLI tools downloaded inside `run:` steps (conftest, kubeconform, promtool, actionlint,
> govulncheck) are pinned by **version + verified SHA-256 checksum** in [`ci.yml`](../../.github/workflows/ci.yml).

### 4.2 Container base images (digest-pinned)

| Base image | Pinning reference (`@sha256:`) | Used by | Control |
|---|---|---|---|
| `golang:1.25-alpine` (builder) | `@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45` | both image Dockerfiles + dashboard go-builder | SR-3, SR-5, CM-2 |
| `gcr.io/distroless/static:nonroot` (runtime) | `@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240` | both runtime images (nonroot, no shell) | SR-3, SR-11, PW.4 |
| `node:22-alpine` (dashboard web-builder) | `@sha256:968df39aedcea65eeb078fb336ed7191baf48f972b4479711397108be0966920` | `build/Dockerfile.dashboard` | SR-3, SR-5 |
| `scratch` (dashboard final) | n/a (empty base; no packages to trust) | `build/Dockerfile.dashboard` final stage | SR-3, PW.4 |

Regenerate base-image digests with `scripts/pin-base-images.sh --write`; Dependabot's `docker`
ecosystem rewrites these `@sha256` pins on upstream rebuilds, preserving digest pinning
(**POAM-023** tracks defaulting *deployed* workload images to digests).

### 4.3 Build toolchain & language deps

| Component | Pinning / integrity | Control |
|---|---|---|
| Go toolchain | `go 1.25.0` (`go.mod`); `GOTOOLCHAIN=local` (no silent auto-upgrade) | SR-3, PO.3 |
| Go modules | `go.sum` + `GOFLAGS=-mod=readonly` + `go mod verify` (CI `lint`) + checksum DB | SR-3, PS.1, PW.4 |
| npm (dashboard) | `web/pnpm-lock.yaml`; Dependabot `npm` ecosystem at `/web` (reads `pnpm-lock.yaml`) | SR-3, PW.4 |
| Vulnerable-dep scan | `govulncheck@v1.3.0` (CI `govulncheck` job, build-failing) | RA-5, SI-2, RV.1 |

---

## 5. Hardware / identity root-of-trust statement

KP uses **no long-lived signing key and no HSM**. The root of trust for *every* signature,
attestation, and provenance record is **GitHub Actions workload identity (OIDC)**, anchored as
follows:

- **Identity anchor (Fulcio).** At signing time the workflow presents a short-lived **OIDC token**
  to **Sigstore Fulcio**, which issues an **ephemeral X.509 signing certificate** (valid ~10 min)
  **bound to the workflow identity**. No private key is ever stored, mounted, or rotated. The
  authorized signer identity is fixed and consumer-verifiable:
  - **certificate-identity-regexp:** `^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$`
  - **OIDC issuer:** `https://token.actions.githubusercontent.com`

  These exact values are what `scripts/verify-release.sh` passes to `cosign verify` /
  `cosign verify-attestation` (`--certificate-identity-regexp`, `--certificate-oidc-issuer`), so a
  signature only validates if it was produced by **this repo's `release.yml` running on a `v*`
  tag** — not a fork, not a branch, not a workflow_dispatch on an arbitrary ref.

- **Transparency anchor (Rekor).** Each signature, SBOM attestation, and SLSA provenance is
  recorded in the **Sigstore Rekor** public transparency log, giving a tamper-evident, publicly
  auditable inclusion proof bound to the artifact **digest**. Provenance is additionally retained
  in the **GitHub attestations API** (`gh attestation verify`).

- **Least-privilege workflow token.** Workflows declare top-level
  `permissions: { contents: read }`; jobs elevate **only** to what they need —
  `packages: write` (push), `security-events: write` (SARIF), `id-token: write` +
  `attestations: write` (only on `sign-attest-provenance`), `contents: write` (only on
  `create-release`). `GITHUB_TOKEN` is the GHCR credential; there is **no long-lived registry
  PAT** in the signing path. (**AC-6 / SR-3 / PS.2**.)

- **Build-environment integrity.** Builds run on **ephemeral GitHub-hosted runners** (no persistent
  state between runs). **`step-security/harden-runner`** runs on every build/sign job in
  **`egress-policy: audit`** mode, recording all network egress so deviation from the documented
  allowlist is detectable before flipping to `block` (egress *block* mode is the next SR-3 step —
  **POAM-033** / SR-GAP-02). Determinism is enforced by `SOURCE_DATE_EPOCH` + `-trimpath` +
  `CGO_ENABLED=0` and proven by the `reproducible-build` CI job.

> **Root-of-trust residual.** The Sigstore public-good Fulcio/Rekor instances and the GHCR control
> plane are **Inherited** trust anchors (modeled, not KP-controlled). The dominant *operating*
> residual is that **no live signed release has yet exercised this chain** (**POAM-015**); until
> the first `v*` tag, the root-of-trust is **implemented and statically verifiable** but **not yet
> operationally assessed**.

---

## 6. Supply-chain risk register and POA&M reconciliation

The full **tamper-point analysis** (dependency confusion, compromised action, malicious base
image, registry MITM, unsigned-artifact substitution, cache poisoning, secret exfiltration) with
mitigation and residual risk per boundary lives in the
**[build-pipeline threat model](build-threat-model.md)**. The residual SCRM risks tracked to
closure here:

| Risk | Current posture | Control | POA&M (phase) |
|---|---|---|---|
| No live signed release / SLSA L3 demonstrated | pipeline implemented; **verify pending first `v*` tag** | SR-4, SR-11 | **POAM-015** (P6) |
| harden-runner egress in `audit` (not `block`) | egress observed, not yet enforced | SR-3, SC-7 | **POAM-033** (P6) |
| Deployed workload images tag-pinned by default | digest-deploy option + baseline shipped; default still tag | CM-2, SR-5 | **POAM-023** (P5/P6) |
| No admission-time image-signature verification | no consumer-side enforce rule yet | CM-14, SI-7 | **POAM-035** (P6) |
| Vuln scanning gates release but no SLA program | Trivy/govulncheck gate live; no flaw-remediation SLAs | RA-5, SI-2 | **POAM-025/026** (P11) |
| Secure-SDLC quality-gate formalization | many CI gates exist; not yet a documented SA-15 program | SA-15 | **POAM-034** (P11) |
| Supply-chain governance close-out (SECURITY.md, SCRM) | this plan + threat model authored | SR-2, SR-3 | **POAM-033** (P6) |
| SR roles (release engineer, ISSO) unassigned | TBD-assign before assessment | SR-1, PO.2 | **POAM-018** (P0) |

Each row is an **Open** [POA&M](POAM.md) item with a scheduled remediation phase. As those phases
land — and as the first signed tag produces live attestation evidence — the `status` column in §3
and this register are revised so the SCRM plan, the [control matrix](control-matrix.csv), and the
[POA&M](POAM.md) stay reconciled.

---

## 7. References

- [Supply Chain Control Narrative](supply-chain.md) — SSP-style SR-1/SR-3/SR-4/SR-11 narrative.
- [Build-Pipeline Threat Model](build-threat-model.md) — trust boundaries + tamper-point analysis.
- [System Threat Model (STRIDE)](threat-model.md) — §6.5 supply-chain entry points.
- [SR Policy](policies/SR-policy.md) · [SR Procedures](procedures/SR-procedures.md).
- [Build & CI Integrity (P1)](../supply-chain/build-integrity.md).
- [`release.yml`](../../.github/workflows/release.yml) · [`ci.yml`](../../.github/workflows/ci.yml) · [`dependabot.yml`](../../.github/dependabot.yml).
- `scripts/verify-release.sh` · `scripts/verify-reproducible-build.sh` · `scripts/pin-base-images.sh`.
- [Control Matrix](control-matrix.csv) · [POA&M](POAM.md) · [poam.csv](poam.csv) · [Inventory](inventory.csv).
- NIST SP 800-53 Rev 5 (SR-1/SR-2/SR-3/SR-4/SR-5/SR-11, SA-12/SA-15, SI-2/SI-7, RA-5, CM-2/CM-14, AC-6, SC-7); NIST SP 800-161r1 (C-SCRM); NIST SP 800-218 (SSDF) PO.1/PO.2/PO.3/PO.5/PS.1/PS.2/PS.3/PW.4/RV.1; SLSA Build L3; FedRAMP Moderate baseline; FIPS-199; Sigstore (Fulcio/Rekor/cosign).
