---
title: "Build-Pipeline Threat Model — Kube-Policies (KP)"
control_family: "SR / SA — Supply Chain Risk Management & System Development"
controls: "SR-3, SR-4, SR-11, SA-12, SA-15; NIST SP 800-218 PO.5/PS.1/PS.2/PW.4/RV.1"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Build-Pipeline Threat Model — Kube-Policies (KP)

This is the **canonical build-pipeline threat model** for the Kube-Policies (KP) system (work unit
**SUP-WU-17**), the supply-chain counterpart to the **system** threat model
([threat-model.md](threat-model.md), which covers the running webhook/policy-manager/dashboard).
Where that document models the **deployed** system per trust-boundary crossing, this one models
the **build and release supply chain** — source → CI runner → registry → consumer — per
**trust boundary** and **tamper point**, using the same STRIDE-style **threat → mitigation →
control → POA&M** table format.

It is driven entirely by the **real pipeline**:
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) and
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml). It realizes the supply-chain slice
of the **Threat Modeling** activity referenced in [`CONTRIBUTING.md`](../../CONTRIBUTING.md), and
is referenced by the [SCRM plan](supply-chain-risk-management.md) (§6) and the supply-chain
control narrative ([supply-chain.md](supply-chain.md)).

> **Honesty note.** KP is a **pre-1.0 Proof-of-Concept being driven to assessment readiness**; it
> is **not authorized** (**NO ATO**). The mitigations below are **IMPLEMENTED in the pipeline and
> statically verified** on branch `feat/p0-compliance-foundation`. That branch has **not been
> pushed**; there is **no live CI run** and **no published signed release** yet — so the
> **operating** evidence for the keyless-signing/provenance mitigations (Rekor entries, registry
> attestations) is **PENDING the first signed `v*` tag**. "Implemented" (control exists, statically
> verified) is distinguished from "operating/assessed" throughout. Open weaknesses cross-reference
> the [POA&M](POAM.md). No CVEs, incidents, or assessors are invented.
>
> **Annual review.** Reviewed at least **annually** (next review **2027-06-01**) and whenever the
> pipeline, trust list, or root-of-trust anchors materially change (**SR-1**).

---

## 1. Scope, methodology, and conventions

**Scope.** The assessed surface is the **software supply chain that produces the KP release**:
first-party source in the repository, the GitHub Actions build/release jobs, the third-party
actions and base images they consume, the SBOM/scan/sign/attest gates, and the published artifacts
a consumer installs and verifies. The **deployed** runtime (webhook `:8443`, policy-manager
`:8080`, dashboard `:8090`) is **out of scope here** and modeled in
[threat-model.md](threat-model.md). The Sigstore public instances (Fulcio/Rekor), the GitHub
Actions runner OS, and the GHCR control plane are **Inherited** trust anchors — modeled as anchors
(§3), not as in-scope components for control implementation.

**Methodology.** STRIDE-style analysis applied **per trust boundary** (§4) and per **tamper point**
(§5), layered with the **SLSA Build L3** threat model (the SLSA "threats to the build" taxonomy:
source, build, dependency, distribution). Each row maps **threat → mitigation (implemented) →
control ID → POA&M (phase)**. Where a threat is **already mitigated**, the POA&M column is `—`;
where residual risk remains, it carries the open [POA&M](POAM.md) id and remediating phase, so the
threat model and POA&M stay reconciled.

**Pipeline facts (verbatim from the workflows).**

| Fact | Value |
|---|---|
| Build path | `validate-release` → `test-suite` (calls `ci.yml`) → `build-release`/`build-images`/`package-helm` → `generate-sbom` → `security-scan` → `sign-attest-provenance` → `create-release` |
| Image push | `docker/build-push-action` push **by digest**, `provenance: mode=max`, `sbom: true` |
| SBOM | `anchore/sbom-action`, SPDX-JSON, **by digest** (`generate-sbom`) |
| Vuln gate | Trivy `CRITICAL,HIGH`, `ignore-unfixed`, `.trivyignore`; `security-scan` **gates** `sign-attest-provenance` via `needs:` |
| Signing | `cosign sign`/`attest` (images, by digest) + `cosign sign-blob` (binaries/chart/checksums) + `actions/attest-build-provenance`; keyless OIDC; **no static key** |
| Release gate | `create-release` `needs: sign-attest-provenance`, `if: always() && !failure() && !cancelled()` |
| Identity | `^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$`; issuer `https://token.actions.githubusercontent.com` |
| Runner | ephemeral GitHub-hosted; `step-security/harden-runner` egress `audit` on build/sign jobs |
| Token | top-level `permissions: { contents: read }`; least-priv job elevation; `id-token: write` only on signing job |

---

## 2. Adversaries and assets

**Threat actors** (supply-chain extension of TA-5 in [threat-model.md](threat-model.md)):

- **BTA-1 Dependency adversary** — controls or squats a Go module, npm package, base image, or
  GitHub Action the build pulls (typosquat, dependency confusion, hijacked maintainer).
- **BTA-2 Pipeline/config adversary** — can influence workflow YAML, a referenced action's
  upstream code, or build inputs (e.g. via a malicious PR or a moved action tag).
- **BTA-3 Network/path adversary** — interposes between the runner and a registry/dependency
  source (registry MITM, DNS/cache poisoning).
- **BTA-4 Insider / credential thief** — attempts to exfiltrate the `GITHUB_TOKEN`, OIDC token, or
  registry credentials from the runner.
- **BTA-5 Distribution adversary** — substitutes an unsigned or attacker-built artifact for the
  genuine one between build and consumer.

**Primary assets.** The **release artifacts** (images, binaries, chart, SBOMs, provenance,
signatures, checksums — enumerated in [SCRM §3](supply-chain-risk-management.md)); the **build
integrity** itself (that a published artifact is a faithful function of reviewed source); the
**OIDC signing identity** and **`GITHUB_TOKEN`**; and **consumer trust** that a verified KP release
is authentic.

---

## 3. Trust boundaries and OIDC trust anchors

The supply chain crosses four trust boundaries. Trust is **anchored**, not assumed, at the signing
step by GitHub Actions OIDC → Fulcio → Rekor.

**Trust boundaries (source → CI runner → registry → consumer).**

| TB | Boundary crossing | What crosses | Current protection |
|---|---|---|---|
| `TB-1` | **Developer / source → CI runner** | git source @ tag, workflow YAML | tag-triggered (`v*`), version-format validated; `GOFLAGS=-mod=readonly`, `go mod verify`; branch protection (target, **POAM-018**/PS.1) |
| `TB-2` | **CI runner → external deps** (actions, base images, modules) | third-party action code, base layers, Go/npm modules | **SHA-pinned actions**, **digest-pinned bases**, `go.sum`/checksum DB; harden-runner egress audit; Dependabot freshness |
| `TB-3` | **CI runner → registry (GHCR)** | image layers, attestations, signatures | TLS to GHCR; `GITHUB_TOKEN` least-priv; push **by digest**; cosign sign/attest by digest |
| `TB-4` | **Registry / release → consumer** | image, binary, chart, SBOM, provenance, `.sig`/`.pem` | keyless signatures + SLSA provenance + checksums; `scripts/verify-release.sh` verifies against the documented OIDC identity |

**OIDC trust anchors (the root of trust).**

- **Fulcio (identity).** The signing job presents a short-lived **OIDC token** to **Sigstore
  Fulcio**, which issues an **ephemeral signing certificate (~10 min)** bound to the workflow
  identity. **No long-lived private key exists.** The authorized identity is
  `^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$`,
  issuer `https://token.actions.githubusercontent.com` — so a signature is only trusted if it came
  from **this repo's `release.yml` on a `v*` tag**.
- **Rekor (transparency).** Every signature/attestation/provenance is logged in **Sigstore Rekor**,
  giving a tamper-evident inclusion proof bound to the artifact **digest**.
- **Least-privilege `GITHUB_TOKEN` + `id-token: write`.** OIDC `id-token: write` and
  `attestations: write` are granted **only** to `sign-attest-provenance`; everything else runs
  `contents: read`. The runner is **ephemeral** and **harden-runner**-audited.

These anchors are detailed in the [SCRM plan §5](supply-chain-risk-management.md). The Sigstore
public-good and GHCR control planes are **Inherited** (not KP-controlled) trust anchors.

---

## 4. STRIDE per trust boundary

### 4.1 TB-1 — developer / source → CI runner

| # | STRIDE | Threat | Mitigation (implemented) | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| BLD-01 | **T** Tampering | A malicious change to source or workflow YAML is built and released. | `validate-release` enforces `v*` tag + semver format; `test-suite` reuses `ci.yml` (lint, vet, govulncheck, gosec, reproducible-build, conftest gates) as a **`needs:` precondition** to build; `GOFLAGS=-mod=readonly` + `go mod verify` block silent `go.mod` edits. **Residual:** branch-protection / required-reviews not yet enforced. | SA-15, CM-5, PS.1 | **POAM-034** (P11); **POAM-018** (P0, roles) |
| BLD-02 | **S** Spoofing | An attacker triggers a release from a fork or arbitrary ref. | Signing identity is pinned to **this repo's `release.yml` on `refs/tags/v.*`** (Fulcio cert-identity regexp); a fork/branch build cannot produce a signature that verifies. | SR-11, IA-2 | — (mitigated by identity binding); live proof **POAM-015** (P6) |
| BLD-03 | **R** Repudiation | Build inputs (commit, builder) for a release cannot be proven later. | SLSA provenance (`attest-build-provenance`) records builder + source digest; recorded in Rekor + GitHub attestations API. | SR-4, AU-12 | **POAM-015** (P6, live attest) |

### 4.2 TB-2 — CI runner → external dependencies

| # | STRIDE | Threat | Mitigation (implemented) | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| BLD-04 | **T** Tampering | A third-party **GitHub Action** is swapped under a moved tag (`@v4` → attacker commit). | **All third-party actions SHA-pinned** to 40-char commit SHA; Dependabot `github-actions` rewrites the SHA on legitimate updates. (See [trust list §4.1](supply-chain-risk-management.md).) | SR-3, CM-2 | — (mitigated; freshness via Dependabot) |
| BLD-05 | **T** Tampering | A **base image** tag is re-pushed with a backdoored layer. | **All base images digest-pinned** (`golang:1.25-alpine@sha256:…`, `distroless/static:nonroot@sha256:…`, `node:22-alpine@sha256:…`); distroless runtime has **no shell/package manager**; Dependabot `docker` updates digests. | SR-3, SR-5, PW.4 | — (mitigated); deployed-image default **POAM-023** (P6) |
| BLD-06 | **T/I** Dependency confusion / hijack | A typosquatted or hijacked Go/npm module is pulled. | `go.sum` + Go checksum DB + `GOFLAGS=-mod=readonly` pin module content; `govulncheck@v1.3.0` + Trivy `fs` + gosec scan deps; Dependabot SCA across gomod/npm. **Residual:** no formal flaw-remediation SLA program. | RA-5, SI-2, SR-3 | **POAM-025/026** (P11) |
| BLD-07 | **I** Egress exfiltration via a dependency | A compromised action/build step beacons out or exfiltrates. | **harden-runner** runs `egress-policy: audit` on every build/sign job, recording all egress for detection. **Residual:** `audit`, not `block` — egress is observed, not yet enforced. | SR-3, SC-7, PO.5 | **POAM-033** (P6, egress block) |

### 4.3 TB-3 — CI runner → registry (GHCR)

| # | STRIDE | Threat | Mitigation (implemented) | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| BLD-08 | **T** Tampering (MITM) | A path adversary alters image layers in transit to GHCR or swaps the pushed digest. | Push is **TLS** to GHCR and **by content-addressed digest**; the digest is captured as a job output and every downstream step (scan, sign, attest, SBOM) references `@sha256:` — a swapped layer changes the digest and breaks the chain. | SR-3, SC-8, SI-7 | — (mitigated by digest binding) |
| BLD-09 | **I/E** Credential theft | `GITHUB_TOKEN` or the OIDC token is exfiltrated from the runner to push or sign as KP. | Top-level `permissions: { contents: read }`; `packages: write` only on push jobs; `id-token: write`+`attestations: write` **only** on `sign-attest-provenance`; ephemeral runner; harden-runner audit; **no long-lived registry PAT** in the signing path. | AC-6, SR-3, PS.2 | — (mitigated; least-priv token) |
| BLD-10 | **T** Cache poisoning | The buildkit GHA cache (`cache-from/to: type=gha`) is poisoned to inject a malicious layer. | Final artifact integrity does **not** rest on the cache: the pushed artifact is captured **by digest** and then **scanned, signed, attested, and SBOM'd by that digest**; a poisoned layer that changed output would change the digest and either fail the Trivy gate or be visibly bound into a verifiable attestation. **Residual:** cache is a convenience input, not an attested one. | SR-3, SI-7 | — (residual contained by digest+scan gate) |

### 4.4 TB-4 — registry / release → consumer

| # | STRIDE | Threat | Mitigation (implemented) | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| BLD-11 | **S/T** Unsigned-artifact substitution | An attacker serves a forged image/binary/chart in place of the genuine release. | Every artifact is **keyless-signed** + carries **SLSA provenance**; SBOMs are **cosign-attested to the digest**; checksums are themselves **sign-blob'd**; `scripts/verify-release.sh` rejects anything not signed by the documented OIDC identity. | SR-11, SR-4, SI-7 | **POAM-015** (P6, live verify) |
| BLD-12 | **R** Repudiation | A consumer cannot independently prove a release's origin offline. | `.sig` + `.pem` (Fulcio cert) bundles enable **offline** verification; Rekor inclusion proofs + GitHub attestations API provide a public audit trail. | SR-4, SR-11 | **POAM-015** (P6) |
| BLD-13 | **T** Vulnerable-artifact release | A release ships an image with a fixable CRITICAL/HIGH CVE. | **Trivy gate** (`CRITICAL,HIGH`, `ignore-unfixed`, `.trivyignore`) runs in `security-scan`, which **`needs:`-gates `sign-attest-provenance`** — a vulnerable image is **never** signed or published. `create-release` then `needs: sign-attest-provenance`. | RA-5, SI-2 | **POAM-025** (P11, SLA program) |
| BLD-14 | **E** Consumer runs unverified image | The cluster admits an unsigned/unverified KP (or any) image. | Consumer verify is documented (`verify-release.sh`). **Residual:** no **admission-time** signature/provenance verification rule ships yet. | CM-14, SI-7, SI-7(1) | **POAM-035** (P6) |

---

## 5. Tamper-point analysis (required deep dive)

The named tamper points across the chain, each with the **implemented** mitigation and the
**residual risk**. This is the supply-chain analogue of the system threat model's focused analyses.

| Tamper point | Where | Mitigation (implemented) | Residual risk | Control | POA&M |
|---|---|---|---|---|---|
| **Dependency confusion / typosquat** | TB-2 (modules) | `go.sum` + checksum DB + `-mod=readonly`; govulncheck/Trivy/gosec; Dependabot SCA | No SLA-bound flaw-remediation program yet | RA-5, SI-2 | POAM-025/026 |
| **Compromised GitHub Action** | TB-2 (actions) | **SHA-pin every third-party action**; Dependabot rewrites SHAs | Pinned SHA could itself be malicious if the action's upstream is compromised at pin time (mitigated by review on Dependabot PRs) | SR-3, CM-2 | — |
| **Malicious base image** | TB-2 (bases) | **Digest-pin all bases**; distroless runtime (no shell/pkg mgr); Dependabot docker | Inherited trust in upstream image publisher at digest-capture time | SR-3, SR-5, PW.4 | — |
| **Registry MITM** | TB-3 | TLS to GHCR; push **by digest**; all downstream steps reference `@sha256:` | Inherited trust in GHCR control plane | SR-3, SC-8 | — |
| **Unsigned-artifact substitution** | TB-4 | keyless cosign sign/attest + SLSA provenance + signed checksums, all **by digest** | **No live release has exercised the chain yet** | SR-11, SR-4 | **POAM-015** (P6) |
| **Cache poisoning** | TB-3 (gha cache) | output captured + scanned + signed + attested **by digest**; cache not in the attested path | Cache is an unattested convenience input | SR-3, SI-7 | — |
| **Secret exfiltration** | TB-2/TB-3 (runner) | least-priv `GITHUB_TOKEN`; `id-token: write` scoped to signing job; ephemeral runner; **harden-runner egress audit** | harden-runner in `audit`, **not `block`** — egress observed, not enforced | SR-3, SC-7, AC-6 | **POAM-033** (P6) |
| **Toolchain skew (untrustworthy CI)** | TB-1 | CI + release both build/test on **Go 1.25** matching `go.mod`; `GOTOOLCHAIN=local` | — (closed in P1; see build-integrity.md) | SA-11, CM-5 | POAM-014 (P1, remediated) |
| **Non-reproducible build** | TB-1 | `SOURCE_DATE_EPOCH` + `-trimpath` + `CGO_ENABLED=0`; `reproducible-build` CI job proves byte-identical rebuilds | — (mitigated) | SI-7 | — |

**Reading the analysis.** The chain's strength is that **every protection is anchored to an
immutable digest and the scan gates the signature gates the release**: a tamper at TB-2/TB-3 that
changes output changes the digest, which either trips the Trivy gate or is bound into a verifiable
attestation a consumer can reject. The dominant **operating** residuals are (1) **no live signed
release has yet exercised the keyless-signing chain** (POAM-015), (2) **harden-runner egress is in
`audit`, not `block`** (POAM-033), and (3) **no admission-time signature verification** on the
consumer side (POAM-035). None of these is an *implementation* gap in the pipeline as written;
each is an **operating/assessment** gap pending the first signed tag or a later phase.

---

## 6. Residual-risk summary and POA&M reconciliation

The dominant residual supply-chain risks are: **(1)** the keyless signing/provenance chain is
**implemented but not yet operationally assessed** — no `v*` tag has run, so Rekor/registry
attestation evidence does not exist yet (**POAM-015**, P6); **(2)** harden-runner is in **`audit`**
not **`block`** mode (**POAM-033**, P6); **(3)** no **admission-time image-signature verification**
on the consumer side (**POAM-035**, P6); **(4)** deployed workload images **tag-pinned by default**
(**POAM-023**, P6); and **(5)** vulnerability scanning **gates** the release but is **not yet a
SLA-bound flaw-remediation program** (**POAM-025/026**, P11). Each is an **Open** [POA&M](POAM.md)
item with a scheduled phase.

The genuine bright spots that reduce risk **today** — **SHA-pinned actions**, **digest-pinned
bases**, **push/scan/sign/attest all by immutable digest**, **scan-gates-signing-gates-release**,
**keyless signing with no long-lived key**, **least-privilege `GITHUB_TOKEN`**, **reproducible
builds**, and **Dependabot freshness** — are noted inline; together they make the chain assessable,
but they do not substitute for the live attestation evidence (POAM-015) an assessor will require.

Every threat in §§4–5 maps to a control and, where open, to a [POA&M](POAM.md) id and phase. As
those phases land — and as the first signed tag produces live evidence — this model, the
[SCRM plan](supply-chain-risk-management.md), the [control matrix](control-matrix.csv), and the
[POA&M](POAM.md) are revised to stay reconciled.

---

## 7. References

- [Supply-Chain Risk Management (SCRM) Plan](supply-chain-risk-management.md) — artifact→control map, trust list, root-of-trust.
- [Supply Chain Control Narrative](supply-chain.md) — SSP-style SR narrative.
- [System Threat Model (STRIDE)](threat-model.md) — deployed-system model; §6.5 supply-chain entry points.
- [Build & CI Integrity (P1)](../supply-chain/build-integrity.md) · [SR Policy](policies/SR-policy.md) · [SR Procedures](procedures/SR-procedures.md).
- [`release.yml`](../../.github/workflows/release.yml) · [`ci.yml`](../../.github/workflows/ci.yml) · [`dependabot.yml`](../../.github/dependabot.yml) · `scripts/verify-release.sh` · `scripts/verify-reproducible-build.sh`.
- [Control Matrix](control-matrix.csv) · [POA&M](POAM.md) · [poam.csv](poam.csv).
- NIST SP 800-53 Rev 5 (SR-3/SR-4/SR-11, SA-11/SA-12/SA-15, SI-2/SI-7, RA-5, CM-2/CM-5/CM-14, AC-6, SC-7/SC-8, IA-2, AU-12); NIST SP 800-161r1 (C-SCRM); NIST SP 800-218 (SSDF) PO.5/PS.1/PS.2/PW.4/RV.1; SLSA Build L3 threat model; STRIDE (Microsoft SDL); FedRAMP Moderate baseline.
