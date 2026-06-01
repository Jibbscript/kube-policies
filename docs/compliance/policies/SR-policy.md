---
title: "Supply Chain Risk Management Policy (SR) — Kube-Policies (KP)"
control_family: "SR — Supply Chain Risk Management"
controls: "SR-1, SR-3, SR-4, SR-11"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Supply Chain Risk Management Policy — Kube-Policies (KP)

This policy establishes the Supply Chain Risk Management requirements for the Kube-Policies system
(KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It implements control **SR-1 (Policy and Procedures)** and anchors the SR controls that
govern the integrity of KP's software supply chain: **SR-3 (Supply Chain Controls and Plans)**,
**SR-4 (Provenance)**, and **SR-11 (Component Authenticity)**. It is the SR-family anchor; the
operational steps live in the companion [SR procedures](../procedures/SR-procedures.md), and the
technical attestation evidence is described in the
[supply-chain control narrative](../supply-chain.md). The implemented pipeline is in
[`.github/workflows/release.yml`](../../../.github/workflows/release.yml).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is **not
yet authorized** (**no ATO**) and not in production use. This policy documents the supply-chain
*discipline* the program operates under and the controls that are *actually implemented* in the
pipeline — it is not a claim that every SR control is fully operational. Per-control status is
tracked in the [control matrix](../control-matrix.csv) and open weaknesses in the
[POA&M](../POAM.md), with remediation phases (P0–P12) defined in
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually** (next review
**2027-06-01**) and whenever a significant change to the system, its build pipeline, its
third-party component set, the signing/attestation toolchain, or the applicable standards occurs.
Reviews are recorded by updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that every artifact built, published, or deployed as part
of KP can be traced to a known, unmodified source; that third-party components are governed and
periodically reviewed; that SBOMs are generated and retained; and that images and binaries carry
verifiable provenance attestations. It applies to:

- All KP build artifacts: container images
  (`ghcr.io/jibbscript/kube-policies/admission-webhook`,
  `ghcr.io/jibbscript/kube-policies/policy-manager`), Go binaries (admission-webhook,
  policy-manager for linux/darwin/windows × amd64/arm64), and the Helm chart
  (`charts/kube-policies`).
- All direct and transitive Go module dependencies declared in `go.mod` / `go.sum`.
- Front-end dependencies in `web/` declared in `package.json` / `pnpm-lock.yaml`.
- Third-party GitHub Actions used in `.github/workflows/`.
- Container base images referenced in `build/docker/*.Dockerfile` and
  `build/Dockerfile.dashboard`.
- All personnel filling the System Owner, ISSO, Maintainer/CODEOWNERS, and release-engineer roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)).

## 2 SR-1 — Supply Chain Risk Management Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this SR policy and the procedures needed to
implement it; shall designate an official to manage them; and shall review and update both on a
defined frequency. This document is that policy; the procedures are in
[../procedures/SR-procedures.md](../procedures/SR-procedures.md) and the technical narrative in
[../supply-chain.md](../supply-chain.md).

### 2.2 SR-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System Owner,
ISSO, AO, Maintainers, and all repository contributors by being maintained in version control under
[`docs/compliance/policies/`](.) and referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), SR
family) and the [CRM](../CRM.md).

### 2.3 SR-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update this
policy and its procedures, with the **System Owner (TBD — assign before assessment)** accountable
for adequacy and resourcing.

### 2.4 SR-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This SR policy (SR-1) | ISSO | At least annually | Pipeline change; new dependency class; tooling change; assessor finding |
| SR procedures ([SR-procedures.md](../procedures/SR-procedures.md)) | ISSO | At least annually | Procedure drift; new component; signing-toolchain change |
| Supply-chain narrative ([supply-chain.md](../supply-chain.md)) | ISSO | Per release + annually | SLSA level change; new attestation type; GAP closure |
| SBOM artifacts | Release engineer | Per release | Any image or binary change |

"Significant change" includes any change to the signing toolchain, the SBOM generator, the
vulnerability-scan gate, the set of trusted third-party actions, the Go toolchain version, or the
base image digests.

## 3 SR-3 — Supply Chain Controls and Plans

### 3.1 Dependency governance

KP shall pin and verify all dependency classes:

**Go modules.** `go.mod` pins each direct dependency to an explicit version; `go.sum` records the
cryptographic hash of every module zip and `go.mod` file. CI enforces `GOFLAGS: -mod=readonly` so
no implicit `go.mod` edits occur during builds, and the `lint` job runs `go mod verify` plus `go
mod tidy && git diff --exit-code` to detect sum-file drift.

**Frontend (web/).** `package.json` pins dependencies and `pnpm-lock.yaml` is the authoritative
lockfile. The lockfile must be committed and kept in sync; any divergence between `package.json`
and the lockfile is a change-control finding.

**Dependabot.** Automated dependency-update PRs are configured in
[`.github/dependabot.yml`](.github/dependabot.yml) covering the `gomod`, `npm`, `docker`, and
`github-actions` ecosystems. Dependabot PRs follow the same PR + gating-CI review as any other
change (see [CM procedures](../procedures/CM-procedures.md) §2).

**GitHub Actions.** Every third-party `uses:` reference in all workflows is pinned to a 40-character
commit SHA with a trailing human-readable version comment. No `@main`, `@master`, `@latest`, or
bare `@vN` forms are permitted on third-party actions. The trusted action set (all SHA-pinned) is:
`actions/checkout`, `actions/setup-go`, `docker/setup-buildx-action`, `docker/login-action`,
`docker/build-push-action`, `docker/metadata-action`, `anchore/sbom-action`,
`aquasecurity/trivy-action`, `sigstore/cosign-installer`, `actions/attest-build-provenance`,
`step-security/harden-runner`, `softprops/action-gh-release`.

**Container base images.** All non-`scratch` `FROM` lines in `build/docker/*.Dockerfile` and
`build/Dockerfile.dashboard` are pinned by `@sha256:` digest (multi-arch image index) while
retaining the human-readable tag. Digests are refreshed via `scripts/pin-base-images.sh --write`.

### 3.2 Vulnerability gate

The release pipeline (`security-scan` job) scans the exact built image digests with Trivy at
severity `CRITICAL,HIGH`; fixable findings fail the release. Suppressions require a dated, time-boxed
entry in `.trivyignore` with a justification comment (see [SR procedures](../procedures/SR-procedures.md)
§5). The `sign-attest-provenance` job has `needs: security-scan`, so a vulnerable image is never
signed or attested.

### 3.3 Build isolation (harden-runner)

Build and signing jobs in `release.yml` run `step-security/harden-runner` with
`egress-policy: audit` to monitor outbound network access. Full `block` mode for non-allowlisted
egress is a documented gap (see [supply-chain.md](../supply-chain.md) §4).

## 4 SR-4 — Provenance

KP shall generate and retain cryptographically bound provenance attestations for every released
artifact:

**Container image provenance.** The `sign-attest-provenance` job generates a signed in-toto SLSA
provenance attestation for each image digest via `actions/attest-build-provenance` (Fulcio
certificate + Rekor transparency-log entry). Attestations are pushed to the GHCR registry alongside
the image.

**Binary provenance.** `actions/attest-build-provenance` also covers the release binaries
(`artifacts/binaries-*`); these are verifiable with `gh attestation verify <binary>`.

**SBOM attestation.** The `generate-sbom` job produces SPDX-JSON SBOMs for each image by immutable
digest using `anchore/sbom-action`. The `sign-attest-provenance` job then attests each SBOM to its
image digest via `cosign attest --type spdxjson`, cryptographically binding the SBOM to the exact
artifact and recording it in Rekor. The loose SPDX-JSON files are also attached as GitHub release
assets for consumer convenience.

**SBOM generation policy.** An SBOM shall be generated for every container image and every release.
SBOMs shall be in SPDX-JSON format, generated against immutable digests (not mutable tags), and
retained as both GitHub release assets and as cosign attestations in the registry.

**Reproducible builds.** Go binaries use `SOURCE_DATE_EPOCH` (derived from the commit timestamp,
not wall-clock time), `-trimpath`, `CGO_ENABLED=0`, and a toolchain pinned to `go.mod`
(`GOTOOLCHAIN=local`) to minimize build nondeterminism. Reproducibility is verified by
`scripts/verify-reproducible-build.sh`.

**Target SLSA level.** The pipeline is designed to reach **SLSA Build L3** (isolated, ephemeral
build environment; signed provenance; no persistent build credentials). The current gap and the
honest assessment of level-readiness are documented in [supply-chain.md](../supply-chain.md) §3.

## 5 SR-11 — Component Authenticity

KP shall sign and verify the authenticity of its released artifacts:

**Image signing.** The `sign-attest-provenance` job signs each container image by its immutable
digest using keyless cosign (workflow OIDC token; no static private key; no
`COSIGN_EXPERIMENTAL`). The signing identity is the workflow OIDC subject:

```
^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$
```

issuer `https://token.actions.githubusercontent.com`. Signatures and certificates are recorded in
the Sigstore Rekor transparency log.

**Blob signing.** The Helm chart, binaries, and checksum manifests are signed with
`cosign sign-blob` (keyless OIDC), emitting a `.sig` signature and a `.pem` Fulcio certificate
bundle per artifact. These are attached as GitHub release assets.

**Consumer verification.** Consumers shall verify artifact authenticity before deployment using
`scripts/verify-release.sh <version>` or the procedures in
[docs/supply-chain/verification.md](../../supply-chain/verification.md).

**Admission-time verification (opt-in).** The bundled image-provenance policy
(`internal/policy/engine.go`) and the chart `ClusterImagePolicy` (Sigstore policy-controller) via
`imageVerification.enabled` (default `false`) can enforce signature verification at admission time.
This is an operator opt-in; it is not enforced by default.

**Third-party component acceptance.** A third-party component (action, base image, Go module, npm
package) is accepted only when it: (a) has a maintained upstream; (b) is pinned to an immutable
reference (SHA or digest); and (c) is reviewed by a Maintainer on the introducing PR. Components
that are end-of-life or that have unmitigated CRITICAL findings shall be replaced or exception-tracked
in the [POA&M](../POAM.md).

## 6 Roles and responsibilities (summary)

| Role | Holder | SR responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for supply-chain program adequacy/resourcing; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures; reviews pipeline attestation evidence; maintains the POA&M for SR findings. |
| Maintainers / CODEOWNERS | TBD — assign | Review/approve PRs adding or updating dependencies; enforce SHA-pinned actions; review .trivyignore suppressions. |
| Release engineer | TBD — assign | Executes release pipeline; validates signing/attestation completeness before `create-release` job; retains SBOM artifacts. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP; renders the authorization decision; approves out-of-delegation deviations. |

## 7 Compliance, exceptions, and enforcement

- Dependencies not pinned to an immutable reference (SHA/digest/exact version) are a finding
  requiring immediate remediation or a time-boxed POA&M entry.
- `.trivyignore` suppressions must include a dated justification and an expiry date; suppressions
  without a justification are invalid and will be removed on the next review pass.
- A release that fails the `security-scan` gate must not be published. The `sign-attest-provenance`
  job's `needs: security-scan` dependency enforces this in the pipeline; manual overrides require
  ISSO and System Owner approval and a corresponding POA&M entry.

## 8 References

- SR procedures: [../procedures/SR-procedures.md](../procedures/SR-procedures.md)
- Supply-chain control narrative: [../supply-chain.md](../supply-chain.md)
- Build integrity (P1): [../../supply-chain/build-integrity.md](../../supply-chain/build-integrity.md)
- Release pipeline: [`.github/workflows/release.yml`](../../../.github/workflows/release.yml)
- Dependabot config: [`.github/dependabot.yml`](../../../.github/dependabot.yml)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- CM policy (dependency governance anchor): [CM-policy.md](CM-policy.md)
- NIST SP 800-53 Rev 5 (SR-1, SR-3, SR-4, SR-11); NIST SP 800-161r1 (C-SCRM); NIST SP 800-218 (SSDF); FedRAMP Moderate baseline; SLSA Build L3 specification; FIPS-199.
