---
title: "Secure Software Development Lifecycle (SDL) — Kube-Policies (KP)"
control_family: "SA — System and Services Acquisition"
controls: "SA-3, SA-11, SA-11(1), SA-11(8), SA-15, SI-10, RA-5, SI-2"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# Secure Software Development Lifecycle (SDL) — Kube-Policies (KP)

This document describes the secure software development lifecycle (SDL) discipline
that the Kube-Policies program operates under, satisfying **SA-3** (System Development
Life Cycle), **SA-15** (Development Process, Standards, and Tools), and the **NIST SP
800-218 Secure Software Development Framework (SSDF)**. It records the concrete
practices, tooling gates, and CI workflow jobs that implement each phase, and maps
them to NIST SP 800-53 Rev 5 and SSDF control identifiers.

Kube-Policies is a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. Named roles are not yet
staffed; contacts such as `security@kube-policies.io` are **placeholders** pending
role assignment. Per-control status is tracked in the
[control matrix](../compliance/control-matrix.csv) and open weaknesses in the
[POA&M](../compliance/POAM.md), with remediation phases (P0–P12) defined in
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This document is reviewed and updated at least **annually**. The
last review was **2026-06-02**; the **next review is 2027-06-02**. It is also
reviewed after a material change to the CI pipeline, a new vulnerability class is
introduced into scope, or an assessor finding requires a process update. Reviews are
recorded by updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 SDL overview

The KP SDL is organized into six sequential phases. Each phase has concrete
gates that must pass before the next phase proceeds.

```
Planning / Threat Modeling
        ↓
Secure Coding Standards + Peer Review
        ↓
Automated Testing (unit → integration → fuzz → DAST → mutation)
        ↓
Security Scanning (SAST / SCA / secrets / IaC)
        ↓
Release / Sign / Attest
        ↓
Vulnerability Management
```

---

## 2 Phase 1 — Planning and Threat Modeling (SA-3, SA-15)

### 2.1 System development life cycle (SA-3)

KP follows a defined SDLC in which security roles and responsibilities are
integrated from initial design through release. The ISSO role (TBD — assign before
assessment) reviews security-relevant changes at the review gate (§3) and signs off
on significant architecture changes before implementation begins.

### 2.2 Threat modeling (SA-15, SSDF PO.3)

A structured threat model is maintained at
[docs/security/threat-model.md](threat-model.md). The threat model identifies:

- Trust boundaries (admission-webhook, policy-manager, OPA/Rego engine, CRDs,
  dashboard BFF, kube-policies-system namespace).
- Attack surfaces and threat actors relevant to a Kubernetes admission-control gate.
- Mitigating controls and residual risks tracked in the [POA&M](../compliance/POAM.md).

The threat model is reviewed at least annually and whenever a new component or
attack surface is added to the authorization boundary.

---

## 3 Phase 2 — Secure Coding Standards and Review Gates (SA-11, SA-15)

### 3.1 Secure coding standards (SA-15, SSDF PW.5)

All Go source code is governed by **`.golangci.yml`**, which enables 15 linters
focused on bug-catching rather than stylistic opinion. The configuration uses
`default: none` and explicitly enables only real-bug detectors:

| Category | Enabled linters |
|---|---|
| Error handling | `errcheck`, `errorlint`, `nilerr`, `nilnil` |
| Security | `gosec` (MEDIUM+ / MEDIUM+ confidence gate, see §4.1) |
| Type safety | `forcetypeassert`, `makezero` |
| Resource leaks | `bodyclose`, `noctx` |
| Correctness | `govet`, `staticcheck`, `ineffassign`, `unused`, `durationcheck` |
| Readability | `misspell` |
| Formatters | `gofmt`, `gofumpt`, `goimports` |

Pure style/complexity linters are intentionally excluded. `go vet` and `go fmt`
run independently in CI alongside the lint step.

### 3.2 Pull-request review gate (SA-11, CM-3)

Every change enters the codebase through a pull request. The
**`.github/pull_request_template.md`** provides a CM-3 configuration change-control
checklist that reviewers must complete; a PR with unchecked, unexplained boxes
must not be merged. Required checklist items include: baseline updated, inventory
updated, policy gates green (manifest-hardening-gate, rbac-sa-gate,
network-posture-gate, helm-unittest), image digest pinned, security impact assessed.

**`.github/CODEOWNERS`** routes all paths to `@Jibbscript` (the single maintainer
PoC); security-critical paths (`/docs/compliance/**`, `/docs/security/**`,
`/.github/workflows/**`, `/internal/**`, `/charts/**`) are called out explicitly.
CODEOWNERS entries must be updated before any multi-contributor launch.

Branch protection and required-status-check policy are applied at the repository
level (GitHub branch-protection rules requiring the `ci-gate` aggregator job to
pass before merge). These are operational controls in GitHub, not documented in a
separate file.

---

## 4 Phase 3 — CI Security Gates (SA-11, SA-11(1), SA-11(8), SI-10)

All gates below are enforced in `.github/workflows/ci.yml` unless a different
workflow file is noted.

### CI gate architecture — aggregated vs. independent required checks

The **`ci-gate`** job in `ci.yml` is the single **aggregating** required status check.
Its `needs:` list is the authoritative set of jobs it aggregates: `lint`, `unit-tests`,
`fips-verify`, `build-images`, `integration-tests`, `e2e-kind`, `e2e-k3s`,
`security-scan`, `helm-tests`, `docs-tests`, `rbac-sa-gate`, `network-posture-gate`,
`manifest-hardening-gate`, `helm-unittest`, `monitoring-rules`, `actionlint`,
`govulncheck`, `reproducible-build`, `fuzz-smoke`.

The following workflows are **independent required checks** — they run in separate
workflow files and are NOT part of `ci-gate`'s `needs:`. They must be enumerated
separately as required status checks in branch protection (see
`docs/security/branch-protection.md` and `.github/settings.yml`):

| Workflow | Check name | Notes |
|---|---|---|
| `.github/workflows/codeql.yml` | `Analyze (go)`, `Analyze (javascript-typescript)` | CodeQL `security-extended`; uploads SARIF/informational. Does NOT fail the build on findings by default unless GitHub code-scanning is separately set to block. |
| `.github/workflows/secrets-scan.yml` | `Gitleaks — secret scan (full history)` | Fails its own job on any detected credential (gitleaks exits non-zero). |
| `.github/workflows/ui.yml` | `Lint, Test, and Build UI` | UI lint/Vitest/Rego bundle/build; gates production deps via `pnpm audit`. |

The following workflows are **scheduled / non-PR-gating** — they run on a schedule
or manual dispatch and do NOT block merges:

| Workflow | Trigger | Notes |
|---|---|---|
| `.github/workflows/dast.yml` | Nightly + dispatch; PR only on `web/**`/`cmd/dashboard/**` | NOT a blanket PR gate |
| `.github/workflows/mutation.yml` | Weekly schedule | Non-gating (`|| true`); informational baseline |
| `.github/workflows/fuzz-nightly.yml` | Nightly | Extended fuzz |
| `.github/workflows/monthly-vuln-scan.yml` | Monthly | Report + tracking issue |
| `.github/workflows/poam-aging.yml` | Weekly | SLA-breach alerting |
| `.github/workflows/base-image-refresh.yml` | Weekly | Digest-drift PR + issue |

The sections below describe each gate. "Aggregated by ci-gate" means the job is in
`ci-gate`'s `needs:` list. "Independent required check" means it must also be listed
in branch protection but is not part of that list.

### 4.1 Lint and static analysis — `lint` job

- **`golangci-lint`** runs the 15-linter set from §3.1.
- **`gosec`** runs with `-severity medium -confidence medium -fmt sarif` and the job
  fails on any MEDIUM+ severity / MEDIUM+ confidence finding (gating, not just
  SARIF upload). SARIF results are uploaded to the GitHub Security tab regardless of
  outcome.
- `go vet` and `go fmt` run as separate steps in the same job.
- Controls: **SA-11(1)** (code analysis tool), **SSDF PW.8**.

### 4.2 Unit-test coverage floor — `unit-tests` job

- `go test -race -coverprofile=coverage.out` runs across `./cmd/...`, `./internal/...`,
  `./pkg/...`.
- **`scripts/test/cover-gate.sh`** enforces `MIN_COVERAGE=46` (the current measured
  floor); the job fails if total unit coverage drops below this value. Coverage is
  also uploaded to Codecov with a project target of 46% (informational flag set
  while the ratchet is in progress; see [docs/testing.md](../testing.md) for the
  ratchet schedule).
- Controls: **SA-11**, **SA-11(1)**, **SSDF PW.8**.

### 4.3 Integration test coverage — `integration-tests` job

- Uses `controller-runtime/tools/setup-envtest` (envtest) against Kubernetes
  v1.28.2.
- Runs `go test -race -coverpkg=./cmd/...,./internal/...,./pkg/...` so cross-package
  coverage from the integration suite is recorded.
- Controls: **SA-11**, **SA-11(1)**.

### 4.4 Fuzz smoke — `fuzz-smoke` job (ci.yml)

- Runs both native Go fuzz targets for 40 seconds each on every PR/push:
  - `FuzzAdmissionRequest` in `./internal/admission/`
  - `FuzzEngineEvaluate` in `./internal/policy/`
- Catches newly-introduced crashers before they land on the default branch.
- Controls: **SA-11(8)**, **SI-10**, **SSDF PW.8**.

### 4.5 Security scanning — `security-scan` job (ci.yml)

Trivy runs in two passes:

1. **SARIF pass** (non-gating, `exit-code: 0`): filesystem, admission-webhook
   image, policy-manager image, and IaC/config scans all upload to the GitHub
   Security tab.
2. **Gating pass** (`exit-code: 1`): fails the build on any fixable CRITICAL/HIGH
   CVE across fs, both images, and the IaC config scan. Unfixed CVEs and
   operator-owned fixtures are excluded via `.trivyignore` / `.trivyignore.yaml`
   with dated justifications.

Controls: **RA-5**, **SI-2**, **SP 800-190 §3.1**, **SSDF RV.1**.

### 4.6 Govulncheck — `govulncheck` job (ci.yml)

- Installs `govulncheck@v1.3.0` (pinned).
- Emits SARIF for the GitHub Security tab (non-gating) and then runs a gating text
  pass (`govulncheck ./...`) that fails the build on any reachable known
  vulnerability in Go module dependencies.
- Controls: **RA-5**, **SI-2**, **SI-2(2)**, **SSDF RV.1**.

### 4.7 CodeQL SAST — `codeql.yml` (independent required check)

- Runs CodeQL `security-extended` analysis for both `go` and `javascript-typescript`
  (the Svelte dashboard SPA) on push, PR, and weekly schedule (Monday 03:30 UTC).
- This is an **independent required workflow** in `.github/workflows/codeql.yml`. It
  is **NOT** part of `ci-gate`'s `needs:` list. It must be listed separately as a
  required status check in branch protection (`Analyze (go)` and
  `Analyze (javascript-typescript)` — see `docs/security/branch-protection.md`).
- Results upload to the GitHub Security tab (SARIF). CodeQL does **not** fail the
  build on findings by default; it is informational unless GitHub code-scanning is
  separately configured to block merges. Findings are triaged and tracked in the POA&M.
- Controls: **SA-11(1)**, **SI-10**, **SSDF PW.8**.

### 4.8 Secret scanning — `secrets-scan.yml` (independent required check)

- Runs `gitleaks` (v8.27.2, checksum-verified) over the full git history
  (`--log-opts "--all"`) on PR, push, and weekly schedule (Monday 03:00 UTC).
- Any confirmed finding exits non-zero and fails the job.
- This is an **independent required workflow** in `.github/workflows/secrets-scan.yml`.
  It is **NOT** part of `ci-gate`'s `needs:` list. It must be listed separately as a
  required status check in branch protection (`Gitleaks — secret scan (full history)`
  — see `docs/security/branch-protection.md`).
- Controls: **IA-5**, **SI-7**, **SSDF PW.4**.

### 4.9 Manifest-hardening gates — `rbac-sa-gate`, `network-posture-gate`, `manifest-hardening-gate` jobs (ci.yml)

Pure static render-then-scan jobs (no cluster required) that run in parallel with
`lint`. Each uses pinned `conftest` (v0.68.2, checksum-verified) against the Helm
chart rendered in realistic configurations:

- **`rbac-sa-gate`**: enforces RBAC least-privilege and ServiceAccount
  automount-disable policies (`rbac.leastprivilege`, `sa.token`, `sa.shared`
  namespaces). Includes policy self-tests that confirm fail fixtures are correctly
  denied.
- **`network-posture-gate`**: enforces default-deny NetworkPolicy, per-component
  ingress scoping, PSA-restricted Namespace, and plaintext-URL prohibition
  (`network.posture`). Includes a keystone regression proof (removing the
  default-deny template must be denied).
- **`manifest-hardening-gate`**: enforces full restricted-PSS controls (seccomp,
  drop ALL, readOnlyRootFs, no priv-esc, runAsNonRoot, non-root runAsGroup,
  resource requests+limits) using `restricted.pss` namespace + `kubeconform
  -strict` schema validation. Includes a seccomp-removed regression proof.

Controls: **CM-6**, **CM-7**, **SA-11**, **CIS Kubernetes Benchmark 5.1/5.2/5.3**,
**SSDF PW.8**.

### 4.10 Helm unit tests — `helm-unittest` job (ci.yml)

Runs `helm unittest` against `charts/kube-policies/tests/*_test.yaml`, asserting
that every control-plane pod and container carries the restricted-PSS control set.
Deleting a hardening attribute from a template fails the test.
Controls: **CM-6**, **SA-11**.

---

## 5 Phase 4 — Extended / Scheduled Security Testing

### 5.1 Nightly fuzz — `fuzz-nightly.yml`

- Runs `FuzzAdmissionRequest` and `FuzzEngineEvaluate` for **10 minutes each**
  (scheduled 04:00 UTC nightly, also dispatchable).
- Corpus is uploaded as an artifact after each run so seeds accumulate over time.
  Crashers trigger an explicit failure annotation with artifact linkage.
- Controls: **SA-11(8)**, **CA-7**, **SSDF PW.8**.

### 5.2 DAST scan — `dast.yml` (scheduled / scoped; NOT a blanket PR gate)

- Runs OWASP ZAP baseline scans against the policy-manager REST API (:8080) and
  the dashboard BFF (:3000), plus TLS/cipher checks against the admission-webhook
  HTTPS endpoint (:8443) on a Kind cluster.
- **Trigger scope**: nightly schedule (03:00 UTC); manual dispatch (configurable
  severity threshold); pull requests **only when changes touch `web/**` or
  `cmd/dashboard/**`**. It does NOT trigger on general Go/chart/policy PRs and is
  NOT a blanket PR gate.
- SARIF results upload to the GitHub Security tab. Not aggregated by `ci-gate`.
- Controls: **CA-8**, **SA-11**, **SC-8**, **RA-5(5)**.

### 5.3 Mutation testing — `mutation.yml` (scheduled; non-gating)

- Runs `gremlins unleash` (v0.5.0) against `./internal/admission/...` and
  `./internal/policy/...` weekly (Monday 05:00 UTC, also dispatchable).
- **Non-gating**: the workflow uses `|| true` so it never fails the run.
  Informational minimum score: **50%**. The hard `--threshold` gate is intentionally
  disabled on first adoption to establish a baseline; it will be enabled once a
  stable score is measured (SDL-WU-30 ratchet). Not aggregated by `ci-gate`.
- Controls: **SA-11**, **SA-15**.

### 5.4 Monthly vulnerability scan — `monthly-vuln-scan.yml`

- Runs on the 1st of each month (06:00 UTC) and on manual dispatch.
- Executes `govulncheck`, Trivy fs scan, and Trivy image scans against both
  container images built from HEAD. Produces a consolidated dated Markdown + JSON
  report artifact and opens/updates a tracking GitHub Issue with findings grouped
  by severity and SLA due dates (Critical/High: 30 days, Moderate: 90 days,
  Low: 180 days).
- Controls: **RA-5**, **RA-5(2)**, **RA-5(5)**, **CA-7**.

### 5.5 POA&M aging — `poam-aging.yml`

- Runs weekly (Monday 07:00 UTC) and on manual dispatch.
- Enumerates open GitHub Issues labelled `vuln`, computes age vs SLA due date,
  and produces a weekly aging report artifact. Posts a Slack notification if any
  item is past its SLA (guarded by `secrets.SLACK_WEBHOOK` availability).
- Controls: **CA-5**, **PM-4**, **RA-5**, **SI-2**, **SI-4**.

### 5.6 Base-image refresh — `base-image-refresh.yml`

- Runs weekly (Tuesday 05:00 UTC) and on manual dispatch.
- Resolves current upstream digests for `golang:1.25-alpine`,
  `gcr.io/distroless/static:nonroot`, and `node:22-alpine` using `crane` (v0.20.2,
  checksum-verified) and compares them against the pinned digests in the
  Dockerfiles. On drift: opens an automated PR rewriting the `FROM …@sha256:`
  pins and opens/updates a tracking GitHub Issue with a remediation SLA (7 days
  for a stale base image, 24 hours for a CVE-advisory-linked issue).
- Controls: **SI-2**, **SP 800-190 §3.1**, **SLSA L3**.

---

## 6 Phase 5 — Release, Signing, and Provenance (SA-15, SR-4, SI-7)

The release pipeline (`.github/workflows/release.yml`) runs on version tags and
implements the following supply-chain controls:

- **Cosign image signing**: both `admission-webhook` and `policy-manager` container
  images are signed by digest using keyless Sigstore OIDC identity (GitHub Actions
  OIDC). Signatures are recorded in Rekor.
- **SBOM generation and attestation**: SPDX SBOMs are generated with
  `anchore/sbom-action` and attested via `cosign attest --type spdxjson` by
  digest. A vulnerability predicate (`cosign attest --type vuln`) is also generated
  using Trivy in `cosign-vuln` format.
- **SLSA provenance**: OCI-native BuildKit provenance + SBOM attestation is
  recorded per image.
- **SBOM vulnerability gate**: Trivy scans each generated SBOM before attestation;
  the release fails if any CRITICAL/HIGH CVE is present in the attested component
  set.
- **Policy bundle**: the OPA policy bundle carries a reproducible, content-addressed
  digest verified by two independent builds in CI (`policy-library` job). The bundle
  is SemVer-versioned and signed.
- **Binary reproducibility**: the `reproducible-build` job proves that two
  independent builds of the same commit produce byte-identical binaries (SHA-256
  match).

Verification of release artifacts is documented in
[docs/policy-bundle-verification.md](../policy-bundle-verification.md) and
[docs/supply-chain/](../supply-chain/).

Controls: **SR-4**, **SI-7**, **SSDF PO.5**, **SSDF RV.2**, **SLSA L3**.

---

## 7 Phase 6 — Vulnerability Management (RA-5, SI-2)

Ongoing vulnerability management is operated through the following cadence. The
vulnerability management procedure is documented at
[docs/security/vulnerability-management.md](vulnerability-management.md).

| Cadence | Mechanism | Severity gate | SLA |
|---|---|---|---|
| Every PR/push | `govulncheck` (gating, `govulncheck` job in ci-gate), Trivy fs + image (gating CRITICAL/HIGH fixable, `security-scan` job in ci-gate) | Reachable vuln → build fails | Immediate |
| Every PR/push | CodeQL SARIF (independent required check, informational), gosec SARIF (lint job in ci-gate, MEDIUM+ blocks merge), gitleaks (independent required check, blocks on finding) | Finding → Security tab / blocks merge | Triage each sprint |
| Nightly | DAST/ZAP (`dast.yml`, scheduled); fuzz (`fuzz-nightly.yml`, 10 m/target) | DAST High finding → SARIF upload (workflow non-gating for general PRs); fuzz crash → issue filed | Same-day for fuzz crashers |
| Monthly | `monthly-vuln-scan.yml` (govulncheck + Trivy fs + images) | Report + tracking issue | Critical/High: 30 d; Moderate: 90 d; Low: 180 d |
| Weekly | `poam-aging.yml` (SLA breach alert) | Slack notification | Per SLA above |
| Weekly (Tuesday) | `base-image-refresh.yml` (digest drift) | PR + issue on drift | 7 days (24 h if CVE-linked) |

Externally reported vulnerabilities follow the disclosure process in
[SECURITY.md](../../SECURITY.md). All open weaknesses are tracked in the
[POA&M](../compliance/POAM.md).

---

## 8 SSDF / SP 800-53 crosswalk

The following table maps each SDL practice implemented in this repo to NIST SP
800-218 SSDF practices and SP 800-53 Rev 5 control identifiers.

| Practice | SSDF practice | SP 800-53 controls |
|---|---|---|
| Threat model ([threat-model.md](threat-model.md)) | PO.3 (Implement Supporting Toolchains) | SA-3, SA-15 |
| Secure coding standards (`.golangci.yml`) | PW.5 (Create Source Code by Adhering to Secure Coding Practices) | SA-15 |
| PR checklist + CODEOWNERS review gate | PO.4 (Define and Use Criteria for Software Security Checks) | SA-11, CM-3 |
| `gosec` MEDIUM+ gate (`lint` job) | PW.8.1 (Test Executable Code to Identify Vulnerabilities) | SA-11(1) |
| Unit-test coverage floor (`cover-gate.sh`, `unit-tests` job) | PW.8.2 (Test Executable Code to Identify Vulnerabilities) | SA-11, SA-11(1) |
| Integration tests with `-coverpkg` (`integration-tests` job) | PW.8.2 | SA-11, SA-11(1) |
| Fuzz smoke / nightly (`fuzz-smoke`, `fuzz-nightly.yml`) | PW.8.3 (Fuzz Testing) | SA-11(8), SI-10 |
| CodeQL SAST (`codeql.yml`) | PW.8.1 | SA-11(1), SI-10 |
| Secret scanning (`secrets-scan.yml`) | PW.4 (Review and/or Analyze Human-Readable Code) | IA-5, SI-7 |
| Trivy SCA / IaC / image gating (`security-scan` job) | RV.1 (Identify and Confirm Vulnerabilities) | RA-5, SI-2 |
| `govulncheck` gate (`govulncheck` job) | RV.1 | RA-5, SI-2, SI-2(2) |
| DAST / ZAP (`dast.yml`) | RV.2 (Assess, Prioritize, and Remediate Vulnerabilities) | CA-8, SA-11, RA-5(5) |
| Mutation testing (`mutation.yml`) | PW.8.2 | SA-11, SA-15 |
| Monthly vulnerability scan (`monthly-vuln-scan.yml`) | RV.1, RV.2 | RA-5, RA-5(2), RA-5(5), CA-7 |
| POA&M aging (`poam-aging.yml`) | RV.3 (Analyze Vulnerabilities to Develop Remediations) | CA-5, PM-4, RA-5, SI-2, SI-4 |
| Base-image CVE refresh (`base-image-refresh.yml`) | RV.2 | SI-2, SP 800-190 §3.1 |
| Cosign sign + SBOM/SLSA/vuln attestation (`release.yml`) | PO.5 (Implement and Maintain Secure Environments for Software Development) | SR-4, SI-7, SLSA L3 |
| Reproducible binary builds (`reproducible-build` job) | PO.5 | SI-7 |
| Manifest-hardening gates (rbac-sa, network, PSS) | PW.8.2 | CM-6, CM-7, SA-11 |
| Input validation (gosec + govet + errorlint) | PW.6 (Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security) | SI-10 |

---

## 9 Roles and responsibilities

| Role | Holder | SDL responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for SDL program adequacy; approves this document; ensures ISSO role is staffed. |
| ISSO | TBD — assign before assessment | Reviews security-relevant changes at the PR gate; reviews threat model; reviews POA&M; approves significant architecture changes. |
| Maintainers / CODEOWNERS | @Jibbscript (single-maintainer PoC) | Implement and maintain CI gates; review PRs; remediate vulnerabilities within SLA; update this document. |
| Authorizing Official (AO) | TBD — assign before assessment | Reviews SDL evidence at assessment; approves residual risk. |

---

## 10 References

- Threat model: [docs/security/threat-model.md](threat-model.md)
- Secure coding configuration: [`.golangci.yml`](../../.golangci.yml)
- PR change-control checklist: [`.github/pull_request_template.md`](../../.github/pull_request_template.md)
- Code ownership: [`.github/CODEOWNERS`](../../.github/CODEOWNERS)
- Testing strategy (governance): [docs/testing.md](../testing.md)
- Testing how-to (operational): [`TESTING.md`](../../TESTING.md)
- Policy bundle verification: [docs/policy-bundle-verification.md](../policy-bundle-verification.md)
- Vulnerability disclosure: [`SECURITY.md`](../../SECURITY.md)
- CI pipeline: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
- CodeQL: [`.github/workflows/codeql.yml`](../../.github/workflows/codeql.yml)
- Secret scanning: [`.github/workflows/secrets-scan.yml`](../../.github/workflows/secrets-scan.yml)
- DAST: [`.github/workflows/dast.yml`](../../.github/workflows/dast.yml)
- Nightly fuzz: [`.github/workflows/fuzz-nightly.yml`](../../.github/workflows/fuzz-nightly.yml)
- Mutation testing: [`.github/workflows/mutation.yml`](../../.github/workflows/mutation.yml)
- Monthly vulnerability scan: [`.github/workflows/monthly-vuln-scan.yml`](../../.github/workflows/monthly-vuln-scan.yml)
- POA&M aging: [`.github/workflows/poam-aging.yml`](../../.github/workflows/poam-aging.yml)
- Base-image refresh: [`.github/workflows/base-image-refresh.yml`](../../.github/workflows/base-image-refresh.yml)
- Release and signing: [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- Control matrix: [docs/compliance/control-matrix.csv](../compliance/control-matrix.csv)
- NIST SP 800-53 Rev 5 (SA-3, SA-11, SA-11(1), SA-11(8), SA-15, SI-10, RA-5, SI-2)
- NIST SP 800-218 SSDF (PO.3, PO.4, PO.5, PW.4, PW.5, PW.6, PW.8, RV.1, RV.2, RV.3)
- FedRAMP Moderate baseline; FIPS-199; SP 800-190; SLSA L3
