---
title: "System and Services Acquisition Procedures (SA) — Kube-Policies (KP)"
control_family: "SA — System and Services Acquisition"
controls: "SA-1, SA-3, SA-11, SA-15"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# System and Services Acquisition Procedures (SA) — Kube-Policies (KP)

These are the operational procedures that implement the System and Services Acquisition policy
([../policies/SA-policy.md](../policies/SA-policy.md)) for the Kube-Policies system (KP).
They provide step-by-step guidance for operating the secure SDLC, running the developer
testing pipeline, and maintaining the development process, standards, and toolchain that
enforce SA-3, SA-11, and SA-15 for the KP admission-control system.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**). These procedures describe what is *actually implemented*
and what a maintainer, operator, or assessor can run to verify it. Where a control is Partial
or has a residual, the procedure says so; open weaknesses are tracked in [../POAM.md](../POAM.md).
All `@kube-policies.io` contacts below are **placeholders** pending role assignment.

**Annual review.** These procedures are reviewed and updated at least **annually** (last
review **2026-06-02**; next review **2027-06-02**) and after any significant CI pipeline
change, tool version update, or assessor finding. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to all KP authorization-boundary components in §1 of
[SA-policy.md](../policies/SA-policy.md): the admission-webhook, policy-manager, dashboard,
CRDs, Helm chart, and OPA/Rego engine. They govern every code change from branch creation
through merge and release.

## 2 SDLC gate procedure (SA-3)

### 2.1 Prerequisite: verify CI gate configuration

Before beginning development work, confirm the CI gate is correctly configured. The
`ci-gate` job in `.github/workflows/ci.yml` must list all required jobs as dependencies.
Verify:

```console
# Confirm the ci-gate job exists and its needs list matches the policy table in SA-policy.md §4.2
grep -A 30 'ci-gate:' .github/workflows/ci.yml
```

An assessor can verify the required-status-checks branch protection rule via:

```console
gh api repos/{owner}/kube-policies/branches/main/protection \
  --jq '.required_status_checks.contexts[]'
```

### 2.2 Feature branch and pull request

1. **Create a feature branch** from the current `main`:
   ```console
   git checkout main && git pull
   git checkout -b feat/your-feature-name
   ```

2. **Implement the change**, following the coding standards in
   [CONTRIBUTING.md §Coding Standards](../../../CONTRIBUTING.md#coding-standards).

3. **Run local pre-flight checks** before opening a PR:
   ```console
   # Format and lint
   make fmt
   make lint

   # Unit tests with race detector
   go test -race ./...

   # Security scanning (local equivalent of CI security-scan)
   make security
   ```

4. **Open a pull request** using the template at `.github/pull_request_template.md`.
   Complete every checklist item in the template. For security-sensitive changes
   (authentication, cryptography, policy evaluation, audit, trust-boundary), add the
   `security-review` label to request manual security review per
   [CONTRIBUTING.md §Security Review Process](../../../CONTRIBUTING.md#security-review-process).

5. **Wait for `ci-gate` to pass.** All required status checks must be green before merge.
   A failing check is not bypassed under any circumstance without ISSO approval and a
   POA&M entry.

6. **Address reviewer feedback.** At least one CODEOWNERS approval (for paths listed in
   `.github/CODEOWNERS`) is required before merge.

### 2.3 Merge and traceability

Once CI passes and approval is obtained:

```console
# Squash-merge with a conventional commit message
# GitHub enforces this via branch protection merge-strategy settings
```

All merged commits must reference the relevant issue or control ID (e.g., `SA-11`, `POAM-008`)
in the commit body or PR description for traceability to the control matrix.

## 3 Developer testing pipeline (SA-11)

The following procedure maps each testing tier to its CI job, the commands to run it
locally, and the evidence it produces for assessors.

### 3.1 Unit tests and coverage gate

**CI job:** `test` / `coverage` in `.github/workflows/ci.yml`

**Purpose:** Verifies that individual units of logic behave correctly and that the codebase
maintains the minimum test coverage threshold required by the gate.

**Local execution:**
```console
# Run all unit tests with race detection
go test -race -count=1 ./...

# Run with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Check coverage threshold (mirrors CI gate)
go test -coverprofile=coverage.out ./... && \
  go tool cover -func=coverage.out | grep '^total:' | awk '{print $3}'
```

**Assessor evidence:** CI run logs showing `PASS` and coverage percentage meeting threshold;
`coverage.out` artifact.

### 3.2 Integration tests

**CI job:** `integration-test` in `.github/workflows/ci.yml`

**Purpose:** Verifies component interactions — admission webhook calling policy manager,
policy evaluation against real OPA engine, audit pipeline end-to-end.

**Local execution:**
```console
# Run integration tests (requires Docker for envtest or kind cluster)
go test -tags integration -race -count=1 ./...

# Alternatively, using make target
make test-integration
```

**Assessor evidence:** CI run logs showing all integration tests passing; test binary output
includes the component names under test.

### 3.3 SAST — static analysis (SA-11(1))

**CI jobs:** `lint` in `.github/workflows/ci.yml`; `codeql-analysis` in
`.github/workflows/codeql.yml`

**Purpose:** Detects security smells, style violations, and language-level bugs before they
reach production code. `golangci-lint` runs the linter set defined in `.golangci.yml`,
including `gosec` for security-oriented Go patterns.

**Local execution:**
```console
# Run golangci-lint (uses .golangci.yml configuration)
golangci-lint run ./...

# Run only gosec for a security-focused view
gosec ./...
```

**Suppression policy:** Any `//nolint:...` directive added to suppress a finding must
carry a dated comment with the justification and a review-date comment. Suppressions
for `gosec` findings at HIGH or CRITICAL severity require ISSO review before merge.

**Assessor evidence:** `golangci-lint` exit 0 in CI lint job; CodeQL scan results in
the GitHub Security tab (`codeql-analysis` job artifacts).

### 3.4 Vulnerability scanning

**CI jobs:** `security-scan` and `govulncheck` in `.github/workflows/ci.yml`

**Purpose:** Detects known CVEs in Go dependencies and container-image layers before merge.
These jobs gate merge; a fixable CRITICAL or HIGH CVE causes exit 1 and blocks the PR.

**Local execution:**
```console
# Trivy filesystem scan (mirrors CI security-scan)
trivy fs --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed .

# Trivy image scans (run after make docker-build)
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
  kube-policies/admission-webhook:dev
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
  kube-policies/policy-manager:dev

# govulncheck for Go module vulnerabilities
govulncheck ./...

# All-in-one via make target
make security
```

**Suppression policy:** Any `.trivyignore` entry must include a dated comment with the CVE
ID, suppression rationale, and a review date no more than 90 days in the future. CRITICAL
or HIGH suppressions require a corresponding POA&M entry. See [RA-procedures.md](RA-procedures.md)
§4.3 for the full suppression procedure.

**Assessor evidence:** `security-scan` and `govulncheck` CI job logs showing exit 0; Trivy
SARIF artifacts uploaded to the GitHub Security tab; `.trivyignore` with dated entries.

### 3.5 DAST — dynamic analysis (SA-11(8))

**CI job:** `dast` in `.github/workflows/dast.yml`

**Purpose:** Exercises the running KP API and admission endpoint dynamically, detecting
vulnerabilities that static analysis cannot reach (injection, authentication bypass, header
anomalies).

**Execution:** The `dast` workflow spins up KP components (admission-webhook,
policy-manager) in a test environment and runs the DAST toolchain against the live endpoints.
See `.github/workflows/dast.yml` for the exact tool invocation and gating threshold.

**Assessor evidence:** `dast` CI job logs and artifact report; HIGH findings are filed as
GitHub Security advisories or issues and tracked in the [POA&M](../POAM.md).

### 3.6 Fuzz testing (SA-11(8))

**CI jobs:** `fuzz-smoke` in `.github/workflows/ci.yml` (per-PR); `fuzz-nightly` in
`.github/workflows/fuzz-nightly.yml` (scheduled)

**Purpose:** Discovers crash-inducing and security-relevant inputs in the admission-request
parsing and OPA policy-evaluation surfaces that structured tests do not exercise.

**Local execution:**
```console
# Run a short fuzz session against the admission parser (mirrors fuzz-smoke)
go test -fuzz=FuzzAdmissionRequest -fuzztime=30s ./internal/admission/...

# Run against policy evaluation surface
go test -fuzz=FuzzPolicyEval -fuzztime=30s ./internal/policy/...
```

**Crash handling:** Any crash produced by the fuzz engine (in CI or locally) must be:
1. Reproduced and root-caused locally using the generated corpus entry.
2. Filed as a GitHub issue (HIGH priority) within 1 business day of discovery.
3. Patched within 30 days; if it cannot be patched in time, a POA&M entry is required.

**Assessor evidence:** `fuzz-smoke` and `fuzz-nightly` CI job logs; corpus directory under
`testdata/fuzz/`; any crash entries filed as GitHub issues with the `fuzz-crash` label.

### 3.7 Mutation testing

**CI job:** `mutation` in `.github/workflows/mutation.yml`

**Purpose:** Validates that the unit test suite actually detects defects by introducing
controlled mutations to the source code and verifying that tests fail on the mutants.

**Execution:** See `.github/workflows/mutation.yml` for the toolchain and mutation-score
gate threshold.

**Assessor evidence:** `mutation` CI job logs; mutation score report showing the gate
threshold is met.

### 3.8 Secrets scanning

**CI job:** `secrets-scan` in `.github/workflows/secrets-scan.yml`

**Purpose:** Detects committed secrets (API keys, tokens, certificates, passwords) before
they reach the remote repository.

**Assessor evidence:** `secrets-scan` CI job exit 0; any prior finding records in the
Security tab.

### 3.9 UI dependency audit

**CI job:** `audit` in `.github/workflows/ui.yml`

**Purpose:** Detects high-severity advisories in the dashboard SPA's npm dependency tree.

**Local execution:**
```console
cd web/
pnpm audit --audit-level high
```

**Assessor evidence:** `audit` CI job exit 0 in ui.yml.

## 4 Release pipeline (SA-3 / SA-15)

Every KP release is produced by `.github/workflows/release.yml`, which enforces the
following security steps in sequence:

1. **Build by digest.** All three component images are built from pinned base digests
   and tagged with the release version.
2. **Sign.** Each image is signed with `cosign` using keyless OIDC identity (SLSA
   provenance signer); the signature is pushed to the registry alongside the image digest.
3. **SBOM generation.** A Software Bill of Materials (SBOM) is generated for each image
   and attached as an attestation.
4. **SLSA provenance.** SLSA provenance attestation is generated and attached to each
   image digest.
5. **Vulnerability attestation.** A post-build Trivy scan result is attached as a
   vulnerability attestation.

Verify a released image carries all attestations:

```console
# Verify cosign signature (keyless OIDC)
cosign verify \
  --certificate-identity-regexp 'https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <image>@<digest>

# Verify SLSA provenance attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <image>@<digest>
```

See [SR-procedures.md](SR-procedures.md) for the full supply-chain integrity verification
procedure.

## 5 Development process, standards, and tools (SA-15)

### 5.1 Toolchain version management

Toolchain versions affecting security gating are pinned in CI and reviewed at each annual
SA artifact review. The canonical pinned-version sources are:

| Tool | Version source | How to verify |
|---|---|---|
| Go runtime | `go` directive in `go.mod`; `FROM` line in `Dockerfile.*` | `go version`; `grep ^go go.mod` |
| `golangci-lint` | `.github/workflows/ci.yml` `golangci-lint-action` version pin | `grep golangci-lint .github/workflows/ci.yml` |
| `gosec` | Included in `golangci-lint` linter set via `.golangci.yml` | `grep gosec .golangci.yml` |
| CodeQL | `.github/workflows/codeql.yml` `actions/codeql-action` pin | `grep codeql-action .github/workflows/codeql.yml` |
| Trivy | `.github/workflows/ci.yml` `aquasecurity/trivy-action` pin | `grep trivy-action .github/workflows/ci.yml` |
| `govulncheck` | `.github/workflows/ci.yml` `golang/govulncheck-action` pin | `grep govulncheck-action .github/workflows/ci.yml` |
| `cosign` | `.github/workflows/release.yml` action pin | `grep cosign .github/workflows/release.yml` |

A pull request that bumps any security-tooling version must:
1. Update the version reference in the relevant workflow file.
2. Reference the upstream release/changelog confirming the version is not known-vulnerable.
3. Obtain CODEOWNERS approval on the modified workflow file.
4. Note the change in the next SA policy annual review.

### 5.2 Branch protection and CODEOWNERS

Branch protection on `main` enforces:
- Required status checks: all `ci-gate` dependencies.
- At least one approving review from a CODEOWNERS owner for the changed path.
- No direct pushes to `main`.

Verify branch protection is active:

```console
gh api repos/{owner}/kube-policies/branches/main/protection \
  --jq '{required_reviews: .required_pull_request_reviews.required_approving_review_count,
         required_checks: .required_status_checks.contexts,
         enforce_admins: .enforce_admins.enabled}'
```

Security-sensitive paths covered by `.github/CODEOWNERS` include at minimum:
- `.github/workflows/` — CI/CD pipeline changes
- `internal/admission/` — admission-webhook logic
- `internal/policymanager/` — policy evaluation and authZ
- `internal/audit/` — audit and integrity code
- `docs/compliance/` — compliance artifacts

### 5.3 PR template compliance

Every pull request must complete the checklist in `.github/pull_request_template.md`.
The ISSO reviews a sample of merged PRs quarterly to confirm the checklist is being
completed and that security-impact fields are not left blank.

### 5.4 Secure coding standards

Contributors follow the secure coding standards defined in
[CONTRIBUTING.md §Security Best Practices](../../../CONTRIBUTING.md#security-best-practices)
and [CONTRIBUTING.md §Coding Standards](../../../CONTRIBUTING.md#coding-standards):

- **Input validation:** All inputs from external sources (admission requests, API bodies,
  CRD fields) are validated before use; see `internal/config/config.go` and
  `internal/admission/` for established patterns.
- **Secure defaults:** TLS min-version 1.3; fail-closed admission (`failurePolicy: Fail`
  on the validate webhook); deny-by-default RBAC; no unauthenticated endpoints except
  `/healthz` and `/readyz`.
- **Error handling:** Errors do not leak sensitive information (token values, internal
  paths, stack traces) in API responses or logs. Panics are recovered by
  `gin.Recovery()` (SI-11); internal error details are logged only at debug level.
- **No secrets in code:** Secrets are loaded from Kubernetes Secrets or environment
  variables; never hard-coded. The secrets-scan CI job enforces this.

Note: [CONTRIBUTING.md](../../../CONTRIBUTING.md) exists and contains the security review
process and coding standards referenced above. The authoritative branch-protection policy is
[docs/security/branch-protection.md](../../../docs/security/branch-protection.md) (created in
P11); the `gh api` command in §5.2 remains the live verification step for confirming the
settings are applied to the repository.

## 6 Supply-chain verification at deployment (SA-3 / SA-15)

Before deploying any KP release to a cluster, the Operator verifies the release artifacts:

```console
# 1. Confirm the release tag and digest
gh release view v<version> --repo Jibbscript/kube-policies

# 2. Verify cosign signature on each image
cosign verify \
  --certificate-identity-regexp 'https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <registry>/kube-policies/admission-webhook@<digest>

# 3. Verify SLSA provenance
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <registry>/kube-policies/admission-webhook@<digest>
```

Any release that fails signature or attestation verification must not be deployed. The
failure is reported to the ISSO immediately and a POA&M entry is opened.

## 7 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| Run unit + integration tests (all PRs) | Per pull request (automated CI) | CI / Maintainer |
| SAST scan — golangci-lint + CodeQL | Per pull request (automated CI) | CI / Maintainer |
| Vulnerability scan — Trivy + govulncheck | Per pull request (automated CI) | CI / Maintainer |
| DAST scan | Per pull request (automated CI) | CI / Maintainer |
| Fuzz smoke | Per pull request (automated CI) | CI / Maintainer |
| Fuzz nightly (extended) | Nightly (scheduled — fuzz-nightly.yml) | CI / Maintainer |
| Mutation testing | Scheduled (mutation.yml) | CI / Maintainer |
| Secrets scan | Per pull request (automated CI) | CI / Maintainer |
| UI dependency audit | Per pull request (automated CI, ui.yml) | CI / Maintainer |
| Branch protection verification | Quarterly | ISSO |
| PR template compliance sampling | Quarterly | ISSO |
| Supply-chain verification at deployment | Per release deployment | Operator |
| Toolchain version review | Annually | Maintainer + ISSO |
| SA policy and procedures review | Annually (next: 2027-06-02) | ISSO |

## 8 Records and evidence

Evidence produced by these procedures is retained as SA assessment evidence:

- CI run logs for all `ci-gate` required jobs (retained by GitHub Actions; export to
  long-term storage before 90-day expiry if needed for assessment).
- CodeQL SARIF results in the GitHub Security tab.
- Trivy SARIF results in the GitHub Security tab.
- Release attestations (cosign signatures, SLSA provenance, SBOM) in the image registry.
- `.trivyignore` with dated suppression entries.
- `//nolint` directives with dated justifications in source files.
- Fuzz corpus and crash entries in `testdata/fuzz/` and GitHub issues with `fuzz-crash` label.
- Branch protection configuration (verified via `gh api`).
- CODEOWNERS approval records in merged PR audit trail.
- PR template completion records in merged PR descriptions.

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), SA family).

## 9 References

- SA policy: [../policies/SA-policy.md](../policies/SA-policy.md)
- Secure SDLC: [docs/security/secure-sdlc.md](../../security/secure-sdlc.md)
- Contributing guide: [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- Linter configuration: `.golangci.yml`
- CI pipeline: `.github/workflows/ci.yml`
- Release pipeline: `.github/workflows/release.yml`
- CodeQL workflow: `.github/workflows/codeql.yml`
- DAST workflow: `.github/workflows/dast.yml`
- Fuzz nightly: `.github/workflows/fuzz-nightly.yml`
- Mutation workflow: `.github/workflows/mutation.yml`
- Secrets scan: `.github/workflows/secrets-scan.yml`
- UI audit: `.github/workflows/ui.yml`
- RA procedures (vulnerability suppression): [RA-procedures.md](RA-procedures.md)
- SR procedures (supply-chain verification): [SR-procedures.md](SR-procedures.md)
- SI procedures (flaw remediation): [SI-procedures.md](SI-procedures.md)
- CM procedures (configuration management): [CM-procedures.md](CM-procedures.md)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (SA-1, SA-3, SA-11, SA-15); FedRAMP Moderate baseline; OMB M-17-12.
