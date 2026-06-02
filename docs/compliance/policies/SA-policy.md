---
title: "System and Services Acquisition Policy (SA) — Kube-Policies (KP)"
control_family: "SA — System and Services Acquisition"
controls: "SA-1, SA-3, SA-11, SA-15"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# System and Services Acquisition Policy (SA) — Kube-Policies (KP)

This policy establishes the System and Services Acquisition requirements for the Kube-Policies
system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP
**Moderate** baseline). It implements control **SA-1 (Policy and Procedures)** and anchors the
SA controls that govern how KP is developed, tested, and maintained as a secure system:
**SA-3** (System Development Life Cycle), **SA-11** (Developer Testing and Evaluation), and
**SA-15** (Development Process, Standards, and Tools). The operational steps live in the
companion [SA procedures](../procedures/SA-procedures.md). The operational secure SDLC document
is at [docs/security/secure-sdlc.md](../../security/secure-sdlc.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This policy documents the
secure-SDLC *discipline* the program operates under and the controls that are *actually
implemented* — it does not claim that every SA control is operating at steady state. Per-control
status is tracked in the [control matrix](../control-matrix.csv) and open weaknesses in the
[POA&M](../POAM.md), with remediation phases (P0–P12) defined in
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review
was **2026-06-02**; the **next review is 2027-06-02**. It is also reviewed whenever the
SDLC process materially changes, a new tool class is added to the CI pipeline, a SA-family
finding is received from an assessor, or the development process, standards, or toolchain are
significantly updated. Reviews are recorded by updating the `last_reviewed`/`next_review`
front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that security is integrated into every phase of the
KP system development life cycle — from requirements and design through implementation,
testing, and release — and that the development process uses documented, approved tools and
standards that are verifiably enforced in CI. It applies to:

- All KP authorization-boundary components: admission-webhook (`AST-WH`), policy-manager
  (`AST-PM`), dashboard (`AST-DB`/`AST-SPA`), Policy and PolicyException CRDs
  (`AST-CRD-POL`, `AST-CRD-EXC`), Helm chart (`AST-CHART`), and the embedded OPA/Rego
  engine (`AST-OPA`) — all running in the `kube-policies-system` namespace.
- All Go modules in `go.mod`, all container images built from `Dockerfile.*`, and all
  Helm chart artifacts released under the signed bundle provenance chain.
- All personnel filling the System Owner, ISSO, Maintainer/CODEOWNERS, and Operator roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts referenced in
procedures are **placeholders**.

## 2 SA-1 — System and Services Acquisition Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this SA policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the procedures are in
[SA procedures](../procedures/SA-procedures.md).

### 2.2 SA-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System
Owner, ISSO, AO, Maintainers, and all repository contributors by being maintained in version
control under [`docs/compliance/policies/`](.) and referenced from the SSP
([../ssp/SSP.md](../ssp/SSP.md), SA family) and the [CRM](../CRM.md).

### 2.3 SA-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing.

### 2.4 SA-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This SA policy (SA-1) | ISSO | At least annually (next: 2027-06-02) | SDLC process change; new tool class added to CI; assessor finding |
| SA procedures ([SA-procedures.md](../procedures/SA-procedures.md)) | ISSO | At least annually (next: 2027-06-02) | Procedure drift; CI pipeline change; new testing tier added |
| Secure SDLC document ([docs/security/secure-sdlc.md](../../security/secure-sdlc.md)) | Maintainer | Per SDLC process change; annually | New phase added; tool version bump; assessor finding |
| CI/CD pipeline configuration (`.github/workflows/`) | Maintainer | Per tool change; annually | New job added; gate threshold changed; tool deprecated |
| Development standards (`.golangci.yml`, linter config) | Maintainer | Per tool update; annually | Linter version bump; new rule enabled/disabled |

## 3 SA-3 — System Development Life Cycle

### 3.1 SDLC overview

KP uses a security-integrated SDLC that enforces security requirements at every phase through
automated CI gates, branch protection, and mandatory code review. The SDLC phases and their
primary security enforcement artifacts are:

| Phase | Security enforcement artifacts |
|---|---|
| **Requirements** | [docs/compliance/control-matrix.csv](../control-matrix.csv); [POA&M](../POAM.md); threat model ([docs/compliance/threat-model.md](../threat-model.md)) |
| **Design** | Trust-zone architecture ([docs/compliance/system-facts.md](../system-facts.md)); data flow diagram ([docs/compliance/diagrams/data-flow.md](../diagrams/data-flow.md)); threat model STRIDE analysis |
| **Implementation** | `.golangci.yml` (static analysis/linting); `CONTRIBUTING.md` (coding standards); CODEOWNERS (`.github/CODEOWNERS`) |
| **Testing** | `.github/workflows/ci.yml` (unit, integration, coverage gate, SAST, DAST, fuzz-smoke, govulncheck); `.github/workflows/fuzz-nightly.yml`; `.github/workflows/mutation.yml` |
| **Release** | `.github/workflows/release.yml` (build, sign, SBOM, SLSA provenance, vuln-attest) |
| **Operations** | `charts/kube-policies/` (Helm deployment); monitoring/alerting (P9); backup/restore ([docs/backup-restore.md](../../backup-restore.md)) |

The operational secure SDLC document at [docs/security/secure-sdlc.md](../../security/secure-sdlc.md)
provides the authoritative phase-by-phase narrative. Procedures for operating the SDLC controls
are in [SA-procedures.md](../procedures/SA-procedures.md).

### 3.2 Security roles in the SDLC

Security considerations are integrated into the SDLC through defined role accountabilities:

| Role | Holder | SA-3 responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for SDLC program adequacy; approves deviations from secure development standards |
| ISSO | TBD — assign before assessment | Designated SA-1 official; reviews SDLC artifacts annually; approves changes to CI security gates; maintains POA&M for SA findings |
| Maintainers / CODEOWNERS | TBD — assign | Implement and maintain the CI pipeline; enforce branch protection; conduct code review; update SDLC tooling |
| Operator | TBD — assign | Validates deployment artifacts; confirms signed/attested releases before deployment |
| Authorizing Official (AO) | TBD — assign before assessment | Approves authorization decision at P12; receives SDLC posture summary at each phase gate |

### 3.3 SA-3 current status

SA-3 is **Partial** for KP at this stage. The SDLC scaffold exists (CI pipeline, PR review
enforced, branch protection), and the secure-SDLC discipline is operationally applied. The
formal secure-SDLC process document ([docs/security/secure-sdlc.md](../../security/secure-sdlc.md))
and the full set of SA-11/SA-15 enforcement gates are being formalized in P11. Open weaknesses
are tracked in [POAM.md](../POAM.md) under the SA family.

## 4 SA-11 — Developer Testing and Evaluation

### 4.1 Policy statement

All KP code changes shall be tested with a tiered set of automated tests before merge. The
test tiers and their required coverage thresholds are defined in the CI pipeline
(`.github/workflows/ci.yml`) and documented in the companion [SA procedures](../procedures/SA-procedures.md).
The testing documentation is at [docs/testing.md](../../testing.md) (when present) and
in the CI pipeline jobs listed in §4.2.

### 4.2 Testing tiers

KP enforces the following developer testing tiers. The **`ci-gate`** job in
`.github/workflows/ci.yml` is the single aggregating required check; its `needs:` list
is the authoritative set of jobs it gates. Workflows listed as "independent required check"
are separate workflows that must also be enumerated in branch protection
(see `docs/security/branch-protection.md` and `.github/settings.yml`) but are NOT
part of ci-gate's `needs:` list.

**Jobs aggregated by `ci-gate` (`.github/workflows/ci.yml`):**

| Tier | CI job name | Tools | Gating behavior |
|---|---|---|---|
| **Lint + SAST** | `lint` | `golangci-lint`, `gosec` (MEDIUM+ severity/confidence gate), `go vet`, `go fmt` | Fails on lint violations or any gosec MEDIUM+ finding |
| **Unit tests + coverage floor** | `unit-tests` | `go test -race`, `cover-gate.sh` (MIN_COVERAGE=46) | Fails if coverage drops below floor |
| **FIPS verification** | `fips-verify` | Go FIPS build check | Fails if FIPS build breaks |
| **Image build** | `build-images` | Docker BuildKit | Fails on build error |
| **Integration tests** | `integration-tests` | `go test -race` + envtest (k8s v1.28.2) | Fails on integration test failure |
| **e2e (Kind)** | `e2e-kind` | Kind cluster, Helm | Fails on e2e failure |
| **e2e (k3s)** | `e2e-k3s` | k3s cluster, Helm | Fails on e2e failure |
| **Vulnerability scanning** | `security-scan` | Trivy fs + image + config (gating CRITICAL/HIGH fixable; SARIF upload for unfixable) | Fails on fixable CRITICAL/HIGH CVE |
| **Helm tests** | `helm-tests` | `helm test` | Fails on Helm test failure |
| **Docs tests** | `docs-tests` | Link/doc checks | Fails on broken docs |
| **RBAC/SA gate** | `rbac-sa-gate` | `conftest` (RBAC least-privilege, SA automount policies) | Fails on policy violation |
| **Network posture gate** | `network-posture-gate` | `conftest` (default-deny NetworkPolicy, PSA-restricted namespace) | Fails on policy violation |
| **Manifest hardening gate** | `manifest-hardening-gate` | `conftest` (restricted PSS), `kubeconform -strict` | Fails on hardening violation |
| **Helm unit tests** | `helm-unittest` | `helm unittest` | Fails if any pod/container loses a hardening attribute |
| **Monitoring rules** | `monitoring-rules` | `promtool check/test`, drift check | Fails on rule or drift error |
| **Action lint** | `actionlint` | `actionlint` | Fails on workflow syntax error |
| **Govulncheck** | `govulncheck` | `govulncheck` (reachable vuln gate) | Fails on any reachable known Go module vulnerability |
| **Reproducible build** | `reproducible-build` | Two independent builds, SHA-256 comparison | Fails if builds are not byte-identical |
| **Fuzz smoke** | `fuzz-smoke` | `go test -fuzz` (40 s/target) | Fails on any crasher |

**Independent required workflows (NOT in ci-gate `needs:`, must be listed separately in branch protection):**

| Workflow | Job | Tools | Gating behavior |
|---|---|---|---|
| `.github/workflows/codeql.yml` | `Analyze (go)` / `Analyze (javascript-typescript)` | CodeQL `security-extended` | Uploads SARIF to Security tab; informational unless GitHub code-scanning is separately configured to block |
| `.github/workflows/secrets-scan.yml` | `Gitleaks — secret scan (full history)` | `gitleaks` v8.27.2 | Fails its own job on any detected credential |
| `.github/workflows/ui.yml` | `Lint, Test, and Build UI` | `pnpm audit`, Vitest, Rego bundle, build | Fails on high-severity npm advisory or build error |

**Scheduled / non-gating workflows (not PR gates):**

| Workflow | Schedule | Notes |
|---|---|---|
| `.github/workflows/dast.yml` | Nightly + dispatch; PR only on `web/**` / `cmd/dashboard/**` path changes | NOT a blanket PR gate; SARIF upload |
| `.github/workflows/mutation.yml` | Weekly schedule | Non-gating (`|| true`); informational baseline |
| `.github/workflows/fuzz-nightly.yml` | Nightly | Extended fuzz; crashes filed as issues |
| `.github/workflows/monthly-vuln-scan.yml` | Monthly (1st of month) | Govulncheck + Trivy; tracking issue |
| `.github/workflows/poam-aging.yml` | Weekly | SLA-breach alerting |
| `.github/workflows/base-image-refresh.yml` | Weekly | Digest-drift PR + issue |

See `docs/security/branch-protection.md` for the full required-status-check enumeration.

### 4.3 SA-11(1) — Static code analysis

Static code analysis is enforced on every pull request via:

- **`golangci-lint`** with the configuration in `.golangci.yml` (runs in the `lint` job,
  aggregated by ci-gate). Violations block merge.
- **`gosec`** (security-oriented Go static analysis, run as part of the `lint` job).
  The gate threshold is **MEDIUM+ severity / MEDIUM+ confidence** — any finding at or
  above MEDIUM on both axes fails the `lint` job and blocks merge. SARIF results are
  uploaded to the GitHub Security tab regardless of outcome.
- **CodeQL** via `.github/workflows/codeql.yml` (`security-extended` queries for Go
  and JavaScript/TypeScript). CodeQL runs as an **independent required workflow** (not
  part of ci-gate's `needs:`). It uploads SARIF to the GitHub Security tab
  (informational). CodeQL does NOT fail the build on findings by default unless GitHub
  code-scanning is separately configured to block merges. Findings are triaged and
  tracked in the POA&M.

Suppressions of gosec findings (`//nolint:gosec`) require a dated, justified inline
comment and ISSO review before merge. Suppressing a CodeQL finding in the Security tab
also requires ISSO review.

### 4.4 SA-11(8) — Dynamic code analysis

Dynamic analysis and fuzz testing are enforced via:

- **DAST** (`.github/workflows/dast.yml`): OWASP ZAP baseline scans against the
  policy-manager REST API, dashboard BFF, and admission-webhook TLS endpoint on a Kind
  cluster. Triggered on **nightly schedule (03:00 UTC)** and **manual dispatch**; triggered
  on pull requests **only for changes under `web/**` or `cmd/dashboard/**`**. It is
  NOT a blanket PR gate for all changes.
- **Fuzz-smoke** (`fuzz-smoke` job, ci.yml; aggregated by ci-gate): short-horizon
  fuzzing (40 s/target) on every PR targeting the admission parsing and policy evaluation
  surfaces. Blocks merge on any crasher.
- **Fuzz-nightly** (`.github/workflows/fuzz-nightly.yml`): extended overnight fuzzing
  (10 min/target, nightly); crashes are filed as priority issues and tracked in the
  [POA&M](../POAM.md).

## 5 SA-15 — Development Process, Standards, and Tools

### 5.1 Development process

KP's development process is documented in [CONTRIBUTING.md](../../../CONTRIBUTING.md) and
enforced through the combination of branch protection, CODEOWNERS review, and the CI
gate jobs described in §4. Key process requirements:

- **All changes via pull request.** Direct commits to the main branch are prohibited by
  branch protection. Every PR must pass all `ci-gate` required checks before merge.
- **CODEOWNERS review.** Security-sensitive paths are listed in `.github/CODEOWNERS`;
  changes to those paths require approval from the designated CODEOWNERS before merge.
- **PR template.** The `.github/pull_request_template.md` checklist enforces that every
  PR author confirms: baseline/inventory updated, CI gates green, security impact assessed,
  digest pinned (for image changes).
- **Conventional commits.** Contributors follow the commit-message conventions in
  [CONTRIBUTING.md §Contribution Workflow](../../../CONTRIBUTING.md#contribution-workflow)
  to support automated release-note generation and change traceability.
- **Security review.** Security-sensitive changes (trust-boundary, authentication,
  cryptography, policy evaluation, audit) undergo manual security review per the process
  in [CONTRIBUTING.md §Security Review Process](../../../CONTRIBUTING.md#security-review-process).

### 5.2 Approved standards and tools

The following tool classes are approved for KP development. Pinned versions are established
in the CI pipeline and are not to be changed without ISSO review:

| Tool class | Primary tool(s) | Configuration artifact |
|---|---|---|
| Language runtime | Go (version pinned in `go.mod` / `Dockerfile.*`) | `go.mod`, `Dockerfile.*` |
| Static analysis / linting | `golangci-lint`, `gosec` | `.golangci.yml` |
| Security static analysis | CodeQL | `.github/workflows/codeql.yml` |
| Vulnerability scanning | Trivy, `govulncheck` | `.github/workflows/ci.yml` |
| Dynamic analysis | DAST toolchain | `.github/workflows/dast.yml` |
| Fuzz testing | `go test -fuzz` | `.github/workflows/ci.yml`, `.github/workflows/fuzz-nightly.yml` |
| Mutation testing | Mutation toolchain | `.github/workflows/mutation.yml` |
| Secrets detection | Secrets-scan toolchain | `.github/workflows/secrets-scan.yml` |
| Frontend dependency audit | `pnpm audit` | `.github/workflows/ui.yml` |
| Build / release | `make`, Docker BuildKit | `Makefile`, `Dockerfile.*` |
| Signing / provenance | `cosign`, SLSA builder | `.github/workflows/release.yml` |
| Chart templating | Helm | `charts/kube-policies/` |
| Policy testing | `conftest`, `helm-unittest` | `tests/`, `.github/workflows/ci.yml` |

Tool version changes that affect security gating (scanners, linters, signing tools) require
ISSO acknowledgement and a corresponding update to this policy's §5.2 table at the next
annual review.

### 5.3 SA-15(3) — Criticality analysis

Criticality analysis is applied to KP components in the inventory
([docs/compliance/inventory.csv](../inventory.csv)). The admission-webhook (`AST-WH`) is
classified as the highest-criticality component (gatekeeper for all workload admission);
it receives priority attention in security review, fuzz targeting, and the POA&M remediation
sequence. The criticality designation is reviewed at each SDLC phase gate and at P12 prior
to the authorization decision.

## 6 Roles and responsibilities (summary)

| Role | Holder | SA responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for SA program adequacy; approves this policy; approves changes to the SDLC that affect the authorization boundary |
| ISSO | TBD — assign before assessment | Designated SA-1 official; reviews SDLC gate configurations annually; approves SAST/DAST suppressions; maintains POA&M for SA findings; authorizes tool version changes that affect security gating |
| Maintainers / CODEOWNERS | TBD — assign | Implement and operate the CI pipeline; enforce coding standards; conduct code review; maintain `.golangci.yml` and scanner configurations; update CONTRIBUTING.md |
| Operator | TBD — assign | Validates release artifacts (signature, SBOM, provenance) before deployment; reports anomalies to ISSO |
| Authorizing Official (AO) | TBD — assign before assessment | Approves authorization decision at P12 based on SA-3 SDLC posture and SA-11 test-coverage evidence |

Contacts (e.g., `security@kube-policies.io`, `isso@kube-policies.io`) are **placeholders**
pending role assignment.

## 7 Compliance, exceptions, and enforcement

- Merging a PR that disables or bypasses a `ci-gate` required check is prohibited without
  ISSO approval and a POA&M entry.
- Adding a SAST or vulnerability suppression (`.golangci.yml` `nolint`, `.trivyignore`,
  `govulncheck` exception) without a dated justification and reviewer approval is a finding
  requiring correction before merge.
- Introducing a new tool class to the CI pipeline without updating the approved-tools table
  in §5.2 and obtaining ISSO review is a policy violation.
- Allowing a fuzz crash or DAST HIGH finding to remain unaddressed beyond 30 days without
  a POA&M entry and ISSO acknowledgement is a material compliance failure.
- Changing the Go toolchain version or a scanner version on the main branch without a
  corresponding update to the inventory and this policy's §5.2 requires ISSO approval.
- Skipping the annual SDLC/SA artifacts review requires ISSO and System Owner approval
  and a POA&M entry.

## 8 References

- SA procedures: [../procedures/SA-procedures.md](../procedures/SA-procedures.md)
- Secure SDLC: [docs/security/secure-sdlc.md](../../security/secure-sdlc.md)
- Contributing guide: [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- CI pipeline: `.github/workflows/ci.yml`
- Release pipeline: `.github/workflows/release.yml`
- CodeQL workflow: `.github/workflows/codeql.yml`
- DAST workflow: `.github/workflows/dast.yml`
- Fuzz nightly: `.github/workflows/fuzz-nightly.yml`
- Mutation workflow: `.github/workflows/mutation.yml`
- Secrets scan: `.github/workflows/secrets-scan.yml`
- UI audit: `.github/workflows/ui.yml`
- Linter configuration: `.golangci.yml`
- CODEOWNERS: `.github/CODEOWNERS`
- PR template: `.github/pull_request_template.md`
- Inventory: [../inventory.csv](../inventory.csv)
- Threat model: [../threat-model.md](../threat-model.md)
- CM policy (configuration management): [CM-policy.md](CM-policy.md)
- RA policy (vulnerability scanning): [RA-policy.md](RA-policy.md)
- SI policy (flaw remediation): [SI-policy.md](SI-policy.md)
- SR policy (supply chain): [SR-policy.md](SR-policy.md)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (SA-1, SA-3, SA-11, SA-15); FedRAMP Moderate baseline; FIPS-199.
