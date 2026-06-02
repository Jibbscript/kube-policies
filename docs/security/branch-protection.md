---
title: "Branch Protection & Signed-Commit Policy — Kube-Policies (KP)"
control_family: "CM — Configuration Management / AU — Audit and Accountability / SA — System and Services Acquisition / IA — Identification and Authentication"
controls: "CM-3, AU-10, SA-15, IA-5"
frameworks: "SLSA L3, SSDF PO.3"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
sdlc_work_unit: "SDL-WU-22"
---

# Branch Protection & Signed-Commit Policy — Kube-Policies (KP)

This document specifies the **required** branch-protection configuration for the `main` branch
of the Kube-Policies repository, and the associated signed-commit requirement. It addresses
NIST SP 800-53 Rev 5 controls **CM-3** (Configuration Change Control), **AU-10**
(Non-repudiation), **SA-15** (Development Process, Standards, and Tools), and **IA-5**
(Authenticator Management), as well as **SLSA Level 3** and **SSDF PO.3** supply-chain
requirements.

> **PoC / not-yet-enabled notice.** Kube-Policies is a single-maintainer Proof-of-Concept
> with **no ATO**. The settings documented here reflect the *desired, required* posture.
> Enforcement requires explicitly enabling each setting in **GitHub → Settings → Branches →
> Branch protection rules** (or via the Probot Settings app using `.github/settings.yml`).
> Neither has been enabled on the current repository. This document records the intended
> configuration so that it can be applied when the project acquires a GitHub organisation or
> moves to a production context.

---

## 1. Protected Branch: `main`

All production-bound code ships from `main`. Every merge to `main` must pass the full CI
pipeline and carry an auditable, attributable author identity. The following settings are
required.

---

## 2. Required Settings and Control Rationale

### 2.1 Require Pull Requests — No Direct Pushes

| Setting | Value |
|---|---|
| Require a pull request before merging | **Enabled** |
| Required number of approvals | **1** |

**Rationale.**
- **CM-3** requires that changes to the system undergo review and approval before
  implementation. Blocking direct pushes to `main` ensures every change is introduced through
  a pull request that is visible, reviewable, and recorded in the audit trail.
- **SA-15** requires that the development process enforce standards and tooling that support
  supply-chain security. Gating all merges behind PRs enforces separation of duties between
  author and approver.
- **SSDF PO.3** calls for protected branches and mandatory code review as part of the secure
  development environment baseline.

### 2.2 Require CODEOWNER Review and Dismiss Stale Reviews

| Setting | Value |
|---|---|
| Require review from Code Owners | **Enabled** |
| Dismiss stale pull-request approvals when new commits are pushed | **Enabled** |

**Rationale.**
- The repository's [`CODEOWNERS`](../../.github/CODEOWNERS) file designates `@Jibbscript` as
  the required reviewer for all paths, with elevated coverage over compliance documents,
  security configurations, CI/CD workflows, Helm charts, and container build files.
- Requiring CODEOWNER approval ensures that the designated responsible party has reviewed
  every change before it lands on `main`.
- Dismissing stale approvals ensures that a new commit added after an approval cannot bypass
  review: the reviewer must re-approve the final state of the PR. This closes the approval
  bypass vector that would otherwise undermine CM-3 and AU-10.

### 2.3 Require Status Checks to Pass Before Merge

| Setting | Value |
|---|---|
| Require status checks to pass before merging | **Enabled** |
| Require branches to be up to date before merging | **Enabled** |

The following checks **must** be listed as required status checks by their exact GitHub
check name:

| Check Name | Workflow File | Job ID | Purpose |
|---|---|---|---|
| `CI Gate` | `.github/workflows/ci.yml` | `ci-gate` | Aggregates all upstream CI jobs; fails if any required job failed **or was skipped** (anti-bypass) |
| `Analyze (go)` | `.github/workflows/codeql.yml` | `analyze` | CodeQL SAST for Go sources |
| `Analyze (javascript-typescript)` | `.github/workflows/codeql.yml` | `analyze` | CodeQL SAST for JavaScript/TypeScript UI sources |
| `Gitleaks — secret scan (full history)` | `.github/workflows/secrets-scan.yml` | `gitleaks` | Full-history secret scanning; fails on any detected credential |
| `Lint, Test, and Build UI` | `.github/workflows/ui.yml` | `ui` | UI lint, Vitest, Rego bundle, and build |

**Anti-bypass property of `CI Gate`.** The `ci-gate` job in `ci.yml` runs with `if: always()`
and iterates over all upstream job results, failing immediately if any result is not exactly
`"success"`. A skipped job (e.g. from a path filter or conditional) produces `"skipped"`, which
also fails the gate. This prevents an attacker or a workflow misconfiguration from bypassing
the gate by skipping required jobs.

**Rationale.**
- **CM-3** requires that configuration changes be tested and validated before deployment.
  Mandating that all CI checks pass before merge ensures no untested or failing code lands
  on `main`.
- **SA-15** requires tooling that enforces secure coding standards. CodeQL (SAST), gitleaks
  (secret detection), golangci-lint, and the full test matrix collectively enforce this.
- **SLSA L3** requires that all build steps are hermetic, that the provenance of every
  artifact is verified, and that the CI system is authenticated. Requiring `CI Gate` to pass
  before merge ensures that every commit on `main` has a passing, attributable build record.
- Requiring branches to be up to date prevents a merge-race where a PR that passed checks
  against an older `main` could introduce a regression after a concurrent merge.

### 2.4 Require Linear History

| Setting | Value |
|---|---|
| Require linear history | **Enabled** |

**Rationale.**
- Linear history (squash or rebase merges only) ensures that `git log --first-parent` on
  `main` is a clean, auditable sequence of signed commits. Merge commits with multiple
  parents complicate attribution and forensic review.
- **AU-10** requires non-repudiation of actions. A linear signed history makes it
  unambiguous which author introduced which change and in what order.

### 2.5 Require Signed Commits

| Setting | Value |
|---|---|
| Require signed commits | **Enabled** |

**Rationale.**
- **AU-10** (Non-repudiation) requires that the system generate, protect, and retain
  information sufficient to uniquely bind an action to the individual who performed it.
  Unsigned Git commits carry no cryptographic guarantee that the `author` and `committer`
  fields are authentic — any name and email can be spoofed.
- Requiring signed commits on `main` ensures that every commit carries a verifiable
  cryptographic signature that links it to a known identity (GPG key, SSH signing key,
  or Sigstore gitsign token).
- **IA-5** requires that authenticators (here: signing keys) are managed with appropriate
  controls. Contributors must generate and protect their signing keys and register them
  with GitHub.
- See §3 (Commit Signing) for accepted signing methods.

### 2.6 No Force-Pushes, No Deletions, Include Administrators

| Setting | Value |
|---|---|
| Allow force pushes | **Disabled** |
| Allow deletions | **Disabled** |
| Do not allow bypassing the above settings (enforce for administrators) | **Enabled** |

**Rationale.**
- Force-pushing `main` rewrites history and can destroy the audit trail. Combined with
  the signed-commit requirement, a force-push could silently remove signed evidence of
  a prior change, violating **AU-10** and **CM-3**.
- Deleting `main` would destroy the protected branch and all its rules.
- Applying these rules to administrators closes the privileged-account bypass vector.
  An administrator bypassing branch protection is indistinguishable from an attacker
  who has compromised an administrator account.

---

## 3. Commit Signing

All commits merged to `main` must be cryptographically signed. Three methods are accepted,
in order of preference for this project:

### 3.1 Sigstore gitsign (preferred)

[gitsign](https://github.com/sigstore/gitsign) signs commits via the Sigstore keyless flow,
using an OIDC identity (GitHub Actions OIDC, Google, Microsoft, etc.) as the signing
credential. No long-lived key material to manage.

```sh
# Install gitsign and configure git
brew install sigstore/tap/gitsign          # macOS
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
git config --global commit.gpgsign true
```

This is consistent with the project's existing **keyless supply-chain posture**: the
`release.yml` workflow signs container images and SLSA provenance attestations via
`cosign` / Sigstore OIDC. Using gitsign for commit signing completes the keyless chain
from source commit through to published artifact.

### 3.2 SSH signing key

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Register the same public key in GitHub → Settings → SSH and GPG keys → **Signing keys**.

### 3.3 GPG signing key

```sh
gpg --full-generate-key    # RSA 4096 or Ed25519
git config --global user.signingkey <KEY-ID>
git config --global commit.gpgsign true
```

Register the public key in GitHub → Settings → SSH and GPG keys → **GPG keys**.

### 3.4 Verification

GitHub marks commits with a **Verified** badge when the signature validates against a key
registered to the committing GitHub account. The `require signed commits` branch protection
rule blocks a merge if any commit in the PR branch is unverified.

The existing `release.yml` cosign/SLSA provenance chain (implemented in P6, commit
`6ca189f`) provides artifact-level signing downstream of the commit. Commit signing via
this policy closes the remaining upstream gap in the chain of custody.

---

## 4. Summary Table

| Requirement | Setting | Controls |
|---|---|---|
| No direct pushes to `main` | Require PR | CM-3, SA-15, SSDF PO.3 |
| At least one CODEOWNER approval | Require CODEOWNER review | CM-3, SA-15 |
| Approval invalidated by new commits | Dismiss stale reviews | CM-3, AU-10 |
| All CI checks pass | Required status checks (see §2.3) | CM-3, SA-15, SLSA L3 |
| Branch up to date before merge | Require up-to-date branch | CM-3 |
| Clean attributable history | Require linear history | AU-10 |
| Cryptographic author attribution | Require signed commits | AU-10, IA-5 |
| No history rewriting | Disable force-push | AU-10, CM-3 |
| Branch cannot be deleted | Disable deletions | AU-10, CM-3 |
| No admin bypass | Enforce for administrators | CM-3, AU-10 |

---

## 5. Enabling the Configuration

The machine-readable desired state is encoded in [`.github/settings.yml`](../../.github/settings.yml)
for use with the [Probot Settings app](https://github.com/apps/settings). To apply manually:

1. Navigate to **GitHub → \<org\>/kube-policies → Settings → Branches**.
2. Add a branch protection rule for the pattern `main`.
3. Enable each setting in §2 above.
4. Add the required status checks in §2.3 by exact name (the check names must already exist
   in the repository's check history for GitHub to accept them).

---

## 6. Annual Review

This policy is reviewed and updated at least annually, or when:

- The set of required CI checks changes (new workflow or job rename).
- The signing toolchain changes (e.g. migration from GPG to gitsign).
- A new contributor joins and needs signing key onboarding.
- A security incident or tabletop exercise identifies a gap in branch controls.

The last review was **2026-06-02**. The next review is **2027-06-02**.
