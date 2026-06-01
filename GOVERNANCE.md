# Governance

This document describes how Kube-Policies is governed: who makes decisions,
how changes are authorised, and how security-sensitive work is separated from
the people who propose it.

> **Honest status.** Kube-Policies is a pre-1.0 Proof-of-Concept with a
> single maintainer. The model described here is lightweight but deliberately
> auditable, so that change history can be inspected for FedRAMP/NIST
> compliance evidence. It will grow as the project grows.

---

## Roles

### Contributor

Anyone who opens an issue, submits a pull request, or participates in
discussions. No formal appointment required. Contributors are expected to
follow the [Code of Conduct](CODE_OF_CONDUCT.md).

### Reviewer

A contributor who is trusted to give substantive technical review on pull
requests. Reviewers are identified informally (by mention in a PR) until the
project establishes a formal reviewer list. Reviewers do not have merge
permission.

### Maintainer

A maintainer has repository write access and can merge pull requests. The
current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).
Maintainers are responsible for:

- Reviewing and merging pull requests in a timely way
- Triaging issues and enforcing the Code of Conduct
- Owning the release process and signing off releases
- Maintaining the [SECURITY.md](SECURITY.md) disclosure policy and POA&M
- Authorising changes to security-sensitive paths (see below)

---

## Decision-making model

For a pre-1.0 single-maintainer project the decision process is simple:

| Change type | Who decides | Merge requirement |
|---|---|---|
| Bug fixes, dependency bumps, documentation | Any maintainer | 1 maintainer approval + CI green |
| New features, API changes | Any maintainer after brief design note in the issue | 1 maintainer approval + CI green |
| Breaking changes | Maintainer consensus (all active maintainers) | All active maintainers approve |
| Security-sensitive changes (see below) | Maintainer who is **not** the author | Separation-of-duties rule applies (see below) |
| Governance or policy changes (this file, SECURITY.md, MAINTAINERS.md, CODE_OF_CONDUCT.md) | All active maintainers | All active maintainers approve |

When there is only one active maintainer (the current state), security-sensitive
changes must still go through a pull request — the maintainer cannot merge their
own security-sensitive PRs without a documented justification recorded in the PR
description (explaining why no second reviewer is available). This creates an
auditable paper trail even in the absence of a second person.

---

## Change-authorization process

All changes land via pull request against `main`. Direct pushes to `main` are
not permitted (enforced by branch-protection rules — to be enabled before
assessment; tracked in the POA&M).

Pull request requirements:

1. All CI checks must pass (lint, test, security scan).
2. The [pull request template](.github/pull_request_template.md) must be
   completed, including the security-impact checklist.
3. At least one approving review from a maintainer who is not the PR author
   (separation of duties — see below).
4. No unresolved blocking comments.

For changes to paths listed in [CODEOWNERS](.github/CODEOWNERS), GitHub
automatically requests review from the designated owners.

---

## Separation of duties for security-sensitive changes

The following change categories are **security-sensitive** and require review
by a maintainer who is **not** the author of the change (NIST AC-5, AC-6, CM-3):

- Changes to CI/CD pipeline files (`.github/workflows/**`)
- Changes to release or signing scripts (`scripts/**`, `build/docker/**`)
- Changes to Helm charts (`charts/**`) — policy logic shipped to clusters
- Changes to compliance documentation (`docs/compliance/**`, `docs/security/**`)
- Changes to `SECURITY.md`, `.trivyignore`, `.github/dependabot.yml`
- Changes to this file (`GOVERNANCE.md`), `MAINTAINERS.md`, or `CODE_OF_CONDUCT.md`
- Changes to `internal/**` packages

If the project currently has only one available maintainer, the exception
procedure is: the maintainer records in the PR body that no second reviewer is
available, notes the business reason, and merges. The PR and the recorded
justification serve as the audit evidence for AC-5/CM-3 controls. This
exception is tracked in the POA&M and must be resolved before assessment by
adding at least one additional maintainer or external reviewer.

---

## Becoming a maintainer

To be nominated as a maintainer:

1. Sustained, quality contributions over at least 3 months (code, reviews, docs,
   or security/compliance work).
2. Demonstrated understanding of the project's security and compliance goals.
3. Nomination by an existing maintainer in a GitHub issue or discussion.
4. Approval by all active maintainers (lazy consensus — no objection within 7
   days counts as approval).
5. Addition to [MAINTAINERS.md](MAINTAINERS.md) via a pull request that
   follows the security-sensitive change process above.

---

## Emeritus and removal

A maintainer who is no longer active may be moved to emeritus status:

- **Voluntary:** a maintainer may step down at any time by opening a PR to
  update [MAINTAINERS.md](MAINTAINERS.md).
- **Involuntary:** after 6 months of inactivity with no response to direct
  contact, the remaining maintainers may vote to move the inactive maintainer
  to emeritus.
- **Removal for cause:** a maintainer who violates the Code of Conduct or
  acts against the project's interests may be removed by a vote of all other
  active maintainers.

Emeritus maintainers retain their historical contributions in git and are
acknowledged in MAINTAINERS.md but do not have write access or merge
authority.

---

## Amendments

Changes to this document follow the governance change process in the
decision-making table above: all active maintainers must approve, and the
change must be made via pull request.
