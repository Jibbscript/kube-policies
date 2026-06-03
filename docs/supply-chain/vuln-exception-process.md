# Vulnerability Exception Process (SUP-WU-10)

Controls: NIST RA-5, SI-2, SR-11

This document defines the time-boxed, justified exception process for
suppressing Trivy vulnerability findings in `.trivyignore`. It also describes
the monthly review cadence and how the gate integrates into the release
pipeline.

---

## How the gate works

Both `ci.yml` and `release.yml` (each in a `security-scan` job, "Trivy GATE"
steps) run Trivy with:

```
--severity CRITICAL,HIGH
--ignore-unfixed=true
--ignorefile .trivyignore
--exit-code 1
```

A fixable CRITICAL or HIGH finding that is **not** listed in `.trivyignore`
causes the job to exit 1 and fail the build or release. Unfixed findings
(no upstream patch available) are excluded from the gate via `--ignore-unfixed`;
they are still surfaced in the non-gating SARIF-upload pass and appear in the
GitHub Security tab.

The `sign-attest-provenance` job `needs: security-scan`, so a vulnerable image
can never be signed, attested, or published. The Trivy gate is therefore a
hard prerequisite for all supply-chain artifacts.

---

## Adding a suppression entry

A suppression in `.trivyignore` is a risk-acceptance decision and requires
explicit justification, ownership, a time-box, and a tracking reference. The
required fields are:

| Field | Description |
|-------|-------------|
| `OWNER` | Name or team responsible for monitoring this exception |
| `JUSTIFICATION` | Why the CVE is not exploitable or is accepted as residual risk |
| `ADDED` | ISO-8601 date the entry was added (`YYYY-MM-DD`) |
| `EXPIRES` | ISO-8601 date after which the entry must be re-justified or removed |
| `TRACKING` | Issue number or POA&M identifier (e.g. `POAM-123`) |

### Entry format

```
CVE-XXXX-NNNNN   # OWNER: <name/team> | JUSTIFICATION: <why not exploitable
                 # / why accepted> | ADDED: YYYY-MM-DD | EXPIRES: YYYY-MM-DD
                 # | TRACKING: <issue/POA&M id>
```

Example (illustrative; no active suppressions exist today):

```
# CVE-2024-00000   # OWNER: platform-sec | JUSTIFICATION: not reachable — the
#                  # affected codepath (foo.Bar) is never invoked by either
#                  # shipped binary | ADDED: 2026-06-01 | EXPIRES: 2026-09-01
#                  # | TRACKING: POAM-123
```

### Approval

A pull request that adds or modifies a `.trivyignore` entry requires:

1. A comment on the PR explaining the justification in full.
2. Approval from the security owner (the team or individual named in `OWNER`).
3. A linked tracking issue or POA&M entry.

Reviewers must confirm that `EXPIRES` is no more than 90 days from `ADDED`
for CRITICAL findings or 180 days for HIGH findings, unless a longer period
is formally documented in the POA&M.

---

## Monthly review cadence

On the first working day of each month:

1. Run `grep -n 'EXPIRES' .trivyignore` and compare each date against today.
2. For entries where `EXPIRES` has passed:
   - Check whether the upstream fix is now available. If yes, remove the entry
     and upgrade the dependency to take the fix.
   - If the CVE remains unfixed and the risk is still accepted, re-justify,
     update `ADDED` and `EXPIRES`, and obtain fresh approval.
3. Record the review outcome in the tracking issue or POA&M.

Trivy does **not** enforce the `EXPIRES` field automatically; the monthly
cadence is the human gate.

---

## Important constraints

- **No perpetual suppressions.** An undated or `EXPIRES: 9999-12-31` entry is
  not acceptable. Every suppression is a time-boxed risk acceptance.
- **`--ignore-unfixed` is not a wildcard.** It only skips CVEs with no
  available fix. Once a fix is published, that CVE becomes fixable and the
  gate will fail unless the dependency is patched or the CVE is explicitly
  added to `.trivyignore` with justification.
- **The SARIF-upload pass is always non-gating.** The separate `exit-code: 0`
  Trivy runs upload results to the GitHub Security tab regardless of any
  suppression, so the full finding set is always visible.
- **Currently no active suppressions.** The `.trivyignore` file is
  intentionally empty. A build must pass the gate with zero suppressions
  before a first signed release can be cut.
