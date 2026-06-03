# Build Hardening (SUP-WU-18)

Controls: NIST SC-7, SR-3, CM-7(5) | SLSA L3 isolated build

This document describes the network-egress monitoring and secret-scoping
controls applied to the release pipeline jobs, and the SLSA L3 isolated-build
assumption that underpins the supply-chain trust model.

---

## StepSecurity harden-runner

The following `release.yml` jobs install
[StepSecurity harden-runner](https://github.com/step-security/harden-runner)
as their first step:

| Job | Purpose |
|-----|---------|
| `build-release` | Cross-platform binary builds |
| `build-images` | Container image builds and pushes |
| `generate-sbom` | SBOM generation against immutable image digests |
| `security-scan` | Trivy vulnerability scans |
| `sign-attest-provenance` | cosign signing, SBOM attestation, SLSA provenance |

The `validate-release`, `package-helm`, `create-release`, `update-helm-repo`,
and `notify` jobs do not currently include harden-runner.

### Current mode: audit

All five jobs are configured with:

```yaml
- name: Harden runner
  uses: step-security/harden-runner@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # v2
  with:
    egress-policy: audit
```

In `audit` mode, harden-runner logs all outbound network connections made by
the job but does not block any of them. This produces a traffic baseline that
reveals the minimal allowlist needed before the mode is flipped to `block`.

### Audit-to-block rollout

The intended rollout path is:

1. **Observe** — run several releases with `egress-policy: audit` and collect
   the logged destinations from the StepSecurity dashboard.
2. **Document the allowlist** — record each required destination (e.g.
   `ghcr.io`, `sigstore.dev`, `rekor.sigstore.dev`, `fulcio.sigstore.dev`,
   `proxy.golang.org`, `sum.golang.org`, `registry-1.docker.io`) as a named
   `allowed-endpoints` list in the harden-runner configuration.
3. **Flip to block** — change `egress-policy: audit` to `egress-policy: block`
   on each job, keeping only the documented allowlist. Any unlisted outbound
   connection will then fail the job rather than silently succeed.

The goal is to prevent a compromised action or malicious dependency from
exfiltrating secrets or build artifacts to an attacker-controlled host.

### Network allowlist concept

When `egress-policy: block` is active, harden-runner allows only destinations
listed in `allowed-endpoints`. For the signing job the list will include at
minimum:

- `ghcr.io:443` — container registry (image pull and push)
- `fulcio.sigstore.dev:443` — Fulcio CA (keyless certificate issuance)
- `rekor.sigstore.dev:443` — Rekor transparency log (signature recording)
- `tuf-repo-cdn.sigstore.dev:443` — Sigstore TUF root distribution
- `oauth2.sigstore.dev:443` — Sigstore OIDC exchange

Exact ports and hosts should be confirmed from the audit-mode logs before
enforcing.

---

## Secret scoping

Secrets are scoped to the jobs that consume them and are never made available
to unrelated jobs:

| Secret | Job(s) that receive it |
|--------|------------------------|
| `GITHUB_TOKEN` | `build-images` (registry push), `sign-attest-provenance` (registry push + attestation write) |
| `HELM_REPO_TOKEN` | `update-helm-repo` only |
| `SLACK_WEBHOOK` | `notify` only |

The `build-release`, `generate-sbom`, `security-scan`, `validate-release`, and
`create-release` jobs do not receive `HELM_REPO_TOKEN` or `SLACK_WEBHOOK`.
`GITHUB_TOKEN` is available to all jobs by default but is used with elevated
permissions (`packages: write`, `contents: write`, `id-token: write`) only in
the jobs that require it; all other jobs operate under the top-level
`permissions: { contents: read }` policy.

---

## SLSA L3 isolated-build assumption

The release pipeline meets the SLSA L3 build-isolation requirement through the
GitHub Actions ephemeral-runner model:

- Each job runs in a **fresh, ephemeral VM** that is provisioned at job start
  and torn down at job end. No state persists between jobs or between runs.
- The build environment is determined entirely by the workflow file and the
  pinned action SHAs it references (all third-party actions are pinned to a
  40-character commit SHA — see `docs/supply-chain/build-integrity.md`).
- The Go build is reproducible: `SOURCE_DATE_EPOCH` is derived from the commit
  timestamp (not wall-clock time), `-trimpath` strips machine paths,
  `CGO_ENABLED=0` removes host-C-toolchain variance, and `GOTOOLCHAIN: local`
  pins the compiler to the version in `go.mod`. See
  `scripts/verify-reproducible-build.sh` for the local verification procedure.
- Signing (`cosign sign`, `cosign attest`, `actions/attest-build-provenance`)
  runs in the `sign-attest-provenance` job, which is gated on `needs:
  security-scan`. A vulnerable image therefore cannot be signed, satisfying
  the SLSA requirement that provenance is only generated for builds that pass
  the defined quality/security gates.

The SLSA provenance documents the exact runner environment, the workflow ref,
the commit SHA, and the triggering event, providing an auditable record of the
build environment for each released artifact.

---

## Limitations and tracked gaps

- `egress-policy` is currently `audit`, not `block`. Until it is flipped to
  `block` with a complete allowlist, outbound exfiltration from a compromised
  build step is logged but not prevented.
- The `validate-release`, `package-helm`, `create-release`, `update-helm-repo`,
  and `notify` jobs do not yet include harden-runner. These jobs are lower-risk
  (no signing keys, no image pushes) but should be added in a follow-on phase.
- No published signed release exists yet; these controls are in place and ready
  to produce signed artifacts when the first tag is cut.
