# Build & CI Integrity (Phase P1)

This document records the toolchain-trust controls established in phase P1 so that
every downstream quality and supply-chain gate runs against the real artifacts.
It supports NIST SR-3/SR-4, CM-2, SA-15, and SLSA build-integrity expectations.

## Go toolchain

- CI (`ci.yml`) and the release pipeline (`release.yml`) build and test on **Go 1.25
  only**, matching the `go 1.25.0` directive in `go.mod` and the `golang:1.25-alpine`
  build image. No end-of-life Go (1.20/1.21) remains in any matrix.
- `GOTOOLCHAIN: local` prevents the toolchain from silently auto-upgrading.
- `GOFLAGS: -mod=readonly` (CI env and the `Makefile`) forbids implicit `go.mod`
  edits during builds.
- The `lint` job runs `go mod verify` and `go mod tidy` + `git diff --exit-code`,
  failing the build on module-integrity or `go.sum` drift.

## GitHub Actions pinning

- **Every** third-party action `uses:` reference is pinned to a 40-character commit
  SHA with a trailing human-readable version comment (e.g. `# v4`). No `@master`,
  `@main`, `@latest`, or bare `@vN` remain on third-party actions.
- The archived `securecodewarrior/github-action-gosec` action was replaced with the
  maintained `securego/gosec`; `github/codeql-action` was moved from the deprecated
  v2 to v3.
- To refresh a pin: resolve the new SHA with
  `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha` and update the `uses:` line,
  keeping the version comment. Dependabot/Renovate automation for `github-actions`
  is added in phase P6.

## Workflow permissions

- All workflows declare an explicit least-privilege top-level
  `permissions: { contents: read }` block. Jobs elevate only as needed:
  `packages: write` (image push), `security-events: write` (SARIF upload),
  `contents: write` (release creation), and `id-token: write` on the release
  signing job (required for keyless cosign — implemented in phase P6).

## Container base images

- All non-`scratch` `FROM` lines in `build/docker/*.Dockerfile` and
  `build/Dockerfile.dashboard` are pinned by `@sha256:` digest (multi-arch image
  index) while retaining the readable tag.
- Regenerate digests with `scripts/pin-base-images.sh --write` (uses the registry
  HTTP API; no Docker/crane required).

## Reproducibility

- Go builds use `-trimpath`, `-buildid=`, and `-s -w` (via `GOFLAGS` and `LDFLAGS`
  in the `Makefile`) and `CGO_ENABLED=0` in the Dockerfiles, reducing build
  nondeterminism. Full bit-for-bit reproducibility (e.g. `SOURCE_DATE_EPOCH`
  normalization of build dates) is tracked for phase P6.

## Missing-config fixes

- Added `.github/ct.yaml` (Helm chart-testing) and `.github/mlc_config.json`
  (markdown link checking) so the `helm-tests` and `docs-tests` jobs are runnable
  rather than referencing absent config.
