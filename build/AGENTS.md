<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# build

## Purpose
Container build assets. Currently houses the two Dockerfiles consumed by `make docker-build` for producing the admission-webhook and policy-manager images.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `docker/` | Dockerfiles for `admission-webhook` and `policy-manager` (see `docker/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- `make docker-build` invokes both Dockerfiles, tagging with `$REGISTRY/$IMAGE:$VERSION` and `:latest`. Build args `VERSION`, `COMMIT`, `DATE` flow into Go ldflags.
- Keep build context at the repo root; the Dockerfiles `COPY` the entire module to perform `go build`.

### Testing Requirements
- Build images locally and validate with `docker run --rm <image> --help` before pushing.

## Dependencies

### External
- Docker / BuildKit
- Distroless or minimal base images (chosen by the Dockerfiles) for runtime

<!-- MANUAL: -->
