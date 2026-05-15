<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# docker

## Purpose
Dockerfiles for the two service images. Built by `make docker-build-admission-webhook` and `make docker-build-policy-manager` from the repo root.

## Key Files

| File | Description |
|------|-------------|
| `admission-webhook.Dockerfile` | Multi-stage build that compiles `cmd/admission-webhook` and ships the binary in a minimal runtime image |
| `policy-manager.Dockerfile` | Multi-stage build that compiles `cmd/policy-manager` and ships the binary in a minimal runtime image |

## For AI Agents

### Working In This Directory
- Build context is the repo root, not this directory. Use `COPY . .` patterns aware of `.dockerignore`.
- Build args `VERSION`, `COMMIT`, `DATE` are wired through `-ldflags` in the Makefile to populate `main.version`, `main.commit`, `main.date`. Keep variables consistent if renaming.
- Prefer distroless or scratch-style runtime images for security; do not introduce a shell unless required. The TLS webhook needs CA certs available at runtime.

### Testing Requirements
- Run `docker run --rm <image> --help` after build to verify the entrypoint and flag wiring.

## Dependencies

### External
- Docker / BuildKit

<!-- MANUAL: -->
