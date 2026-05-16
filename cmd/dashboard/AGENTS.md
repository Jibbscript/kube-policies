<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# cmd/dashboard

## Purpose
Thin Go BFF binary for the Svelte demo dashboard. Serves the embedded SPA at `/`, reverse-proxies `/api/v1/*` to `policy-manager:8080`, aggregates Prometheus exposition from both upstream services into typed JSON at `/api/metrics/summary`, and exposes a poll-based decision feed (`/api/decisions/recent`, `/api/decisions/stream`, `/api/decisions/internal`).

## Why this binary exists
The repo is otherwise pure Go. Embedding the SPA into a single Go binary preserves the "one image per concern" pattern, keeps the demo same-origin (no CORS for the SPA), and lets the BFF enforce the two-flag write gate from one place. See `.omc/plans/svelte-dashboard.md` §3 (Option B) and §15 (ADR).

## Key Files

| File | Description |
|------|-------------|
| `main.go` | Gin server, CSP middleware, route wiring, graceful shutdown |
| `config.go` | Env-driven `Config` (no file IO) |
| `proxy.go` | `/api/v1/*` reverse proxy + verb gate (ALLOW_WRITES) |
| `metrics.go` | `/api/metrics/summary` — parses upstream `/metrics` via `expfmt` |
| `decisions.go` | Ring buffer + ingest/recent/stream handlers for the decision feed |
| `web_embed.go` | `//go:build !no_ui` — embeds `web_dist/` (populated by Makefile) |
| `web_stub.go` | `//go:build no_ui` — stub SPA handler for CI builds without UI assets |
| `web_dist/` | Build-time SPA assets. Populated by `make build-dashboard`; the `.placeholder` file keeps `//go:embed` valid before the first copy |
| `main_test.go` | HTTP-level tests: CSP header shape, healthz, ingest/recent round-trip, verb gate |

## Environment

| Var | Default | Purpose |
|-----|---------|---------|
| `POLICY_MANAGER_URL` | `http://policy-manager:8080` | Reverse-proxy upstream |
| `POLICY_MANAGER_METRICS_URL` | `http://policy-manager:9091/metrics` | Prometheus scrape for `/api/metrics/summary` |
| `ADMISSION_WEBHOOK_METRICS_URL` | `http://admission-webhook:9090/metrics` | Same, admission webhook side |
| `ALLOW_WRITES` | `false` | Verb gate on `/api/v1/*` — writes return 403 when unset |
| `INTERNAL_TOKEN` | (unset) | Bearer token for `POST /api/decisions/internal`. Empty → endpoint closed |
| `DASHBOARD_CSP_UNSAFE_INLINE_STYLE` | `false` | Re-enables `'unsafe-inline'` on CSP `style-src` if the SPA emits inline styles. M1 verdict: not needed (see `web/CSP_VERDICT.md`) |

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--port` | 8090 | HTTP API + SPA |
| `--metrics-port` | 9092 | Prometheus `/metrics` for this binary |

## Build modes

- Default: `go build ./cmd/dashboard` — embeds `cmd/dashboard/web_dist/` via `//go:embed`. The Makefile's `build-dashboard` target copies `web/dist/` into this subdir before invoking `go build`.
- No UI: `go build -tags=no_ui ./cmd/dashboard` — uses `web_stub.go` for the SPA route. Useful in CI when the SPA build has not yet run.

## Security posture
- CSP header on every response (strict by default; see `cspMiddleware` in `main.go`).
- Read-only by default; write verbs return 403 unless `ALLOW_WRITES=true` AND the operator has independently enabled the binary in Helm (`dashboard.enabled=true`). This is the two-flag gate from the plan §1.
- `/api/decisions/internal` is closed when `INTERNAL_TOKEN` is unset — an empty token is **not** a wildcard.
- No raw K8s manifests on the public decision feed; the `PublicEvent` DTO (mirrored from `internal/audit/public_event.go`) strips `UserInfo`, request IDs, and object bodies at the source.
