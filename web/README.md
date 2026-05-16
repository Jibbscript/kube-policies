# kube-policies dashboard SPA

Svelte 5 (runes) + Vite 5 + TypeScript strict + Tailwind v4 (CSS-only) +
svelte-spa-router. Built with `pnpm` (lockfile committed).

## Commands

```bash
pnpm install                  # install pinned deps
pnpm dev                      # vite dev server on :5173 — proxies /api → :8091 (cmd/dashboard)
pnpm build                    # vite build → dist/, then bundle-report → ../.omc/research/bundle-size-m1.json
pnpm svelte-check             # type-check .ts and .svelte
pnpm lint                     # eslint
pnpm test --run               # vitest one-shot
pnpm test:e2e                 # playwright (requires `pnpm exec playwright install chromium` first)
```

`pnpm dev` expects `cmd/dashboard` running on :8091 — the Vite proxy targets it
so the BFF write-mode gate is active in dev (plan §4).

## Architecture

- Hash routing (`svelte-spa-router`). Routes live in `src/routes/`; components
  in `src/components/`; library code in `src/lib/`.
- `lib/api.ts` is the single fetch wrapper; same-origin (empty base URL).
- M1 ships poll-based live decisions (`getRecentDecisions` every 2 s). `sse.ts`
  is ready for M2 — flip the call in `LiveDecisions.svelte`.
- Write-mode is gated at build time by `VITE_ALLOW_WRITES` and at runtime by
  the BFF returning 403 on writes regardless.

## Tests

- Vitest unit tests under `tests/unit/`:
  - `api.test.ts` — assert `testPolicy` POSTs the right URL/body.
  - `sse.test.ts` — assert reconnect-with-backoff fires on EventSource errors.
  - `metrics-parser.test.ts` — assert `metricsToTiles` produces expected values.
- Playwright e2e under `tests/e2e/`:
  - `demo-60s.spec.ts` — Home → Playground → privileged sample → DENY badge.
  - `read-only.spec.ts` — write-mode buttons hidden, direct POST returns 403.
  - `mock-bff.ts` provides the network-layer mock fixture used by both specs.

The Playwright base URL can be overridden via `PLAYWRIGHT_BASE_URL` to point
at the embedded `cmd/dashboard` binary instead of Vite dev.

## CSP

Per plan §3 the CSP verdict is captured in `CSP_VERDICT.md` after the first
build, derived from inspecting `dist/index.html` for inline `<style>` tags.
