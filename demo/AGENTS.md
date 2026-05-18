<!-- Generated: 2026-05-17 | Updated: 2026-05-17 -->

# demo

## Purpose
60-second Remotion-rendered demo video (`demo/dist/kube-policies-demo.mp4`) plus a captured screenshot/terminal/audit bundle that proves real-time admission control, `PolicyException`-driven suppression, and the read-only Svelte dashboard on this branch. The bundle exists for the public-facing `README.md` (see `demo/README.patch.md`) and is regenerable end-to-end by any contributor with the prerequisite toolchain.

The plan at [`.omc/plans/kube-policies-demo-video.md`](../.omc/plans/kube-policies-demo-video.md) is the source of truth — every design decision, acceptance criterion, and capture-time invariant in this directory derives from it.

## Key Files

| File | Description |
|------|-------------|
| `AGENTS.md` | This file — orientation for AI agents and human contributors |
| `README.patch.md` | Staged README block (gated; applied only on explicit user approval per plan §5.5) |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `remotion/` | Remotion project (React + Vite). Composes scenes from assets under `remotion/public/`. Render output lands in `demo/dist/` (gitignored). |
| `capture/` | bash + Playwright capture pipeline. Writes screenshots, terminal text, and audit JSON into `remotion/public/`. Sources `scripts/test/lib.sh` for cluster lifecycle helpers. |
| `verify/` | Verification scripts that check the 17 acceptance criteria, extract frames, and emit `demo/dist/verify-report.json`. |

## Pipeline Architecture (two-pipeline split)

Per plan §1 Principle 1 ("Render is hermetic; capture is best-effort idempotent") the demo is split into two strictly separated pipelines with a single contract between them:

1. **Capture pipeline (`make demo-capture`).** Drives a local Kind cluster + the Helm-installed dashboard via Playwright + kubectl. Writes assets exclusively into `demo/remotion/public/`:
   - `terminals/*.txt` — captured kubectl stdout (verbatim engine messages, no hand-editing).
   - `screenshots/*.png` — dashboard and Grafana screenshots at viewport `1920×1080`, `deviceScaleFactor: 1`.
   - `audit/*.json` — captured audit-log events from the admission-webhook stdout backend.
   - `manifest.json` — the contract listing every asset, mask invocation, and timing offset.

2. **Render pipeline (`make demo-render`).** Pure Remotion. Reads from `demo/remotion/public/` only — never opens a network socket, never queries kubectl. Produces a byte-equivalent MP4 across re-renders given the same `public/` contents and Remotion version. Output: `demo/dist/kube-policies-demo.mp4`.

The render pipeline MUST NOT touch the cluster. The capture pipeline MUST NOT touch the rendered MP4. Cross-contamination breaks Principle 1.

### The `manifest.json` contract

`demo/remotion/public/manifest.json` (validated against `manifest.schema.json`) is the single asset-handoff contract between the two pipelines. The capture pipeline writes it; the render pipeline reads it. Every scene's asset paths, timing offsets, and applied masks are enumerated there so the render is fully determined by the manifest.

### Principle 4 — Capture-time mask audit trail

Per plan §1 Principle 4, capture-time DOM masking is permitted **only** under a named, logged, enumerated contract:

- **Named.** Every mask is a named function in `demo/capture/lib.sh` (e.g. `mask_relative_time_column`, `mask_sparkline_path`).
- **Logged.** Every mask invocation appends a record to `capture-log.json` with the shape:
  ```json
  {
    "mask_name": "mask_relative_time_column",
    "css_selector": "td[data-col=\"time\"]",
    "fixed_value": "00:00:00",
    "applied_at_url": "http://localhost:8090/livedecisions"
  }
  ```
- **Enumerated.** The full mask inventory lives in `demo/capture/AGENTS.md` so reviewers can audit what was masked without reading bash.

Hand-editing PNGs or text files under `remotion/public/` is forbidden because it silently desyncs the demo from the engine.

## Prerequisites

| Tool | Minimum version | Why |
|------|-----------------|-----|
| `kind` | ≥ 0.20 | Local Kubernetes cluster for the capture pipeline |
| `docker` | ≥ 24 | Container runtime for kind, image build, and the local registry |
| `node` | ≥ 20 | Remotion 4 + Playwright capture spec |
| `ffmpeg` | ≥ 6 | Frame extraction and MP4 mux (Remotion ships `ffmpeg-static`; system `ffmpeg` is used by `demo/verify/`) |
| `imagemagick` | ≥ 7 | `identify` + `compare` for the AC-13 informational pixel diff (recommended; non-gating) |
| `kubectl` | latest stable | Cluster automation |
| `helm` | latest stable | Chart install with `values-demo.yaml` |
| `jq` | ≥ 1.6 | Audit-log JSON predicate matching |

## Make targets

All six targets are alphabetised in `make help`:

| Target | Action |
|--------|--------|
| `make demo` | Full pipeline: `demo-scaffold` → `demo-capture` → `demo-render` → `demo-verify`. |
| `make demo-capture` | Runs `demo/capture/capture.sh`. Boots Kind, deploys via Helm, captures assets into `remotion/public/`. |
| `make demo-promote-golden` | Copies the current capture bundle into `demo/capture/golden/` as the new pixel-diff baseline. Run once after a green AC pass. |
| `make demo-render` | `npx remotion render` against the captured assets. Hermetic. Writes `demo/dist/kube-policies-demo.mp4`. |
| `make demo-scaffold` | `npm ci` inside `demo/remotion/`. Idempotent. |
| `make demo-verify` | Runs `demo/verify/verify.sh`. Checks AC-1..AC-17, emits `demo/dist/verify-report.json`. |

## For AI Agents

### Working In This Directory

- **Plan first.** Every non-trivial change here is anchored in `.omc/plans/kube-policies-demo-video.md`. Read the relevant section before editing; do not invent new beats or capture-time transforms.
- **Two-pipeline discipline.** Never let `demo/remotion/` code reach the cluster, and never let `demo/capture/` code reach `demo/dist/`. If you find yourself wanting to bridge them, you have probably found a `manifest.json` schema gap — extend the schema instead.
- **Capture-time masks are named functions.** If you need a new mask, add a `mask_*` function in `demo/capture/lib.sh`, document it in `demo/capture/AGENTS.md`, and ensure it logs to `capture-log.json` with the four-field record above.
- **Fixtures are linted against `examples/`.** Per plan §5.3 step 4, fixtures under `demo/capture/fixtures/` are diff-checked against the canonical examples — the one exception is `emergency-exception.yaml` (stale upstream, freshly authored here; waiver documented in `demo/capture/AGENTS.md`).

### Boundary Rules

- Source files outside `demo/`, `scripts/test/`, `Makefile`, `.gitignore`, and root `AGENTS.md` are off-limits to demo work (per plan AC-15).
- README integration is gated. `demo/README.patch.md` is the staged block; do not patch `README.md` itself without explicit user approval.

## Dependencies

### External
- **Remotion 4** — React-based video composer (`demo/remotion/package.json`).
- **Playwright** — already a `web/` dev dep; reused for dashboard + Grafana screenshots.
- **kind + helm + kubectl** — already required by `scripts/test/`.
- **ffmpeg, ImageMagick, jq** — host-system tools; not added to the Go module graph.

<!-- MANUAL: Custom project notes can be added below -->
