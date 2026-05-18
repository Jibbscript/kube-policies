# demo/remotion — composition agent guide

This directory contains the Remotion composition for the kube-policies 60s
demo video. The plan source of truth lives at
`.omc/plans/kube-policies-demo-video.md` (§5.2 + §4). Read the parent
`../AGENTS.md` first for the two-pipeline split and the `manifest.json`
contract.

## Composition shape

* **Root**: `src/Root.tsx` registers a single `<Composition id="KubePoliciesDemo" />`
  at 1920×1080, 30 fps, **1800 frames** (60.0 s exactly).
* **Top-level composition**: `src/KubePoliciesDemo.tsx` — six `<Sequence>`
  children, one per beat (Title, Pitch, Deny, Exception, DashboardGlimpse,
  Closing). Frame budget reconciles to 120 + 180 + 420 + 480 + 420 + 180 = 1800.
* **Scenes**: `src/scenes/{Title,Pitch,Deny,Exception,DashboardGlimpse,Closing}.tsx`.
* **Shared primitives**: `src/components/{TerminalReplay,AuditPane,ScreenshotPanel,Caption,Logo}.tsx`.
* **Theme tokens**: `src/theme.ts` — `bg`, `fg`, `accent`, `danger`, `ok`, `mute`.

## Hard constraints

1. **No CSS animations, no Tailwind animate-\* classes.** All animation is
   driven by `useCurrentFrame()` + `interpolate()` + `Easing.bezier(0.16, 1, 0.3, 1)`
   per the `remotion-best-practices` skill. CSS keyframes do not advance in
   Remotion's frame-by-frame renderer.
2. **Two brand colors max per scene.** `theme.bg` plus one of
   `{accent, danger, ok, mute}`. `theme.fg` for body text is always available.
   The `Exception` scene legitimately uses `accent` for the `suppressed_by`
   syntax highlight; the rest of the pane stays on `fg`.
3. **Fonts** must come from `@remotion/google-fonts/Inter` at weights 400 + 700
   only. Monospace fallback chain is the system stack —
   `"JetBrains Mono", "Fira Code", "Menlo", "Consolas", monospace` — because
   shipping a self-hosted monospace family is out of scope.
4. **Assets are referenced via `staticFile()`**, never imported. The capture
   pipeline (W3) writes `public/terminals/`, `public/audit/`,
   `public/screenshots/`. The Remotion scenes assume those paths exist at
   render time; missing assets fall the composition through `delayRender` →
   `continueRender(null)` so a render fails rather than silently rendering
   blank panes.

## Manifest contract

`public/manifest.json` is the capture-pipeline output. The schema is in
`public/manifest.schema.json` (JSON Schema draft-07). Required fields:
`anchor_commit`, `captured_at`, `screenshots`, `terminals`, `audit`,
`masks_applied`. Every asset referenced by a scene must appear in the manifest
with a sha256 so `demo/verify/verify.sh` can prove the composition is
rendering the asset it was authored against.

## Logo

`public/brand/logo.svg` is the wordmark. `src/components/Logo.tsx` loads it
via `staticFile('brand/logo.svg')`. An inline-SVG fallback is gated behind
the `forceFallback` prop (OQ-D-2) for environments where the asset is
unavailable; the fallback's contrast was chosen to remain legible on both
`theme.bg` (#0B1220) and a transparent backdrop.

## Testing

Unit tests live in `src/components/__tests__/`. They mock
`Remotion.useCurrentFrame` with `vi.spyOn` to drive frame-deterministic
assertions. Run from this directory:

```
npm test            # vitest run
```

The Remotion render itself is **not** exercised by Vitest; full-render
correctness is W4's job (`demo/verify/`).

## Scope discipline

* Do **not** run `npx remotion render` from this directory until W4 wires up
  capture; rendering against missing assets produces undefined output.
* Do **not** touch `scripts/test/test-kind.sh` or the root `Makefile`
  (W1 owns).
* Do **not** modify `demo/capture/` (W3 owns).

Cited parent: `../AGENTS.md`.

5. **Render-time synthesized content must carry `data-synthetic="true"` and
   the synthesizing component must export a `SYNTHETIC_ROWS` (or analogous
   `SYNTHETIC_*`) const enumerating every fabricated row's `id`, `intent`,
   and provenance basis. A Vitest invariant must assert that
   `SYNTHETIC_ROWS.length === document.querySelectorAll('[data-synthetic="true"]').length`
   for every component that renders synthetic content. Synthetic content
   without this triad MUST NOT ship.**

   Rationale: the capture pipeline already enforces a parallel contract for
   capture-time DOM masks (`demo/AGENTS.md:43–58`); render-time synthesis needs
   the symmetric guardrail or it becomes an untracked source of visual lies.
   See `src/components/LiveDecisionsPane.tsx` (SYNTHETIC_ROWS export) and
   `src/scenes/__tests__/DashboardGlimpse.test.tsx` (AC-DG-7 invariant) for
   the reference implementation.
