# demo/verify — Verification Scripts

This directory contains the verification harness for the kube-policies demo
video. It implements **AC-1 through AC-17** from
`.omc/plans/kube-policies-demo-video.md` §7 and the test plan in §8.

> All scripts in this directory are READ-ONLY relative to the rest of the
> repository — they consume artifacts produced by `make demo-scaffold`,
> `make demo-capture`, and `make demo-render` and emit reports under
> `demo/dist/` (gitignored).

---

## Files

| File | Purpose | Anchors |
|---|---|---|
| `verify.sh` | Sequential AC-1..AC-17 runner; writes `demo/dist/verify-report.json`; fails fast on first AC failure. | §5.4, §7, §8.4 |
| `verify-frames.ts` | Extracts frames at `t∈{2.0,15.0,30.0,45.0,58.0}s` via `ffmpeg` and asserts mean-RGB conditions for AC-10 and AC-11. Pure-Node PNG decoder (no `sharp`/`canvas`). | §5.4, AC-10, AC-11 |
| `verify-fixtures.sh` | AC-16 diff-lint comparing `demo/capture/fixtures/*.yaml` to canonical `examples/policies/` or `examples/exceptions/`. Honors the waiver list in `demo/capture/AGENTS.md`. | §5.4, §6.4, AC-16 |
| `verify-schema.sh` | AC-13 schema-only comparison between two `public/` snapshots: filename-set equality + `file --mime-type` parity. Emits `demo/dist/pixel-diff.json` (trend-only, non-gating). | §5.4, §6.5, AC-13, I3-7 |
| `__tests__/verify-frames.test.ts` | Vitest unit tests for `meanRgb` and `withinTolerance` on synthetic in-memory PNGs. | §8.1 |

The integration smoke test `demo/capture/__tests__/capture-integration.sh`
lives in `demo/capture/` (W3 territory) but is exercised by AC review.

---

## AC mapping (cheat sheet)

| AC | Script (function) | Notes |
|----|-------------------|-------|
| AC-1 | `verify.sh::ac_01` | `npm ci --no-audit --no-fund` in `demo/remotion`. |
| AC-2 | `verify.sh::ac_02` | counts of `*.png`, `*.txt`, `*.json` in `public/`. |
| AC-3 | `verify.sh::ac_03` | width=1920 via `ffprobe` (per Critic C-2). |
| AC-4 | `verify.sh::ac_04` | `grep -F "Container must not run in privileged mode"`. |
| AC-5 | `verify.sh::ac_05` | `jq` on `suppressed_by` + terminal `pod/emergency-pod created`. |
| AC-6 | `verify.sh::ac_06` | mp4 existence. |
| AC-7 | `verify.sh::ac_07` | duration 60.0 ± 0.05s. |
| AC-8 | `verify.sh::ac_08` | `h264,1920,1080`. |
| AC-9 | `verify.sh::ac_09` | `wc -c <= 8388608` (per Critic C-3). |
| AC-10 | `verify-frames.ts::ac10` | left-half mean RGB within ±10 of `theme.bg=#0B1220`. |
| AC-11 | `verify-frames.ts::ac11` | caption-row green-channel dominance. |
| AC-12 | `verify.sh::ac_12` | `grep -F "PLACEHOLDER"` + `<video` in README diff preview. |
| AC-13 | `verify.sh::ac_13` → `verify-schema.sh` | schema-only; pixel-diff informational. |
| AC-14 | `verify.sh::ac_14` | four `AGENTS.md` files exist. |
| AC-15 | `verify.sh::ac_15` | positive-match `case` against permitted paths (per Architect A4). |
| AC-16 | `verify.sh::ac_16` → `verify-fixtures.sh` | fixture drift lint with waiver list. |
| AC-17 | `verify.sh::ac_17` | `capture-log.json` duration ≤ 600 000 ms. |

---

## `informational_pixel_diff` (Iter-3 I3-7)

`verify-schema.sh` produces `demo/dist/pixel-diff.json` whenever ImageMagick
`compare` is on `PATH`. The numbers are **trend-only**, never gating:

- A single run's `entries` map should NOT be interpreted as a regression
  signal in isolation.
- The intended use is to plot values across a **rolling window of ≥ 3 prior
  runs** and only flag a regression when the current run sits outside the
  observed envelope.
- This is the documented mitigation for the sparkline non-determinism
  (Pre-mortem Scenario E in §6.5).
- When `compare` is absent, `verify-schema.sh` writes a stub
  `pixel-diff.json` explaining the skip. This is **not** a verification
  failure — see AC-13's "ImageMagick missing = warning" clause.

---

## Running locally

```bash
# After demo-scaffold + demo-capture + demo-render have all completed:
make demo-verify

# Equivalent direct invocation:
bash demo/verify/verify.sh

# Frame-only spot check (faster iteration during scene tuning):
node demo/verify/verify-frames.ts --all
# or:
npx tsx demo/verify/verify-frames.ts --all

# Frame helpers unit tests:
cd demo/remotion && npx vitest run ../verify/__tests__/verify-frames.test.ts
```

---

## Report format

`demo/dist/verify-report.json`:

```json
{
  "total": 17,
  "passed": 17,
  "failed": 0,
  "results": [
    {"ac_id": "AC-1", "status": "passed", "evidence": "npm ci clean; ..."},
    {"ac_id": "AC-2", "status": "passed", "evidence": "screenshots=5 ..."}
  ],
  "informational_pixel_diff": {
    "note": "trend-only per plan §8.4 / Iter-3 I3-7; non-gating",
    "entries": { "screenshots/scene-1.png": 0 }
  }
}
```

On the first failure the script exits 1; `passed + failed < 17` and the
failed `results` entry carries the captured `evidence` (stderr or jq/grep
output).

---

## Maintenance contract

When acceptance criteria change in the plan:

1. Edit the matching `ac_NN` function in `verify.sh` to mirror §7's exact
   shell command. Do not paraphrase — copy.
2. Update this AGENTS.md AC-mapping table.
3. Add a regression unit test under `__tests__/` if the change introduces
   non-trivial parsing.
4. Append a note to `.omc/notepads/kube-policies-demo-video/`.
