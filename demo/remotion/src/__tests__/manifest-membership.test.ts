// Manifest-membership guardrail (US-7 of dashboard-500-fix).
//
// The capture pipeline used to emit duplicate PNG variants
// (`dashboard-livedecisions-deny.png`, `dashboard-livedecisions-full.png`,
// `dashboard-metrics-full.png`, `dashboard-metrics-suppressions.png`,
// `dashboard-exceptions-list.png`) that were not referenced in
// `manifest.json`. They lingered on disk after subsequent capture iterations,
// expanding the unreferenced-PNG surface and inviting drift between the
// visible asset set and the provenance contract.
//
// This test asserts that every PNG in `demo/remotion/public/screenshots/`
// is referenced as a `screenshots/<name>.png` artifact in `manifest.json`.
// It fails when an unreferenced PNG is dropped into the directory, forcing
// the contributor to either delete it or add it to the manifest.

import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

interface ManifestArtifact {
  path: string;
  sha256: string;
  bytes: number;
}
interface Manifest {
  version: number;
  artifacts: ManifestArtifact[];
}

describe('manifest membership — screenshots/*.png are all referenced', () => {
  const publicDir = resolve(__dirname, '../../public');
  const screenshotsDir = resolve(publicDir, 'screenshots');
  const manifestPath = resolve(publicDir, 'manifest.json');

  const manifest: Manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
  const manifestPaths = new Set(manifest.artifacts.map((a) => a.path));

  const onDisk = readdirSync(screenshotsDir).filter((f) => f.endsWith('.png'));

  it('every PNG on disk has a manifest entry', () => {
    const unreferenced = onDisk.filter(
      (f) => !manifestPaths.has(`screenshots/${f}`),
    );
    expect(unreferenced, `unreferenced PNGs on disk: ${unreferenced.join(', ')}`).toEqual([]);
  });

  it('every screenshot artifact in the manifest exists on disk', () => {
    const screenshotArtifacts = manifest.artifacts
      .filter((a) => a.path.startsWith('screenshots/'))
      .map((a) => a.path.replace(/^screenshots\//, ''));
    const missing = screenshotArtifacts.filter((f) => !onDisk.includes(f));
    expect(missing, `manifest references missing files: ${missing.join(', ')}`).toEqual([]);
  });

  it('no stale capture variants ever reappear (regression guard for US-7)', () => {
    // These names are the historical leftovers from earlier capture
    // iterations. They should never reappear; if they do, capture.sh or
    // dashboard.spec.ts has regressed.
    const forbidden = [
      'dashboard-livedecisions-deny.png',
      'dashboard-livedecisions-full.png',
      'dashboard-metrics-full.png',
      'dashboard-metrics-suppressions.png',
      'dashboard-exceptions-list.png',
    ];
    const reappeared = forbidden.filter((f) => onDisk.includes(f));
    expect(reappeared, `stale capture variants reappeared: ${reappeared.join(', ')}`).toEqual([]);
  });
});
