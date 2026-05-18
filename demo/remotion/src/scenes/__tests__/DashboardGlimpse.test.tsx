// Frame-deterministic test pattern: same vi.hoisted pattern as ScreenshotPanel.test.tsx.
// See that file's header for rationale.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, cleanup } from '@testing-library/react';

const { frameRef } = vi.hoisted(() => ({ frameRef: { value: 0 } }));
vi.mock('remotion', async () => {
  const actual = await vi.importActual<typeof import('remotion')>('remotion');
  return {
    ...actual,
    useCurrentFrame: () => frameRef.value,
    // Sequence calls useVideoConfig() internally which requires a <Composition> context.
    // Mock it to gate children purely on frameRef.value so tests work without the compositor.
    Sequence: ({
      from = 0,
      durationInFrames,
      children,
    }: {
      from?: number;
      durationInFrames?: number;
      children?: React.ReactNode;
      layout?: string;
    }) => {
      const frame = frameRef.value;
      const end = durationInFrames !== undefined ? from + durationInFrames : Infinity;
      if (frame < from || frame >= end) return null;
      return <>{children}</>;
    },
    Img: (props: React.ImgHTMLAttributes<HTMLImageElement>) => <img {...props} />,
  };
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  DashboardGlimpse,
  TILE_1_CROP,
  TILE_2_CROP,
  TILE_3_CROP,
} from '../DashboardGlimpse';

afterEach(() => {
  cleanup();
});

const getTileOpacity = (container: Element, testid: string): number => {
  const el = container.querySelector(
    `[data-testid="${testid}"]`,
  ) as HTMLElement | null;
  if (!el) return -1;
  return parseFloat(el.style.opacity ?? '0');
};

describe('DashboardGlimpse — tile visibility', () => {
  it('T1: at frame 60, Tile 1 opacity ≈ 1, Tile 2/3 opacity ≈ 0', () => {
    frameRef.value = 60;
    const { container } = render(<DashboardGlimpse />);
    expect(getTileOpacity(container, 'tile-1')).toBeCloseTo(1, 2);
    expect(getTileOpacity(container, 'tile-2')).toBeCloseTo(0, 2);
    expect(getTileOpacity(container, 'tile-3')).toBeCloseTo(0, 2);
  });

  it('T2: at frame 200, Tile 2 opacity ≈ 1, Tile 1/3 opacity ≈ 0', () => {
    frameRef.value = 200;
    const { container } = render(<DashboardGlimpse />);
    expect(getTileOpacity(container, 'tile-1')).toBeCloseTo(0, 2);
    expect(getTileOpacity(container, 'tile-2')).toBeCloseTo(1, 2);
    expect(getTileOpacity(container, 'tile-3')).toBeCloseTo(0, 2);
  });

  it('T3: at frame 350, Tile 3 opacity ≈ 1, Tile 1/2 opacity ≈ 0', () => {
    frameRef.value = 350;
    const { container } = render(<DashboardGlimpse />);
    expect(getTileOpacity(container, 'tile-1')).toBeCloseTo(0, 2);
    expect(getTileOpacity(container, 'tile-2')).toBeCloseTo(0, 2);
    expect(getTileOpacity(container, 'tile-3')).toBeCloseTo(1, 2);
  });
});

describe('DashboardGlimpse — caption content (AC-DG-4)', () => {
  it('T4a: at frame 60, caption headline is "Live decisions."', () => {
    frameRef.value = 60;
    const { container } = render(<DashboardGlimpse />);
    const headline = container.querySelector('[data-testid="caption-headline"]');
    expect(headline?.textContent).toBe('Live decisions.');
  });

  it('T4b: at frame 200, caption headline is "Read-only by default."', () => {
    frameRef.value = 200;
    const { container } = render(<DashboardGlimpse />);
    const headline = container.querySelector('[data-testid="caption-headline"]');
    expect(headline?.textContent).toBe('Read-only by default.');
  });

  it('T4c: at frame 350, caption headline is "Policy denies surface here."', () => {
    frameRef.value = 350;
    const { container } = render(<DashboardGlimpse />);
    const headline = container.querySelector('[data-testid="caption-headline"]');
    expect(headline?.textContent).toBe('Policy denies surface here.');
  });

  it('T5: caption-overlay is absolutely positioned at frame 200', () => {
    frameRef.value = 200;
    const { container } = render(<DashboardGlimpse />);
    const overlay = container.querySelector(
      '[data-testid="caption-overlay"]',
    ) as HTMLElement | null;
    expect(overlay).not.toBeNull();
    expect(overlay?.style.position).toBe('absolute');
  });
});

describe('DashboardGlimpse — manifest-anchored crop AC (AC-DG-CROP)', () => {
  // Verify-side AC: every ScreenshotPanel `crop={...}` in DashboardGlimpse
  // must be mirrored in manifest.json as `expected_content_region` for the
  // PNG it references. The PNG's sha256 is the anchor — when a dashboard
  // restyle changes the PNG bytes the sha256 changes, which forces an
  // explicit AC review of the crop geometry (no silent invalidation).
  type ManifestArtifact = {
    path: string;
    sha256: string;
    bytes: number;
    expected_content_region?: {
      x: number;
      y: number;
      width: number;
      height: number;
      description: string;
    };
  };
  type Manifest = { version: number; artifacts: ManifestArtifact[] };

  const manifestPath = resolve(__dirname, '../../../public/manifest.json');
  const manifest: Manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

  const findArtifact = (rel: string) => {
    const a = manifest.artifacts.find((x) => x.path === rel);
    if (!a) throw new Error(`manifest missing artifact: ${rel}`);
    return a;
  };

  const EPS = 0.001;
  const equalsCrop = (a: { x: number; y: number; width: number; height: number }, b: typeof a) =>
    Math.abs(a.x - b.x) < EPS &&
    Math.abs(a.y - b.y) < EPS &&
    Math.abs(a.width - b.width) < EPS &&
    Math.abs(a.height - b.height) < EPS;

  it('TILE_1_CROP matches manifest expected_content_region for dashboard-livedecisions.png', () => {
    const a = findArtifact('screenshots/dashboard-livedecisions.png');
    expect(a.expected_content_region).toBeDefined();
    expect(equalsCrop(TILE_1_CROP, a.expected_content_region!)).toBe(true);
    // sha256 anchor: forces the AC author to review crop when the PNG changes.
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('TILE_2_CROP matches manifest expected_content_region for dashboard-metrics.png', () => {
    const a = findArtifact('screenshots/dashboard-metrics.png');
    expect(a.expected_content_region).toBeDefined();
    expect(equalsCrop(TILE_2_CROP, a.expected_content_region!)).toBe(true);
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('TILE_3_CROP is recorded somewhere on the dashboard-livedecisions.png manifest entry', () => {
    // Tile 1 and Tile 3 both crop dashboard-livedecisions.png. The manifest
    // entry stores Tile 1's rect under expected_content_region; Tile 3's rect
    // is stored under expected_content_regions_extra[0] when present, so
    // both crops on the same PNG are auditable.
    const a = findArtifact('screenshots/dashboard-livedecisions.png') as ManifestArtifact & {
      expected_content_regions_extra?: Array<typeof TILE_3_CROP & { description: string }>;
    };
    const extra = a.expected_content_regions_extra ?? [];
    const match = extra.some((rect) =>
      equalsCrop(TILE_3_CROP, rect),
    );
    expect(match).toBe(true);
  });
});
