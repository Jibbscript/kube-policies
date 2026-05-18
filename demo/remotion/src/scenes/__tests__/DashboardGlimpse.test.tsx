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

import { DashboardGlimpse } from '../DashboardGlimpse';
import { SYNTHETIC_ROWS } from '../../components/LiveDecisionsPane';

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

describe('DashboardGlimpse — synthesis invariant (AC-DG-7)', () => {
  it('T6: [data-synthetic="true"] count equals SYNTHETIC_ROWS.length at representative frames', () => {
    for (const frame of [0, 60, 150, 200, 264, 350, 419]) {
      frameRef.value = frame;
      const { container } = render(<DashboardGlimpse />);
      const syntheticEls = container.querySelectorAll('[data-synthetic="true"]');
      expect(syntheticEls.length).toBe(SYNTHETIC_ROWS.length);
      cleanup();
    }
  });
});
