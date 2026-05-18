// Frame-deterministic test pattern: vi.hoisted exposes a mutable `frame`
// variable that the remotion mock reads on every useCurrentFrame() call,
// so a single test file can assert behavior at frames 0, 75, 150 etc.
// without remounting the test environment.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { createElement, type ImgHTMLAttributes } from 'react';

const { frameRef } = vi.hoisted(() => ({ frameRef: { value: 0 } }));
vi.mock('remotion', async () => {
  const actual = await vi.importActual<typeof import('remotion')>('remotion');
  return {
    ...actual,
    useCurrentFrame: () => frameRef.value,
    Img: (props: ImgHTMLAttributes<HTMLImageElement>) => createElement('img', props),
  };
});

import { ScreenshotPanel } from '../ScreenshotPanel';

afterEach(() => {
  cleanup();
});

const getImgStyle = (container: Element): CSSStyleDeclaration => {
  const img = container.querySelector(
    '[data-testid="screenshot-panel-img"]',
  ) as HTMLElement;
  return img.style;
};

const parseScale = (transform: string): number => {
  const m = transform.match(/scale\(([^)]+)\)/);
  return m ? parseFloat(m[1]) : NaN;
};

describe('ScreenshotPanel — no crop/zoom (legacy behavior)', () => {
  it('T1: inner Img has objectFit contain and width 100%', () => {
    frameRef.value = 0;
    const { container } = render(
      <ScreenshotPanel src="/test.png" />,
    );
    const style = getImgStyle(container);
    expect(style.objectFit).toBe('contain');
    expect(style.width).toBe('100%');
    expect(style.height).toBe('100%');
  });
});

describe('ScreenshotPanel — crop positioning', () => {
  it('T2: crop={x:0.1,y:0.2,width:0.4,height:0.3} produces correct dimensions', () => {
    frameRef.value = 0;
    const { container } = render(
      <ScreenshotPanel
        src="/test.png"
        crop={{ x: 0.1, y: 0.2, width: 0.4, height: 0.3 }}
      />,
    );
    const style = getImgStyle(container);
    // width = (1/0.4)*100 = 250%
    expect(style.width).toMatch(/^250(\.0+)?%$/);
    // height = (1/0.3)*100 ≈ 333.33%
    const h = parseFloat(style.height);
    expect(h).toBeGreaterThan(333);
    expect(h).toBeLessThan(334);
    // left = -(0.1/0.4)*100 = -25%
    expect(style.left).toMatch(/^-25(\.0+)?%$/);
    // top = -(0.2/0.3)*100 ≈ -66.67%
    const t = parseFloat(style.top);
    expect(t).toBeLessThan(-66);
    expect(t).toBeGreaterThan(-68);
  });
});

describe('ScreenshotPanel — zoom scale', () => {
  it('T3: crop+zoom at frame 75 → scale in [1.03, 1.08] (bezier mid-ramp)', () => {
    frameRef.value = 75;
    const { container } = render(
      <ScreenshotPanel
        src="/test.png"
        crop={{ x: 0, y: 0, width: 1, height: 1 }}
        zoom={{ from: 1.0, to: 1.08, fromFrame: 0, toFrame: 150 }}
      />,
    );
    const scale = parseScale(getImgStyle(container).transform);
    expect(scale).toBeGreaterThanOrEqual(1.03);
    expect(scale).toBeLessThanOrEqual(1.08);
  });

  it('T4: scale is exactly 1.00 at frame 0 and exactly 1.08 at frame 150', () => {
    frameRef.value = 0;
    const { container: c0 } = render(
      <ScreenshotPanel
        src="/test.png"
        crop={{ x: 0, y: 0, width: 1, height: 1 }}
        zoom={{ from: 1.0, to: 1.08, fromFrame: 0, toFrame: 150 }}
      />,
    );
    expect(parseScale(getImgStyle(c0).transform)).toBeCloseTo(1.0, 5);
    cleanup();

    frameRef.value = 150;
    const { container: c150 } = render(
      <ScreenshotPanel
        src="/test.png"
        crop={{ x: 0, y: 0, width: 1, height: 1 }}
        zoom={{ from: 1.0, to: 1.08, fromFrame: 0, toFrame: 150 }}
      />,
    );
    expect(parseScale(getImgStyle(c150).transform)).toBeCloseTo(1.08, 5);
  });
});

describe('ScreenshotPanel — guard', () => {
  it('T5: crop with width=0 throws at render', () => {
    frameRef.value = 0;
    expect(() => {
      render(
        <ScreenshotPanel
          src="/test.png"
          crop={{ x: 0, y: 0, width: 0, height: 1 }}
        />,
      );
    }).toThrow();
  });
});
