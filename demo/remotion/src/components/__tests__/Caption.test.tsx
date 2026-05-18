import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { Caption } from '../Caption';

let currentFrame = 0;

vi.mock('remotion', async () => {
  // Re-import the real Easing + interpolate; only useCurrentFrame is faked.
  const actual = await vi.importActual<typeof import('remotion')>('remotion');
  return {
    ...actual,
    useCurrentFrame: () => currentFrame,
  };
});

afterEach(() => {
  cleanup();
});

const renderAtFrame = (frame: number) => {
  currentFrame = frame;
  return render(<Caption headline="Hello" body="World" />);
};

const readOpacity = (el: Element | null): number => {
  if (!el) return -1;
  const raw = (el as HTMLElement).style.opacity;
  return parseFloat(raw);
};

describe('Caption opacity', () => {
  it('is 0 at frame 0', () => {
    const { container } = renderAtFrame(0);
    const caption = container.querySelector('[data-testid="caption"]');
    expect(readOpacity(caption)).toBeCloseTo(0, 5);
  });

  it('is 1 at frame 15 (default fadeFrames)', () => {
    const { container } = renderAtFrame(15);
    const caption = container.querySelector('[data-testid="caption"]');
    expect(readOpacity(caption)).toBeCloseTo(1, 5);
  });

  it('is 1 at frame 30 (past fadeFrames, clamped)', () => {
    const { container } = renderAtFrame(30);
    const caption = container.querySelector('[data-testid="caption"]');
    expect(readOpacity(caption)).toBeCloseTo(1, 5);
  });

  it('renders both headline and body', () => {
    const { container } = renderAtFrame(30);
    expect(
      container.querySelector('[data-testid="caption-headline"]')?.textContent,
    ).toBe('Hello');
    expect(
      container.querySelector('[data-testid="caption-body"]')?.textContent,
    ).toBe('World');
  });
});
