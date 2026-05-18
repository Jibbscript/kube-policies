import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { ansiToRuns, sliceRuns, TerminalReplay } from '../TerminalReplay';
import { theme } from '../../theme';

let currentFrame = 0;

vi.mock('remotion', () => ({
  useCurrentFrame: () => currentFrame,
  delayRender: () => -1,
  continueRender: () => undefined,
}));

afterEach(() => {
  cleanup();
});

const renderAtFrame = (frame: number, text: string) => {
  currentFrame = frame;
  return render(<TerminalReplay src="ignored" textOverride={text} />);
};

describe('ansiToRuns', () => {
  it('returns a single fg-colored run for plain text', () => {
    const runs = ansiToRuns('hello world');
    expect(runs).toHaveLength(1);
    expect(runs[0].text).toBe('hello world');
    expect(runs[0].color).toBe(theme.fg);
  });

  it('maps \\x1b[31m → theme.danger and \\x1b[0m → theme.fg', () => {
    const runs = ansiToRuns('ok \x1b[31mERR\x1b[0m end');
    expect(runs.map((r) => r.text)).toEqual(['ok ', 'ERR', ' end']);
    expect(runs.map((r) => r.color)).toEqual([
      theme.fg,
      theme.danger,
      theme.fg,
    ]);
  });

  it('maps \\x1b[32m → theme.ok', () => {
    const runs = ansiToRuns('\x1b[32mPASS\x1b[0m');
    expect(runs).toHaveLength(1);
    expect(runs[0].text).toBe('PASS');
    expect(runs[0].color).toBe(theme.ok);
  });
});

describe('sliceRuns', () => {
  it('returns empty array for 0 chars', () => {
    const runs = ansiToRuns('abcdef');
    expect(sliceRuns(runs, 0)).toEqual([]);
  });

  it('slices across run boundaries', () => {
    const runs = ansiToRuns('abc\x1b[31mDEF\x1b[0m');
    const out = sliceRuns(runs, 4);
    expect(out.map((r) => r.text).join('')).toBe('abcD');
  });
});

describe('TerminalReplay rendering', () => {
  it('renders empty visible text at frame 0', () => {
    const { container } = renderAtFrame(0, 'hello');
    const pane = container.querySelector('[data-testid="terminal-replay"]');
    expect(pane).not.toBeNull();
    expect(pane?.textContent ?? '').toBe('');
  });

  it('reveals exactly 2 chars at frame 1 (0.5 frames/char default)', () => {
    const { container } = renderAtFrame(1, 'abcdef');
    const pane = container.querySelector('[data-testid="terminal-replay"]');
    // floor(1 / 0.5) = 2
    expect(pane?.textContent).toBe('ab');
  });

  it('reveals 4 chars at frame 2', () => {
    const { container } = renderAtFrame(2, 'abcdef');
    const pane = container.querySelector('[data-testid="terminal-replay"]');
    expect(pane?.textContent).toBe('abcd');
  });

  it('reveals the full string when frame ≥ length / revealFramesPerChar', () => {
    const { container } = renderAtFrame(100, 'hello world');
    const pane = container.querySelector('[data-testid="terminal-replay"]');
    expect(pane?.textContent).toBe('hello world');
  });
});
