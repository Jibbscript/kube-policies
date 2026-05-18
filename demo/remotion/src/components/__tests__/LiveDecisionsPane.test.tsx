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
  };
});

import { LiveDecisionsPane, SYNTHETIC_ROWS } from '../LiveDecisionsPane';
import type { LiveDecisionRow } from '../LiveDecisionsPane';
import { theme } from '../../theme';

afterEach(() => {
  cleanup();
});

const hexToRgb = (hex: string): string => {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgb(${r}, ${g}, ${b})`;
};

const colorMatches = (actual: string, hex: string): boolean =>
  actual.toLowerCase() === hex.toLowerCase() ||
  actual.toLowerCase() === hexToRgb(hex).toLowerCase();

const SAMPLE_ROWS: LiveDecisionRow[] = [
  {
    id: 'allow001',
    namespace: 'default',
    name: 'allowed-pod',
    verdict: 'ALLOW',
    policy_id: 'security-baseline',
    rule_id: 'no-privileged-containers',
    timestamp_ms_ago: 3000,
    synthetic: false,
  },
  {
    id: 'deny002',
    namespace: 'ci',
    name: 'denied-pod',
    verdict: 'DENY',
    policy_id: 'security-baseline',
    rule_id: 'no-host-path-volumes',
    reason: 'hostPath denied',
    timestamp_ms_ago: 9000,
    synthetic: true,
  },
];

describe('LiveDecisionsPane — row rendering', () => {
  it('T1: renders one <tr> per row', () => {
    const { container } = render(
      <LiveDecisionsPane rows={SAMPLE_ROWS} />,
    );
    const rows = container.querySelectorAll('tbody tr');
    expect(rows.length).toBe(SAMPLE_ROWS.length);
  });

  it('T2: ALLOW verdict pill background matches theme.ok', () => {
    const { container } = render(
      <LiveDecisionsPane rows={[SAMPLE_ROWS[0]]} />,
    );
    const pill = container.querySelector('tbody tr td span') as HTMLElement;
    expect(pill).not.toBeNull();
    const bg = pill.style.background.toLowerCase();
    expect(
      bg === theme.ok.toLowerCase() || bg === 'rgb(52, 211, 153)',
    ).toBe(true);
  });

  it('T3: DENY verdict pill background matches theme.danger', () => {
    const { container } = render(
      <LiveDecisionsPane rows={[SAMPLE_ROWS[1]]} />,
    );
    const pill = container.querySelector('tbody tr td span') as HTMLElement;
    expect(pill).not.toBeNull();
    const bg = pill.style.background.toLowerCase();
    expect(
      bg === theme.danger.toLowerCase() || bg === 'rgb(248, 113, 113)',
    ).toBe(true);
  });
});

describe('LiveDecisionsPane — filter chips', () => {
  it('T4: active chip uses theme.fg border; inactive chips use theme.mute border', () => {
    const chips = [
      { label: 'ALL', active: false },
      { label: 'DENY', active: true },
    ];
    const { container } = render(
      <LiveDecisionsPane rows={[]} filterChips={chips} />,
    );
    const chipEls = container.querySelectorAll('[data-chip-active]');
    expect(chipEls.length).toBe(2);

    const inactiveChip = chipEls[0] as HTMLElement;
    const activeChip = chipEls[1] as HTMLElement;

    expect(colorMatches(inactiveChip.style.borderColor, theme.mute)).toBe(true);
    expect(colorMatches(activeChip.style.borderColor, theme.fg)).toBe(true);
    // Active chip must NOT use theme.accent
    expect(colorMatches(activeChip.style.borderColor, theme.accent)).toBe(false);
  });
});

describe('LiveDecisionsPane — data-synthetic attribute', () => {
  it('T5: synthetic:true → data-synthetic="true"; synthetic:false → no attribute', () => {
    const { container } = render(
      <LiveDecisionsPane rows={SAMPLE_ROWS} />,
    );
    const rows = container.querySelectorAll('tbody tr');
    // SAMPLE_ROWS[0] has synthetic: false
    expect(rows[0].hasAttribute('data-synthetic')).toBe(false);
    // SAMPLE_ROWS[1] has synthetic: true
    expect(rows[1].getAttribute('data-synthetic')).toBe('true');
  });

  it('T6 (AC-DG-7 unit): mounting with SYNTHETIC_ROWS yields exactly SYNTHETIC_ROWS.length data-synthetic="true" elements', () => {
    const { container } = render(
      <LiveDecisionsPane rows={SYNTHETIC_ROWS as LiveDecisionRow[]} />,
    );
    const syntheticEls = container.querySelectorAll('[data-synthetic="true"]');
    expect(syntheticEls.length).toBe(SYNTHETIC_ROWS.length);
  });

  it('T6 inverse: rows=[] yields zero data-synthetic="true" elements', () => {
    const { container } = render(<LiveDecisionsPane rows={[]} />);
    const syntheticEls = container.querySelectorAll('[data-synthetic="true"]');
    expect(syntheticEls.length).toBe(0);
  });
});
