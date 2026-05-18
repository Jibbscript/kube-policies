import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { AuditPane, highlightSuppressedBy } from '../AuditPane';
import { theme } from '../../theme';

vi.mock('remotion', () => ({
  useCurrentFrame: () => 0,
  delayRender: () => -1,
  continueRender: () => undefined,
}));

afterEach(() => {
  cleanup();
});

describe('highlightSuppressedBy', () => {
  it('splits a JSON string into a non-highlighted prefix and a highlighted suppressed_by key+value', () => {
    const json = '{\n  "name": "emergency-pod",\n  "suppressed_by": [\n    { "policy_id": "x" }\n  ]\n}';
    const segments = highlightSuppressedBy(json);
    // Expect at least one highlighted segment.
    const highlighted = segments.filter((s) => s.highlighted);
    expect(highlighted.length).toBeGreaterThan(0);
    expect(highlighted[0].text.startsWith('"suppressed_by"')).toBe(true);
    // The highlighted segment should contain the array closing bracket.
    expect(highlighted[0].text.includes(']')).toBe(true);
  });

  it('returns a single non-highlighted segment when suppressed_by is absent', () => {
    const json = '{\n  "verdict": "deny"\n}';
    const segments = highlightSuppressedBy(json);
    expect(segments).toHaveLength(1);
    expect(segments[0].highlighted).toBe(false);
  });
});

describe('AuditPane rendering', () => {
  const sample = {
    name: 'emergency-pod',
    verdict: 'allow',
    suppressed_by: [
      { policy_id: 'security-baseline', rule_id: 'no-privileged-containers' },
    ],
  };

  it('renders pretty-printed JSON (2-space indent)', () => {
    const { container } = render(
      <AuditPane src="ignored" objectOverride={sample} />,
    );
    const pane = container.querySelector('[data-testid="audit-pane"]');
    expect(pane).not.toBeNull();
    const text = pane?.textContent ?? '';
    expect(text).toContain('  "name": "emergency-pod"');
    expect(text).toContain('"suppressed_by"');
    expect(text).toContain('security-baseline');
  });

  it('applies theme.accent color to the suppressed_by segment', () => {
    const { container } = render(
      <AuditPane src="ignored" objectOverride={sample} />,
    );
    const highlighted = container.querySelector(
      '[data-suppressed-by="true"]',
    ) as HTMLElement | null;
    expect(highlighted).not.toBeNull();
    const color = (highlighted?.style.color ?? '').toLowerCase();
    expect(
      color === theme.accent.toLowerCase() ||
        color === 'rgb(56, 189, 248)',
    ).toBe(true);
    expect(highlighted?.textContent?.startsWith('"suppressed_by"')).toBe(true);
  });
});
