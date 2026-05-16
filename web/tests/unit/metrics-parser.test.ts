import { describe, expect, it } from 'vitest';
import { metricsToTiles, sparklinePath } from '../../src/lib/metrics';
import type { MetricsSummary } from '../../src/lib/types';

describe('metricsToTiles', () => {
  it('produces 8 tiles with expected values', () => {
    const m: MetricsSummary = {
      admission_rps: 12.345,
      eval_p95_ms: 4.2,
      denials_per_min: 3.5,
      policies_loaded: 7,
      audit_buffer: 42,
      top_violating_rules: [{ rule_id: 'no-privileged-containers', count: 9 }],
      policy_manager_degraded: false,
      admission_webhook_degraded: true,
    };
    const tiles = metricsToTiles(m);
    expect(tiles).toHaveLength(8);
    expect(tiles.find((t) => t.key === 'rps')?.value).toBe('12.35');
    expect(tiles.find((t) => t.key === 'p95')?.value).toBe('4.2');
    expect(tiles.find((t) => t.key === 'denials')?.value).toBe('3.5');
    expect(tiles.find((t) => t.key === 'policies')?.value).toBe('7');
    expect(tiles.find((t) => t.key === 'pm')?.value).toBe('OK');
    expect(tiles.find((t) => t.key === 'admit')?.value).toBe('DEGRADED');
    expect(tiles.find((t) => t.key === 'top')?.value).toBe('no-privileged-containers');
    expect(tiles.find((t) => t.key === 'top')?.hint).toBe('9 hits');
  });

  it('handles empty top rules gracefully', () => {
    const m: MetricsSummary = {
      admission_rps: 0,
      eval_p95_ms: 0,
      denials_per_min: 0,
      policies_loaded: 0,
      audit_buffer: 0,
      top_violating_rules: [],
      policy_manager_degraded: false,
      admission_webhook_degraded: false,
    };
    expect(metricsToTiles(m).find((t) => t.key === 'top')?.value).toBe('—');
  });
});

describe('sparklinePath', () => {
  it('returns empty string for empty input', () => {
    expect(sparklinePath([], 100, 20)).toBe('');
  });
  it('starts with M command', () => {
    expect(sparklinePath([1, 2, 3], 100, 20)).toMatch(/^M/);
  });
  it('emits N segments for N points', () => {
    const path = sparklinePath([0, 1, 2, 3], 120, 20);
    expect(path.split(/[ML]/).filter(Boolean)).toHaveLength(4);
  });
});
