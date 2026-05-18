import { theme } from '../theme';

export interface LiveDecisionRow {
  id: string;
  namespace: string;
  name: string;
  verdict: 'ALLOW' | 'DENY';
  policy_id?: string;
  rule_id?: string;
  reason?: string;
  timestamp_ms_ago: number;
  /** Audit flag — true for fabricated rows. Rendered as data-synthetic="true". */
  synthetic?: boolean;
}

export interface LiveDecisionsPaneProps {
  rows: LiveDecisionRow[];
  title?: string;
  filterChips?: { label: string; active?: boolean }[];
}

/**
 * The complete list of synthetic rows that ship in DashboardGlimpse, in the
 * order they appear (Tile 1 rows B/C/D first, then Tile 3 rows C/E/F/G).
 * AC-DG-7 asserts that every row in this array maps 1:1 to a
 * [data-synthetic="true"] element in the rendered scene, and that the
 * rendered count never exceeds this list.
 *
 * demo/remotion/AGENTS.md §5 (the render-side synthesis contract) requires
 * this export.
 */
export const SYNTHETIC_ROWS: readonly LiveDecisionRow[] = [
  // Tile 1 — rows B, C, D
  {
    id: 'a4f0c812',
    namespace: 'payments',
    name: 'api-7d4b',
    verdict: 'ALLOW',
    policy_id: 'security-baseline',
    rule_id: 'no-privileged-containers',
    timestamp_ms_ago: 5000,
    synthetic: true,
  },
  {
    id: 'c9912ee3',
    namespace: 'default',
    name: 'debug-shell',
    verdict: 'DENY',
    policy_id: 'security-baseline',
    rule_id: 'no-host-path-volumes',
    reason: 'hostPath volume denied',
    timestamp_ms_ago: 8000,
    synthetic: true,
  },
  {
    id: '2f1a5708',
    namespace: 'kube-system',
    name: 'metrics-server-77c5',
    verdict: 'ALLOW',
    policy_id: 'security-baseline',
    rule_id: 'image-allowlist',
    timestamp_ms_ago: 12000,
    synthetic: true,
  },
  // Tile 3 — rows C, E, F, G
  {
    id: 'c9912ee3',
    namespace: 'default',
    name: 'debug-shell',
    verdict: 'DENY',
    policy_id: 'security-baseline',
    rule_id: 'no-host-path-volumes',
    reason: 'hostPath volume denied',
    timestamp_ms_ago: 8000,
    synthetic: true,
  },
  {
    id: 'b3801c1c',
    namespace: 'ci',
    name: 'builder-9d8e',
    verdict: 'DENY',
    policy_id: 'security-baseline',
    rule_id: 'no-privileged-containers',
    reason: 'privileged container denied',
    timestamp_ms_ago: 11000,
    synthetic: true,
  },
  {
    id: '7e2cdb91',
    namespace: 'payments',
    name: 'checkout-canary',
    verdict: 'DENY',
    policy_id: 'security-baseline',
    rule_id: 'image-allowlist',
    reason: 'image not on allowlist',
    timestamp_ms_ago: 14000,
    synthetic: true,
  },
  {
    id: '55104acb',
    namespace: 'default',
    name: 'ssh-runner',
    verdict: 'DENY',
    policy_id: 'security-baseline',
    rule_id: 'no-host-network',
    reason: 'hostNetwork denied',
    timestamp_ms_ago: 21000,
    synthetic: true,
  },
];

const formatAgo = (ms: number): string => {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ago`;
};

export const LiveDecisionsPane: React.FC<LiveDecisionsPaneProps> = ({
  rows,
  title = 'Live decisions',
  filterChips = [],
}) => {
  return (
    <div
      data-testid="live-decisions-pane"
      style={{
        width: '100%',
        height: '100%',
        border: `2px solid ${theme.mute}`,
        borderRadius: 12,
        overflow: 'hidden',
        boxShadow: '0 18px 48px rgba(0, 0, 0, 0.45)',
        backgroundColor: theme.bg,
        display: 'flex',
        flexDirection: 'column',
        fontFamily: '"Inter", system-ui, sans-serif',
        color: theme.fg,
      }}
    >
      <div
        style={{
          background: '#1E293B',
          padding: '12px 24px',
          fontSize: 18,
          fontWeight: 500,
          color: theme.mute,
          borderBottom: `1px solid ${theme.mute}`,
          flexShrink: 0,
        }}
      >
        kube-policies / Live decisions
      </div>

      <div
        style={{
          padding: '24px 32px 12px',
          fontSize: 36,
          fontWeight: 600,
          color: theme.fg,
          flexShrink: 0,
        }}
      >
        {title}
      </div>

      {filterChips.length > 0 && (
        <div
          style={{
            padding: '0 32px 16px',
            display: 'flex',
            gap: 8,
            flexShrink: 0,
          }}
        >
          {filterChips.map((chip) => (
            <div
              key={chip.label}
              data-chip-active={chip.active ? 'true' : 'false'}
              style={{
                padding: '4px 16px',
                borderRadius: 999,
                fontSize: 18,
                fontWeight: 500,
                cursor: 'default',
                border: chip.active
                  ? `1px solid ${theme.fg}`
                  : `1px solid ${theme.mute}`,
                background: chip.active
                  ? 'rgba(226,232,240,0.08)'
                  : 'transparent',
                color: chip.active ? theme.fg : theme.mute,
              }}
            >
              {chip.label}
            </div>
          ))}
        </div>
      )}

      <div style={{ flex: 1, overflow: 'auto' }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: 18,
          }}
        >
          <thead>
            <tr
              style={{
                borderBottom: `1px solid ${theme.mute}`,
              }}
            >
              {['ID', 'NS', 'NAME', 'VERDICT', 'POLICY', 'RULE', 'WHEN'].map(
                (h) => (
                  <th
                    key={h}
                    style={{
                      padding: '8px 16px',
                      textAlign: 'left',
                      fontWeight: 600,
                      color: theme.mute,
                      textTransform: 'uppercase',
                      fontSize: 18,
                      letterSpacing: 0.5,
                    }}
                  >
                    {h}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr
                key={`${row.id}-${i}`}
                data-synthetic={row.synthetic === true ? 'true' : undefined}
                style={{
                  height: 64,
                  backgroundColor:
                    i % 2 === 0 ? theme.bg : 'rgba(255,255,255,0.02)',
                  borderBottom: `1px solid ${theme.mute}`,
                }}
              >
                <td
                  style={{
                    padding: '8px 16px',
                    fontFamily:
                      '"JetBrains Mono","Fira Code","Menlo","Consolas",monospace',
                    fontSize: 16,
                  }}
                >
                  {row.id.slice(0, 8)}
                </td>
                <td style={{ padding: '8px 16px' }}>{row.namespace}</td>
                <td style={{ padding: '8px 16px' }}>{row.name}</td>
                <td style={{ padding: '8px 16px' }}>
                  <span
                    data-testid={`verdict-${row.id}-${i}`}
                    style={{
                      display: 'inline-block',
                      padding: '4px 12px',
                      borderRadius: 999,
                      fontWeight: 600,
                      fontSize: 16,
                      background:
                        row.verdict === 'ALLOW' ? theme.ok : theme.danger,
                      color: theme.bg,
                    }}
                  >
                    {row.verdict}
                  </span>
                </td>
                <td style={{ padding: '8px 16px', color: theme.mute }}>
                  {row.policy_id ?? '—'}
                </td>
                <td style={{ padding: '8px 16px', color: theme.mute }}>
                  {row.rule_id ?? '—'}
                </td>
                <td style={{ padding: '8px 16px', color: theme.mute }}>
                  {formatAgo(row.timestamp_ms_ago)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
