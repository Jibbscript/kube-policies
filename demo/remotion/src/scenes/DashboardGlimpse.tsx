import {
  AbsoluteFill,
  Easing,
  Sequence,
  interpolate,
  staticFile,
  useCurrentFrame,
} from 'remotion';
import { theme } from '../theme';
import { ScreenshotPanel } from '../components/ScreenshotPanel';
import { Caption } from '../components/Caption';
import { LiveDecisionsPane, SYNTHETIC_ROWS, type LiveDecisionRow } from '../components/LiveDecisionsPane';

/**
 * DashboardGlimpse scene (frames 0–420 relative, 14 s @ 30 fps).
 *
 * Hybrid tile layout:
 *   Tile 1 (0–150):   LiveDecisionsPane ALL view (1 real row + 3 synthetic)
 *   Tile 2 (132–282): Metrics PNG card-header band, crop+zoom
 *   Tile 3 (264–420): LiveDecisionsPane DENY-filtered view (4 synthetic)
 *
 * Scene brand colors: {ok, danger} only. theme.accent is NOT used here.
 * Ken-Burns 1.00→1.08 per tile via interpolate()+Easing.bezier.
 */
const easing = Easing.bezier(0.16, 1, 0.3, 1);
const FADE = 18; // 600 ms @ 30 fps

const REAL_ROW_A: LiveDecisionRow = {
  id: '930c931b',
  namespace: 'default',
  name: 'emergency-pod',
  verdict: 'ALLOW',
  policy_id: 'security-baseline',
  rule_id: 'no-host-path-volumes',
  reason: 'suppressed by exception',
  timestamp_ms_ago: 2000,
  synthetic: false,
};

// Tile 1: 1 real row (A) + 3 synthetic rows (B, C, D = SYNTHETIC_ROWS[0..2])
const TILE_1_ROWS: LiveDecisionRow[] = [
  REAL_ROW_A,
  SYNTHETIC_ROWS[0],
  SYNTHETIC_ROWS[1],
  SYNTHETIC_ROWS[2],
];

// Tile 3: 4 synthetic DENY rows (C, E, F, G = SYNTHETIC_ROWS[3..6])
const TILE_3_ROWS: LiveDecisionRow[] = [
  SYNTHETIC_ROWS[3],
  SYNTHETIC_ROWS[4],
  SYNTHETIC_ROWS[5],
  SYNTHETIC_ROWS[6],
];

const TILE_1_CHIPS = [
  { label: 'ALL', active: true },
  { label: 'ALLOW', active: false },
  { label: 'DENY', active: false },
];

const TILE_3_CHIPS = [
  { label: 'ALL', active: false },
  { label: 'ALLOW', active: false },
  { label: 'DENY', active: true },
];

export const DashboardGlimpse: React.FC = () => {
  const frame = useCurrentFrame();

  const tile1Opacity = interpolate(
    frame,
    [0, FADE, 150 - FADE, 150],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp', easing },
  );
  const tile2Opacity = interpolate(
    frame,
    [132, 132 + FADE, 282 - FADE, 282],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp', easing },
  );
  const tile3Opacity = interpolate(
    frame,
    [264, 264 + FADE, 420 - FADE, 420],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp', easing },
  );

  // Ken-Burns scale for DOM tiles (ScreenshotPanel tile 2 uses its own zoom prop)
  const tile1Scale = interpolate(frame, [0, 150], [1.0, 1.08], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing,
  });
  const tile3Scale = interpolate(frame, [264, 420], [1.0, 1.08], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing,
  });

  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg }}>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          padding: 96,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div style={{ position: 'relative', flex: 1, minHeight: 0 }}>
          <div
            data-testid="tile-1"
            style={{ position: 'absolute', inset: 0, opacity: tile1Opacity }}
          >
            <div
              style={{
                width: '100%',
                height: '100%',
                transform: `scale(${tile1Scale})`,
                transformOrigin: '50% 50%',
              }}
            >
              <LiveDecisionsPane rows={TILE_1_ROWS} filterChips={TILE_1_CHIPS} />
            </div>
          </div>

          {/* Card-header band only; sparkline body is masked at capture (demo/capture/dashboard.spec.ts:58) and must not be amplified by zoom. */}
          <div
            data-testid="tile-2"
            style={{ position: 'absolute', inset: 0, opacity: tile2Opacity }}
          >
            <ScreenshotPanel
              src={staticFile('screenshots/dashboard-metrics.png')}
              crop={{ x: 0.0, y: 0.20, width: 1.0, height: 0.12 }}
              zoom={{ from: 1.0, to: 1.08, fromFrame: 132, toFrame: 282 }}
              alt="Metrics card headers"
            />
          </div>

          <div
            data-testid="tile-3"
            style={{ position: 'absolute', inset: 0, opacity: tile3Opacity }}
          >
            <div
              style={{
                width: '100%',
                height: '100%',
                transform: `scale(${tile3Scale})`,
                transformOrigin: '50% 50%',
              }}
            >
              <LiveDecisionsPane rows={TILE_3_ROWS} filterChips={TILE_3_CHIPS} />
            </div>
          </div>
        </div>
      </div>

      {/* Caption overlay — sits above tiles, never interacts with pointer events */}
      <AbsoluteFill style={{ pointerEvents: 'none' }}>
        {/* Gradient scrim — single instance, covers bottom 360px */}
        <div
          style={{
            position: 'absolute',
            left: 0,
            bottom: 0,
            width: '100%',
            height: 360,
            background: `linear-gradient(0deg, ${theme.bg} 0%, ${theme.bg}E6 60%, transparent 100%)`,
          }}
        />
        <div
          data-testid="caption-overlay"
          style={{
            position: 'absolute',
            left: 96,
            bottom: 96,
            right: 96,
          }}
        >
          <Sequence from={18} durationInFrames={114} layout="none">
            <Caption
              headline="Live decisions."
              body="Streamed from the audit webhook."
            />
          </Sequence>
          <Sequence from={150} durationInFrames={114} layout="none">
            <Caption
              headline="Read-only by default."
              body="Writes gated by ALLOW_WRITES."
            />
          </Sequence>
          <Sequence from={282} durationInFrames={138} layout="none">
            <Caption
              headline="Policy denies surface here."
              body="kubectl apply blocked at admission."
            />
          </Sequence>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
