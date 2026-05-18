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

/**
 * DashboardGlimpse scene (frames 0–420 relative, 14 s @ 30 fps).
 *
 * Tile layout (all three tiles are ScreenshotPanel — no DOM synthesis since
 * the dashboard `/api/decisions/*` capture-time bug was root-caused and
 * fixed; see `.omc/plans/dashboard-500-fix.md`):
 *   Tile 1 (0–150):   `dashboard-livedecisions.png`, ALL view crop
 *   Tile 2 (132–282): `dashboard-metrics.png`, card-header band crop
 *   Tile 3 (264–420): `dashboard-livedecisions.png` zoomed in on the DENY-rule
 *                     rows (which dominate the captured rows) — gives a
 *                     visual "filter to DENY" effect without re-capturing
 *
 * Scene brand colors: {ok, danger} only. theme.accent is NOT used here.
 * Ken-Burns 1.00→1.08 per tile via ScreenshotPanel's zoom prop +
 * interpolate()+Easing.bezier on the wrapper opacity.
 *
 * The (x, y, width, height) on each ScreenshotPanel.crop is mirrored in
 * `demo/remotion/public/manifest.json` as the per-PNG
 * `expected_content_region` annotation — verify-frames.test.ts asserts
 * the two stay in lock-step, so a dashboard restyle that changes the PNG
 * sha256 forces an explicit AC review of the crop geometry.
 */
const easing = Easing.bezier(0.16, 1, 0.3, 1);
const FADE = 18; // 600 ms @ 30 fps

// Mirror of the manifest's expected_content_region for each tile.
// Verify-side AC: see demo/remotion/src/scenes/__tests__/DashboardGlimpse.test.tsx.
export const TILE_1_CROP = { x: 0.18, y: 0.06, width: 0.64, height: 0.42 } as const;
export const TILE_2_CROP = { x: 0.0, y: 0.20, width: 1.0, height: 0.12 } as const;
export const TILE_3_CROP = { x: 0.18, y: 0.18, width: 0.64, height: 0.30 } as const;

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
            <ScreenshotPanel
              src={staticFile('screenshots/dashboard-livedecisions.png')}
              crop={TILE_1_CROP}
              zoom={{ from: 1.0, to: 1.08, fromFrame: 0, toFrame: 150 }}
              alt="Live decisions — ALL view"
            />
          </div>

          {/* Card-header band only; sparkline body is masked at capture (demo/capture/dashboard.spec.ts:58) and must not be amplified by zoom. */}
          <div
            data-testid="tile-2"
            style={{ position: 'absolute', inset: 0, opacity: tile2Opacity }}
          >
            <ScreenshotPanel
              src={staticFile('screenshots/dashboard-metrics.png')}
              crop={TILE_2_CROP}
              zoom={{ from: 1.0, to: 1.08, fromFrame: 132, toFrame: 282 }}
              alt="Metrics card headers"
            />
          </div>

          <div
            data-testid="tile-3"
            style={{ position: 'absolute', inset: 0, opacity: tile3Opacity }}
          >
            <ScreenshotPanel
              src={staticFile('screenshots/dashboard-livedecisions.png')}
              crop={TILE_3_CROP}
              zoom={{ from: 1.0, to: 1.08, fromFrame: 264, toFrame: 420 }}
              alt="Live decisions — DENY rows in focus"
            />
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
