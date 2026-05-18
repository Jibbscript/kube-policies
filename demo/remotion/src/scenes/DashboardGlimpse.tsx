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
 * DashboardGlimpse scene (frames 0-420 relative).
 *
 * Quarter-screen montage of three dashboard tiles with 600 ms (18-frame)
 * cross-fades. Each tile holds for ~120 frames before fading to the next.
 *
 * Per remotion-best-practices: opacity is driven by `interpolate()`.
 */
const easing = Easing.bezier(0.16, 1, 0.3, 1);
const FADE = 18; // 600 ms @ 30fps

interface TileProps {
  src: string;
  alt: string;
  visibleFrom: number;
  visibleUntil: number;
}

const Tile: React.FC<TileProps> = ({ src, alt, visibleFrom, visibleUntil }) => {
  const frame = useCurrentFrame();
  const opacity = interpolate(
    frame,
    [
      visibleFrom,
      visibleFrom + FADE,
      visibleUntil - FADE,
      visibleUntil,
    ],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp', easing },
  );
  return (
    <div style={{ position: 'absolute', inset: 0, opacity }}>
      <ScreenshotPanel src={src} alt={alt} />
    </div>
  );
};

export const DashboardGlimpse: React.FC = () => {
  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.bg,
        padding: 96,
        flexDirection: 'column',
        gap: 32,
        color: theme.fg,
      }}
    >
      <div
        style={{
          position: 'relative',
          flex: 1,
          minHeight: 0,
          borderRadius: 12,
          overflow: 'hidden',
        }}
      >
        <Tile
          src={staticFile('screenshots/dashboard-livedecisions-full.png')}
          alt="LiveDecisions full"
          visibleFrom={0}
          visibleUntil={150}
        />
        <Tile
          src={staticFile('screenshots/dashboard-metrics-full.png')}
          alt="Metrics full"
          visibleFrom={132}
          visibleUntil={282}
        />
        <Tile
          src={staticFile('screenshots/dashboard-exceptions-list.png')}
          alt="Exceptions list"
          visibleFrom={264}
          visibleUntil={420}
        />
      </div>
      <Sequence from={300} layout="none">
        <Caption
          headline="Read-only by default."
          body="Writes gated by ALLOW_WRITES."
        />
      </Sequence>
    </AbsoluteFill>
  );
};
