import { AbsoluteFill, Easing, interpolate, useCurrentFrame } from 'remotion';
import { theme } from '../theme';
import { Logo } from '../components/Logo';

/**
 * Title scene (frames 0-120). Fade-in 0-30, hold 30-90, fade-out 90-120.
 */
const easing = Easing.bezier(0.16, 1, 0.3, 1);

export const Title: React.FC = () => {
  const frame = useCurrentFrame();
  const opacity = interpolate(
    frame,
    [0, 30, 90, 120],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp', easing },
  );
  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.bg,
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: 48,
        opacity,
        fontFamily: '"Inter", system-ui, sans-serif',
        color: theme.fg,
      }}
    >
      <Logo width={900} height={220} />
      <div
        style={{
          fontWeight: 400,
          fontSize: 56,
          letterSpacing: -0.5,
          color: theme.fg,
        }}
      >
        Kubernetes admission control. As code.
      </div>
      <div
        style={{
          fontWeight: 400,
          fontSize: 32,
          color: theme.mute,
          fontFamily:
            '"JetBrains Mono", "Fira Code", "Menlo", monospace',
        }}
      >
        github.com/Jibbscript/kube-policies
      </div>
    </AbsoluteFill>
  );
};
