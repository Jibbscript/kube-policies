import { AbsoluteFill, Easing, interpolate, useCurrentFrame } from 'remotion';
import { theme } from '../theme';
import { Logo } from '../components/Logo';

/**
 * Closing scene (frames 0-180 relative). Slow fade-in of logo + URL + license.
 */
const easing = Easing.bezier(0.16, 1, 0.3, 1);

export const Closing: React.FC = () => {
  const frame = useCurrentFrame();
  const opacity = interpolate(frame, [0, 60], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing,
  });
  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.bg,
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: 48,
        opacity,
        color: theme.fg,
        fontFamily: '"Inter", system-ui, sans-serif',
      }}
    >
      <Logo width={900} height={220} />
      <div
        style={{
          fontWeight: 400,
          fontSize: 40,
          color: theme.fg,
          fontFamily:
            '"JetBrains Mono", "Fira Code", "Menlo", monospace',
        }}
      >
        github.com/Jibbscript/kube-policies
      </div>
      <div
        style={{
          fontWeight: 400,
          fontSize: 28,
          color: theme.mute,
        }}
      >
        Apache 2.0
      </div>
    </AbsoluteFill>
  );
};
