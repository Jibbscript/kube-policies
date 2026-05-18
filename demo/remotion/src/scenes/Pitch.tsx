import { AbsoluteFill, Easing, interpolate, useCurrentFrame } from 'remotion';
import { theme } from '../theme';

/**
 * Pitch scene (frames 0-180 relative). The one-liner + a small 3-box flow
 * diagram (kubectl apply → admission-webhook → apiserver) drawn inline.
 */
const easing = Easing.bezier(0.16, 1, 0.3, 1);

export const Pitch: React.FC = () => {
  const frame = useCurrentFrame();
  const headlineOpacity = interpolate(frame, [0, 20], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing,
  });
  const diagramOpacity = interpolate(frame, [25, 55], [0, 1], {
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
        gap: 96,
        padding: 96,
        color: theme.fg,
        fontFamily: '"Inter", system-ui, sans-serif',
      }}
    >
      <div
        style={{
          opacity: headlineOpacity,
          fontWeight: 700,
          fontSize: 84,
          textAlign: 'center',
          letterSpacing: -1,
          maxWidth: 1500,
          lineHeight: 1.15,
        }}
      >
        Real-time, fail-closed admission. Rego-defined. Sub-millisecond.
      </div>
      <div style={{ opacity: diagramOpacity, width: 1500, height: 220 }}>
        <PipelineDiagram />
      </div>
    </AbsoluteFill>
  );
};

const PipelineDiagram: React.FC = () => {
  const boxStyle: React.CSSProperties = {
    width: 380,
    height: 140,
    border: `2px solid ${theme.accent}`,
    borderRadius: 16,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily:
      '"JetBrains Mono", "Fira Code", "Menlo", monospace',
    fontSize: 32,
    color: theme.fg,
    backgroundColor: 'rgba(56, 189, 248, 0.08)',
    textAlign: 'center',
    padding: 16,
    boxSizing: 'border-box',
  };
  const arrow: React.CSSProperties = {
    flex: 1,
    height: 4,
    backgroundColor: theme.accent,
    position: 'relative',
    margin: '0 12px',
  };
  const head: React.CSSProperties = {
    width: 0,
    height: 0,
    borderTop: `12px solid transparent`,
    borderBottom: `12px solid transparent`,
    borderLeft: `18px solid ${theme.accent}`,
  };
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        width: '100%',
        height: '100%',
      }}
    >
      <div style={boxStyle}>kubectl apply</div>
      <div style={arrow} />
      <div style={head} />
      <div style={boxStyle}>admission-webhook</div>
      <div style={arrow} />
      <div style={head} />
      <div style={boxStyle}>apiserver</div>
    </div>
  );
};
