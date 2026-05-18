import { AbsoluteFill, Sequence, staticFile } from 'remotion';
import { theme } from '../theme';
import { TerminalReplay } from '../components/TerminalReplay';
import { ScreenshotPanel } from '../components/ScreenshotPanel';
import { Caption } from '../components/Caption';

/**
 * Deny scene (frames 0-420 relative).
 * Split panel: terminal left, dashboard right, caption below.
 */
export const Deny: React.FC = () => {
  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.bg,
        padding: 64,
        gap: 32,
        flexDirection: 'column',
        color: theme.fg,
      }}
    >
      <div
        style={{
          display: 'flex',
          flexDirection: 'row',
          gap: 32,
          flex: 1,
          minHeight: 0,
        }}
      >
        <div
          style={{
            flex: 1,
            border: `2px solid ${theme.mute}`,
            borderRadius: 12,
            overflow: 'hidden',
          }}
        >
          <TerminalReplay
            src={staticFile('terminals/scene-3-deny.txt')}
            revealFramesPerChar={0.5}
          />
        </div>
        <div style={{ flex: 1 }}>
          <ScreenshotPanel
            src={staticFile('screenshots/dashboard-livedecisions.png')}
            alt="LiveDecisions deny verdict"
          />
        </div>
      </div>
      <div style={{ paddingTop: 16 }}>
        <Sequence from={300} layout="none">
          <Caption
            headline="Fail-closed."
            body="Engine wrote the verdict. Engine wrote the message."
          />
        </Sequence>
      </div>
    </AbsoluteFill>
  );
};
