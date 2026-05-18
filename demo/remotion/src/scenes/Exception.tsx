import { AbsoluteFill, Sequence, staticFile } from 'remotion';
import { theme } from '../theme';
import { TerminalReplay } from '../components/TerminalReplay';
import { AuditPane } from '../components/AuditPane';
import { ScreenshotPanel } from '../components/ScreenshotPanel';
import { Caption } from '../components/Caption';

/**
 * Exception scene (frames 0-480 relative).
 *
 * Three panes:
 *   top-left    : TerminalReplay  (terminals/scene-4-exception.txt)
 *   bottom-left : AuditPane       (audit/scene-4-audit.json)
 *   right       : ScreenshotPanel (screenshots/dashboard-metrics.png)
 */
export const Exception: React.FC = () => {
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
            display: 'flex',
            flexDirection: 'column',
            gap: 24,
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
              src={staticFile('terminals/scene-4-exception.txt')}
              revealFramesPerChar={0.5}
            />
          </div>
          <div
            style={{
              flex: 1,
              border: `2px solid ${theme.mute}`,
              borderRadius: 12,
              overflow: 'hidden',
            }}
          >
            <AuditPane src={staticFile('audit/scene-4-audit.json')} />
          </div>
        </div>
        <div style={{ flex: 1 }}>
          <ScreenshotPanel
            src={staticFile('screenshots/dashboard-metrics.png')}
            alt="Metrics dashboard: policy_exception_suppressions_total ticking"
          />
        </div>
      </div>
      <div style={{ paddingTop: 16 }}>
        <Sequence from={360} layout="none">
          <Caption
            headline="Exception waives the deny."
            body="The audit log preserves the suppressed violation."
          />
        </Sequence>
      </div>
    </AbsoluteFill>
  );
};
