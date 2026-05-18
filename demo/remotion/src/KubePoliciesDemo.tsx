import { AbsoluteFill, Sequence } from 'remotion';
import { Title } from './scenes/Title';
import { Pitch } from './scenes/Pitch';
import { Deny } from './scenes/Deny';
import { Exception } from './scenes/Exception';
import { DashboardGlimpse } from './scenes/DashboardGlimpse';
import { Closing } from './scenes/Closing';
import { theme } from './theme';

/**
 * KubePoliciesDemo — 60-second composition root.
 *
 * Frame budget (30 fps, 1800 frames total):
 *   Title              0 → 120   (4.0s)
 *   Pitch            120 → 300   (6.0s)
 *   Deny             300 → 720   (14.0s)
 *   Exception        720 → 1200  (16.0s)
 *   DashboardGlimpse 1200 → 1620 (14.0s)
 *   Closing          1620 → 1800 (6.0s)
 *
 * Storyboard source of truth: .omc/plans/kube-policies-demo-video.md §4.
 */
export const KubePoliciesDemo: React.FC = () => {
  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg }}>
      <Sequence durationInFrames={120} name="Title">
        <Title />
      </Sequence>
      <Sequence from={120} durationInFrames={180} name="Pitch">
        <Pitch />
      </Sequence>
      <Sequence from={300} durationInFrames={420} name="Deny">
        <Deny />
      </Sequence>
      <Sequence from={720} durationInFrames={480} name="Exception">
        <Exception />
      </Sequence>
      <Sequence from={1200} durationInFrames={420} name="DashboardGlimpse">
        <DashboardGlimpse />
      </Sequence>
      <Sequence from={1620} durationInFrames={180} name="Closing">
        <Closing />
      </Sequence>
    </AbsoluteFill>
  );
};
