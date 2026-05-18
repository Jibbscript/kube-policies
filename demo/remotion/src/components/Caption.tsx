import { Easing, interpolate, useCurrentFrame } from 'remotion';
import { theme } from '../theme';

/**
 * Caption — animated headline + body.
 *
 * Opacity is driven by `useCurrentFrame()` + `interpolate()` with
 * `Easing.bezier(0.16, 1, 0.3, 1)` (smooth exponential ease-out)
 * per remotion-best-practices. No CSS animations or transitions.
 */
export interface CaptionProps {
  headline: string;
  body?: string;
  /** Frames to fade in over. Default 15. */
  fadeFrames?: number;
}

const easing = Easing.bezier(0.16, 1, 0.3, 1);

export const Caption: React.FC<CaptionProps> = ({
  headline,
  body,
  fadeFrames = 15,
}) => {
  const frame = useCurrentFrame();
  const opacity = interpolate(frame, [0, fadeFrames], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing,
  });
  return (
    <div
      data-testid="caption"
      style={{
        opacity,
        fontFamily: '"Inter", system-ui, sans-serif',
        color: theme.fg,
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      <div
        data-testid="caption-headline"
        style={{
          fontWeight: 700,
          fontSize: 96,
          lineHeight: 1.1,
          letterSpacing: -1,
        }}
      >
        {headline}
      </div>
      {body ? (
        <div
          data-testid="caption-body"
          style={{
            fontWeight: 400,
            fontSize: 48,
            lineHeight: 1.3,
            color: theme.fg,
            opacity: 0.85,
          }}
        >
          {body}
        </div>
      ) : null}
    </div>
  );
};
