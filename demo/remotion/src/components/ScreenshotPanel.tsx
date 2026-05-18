import { Img } from 'remotion';
import { theme } from '../theme';

/**
 * ScreenshotPanel — renders a captured PNG screenshot with a uniform border,
 * drop-shadow, and rounded corners. Preserves aspect ratio via `objectFit`.
 */
export interface ScreenshotPanelProps {
  src: string;
  /** Visual width in container px. */
  width?: number | string;
  /** Visual height in container px. */
  height?: number | string;
  alt?: string;
}

export const ScreenshotPanel: React.FC<ScreenshotPanelProps> = ({
  src,
  width = '100%',
  height = '100%',
  alt = 'dashboard screenshot',
}) => {
  return (
    <div
      data-testid="screenshot-panel"
      style={{
        width,
        height,
        border: `2px solid ${theme.mute}`,
        borderRadius: 12,
        overflow: 'hidden',
        boxShadow: '0 18px 48px rgba(0, 0, 0, 0.45)',
        backgroundColor: theme.bg,
      }}
    >
      <Img
        src={src}
        alt={alt}
        style={{
          width: '100%',
          height: '100%',
          objectFit: 'contain',
          display: 'block',
        }}
      />
    </div>
  );
};
