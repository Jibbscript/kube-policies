import { Easing, Img, interpolate, useCurrentFrame } from 'remotion';
import { theme } from '../theme';

export interface CropRect {
  /** Normalized 0..1 x offset of the source rectangle. */
  x: number;
  /** Normalized 0..1 y offset of the source rectangle. */
  y: number;
  /** Normalized 0..1 width of the source rectangle. */
  width: number;
  /** Normalized 0..1 height of the source rectangle. */
  height: number;
}

export interface ZoomSpec {
  /** Scale at scene-relative `fromFrame`. */
  from: number;
  /** Scale at scene-relative `toFrame`. */
  to: number;
  /** Inclusive scene-relative start frame. */
  fromFrame: number;
  /** Inclusive scene-relative end frame. */
  toFrame: number;
}

export interface ScreenshotPanelProps {
  src: string;
  /** Visual width in container px. */
  width?: number | string;
  /** Visual height in container px. */
  height?: number | string;
  alt?: string;
  /** Source rect to display (normalized 0..1). When set, panel uses cover math. */
  crop?: CropRect;
  /** Optional Ken-Burns scale ramp. Anchored at panel center via transform-origin. */
  zoom?: ZoomSpec;
}

export const ScreenshotPanel: React.FC<ScreenshotPanelProps> = ({
  src,
  width = '100%',
  height = '100%',
  alt = 'dashboard screenshot',
  crop,
  zoom,
}) => {
  if (crop && (crop.width <= 0 || crop.height <= 0)) {
    throw new Error(
      `ScreenshotPanel: crop.width and crop.height must be > 0 (got ${crop.width}, ${crop.height})`,
    );
  }

  const frame = useCurrentFrame();

  const scale = zoom
    ? interpolate(frame, [zoom.fromFrame, zoom.toFrame], [zoom.from, zoom.to], {
        extrapolateLeft: 'clamp',
        extrapolateRight: 'clamp',
        easing: Easing.bezier(0.16, 1, 0.3, 1),
      })
    : 1;

  const imgStyle = {
    display: 'block',
    transformOrigin: '50% 50%',
    transform: `scale(${scale})`,
    ...(crop
      ? {
          position: 'absolute' as const,
          width: `${(1 / crop.width) * 100}%`,
          height: `${(1 / crop.height) * 100}%`,
          left: `${-(crop.x / crop.width) * 100}%`,
          top: `${-(crop.y / crop.height) * 100}%`,
          objectFit: 'cover' as const,
        }
      : {
          width: '100%',
          height: '100%',
          objectFit: 'contain' as const,
        }),
  };

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
        position: 'relative',
      }}
    >
      <div
        data-testid="screenshot-panel-stage"
        style={{
          position: 'absolute',
          inset: 0,
          overflow: 'hidden',
        }}
      >
        <Img
          data-testid="screenshot-panel-img"
          src={src}
          alt={alt}
          style={imgStyle}
        />
      </div>
    </div>
  );
};
