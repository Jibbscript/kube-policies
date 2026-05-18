import { Img, staticFile } from 'remotion';
import { theme } from '../theme';

/**
 * Logo — `kube-policies` wordmark.
 *
 * Loads `public/brand/logo.svg` via `staticFile()`. Falls back to an inline
 * SVG rendering if the asset is missing (per OQ-D-2). The accent underline
 * uses `theme.accent`.
 */
export interface LogoProps {
  width?: number;
  height?: number;
  /** Force the inline fallback (skips the `staticFile()` render). */
  forceFallback?: boolean;
}

export const Logo: React.FC<LogoProps> = ({
  width = 800,
  height = 200,
  forceFallback = false,
}) => {
  if (forceFallback) {
    return <FallbackLogo width={width} height={height} />;
  }
  return (
    <Img
      data-testid="logo"
      src={staticFile('brand/logo.svg')}
      alt="kube-policies"
      style={{
        width,
        height,
        objectFit: 'contain',
        display: 'block',
      }}
    />
  );
};

const FallbackLogo: React.FC<{ width: number; height: number }> = ({
  width,
  height,
}) => {
  return (
    <svg
      data-testid="logo-fallback"
      width={width}
      height={height}
      viewBox="0 0 800 200"
      xmlns="http://www.w3.org/2000/svg"
    >
      <text
        x="400"
        y="120"
        textAnchor="middle"
        fontFamily="Inter, system-ui, sans-serif"
        fontWeight="700"
        fontSize="96"
        fill={theme.fg}
      >
        kube-policies
      </text>
      <rect x="120" y="150" width="560" height="8" fill={theme.accent} />
    </svg>
  );
};
