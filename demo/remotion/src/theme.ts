export const theme = {
  bg: '#0B1220',
  fg: '#E2E8F0',
  accent: '#38BDF8',
  danger: '#F87171',
  ok: '#34D399',
  mute: '#475569',
} as const;

export type Theme = typeof theme;
