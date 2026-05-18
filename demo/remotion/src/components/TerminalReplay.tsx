import { useEffect, useState } from 'react';
import { continueRender, delayRender, useCurrentFrame } from 'remotion';
import { theme } from '../theme';

/**
 * TerminalReplay — typewriter renderer for real captured terminal text.
 *
 * Reads a UTF-8 text file (via `staticFile()` → fetch) and reveals
 * `1 / revealFramesPerChar` characters per frame using `useCurrentFrame()`.
 * ANSI color escapes are decoded into themed <span> runs:
 *   - `\x1b[31m` → theme.danger
 *   - `\x1b[32m` → theme.ok
 *   - `\x1b[0m`  → reset (theme.fg)
 *
 * Per remotion-best-practices: animation is driven by frame math —
 * no CSS keyframes, no Tailwind animate-* classes.
 */
export interface TerminalReplayProps {
  src: string;
  /** Default 0.5 frames/char ≈ 60 chars/sec @ 30fps. */
  revealFramesPerChar?: number;
  /** Override text directly (skips fetch — used in unit tests). */
  textOverride?: string;
  fontSize?: number;
}

interface Run {
  text: string;
  color: string;
}

export const ansiToRuns = (input: string): Run[] => {
  const runs: Run[] = [];
  let buffer = '';
  let color: string = theme.fg;
  const flush = () => {
    if (buffer.length === 0) return;
    runs.push({ text: buffer, color });
    buffer = '';
  };
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === '\x1b' && input[i + 1] === '[') {
      // Parse ESC[<digits>m
      let j = i + 2;
      let digits = '';
      while (j < input.length && /[0-9]/.test(input[j])) {
        digits += input[j];
        j++;
      }
      if (input[j] === 'm') {
        flush();
        if (digits === '31') color = theme.danger;
        else if (digits === '32') color = theme.ok;
        else color = theme.fg;
        i = j;
        continue;
      }
    }
    buffer += ch;
  }
  flush();
  return runs;
};

export const sliceRuns = (runs: Run[], chars: number): Run[] => {
  if (chars <= 0) return [];
  let remaining = chars;
  const out: Run[] = [];
  for (const run of runs) {
    if (remaining <= 0) break;
    if (run.text.length <= remaining) {
      out.push(run);
      remaining -= run.text.length;
    } else {
      out.push({ text: run.text.slice(0, remaining), color: run.color });
      remaining = 0;
    }
  }
  return out;
};

export const TerminalReplay: React.FC<TerminalReplayProps> = ({
  src,
  revealFramesPerChar = 0.5,
  textOverride,
  fontSize = 28,
}) => {
  const frame = useCurrentFrame();
  const [text, setText] = useState<string>(textOverride ?? '');
  const [handle] = useState(() =>
    textOverride === undefined ? delayRender(`TerminalReplay:${src}`) : -1,
  );

  useEffect(() => {
    if (textOverride !== undefined) return;
    let canceled = false;
    fetch(src)
      .then((r) => r.text())
      .then((t) => {
        if (canceled) return;
        setText(t);
        continueRender(handle);
      })
      .catch(() => {
        if (canceled) return;
        setText('');
        continueRender(handle);
      });
    return () => {
      canceled = true;
    };
  }, [src, textOverride, handle]);

  const visibleChars = Math.max(0, Math.floor(frame / revealFramesPerChar));
  const runs = ansiToRuns(text);
  const visibleRuns = sliceRuns(runs, visibleChars);

  return (
    <div
      data-testid="terminal-replay"
      style={{
        backgroundColor: theme.bg,
        color: theme.fg,
        fontFamily:
          '"JetBrains Mono", "Fira Code", "Menlo", "Consolas", monospace',
        fontSize,
        lineHeight: 1.35,
        padding: 32,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        height: '100%',
        boxSizing: 'border-box',
      }}
    >
      {visibleRuns.map((run, i) => (
        <span key={i} style={{ color: run.color }}>
          {run.text}
        </span>
      ))}
    </div>
  );
};
