import { useEffect, useState } from 'react';
import { continueRender, delayRender } from 'remotion';
import { theme } from '../theme';

/**
 * AuditPane — renders a captured audit-log JSON object pretty-printed.
 *
 * Syntax-highlights the `"suppressed_by"` key (and its array value) in
 * `theme.accent` so the PolicyException story is visually obvious.
 *
 * Per remotion-best-practices: no CSS animations.
 */
export interface AuditPaneProps {
  src: string;
  /** Override the loaded object directly (skips fetch — used in unit tests). */
  objectOverride?: unknown;
  fontSize?: number;
}

const SUPPRESSED_KEY = '"suppressed_by"';

interface Segment {
  text: string;
  highlighted: boolean;
}

/**
 * Splits a pretty-printed JSON string into segments where `"suppressed_by"`
 * and its value (until the matching closing bracket at the same indent) are
 * marked highlighted.
 */
export const highlightSuppressedBy = (json: string): Segment[] => {
  const segments: Segment[] = [];
  let cursor = 0;
  while (cursor < json.length) {
    const keyIdx = json.indexOf(SUPPRESSED_KEY, cursor);
    if (keyIdx === -1) {
      segments.push({ text: json.slice(cursor), highlighted: false });
      break;
    }
    if (keyIdx > cursor) {
      segments.push({ text: json.slice(cursor, keyIdx), highlighted: false });
    }
    // Find the end of the value: walk forward, balance brackets.
    let i = keyIdx + SUPPRESSED_KEY.length;
    // Skip ":" and whitespace.
    while (i < json.length && json[i] !== '[' && json[i] !== '{' && json[i] !== '"' && json[i] !== 'n' && !/[0-9-]/.test(json[i])) {
      i++;
    }
    let endIdx = i;
    if (json[i] === '[' || json[i] === '{') {
      const open = json[i];
      const close = open === '[' ? ']' : '}';
      let depth = 0;
      for (let j = i; j < json.length; j++) {
        if (json[j] === open) depth++;
        else if (json[j] === close) {
          depth--;
          if (depth === 0) {
            endIdx = j + 1;
            break;
          }
        }
      }
    } else if (json[i] === '"') {
      // Quoted scalar.
      for (let j = i + 1; j < json.length; j++) {
        if (json[j] === '\\') {
          j++;
          continue;
        }
        if (json[j] === '"') {
          endIdx = j + 1;
          break;
        }
      }
    } else {
      // Bare scalar (number, null, true, false): consume until comma/newline.
      while (endIdx < json.length && !/[,\n]/.test(json[endIdx])) endIdx++;
    }
    segments.push({ text: json.slice(keyIdx, endIdx), highlighted: true });
    cursor = endIdx;
  }
  return segments;
};

export const AuditPane: React.FC<AuditPaneProps> = ({
  src,
  objectOverride,
  fontSize = 20,
}) => {
  const [obj, setObj] = useState<unknown>(objectOverride ?? null);
  const [handle] = useState(() =>
    objectOverride === undefined ? delayRender(`AuditPane:${src}`) : -1,
  );

  useEffect(() => {
    if (objectOverride !== undefined) return;
    let canceled = false;
    fetch(src)
      .then((r) => r.json())
      .then((j) => {
        if (canceled) return;
        setObj(j);
        continueRender(handle);
      })
      .catch(() => {
        if (canceled) return;
        setObj({});
        continueRender(handle);
      });
    return () => {
      canceled = true;
    };
  }, [src, objectOverride, handle]);

  const pretty = obj === null ? '' : JSON.stringify(obj, null, 2);
  const segments = highlightSuppressedBy(pretty);

  return (
    <pre
      data-testid="audit-pane"
      style={{
        backgroundColor: theme.bg,
        color: theme.fg,
        fontFamily:
          '"JetBrains Mono", "Fira Code", "Menlo", "Consolas", monospace',
        fontSize,
        lineHeight: 1.4,
        padding: 24,
        margin: 0,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        height: '100%',
        boxSizing: 'border-box',
        overflow: 'hidden',
      }}
    >
      {segments.map((seg, i) =>
        seg.highlighted ? (
          <span
            key={i}
            data-suppressed-by="true"
            style={{ color: theme.accent }}
          >
            {seg.text}
          </span>
        ) : (
          <span key={i}>{seg.text}</span>
        ),
      )}
    </pre>
  );
};
