/**
 * SSE client with exponential backoff reconnect.
 *
 * Even though M1 only ships poll fallback, this client ships so M2 just flips a
 * route in App.svelte from LiveDecisions polling to SSE streaming.
 */

export interface SseOptions<T> {
  url: string;
  onMessage: (event: T) => void;
  onError?: (err: Event | Error) => void;
  /** EventSource factory (overridable for tests). */
  factory?: (url: string) => EventSource;
  /** Initial backoff in ms. Default 500. */
  initialBackoffMs?: number;
  /** Cap on backoff in ms. Default 30000. */
  maxBackoffMs?: number;
}

export interface SseConnection {
  close: () => void;
  /** Public for tests — number of times reconnect has been scheduled. */
  reconnectCount: () => number;
}

export function connectSse<T = unknown>(opts: SseOptions<T>): SseConnection {
  const initial = opts.initialBackoffMs ?? 500;
  const max = opts.maxBackoffMs ?? 30_000;
  const factory = opts.factory ?? ((u: string) => new EventSource(u));

  let backoff = initial;
  let reconnects = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let es: EventSource | null = null;
  let closed = false;

  function open(): void {
    if (closed) return;
    es = factory(opts.url);
    es.onmessage = (ev: MessageEvent) => {
      // Successful message — reset backoff.
      backoff = initial;
      try {
        const data = JSON.parse(ev.data) as T;
        opts.onMessage(data);
      } catch (parseErr) {
        opts.onError?.(parseErr as Error);
      }
    };
    es.onerror = (ev: Event) => {
      opts.onError?.(ev);
      es?.close();
      es = null;
      scheduleReconnect();
    };
  }

  function scheduleReconnect(): void {
    if (closed) return;
    reconnects += 1;
    const delay = backoff;
    backoff = Math.min(backoff * 2, max);
    timer = setTimeout(open, delay);
  }

  open();

  return {
    close: () => {
      closed = true;
      if (timer) clearTimeout(timer);
      timer = null;
      es?.close();
      es = null;
    },
    reconnectCount: () => reconnects,
  };
}
