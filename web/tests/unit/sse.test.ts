import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { connectSse } from '../../src/lib/sse';

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }
  close(): void {
    this.closed = true;
  }
  fireError(): void {
    this.onerror?.(new Event('error'));
  }
  fireMessage(data: unknown): void {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent);
  }
}

describe('connectSse', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeEventSource.instances = [];
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('reconnects with exponential backoff after error', () => {
    const messages: unknown[] = [];
    const conn = connectSse({
      url: '/api/decisions/stream',
      onMessage: (m) => messages.push(m),
      factory: (u) => new FakeEventSource(u) as unknown as EventSource,
      initialBackoffMs: 100,
      maxBackoffMs: 1_000,
    });

    expect(FakeEventSource.instances).toHaveLength(1);
    FakeEventSource.instances[0].fireError();
    expect(conn.reconnectCount()).toBe(1);

    // First reconnect after 100ms.
    vi.advanceTimersByTime(100);
    expect(FakeEventSource.instances).toHaveLength(2);

    FakeEventSource.instances[1].fireError();
    expect(conn.reconnectCount()).toBe(2);

    // Second reconnect after 200ms (backoff doubled).
    vi.advanceTimersByTime(199);
    expect(FakeEventSource.instances).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeEventSource.instances).toHaveLength(3);

    conn.close();
    expect(FakeEventSource.instances[2].closed).toBe(true);
  });

  it('resets backoff on successful message', () => {
    let received = 0;
    const conn = connectSse<{ ok: boolean }>({
      url: '/api/decisions/stream',
      onMessage: () => {
        received += 1;
      },
      factory: (u) => new FakeEventSource(u) as unknown as EventSource,
      initialBackoffMs: 100,
    });

    FakeEventSource.instances[0].fireMessage({ ok: true });
    expect(received).toBe(1);
    FakeEventSource.instances[0].fireError();
    vi.advanceTimersByTime(100);
    expect(FakeEventSource.instances).toHaveLength(2);

    conn.close();
  });
});
