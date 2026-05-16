package audit

import (
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

const defaultBufSize = 256

// Bus is an in-process fan-out pub-sub for PublicEvent. Each subscriber holds
// its own bounded channel; when that channel is full the oldest event is evicted
// to make room for the newest (drop-oldest semantics). Publish never blocks the
// caller regardless of subscriber count or speed.
type Bus struct {
	mu     sync.RWMutex
	subs   map[uint64]chan PublicEvent
	nextID uint64
	bufSz  int
	log    *zap.Logger
	once   sync.Once
	closed atomic.Bool
}

// NewBus constructs a Bus with the given per-subscriber buffer size.
// bufSize <= 0 defaults to 256.
func NewBus(bufSize int, log *zap.Logger) *Bus {
	if bufSize <= 0 {
		bufSize = defaultBufSize
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Bus{
		subs:  make(map[uint64]chan PublicEvent),
		bufSz: bufSize,
		log:   log,
	}
}

// Subscribe returns a receive-only channel of PublicEvent and a cancel function.
// The channel is closed when cancel() is called or when Bus.Close() is called.
// Calling cancel() more than once is safe.
func (b *Bus) Subscribe() (<-chan PublicEvent, func()) {
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	ch := make(chan PublicEvent, b.bufSz)
	b.subs[id] = ch
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(ch)
		}
		// If already removed by Close(), nothing to do — idempotent.
	}
	return ch, cancel
}

// Publish posts ev to all current subscribers. It is non-blocking: if a
// subscriber's buffer is full the oldest event in that buffer is dropped to
// make room, and a structured warning is logged. Publish is a no-op after Close.
func (b *Bus) Publish(ev PublicEvent) {
	if b.closed.Load() {
		return
	}
	// RLock guards iteration of the subs map. Close() holds the write lock
	// before closing channels, so channels are always open while we hold RLock.
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		b.sendOne(ch, ev)
	}
}

// sendOne delivers ev to a single subscriber channel using drop-oldest semantics.
//
// Two-step approach (neither step holds any mutex, so no deadlock risk):
//  1. Non-blocking send — succeeds on the fast path.
//  2. On default (buffer full): drain the oldest element to free a slot, then
//     retry the send once. If a concurrent publisher raced us and refilled the
//     slot we log the drop and move on.
func (b *Bus) sendOne(ch chan PublicEvent, ev PublicEvent) {
	select {
	case ch <- ev:
		// Fast path: slot available.
	default:
		// Buffer full — evict the oldest event then send the new one.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- ev:
		default:
			// Rare: a concurrent publisher raced us and refilled the slot.
			// ev is dropped here too; log below covers both cases.
		}
		b.log.Warn("audit pubsub: subscriber buffer full, oldest event dropped",
			zap.String("decision", ev.Decision),
			zap.String("kind", ev.Kind),
		)
	}
}

// Close drains and closes all subscriber channels. Subsequent Publish calls are
// no-ops. Close is idempotent — multiple calls are safe.
func (b *Bus) Close() {
	b.once.Do(func() {
		// Mark closed before acquiring the write lock so that any Publish that
		// checks closed.Load() after we release the lock is also a no-op.
		b.closed.Store(true)
		b.mu.Lock()
		defer b.mu.Unlock()
		for id, ch := range b.subs {
			close(ch)
			delete(b.subs, id)
		}
	})
}

// NumSubscribers returns the current number of registered subscribers.
// Useful for testing and metrics.
func (b *Bus) NumSubscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
