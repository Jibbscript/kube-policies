package policymanager

import (
	"sync"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

// Ring is a fixed-capacity ring-buffered store of recent audit.PublicEvents.
// Concurrent-safe; reads return a copy so callers can iterate without holding the lock.
type Ring struct {
	mu       sync.RWMutex
	items    []audit.PublicEvent
	capacity int
	// next is the index where the next Add will write.
	next int
	// full reports whether the buffer has wrapped at least once.
	full bool
}

// NewRing constructs a Ring with the given capacity. capacity <= 0 is
// normalized to 1 to avoid pathological zero-length buffers.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 1
	}
	return &Ring{
		items:    make([]audit.PublicEvent, capacity),
		capacity: capacity,
	}
}

// Add inserts ev at the next slot, overwriting the oldest entry once full.
func (r *Ring) Add(ev audit.PublicEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[r.next] = ev
	r.next = (r.next + 1) % r.capacity
	if r.next == 0 {
		r.full = true
	}
}

// Recent returns up to `limit` most-recent events, newest first.
func (r *Ring) Recent(limit int) []audit.PublicEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var size int
	if r.full {
		size = r.capacity
	} else {
		size = r.next
	}
	if limit < 0 || limit > size {
		limit = size
	}
	out := make([]audit.PublicEvent, 0, limit)
	// Walk backwards from the most-recent write.
	for i := 0; i < limit; i++ {
		idx := (r.next - 1 - i + r.capacity) % r.capacity
		out = append(out, r.items[idx])
	}
	return out
}

// Len returns the current count of stored events (0..capacity).
func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.full {
		return r.capacity
	}
	return r.next
}
