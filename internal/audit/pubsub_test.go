package audit

import (
	"testing"
	"time"
)

// makeEv is a test helper that creates a minimal PublicEvent with the given
// decision string so test assertions stay readable.
func makeEv(decision string) PublicEvent {
	return PublicEvent{Decision: decision, Kind: "Pod", Timestamp: time.Now()}
}

func TestBus_SubscribePublishReceive(t *testing.T) {
	b := NewBus(8, nil)
	defer b.Close()

	ch, cancel := b.Subscribe()
	defer cancel()

	b.Publish(makeEv("ALLOW"))

	select {
	case ev := <-ch:
		if ev.Decision != "ALLOW" {
			t.Errorf("want ALLOW, got %q", ev.Decision)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestBus_MultipleSubscribersAllReceive(t *testing.T) {
	b := NewBus(8, nil)
	defer b.Close()

	ch1, cancel1 := b.Subscribe()
	defer cancel1()
	ch2, cancel2 := b.Subscribe()
	defer cancel2()
	ch3, cancel3 := b.Subscribe()
	defer cancel3()

	b.Publish(makeEv("DENY"))

	for i, ch := range []<-chan PublicEvent{ch1, ch2, ch3} {
		select {
		case ev := <-ch:
			if ev.Decision != "DENY" {
				t.Errorf("subscriber %d: want DENY, got %q", i+1, ev.Decision)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timeout waiting for event", i+1)
		}
	}
}

func TestBus_CancelClosesChannelOtherUnaffected(t *testing.T) {
	b := NewBus(8, nil)
	defer b.Close()

	ch1, cancel1 := b.Subscribe()
	ch2, cancel2 := b.Subscribe()
	defer cancel2()

	cancel1()

	// ch1 must be closed.
	select {
	case _, ok := <-ch1:
		if ok {
			t.Error("expected ch1 to be closed after cancel, but received a value")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: ch1 not closed after cancel")
	}

	// ch2 must still work.
	b.Publish(makeEv("ALLOW"))
	select {
	case ev := <-ch2:
		if ev.Decision != "ALLOW" {
			t.Errorf("ch2: want ALLOW, got %q", ev.Decision)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: ch2 did not receive after ch1 was canceled")
	}

	if b.NumSubscribers() != 1 {
		t.Errorf("NumSubscribers: want 1 after cancel, got %d", b.NumSubscribers())
	}
}

func TestBus_DropOldest(t *testing.T) {
	// bufSize=1: the channel holds at most one event at a time.
	// Publishing 3 events without reading means each new event evicts the previous.
	// The final state must be exactly [C] — the newest/last event.
	b := NewBus(1, nil)
	defer b.Close()

	ch, cancel := b.Subscribe()
	defer cancel()

	// Do NOT read between publishes — simulate a slow subscriber.
	b.Publish(makeEv("A"))
	b.Publish(makeEv("B"))
	b.Publish(makeEv("C"))

	select {
	case ev := <-ch:
		if ev.Decision != "C" {
			t.Errorf("drop-oldest: want C (newest), got %q", ev.Decision)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event after drop-oldest")
	}

	// Channel must now be empty — A and B were dropped.
	select {
	case ev := <-ch:
		t.Errorf("expected empty channel after receiving C, got extra event %q", ev.Decision)
	default:
	}
}

func TestBus_CloseIdempotent(t *testing.T) {
	b := NewBus(8, nil)
	b.Close()
	b.Close() // must not panic
	b.Close()
}

func TestBus_PublishAfterCloseIsNoop(t *testing.T) {
	b := NewBus(8, nil)
	_, cancel := b.Subscribe()
	defer cancel()

	b.Close()

	// Must not panic.
	b.Publish(makeEv("ALLOW"))
	b.Publish(makeEv("DENY"))
}

func TestBus_NumSubscribers(t *testing.T) {
	b := NewBus(8, nil)
	defer b.Close()

	if n := b.NumSubscribers(); n != 0 {
		t.Errorf("want 0 initial subscribers, got %d", n)
	}

	_, cancel1 := b.Subscribe()
	_, cancel2 := b.Subscribe()

	if n := b.NumSubscribers(); n != 2 {
		t.Errorf("want 2 subscribers, got %d", n)
	}

	cancel1()
	if n := b.NumSubscribers(); n != 1 {
		t.Errorf("want 1 subscriber after first cancel, got %d", n)
	}

	cancel2()
	if n := b.NumSubscribers(); n != 0 {
		t.Errorf("want 0 subscribers after all canceled, got %d", n)
	}
}

func TestBus_CancelAfterCloseIsNoop(t *testing.T) {
	b := NewBus(8, nil)
	_, cancel := b.Subscribe()

	b.Close()
	cancel() // must not panic (channel already closed by Bus.Close)
}

func TestBus_RaceSafe(t *testing.T) {
	// Run concurrent publishers and a subscriber to exercise the race detector.
	b := NewBus(32, nil)
	defer b.Close()

	ch, cancel := b.Subscribe()
	done := make(chan struct{})

	// Drain subscriber in background.
	go func() {
		defer close(done)
		for range ch {
		}
	}()

	// Three concurrent publishers.
	for range 3 {
		go func() {
			for range 50 {
				b.Publish(makeEv("ALLOW"))
			}
		}()
	}

	// Let publishers run, then shut down.
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
}
