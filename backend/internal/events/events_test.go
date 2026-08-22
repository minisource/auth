package events

import (
	"testing"
	"time"

	"github.com/minisource/go-common/logging"
)

type nopLogger struct{}

func (nopLogger) Init() {}

func (nopLogger) Debug(cat logging.Category, sub logging.SubCategory, msg string, extra map[logging.ExtraKey]interface{}) {
}
func (nopLogger) Debugf(template string, args ...interface{}) {}

func (nopLogger) Info(cat logging.Category, sub logging.SubCategory, msg string, extra map[logging.ExtraKey]interface{}) {
}
func (nopLogger) Infof(template string, args ...interface{}) {}

func (nopLogger) Warn(cat logging.Category, sub logging.SubCategory, msg string, extra map[logging.ExtraKey]interface{}) {
}
func (nopLogger) Warnf(template string, args ...interface{}) {}

func (nopLogger) Error(cat logging.Category, sub logging.SubCategory, msg string, extra map[logging.ExtraKey]interface{}) {
}
func (nopLogger) Errorf(template string, args ...interface{}) {}

func (nopLogger) Fatal(cat logging.Category, sub logging.SubCategory, msg string, extra map[logging.ExtraKey]interface{}) {
}
func (nopLogger) Fatalf(template string, args ...interface{}) {}

func newTestBus() *Bus {
	return NewBus(nopLogger{})
}

func TestSubscribeAndPublish(t *testing.T) {
	b := newTestBus()
	defer b.Close()

	ch, unsubscribe := b.Subscribe(TypeLoginCompleted)
	defer unsubscribe()

	b.Publish(TypeLoginCompleted, map[string]any{"userId": "u1"})

	select {
	case ev := <-ch:
		if ev.Type != TypeLoginCompleted {
			t.Fatalf("expected %s, got %s", TypeLoginCompleted, ev.Type)
		}
		data, ok := ev.Data.(map[string]any)
		if !ok {
			t.Fatalf("expected map payload, got %T", ev.Data)
		}
		if data["userId"] != "u1" {
			t.Fatalf("unexpected payload: %v", data)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestTypeFiltering(t *testing.T) {
	b := newTestBus()
	defer b.Close()

	ch, unsubscribe := b.Subscribe(TypeLoginFailed)
	defer unsubscribe()

	// Non-matching type must not be delivered.
	b.Publish(TypeLoginCompleted, nil)

	select {
	case ev := <-ch:
		t.Fatalf("unexpected event delivered: %s", ev.Type)
	case <-time.After(100 * time.Millisecond):
		// expected — filtered out
	}

	b.Publish(TypeLoginFailed, map[string]any{"reason": "bad password"})
	select {
	case ev := <-ch:
		if ev.Type != TypeLoginFailed {
			t.Fatalf("expected %s, got %s", TypeLoginFailed, ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for filtered event")
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	b := newTestBus()
	defer b.Close()

	ch, unsubscribe := b.Subscribe()
	unsubscribe()

	// Closed channel yields zero value with ok=false.
	if _, ok := <-ch; ok {
		t.Fatal("expected channel to be closed after unsubscribe")
	}
}

func TestMultipleSubscribers(t *testing.T) {
	b := newTestBus()
	defer b.Close()

	ch1, unsub1 := b.Subscribe()
	defer unsub1()
	ch2, unsub2 := b.Subscribe()
	defer unsub2()

	b.Publish(TypeUserUpdated, map[string]any{"id": "u1"})

	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.Type != TypeUserUpdated {
				t.Fatalf("subscriber %d: expected %s, got %s", i, TypeUserUpdated, ev.Type)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out", i)
		}
	}
}

func TestSlowConsumerDoesNotBlockPublisher(t *testing.T) {
	b := newTestBus()
	defer b.Close()

	ch, unsubscribe := b.Subscribe()
	defer unsubscribe()

	// Do not drain ch — a burst fills the 128-buffer and the rest drops.
	for i := 0; i < subscriberBuffer*3; i++ {
		b.Publish(TypeLoginCompleted, nil)
	}

	done := make(chan struct{})
	go func() {
		// Publishing must not block even when the subscriber is full.
		for i := 0; i < 50; i++ {
			b.Publish(TypeLoginCompleted, nil)
		}
		close(done)
	}()

	select {
	case <-done:
		// good — publisher never blocked
	case <-time.After(time.Second):
		t.Fatal("publisher blocked on a slow subscriber")
	}

	// Sanity: the unread events are still in the channel (buffer held them).
	if len(ch) != subscriberBuffer {
		t.Fatalf("expected buffer to hold %d events, got %d", subscriberBuffer, len(ch))
	}
}

func TestCloseTerminatesSubscribers(t *testing.T) {
	b := newTestBus()

	ch, _ := b.Subscribe()
	b.Close()

	if b.Len() != 0 {
		t.Fatalf("expected 0 subscribers after Close, got %d", b.Len())
	}
	if _, ok := <-ch; ok {
		t.Fatal("expected channel to be closed after bus Close")
	}
}

func TestPublishNilData(t *testing.T) {
	b := newTestBus()
	defer b.Close()

	ch, unsubscribe := b.Subscribe(TypeSessionRevoked)
	defer unsubscribe()

	b.Publish(TypeSessionRevoked, nil) // must not panic

	select {
	case ev := <-ch:
		if ev.Type != TypeSessionRevoked {
			t.Fatalf("unexpected event: %s", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}

// TestRelayedBusNilRedisDegradesToLocal ensures the relay constructor is safe
// with a nil Redis client (local-only behavior).
func TestRelayedBusNilRedisDegradesToLocal(t *testing.T) {
	b := NewRelayedBus(nopLogger{}, nil)
	defer b.Close()

	ch, unsubscribe := b.Subscribe()
	defer unsubscribe()

	b.Publish(TypeSettingsChanged, map[string]any{"keys": []string{"a"}})

	select {
	case ev := <-ch:
		if ev.Type != TypeSettingsChanged {
			t.Fatalf("unexpected event: %s", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}
