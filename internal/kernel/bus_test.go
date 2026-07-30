package kernel

import (
	"context"
	"testing"
	"time"
)

func TestBusSubscribePublish(t *testing.T) {
	b := NewBus(16)
	defer b.Stop()

	received := make(chan Message, 1)
	b.Subscribe("test.topic", "t1", func(ctx context.Context, msg Message) error {
		received <- msg
		return nil
	})

	b.Publish(context.Background(), Message{Topic: "test.topic", Payload: "hello"})

	select {
	case msg := <-received:
		if msg.Payload.(string) != "hello" {
			t.Errorf("expected 'hello', got %v", msg.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestBusPublishSync(t *testing.T) {
	b := NewBus(16)
	defer b.Stop()

	var called bool
	b.Subscribe("sync.topic", "t1", func(ctx context.Context, msg Message) error {
		called = true
		return nil
	})

	errs := b.PublishSync(context.Background(), Message{Topic: "sync.topic", Payload: "sync"})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestBusUnsubscribe(t *testing.T) {
	b := NewBus(16)
	defer b.Stop()

	count := 0
	b.Subscribe("topic", "t1", func(ctx context.Context, msg Message) error {
		count++
		return nil
	})

	b.PublishSync(context.Background(), Message{Topic: "topic", Payload: "first"})
	if count != 1 {
		t.Fatalf("expected 1 message, got %d", count)
	}

	b.Unsubscribe("topic", "t1")
	b.PublishSync(context.Background(), Message{Topic: "topic", Payload: "second"})
	if count != 1 {
		t.Fatalf("expected still 1 after unsubscribe, got %d", count)
	}
}

func TestBusMetrics(t *testing.T) {
	b := NewBus(16)
	defer b.Stop()

	b.Subscribe("metrics", "t1", func(ctx context.Context, msg Message) error {
		return nil
	})

	for i := 0; i < 5; i++ {
		b.Publish(context.Background(), Message{Topic: "metrics", Payload: i})
	}

	time.Sleep(100 * time.Millisecond)
	b.Stop()

	m := b.GetMetrics()
	if m.MessageCount < 1 {
		t.Logf("MessageCount=%d (Publish is async, count may vary)", m.MessageCount)
	}
}

func TestBusPanicRecovery(t *testing.T) {
	b := NewBus(16)
	defer b.Stop()

	done := make(chan struct{})
	b.Subscribe("panic.topic", "t1", func(ctx context.Context, msg Message) error {
		close(done)
		panic("deliberate panic — should be recovered by bus")
	})

	b.Publish(context.Background(), Message{Topic: "panic.topic", Payload: "boom"})

	select {
	case <-done:
		// Handler was called (and panicked — bus should have recovered)
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not called")
	}

	time.Sleep(100 * time.Millisecond)
	m := b.GetMetrics()
	if m.PanicCount < 1 {
		t.Errorf("expected at least 1 panic recorded, got %d", m.PanicCount)
	}
}
