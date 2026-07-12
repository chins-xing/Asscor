package kernel

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBus_PublishSubscribe(t *testing.T) {
	bus := NewBus(10)
	var received atomic.Int32
	bus.Subscribe("test.topic", "sub1", func(ctx context.Context, msg Message) error {
		received.Add(1)
		return nil
	})
	bus.Publish(context.Background(), Message{Topic: "test.topic", Payload: "hello", Source: "test"})
	time.Sleep(50 * time.Millisecond)
	if received.Load() != 1 {
		t.Errorf("expected 1 message, got %d", received.Load())
	}
}

func TestBus_PublishSync(t *testing.T) {
	bus := NewBus(10)
	var received atomic.Int32
	bus.Subscribe("test.sync", "sub1", func(ctx context.Context, msg Message) error {
		received.Add(1)
		return nil
	})
	errs := bus.PublishSync(context.Background(), Message{Topic: "test.sync", Payload: "sync", Source: "test"})
	if len(errs) != 0 {
		t.Errorf("unexpected publish errors: %v", errs)
	}
	if received.Load() != 1 {
		t.Errorf("expected 1, got %d", received.Load())
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	bus := NewBus(10)
	var c1, c2 atomic.Int32
	bus.Subscribe("test.multi", "sub1", func(ctx context.Context, msg Message) error {
		c1.Add(1)
		return nil
	})
	bus.Subscribe("test.multi", "sub2", func(ctx context.Context, msg Message) error {
		c2.Add(1)
		return nil
	})
	bus.Publish(context.Background(), Message{Topic: "test.multi", Source: "test"})
	time.Sleep(50 * time.Millisecond)
	if c1.Load() != 1 || c2.Load() != 1 {
		t.Errorf("expected 1 each, got c1=%d c2=%d", c1.Load(), c2.Load())
	}
}

func TestBus_StopGracefulDrain(t *testing.T) {
	bus := NewBus(10)
	var wg sync.WaitGroup
	wg.Add(1)
	bus.Subscribe("test.stop", "sub1", func(ctx context.Context, msg Message) error {
		time.Sleep(100 * time.Millisecond)
		wg.Done()
		return nil
	})
	bus.Publish(context.Background(), Message{Topic: "test.stop", Source: "test"})
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	bus.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("bus Stop did not drain in-flight handlers")
	}
}

func TestBus_TopicIsolation(t *testing.T) {
	bus := NewBus(10)
	var count atomic.Int32
	bus.Subscribe("topic.a", "sub1", func(ctx context.Context, msg Message) error {
		count.Add(1)
		return nil
	})
	bus.Publish(context.Background(), Message{Topic: "topic.b", Source: "test"})
	time.Sleep(50 * time.Millisecond)
	if count.Load() != 0 {
		t.Errorf("expected 0 (topic isolation), got %d", count.Load())
	}
}
