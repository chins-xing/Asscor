package kernel

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type Message struct {
	ID        string
	Topic     string
	Payload   interface{}
	Timestamp time.Time
	Source    string
}

type MessageHandler func(ctx context.Context, msg Message) error

type subscriber struct {
	id      string
	handler MessageHandler
}

type BusMetrics struct {
	PanicCount   int64
	ErrorCount   int64
	MessageCount int64
}

type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]subscriber
	queueSize   int
	dispatchSem chan struct{}
	maxGoroutines chan struct{}
	metrics     BusMetrics
	stopped     int32
}

func NewBus(queueSize int) *Bus {
	if queueSize <= 0 {
		queueSize = 256
	}
	maxG := 1024
	return &Bus{
		subscribers:   make(map[string][]subscriber),
		queueSize:     queueSize,
		dispatchSem:   make(chan struct{}, queueSize),
		maxGoroutines: make(chan struct{}, maxG),
	}
}

func (b *Bus) Subscribe(topic string, id string, handler MessageHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, sub := range b.subscribers[topic] {
		if sub.id == id {
			return
		}
	}

	b.subscribers[topic] = append(b.subscribers[topic], subscriber{
		id:      id,
		handler: handler,
	})
}

func (b *Bus) Unsubscribe(topic string, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	subs := b.subscribers[topic]
	for i, sub := range subs {
		if sub.id == id {
			b.subscribers[topic] = append(subs[:i], subs[i+1:]...)
			return
		}
	}
}

func (b *Bus) UnsubscribeAll(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for topic, subs := range b.subscribers {
		filtered := subs[:0]
		for _, sub := range subs {
			if sub.id != id {
				filtered = append(filtered, sub)
			}
		}
		if len(filtered) == 0 {
			delete(b.subscribers, topic)
		} else {
			b.subscribers[topic] = filtered
		}
	}
}

func (b *Bus) Publish(ctx context.Context, msg Message) {
	if atomic.LoadInt32(&b.stopped) == 1 {
		return
	}

	b.mu.RLock()
	subs := make([]subscriber, len(b.subscribers[msg.Topic]))
	copy(subs, b.subscribers[msg.Topic])
	b.mu.RUnlock()

	atomic.AddInt64(&b.metrics.MessageCount, 1)

	for _, sub := range subs {
		select {
		case b.maxGoroutines <- struct{}{}:
		default:
			atomic.AddInt64(&b.metrics.ErrorCount, 1)
			logger.WithComponent("bus").Warn("max goroutines reached, dropping message",
				"subscriber", sub.id, "topic", msg.Topic)
			continue
		}
		go func(s subscriber) {
			acquired := false
			defer func() {
				<-b.maxGoroutines
				if acquired {
					<-b.dispatchSem
				}
				if r := recover(); r != nil {
					atomic.AddInt64(&b.metrics.PanicCount, 1)
					logger.WithComponent("bus").Error("subscriber panic", "subscriber", s.id, "topic", msg.Topic, "panic", r, "total_panics", atomic.LoadInt64(&b.metrics.PanicCount))
				}
			}()
			select {
			case b.dispatchSem <- struct{}{}:
				acquired = true
			default:
				atomic.AddInt64(&b.metrics.ErrorCount, 1)
				logger.WithComponent("bus").Warn("dispatch semaphore full, dropping message",
					"subscriber", s.id, "topic", msg.Topic,
					"queue_size", b.queueSize)
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				if err := s.handler(ctx, msg); err != nil {
					atomic.AddInt64(&b.metrics.ErrorCount, 1)
					logger.WithComponent("bus").Error("subscriber error", "subscriber", s.id, "topic", msg.Topic, "error", err)
				}
			}
		}(sub)
	}
}

func (b *Bus) PublishSync(ctx context.Context, msg Message) []error {
	b.mu.RLock()
	subs := make([]subscriber, len(b.subscribers[msg.Topic]))
	copy(subs, b.subscribers[msg.Topic])
	b.mu.RUnlock()

	errs := make([]error, 0)
	for _, sub := range subs {
		if err := sub.handler(ctx, msg); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sub.id, err))
		}
	}
	return errs
}

func (b *Bus) SubscriberCount(topic string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers[topic])
}

func (b *Bus) GetMetrics() BusMetrics {
	return BusMetrics{
		PanicCount:   atomic.LoadInt64(&b.metrics.PanicCount),
		ErrorCount:   atomic.LoadInt64(&b.metrics.ErrorCount),
		MessageCount: atomic.LoadInt64(&b.metrics.MessageCount),
	}
}

func (b *Bus) Topics() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	topics := make([]string, 0, len(b.subscribers))
	for t := range b.subscribers {
		topics = append(topics, t)
	}
	return topics
}

func (b *Bus) Stop() {
	atomic.StoreInt32(&b.stopped, 1)
	b.mu.Lock()
	b.subscribers = make(map[string][]subscriber)
	b.mu.Unlock()
}