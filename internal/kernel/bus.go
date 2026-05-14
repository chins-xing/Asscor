package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"
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

type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]subscriber
	queueSize   int
}

func NewBus(queueSize int) *Bus {
	if queueSize <= 0 {
		queueSize = 256
	}
	return &Bus{
		subscribers: make(map[string][]subscriber),
		queueSize:   queueSize,
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
	b.mu.RLock()
	subs := make([]subscriber, len(b.subscribers[msg.Topic]))
	copy(subs, b.subscribers[msg.Topic])
	b.mu.RUnlock()

	for _, sub := range subs {
		go func(s subscriber) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("bus: panic in subscriber %s for topic %s: %v\n", s.id, msg.Topic, r)
				}
			}()
			_ = s.handler(ctx, msg)
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

func (b *Bus) Topics() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	topics := make([]string, 0, len(b.subscribers))
	for t := range b.subscribers {
		topics = append(topics, t)
	}
	return topics
}