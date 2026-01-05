package streaming

import (
	"context"
	"sync"

	"orbguard-lab/pkg/logger"
)

// EventBus distributes threat events to subscribers
type EventBus struct {
	nats   *NATSPublisher
	logger *logger.Logger

	mu          sync.RWMutex
	subscribers map[string]chan *ThreatEvent
	nextID      int
}

// NewEventBus creates a new event bus
func NewEventBus(nats *NATSPublisher, log *logger.Logger) *EventBus {
	return &EventBus{
		nats:        nats,
		logger:      log.WithComponent("event-bus"),
		subscribers: make(map[string]chan *ThreatEvent),
	}
}

// Publish publishes a threat event to all subscribers
func (eb *EventBus) Publish(ctx context.Context, event *ThreatEvent) error {
	// Publish to NATS if available
	if eb.nats != nil && eb.nats.IsConnected() {
		if err := eb.nats.PublishThreatEvent(ctx, event); err != nil {
			eb.logger.Warn().Err(err).Msg("failed to publish to NATS, using local broadcast only")
		}
	}

	// Broadcast to local subscribers
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for id, ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
			eb.logger.Debug().Str("subscriber", id).Msg("subscriber channel full, dropping event")
		}
	}

	return nil
}

// PublishSourceUpdate publishes a source update event
func (eb *EventBus) PublishSourceUpdate(ctx context.Context, event *SourceUpdateEvent) error {
	if eb.nats != nil && eb.nats.IsConnected() {
		if err := eb.nats.PublishSourceUpdate(ctx, event); err != nil {
			eb.logger.Warn().Err(err).Msg("failed to publish source update to NATS")
		}
	}
	return nil
}

// Subscribe creates a new subscription and returns a channel for events
func (eb *EventBus) Subscribe(ctx context.Context, sub *Subscription) (<-chan *ThreatEvent, func()) {
	eb.mu.Lock()
	eb.nextID++
	id := string(rune(eb.nextID))
	ch := make(chan *ThreatEvent, 100)
	eb.subscribers[id] = ch
	eb.mu.Unlock()

	eb.logger.Debug().Str("subscriber_id", id).Msg("new subscriber")

	// Return unsubscribe function
	unsubscribe := func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()
		if _, ok := eb.subscribers[id]; ok {
			close(ch)
			delete(eb.subscribers, id)
			eb.logger.Debug().Str("subscriber_id", id).Msg("subscriber removed")
		}
	}

	// If NATS is available, also subscribe there for distributed events
	if eb.nats != nil && eb.nats.IsConnected() {
		natsCh, err := eb.nats.Subscribe(ctx, sub)
		if err == nil {
			// Forward NATS events to the subscriber channel
			go func() {
				for event := range natsCh {
					select {
					case ch <- event:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
	}

	return ch, unsubscribe
}

// SubscriberCount returns the number of active subscribers
func (eb *EventBus) SubscriberCount() int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers)
}

// Close closes the event bus
func (eb *EventBus) Close() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	for id, ch := range eb.subscribers {
		close(ch)
		delete(eb.subscribers, id)
	}

	if eb.nats != nil {
		eb.nats.Close()
	}
}
