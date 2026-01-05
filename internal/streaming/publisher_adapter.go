package streaming

import (
	"context"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
)

// EventBusPublisher implements services.EventPublisher using the EventBus
type EventBusPublisher struct {
	eventBus *EventBus
	wsHub    *WebSocketHub
}

// NewEventBusPublisher creates a new publisher adapter
func NewEventBusPublisher(eventBus *EventBus, wsHub *WebSocketHub) *EventBusPublisher {
	return &EventBusPublisher{
		eventBus: eventBus,
		wsHub:    wsHub,
	}
}

// PublishNewThreat publishes an event for a new threat indicator
func (p *EventBusPublisher) PublishNewThreat(ctx context.Context, indicator *models.Indicator, sourceSlug, sourceName string) error {
	event := NewThreatEvent(EventTypeNewThreat, indicator)
	event.SourceSlug = sourceSlug
	event.SourceName = sourceName

	// Publish to event bus (NATS + local subscribers including gRPC streams)
	if p.eventBus != nil {
		if err := p.eventBus.Publish(ctx, event); err != nil {
			return err
		}
	}

	// Broadcast to WebSocket clients (mobile apps)
	if p.wsHub != nil {
		p.wsHub.BroadcastEvent(event)
	}

	return nil
}

// PublishSourceUpdate publishes a source update completion event
func (p *EventBusPublisher) PublishSourceUpdate(ctx context.Context, sourceSlug, sourceName string, success bool, newCount, updatedCount int, duration time.Duration, err error) error {
	event := &SourceUpdateEvent{
		ID:                uuid.New().String(),
		Type:              EventTypeSourceUpdated,
		Timestamp:         time.Now(),
		SourceSlug:        sourceSlug,
		SourceName:        sourceName,
		Success:           success,
		NewIndicators:     newCount,
		UpdatedIndicators: updatedCount,
		Duration:          duration,
	}

	if err != nil {
		event.Error = err.Error()
	}

	// Publish to event bus
	if p.eventBus != nil {
		return p.eventBus.PublishSourceUpdate(ctx, event)
	}

	return nil
}
