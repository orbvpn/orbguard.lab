package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"orbguard-lab/internal/config"
	"orbguard-lab/pkg/logger"
)

// NATSPublisher handles publishing events to NATS JetStream
type NATSPublisher struct {
	conn   *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream
	config config.NATSConfig
	logger *logger.Logger

	mu        sync.RWMutex
	connected bool
}

// NewNATSPublisher creates a new NATS publisher
func NewNATSPublisher(ctx context.Context, cfg config.NATSConfig, log *logger.Logger) (*NATSPublisher, error) {
	log = log.WithComponent("nats")

	if cfg.URL == "" {
		cfg.URL = nats.DefaultURL
	}
	if cfg.StreamName == "" {
		cfg.StreamName = "ORBGUARD_THREATS"
	}

	log.Info().Str("url", cfg.URL).Str("stream", cfg.StreamName).Msg("connecting to NATS")

	// Connect to NATS
	conn, err := nats.Connect(cfg.URL,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn().Err(err).Msg("NATS disconnected")
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info().Msg("NATS reconnected")
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Info().Msg("NATS connection closed")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// Create JetStream context
	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	// Create or get the stream
	streamCfg := jetstream.StreamConfig{
		Name:        cfg.StreamName,
		Description: "OrbGuard threat intelligence events",
		Subjects:    []string{"threats.>"},
		Retention:   jetstream.LimitsPolicy,
		MaxAge:      24 * time.Hour, // Keep events for 24 hours
		MaxMsgs:     100000,         // Max 100k messages
		MaxBytes:    100 * 1024 * 1024, // 100MB
		Discard:     jetstream.DiscardOld,
		Storage:     jetstream.FileStorage,
		Replicas:    1,
	}

	stream, err := js.CreateOrUpdateStream(ctx, streamCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}

	log.Info().Str("stream", stream.CachedInfo().Config.Name).Msg("NATS stream ready")

	return &NATSPublisher{
		conn:      conn,
		js:        js,
		stream:    stream,
		config:    cfg,
		logger:    log,
		connected: true,
	}, nil
}

// Close closes the NATS connection
func (p *NATSPublisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conn != nil {
		p.conn.Close()
		p.connected = false
	}
}

// IsConnected returns whether NATS is connected
func (p *NATSPublisher) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected && p.conn.IsConnected()
}

// PublishThreatEvent publishes a threat event to NATS
func (p *NATSPublisher) PublishThreatEvent(ctx context.Context, event *ThreatEvent) error {
	if !p.IsConnected() {
		return fmt.Errorf("NATS not connected")
	}

	// Determine subject based on event type and severity
	subject := p.getSubject(event)

	// Serialize event
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Publish with acknowledgement
	_, err = p.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.logger.Debug().
		Str("subject", subject).
		Str("event_type", string(event.Type)).
		Str("indicator", event.IndicatorValue).
		Msg("published threat event")

	return nil
}

// PublishSourceUpdate publishes a source update event
func (p *NATSPublisher) PublishSourceUpdate(ctx context.Context, event *SourceUpdateEvent) error {
	if !p.IsConnected() {
		return fmt.Errorf("NATS not connected")
	}

	subject := fmt.Sprintf("threats.source.%s", event.SourceSlug)

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	_, err = p.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.logger.Debug().
		Str("subject", subject).
		Str("source", event.SourceSlug).
		Bool("success", event.Success).
		Int("new_indicators", event.NewIndicators).
		Msg("published source update event")

	return nil
}

// getSubject returns the NATS subject for an event
func (p *NATSPublisher) getSubject(event *ThreatEvent) string {
	// Subject hierarchy: threats.<event_type>.<severity>.<platform>
	// Example: threats.new_threat.critical.android

	severity := string(event.Severity)
	if severity == "" {
		severity = "unknown"
	}

	platform := "all"
	if len(event.Platforms) == 1 {
		platform = event.Platforms[0]
	}

	return fmt.Sprintf("threats.%s.%s.%s", event.Type, severity, platform)
}

// Subscribe creates a subscription to threat events
func (p *NATSPublisher) Subscribe(ctx context.Context, sub *Subscription) (<-chan *ThreatEvent, error) {
	if !p.IsConnected() {
		return nil, fmt.Errorf("NATS not connected")
	}

	// Build subject pattern based on subscription
	subject := p.buildSubscriptionSubject(sub)

	// Create consumer
	consumerCfg := jetstream.ConsumerConfig{
		Durable:       "", // Ephemeral consumer
		DeliverPolicy: jetstream.DeliverNewPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    3,
		FilterSubject: subject,
	}

	consumer, err := p.stream.CreateOrUpdateConsumer(ctx, consumerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer: %w", err)
	}

	// Create channel for events
	eventCh := make(chan *ThreatEvent, 100)

	// Start consuming
	go func() {
		defer close(eventCh)

		msgs, err := consumer.Messages()
		if err != nil {
			p.logger.Error().Err(err).Msg("failed to get messages iterator")
			return
		}
		defer msgs.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := msgs.Next()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					p.logger.Warn().Err(err).Msg("error getting next message")
					continue
				}

				var event ThreatEvent
				if err := json.Unmarshal(msg.Data(), &event); err != nil {
					p.logger.Warn().Err(err).Msg("failed to unmarshal event")
					msg.Nak()
					continue
				}

				// Apply subscription filters
				if sub.Matches(&event) {
					select {
					case eventCh <- &event:
						msg.Ack()
					case <-ctx.Done():
						return
					}
				} else {
					msg.Ack() // Acknowledge but don't send
				}
			}
		}
	}()

	return eventCh, nil
}

// buildSubscriptionSubject builds a NATS subject pattern from subscription
func (p *NATSPublisher) buildSubscriptionSubject(sub *Subscription) string {
	// Default: all threats
	if sub == nil {
		return "threats.>"
	}

	// For now, use wildcard and filter in code
	// Could optimize with more specific subjects if needed
	return "threats.>"
}
