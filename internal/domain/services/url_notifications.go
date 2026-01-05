package services

import (
	"context"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// URLNotificationPublisher publishes URL block notifications
type URLNotificationPublisher interface {
	PublishURLBlock(ctx context.Context, event *URLBlockEvent) error
}

// URLBlockEvent represents a URL blocking notification event
type URLBlockEvent struct {
	ID          string           `json:"id"`
	Type        string           `json:"type"` // "url_blocked"
	Timestamp   time.Time        `json:"timestamp"`
	DeviceID    string           `json:"device_id"`
	URL         string           `json:"url"`
	Domain      string           `json:"domain"`
	Category    models.URLCategory `json:"category"`
	ThreatLevel models.Severity  `json:"threat_level"`
	Confidence  float64          `json:"confidence"`
	Reason      string           `json:"reason"`
	Source      string           `json:"source"` // "browser", "vpn", "accessibility"
	Actions     []URLBlockAction `json:"actions,omitempty"`
}

// URLBlockAction represents an action for a blocked URL
type URLBlockAction struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Action string `json:"action"` // "whitelist", "proceed", "back", "report"
}

// URLNotificationService handles URL blocking notifications
type URLNotificationService struct {
	publisher URLNotificationPublisher
	logger    *logger.Logger
}

// NewURLNotificationService creates a new notification service
func NewURLNotificationService(publisher URLNotificationPublisher, log *logger.Logger) *URLNotificationService {
	return &URLNotificationService{
		publisher: publisher,
		logger:    log.WithComponent("url-notifications"),
	}
}

// NotifyBlock sends a real-time notification for a blocked URL
func (s *URLNotificationService) NotifyBlock(ctx context.Context, result *models.URLCheckResponse, deviceID string, source string) error {
	if !result.ShouldBlock {
		return nil
	}

	// Create notification event
	event := &URLBlockEvent{
		ID:          uuid.New().String(),
		Type:        "url_blocked",
		Timestamp:   time.Now(),
		DeviceID:    deviceID,
		URL:         result.URL,
		Domain:      result.Domain,
		Category:    result.Category,
		ThreatLevel: result.ThreatLevel,
		Confidence:  result.Confidence,
		Reason:      result.BlockReason,
		Source:      source,
	}

	// Add actions based on threat level
	event.Actions = s.getActionsForBlock(result)

	// Publish notification
	if s.publisher != nil {
		if err := s.publisher.PublishURLBlock(ctx, event); err != nil {
			s.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to publish URL block notification")
			return err
		}
	}

	s.logger.Info().
		Str("device_id", deviceID).
		Str("url", result.URL).
		Str("category", string(result.Category)).
		Str("source", source).
		Msg("URL block notification sent")

	return nil
}

// getActionsForBlock returns available actions for a blocked URL
func (s *URLNotificationService) getActionsForBlock(result *models.URLCheckResponse) []URLBlockAction {
	actions := []URLBlockAction{
		{
			ID:     "back",
			Label:  "Go Back",
			Action: "back",
		},
	}

	// Add proceed with caution if override is allowed
	if result.AllowOverride {
		actions = append(actions, URLBlockAction{
			ID:     "proceed",
			Label:  "Proceed Anyway",
			Action: "proceed",
		})

		// Add whitelist option for lower threat levels
		if result.ThreatLevel == models.SeverityLow || result.ThreatLevel == models.SeverityMedium {
			actions = append(actions, URLBlockAction{
				ID:     "whitelist",
				Label:  "Add to Whitelist",
				Action: "whitelist",
			})
		}
	}

	// Always add report option
	actions = append(actions, URLBlockAction{
		ID:     "report",
		Label:  "Report False Positive",
		Action: "report",
	})

	return actions
}

// BlockNotificationContent returns the notification display content
func (s *URLNotificationService) BlockNotificationContent(result *models.URLCheckResponse) URLNotificationContent {
	content := URLNotificationContent{
		ChannelID: "url_protection",
	}

	switch result.ThreatLevel {
	case models.SeverityCritical:
		content.Title = "Dangerous Website Blocked"
		content.Priority = "max"
		content.Vibrate = true
		content.Sound = "alarm"
		content.Color = "#FF0000"
	case models.SeverityHigh:
		content.Title = "Harmful Website Blocked"
		content.Priority = "high"
		content.Vibrate = true
		content.Sound = "warning"
		content.Color = "#FF6600"
	case models.SeverityMedium:
		content.Title = "Suspicious Website Blocked"
		content.Priority = "default"
		content.Vibrate = false
		content.Sound = "default"
		content.Color = "#FFCC00"
	default:
		content.Title = "Website Blocked"
		content.Priority = "low"
		content.Vibrate = false
		content.Sound = ""
		content.Color = "#FFFF00"
	}

	// Set body based on category
	switch result.Category {
	case models.URLCategoryPhishing:
		content.Body = "This website attempts to steal your personal information. Access has been blocked for your protection."
	case models.URLCategoryMalware:
		content.Body = "This website contains harmful software that could damage your device. Access has been blocked."
	case models.URLCategoryScam:
		content.Body = "This website is associated with scams. Access has been blocked for your protection."
	case models.URLCategoryC2:
		content.Body = "This website is used for malware control. Access has been blocked immediately."
	case models.URLCategoryRansomware:
		content.Body = "This website is associated with ransomware. Access has been blocked for your protection."
	case models.URLCategoryCryptojacking:
		content.Body = "This website attempts to mine cryptocurrency using your device. Access has been blocked."
	default:
		content.Body = result.BlockReason
	}

	return content
}

// URLNotificationContent represents the notification display content
type URLNotificationContent struct {
	ChannelID string `json:"channel_id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Priority  string `json:"priority"` // max, high, default, low, min
	Vibrate   bool   `json:"vibrate"`
	Sound     string `json:"sound"`
	Color     string `json:"color"`
}

// URLEventBusPublisher implements URLNotificationPublisher using the event bus
type URLEventBusPublisher struct {
	eventBus EventPublisher
}

// NewURLEventBusPublisher creates a new URL event bus publisher
func NewURLEventBusPublisher(eventBus EventPublisher) *URLEventBusPublisher {
	return &URLEventBusPublisher{
		eventBus: eventBus,
	}
}

// PublishURLBlock publishes a URL block event to the event bus
func (p *URLEventBusPublisher) PublishURLBlock(ctx context.Context, event *URLBlockEvent) error {
	// Convert to generic threat indicator for the event bus
	indicator := &models.Indicator{
		ID:          uuid.New(),
		Value:       event.URL,
		Type:        models.IndicatorTypeURL,
		Severity:    event.ThreatLevel,
		Confidence:  event.Confidence,
		Description: event.Reason,
		Tags:        []string{"blocked", string(event.Category), event.Source},
		FirstSeen:   event.Timestamp,
		LastSeen:    event.Timestamp,
	}

	return p.eventBus.PublishNewThreat(ctx, indicator, "url-protection", "URL Protection")
}
