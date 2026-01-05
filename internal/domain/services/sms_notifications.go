package services

import (
	"context"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// SMSNotificationPublisher publishes SMS threat notifications
type SMSNotificationPublisher interface {
	PublishSMSThreat(ctx context.Context, event *SMSThreatEvent) error
}

// SMSThreatEvent represents an SMS threat notification event
type SMSThreatEvent struct {
	ID           string              `json:"id"`
	Type         string              `json:"type"` // "sms_threat"
	Timestamp    time.Time           `json:"timestamp"`
	DeviceID     string              `json:"device_id"`
	ThreatLevel  models.ThreatLevel  `json:"threat_level"`
	ThreatType   models.SMSThreatType `json:"threat_type"`
	Confidence   float64             `json:"confidence"`
	Sender       string              `json:"sender"`
	Preview      string              `json:"preview"` // First 50 chars of message
	Description  string              `json:"description"`
	URLs         []string            `json:"malicious_urls,omitempty"`
	Actions      []NotificationAction `json:"actions,omitempty"`
}

// NotificationAction represents an action the user can take
type NotificationAction struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Action string `json:"action"` // "block_sender", "report", "delete", "view_details"
}

// SMSNotificationService handles SMS threat notifications
type SMSNotificationService struct {
	publisher SMSNotificationPublisher
	logger    *logger.Logger
}

// NewSMSNotificationService creates a new notification service
func NewSMSNotificationService(publisher SMSNotificationPublisher, log *logger.Logger) *SMSNotificationService {
	return &SMSNotificationService{
		publisher: publisher,
		logger:    log.WithComponent("sms-notifications"),
	}
}

// NotifyThreat sends a real-time notification for an SMS threat
func (s *SMSNotificationService) NotifyThreat(ctx context.Context, result *models.SMSAnalysisResult, msg *models.SMSMessage) error {
	if !result.IsThreat {
		return nil
	}

	// Create notification event
	event := &SMSThreatEvent{
		ID:          uuid.New().String(),
		Type:        "sms_threat",
		Timestamp:   time.Now(),
		DeviceID:    msg.DeviceID,
		ThreatLevel: result.ThreatLevel,
		ThreatType:  result.ThreatType,
		Confidence:  result.Confidence,
		Sender:      msg.Sender,
		Preview:     truncateString(msg.Body, 50),
		Description: result.Description,
	}

	// Add malicious URLs
	for _, u := range result.URLs {
		if u.IsMalicious {
			event.URLs = append(event.URLs, u.URL)
		}
	}

	// Add actions based on threat level
	event.Actions = s.getActionsForThreat(result)

	// Publish notification
	if s.publisher != nil {
		if err := s.publisher.PublishSMSThreat(ctx, event); err != nil {
			s.logger.Error().Err(err).Str("device_id", msg.DeviceID).Msg("failed to publish SMS threat notification")
			return err
		}
	}

	s.logger.Info().
		Str("device_id", msg.DeviceID).
		Str("threat_level", string(result.ThreatLevel)).
		Str("threat_type", string(result.ThreatType)).
		Msg("SMS threat notification sent")

	return nil
}

// getActionsForThreat returns recommended actions based on threat type
func (s *SMSNotificationService) getActionsForThreat(result *models.SMSAnalysisResult) []NotificationAction {
	actions := []NotificationAction{
		{
			ID:     "view_details",
			Label:  "View Details",
			Action: "view_details",
		},
	}

	// Critical threats get immediate actions
	if result.ThreatLevel == models.ThreatLevelCritical || result.ThreatLevel == models.ThreatLevelHigh {
		actions = append([]NotificationAction{
			{
				ID:     "block_sender",
				Label:  "Block Sender",
				Action: "block_sender",
			},
			{
				ID:     "delete",
				Label:  "Delete Message",
				Action: "delete",
			},
		}, actions...)
	}

	// Report option for all threats
	actions = append(actions, NotificationAction{
		ID:     "report",
		Label:  "Report to Carrier",
		Action: "report",
	})

	return actions
}

// NotificationTemplate returns a notification template for the threat
func (s *SMSNotificationService) NotificationTemplate(result *models.SMSAnalysisResult) NotificationContent {
	content := NotificationContent{
		ChannelID: "sms_threats",
	}

	switch result.ThreatLevel {
	case models.ThreatLevelCritical:
		content.Title = "CRITICAL: Dangerous SMS Detected"
		content.Priority = "max"
		content.Vibrate = true
		content.Sound = "alarm"
		content.Color = "#FF0000"
	case models.ThreatLevelHigh:
		content.Title = "Warning: Suspicious SMS Detected"
		content.Priority = "high"
		content.Vibrate = true
		content.Sound = "warning"
		content.Color = "#FF6600"
	case models.ThreatLevelMedium:
		content.Title = "Caution: Potentially Unsafe SMS"
		content.Priority = "default"
		content.Vibrate = false
		content.Sound = "default"
		content.Color = "#FFCC00"
	default:
		content.Title = "SMS Security Alert"
		content.Priority = "low"
		content.Vibrate = false
		content.Sound = ""
		content.Color = "#FFFF00"
	}

	// Set body based on threat type
	switch result.ThreatType {
	case models.SMSThreatTypeExecutiveImpersonation:
		content.Body = "This message appears to be an executive impersonation scam. Do NOT send money or gift cards."
	case models.SMSThreatTypeBankFraud:
		content.Body = "This message pretends to be from your bank. Do NOT click any links or share information."
	case models.SMSThreatTypeDeliveryScam:
		content.Body = "This is a fake delivery notification. Do NOT click the tracking link."
	case models.SMSThreatTypePhishing:
		content.Body = "This message contains a phishing link. Do NOT enter any information."
	case models.SMSThreatTypeScam:
		content.Body = "This message appears to be a scam. Ignore and delete."
	default:
		content.Body = result.Description
	}

	return content
}

// NotificationContent represents the notification display content
type NotificationContent struct {
	ChannelID string `json:"channel_id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Priority  string `json:"priority"` // max, high, default, low, min
	Vibrate   bool   `json:"vibrate"`
	Sound     string `json:"sound"`
	Color     string `json:"color"`
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// SMSEventBusPublisher implements SMSNotificationPublisher using the event bus
type SMSEventBusPublisher struct {
	eventBus EventPublisher
}

// NewSMSEventBusPublisher creates a new SMS event bus publisher
func NewSMSEventBusPublisher(eventBus EventPublisher) *SMSEventBusPublisher {
	return &SMSEventBusPublisher{
		eventBus: eventBus,
	}
}

// PublishSMSThreat publishes an SMS threat event
func (p *SMSEventBusPublisher) PublishSMSThreat(ctx context.Context, event *SMSThreatEvent) error {
	// Convert to generic threat indicator for the event bus
	indicator := &models.Indicator{
		ID:          uuid.New(),
		Value:       event.Preview,
		Type:        models.IndicatorTypeURL, // Use URL type for SMS threats
		Severity:    severityFromThreatLevel(event.ThreatLevel),
		Confidence:  event.Confidence,
		Description: event.Description,
		Tags:        []string{"sms", "smishing", string(event.ThreatType)},
		FirstSeen:   event.Timestamp,
		LastSeen:    event.Timestamp,
	}

	return p.eventBus.PublishNewThreat(ctx, indicator, "sms-scanner", "SMS Scanner")
}

// severityFromThreatLevel converts ThreatLevel to Severity
func severityFromThreatLevel(level models.ThreatLevel) models.Severity {
	switch level {
	case models.ThreatLevelCritical:
		return models.SeverityCritical
	case models.ThreatLevelHigh:
		return models.SeverityHigh
	case models.ThreatLevelMedium:
		return models.SeverityMedium
	case models.ThreatLevelLow:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}
