package services

import (
	"context"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// BreachNotificationPublisher publishes breach notifications
type BreachNotificationPublisher interface {
	PublishBreach(ctx context.Context, event *BreachNotificationEvent) error
}

// BreachNotificationEvent represents a breach notification event
type BreachNotificationEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // "breach_detected", "new_breach", "password_compromised"
	Timestamp   time.Time              `json:"timestamp"`
	DeviceID    string                 `json:"device_id"`
	UserID      string                 `json:"user_id,omitempty"`
	Severity    models.BreachSeverity  `json:"severity"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	BreachName  string                 `json:"breach_name,omitempty"`
	DataExposed []string               `json:"data_exposed,omitempty"`
	Actions     []models.AlertAction   `json:"actions,omitempty"`
}

// BreachNotificationService handles breach notifications
type BreachNotificationService struct {
	publisher BreachNotificationPublisher
	logger    *logger.Logger
}

// NewBreachNotificationService creates a new breach notification service
func NewBreachNotificationService(publisher BreachNotificationPublisher, log *logger.Logger) *BreachNotificationService {
	return &BreachNotificationService{
		publisher: publisher,
		logger:    log.WithComponent("breach-notifications"),
	}
}

// NotifyEmailBreach sends a notification for an email breach
func (s *BreachNotificationService) NotifyEmailBreach(ctx context.Context, result *models.BreachCheckResponse, deviceID, userID string) error {
	if !result.IsBreached {
		return nil
	}

	event := &BreachNotificationEvent{
		ID:        uuid.New().String(),
		Type:      "breach_detected",
		Timestamp: time.Now(),
		DeviceID:  deviceID,
		UserID:    userID,
		Severity:  result.RiskLevel,
		Title:     s.getTitleForSeverity(result.RiskLevel, result.BreachCount),
		Message:   s.getMessageForBreaches(result),
	}

	// Add exposed data types
	event.DataExposed = result.ExposedDataTypes

	// Add actions
	event.Actions = s.getActionsForBreaches(result)

	if s.publisher != nil {
		if err := s.publisher.PublishBreach(ctx, event); err != nil {
			s.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to publish breach notification")
			return err
		}
	}

	s.logger.Info().
		Str("device_id", deviceID).
		Int("breach_count", result.BreachCount).
		Str("severity", string(result.RiskLevel)).
		Msg("breach notification sent")

	return nil
}

// NotifyPasswordCompromised sends a notification for a compromised password
func (s *BreachNotificationService) NotifyPasswordCompromised(ctx context.Context, result *models.PasswordCheckResponse, deviceID, userID string) error {
	if !result.IsBreached {
		return nil
	}

	severity := s.passwordRiskToSeverity(result.RiskLevel)

	event := &BreachNotificationEvent{
		ID:        uuid.New().String(),
		Type:      "password_compromised",
		Timestamp: time.Now(),
		DeviceID:  deviceID,
		UserID:    userID,
		Severity:  severity,
		Title:     "Password Compromised",
		Message:   result.Message,
		Actions: []models.AlertAction{
			{
				ID:     "change_password",
				Label:  "Change Password",
				Action: "change_password",
			},
			{
				ID:     "use_password_manager",
				Label:  "Use Password Manager",
				Action: "use_password_manager",
			},
		},
	}

	if s.publisher != nil {
		if err := s.publisher.PublishBreach(ctx, event); err != nil {
			s.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to publish password notification")
			return err
		}
	}

	s.logger.Info().
		Str("device_id", deviceID).
		Int("breach_count", result.BreachCount).
		Str("risk", result.RiskLevel).
		Msg("password compromise notification sent")

	return nil
}

// NotifyNewBreach sends a notification for a newly discovered breach
func (s *BreachNotificationService) NotifyNewBreach(ctx context.Context, alert *models.BreachAlert, asset *models.MonitoredAsset) error {
	event := &BreachNotificationEvent{
		ID:          uuid.New().String(),
		Type:        "new_breach",
		Timestamp:   time.Now(),
		DeviceID:    asset.DeviceID,
		UserID:      asset.UserID,
		Severity:    alert.Severity,
		Title:       "New Data Breach Detected",
		Message:     s.getNewBreachMessage(alert, asset),
		BreachName:  alert.BreachName,
		DataExposed: alert.DataExposed,
		Actions:     alert.Actions,
	}

	if s.publisher != nil {
		if err := s.publisher.PublishBreach(ctx, event); err != nil {
			s.logger.Error().Err(err).Msg("failed to publish new breach notification")
			return err
		}
	}

	s.logger.Warn().
		Str("asset_id", asset.ID.String()).
		Str("breach", alert.BreachName).
		Str("severity", string(alert.Severity)).
		Msg("new breach notification sent")

	return nil
}

// GetNotificationContent returns the notification display content
func (s *BreachNotificationService) GetNotificationContent(severity models.BreachSeverity, notificationType string) BreachNotificationContent {
	content := BreachNotificationContent{
		ChannelID: "breach_alerts",
	}

	switch severity {
	case models.BreachSeverityCritical:
		content.Priority = "max"
		content.Vibrate = true
		content.Sound = "alarm"
		content.Color = "#FF0000"
	case models.BreachSeverityHigh:
		content.Priority = "high"
		content.Vibrate = true
		content.Sound = "warning"
		content.Color = "#FF6600"
	case models.BreachSeverityMedium:
		content.Priority = "default"
		content.Vibrate = false
		content.Sound = "default"
		content.Color = "#FFCC00"
	default:
		content.Priority = "low"
		content.Vibrate = false
		content.Sound = ""
		content.Color = "#FFFF00"
	}

	switch notificationType {
	case "breach_detected":
		content.Title = "Data Breach Found"
		content.Body = "Your email was found in a data breach. Tap to see details and recommendations."
	case "new_breach":
		content.Title = "New Data Breach Alert"
		content.Body = "A new breach has been detected affecting your monitored data."
	case "password_compromised":
		content.Title = "Password Compromised"
		content.Body = "This password has been found in data breaches. Change it immediately."
	}

	return content
}

// BreachNotificationContent represents the notification display content
type BreachNotificationContent struct {
	ChannelID string `json:"channel_id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Priority  string `json:"priority"` // max, high, default, low, min
	Vibrate   bool   `json:"vibrate"`
	Sound     string `json:"sound"`
	Color     string `json:"color"`
}

// Helper methods

func (s *BreachNotificationService) getTitleForSeverity(severity models.BreachSeverity, breachCount int) string {
	switch severity {
	case models.BreachSeverityCritical:
		return "CRITICAL: Sensitive Data Exposed"
	case models.BreachSeverityHigh:
		return "WARNING: Data Breach Detected"
	case models.BreachSeverityMedium:
		if breachCount > 5 {
			return "Multiple Data Breaches Found"
		}
		return "Data Breach Detected"
	default:
		return "Data Breach Information"
	}
}

func (s *BreachNotificationService) getMessageForBreaches(result *models.BreachCheckResponse) string {
	if result.BreachCount == 1 {
		return "Your email was found in 1 data breach. Tap to see details and take action."
	}
	if result.BreachCount <= 5 {
		return "Your email was found in " + itoa(result.BreachCount) + " data breaches. Tap to see details."
	}
	return "Your email was found in " + itoa(result.BreachCount) + " data breaches. Review immediately."
}

func (s *BreachNotificationService) getActionsForBreaches(result *models.BreachCheckResponse) []models.AlertAction {
	actions := []models.AlertAction{
		{
			ID:     "view_details",
			Label:  "View Details",
			Action: "view_details",
		},
	}

	// Check what data was exposed
	hasPassword := false
	hasFinancial := false
	for _, dataType := range result.ExposedDataTypes {
		if dataType == "Passwords" {
			hasPassword = true
		}
		if dataType == "Credit cards" || dataType == "Bank account numbers" {
			hasFinancial = true
		}
	}

	if hasPassword {
		actions = append(actions, models.AlertAction{
			ID:     "change_passwords",
			Label:  "Change Passwords",
			Action: "change_passwords",
		})
	}

	if hasFinancial {
		actions = append(actions, models.AlertAction{
			ID:     "check_accounts",
			Label:  "Check Financial Accounts",
			Action: "check_accounts",
		})
	}

	actions = append(actions, models.AlertAction{
		ID:     "enable_2fa",
		Label:  "Enable 2FA",
		Action: "enable_2fa",
	})

	return actions
}

func (s *BreachNotificationService) getNewBreachMessage(alert *models.BreachAlert, asset *models.MonitoredAsset) string {
	return "Your " + string(asset.AssetType) + " (" + asset.DisplayName + ") was found in the " + alert.BreachName + " breach."
}

func (s *BreachNotificationService) passwordRiskToSeverity(risk string) models.BreachSeverity {
	switch risk {
	case "critical":
		return models.BreachSeverityCritical
	case "high_risk":
		return models.BreachSeverityHigh
	case "compromised":
		return models.BreachSeverityMedium
	case "weak":
		return models.BreachSeverityLow
	default:
		return models.BreachSeverityLow
	}
}

func itoa(i int) string {
	return string(rune('0'+i%10)) + string(rune('0'+i/10))
}

// BreachEventBusPublisher implements BreachNotificationPublisher using the event bus
type BreachEventBusPublisher struct {
	eventBus EventPublisher
}

// NewBreachEventBusPublisher creates a new breach event bus publisher
func NewBreachEventBusPublisher(eventBus EventPublisher) *BreachEventBusPublisher {
	return &BreachEventBusPublisher{
		eventBus: eventBus,
	}
}

// PublishBreach publishes a breach event to the event bus
func (p *BreachEventBusPublisher) PublishBreach(ctx context.Context, event *BreachNotificationEvent) error {
	// Convert breach severity to indicator severity
	var severity models.Severity
	switch event.Severity {
	case models.BreachSeverityCritical:
		severity = models.SeverityCritical
	case models.BreachSeverityHigh:
		severity = models.SeverityHigh
	case models.BreachSeverityMedium:
		severity = models.SeverityMedium
	default:
		severity = models.SeverityLow
	}

	// Create a pseudo-indicator for the event bus
	indicator := &models.Indicator{
		ID:          uuid.New(),
		Value:       event.BreachName,
		Type:        models.IndicatorTypeEmail, // Use email type for breach events
		Severity:    severity,
		Confidence:  1.0,
		Description: event.Message,
		Tags:        append([]string{"breach", event.Type}, event.DataExposed...),
		FirstSeen:   event.Timestamp,
		LastSeen:    event.Timestamp,
	}

	return p.eventBus.PublishNewThreat(ctx, indicator, "dark-web-monitor", "Dark Web Monitor")
}
