package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
)

// IntegrationService handles external integrations
type IntegrationService struct {
	integrations map[uuid.UUID]*models.Integration
	deliveries   map[uuid.UUID]*models.IntegrationDelivery
	mu           sync.RWMutex
	client       *http.Client
	workers      chan struct{}
	deliveryChan chan *deliveryTask
	stopChan     chan struct{}
}

type deliveryTask struct {
	integration *models.Integration
	message     *models.IntegrationMessage
}

// NewIntegrationService creates a new integration service
func NewIntegrationService() *IntegrationService {
	s := &IntegrationService{
		integrations: make(map[uuid.UUID]*models.Integration),
		deliveries:   make(map[uuid.UUID]*models.IntegrationDelivery),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		workers:      make(chan struct{}, 10),
		deliveryChan: make(chan *deliveryTask, 1000),
		stopChan:     make(chan struct{}),
	}

	// Start worker pool
	go s.processDeliveries()

	return s
}

// processDeliveries processes the delivery queue
func (s *IntegrationService) processDeliveries() {
	for {
		select {
		case <-s.stopChan:
			return
		case task := <-s.deliveryChan:
			s.workers <- struct{}{}
			go func(t *deliveryTask) {
				defer func() { <-s.workers }()
				s.deliverMessage(context.Background(), t.integration, t.message)
			}(task)
		}
	}
}

// Stop stops the integration service
func (s *IntegrationService) Stop() {
	close(s.stopChan)
}

// CreateIntegration creates a new integration
func (s *IntegrationService) CreateIntegration(ctx context.Context, req *models.Integration) (*models.Integration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	integration := &models.Integration{
		ID:          uuid.New(),
		Name:        req.Name,
		Type:        req.Type,
		Status:      models.IntegrationStatusPending,
		Description: req.Description,
		Config:      req.Config,
		EventTypes:  req.EventTypes,
		Filters:     req.Filters,
		CreatedBy:   req.CreatedBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Validate configuration
	if err := s.validateConfig(integration); err != nil {
		return nil, err
	}

	s.integrations[integration.ID] = integration
	return integration, nil
}

// GetIntegration retrieves an integration by ID
func (s *IntegrationService) GetIntegration(ctx context.Context, id uuid.UUID) (*models.Integration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	integration, exists := s.integrations[id]
	if !exists {
		return nil, fmt.Errorf("integration not found")
	}

	return integration, nil
}

// ListIntegrations returns all integrations
func (s *IntegrationService) ListIntegrations(ctx context.Context, integrationType *models.IntegrationType) ([]*models.Integration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.Integration, 0)
	for _, integration := range s.integrations {
		if integrationType != nil && integration.Type != *integrationType {
			continue
		}
		result = append(result, integration)
	}

	return result, nil
}

// UpdateIntegration updates an integration
func (s *IntegrationService) UpdateIntegration(ctx context.Context, id uuid.UUID, req *models.Integration) (*models.Integration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	integration, exists := s.integrations[id]
	if !exists {
		return nil, fmt.Errorf("integration not found")
	}

	if req.Name != "" {
		integration.Name = req.Name
	}
	if req.Description != "" {
		integration.Description = req.Description
	}
	if req.EventTypes != nil {
		integration.EventTypes = req.EventTypes
	}
	if req.Filters != nil {
		integration.Filters = req.Filters
	}

	// Update config fields if provided
	integration.Config = req.Config

	// Validate updated config
	if err := s.validateConfig(integration); err != nil {
		return nil, err
	}

	integration.UpdatedAt = time.Now()
	return integration, nil
}

// DeleteIntegration deletes an integration
func (s *IntegrationService) DeleteIntegration(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.integrations[id]; !exists {
		return fmt.Errorf("integration not found")
	}

	delete(s.integrations, id)
	return nil
}

// EnableIntegration enables an integration
func (s *IntegrationService) EnableIntegration(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	integration, exists := s.integrations[id]
	if !exists {
		return fmt.Errorf("integration not found")
	}

	integration.Status = models.IntegrationStatusActive
	integration.UpdatedAt = time.Now()
	return nil
}

// DisableIntegration disables an integration
func (s *IntegrationService) DisableIntegration(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	integration, exists := s.integrations[id]
	if !exists {
		return fmt.Errorf("integration not found")
	}

	integration.Status = models.IntegrationStatusInactive
	integration.UpdatedAt = time.Now()
	return nil
}

// TestIntegration tests an integration configuration
func (s *IntegrationService) TestIntegration(ctx context.Context, id uuid.UUID) (*models.IntegrationTestResult, error) {
	s.mu.RLock()
	integration, exists := s.integrations[id]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("integration not found")
	}

	start := time.Now()
	testMsg := &models.IntegrationMessage{
		ID:        uuid.New(),
		EventType: "test",
		Title:     "OrbGuard Integration Test",
		Summary:   "This is a test message from OrbGuard to verify the integration is working correctly.",
		Severity:  "info",
		Fields: map[string]string{
			"Integration": integration.Name,
			"Type":        string(integration.Type),
			"Timestamp":   time.Now().Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}

	statusCode, response, err := s.sendMessage(ctx, integration, testMsg)
	latency := time.Since(start).Milliseconds()

	result := &models.IntegrationTestResult{
		StatusCode: statusCode,
		Response:   response,
		LatencyMs:  latency,
		TestedAt:   time.Now(),
	}

	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Test failed: %v", err)
	} else {
		result.Success = true
		result.Message = "Test message sent successfully"

		// Update integration status
		s.mu.Lock()
		integration.Status = models.IntegrationStatusActive
		s.mu.Unlock()
	}

	return result, nil
}

// SendNotification sends a notification through all matching integrations
func (s *IntegrationService) SendNotification(ctx context.Context, message *models.IntegrationMessage) error {
	s.mu.RLock()
	integrations := make([]*models.Integration, 0)
	for _, integration := range s.integrations {
		if integration.Status == models.IntegrationStatusActive && s.matchesFilters(integration, message) {
			integrations = append(integrations, integration)
		}
	}
	s.mu.RUnlock()

	for _, integration := range integrations {
		select {
		case s.deliveryChan <- &deliveryTask{integration: integration, message: message}:
		default:
			// Queue full, log and continue
		}
	}

	return nil
}

// matchesFilters checks if a message matches an integration's filters
func (s *IntegrationService) matchesFilters(integration *models.Integration, message *models.IntegrationMessage) bool {
	// Check event types
	if len(integration.EventTypes) > 0 {
		matched := false
		for _, et := range integration.EventTypes {
			if et == message.EventType || et == "*" {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check severity filter
	if integration.Filters != nil && integration.Filters.MinSeverity != "" {
		if !integrationSeverityAtLeast(message.Severity, integration.Filters.MinSeverity) {
			return false
		}
	}

	return true
}

// integrationSeverityAtLeast checks if severity meets minimum
func integrationSeverityAtLeast(severity, minSeverity string) bool {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	severityLevel, ok := severityOrder[severity]
	if !ok {
		return false
	}

	minLevel, ok := severityOrder[minSeverity]
	if !ok {
		return true
	}

	return severityLevel >= minLevel
}

// deliverMessage delivers a message to an integration
func (s *IntegrationService) deliverMessage(ctx context.Context, integration *models.Integration, message *models.IntegrationMessage) {
	delivery := &models.IntegrationDelivery{
		ID:            uuid.New(),
		IntegrationID: integration.ID,
		MessageID:     message.ID,
		Status:        models.DeliveryStatusPending,
		CreatedAt:     time.Now(),
	}

	s.mu.Lock()
	s.deliveries[delivery.ID] = delivery
	s.mu.Unlock()

	statusCode, response, err := s.sendMessage(ctx, integration, message)
	now := time.Now()
	delivery.LastAttemptAt = &now
	delivery.Attempts++
	delivery.StatusCode = statusCode
	delivery.Response = response

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		delivery.Status = models.DeliveryStatusFailed
		delivery.Error = err.Error()
		integration.ErrorCount++
		integration.LastError = err.Error()
		integration.LastErrorAt = &now
	} else {
		delivery.Status = models.DeliveryStatusSuccess
		integration.MessagesSent++
		integration.LastMessageAt = &now
	}
}

// sendMessage sends a message through an integration
func (s *IntegrationService) sendMessage(ctx context.Context, integration *models.Integration, message *models.IntegrationMessage) (int, string, error) {
	switch integration.Type {
	case models.IntegrationTypeSlack:
		return s.sendSlackMessage(ctx, integration, message)
	case models.IntegrationTypeTeams:
		return s.sendTeamsMessage(ctx, integration, message)
	case models.IntegrationTypePagerDuty:
		return s.sendPagerDutyEvent(ctx, integration, message)
	default:
		return 0, "", fmt.Errorf("unsupported integration type: %s", integration.Type)
	}
}

// sendSlackMessage sends a message to Slack
func (s *IntegrationService) sendSlackMessage(ctx context.Context, integration *models.Integration, message *models.IntegrationMessage) (int, string, error) {
	slackMsg := models.SlackMessage{
		Channel:   integration.Config.SlackChannel,
		Username:  integration.Config.SlackUsername,
		IconEmoji: integration.Config.SlackIconEmoji,
		Attachments: []models.SlackAttachment{
			{
				Color:     models.GetSeverityColor(message.Severity),
				Fallback:  message.Summary,
				Title:     message.Title,
				TitleLink: message.URL,
				Text:      message.Details,
				Fields:    s.buildSlackFields(message.Fields),
				Footer:    "OrbGuard Threat Intelligence",
				Ts:        message.Timestamp.Unix(),
			},
		},
	}

	if slackMsg.Username == "" {
		slackMsg.Username = "OrbGuard"
	}
	if slackMsg.IconEmoji == "" {
		slackMsg.IconEmoji = ":shield:"
	}

	return s.postJSON(ctx, integration.Config.SlackWebhookURL, slackMsg)
}

// buildSlackFields converts message fields to Slack fields
func (s *IntegrationService) buildSlackFields(fields map[string]string) []models.SlackField {
	result := make([]models.SlackField, 0, len(fields))
	for k, v := range fields {
		result = append(result, models.SlackField{
			Title: k,
			Value: v,
			Short: len(v) < 30,
		})
	}
	return result
}

// sendTeamsMessage sends a message to Microsoft Teams
func (s *IntegrationService) sendTeamsMessage(ctx context.Context, integration *models.Integration, message *models.IntegrationMessage) (int, string, error) {
	teamsMsg := models.TeamsMessage{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: models.GetSeverityColor(message.Severity)[1:], // Remove # from color
		Summary:    message.Summary,
		Title:      message.Title,
		Sections: []models.TeamsSection{
			{
				ActivityTitle:    "OrbGuard Alert",
				ActivitySubtitle: time.Now().Format(time.RFC3339),
				Text:             message.Details,
				Facts:            s.buildTeamsFacts(message.Fields),
				Markdown:         true,
			},
		},
	}

	if message.URL != "" {
		teamsMsg.Actions = []models.TeamsAction{
			{
				Type: "OpenUri",
				Name: "View Details",
				Targets: []models.TeamsActionTarget{
					{URI: message.URL},
				},
			},
		}
	}

	return s.postJSON(ctx, integration.Config.TeamsWebhookURL, teamsMsg)
}

// buildTeamsFacts converts message fields to Teams facts
func (s *IntegrationService) buildTeamsFacts(fields map[string]string) []models.TeamsFact {
	result := make([]models.TeamsFact, 0, len(fields))
	for k, v := range fields {
		result = append(result, models.TeamsFact{
			Name:  k,
			Value: v,
		})
	}
	return result
}

// sendPagerDutyEvent sends an event to PagerDuty
func (s *IntegrationService) sendPagerDutyEvent(ctx context.Context, integration *models.Integration, message *models.IntegrationMessage) (int, string, error) {
	pdSeverity := s.mapToPagerDutySeverity(message.Severity)

	pdEvent := models.PagerDutyEvent{
		RoutingKey:  integration.Config.PagerDutyRoutingKey,
		EventAction: "trigger",
		DedupKey:    message.ID.String(),
		Payload: models.PagerDutyPayload{
			Summary:   fmt.Sprintf("[%s] %s", message.Severity, message.Title),
			Source:    "OrbGuard",
			Severity:  pdSeverity,
			Timestamp: message.Timestamp.Format(time.RFC3339),
			Class:     message.EventType,
			CustomDetails: map[string]interface{}{
				"summary": message.Summary,
				"details": message.Details,
				"fields":  message.Fields,
			},
		},
		Client:    "OrbGuard",
		ClientURL: message.URL,
	}

	if message.URL != "" {
		pdEvent.Links = []models.PagerDutyLink{
			{Href: message.URL, Text: "View in OrbGuard"},
		}
	}

	return s.postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", pdEvent)
}

// mapToPagerDutySeverity maps our severity to PagerDuty severity
func (s *IntegrationService) mapToPagerDutySeverity(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// postJSON posts JSON data to a URL
func (s *IntegrationService) postJSON(ctx context.Context, url string, payload interface{}) (int, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return 0, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	var respBody bytes.Buffer
	respBody.ReadFrom(resp.Body)
	response := respBody.String()

	if resp.StatusCode >= 400 {
		return resp.StatusCode, response, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, response)
	}

	return resp.StatusCode, response, nil
}

// validateConfig validates integration configuration
func (s *IntegrationService) validateConfig(integration *models.Integration) error {
	switch integration.Type {
	case models.IntegrationTypeSlack:
		if integration.Config.SlackWebhookURL == "" {
			return fmt.Errorf("slack webhook URL is required")
		}
	case models.IntegrationTypeTeams:
		if integration.Config.TeamsWebhookURL == "" {
			return fmt.Errorf("teams webhook URL is required")
		}
	case models.IntegrationTypePagerDuty:
		if integration.Config.PagerDutyRoutingKey == "" {
			return fmt.Errorf("pagerduty routing key is required")
		}
	case models.IntegrationTypeEmail:
		if integration.Config.EmailSMTPHost == "" {
			return fmt.Errorf("email SMTP host is required")
		}
		if len(integration.Config.EmailTo) == 0 {
			return fmt.Errorf("at least one email recipient is required")
		}
	}
	return nil
}

// GetIntegrationStats returns statistics for an integration
func (s *IntegrationService) GetIntegrationStats(ctx context.Context, id uuid.UUID) (*models.IntegrationStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	integration, exists := s.integrations[id]
	if !exists {
		return nil, fmt.Errorf("integration not found")
	}

	stats := &models.IntegrationStats{
		IntegrationID:    id,
		TotalMessages:    integration.MessagesSent + integration.ErrorCount,
		SuccessfulSends:  integration.MessagesSent,
		FailedSends:      integration.ErrorCount,
		AverageLatencyMs: 50, // Would calculate from delivery history
	}

	if integration.LastMessageAt != nil {
		stats.LastSuccess = *integration.LastMessageAt
	}
	if integration.LastErrorAt != nil {
		stats.LastFailure = *integration.LastErrorAt
	}

	return stats, nil
}

// ListDeliveries returns delivery history for an integration
func (s *IntegrationService) ListDeliveries(ctx context.Context, integrationID uuid.UUID, limit int) ([]*models.IntegrationDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.IntegrationDelivery, 0)
	for _, delivery := range s.deliveries {
		if delivery.IntegrationID == integrationID {
			result = append(result, delivery)
			if len(result) >= limit {
				break
			}
		}
	}

	return result, nil
}
