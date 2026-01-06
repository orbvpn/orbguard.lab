package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// WebhookService manages webhook registrations and deliveries
type WebhookService struct {
	webhooks     map[uuid.UUID]*models.Webhook
	deliveryQueue chan *deliveryJob
	httpClient   *http.Client
	cache        *cache.RedisCache
	logger       *logger.Logger

	mu           sync.RWMutex
	wg           sync.WaitGroup
	stopCh       chan struct{}
	workerCount  int
}

// deliveryJob represents a webhook delivery job
type deliveryJob struct {
	webhook  *models.Webhook
	delivery *models.WebhookDelivery
	payload  *models.WebhookPayload
}

// WebhookServiceConfig contains configuration for the webhook service
type WebhookServiceConfig struct {
	WorkerCount    int
	QueueSize      int
	DefaultTimeout time.Duration
	MaxPayloadSize int64
}

// DefaultWebhookConfig returns sensible defaults
func DefaultWebhookConfig() *WebhookServiceConfig {
	return &WebhookServiceConfig{
		WorkerCount:    5,
		QueueSize:      1000,
		DefaultTimeout: 30 * time.Second,
		MaxPayloadSize: 1024 * 1024, // 1MB
	}
}

// NewWebhookService creates a new webhook service
func NewWebhookService(cache *cache.RedisCache, log *logger.Logger, cfg *WebhookServiceConfig) *WebhookService {
	if cfg == nil {
		cfg = DefaultWebhookConfig()
	}

	svc := &WebhookService{
		webhooks:      make(map[uuid.UUID]*models.Webhook),
		deliveryQueue: make(chan *deliveryJob, cfg.QueueSize),
		httpClient: &http.Client{
			Timeout: cfg.DefaultTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		cache:       cache,
		logger:      log.WithComponent("webhook-service"),
		stopCh:      make(chan struct{}),
		workerCount: cfg.WorkerCount,
	}

	// Start delivery workers
	svc.startWorkers()

	return svc
}

// startWorkers starts the delivery worker goroutines
func (s *WebhookService) startWorkers() {
	for i := 0; i < s.workerCount; i++ {
		s.wg.Add(1)
		go s.deliveryWorker(i)
	}
	s.logger.Info().Int("workers", s.workerCount).Msg("webhook delivery workers started")
}

// deliveryWorker processes webhook deliveries
func (s *WebhookService) deliveryWorker(id int) {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug().Int("worker", id).Msg("webhook worker stopping")
			return
		case job := <-s.deliveryQueue:
			s.processDelivery(job)
		}
	}
}

// Stop stops the webhook service
func (s *WebhookService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info().Msg("webhook service stopped")
}

// RegisterWebhook registers a new webhook
func (s *WebhookService) RegisterWebhook(ctx context.Context, webhook *models.Webhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if webhook.ID == uuid.Nil {
		webhook.ID = uuid.New()
	}
	if webhook.Secret == "" {
		webhook.Secret = generateWebhookSecret()
	}
	if webhook.RetryConfig == nil {
		webhook.RetryConfig = models.DefaultRetryConfig()
	}

	webhook.CreatedAt = time.Now()
	webhook.UpdatedAt = time.Now()

	s.webhooks[webhook.ID] = webhook

	s.logger.Info().
		Str("webhook_id", webhook.ID.String()).
		Str("name", webhook.Name).
		Str("url", webhook.URL).
		Int("events", len(webhook.Events)).
		Msg("webhook registered")

	return nil
}

// UpdateWebhook updates an existing webhook
func (s *WebhookService) UpdateWebhook(ctx context.Context, webhook *models.Webhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.webhooks[webhook.ID]
	if !ok {
		return fmt.Errorf("webhook not found: %s", webhook.ID)
	}

	// Preserve immutable fields
	webhook.CreatedAt = existing.CreatedAt
	webhook.Secret = existing.Secret
	webhook.TotalDeliveries = existing.TotalDeliveries
	webhook.SuccessDeliveries = existing.SuccessDeliveries
	webhook.FailedDeliveries = existing.FailedDeliveries

	webhook.UpdatedAt = time.Now()
	s.webhooks[webhook.ID] = webhook

	s.logger.Info().
		Str("webhook_id", webhook.ID.String()).
		Str("name", webhook.Name).
		Msg("webhook updated")

	return nil
}

// DeleteWebhook deletes a webhook
func (s *WebhookService) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.webhooks[id]; !ok {
		return fmt.Errorf("webhook not found: %s", id)
	}

	delete(s.webhooks, id)

	s.logger.Info().Str("webhook_id", id.String()).Msg("webhook deleted")

	return nil
}

// GetWebhook retrieves a webhook by ID
func (s *WebhookService) GetWebhook(ctx context.Context, id uuid.UUID) (*models.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	webhook, ok := s.webhooks[id]
	if !ok {
		return nil, fmt.Errorf("webhook not found: %s", id)
	}

	return webhook, nil
}

// ListWebhooks returns all webhooks
func (s *WebhookService) ListWebhooks(ctx context.Context) ([]*models.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	webhooks := make([]*models.Webhook, 0, len(s.webhooks))
	for _, w := range s.webhooks {
		webhooks = append(webhooks, w)
	}

	return webhooks, nil
}

// EnableWebhook enables a webhook
func (s *WebhookService) EnableWebhook(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	webhook, ok := s.webhooks[id]
	if !ok {
		return fmt.Errorf("webhook not found: %s", id)
	}

	webhook.Enabled = true
	webhook.UpdatedAt = time.Now()

	return nil
}

// DisableWebhook disables a webhook
func (s *WebhookService) DisableWebhook(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	webhook, ok := s.webhooks[id]
	if !ok {
		return fmt.Errorf("webhook not found: %s", id)
	}

	webhook.Enabled = false
	webhook.UpdatedAt = time.Now()

	return nil
}

// TriggerEvent triggers an event and sends it to all matching webhooks
func (s *WebhookService) TriggerEvent(ctx context.Context, eventType models.WebhookEventType, data interface{}) error {
	s.mu.RLock()
	matchingWebhooks := s.findMatchingWebhooks(eventType, data)
	s.mu.RUnlock()

	if len(matchingWebhooks) == 0 {
		s.logger.Debug().
			Str("event", string(eventType)).
			Msg("no webhooks matched event")
		return nil
	}

	// Create payload
	payload := &models.WebhookPayload{
		ID:        uuid.New().String(),
		Event:     eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Queue deliveries for each matching webhook
	for _, webhook := range matchingWebhooks {
		delivery := &models.WebhookDelivery{
			ID:           uuid.New(),
			WebhookID:    webhook.ID,
			EventType:    eventType,
			EventID:      payload.ID,
			Status:       models.DeliveryStatusPending,
			AttemptCount: 0,
			CreatedAt:    time.Now(),
		}

		// Add metadata to payload
		payloadCopy := *payload
		payloadCopy.Meta = &models.WebhookPayloadMeta{
			WebhookID:    webhook.ID.String(),
			DeliveryID:   delivery.ID.String(),
			AttemptCount: 1,
		}

		job := &deliveryJob{
			webhook:  webhook,
			delivery: delivery,
			payload:  &payloadCopy,
		}

		select {
		case s.deliveryQueue <- job:
			s.logger.Debug().
				Str("webhook_id", webhook.ID.String()).
				Str("event", string(eventType)).
				Msg("delivery queued")
		default:
			s.logger.Warn().
				Str("webhook_id", webhook.ID.String()).
				Msg("delivery queue full, dropping webhook")
		}
	}

	s.logger.Info().
		Str("event", string(eventType)).
		Int("webhooks", len(matchingWebhooks)).
		Msg("event triggered")

	return nil
}

// findMatchingWebhooks finds webhooks that match the event
func (s *WebhookService) findMatchingWebhooks(eventType models.WebhookEventType, data interface{}) []*models.Webhook {
	var matching []*models.Webhook

	for _, webhook := range s.webhooks {
		if !webhook.Enabled {
			continue
		}

		if s.webhookMatchesEvent(webhook, eventType, data) {
			matching = append(matching, webhook)
		}
	}

	return matching
}

// webhookMatchesEvent checks if a webhook should receive an event
func (s *WebhookService) webhookMatchesEvent(webhook *models.Webhook, eventType models.WebhookEventType, data interface{}) bool {
	// Check event type
	if !s.eventTypeMatches(webhook.Events, eventType) {
		return false
	}

	// Check filters
	if webhook.Filters != nil {
		if !s.filtersMatch(webhook.Filters, eventType, data) {
			return false
		}
	}

	return true
}

// eventTypeMatches checks if the event type is in the list
func (s *WebhookService) eventTypeMatches(events []models.WebhookEventType, eventType models.WebhookEventType) bool {
	for _, e := range events {
		if e == models.WebhookEventAll {
			return true
		}
		if e == eventType {
			return true
		}
		// Check prefix match (e.g., "threat.*" matches "threat.detected")
		if strings.HasSuffix(string(e), ".*") {
			prefix := strings.TrimSuffix(string(e), ".*")
			if strings.HasPrefix(string(eventType), prefix) {
				return true
			}
		}
	}
	return false
}

// filtersMatch checks if the data matches the webhook filters
func (s *WebhookService) filtersMatch(filters *models.WebhookFilters, eventType models.WebhookEventType, data interface{}) bool {
	// Type assertion for threat events
	if threatPayload, ok := data.(*models.ThreatEventPayload); ok {
		// Check severity
		if filters.MinSeverity != "" {
			if !webhookSeverityAtLeast(threatPayload.Severity, filters.MinSeverity) {
				return false
			}
		}
		if len(filters.Severities) > 0 {
			if !webhookContains(filters.Severities, threatPayload.Severity) {
				return false
			}
		}

		// Check indicator type
		if len(filters.IndicatorTypes) > 0 {
			if !webhookContains(filters.IndicatorTypes, threatPayload.Type) {
				return false
			}
		}

		// Check platforms
		if len(filters.Platforms) > 0 {
			if !webhookHasAny(threatPayload.Platforms, filters.Platforms) {
				return false
			}
		}

		// Check required tags
		if len(filters.RequiredTags) > 0 {
			if !webhookHasAll(threatPayload.Tags, filters.RequiredTags) {
				return false
			}
		}

		// Check excluded tags
		if len(filters.ExcludedTags) > 0 {
			if webhookHasAny(threatPayload.Tags, filters.ExcludedTags) {
				return false
			}
		}

		// Check confidence
		if filters.MinConfidence > 0 {
			if threatPayload.Confidence < filters.MinConfidence {
				return false
			}
		}

		// Check Pegasus-only
		if filters.PegasusOnly {
			if !webhookContains(threatPayload.Tags, "pegasus") {
				return false
			}
		}
	}

	return true
}

// processDelivery handles the actual webhook delivery
func (s *WebhookService) processDelivery(job *deliveryJob) {
	startTime := time.Now()

	// Serialize payload
	payloadBytes, err := json.Marshal(job.payload)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to marshal webhook payload")
		s.recordFailure(job.webhook, job.delivery, "marshal_error", err.Error())
		return
	}

	job.delivery.Payload = payloadBytes

	// Create request
	req, err := http.NewRequest(http.MethodPost, job.webhook.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to create webhook request")
		s.recordFailure(job.webhook, job.delivery, "request_error", err.Error())
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OrbGuard-Webhook/1.0")
	req.Header.Set("X-Webhook-ID", job.webhook.ID.String())
	req.Header.Set("X-Webhook-Event", string(job.delivery.EventType))
	req.Header.Set("X-Webhook-Delivery", job.delivery.ID.String())
	req.Header.Set("X-Webhook-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	// Add HMAC signature
	signature := s.signPayload(payloadBytes, job.webhook.Secret)
	req.Header.Set("X-Webhook-Signature", "sha256="+signature)

	// Add custom headers
	for k, v := range job.webhook.Headers {
		req.Header.Set(k, v)
	}

	// Send request
	job.delivery.AttemptCount++
	resp, err := s.httpClient.Do(req)

	duration := time.Since(startTime)
	job.delivery.Duration = duration

	if err != nil {
		s.logger.Warn().
			Err(err).
			Str("webhook_id", job.webhook.ID.String()).
			Str("url", job.webhook.URL).
			Msg("webhook delivery failed")
		s.handleDeliveryError(job, err.Error())
		return
	}
	defer resp.Body.Close()

	// Read response
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	job.delivery.StatusCode = resp.StatusCode
	job.delivery.Response = string(respBody)

	// Check status code
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.recordSuccess(job.webhook, job.delivery)
		s.logger.Info().
			Str("webhook_id", job.webhook.ID.String()).
			Int("status", resp.StatusCode).
			Dur("duration", duration).
			Msg("webhook delivered successfully")
	} else {
		errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody))
		s.handleDeliveryError(job, errMsg)
	}
}

// handleDeliveryError handles a failed delivery
func (s *WebhookService) handleDeliveryError(job *deliveryJob, errMsg string) {
	job.delivery.Error = errMsg

	retryConfig := job.webhook.RetryConfig
	if retryConfig == nil {
		retryConfig = models.DefaultRetryConfig()
	}

	// Check if we should retry
	if job.delivery.AttemptCount < retryConfig.MaxRetries {
		// Calculate next retry time with exponential backoff
		delay := retryConfig.RetryInterval
		for i := 1; i < job.delivery.AttemptCount; i++ {
			delay = time.Duration(float64(delay) * retryConfig.BackoffFactor)
		}
		if delay > retryConfig.MaxRetryDelay {
			delay = retryConfig.MaxRetryDelay
		}

		nextRetry := time.Now().Add(delay)
		job.delivery.NextRetryAt = &nextRetry
		job.delivery.Status = models.DeliveryStatusRetrying

		// Schedule retry (simplified - in production use a proper scheduler)
		go func() {
			time.Sleep(delay)
			select {
			case s.deliveryQueue <- job:
				s.logger.Debug().
					Str("webhook_id", job.webhook.ID.String()).
					Int("attempt", job.delivery.AttemptCount).
					Msg("webhook retry queued")
			case <-s.stopCh:
				return
			}
		}()

		s.logger.Warn().
			Str("webhook_id", job.webhook.ID.String()).
			Int("attempt", job.delivery.AttemptCount).
			Dur("retry_in", delay).
			Msg("webhook delivery will retry")
	} else {
		s.recordFailure(job.webhook, job.delivery, "max_retries", errMsg)
	}
}

// recordSuccess records a successful delivery
func (s *WebhookService) recordSuccess(webhook *models.Webhook, delivery *models.WebhookDelivery) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	delivery.Status = models.DeliveryStatusSuccess
	delivery.DeliveredAt = &now

	webhook.TotalDeliveries++
	webhook.SuccessDeliveries++
	webhook.LastDeliveryAt = now
}

// recordFailure records a failed delivery
func (s *WebhookService) recordFailure(webhook *models.Webhook, delivery *models.WebhookDelivery, reason, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	delivery.Status = models.DeliveryStatusFailed
	delivery.Error = errMsg

	webhook.TotalDeliveries++
	webhook.FailedDeliveries++
	webhook.LastErrorAt = now
	webhook.LastError = errMsg

	s.logger.Error().
		Str("webhook_id", webhook.ID.String()).
		Str("reason", reason).
		Str("error", errMsg).
		Msg("webhook delivery failed permanently")
}

// signPayload creates an HMAC signature for the payload
func (s *WebhookService) signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// TestWebhook sends a test event to a webhook
func (s *WebhookService) TestWebhook(ctx context.Context, id uuid.UUID) (*models.WebhookTest, error) {
	s.mu.RLock()
	webhook, ok := s.webhooks[id]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("webhook not found: %s", id)
	}

	// Create test payload
	payload := &models.WebhookPayload{
		ID:        uuid.New().String(),
		Event:     "test",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message": "This is a test webhook delivery from OrbGuard",
			"webhook_id": webhook.ID.String(),
			"webhook_name": webhook.Name,
		},
		Meta: &models.WebhookPayloadMeta{
			WebhookID:    webhook.ID.String(),
			DeliveryID:   uuid.New().String(),
			AttemptCount: 1,
		},
	}

	// Serialize
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return &models.WebhookTest{
			Success:  false,
			Error:    err.Error(),
			TestedAt: time.Now(),
		}, nil
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		return &models.WebhookTest{
			Success:  false,
			Error:    err.Error(),
			TestedAt: time.Now(),
		}, nil
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OrbGuard-Webhook/1.0")
	req.Header.Set("X-Webhook-ID", webhook.ID.String())
	req.Header.Set("X-Webhook-Event", "test")
	req.Header.Set("X-Webhook-Signature", "sha256="+s.signPayload(payloadBytes, webhook.Secret))

	for k, v := range webhook.Headers {
		req.Header.Set(k, v)
	}

	// Send
	startTime := time.Now()
	resp, err := s.httpClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return &models.WebhookTest{
			Success:  false,
			Error:    err.Error(),
			Duration: duration,
			TestedAt: time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	return &models.WebhookTest{
		Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode: resp.StatusCode,
		Response:   string(respBody),
		Duration:   duration,
		TestedAt:   time.Now(),
	}, nil
}

// GetStats returns webhook statistics
func (s *WebhookService) GetStats(ctx context.Context) *models.WebhookStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &models.WebhookStats{
		DeliveriesByEvent: make(map[string]int64),
		FailuresByReason:  make(map[string]int64),
	}

	var totalSuccess, totalFailed int64

	for _, w := range s.webhooks {
		stats.TotalWebhooks++
		if w.Enabled {
			stats.EnabledWebhooks++
		}
		stats.TotalDeliveries += w.TotalDeliveries
		totalSuccess += w.SuccessDeliveries
		totalFailed += w.FailedDeliveries
	}

	if stats.TotalDeliveries > 0 {
		stats.SuccessRate = float64(totalSuccess) / float64(stats.TotalDeliveries) * 100
	}

	return stats
}

// RotateSecret rotates the secret for a webhook
func (s *WebhookService) RotateSecret(ctx context.Context, id uuid.UUID) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	webhook, ok := s.webhooks[id]
	if !ok {
		return "", fmt.Errorf("webhook not found: %s", id)
	}

	newSecret := generateWebhookSecret()
	webhook.Secret = newSecret
	webhook.UpdatedAt = time.Now()

	s.logger.Info().
		Str("webhook_id", id.String()).
		Msg("webhook secret rotated")

	return newSecret, nil
}

// Helper functions

func generateWebhookSecret() string {
	return uuid.New().String() + "-" + uuid.New().String()
}

func webhookSeverityAtLeast(actual, minimum string) bool {
	levels := map[string]int{
		"low": 1, "medium": 2, "high": 3, "critical": 4,
	}
	return levels[strings.ToLower(actual)] >= levels[strings.ToLower(minimum)]
}

func webhookContains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func webhookHasAny(slice, items []string) bool {
	for _, item := range items {
		if webhookContains(slice, item) {
			return true
		}
	}
	return false
}

func webhookHasAll(slice, items []string) bool {
	for _, item := range items {
		if !webhookContains(slice, item) {
			return false
		}
	}
	return true
}
