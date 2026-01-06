package models

import (
	"time"

	"github.com/google/uuid"
)

// Webhook represents a registered webhook endpoint
type Webhook struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	URL         string                 `json:"url" db:"url"`
	Secret      string                 `json:"-" db:"secret"` // For HMAC signing
	Enabled     bool                   `json:"enabled" db:"enabled"`
	Events      []WebhookEventType     `json:"events" db:"events"`
	Filters     *WebhookFilters        `json:"filters,omitempty" db:"filters"`
	Headers     map[string]string      `json:"headers,omitempty" db:"headers"`
	RetryConfig *WebhookRetryConfig    `json:"retry_config,omitempty" db:"retry_config"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	// Statistics
	TotalDeliveries   int64     `json:"total_deliveries" db:"total_deliveries"`
	SuccessDeliveries int64     `json:"success_deliveries" db:"success_deliveries"`
	FailedDeliveries  int64     `json:"failed_deliveries" db:"failed_deliveries"`
	LastDeliveryAt    time.Time `json:"last_delivery_at,omitempty" db:"last_delivery_at"`
	LastErrorAt       time.Time `json:"last_error_at,omitempty" db:"last_error_at"`
	LastError         string    `json:"last_error,omitempty" db:"last_error"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// WebhookEventType represents types of events that can trigger webhooks
type WebhookEventType string

const (
	// Threat events
	WebhookEventThreatDetected     WebhookEventType = "threat.detected"
	WebhookEventThreatUpdated      WebhookEventType = "threat.updated"
	WebhookEventThreatResolved     WebhookEventType = "threat.resolved"
	WebhookEventCriticalThreat     WebhookEventType = "threat.critical"
	WebhookEventPegasusThreat      WebhookEventType = "threat.pegasus"

	// Indicator events
	WebhookEventIndicatorNew       WebhookEventType = "indicator.new"
	WebhookEventIndicatorUpdated   WebhookEventType = "indicator.updated"
	WebhookEventIndicatorExpired   WebhookEventType = "indicator.expired"

	// Campaign events
	WebhookEventCampaignNew        WebhookEventType = "campaign.new"
	WebhookEventCampaignUpdated    WebhookEventType = "campaign.updated"
	WebhookEventCampaignEnded      WebhookEventType = "campaign.ended"

	// Source events
	WebhookEventSourceUpdate       WebhookEventType = "source.update"
	WebhookEventSourceError        WebhookEventType = "source.error"

	// Scam detection events
	WebhookEventScamDetected       WebhookEventType = "scam.detected"
	WebhookEventPhishingDetected   WebhookEventType = "phishing.detected"

	// Digital footprint events
	WebhookEventBreachDetected     WebhookEventType = "breach.detected"
	WebhookEventExposureFound      WebhookEventType = "exposure.found"

	// Device events
	WebhookEventDeviceCompromised  WebhookEventType = "device.compromised"
	WebhookEventMalwareDetected    WebhookEventType = "malware.detected"

	// Alert events
	WebhookEventAlertCreated       WebhookEventType = "alert.created"
	WebhookEventAlertAcknowledged  WebhookEventType = "alert.acknowledged"
	WebhookEventAlertResolved      WebhookEventType = "alert.resolved"

	// Wildcard for all events
	WebhookEventAll                WebhookEventType = "*"
)

// WebhookFilters allows filtering which events trigger the webhook
type WebhookFilters struct {
	// Severity filters
	MinSeverity   string   `json:"min_severity,omitempty"`   // low, medium, high, critical
	Severities    []string `json:"severities,omitempty"`     // Specific severities

	// Type filters
	IndicatorTypes []string `json:"indicator_types,omitempty"` // ip, domain, hash, etc.
	ThreatTypes    []string `json:"threat_types,omitempty"`    // malware, phishing, etc.

	// Platform filters
	Platforms     []string `json:"platforms,omitempty"`       // ios, android, windows, etc.

	// Tag filters
	RequiredTags  []string `json:"required_tags,omitempty"`   // Must have all these tags
	ExcludedTags  []string `json:"excluded_tags,omitempty"`   // Must not have these tags

	// Source filters
	Sources       []string `json:"sources,omitempty"`         // Specific source slugs

	// Campaign filters
	CampaignIDs   []string `json:"campaign_ids,omitempty"`

	// Confidence filter
	MinConfidence float64  `json:"min_confidence,omitempty"`

	// Pegasus-specific
	PegasusOnly   bool     `json:"pegasus_only,omitempty"`
}

// WebhookRetryConfig configures retry behavior
type WebhookRetryConfig struct {
	MaxRetries     int           `json:"max_retries"`      // Default: 3
	RetryInterval  time.Duration `json:"retry_interval"`   // Default: 30s
	BackoffFactor  float64       `json:"backoff_factor"`   // Default: 2.0
	MaxRetryDelay  time.Duration `json:"max_retry_delay"`  // Default: 1h
}

// DefaultRetryConfig returns sensible default retry settings
func DefaultRetryConfig() *WebhookRetryConfig {
	return &WebhookRetryConfig{
		MaxRetries:    3,
		RetryInterval: 30 * time.Second,
		BackoffFactor: 2.0,
		MaxRetryDelay: time.Hour,
	}
}

// WebhookDelivery represents a single webhook delivery attempt
type WebhookDelivery struct {
	ID            uuid.UUID          `json:"id" db:"id"`
	WebhookID     uuid.UUID          `json:"webhook_id" db:"webhook_id"`
	EventType     WebhookEventType   `json:"event_type" db:"event_type"`
	EventID       string             `json:"event_id" db:"event_id"`
	Payload       []byte             `json:"payload" db:"payload"`
	Status        DeliveryStatus     `json:"status" db:"status"`
	StatusCode    int                `json:"status_code,omitempty" db:"status_code"`
	Response      string             `json:"response,omitempty" db:"response"`
	Error         string             `json:"error,omitempty" db:"error"`
	AttemptCount  int                `json:"attempt_count" db:"attempt_count"`
	NextRetryAt   *time.Time         `json:"next_retry_at,omitempty" db:"next_retry_at"`
	CreatedAt     time.Time          `json:"created_at" db:"created_at"`
	DeliveredAt   *time.Time         `json:"delivered_at,omitempty" db:"delivered_at"`
	Duration      time.Duration      `json:"duration,omitempty" db:"duration"`
}

// DeliveryStatus represents the status of a webhook delivery
type DeliveryStatus string

const (
	DeliveryStatusPending   DeliveryStatus = "pending"
	DeliveryStatusSuccess   DeliveryStatus = "success"
	DeliveryStatusFailed    DeliveryStatus = "failed"
	DeliveryStatusRetrying  DeliveryStatus = "retrying"
	DeliveryStatusExpired   DeliveryStatus = "expired"
)

// WebhookPayload is the standard payload sent to webhooks
type WebhookPayload struct {
	ID        string                 `json:"id"`
	Event     WebhookEventType       `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	Data      interface{}            `json:"data"`
	Meta      *WebhookPayloadMeta    `json:"meta,omitempty"`
}

// WebhookPayloadMeta contains metadata about the webhook payload
type WebhookPayloadMeta struct {
	WebhookID    string `json:"webhook_id"`
	DeliveryID   string `json:"delivery_id"`
	AttemptCount int    `json:"attempt_count"`
	Source       string `json:"source,omitempty"`
}

// ThreatEventPayload is the payload for threat-related webhook events
type ThreatEventPayload struct {
	ID             string            `json:"id"`
	Type           string            `json:"type"`
	Value          string            `json:"value"`
	Severity       string            `json:"severity"`
	Confidence     float64           `json:"confidence"`
	Description    string            `json:"description,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Platforms      []string          `json:"platforms,omitempty"`
	Campaign       *CampaignRef      `json:"campaign,omitempty"`
	Source         *SourceRef        `json:"source,omitempty"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	MitreAttack    []string          `json:"mitre_attack,omitempty"`
	RelatedIOCs    []string          `json:"related_iocs,omitempty"`
}

// CampaignRef is a reference to a campaign
type CampaignRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// SourceRef is a reference to a data source
type SourceRef struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// ScamEventPayload is the payload for scam detection webhook events
type ScamEventPayload struct {
	ID            string            `json:"id"`
	ContentType   string            `json:"content_type"`
	IsScam        bool              `json:"is_scam"`
	ScamType      string            `json:"scam_type,omitempty"`
	RiskScore     float64           `json:"risk_score"`
	Confidence    float64           `json:"confidence"`
	Description   string            `json:"description,omitempty"`
	Indicators    []string          `json:"indicators,omitempty"`
	URLs          []string          `json:"urls,omitempty"`
	PhoneNumbers  []string          `json:"phone_numbers,omitempty"`
	Language      string            `json:"language,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// BreachEventPayload is the payload for breach detection webhook events
type BreachEventPayload struct {
	ID            string            `json:"id"`
	BreachName    string            `json:"breach_name"`
	BreachDate    time.Time         `json:"breach_date"`
	AffectedEmail string            `json:"affected_email,omitempty"`
	DataTypes     []string          `json:"data_types,omitempty"`
	Severity      string            `json:"severity"`
	Description   string            `json:"description,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// AlertEventPayload is the payload for alert webhook events
type AlertEventPayload struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	Description   string            `json:"description"`
	Severity      string            `json:"severity"`
	Status        string            `json:"status"`
	Category      string            `json:"category"`
	Source        string            `json:"source,omitempty"`
	AffectedAsset string            `json:"affected_asset,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// WebhookStats contains webhook statistics
type WebhookStats struct {
	TotalWebhooks     int64            `json:"total_webhooks"`
	EnabledWebhooks   int64            `json:"enabled_webhooks"`
	TotalDeliveries   int64            `json:"total_deliveries"`
	SuccessRate       float64          `json:"success_rate"`
	AverageLatency    time.Duration    `json:"average_latency"`
	DeliveriesByEvent map[string]int64 `json:"deliveries_by_event"`
	FailuresByReason  map[string]int64 `json:"failures_by_reason"`
	Last24Hours       *WebhookPeriodStats `json:"last_24_hours"`
	Last7Days         *WebhookPeriodStats `json:"last_7_days"`
}

// WebhookPeriodStats contains stats for a specific period
type WebhookPeriodStats struct {
	TotalDeliveries   int64   `json:"total_deliveries"`
	SuccessDeliveries int64   `json:"success_deliveries"`
	FailedDeliveries  int64   `json:"failed_deliveries"`
	SuccessRate       float64 `json:"success_rate"`
}

// WebhookTest represents a test delivery result
type WebhookTest struct {
	Success     bool          `json:"success"`
	StatusCode  int           `json:"status_code,omitempty"`
	Response    string        `json:"response,omitempty"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	TestedAt    time.Time     `json:"tested_at"`
}
