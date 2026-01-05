package streaming

import (
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
)

// EventType represents the type of threat event
type EventType string

const (
	EventTypeNewThreat        EventType = "new_threat"
	EventTypeUpdatedThreat    EventType = "updated_threat"
	EventTypeRemovedThreat    EventType = "removed_threat"
	EventTypeCampaignDetected EventType = "campaign_detected"
	EventTypeSourceUpdated    EventType = "source_updated"
)

// ThreatEvent represents a real-time threat update event
type ThreatEvent struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`

	// Indicator details
	IndicatorID    string              `json:"indicator_id,omitempty"`
	IndicatorValue string              `json:"indicator_value,omitempty"`
	IndicatorType  models.IndicatorType `json:"indicator_type,omitempty"`
	Severity       models.Severity     `json:"severity,omitempty"`
	Confidence     float64             `json:"confidence,omitempty"`
	Description    string              `json:"description,omitempty"`
	Tags           []string            `json:"tags,omitempty"`
	Platforms      []string            `json:"platforms,omitempty"`

	// Campaign/Actor info
	CampaignID   string `json:"campaign_id,omitempty"`
	CampaignName string `json:"campaign_name,omitempty"`
	ThreatActorID string `json:"threat_actor_id,omitempty"`

	// Source info
	SourceSlug string `json:"source_slug,omitempty"`
	SourceName string `json:"source_name,omitempty"`

	// Metadata
	Metadata map[string]any `json:"metadata,omitempty"`
}

// NewThreatEvent creates a new threat event from an indicator
func NewThreatEvent(eventType EventType, indicator *models.Indicator) *ThreatEvent {
	// Convert platforms to strings
	platforms := make([]string, len(indicator.Platforms))
	for i, p := range indicator.Platforms {
		platforms[i] = string(p)
	}

	event := &ThreatEvent{
		ID:             uuid.New().String(),
		Type:           eventType,
		Timestamp:      time.Now(),
		IndicatorID:    indicator.ID.String(),
		IndicatorValue: indicator.Value,
		IndicatorType:  indicator.Type,
		Severity:       indicator.Severity,
		Confidence:     indicator.Confidence,
		Description:    indicator.Description,
		Tags:           indicator.Tags,
		Platforms:      platforms,
	}

	if indicator.CampaignID != nil {
		event.CampaignID = indicator.CampaignID.String()
	}
	if indicator.ThreatActorID != nil {
		event.ThreatActorID = indicator.ThreatActorID.String()
	}

	return event
}

// SourceUpdateEvent represents a source update completion event
type SourceUpdateEvent struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`

	SourceSlug        string        `json:"source_slug"`
	SourceName        string        `json:"source_name"`
	Success           bool          `json:"success"`
	NewIndicators     int           `json:"new_indicators"`
	UpdatedIndicators int           `json:"updated_indicators"`
	Duration          time.Duration `json:"duration_ms"`
	Error             string        `json:"error,omitempty"`
}

// Subscription represents a client's subscription preferences
type Subscription struct {
	// Filter by severity (empty = all)
	MinSeverity models.Severity `json:"min_severity,omitempty"`

	// Filter by indicator types (empty = all)
	Types []models.IndicatorType `json:"types,omitempty"`

	// Filter by platforms (empty = all)
	Platforms []string `json:"platforms,omitempty"`

	// Filter by campaigns (empty = all)
	CampaignIDs []string `json:"campaign_ids,omitempty"`

	// Filter by tags (empty = all)
	Tags []string `json:"tags,omitempty"`

	// Include only Pegasus-related threats
	PegasusOnly bool `json:"pegasus_only,omitempty"`

	// Include source update events
	IncludeSourceUpdates bool `json:"include_source_updates,omitempty"`
}

// Matches checks if an event matches the subscription filters
func (s *Subscription) Matches(event *ThreatEvent) bool {
	// Check severity
	if s.MinSeverity != "" {
		severityOrder := map[models.Severity]int{
			models.SeverityInfo:     1,
			models.SeverityLow:      2,
			models.SeverityMedium:   3,
			models.SeverityHigh:     4,
			models.SeverityCritical: 5,
		}
		if severityOrder[event.Severity] < severityOrder[s.MinSeverity] {
			return false
		}
	}

	// Check types
	if len(s.Types) > 0 {
		found := false
		for _, t := range s.Types {
			if t == event.IndicatorType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check platforms
	if len(s.Platforms) > 0 {
		found := false
		for _, p := range s.Platforms {
			for _, ep := range event.Platforms {
				if p == ep {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	// Check campaigns
	if len(s.CampaignIDs) > 0 {
		found := false
		for _, c := range s.CampaignIDs {
			if c == event.CampaignID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check tags
	if len(s.Tags) > 0 {
		found := false
		for _, t := range s.Tags {
			for _, et := range event.Tags {
				if t == et {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	// Check Pegasus only
	if s.PegasusOnly {
		isPegasus := false
		for _, tag := range event.Tags {
			if tag == "pegasus" || tag == "nso_group" {
				isPegasus = true
				break
			}
		}
		if !isPegasus {
			return false
		}
	}

	return true
}
