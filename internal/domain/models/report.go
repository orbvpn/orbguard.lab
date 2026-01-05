package models

import (
	"time"

	"github.com/google/uuid"
)

// ReportStatus represents the status of a community report
type ReportStatus string

const (
	ReportStatusPending   ReportStatus = "pending"
	ReportStatusReviewing ReportStatus = "reviewing"
	ReportStatusApproved  ReportStatus = "approved"
	ReportStatusRejected  ReportStatus = "rejected"
	ReportStatusDuplicate ReportStatus = "duplicate"
)

// CommunityReport represents a user-submitted threat report
type CommunityReport struct {
	ID          uuid.UUID    `json:"id" db:"id"`
	Status      ReportStatus `json:"status" db:"status"`

	// Indicator data
	IndicatorValue string        `json:"indicator_value" db:"indicator_value"`
	IndicatorType  IndicatorType `json:"indicator_type" db:"indicator_type"`
	Severity       Severity      `json:"severity" db:"severity"`
	Description    string        `json:"description" db:"description"`
	Tags           []string      `json:"tags,omitempty" db:"tags"`

	// Reporter info (anonymized)
	ReporterHash    string `json:"-" db:"reporter_hash"` // Hash of user ID or device ID
	ReporterCountry string `json:"reporter_country,omitempty" db:"reporter_country"`

	// Device info (for mobile reports)
	DeviceType     string `json:"device_type,omitempty" db:"device_type"`       // android/ios
	DeviceModel    string `json:"device_model,omitempty" db:"device_model"`
	OSVersion      string `json:"os_version,omitempty" db:"os_version"`
	AppVersion     string `json:"app_version,omitempty" db:"app_version"`

	// Evidence
	EvidenceData   map[string]any `json:"evidence_data,omitempty" db:"evidence_data"`
	ScreenshotURL  *string        `json:"screenshot_url,omitempty" db:"screenshot_url"`

	// Review
	ReviewedBy   *uuid.UUID `json:"reviewed_by,omitempty" db:"reviewed_by"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty" db:"reviewed_at"`
	ReviewNotes  *string    `json:"review_notes,omitempty" db:"review_notes"`

	// If approved, link to created indicator
	IndicatorID *uuid.UUID `json:"indicator_id,omitempty" db:"indicator_id"`

	// Audit
	ReportedAt time.Time `json:"reported_at" db:"reported_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// CreateReportRequest represents the request to create a community report
type CreateReportRequest struct {
	IndicatorValue string            `json:"indicator_value" validate:"required"`
	IndicatorType  IndicatorType     `json:"indicator_type" validate:"required"`
	Severity       Severity          `json:"severity"`
	Description    string            `json:"description" validate:"required,min=10,max=1000"`
	Tags           []string          `json:"tags,omitempty"`
	DeviceInfo     DeviceInfo        `json:"device_info,omitempty"`
	EvidenceData   map[string]any    `json:"evidence_data,omitempty"`
}

// DeviceInfo represents device information submitted with a report
type DeviceInfo struct {
	Type      string `json:"type"`       // android/ios
	Model     string `json:"model"`
	OSVersion string `json:"os_version"`
	AppVersion string `json:"app_version"`
	Country   string `json:"country,omitempty"`
}

// UpdateHistory represents an update/aggregation history entry
type UpdateHistory struct {
	ID         uuid.UUID `json:"id" db:"id"`
	SourceID   uuid.UUID `json:"source_id" db:"source_id"`
	SourceSlug string    `json:"source_slug" db:"source_slug"`

	// Timing
	StartedAt  time.Time     `json:"started_at" db:"started_at"`
	CompletedAt time.Time    `json:"completed_at" db:"completed_at"`
	Duration   time.Duration `json:"duration" db:"duration"`

	// Results
	Success           bool   `json:"success" db:"success"`
	Error             *string `json:"error,omitempty" db:"error"`
	TotalFetched      int    `json:"total_fetched" db:"total_fetched"`
	NewIndicators     int    `json:"new_indicators" db:"new_indicators"`
	UpdatedIndicators int    `json:"updated_indicators" db:"updated_indicators"`
	SkippedIndicators int    `json:"skipped_indicators" db:"skipped_indicators"`

	// Metadata
	Metadata map[string]any `json:"metadata,omitempty" db:"metadata"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Stats represents aggregated statistics
type Stats struct {
	// Indicator counts
	TotalIndicators    int            `json:"total_indicators"`
	IndicatorsByType   map[string]int `json:"indicators_by_type"`
	IndicatorsBySeverity map[string]int `json:"indicators_by_severity"`
	IndicatorsByPlatform map[string]int `json:"indicators_by_platform"`

	// Source counts
	TotalSources   int `json:"total_sources"`
	ActiveSources  int `json:"active_sources"`

	// Campaign counts
	TotalCampaigns  int `json:"total_campaigns"`
	ActiveCampaigns int `json:"active_campaigns"`

	// Report counts
	TotalReports   int `json:"total_reports"`
	PendingReports int `json:"pending_reports"`

	// Special categories
	PegasusIndicators   int `json:"pegasus_indicators"`
	MobileIndicators    int `json:"mobile_indicators"`
	CriticalIndicators  int `json:"critical_indicators"`

	// Temporal
	LastUpdate     time.Time `json:"last_update"`
	TodayNewIOCs   int       `json:"today_new_iocs"`
	WeeklyNewIOCs  int       `json:"weekly_new_iocs"`
	MonthlyNewIOCs int       `json:"monthly_new_iocs"`

	// Data version (for sync)
	DataVersion int64 `json:"data_version"`
}

// MobileSyncResponse represents the optimized sync response for mobile apps
type MobileSyncResponse struct {
	Version     int64       `json:"version"`
	LastUpdated time.Time   `json:"last_updated"`
	HasMore     bool        `json:"has_more"`
	NextCursor  string      `json:"next_cursor,omitempty"`

	// Delta updates (since last sync)
	NewIndicators     []MobileIndicator `json:"new_indicators,omitempty"`
	UpdatedIndicators []MobileIndicator `json:"updated_indicators,omitempty"`
	RemovedIDs        []string          `json:"removed_ids,omitempty"`

	// Full sync data (if requested or first sync)
	Indicators []MobileIndicator `json:"indicators,omitempty"`
}

// MobileIndicator is an optimized indicator format for mobile apps
type MobileIndicator struct {
	ID         string        `json:"id"`
	Value      string        `json:"value"`
	Type       IndicatorType `json:"type"`
	Severity   Severity      `json:"severity"`
	Confidence float64       `json:"confidence"`
	Tags       []string      `json:"tags,omitempty"`
	Platforms  []Platform    `json:"platforms,omitempty"`
	IsPegasus  bool          `json:"is_pegasus,omitempty"`
	UpdatedAt  int64         `json:"updated_at"` // Unix timestamp for efficiency
}

// CheckRequest represents a batch indicator check request
type CheckRequest struct {
	Indicators []CheckIndicator `json:"indicators" validate:"required,min=1,max=100"`
}

// CheckIndicator represents a single indicator to check
type CheckIndicator struct {
	Value string        `json:"value" validate:"required"`
	Type  IndicatorType `json:"type" validate:"required"`
}

// CheckResponse represents the response to a check request
type CheckResponse struct {
	Results []CheckResult `json:"results"`
}

// CheckResult represents the result of checking a single indicator
type CheckResult struct {
	Value       string        `json:"value"`
	Type        IndicatorType `json:"type"`
	IsMalicious bool          `json:"is_malicious"`
	Severity    Severity      `json:"severity,omitempty"`
	Confidence  float64       `json:"confidence,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	Description string        `json:"description,omitempty"`
	CampaignID  *string       `json:"campaign_id,omitempty"`
	Indicator   *Indicator    `json:"indicator,omitempty"` // Full indicator details if malicious
}
