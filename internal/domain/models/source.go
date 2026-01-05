package models

import (
	"time"

	"github.com/google/uuid"
)

// SourceCategory represents the category of threat intelligence source
type SourceCategory string

const (
	SourceCategoryAbuseCH    SourceCategory = "abuse_ch"
	SourceCategoryPhishing   SourceCategory = "phishing"
	SourceCategoryIPRep      SourceCategory = "ip_reputation"
	SourceCategoryMobile     SourceCategory = "mobile"
	SourceCategoryGeneral    SourceCategory = "general"
	SourceCategoryGovernment SourceCategory = "government"
	SourceCategoryISAC       SourceCategory = "isac"
	SourceCategoryCommunity  SourceCategory = "community"
	SourceCategoryPremium    SourceCategory = "premium"
)

// SourceType represents the data format type
type SourceType string

const (
	SourceTypeAPI      SourceType = "api"
	SourceTypeFeed     SourceType = "feed"
	SourceTypeGithub   SourceType = "github"
	SourceTypeTAXII    SourceType = "taxii"
	SourceTypeManual   SourceType = "manual"
	SourceTypeCommunity SourceType = "community"
)

// SourceStatus represents the current status of a source
type SourceStatus string

const (
	SourceStatusActive   SourceStatus = "active"
	SourceStatusPaused   SourceStatus = "paused"
	SourceStatusError    SourceStatus = "error"
	SourceStatusDisabled SourceStatus = "disabled"
)

// Source represents a threat intelligence source/feed
type Source struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Slug        string         `json:"slug" db:"slug"` // urlhaus, threatfox, etc.
	Description string         `json:"description,omitempty" db:"description"`
	Category    SourceCategory `json:"category" db:"category"`
	Type        SourceType     `json:"type" db:"type"`
	Status      SourceStatus   `json:"status" db:"status"`

	// Configuration
	APIURL          string   `json:"api_url,omitempty" db:"api_url"`
	FeedURL         string   `json:"feed_url,omitempty" db:"feed_url"`
	GithubURLs      []string `json:"github_urls,omitempty" db:"github_urls"`
	RequiresAPIKey  bool     `json:"requires_api_key" db:"requires_api_key"`
	HasAPIKey       bool     `json:"has_api_key" db:"-"` // Computed, not stored

	// Reliability & Scoring
	Reliability float64 `json:"reliability" db:"reliability"` // 0.0 - 1.0
	Weight      float64 `json:"weight" db:"weight"`           // Weight in scoring

	// Scheduling
	UpdateInterval time.Duration `json:"update_interval" db:"update_interval"`
	LastFetched    *time.Time    `json:"last_fetched,omitempty" db:"last_fetched"`
	NextFetch      *time.Time    `json:"next_fetch,omitempty" db:"next_fetch"`
	LastError      *string       `json:"last_error,omitempty" db:"last_error"`
	ErrorCount     int           `json:"error_count" db:"error_count"`

	// Statistics
	IndicatorCount  int       `json:"indicator_count" db:"indicator_count"`
	LastIndicatorAt *time.Time `json:"last_indicator_at,omitempty" db:"last_indicator_at"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SourceFetchResult represents the result of fetching from a source
type SourceFetchResult struct {
	SourceID          uuid.UUID      `json:"source_id"`
	SourceSlug        string         `json:"source_slug"`
	FetchedAt         time.Time      `json:"fetched_at"`
	Duration          time.Duration  `json:"duration"`
	Success           bool           `json:"success"`
	Error             error          `json:"error,omitempty"`
	TotalFetched      int            `json:"total_fetched"`
	NewIndicators     int            `json:"new_indicators"`
	UpdatedIndicators int            `json:"updated_indicators"`
	SkippedIndicators int            `json:"skipped_indicators"`
	RawIndicators     []RawIndicator `json:"-"` // Parsed but not normalized
}

// StartedAt returns FetchedAt for database compatibility
func (r *SourceFetchResult) StartedAt() time.Time {
	return r.FetchedAt
}

// CompletedAt returns FetchedAt + Duration for database compatibility
func (r *SourceFetchResult) CompletedAt() time.Time {
	return r.FetchedAt.Add(r.Duration)
}

// ErrorString returns the error as a string
func (r *SourceFetchResult) ErrorString() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Error()
}

// RawIndicator represents a raw indicator from a source before normalization
type RawIndicator struct {
	Value       string            `json:"value"`
	Type        IndicatorType     `json:"type"`
	Severity    Severity          `json:"severity,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	FirstSeen   *time.Time        `json:"first_seen,omitempty"`
	LastSeen    *time.Time        `json:"last_seen,omitempty"`
	Confidence  *float64          `json:"confidence,omitempty"`
	RawData     map[string]any    `json:"raw_data,omitempty"`
}

// DefaultSources returns the list of built-in sources
func DefaultSources() []Source {
	return []Source{
		// Abuse.ch Suite
		{
			Name:           "URLhaus",
			Slug:           "urlhaus",
			Description:    "Abuse.ch URLhaus - Malware URL Database",
			Category:       SourceCategoryAbuseCH,
			Type:           SourceTypeAPI,
			Status:         SourceStatusActive,
			APIURL:         "https://urlhaus-api.abuse.ch/v1",
			Reliability:    0.80,
			Weight:         1.0,
			UpdateInterval: 15 * time.Minute,
		},
		{
			Name:           "ThreatFox",
			Slug:           "threatfox",
			Description:    "Abuse.ch ThreatFox - IOC Sharing Platform",
			Category:       SourceCategoryAbuseCH,
			Type:           SourceTypeAPI,
			Status:         SourceStatusActive,
			APIURL:         "https://threatfox-api.abuse.ch/api/v1",
			Reliability:    0.85,
			Weight:         1.0,
			UpdateInterval: 15 * time.Minute,
		},
		{
			Name:           "MalwareBazaar",
			Slug:           "malwarebazaar",
			Description:    "Abuse.ch MalwareBazaar - Malware Samples",
			Category:       SourceCategoryAbuseCH,
			Type:           SourceTypeAPI,
			Status:         SourceStatusActive,
			APIURL:         "https://mb-api.abuse.ch/api/v1",
			Reliability:    0.85,
			Weight:         1.0,
			UpdateInterval: 4 * time.Hour,
		},
		{
			Name:           "Feodo Tracker",
			Slug:           "feodotracker",
			Description:    "Abuse.ch Feodo Tracker - Botnet C2 Tracker",
			Category:       SourceCategoryAbuseCH,
			Type:           SourceTypeFeed,
			Status:         SourceStatusActive,
			FeedURL:        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
			Reliability:    0.85,
			Weight:         1.0,
			UpdateInterval: 1 * time.Hour,
		},
		{
			Name:           "SSL Blacklist",
			Slug:           "sslblacklist",
			Description:    "Abuse.ch SSL Blacklist - Malicious SSL Certificates",
			Category:       SourceCategoryAbuseCH,
			Type:           SourceTypeFeed,
			Status:         SourceStatusActive,
			FeedURL:        "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
			Reliability:    0.80,
			Weight:         1.0,
			UpdateInterval: 24 * time.Hour,
		},

		// Phishing
		{
			Name:           "OpenPhish",
			Slug:           "openphish",
			Description:    "OpenPhish - Phishing Intelligence",
			Category:       SourceCategoryPhishing,
			Type:           SourceTypeFeed,
			Status:         SourceStatusActive,
			FeedURL:        "https://openphish.com/feed.txt",
			Reliability:    0.75,
			Weight:         0.8,
			UpdateInterval: 4 * time.Hour,
		},
		{
			Name:           "PhishTank",
			Slug:           "phishtank",
			Description:    "PhishTank - Community Phishing Data",
			Category:       SourceCategoryPhishing,
			Type:           SourceTypeAPI,
			Status:         SourceStatusPaused, // Requires API key
			RequiresAPIKey: true,
			Reliability:    0.70,
			Weight:         0.8,
			UpdateInterval: 4 * time.Hour,
		},

		// Mobile/Spyware (HIGH PRIORITY)
		{
			Name:           "Citizen Lab",
			Slug:           "citizenlab",
			Description:    "Citizen Lab Malware Indicators",
			Category:       SourceCategoryMobile,
			Type:           SourceTypeGithub,
			Status:         SourceStatusActive,
			GithubURLs: []string{
				"https://raw.githubusercontent.com/citizenlab/malware-indicators/master/",
			},
			Reliability:    0.95,
			Weight:         1.5, // Higher weight for mobile threats
			UpdateInterval: 6 * time.Hour,
		},
		{
			Name:           "Amnesty MVT",
			Slug:           "amnesty_mvt",
			Description:    "Amnesty International Mobile Verification Toolkit",
			Category:       SourceCategoryMobile,
			Type:           SourceTypeGithub,
			Status:         SourceStatusActive,
			GithubURLs: []string{
				"https://raw.githubusercontent.com/AmnestyTech/investigations/master/",
			},
			Reliability:    0.95,
			Weight:         1.5,
			UpdateInterval: 6 * time.Hour,
		},
		{
			Name:           "Koodous",
			Slug:           "koodous",
			Description:    "Koodous Android Malware Analysis",
			Category:       SourceCategoryMobile,
			Type:           SourceTypeAPI,
			Status:         SourceStatusPaused,
			RequiresAPIKey: true,
			Reliability:    0.80,
			Weight:         1.2,
			UpdateInterval: 6 * time.Hour,
		},

		// General
		{
			Name:           "AlienVault OTX",
			Slug:           "alienvault_otx",
			Description:    "AlienVault Open Threat Exchange",
			Category:       SourceCategoryGeneral,
			Type:           SourceTypeAPI,
			Status:         SourceStatusPaused,
			RequiresAPIKey: true,
			Reliability:    0.75,
			Weight:         1.0,
			UpdateInterval: 4 * time.Hour,
		},
		{
			Name:           "VirusTotal",
			Slug:           "virustotal",
			Description:    "VirusTotal Threat Intelligence",
			Category:       SourceCategoryGeneral,
			Type:           SourceTypeAPI,
			Status:         SourceStatusPaused,
			RequiresAPIKey: true,
			Reliability:    0.90,
			Weight:         1.2,
			UpdateInterval: 1 * time.Hour,
		},

		// Community
		{
			Name:        "Community Reports",
			Slug:        "community",
			Description: "User-submitted threat reports",
			Category:    SourceCategoryCommunity,
			Type:        SourceTypeCommunity,
			Status:      SourceStatusActive,
			Reliability: 0.50, // Lower reliability, needs validation
			Weight:      0.5,
		},
	}
}
