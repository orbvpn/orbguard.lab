package models

import (
	"time"

	"github.com/google/uuid"
)

// URLCategory represents the category/classification of a URL
type URLCategory string

const (
	URLCategoryUnknown        URLCategory = "unknown"
	URLCategorySafe           URLCategory = "safe"
	URLCategoryPhishing       URLCategory = "phishing"
	URLCategoryMalware        URLCategory = "malware"
	URLCategoryScam           URLCategory = "scam"
	URLCategorySpam           URLCategory = "spam"
	URLCategoryAdult          URLCategory = "adult"
	URLCategoryGambling       URLCategory = "gambling"
	URLCategoryDrugs          URLCategory = "drugs"
	URLCategoryCryptojacking  URLCategory = "cryptojacking"
	URLCategoryRansomware     URLCategory = "ransomware"
	URLCategoryC2             URLCategory = "command_and_control"
	URLCategoryBotnet         URLCategory = "botnet"
	URLCategoryExploit        URLCategory = "exploit"
	URLCategoryDriveby        URLCategory = "drive_by_download"
	URLCategorySuspicious     URLCategory = "suspicious"
	URLCategoryUncategorized  URLCategory = "uncategorized"
)

// URLReputation represents the reputation/safety rating of a URL
type URLReputation struct {
	ID           uuid.UUID     `json:"id"`
	URL          string        `json:"url"`
	Domain       string        `json:"domain"`
	Category     URLCategory   `json:"category"`
	ThreatLevel  Severity      `json:"threat_level"`
	Confidence   float64       `json:"confidence"`
	IsMalicious  bool          `json:"is_malicious"`
	IsBlocked    bool          `json:"is_blocked"`

	// Source information
	Sources      []string      `json:"sources,omitempty"`
	FirstSeen    time.Time     `json:"first_seen"`
	LastSeen     time.Time     `json:"last_seen"`
	LastChecked  time.Time     `json:"last_checked"`

	// Additional metadata
	Tags         []string      `json:"tags,omitempty"`
	Description  string        `json:"description,omitempty"`
	CampaignID   *uuid.UUID    `json:"campaign_id,omitempty"`
	ThreatActorID *uuid.UUID   `json:"threat_actor_id,omitempty"`

	// Certificate info (for HTTPS)
	CertValid    *bool         `json:"cert_valid,omitempty"`
	CertIssuer   string        `json:"cert_issuer,omitempty"`

	// Hosting info
	IPAddress    string        `json:"ip_address,omitempty"`
	ASN          string        `json:"asn,omitempty"`
	Country      string        `json:"country,omitempty"`
	Registrar    string        `json:"registrar,omitempty"`

	// Risk indicators
	IsShortened  bool          `json:"is_shortened"`
	IsNewDomain  bool          `json:"is_new_domain"`
	HasSuspiciousTLD bool      `json:"has_suspicious_tld"`
	RiskScore    float64       `json:"risk_score"`
}

// URLCheckRequest represents a URL check request
type URLCheckRequest struct {
	URL       string `json:"url"`
	DeviceID  string `json:"device_id,omitempty"`
	Source    string `json:"source,omitempty"` // "browser", "sms", "email", "app"
	UserAgent string `json:"user_agent,omitempty"`
}

// URLCheckResponse represents the response to a URL check
type URLCheckResponse struct {
	URL          string       `json:"url"`
	Domain       string       `json:"domain"`
	IsSafe       bool         `json:"is_safe"`
	ShouldBlock  bool         `json:"should_block"`
	Category     URLCategory  `json:"category"`
	ThreatLevel  Severity     `json:"threat_level"`
	Confidence   float64      `json:"confidence"`
	Description  string       `json:"description,omitempty"`
	Warnings     []string     `json:"warnings,omitempty"`

	// For blocking UI
	BlockReason  string       `json:"block_reason,omitempty"`
	AllowOverride bool        `json:"allow_override"`

	// Related threat info
	CampaignName string       `json:"campaign_name,omitempty"`
	ThreatActorName string    `json:"threat_actor_name,omitempty"`

	// Caching
	CacheHit     bool         `json:"cache_hit"`
	CheckedAt    time.Time    `json:"checked_at"`
}

// URLBatchCheckRequest represents a batch URL check request
type URLBatchCheckRequest struct {
	URLs     []string `json:"urls"`
	DeviceID string   `json:"device_id,omitempty"`
	Source   string   `json:"source,omitempty"`
}

// URLBatchCheckResponse represents the response to a batch URL check
type URLBatchCheckResponse struct {
	Results    []URLCheckResponse `json:"results"`
	TotalCount int                `json:"total_count"`
	SafeCount  int                `json:"safe_count"`
	BlockCount int                `json:"block_count"`
	CheckedAt  time.Time          `json:"checked_at"`
}

// URLListEntry represents an entry in a whitelist or blacklist
type URLListEntry struct {
	ID          uuid.UUID   `json:"id"`
	URL         string      `json:"url,omitempty"`   // Specific URL
	Domain      string      `json:"domain,omitempty"` // Domain pattern (e.g., *.example.com)
	Pattern     string      `json:"pattern,omitempty"` // Regex pattern
	ListType    URLListType `json:"list_type"`
	Reason      string      `json:"reason,omitempty"`
	CreatedBy   string      `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	IsActive    bool        `json:"is_active"`
}

// URLListType represents the type of URL list
type URLListType string

const (
	URLListTypeWhitelist URLListType = "whitelist"
	URLListTypeBlacklist URLListType = "blacklist"
)

// SafeBrowsingResult represents a Google Safe Browsing API result
type SafeBrowsingResult struct {
	URL         string   `json:"url"`
	IsThreat    bool     `json:"is_threat"`
	ThreatTypes []string `json:"threat_types,omitempty"` // MALWARE, SOCIAL_ENGINEERING, etc.
	Platforms   []string `json:"platforms,omitempty"`    // ANY_PLATFORM, WINDOWS, etc.
	CacheTime   int      `json:"cache_time_seconds"`
}

// BlockPageData represents data for rendering a block page
type BlockPageData struct {
	URL           string      `json:"url"`
	Domain        string      `json:"domain"`
	Category      URLCategory `json:"category"`
	ThreatLevel   Severity    `json:"threat_level"`
	Reason        string      `json:"reason"`
	AllowOverride bool        `json:"allow_override"`
	OverrideToken string      `json:"override_token,omitempty"`
	ReportURL     string      `json:"report_url"`
	Timestamp     time.Time   `json:"timestamp"`
}

// URLStats represents URL protection statistics
type URLStats struct {
	TotalChecks       int64            `json:"total_checks"`
	BlockedCount      int64            `json:"blocked_count"`
	ByCategory        map[string]int64 `json:"by_category"`
	ByThreatLevel     map[string]int64 `json:"by_threat_level"`
	TopBlockedDomains []DomainCount    `json:"top_blocked_domains"`
	Last24Hours       struct {
		Checks  int64 `json:"checks"`
		Blocked int64 `json:"blocked"`
	} `json:"last_24_hours"`
}

// DomainCount represents a domain with its block count
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}
