package models

import (
	"time"

	"github.com/google/uuid"
)

// YARARuleStatus represents the status of a YARA rule
type YARARuleStatus string

const (
	YARARuleStatusActive   YARARuleStatus = "active"
	YARARuleStatusDisabled YARARuleStatus = "disabled"
	YARARuleStatusDraft    YARARuleStatus = "draft"
	YARARuleStatusPending  YARARuleStatus = "pending" // Pending review
)

// YARARuleCategory represents categories of YARA rules
type YARARuleCategory string

const (
	YARACategoryPegasus     YARARuleCategory = "pegasus"
	YARACategoryStalkerware YARARuleCategory = "stalkerware"
	YARACategorySpyware     YARARuleCategory = "spyware"
	YARACategoryTrojan      YARARuleCategory = "trojan"
	YARACategoryRansomware  YARARuleCategory = "ransomware"
	YARACategoryAdware      YARARuleCategory = "adware"
	YARACategoryRootkit     YARARuleCategory = "rootkit"
	YARACategoryExploit     YARARuleCategory = "exploit"
	YARACategoryGeneric     YARARuleCategory = "generic"
)

// YARARule represents a YARA detection rule
type YARARule struct {
	ID          uuid.UUID        `json:"id" db:"id"`
	Name        string           `json:"name" db:"name"`
	Description string           `json:"description,omitempty" db:"description"`
	Category    YARARuleCategory `json:"category" db:"category"`
	Severity    Severity         `json:"severity" db:"severity"`
	Status      YARARuleStatus   `json:"status" db:"status"`

	// Rule definition
	Strings    []YARAString    `json:"strings" db:"-"`
	Conditions []YARACondition `json:"conditions" db:"-"`
	RawRule    string          `json:"raw_rule,omitempty" db:"raw_rule"` // Original YARA syntax

	// Metadata
	Author     string   `json:"author,omitempty" db:"author"`
	Reference  string   `json:"reference,omitempty" db:"reference"`
	Tags       []string `json:"tags,omitempty" db:"tags"`
	MitreTTPs  []string `json:"mitre_ttps,omitempty" db:"mitre_ttps"`
	Platforms  []string `json:"platforms,omitempty" db:"platforms"` // android, ios, all

	// Campaign/Actor attribution
	CampaignID    *uuid.UUID `json:"campaign_id,omitempty" db:"campaign_id"`
	ThreatActorID *uuid.UUID `json:"threat_actor_id,omitempty" db:"threat_actor_id"`

	// Statistics
	MatchCount   int64      `json:"match_count" db:"match_count"`
	LastMatchAt  *time.Time `json:"last_match_at,omitempty" db:"last_match_at"`
	FalsePositive int       `json:"false_positive_count" db:"false_positive_count"`

	// User submission
	SubmittedBy *uuid.UUID `json:"submitted_by,omitempty" db:"submitted_by"`
	ReviewedBy  *uuid.UUID `json:"reviewed_by,omitempty" db:"reviewed_by"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty" db:"reviewed_at"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// YARAString represents a string pattern in a YARA rule
type YARAString struct {
	ID         string          `json:"id"`                      // e.g., $a, $str1
	Value      string          `json:"value"`                   // The pattern
	Type       YARAStringType  `json:"type"`                    // text, hex, regex
	Modifiers  []string        `json:"modifiers,omitempty"`     // nocase, wide, ascii, fullword
	Compiled   interface{}     `json:"-"`                       // Compiled pattern (regex or bytes)
}

// YARAStringType represents the type of string pattern
type YARAStringType string

const (
	YARAStringTypeText  YARAStringType = "text"
	YARAStringTypeHex   YARAStringType = "hex"
	YARAStringTypeRegex YARAStringType = "regex"
)

// YARACondition represents a condition in a YARA rule
type YARACondition struct {
	Expression string `json:"expression"` // e.g., "any of them", "$a and $b", "2 of ($str*)"
}

// YARAScanRequest represents a request to scan data with YARA rules
type YARAScanRequest struct {
	// Data to scan (one of these)
	Data       []byte `json:"data,omitempty"`        // Raw bytes
	FilePath   string `json:"file_path,omitempty"`   // Local file path
	Base64Data string `json:"base64_data,omitempty"` // Base64 encoded data
	HexData    string `json:"hex_data,omitempty"`    // Hex encoded data

	// Scan options
	RuleIDs     []uuid.UUID        `json:"rule_ids,omitempty"`     // Specific rules to use
	Categories  []YARARuleCategory `json:"categories,omitempty"`   // Filter by category
	MinSeverity *Severity          `json:"min_severity,omitempty"` // Minimum severity
	Platform    string             `json:"platform,omitempty"`     // android, ios
	Timeout     int                `json:"timeout,omitempty"`      // Timeout in seconds

	// Metadata about the scan target
	FileName    string `json:"file_name,omitempty"`
	FileType    string `json:"file_type,omitempty"`
	PackageName string `json:"package_name,omitempty"` // For APK/IPA
}

// YARAScanResult represents the result of a YARA scan
type YARAScanResult struct {
	ID         uuid.UUID       `json:"id"`
	ScanTime   time.Duration   `json:"scan_time"`
	Matches    []YARAMatch     `json:"matches"`
	RulesUsed  int             `json:"rules_used"`
	DataSize   int64           `json:"data_size"`
	IsMalicious bool           `json:"is_malicious"`
	MaxSeverity Severity       `json:"max_severity"`
	RiskScore  float64         `json:"risk_score"`
	ScannedAt  time.Time       `json:"scanned_at"`

	// Target info
	FileName    string `json:"file_name,omitempty"`
	FileType    string `json:"file_type,omitempty"`
	PackageName string `json:"package_name,omitempty"`
}

// YARAMatch represents a single rule match
type YARAMatch struct {
	RuleID      uuid.UUID        `json:"rule_id"`
	RuleName    string           `json:"rule_name"`
	Category    YARARuleCategory `json:"category"`
	Severity    Severity         `json:"severity"`
	Description string           `json:"description,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	MitreTTPs   []string         `json:"mitre_ttps,omitempty"`

	// Match details
	StringMatches []YARAStringMatch `json:"string_matches"`
	MatchCount    int               `json:"match_count"`

	// Attribution
	CampaignSlug    string `json:"campaign_slug,omitempty"`
	ThreatActorName string `json:"threat_actor_name,omitempty"`
}

// YARAStringMatch represents where a string pattern matched
type YARAStringMatch struct {
	StringID string `json:"string_id"` // e.g., $a
	Offset   int64  `json:"offset"`    // Position in data
	Length   int    `json:"length"`    // Match length
	Data     string `json:"data"`      // Matched content (truncated)
}

// YARARuleSet represents a collection of rules
type YARARuleSet struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Rules       []YARARule `json:"rules"`
	RuleCount   int        `json:"rule_count"`
	Version     string     `json:"version"`
	LastUpdated time.Time  `json:"last_updated"`
}

// YARARuleFilter represents filter options for querying rules
type YARARuleFilter struct {
	Categories    []YARARuleCategory `json:"categories,omitempty"`
	Severities    []Severity         `json:"severities,omitempty"`
	Status        *YARARuleStatus    `json:"status,omitempty"`
	Platforms     []string           `json:"platforms,omitempty"`
	Tags          []string           `json:"tags,omitempty"`
	CampaignID    *uuid.UUID         `json:"campaign_id,omitempty"`
	ThreatActorID *uuid.UUID         `json:"threat_actor_id,omitempty"`
	Search        string             `json:"search,omitempty"`
	Limit         int                `json:"limit,omitempty"`
	Offset        int                `json:"offset,omitempty"`
}

// YARAScanStats represents scanning statistics
type YARAScanStats struct {
	TotalScans        int64              `json:"total_scans"`
	TotalMatches      int64              `json:"total_matches"`
	MaliciousDetected int64              `json:"malicious_detected"`
	ByCategory        map[string]int64   `json:"by_category"`
	BySeverity        map[string]int64   `json:"by_severity"`
	TopRules          []RuleMatchStats   `json:"top_rules"`
	ScansByDay        []DailyScanStats   `json:"scans_by_day"`
	AverageScanTime   time.Duration      `json:"average_scan_time"`
	LastScanAt        *time.Time         `json:"last_scan_at,omitempty"`
}

// RuleMatchStats represents match statistics for a rule
type RuleMatchStats struct {
	RuleID     uuid.UUID `json:"rule_id"`
	RuleName   string    `json:"rule_name"`
	MatchCount int64     `json:"match_count"`
	Category   string    `json:"category"`
}

// DailyScanStats represents daily scan statistics
type DailyScanStats struct {
	Date        string `json:"date"`
	TotalScans  int64  `json:"total_scans"`
	Detections  int64  `json:"detections"`
}

// YARARuleSubmission represents a user-submitted rule
type YARARuleSubmission struct {
	ID          uuid.UUID         `json:"id"`
	RawRule     string            `json:"raw_rule"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Category    YARARuleCategory  `json:"category"`
	Severity    Severity          `json:"severity"`
	Reference   string            `json:"reference,omitempty"`
	SubmittedBy uuid.UUID         `json:"submitted_by"`
	Status      SubmissionStatus  `json:"status"`
	ReviewNotes string            `json:"review_notes,omitempty"`
	SubmittedAt time.Time         `json:"submitted_at"`
	ReviewedAt  *time.Time        `json:"reviewed_at,omitempty"`
}

// SubmissionStatus represents the status of a rule submission
type SubmissionStatus string

const (
	SubmissionStatusPending  SubmissionStatus = "pending"
	SubmissionStatusApproved SubmissionStatus = "approved"
	SubmissionStatusRejected SubmissionStatus = "rejected"
)
