package models

import (
	"time"

	"github.com/google/uuid"
)

// IndicatorType represents the type of threat indicator
type IndicatorType string

const (
	IndicatorTypeDomain      IndicatorType = "domain"
	IndicatorTypeIP          IndicatorType = "ip"
	IndicatorTypeIPv6        IndicatorType = "ipv6"
	IndicatorTypeHash        IndicatorType = "hash"
	IndicatorTypeURL         IndicatorType = "url"
	IndicatorTypeProcess     IndicatorType = "process"
	IndicatorTypeCertificate IndicatorType = "certificate"
	IndicatorTypePackage     IndicatorType = "package"
	IndicatorTypeEmail       IndicatorType = "email"
	IndicatorTypeFilePath    IndicatorType = "filepath"
	IndicatorTypeRegistry    IndicatorType = "registry"
	IndicatorTypeYARA        IndicatorType = "yara"
)

// Severity represents the threat severity level
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Platform represents the target platform
type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "macos"
	PlatformLinux   Platform = "linux"
	PlatformAll     Platform = "all"
)

// Indicator represents a single indicator of compromise (IOC)
type Indicator struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	Value       string        `json:"value" db:"value"`
	ValueHash   string        `json:"-" db:"value_hash"` // SHA256 of value for deduplication
	Type        IndicatorType `json:"type" db:"type"`
	Severity    Severity      `json:"severity" db:"severity"`
	Confidence  float64       `json:"confidence" db:"confidence"` // 0.0 - 1.0
	Description string        `json:"description,omitempty" db:"description"`
	Tags        []string      `json:"tags,omitempty" db:"tags"`
	Platforms   []Platform    `json:"platforms,omitempty" db:"platforms"`

	// Source (required for storage)
	SourceID   string `json:"source_id" db:"source_id"`
	SourceName string `json:"source_name" db:"source_name"`

	// Temporal
	FirstSeen time.Time  `json:"first_seen" db:"first_seen"`
	LastSeen  time.Time  `json:"last_seen" db:"last_seen"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// Attribution
	CampaignID      *uuid.UUID `json:"campaign_id,omitempty" db:"campaign_id"`
	ThreatActorID   *uuid.UUID `json:"threat_actor_id,omitempty" db:"threat_actor_id"`
	MalwareFamilyID *uuid.UUID `json:"malware_family_id,omitempty" db:"malware_family_id"`

	// MITRE ATT&CK
	MitreTechniques []string `json:"mitre_techniques,omitempty" db:"mitre_techniques"`
	MitreTactics    []string `json:"mitre_tactics,omitempty" db:"mitre_tactics"`

	// Enrichment
	CVEIDs      []string `json:"cve_ids,omitempty" db:"cve_ids"`
	ReportCount int      `json:"report_count" db:"report_count"`
	SourceCount int      `json:"source_count" db:"source_count"`
	Metadata    []byte   `json:"metadata,omitempty" db:"metadata"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Neo4j graph ID (for correlation)
	GraphNodeID string `json:"-" db:"graph_node_id"`

	// Related data (not stored in main table)
	Sources []IndicatorSource `json:"sources,omitempty" db:"-"`
}

// IndicatorSource represents the relationship between an indicator and its source
type IndicatorSource struct {
	IndicatorID      uuid.UUID  `json:"indicator_id" db:"indicator_id"`
	SourceID         uuid.UUID  `json:"source_id" db:"source_id"`
	SourceName       string     `json:"source_name" db:"source_name"`
	SourceConfidence float64    `json:"source_confidence" db:"source_confidence"`
	RawData          string     `json:"-" db:"raw_data"` // Original data from source
	FetchedAt        time.Time  `json:"fetched_at" db:"fetched_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

// IndicatorFilter represents filter options for querying indicators
type IndicatorFilter struct {
	Types           []IndicatorType `json:"types,omitempty"`
	Severities      []Severity      `json:"severities,omitempty"`
	Platforms       []Platform      `json:"platforms,omitempty"`
	Tags            []string        `json:"tags,omitempty"`
	CampaignID      *uuid.UUID      `json:"campaign_id,omitempty"`
	ThreatActorID   *uuid.UUID      `json:"threat_actor_id,omitempty"`
	MinConfidence   *float64        `json:"min_confidence,omitempty"`
	FirstSeenAfter  *time.Time      `json:"first_seen_after,omitempty"`
	FirstSeenBefore *time.Time      `json:"first_seen_before,omitempty"`
	LastSeenAfter   *time.Time      `json:"last_seen_after,omitempty"`
	IncludeExpired  bool            `json:"include_expired,omitempty"`
	Search          string          `json:"search,omitempty"`
	Limit           int             `json:"limit,omitempty"`
	Offset          int             `json:"offset,omitempty"`
}

// IsPegasus checks if this indicator is related to Pegasus spyware
func (i *Indicator) IsPegasus() bool {
	for _, tag := range i.Tags {
		if tag == "pegasus" || tag == "nso-group" {
			return true
		}
	}
	return false
}

// IsMobile checks if this indicator targets mobile platforms
func (i *Indicator) IsMobile() bool {
	for _, p := range i.Platforms {
		if p == PlatformAndroid || p == PlatformIOS {
			return true
		}
	}
	return false
}

// IsNotExpired checks if the indicator is still active (not expired)
func (i *Indicator) IsNotExpired() bool {
	if i.ExpiresAt == nil {
		return true
	}
	return time.Now().Before(*i.ExpiresAt)
}

// SeverityWeight returns a numeric weight for sorting by severity
func (i *Indicator) SeverityWeight() int {
	switch i.Severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// String returns the string representation of IndicatorType
func (t IndicatorType) String() string {
	return string(t)
}

// ParseIndicatorType parses a string into IndicatorType
func ParseIndicatorType(s string) IndicatorType {
	switch s {
	case "domain":
		return IndicatorTypeDomain
	case "ip":
		return IndicatorTypeIP
	case "ipv6":
		return IndicatorTypeIPv6
	case "hash":
		return IndicatorTypeHash
	case "url":
		return IndicatorTypeURL
	case "process":
		return IndicatorTypeProcess
	case "certificate":
		return IndicatorTypeCertificate
	case "package":
		return IndicatorTypePackage
	case "email":
		return IndicatorTypeEmail
	case "filepath":
		return IndicatorTypeFilePath
	case "registry":
		return IndicatorTypeRegistry
	case "yara":
		return IndicatorTypeYARA
	default:
		return IndicatorType(s)
	}
}

// String returns the string representation of Severity
func (s Severity) String() string {
	return string(s)
}

// ParseSeverity parses a string into Severity
func ParseSeverity(s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	default:
		return Severity(s)
	}
}

// String returns the string representation of Platform
func (p Platform) String() string {
	return string(p)
}

// ParsePlatform parses a string into Platform
func ParsePlatform(s string) Platform {
	switch s {
	case "android":
		return PlatformAndroid
	case "ios":
		return PlatformIOS
	case "windows":
		return PlatformWindows
	case "macos":
		return PlatformMacOS
	case "linux":
		return PlatformLinux
	case "all":
		return PlatformAll
	default:
		return Platform(s)
	}
}
