package models

import (
	"time"

	"github.com/google/uuid"
)

// MITREDomain represents the ATT&CK domain
type MITREDomain string

const (
	MITREDomainEnterprise MITREDomain = "enterprise-attack"
	MITREDomainMobile     MITREDomain = "mobile-attack"
	MITREDomainICS        MITREDomain = "ics-attack"
)

// MITREObjectType represents the type of ATT&CK object
type MITREObjectType string

const (
	MITRETypeTactic        MITREObjectType = "x-mitre-tactic"
	MITRETypeTechnique     MITREObjectType = "attack-pattern"
	MITRETypeMitigation    MITREObjectType = "course-of-action"
	MITRETypeGroup         MITREObjectType = "intrusion-set"
	MITRETypeSoftware      MITREObjectType = "malware"
	MITRETypeTool          MITREObjectType = "tool"
	MITRETypeDataSource    MITREObjectType = "x-mitre-data-source"
	MITRETypeDataComponent MITREObjectType = "x-mitre-data-component"
	MITRETypeRelationship  MITREObjectType = "relationship"
)

// MITRETactic represents a MITRE ATT&CK tactic
type MITRETactic struct {
	ID             string      `json:"id" db:"id"`                           // e.g., TA0001
	STIXID         string      `json:"stix_id" db:"stix_id"`                 // e.g., x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263
	Name           string      `json:"name" db:"name"`                       // e.g., Initial Access
	Description    string      `json:"description" db:"description"`
	ShortName      string      `json:"short_name" db:"short_name"`           // e.g., initial-access
	Domain         MITREDomain `json:"domain" db:"domain"`
	TechniqueCount int         `json:"technique_count" db:"technique_count"`
	URL            string      `json:"url" db:"url"`
	Created        time.Time   `json:"created" db:"created"`
	Modified       time.Time   `json:"modified" db:"modified"`
}

// MITRETechnique represents a MITRE ATT&CK technique or sub-technique
type MITRETechnique struct {
	ID               string         `json:"id" db:"id"`                       // e.g., T1566 or T1566.001
	STIXID           string         `json:"stix_id" db:"stix_id"`
	Name             string         `json:"name" db:"name"`                   // e.g., Phishing
	Description      string         `json:"description" db:"description"`
	IsSubTechnique   bool           `json:"is_sub_technique" db:"is_sub_technique"`
	ParentID         string         `json:"parent_id,omitempty" db:"parent_id"` // For sub-techniques
	TacticIDs        []string       `json:"tactic_ids" db:"-"`                  // Associated tactics
	Tactics          []string       `json:"tactics" db:"-"`                     // Tactic names
	Platforms        []string       `json:"platforms" db:"-"`                   // windows, linux, macos, android, ios
	Domain           MITREDomain    `json:"domain" db:"domain"`
	PermissionsRequired []string    `json:"permissions_required,omitempty" db:"-"`
	DataSources      []string       `json:"data_sources,omitempty" db:"-"`
	DefenseBypassed  []string       `json:"defense_bypassed,omitempty" db:"-"`
	Detection        string         `json:"detection,omitempty" db:"detection"`
	URL              string         `json:"url" db:"url"`
	Deprecated       bool           `json:"deprecated" db:"deprecated"`
	Revoked          bool           `json:"revoked" db:"revoked"`
	Created          time.Time      `json:"created" db:"created"`
	Modified         time.Time      `json:"modified" db:"modified"`

	// Relationships
	Mitigations      []MITREMitigation `json:"mitigations,omitempty" db:"-"`
	SubTechniques    []MITRETechnique  `json:"sub_techniques,omitempty" db:"-"`
	Groups           []MITREGroup      `json:"groups,omitempty" db:"-"`
	Software         []MITRESoftware   `json:"software,omitempty" db:"-"`
}

// MITREMitigation represents a MITRE ATT&CK mitigation
type MITREMitigation struct {
	ID          string      `json:"id" db:"id"`          // e.g., M1049
	STIXID      string      `json:"stix_id" db:"stix_id"`
	Name        string      `json:"name" db:"name"`      // e.g., Antivirus/Antimalware
	Description string      `json:"description" db:"description"`
	Domain      MITREDomain `json:"domain" db:"domain"`
	URL         string      `json:"url" db:"url"`
	Deprecated  bool        `json:"deprecated" db:"deprecated"`
	Created     time.Time   `json:"created" db:"created"`
	Modified    time.Time   `json:"modified" db:"modified"`
}

// MITREGroup represents a MITRE ATT&CK group (threat actor)
type MITREGroup struct {
	ID          string      `json:"id" db:"id"`          // e.g., G0016
	STIXID      string      `json:"stix_id" db:"stix_id"`
	Name        string      `json:"name" db:"name"`      // e.g., APT29
	Description string      `json:"description" db:"description"`
	Aliases     []string    `json:"aliases" db:"-"`
	Domain      MITREDomain `json:"domain" db:"domain"`
	URL         string      `json:"url" db:"url"`
	Deprecated  bool        `json:"deprecated" db:"deprecated"`
	Created     time.Time   `json:"created" db:"created"`
	Modified    time.Time   `json:"modified" db:"modified"`

	// Associated techniques
	Techniques []string `json:"techniques,omitempty" db:"-"`
}

// MITRESoftware represents malware or tools in MITRE ATT&CK
type MITRESoftware struct {
	ID          string      `json:"id" db:"id"`          // e.g., S0154
	STIXID      string      `json:"stix_id" db:"stix_id"`
	Name        string      `json:"name" db:"name"`      // e.g., Cobalt Strike
	Description string      `json:"description" db:"description"`
	Type        string      `json:"type" db:"type"`      // malware or tool
	Aliases     []string    `json:"aliases" db:"-"`
	Platforms   []string    `json:"platforms" db:"-"`
	Domain      MITREDomain `json:"domain" db:"domain"`
	URL         string      `json:"url" db:"url"`
	Deprecated  bool        `json:"deprecated" db:"deprecated"`
	Created     time.Time   `json:"created" db:"created"`
	Modified    time.Time   `json:"modified" db:"modified"`

	// Associated techniques
	Techniques []string `json:"techniques,omitempty" db:"-"`
}

// MITREDataSource represents a MITRE ATT&CK data source
type MITREDataSource struct {
	ID          string   `json:"id" db:"id"`
	STIXID      string   `json:"stix_id" db:"stix_id"`
	Name        string   `json:"name" db:"name"`
	Description string   `json:"description" db:"description"`
	Platforms   []string `json:"platforms" db:"-"`
	Components  []string `json:"components,omitempty" db:"-"`
	URL         string   `json:"url" db:"url"`
}

// MITRERelationship represents a relationship between ATT&CK objects
type MITRERelationship struct {
	ID               string `json:"id" db:"id"`
	SourceRef        string `json:"source_ref" db:"source_ref"`
	TargetRef        string `json:"target_ref" db:"target_ref"`
	RelationshipType string `json:"relationship_type" db:"relationship_type"` // uses, mitigates, etc.
	Description      string `json:"description,omitempty" db:"description"`
}

// MITREMapping represents a mapping from an indicator to MITRE techniques
type MITREMapping struct {
	ID           uuid.UUID   `json:"id" db:"id"`
	IndicatorID  uuid.UUID   `json:"indicator_id" db:"indicator_id"`
	TechniqueID  string      `json:"technique_id" db:"technique_id"`
	TacticID     string      `json:"tactic_id,omitempty" db:"tactic_id"`
	Confidence   float64     `json:"confidence" db:"confidence"`       // 0.0 - 1.0
	MappingType  string      `json:"mapping_type" db:"mapping_type"`   // auto, manual, vendor
	Source       string      `json:"source,omitempty" db:"source"`     // who/what made the mapping
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
}

// MITREIndicatorMapping is the full mapping with technique details
type MITREIndicatorMapping struct {
	MITREMapping
	Technique    *MITRETechnique `json:"technique,omitempty"`
	Tactic       *MITRETactic    `json:"tactic,omitempty"`
}

// MITREMatrix represents the full ATT&CK matrix
type MITREMatrix struct {
	Domain       MITREDomain      `json:"domain"`
	Version      string           `json:"version"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Tactics      []MITRETactic    `json:"tactics"`
	Techniques   []MITRETechnique `json:"techniques"`
	Mitigations  []MITREMitigation `json:"mitigations"`
	Groups       []MITREGroup     `json:"groups"`
	Software     []MITRESoftware  `json:"software"`
	DataSources  []MITREDataSource `json:"data_sources"`
	LastUpdated  time.Time        `json:"last_updated"`
}

// MITRESearchResult represents search results
type MITRESearchResult struct {
	Techniques   []MITRETechnique  `json:"techniques,omitempty"`
	Tactics      []MITRETactic     `json:"tactics,omitempty"`
	Groups       []MITREGroup      `json:"groups,omitempty"`
	Software     []MITRESoftware   `json:"software,omitempty"`
	Mitigations  []MITREMitigation `json:"mitigations,omitempty"`
	TotalResults int               `json:"total_results"`
}

// MITRETechniqueFilter represents filter options for techniques
type MITRETechniqueFilter struct {
	TacticID        string      `json:"tactic_id,omitempty"`
	Platform        string      `json:"platform,omitempty"`
	Domain          MITREDomain `json:"domain,omitempty"`
	IsSubTechnique  *bool       `json:"is_sub_technique,omitempty"`
	IncludeRevoked  bool        `json:"include_revoked"`
	Query           string      `json:"query,omitempty"`
	Limit           int         `json:"limit,omitempty"`
	Offset          int         `json:"offset,omitempty"`
}

// NavigatorLayer represents an ATT&CK Navigator layer (for export)
type NavigatorLayer struct {
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Domain          string             `json:"domain"`
	Description     string             `json:"description"`
	Filters         NavigatorFilters   `json:"filters"`
	Sorting         int                `json:"sorting"`
	Layout          NavigatorLayout    `json:"layout"`
	HideDisabled    bool               `json:"hideDisabled"`
	Techniques      []NavigatorTechniqueScore `json:"techniques"`
	Gradient        NavigatorGradient  `json:"gradient"`
	LegendItems     []NavigatorLegendItem `json:"legendItems,omitempty"`
	ShowTacticRowBackground bool       `json:"showTacticRowBackground"`
	TacticRowBackground string         `json:"tacticRowBackground"`
	SelectTechniquesAcrossTactics bool `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool `json:"selectSubtechniquesWithParent"`
}

// NavigatorFilters represents ATT&CK Navigator filters
type NavigatorFilters struct {
	Platforms []string `json:"platforms"`
}

// NavigatorLayout represents ATT&CK Navigator layout
type NavigatorLayout struct {
	Layout       string `json:"layout"`
	ShowID       bool   `json:"showID"`
	ShowName     bool   `json:"showName"`
	ShowAggregateScores bool `json:"showAggregateScores"`
	CountUnscored bool  `json:"countUnscored"`
	AggregateFunction string `json:"aggregateFunction"`
	ExpandedSubtechniques string `json:"expandedSubtechniques"`
}

// NavigatorTechniqueScore represents a technique score in Navigator
type NavigatorTechniqueScore struct {
	TechniqueID string   `json:"techniqueID"`
	TacticID    string   `json:"tactic,omitempty"`
	Score       int      `json:"score,omitempty"`
	Color       string   `json:"color,omitempty"`
	Comment     string   `json:"comment,omitempty"`
	Enabled     bool     `json:"enabled"`
	Metadata    []string `json:"metadata,omitempty"`
	ShowSubtechniques bool `json:"showSubtechniques,omitempty"`
}

// NavigatorGradient represents ATT&CK Navigator gradient colors
type NavigatorGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

// NavigatorLegendItem represents a legend item in Navigator
type NavigatorLegendItem struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// MITREStats represents statistics about the loaded ATT&CK data
type MITREStats struct {
	TotalTactics      int            `json:"total_tactics"`
	TotalTechniques   int            `json:"total_techniques"`
	TotalSubTechniques int           `json:"total_sub_techniques"`
	TotalMitigations  int            `json:"total_mitigations"`
	TotalGroups       int            `json:"total_groups"`
	TotalSoftware     int            `json:"total_software"`
	TotalDataSources  int            `json:"total_data_sources"`
	TotalRelationships int           `json:"total_relationships"`
	TechniquesByTactic map[string]int `json:"techniques_by_tactic"`
	TechniquesByPlatform map[string]int `json:"techniques_by_platform"`
	EnterpriseVersion string         `json:"enterprise_version"`
	MobileVersion     string         `json:"mobile_version"`
	LastLoaded        time.Time      `json:"last_loaded"`
}

// MITREAutoMapRequest represents a request to auto-map indicators
type MITREAutoMapRequest struct {
	IndicatorIDs []uuid.UUID `json:"indicator_ids"`
	Overwrite    bool        `json:"overwrite"` // overwrite existing mappings
}

// MITREAutoMapResult represents the result of auto-mapping
type MITREAutoMapResult struct {
	TotalIndicators int                     `json:"total_indicators"`
	MappedCount     int                     `json:"mapped_count"`
	SkippedCount    int                     `json:"skipped_count"`
	ErrorCount      int                     `json:"error_count"`
	Mappings        []MITREIndicatorMapping `json:"mappings"`
	ProcessingTime  time.Duration           `json:"processing_time"`
}

// Common mobile-specific tactics for reference
var MobileTactics = []string{
	"initial-access",
	"execution",
	"persistence",
	"privilege-escalation",
	"defense-evasion",
	"credential-access",
	"discovery",
	"lateral-movement",
	"collection",
	"command-and-control",
	"exfiltration",
	"impact",
	"network-effects",
	"remote-service-effects",
}

// TechniqueKeywordMap maps keywords to likely techniques for auto-mapping
var TechniqueKeywordMap = map[string][]string{
	// Mobile-specific
	"pegasus":       {"T1404", "T1407", "T1417", "T1429", "T1512", "T1533"},
	"nso":           {"T1404", "T1407", "T1417", "T1429", "T1512", "T1533"},
	"spyware":       {"T1417", "T1429", "T1512", "T1533", "T1636"},
	"stalkerware":   {"T1417", "T1430", "T1512", "T1533", "T1636"},
	"keylogger":     {"T1417"},
	"screen":        {"T1513"},
	"camera":        {"T1512"},
	"microphone":    {"T1429"},
	"sms":           {"T1636.004", "T1582"},
	"location":      {"T1430"},
	"contacts":      {"T1636.003"},
	"call":          {"T1636.002"},
	"clipboard":     {"T1414"},
	"rooting":       {"T1404"},
	"jailbreak":     {"T1398"},

	// Network/Phishing
	"phishing":      {"T1566", "T1660"},
	"smishing":      {"T1660"},
	"c2":            {"T1071", "T1571", "T1573"},
	"exfil":         {"T1041", "T1048", "T1567"},
	"dns":           {"T1071.004", "T1568"},

	// Injection/Exploitation
	"injection":     {"T1055", "T1059"},
	"exploit":       {"T1203", "T1210", "T1211"},
	"zero-day":      {"T1203"},
	"rce":           {"T1203"},

	// Malware behavior
	"persistence":   {"T1547", "T1574"},
	"evasion":       {"T1027", "T1070", "T1562"},
	"obfuscation":   {"T1027"},
	"packing":       {"T1027.002"},
}
