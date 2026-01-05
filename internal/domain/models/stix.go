package models

import (
	"encoding/json"
	"time"
)

// STIX 2.1 Specification Implementation
// Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

// STIXType represents the type of a STIX object
type STIXType string

// STIX Domain Object (SDO) types
const (
	STIXTypeAttackPattern    STIXType = "attack-pattern"
	STIXTypeCampaign         STIXType = "campaign"
	STIXTypeCourseOfAction   STIXType = "course-of-action"
	STIXTypeGrouping         STIXType = "grouping"
	STIXTypeIdentity         STIXType = "identity"
	STIXTypeIndicator        STIXType = "indicator"
	STIXTypeInfrastructure   STIXType = "infrastructure"
	STIXTypeIntrusionSet     STIXType = "intrusion-set"
	STIXTypeLocation         STIXType = "location"
	STIXTypeMalware          STIXType = "malware"
	STIXTypeMalwareAnalysis  STIXType = "malware-analysis"
	STIXTypeNote             STIXType = "note"
	STIXTypeObservedData     STIXType = "observed-data"
	STIXTypeOpinion          STIXType = "opinion"
	STIXTypeReport           STIXType = "report"
	STIXTypeThreatActor      STIXType = "threat-actor"
	STIXTypeTool             STIXType = "tool"
	STIXTypeVulnerability    STIXType = "vulnerability"
)

// STIX Relationship Object (SRO) types
const (
	STIXTypeRelationship STIXType = "relationship"
	STIXTypeSighting     STIXType = "sighting"
)

// STIX Cyber-observable Object (SCO) types
const (
	STIXTypeArtifact           STIXType = "artifact"
	STIXTypeAutonomousSystem   STIXType = "autonomous-system"
	STIXTypeDirectory          STIXType = "directory"
	STIXTypeDomainName         STIXType = "domain-name"
	STIXTypeEmailAddr          STIXType = "email-addr"
	STIXTypeEmailMessage       STIXType = "email-message"
	STIXTypeFile               STIXType = "file"
	STIXTypeIPv4Addr           STIXType = "ipv4-addr"
	STIXTypeIPv6Addr           STIXType = "ipv6-addr"
	STIXTypeMACAddr            STIXType = "mac-addr"
	STIXTypeMutex              STIXType = "mutex"
	STIXTypeNetworkTraffic     STIXType = "network-traffic"
	STIXTypeProcess            STIXType = "process"
	STIXTypeSoftware           STIXType = "software"
	STIXTypeURL                STIXType = "url"
	STIXTypeUserAccount        STIXType = "user-account"
	STIXTypeWindowsRegistryKey STIXType = "windows-registry-key"
	STIXTypeX509Certificate    STIXType = "x509-certificate"
)

// STIXCommonProperties contains properties common to all STIX objects
type STIXCommonProperties struct {
	Type             STIXType          `json:"type"`
	SpecVersion      string            `json:"spec_version"`
	ID               string            `json:"id"`
	Created          time.Time         `json:"created"`
	Modified         time.Time         `json:"modified"`
	CreatedByRef     string            `json:"created_by_ref,omitempty"`
	Revoked          bool              `json:"revoked,omitempty"`
	Labels           []string          `json:"labels,omitempty"`
	Confidence       int               `json:"confidence,omitempty"`
	Lang             string            `json:"lang,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	ObjectMarkingRefs  []string        `json:"object_marking_refs,omitempty"`
	GranularMarkings   []GranularMarking `json:"granular_markings,omitempty"`
	Extensions       map[string]interface{} `json:"extensions,omitempty"`
}

// ExternalReference represents a reference to external information
type ExternalReference struct {
	SourceName  string            `json:"source_name"`
	Description string            `json:"description,omitempty"`
	URL         string            `json:"url,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
	ExternalID  string            `json:"external_id,omitempty"`
}

// GranularMarking represents a granular marking
type GranularMarking struct {
	Lang       string   `json:"lang,omitempty"`
	MarkingRef string   `json:"marking_ref,omitempty"`
	Selectors  []string `json:"selectors"`
}

// KillChainPhase represents a phase in a kill chain
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// STIXBundle represents a STIX 2.1 bundle
type STIXBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

// NewSTIXBundle creates a new STIX bundle
func NewSTIXBundle(objects []interface{}) *STIXBundle {
	return &STIXBundle{
		Type:    "bundle",
		ID:      "bundle--" + GenerateSTIXUUID(),
		Objects: objects,
	}
}

// STIXIndicator represents a STIX 2.1 Indicator SDO
type STIXIndicator struct {
	STIXCommonProperties
	Name            string           `json:"name,omitempty"`
	Description     string           `json:"description,omitempty"`
	IndicatorTypes  []string         `json:"indicator_types,omitempty"`
	Pattern         string           `json:"pattern"`
	PatternType     string           `json:"pattern_type"`
	PatternVersion  string           `json:"pattern_version,omitempty"`
	ValidFrom       time.Time        `json:"valid_from"`
	ValidUntil      *time.Time       `json:"valid_until,omitempty"`
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// STIXMalware represents a STIX 2.1 Malware SDO
type STIXMalware struct {
	STIXCommonProperties
	Name              string           `json:"name"`
	Description       string           `json:"description,omitempty"`
	MalwareTypes      []string         `json:"malware_types"`
	IsFamily          bool             `json:"is_family"`
	Aliases           []string         `json:"aliases,omitempty"`
	KillChainPhases   []KillChainPhase `json:"kill_chain_phases,omitempty"`
	FirstSeen         *time.Time       `json:"first_seen,omitempty"`
	LastSeen          *time.Time       `json:"last_seen,omitempty"`
	OperatingSystemRefs []string       `json:"operating_system_refs,omitempty"`
	ArchitectureExecutionEnvs []string `json:"architecture_execution_envs,omitempty"`
	ImplementationLanguages []string   `json:"implementation_languages,omitempty"`
	Capabilities      []string         `json:"capabilities,omitempty"`
	SampleRefs        []string         `json:"sample_refs,omitempty"`
}

// STIXThreatActor represents a STIX 2.1 Threat Actor SDO
type STIXThreatActor struct {
	STIXCommonProperties
	Name              string     `json:"name"`
	Description       string     `json:"description,omitempty"`
	ThreatActorTypes  []string   `json:"threat_actor_types,omitempty"`
	Aliases           []string   `json:"aliases,omitempty"`
	FirstSeen         *time.Time `json:"first_seen,omitempty"`
	LastSeen          *time.Time `json:"last_seen,omitempty"`
	Roles             []string   `json:"roles,omitempty"`
	Goals             []string   `json:"goals,omitempty"`
	Sophistication    string     `json:"sophistication,omitempty"`
	ResourceLevel     string     `json:"resource_level,omitempty"`
	PrimaryMotivation string     `json:"primary_motivation,omitempty"`
	SecondaryMotivations []string `json:"secondary_motivations,omitempty"`
	PersonalMotivations []string `json:"personal_motivations,omitempty"`
}

// STIXCampaign represents a STIX 2.1 Campaign SDO
type STIXCampaign struct {
	STIXCommonProperties
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Aliases     []string   `json:"aliases,omitempty"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Objective   string     `json:"objective,omitempty"`
}

// STIXAttackPattern represents a STIX 2.1 Attack Pattern SDO
type STIXAttackPattern struct {
	STIXCommonProperties
	Name            string           `json:"name"`
	Description     string           `json:"description,omitempty"`
	Aliases         []string         `json:"aliases,omitempty"`
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// STIXIdentity represents a STIX 2.1 Identity SDO
type STIXIdentity struct {
	STIXCommonProperties
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	IdentityClass string   `json:"identity_class,omitempty"`
	Sectors       []string `json:"sectors,omitempty"`
	ContactInformation string `json:"contact_information,omitempty"`
}

// STIXRelationship represents a STIX 2.1 Relationship SRO
type STIXRelationship struct {
	STIXCommonProperties
	RelationshipType string     `json:"relationship_type"`
	Description      string     `json:"description,omitempty"`
	SourceRef        string     `json:"source_ref"`
	TargetRef        string     `json:"target_ref"`
	StartTime        *time.Time `json:"start_time,omitempty"`
	StopTime         *time.Time `json:"stop_time,omitempty"`
}

// STIXSighting represents a STIX 2.1 Sighting SRO
type STIXSighting struct {
	STIXCommonProperties
	Description        string     `json:"description,omitempty"`
	FirstSeen          *time.Time `json:"first_seen,omitempty"`
	LastSeen           *time.Time `json:"last_seen,omitempty"`
	Count              int        `json:"count,omitempty"`
	SightingOfRef      string     `json:"sighting_of_ref"`
	ObservedDataRefs   []string   `json:"observed_data_refs,omitempty"`
	WhereSightedRefs   []string   `json:"where_sighted_refs,omitempty"`
	Summary            bool       `json:"summary,omitempty"`
}

// STIXMarkingDefinition represents a STIX 2.1 Marking Definition
type STIXMarkingDefinition struct {
	Type             STIXType    `json:"type"`
	SpecVersion      string      `json:"spec_version"`
	ID               string      `json:"id"`
	Created          time.Time   `json:"created"`
	CreatedByRef     string      `json:"created_by_ref,omitempty"`
	Name             string      `json:"name,omitempty"`
	DefinitionType   string      `json:"definition_type"`
	Definition       interface{} `json:"definition"`
}

// TLPMarking represents a TLP (Traffic Light Protocol) marking
type TLPMarking struct {
	TLP string `json:"tlp"`
}

// StatementMarking represents a statement marking
type StatementMarking struct {
	Statement string `json:"statement"`
}

// STIX Cyber-observable Objects (SCOs)

// STIXDomainName represents a STIX 2.1 Domain Name SCO
type STIXDomainName struct {
	Type        STIXType `json:"type"`
	SpecVersion string   `json:"spec_version,omitempty"`
	ID          string   `json:"id"`
	Value       string   `json:"value"`
	ResolvesToRefs []string `json:"resolves_to_refs,omitempty"`
}

// STIXIPv4Addr represents a STIX 2.1 IPv4 Address SCO
type STIXIPv4Addr struct {
	Type         STIXType `json:"type"`
	SpecVersion  string   `json:"spec_version,omitempty"`
	ID           string   `json:"id"`
	Value        string   `json:"value"`
	ResolvesToRefs []string `json:"resolves_to_refs,omitempty"`
	BelongsToRefs  []string `json:"belongs_to_refs,omitempty"`
}

// STIXIPv6Addr represents a STIX 2.1 IPv6 Address SCO
type STIXIPv6Addr struct {
	Type         STIXType `json:"type"`
	SpecVersion  string   `json:"spec_version,omitempty"`
	ID           string   `json:"id"`
	Value        string   `json:"value"`
	ResolvesToRefs []string `json:"resolves_to_refs,omitempty"`
	BelongsToRefs  []string `json:"belongs_to_refs,omitempty"`
}

// STIXURL represents a STIX 2.1 URL SCO
type STIXURL struct {
	Type        STIXType `json:"type"`
	SpecVersion string   `json:"spec_version,omitempty"`
	ID          string   `json:"id"`
	Value       string   `json:"value"`
}

// STIXFile represents a STIX 2.1 File SCO
type STIXFile struct {
	Type           STIXType          `json:"type"`
	SpecVersion    string            `json:"spec_version,omitempty"`
	ID             string            `json:"id"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	Size           int64             `json:"size,omitempty"`
	Name           string            `json:"name,omitempty"`
	NameEnc        string            `json:"name_enc,omitempty"`
	MagicNumberHex string            `json:"magic_number_hex,omitempty"`
	MimeType       string            `json:"mime_type,omitempty"`
	Ctime          *time.Time        `json:"ctime,omitempty"`
	Mtime          *time.Time        `json:"mtime,omitempty"`
	Atime          *time.Time        `json:"atime,omitempty"`
	ParentDirectoryRef string        `json:"parent_directory_ref,omitempty"`
	ContainsRefs   []string          `json:"contains_refs,omitempty"`
	ContentRef     string            `json:"content_ref,omitempty"`
}

// STIXEmailAddr represents a STIX 2.1 Email Address SCO
type STIXEmailAddr struct {
	Type        STIXType `json:"type"`
	SpecVersion string   `json:"spec_version,omitempty"`
	ID          string   `json:"id"`
	Value       string   `json:"value"`
	DisplayName string   `json:"display_name,omitempty"`
	BelongsToRef string  `json:"belongs_to_ref,omitempty"`
}

// Indicator type vocabularies
var IndicatorTypeVocab = []string{
	"anomalous-activity",
	"anonymization",
	"benign",
	"compromised",
	"malicious-activity",
	"attribution",
	"unknown",
}

// Malware type vocabularies
var MalwareTypeVocab = []string{
	"adware",
	"backdoor",
	"bot",
	"bootkit",
	"ddos",
	"downloader",
	"dropper",
	"exploit-kit",
	"keylogger",
	"ransomware",
	"remote-access-trojan",
	"resource-exploitation",
	"rogue-security-software",
	"rootkit",
	"screen-capture",
	"spyware",
	"trojan",
	"unknown",
	"virus",
	"webshell",
	"wiper",
	"worm",
}

// Threat actor type vocabularies
var ThreatActorTypeVocab = []string{
	"activist",
	"competitor",
	"crime-syndicate",
	"criminal",
	"hacker",
	"insider-accidental",
	"insider-disgruntled",
	"nation-state",
	"sensationalist",
	"spy",
	"terrorist",
	"unknown",
}

// Standard TLP marking definitions
var (
	TLPWhite = &STIXMarkingDefinition{
		Type:           "marking-definition",
		SpecVersion:    "2.1",
		ID:             "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
		Created:        time.Date(2017, 1, 20, 0, 0, 0, 0, time.UTC),
		DefinitionType: "tlp",
		Definition:     TLPMarking{TLP: "white"},
		Name:           "TLP:WHITE",
	}
	TLPGreen = &STIXMarkingDefinition{
		Type:           "marking-definition",
		SpecVersion:    "2.1",
		ID:             "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
		Created:        time.Date(2017, 1, 20, 0, 0, 0, 0, time.UTC),
		DefinitionType: "tlp",
		Definition:     TLPMarking{TLP: "green"},
		Name:           "TLP:GREEN",
	}
	TLPAmber = &STIXMarkingDefinition{
		Type:           "marking-definition",
		SpecVersion:    "2.1",
		ID:             "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
		Created:        time.Date(2017, 1, 20, 0, 0, 0, 0, time.UTC),
		DefinitionType: "tlp",
		Definition:     TLPMarking{TLP: "amber"},
		Name:           "TLP:AMBER",
	}
	TLPRed = &STIXMarkingDefinition{
		Type:           "marking-definition",
		SpecVersion:    "2.1",
		ID:             "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
		Created:        time.Date(2017, 1, 20, 0, 0, 0, 0, time.UTC),
		DefinitionType: "tlp",
		Definition:     TLPMarking{TLP: "red"},
		Name:           "TLP:RED",
	}
)

// GenerateSTIXUUID generates a UUID for STIX objects
func GenerateSTIXUUID() string {
	return generateUUIDv4()
}

// GenerateSTIXID generates a STIX ID for a given type
func GenerateSTIXID(stixType STIXType) string {
	return string(stixType) + "--" + GenerateSTIXUUID()
}

// Helper function to generate UUID v4
func generateUUIDv4() string {
	// This will be replaced with actual UUID generation
	// For now, use a placeholder that will be overwritten
	return "00000000-0000-0000-0000-000000000000"
}

// MarshalJSON implements custom JSON marshaling for STIXBundle
func (b *STIXBundle) MarshalJSON() ([]byte, error) {
	type Alias STIXBundle
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(b),
	})
}

// PatternType constants for STIX patterns
const (
	PatternTypeSTIX   = "stix"
	PatternTypePCRE   = "pcre"
	PatternTypeSigma  = "sigma"
	PatternTypeSNORT  = "snort"
	PatternTypeYARA   = "yara"
)
