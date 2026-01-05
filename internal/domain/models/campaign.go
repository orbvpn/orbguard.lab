package models

import (
	"time"

	"github.com/google/uuid"
)

// CampaignStatus represents the current status of a campaign
type CampaignStatus string

const (
	CampaignStatusActive   CampaignStatus = "active"
	CampaignStatusInactive CampaignStatus = "inactive"
	CampaignStatusHistoric CampaignStatus = "historic"
)

// Campaign represents a threat campaign (e.g., Pegasus, Predator)
type Campaign struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Slug        string         `json:"slug" db:"slug"`
	Description string         `json:"description,omitempty" db:"description"`
	Status      CampaignStatus `json:"status" db:"status"`

	// Attribution
	ThreatActorID *uuid.UUID `json:"threat_actor_id,omitempty" db:"threat_actor_id"`
	ThreatActor   *ThreatActor `json:"threat_actor,omitempty" db:"-"`

	// Targets
	TargetSectors  []string   `json:"target_sectors,omitempty" db:"target_sectors"`   // journalism, activists, government
	TargetRegions  []string   `json:"target_regions,omitempty" db:"target_regions"`   // countries/regions
	TargetPlatforms []Platform `json:"target_platforms,omitempty" db:"target_platforms"`

	// MITRE ATT&CK
	MitreTechniques []string `json:"mitre_techniques,omitempty" db:"mitre_techniques"`
	MitreTactics    []string `json:"mitre_tactics,omitempty" db:"mitre_tactics"`

	// Temporal
	FirstSeen  time.Time  `json:"first_seen" db:"first_seen"`
	LastSeen   time.Time  `json:"last_seen" db:"last_seen"`
	StartDate  *time.Time `json:"start_date,omitempty" db:"start_date"`
	EndDate    *time.Time `json:"end_date,omitempty" db:"end_date"`

	// Statistics
	IndicatorCount int `json:"indicator_count" db:"indicator_count"`

	// Status
	IsActive bool `json:"is_active" db:"is_active"`

	// Metadata
	References []string       `json:"references,omitempty" db:"references"` // URLs to research/reports
	Metadata   map[string]any `json:"metadata,omitempty" db:"metadata"`

	// Denormalized fields (populated from joins)
	ThreatActorName string `json:"threat_actor_name,omitempty" db:"-"`

	// Neo4j graph ID
	GraphNodeID *string `json:"-" db:"graph_node_id"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ThreatActorMotivation represents the motivation of a threat actor
type ThreatActorMotivation string

const (
	MotivationEspionage   ThreatActorMotivation = "espionage"
	MotivationFinancial   ThreatActorMotivation = "financial"
	MotivationSabotage    ThreatActorMotivation = "sabotage"
	MotivationSurveillance ThreatActorMotivation = "surveillance"
	MotivationHacktivism  ThreatActorMotivation = "hacktivism"
)

// ThreatActorType represents the type of threat actor
type ThreatActorType string

const (
	ActorTypeNationState  ThreatActorType = "nation-state"
	ActorTypeCriminal     ThreatActorType = "criminal"
	ActorTypeHacktivist   ThreatActorType = "hacktivist"
	ActorTypePrivateSector ThreatActorType = "private-sector" // e.g., NSO Group
	ActorTypeUnknown      ThreatActorType = "unknown"
)

// ThreatActor represents a threat actor (e.g., NSO Group, APT28)
type ThreatActor struct {
	ID          uuid.UUID             `json:"id" db:"id"`
	Name        string                `json:"name" db:"name"`
	Aliases     []string              `json:"aliases,omitempty" db:"aliases"`
	Description string                `json:"description,omitempty" db:"description"`
	Type        ThreatActorType       `json:"type" db:"type"`
	Motivation  ThreatActorMotivation `json:"motivation,omitempty" db:"motivation"`
	Country     string                `json:"country,omitempty" db:"country"`
	Active      bool                  `json:"active" db:"active"`

	// Targets
	TargetSectors  []string `json:"target_sectors,omitempty" db:"target_sectors"`
	TargetRegions  []string `json:"target_regions,omitempty" db:"target_regions"`

	// MITRE ATT&CK
	CommonTechniques []string `json:"common_techniques,omitempty" db:"common_techniques"`

	// Statistics
	CampaignCount  int `json:"campaign_count" db:"campaign_count"`
	IndicatorCount int `json:"indicator_count" db:"indicator_count"`

	// Metadata
	References []string       `json:"references,omitempty" db:"references"`
	Metadata   map[string]any `json:"metadata,omitempty" db:"metadata"`

	// Neo4j graph ID
	GraphNodeID *string `json:"-" db:"graph_node_id"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// MalwareFamily represents a malware family (e.g., Pegasus, Predator, Hermit)
type MalwareFamily struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Aliases     []string   `json:"aliases,omitempty" db:"aliases"`
	Description string     `json:"description,omitempty" db:"description"`
	Type        string     `json:"type" db:"type"` // spyware, ransomware, trojan, etc.
	Platforms   []Platform `json:"platforms,omitempty" db:"platforms"`

	// Attribution
	ThreatActorID *uuid.UUID   `json:"threat_actor_id,omitempty" db:"threat_actor_id"`
	ThreatActor   *ThreatActor `json:"threat_actor,omitempty" db:"-"`

	// MITRE ATT&CK
	Techniques []string `json:"techniques,omitempty" db:"techniques"`

	// Capabilities
	Capabilities []string `json:"capabilities,omitempty" db:"capabilities"` // keylogging, screen_capture, etc.

	// Statistics
	IndicatorCount int `json:"indicator_count" db:"indicator_count"`
	CampaignCount  int `json:"campaign_count" db:"campaign_count"`

	// Temporal
	FirstSeen time.Time `json:"first_seen" db:"first_seen"`
	LastSeen  time.Time `json:"last_seen" db:"last_seen"`

	// Metadata
	References []string       `json:"references,omitempty" db:"references"`
	Metadata   map[string]any `json:"metadata,omitempty" db:"metadata"`

	// Neo4j graph ID
	GraphNodeID *string `json:"-" db:"graph_node_id"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// DefaultCampaigns returns well-known campaigns for initial seeding
func DefaultCampaigns() []Campaign {
	now := time.Now()
	return []Campaign{
		{
			Name:        "Pegasus",
			Slug:        "pegasus",
			Description: "NSO Group's Pegasus spyware targeting iOS and Android devices",
			Status:      CampaignStatusActive,
			TargetSectors: []string{"journalism", "activists", "government", "lawyers"},
			TargetPlatforms: []Platform{PlatformIOS, PlatformAndroid},
			MitreTechniques: []string{
				"T1430", // Location Tracking
				"T1417", // Input Capture
				"T1636.004", // SMS Messages
				"T1512", // Video Capture
				"T1429", // Audio Capture
			},
			FirstSeen: time.Date(2016, 8, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:  now,
			References: []string{
				"https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/",
				"https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/",
			},
		},
		{
			Name:        "Predator",
			Slug:        "predator",
			Description: "Cytrox's Predator spyware similar to Pegasus",
			Status:      CampaignStatusActive,
			TargetSectors: []string{"journalism", "politicians", "activists"},
			TargetPlatforms: []Platform{PlatformIOS, PlatformAndroid},
			FirstSeen: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:  now,
		},
		{
			Name:        "Hermit",
			Slug:        "hermit",
			Description: "Italian spyware by RCS Lab targeting Android and iOS",
			Status:      CampaignStatusActive,
			TargetSectors: []string{"activists", "government"},
			TargetPlatforms: []Platform{PlatformIOS, PlatformAndroid},
			FirstSeen: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:  now,
		},
	}
}

// DefaultThreatActors returns well-known threat actors for initial seeding
func DefaultThreatActors() []ThreatActor {
	return []ThreatActor{
		{
			Name:        "NSO Group",
			Aliases:     []string{"Q Cyber Technologies"},
			Description: "Israeli cyber intelligence company known for Pegasus spyware",
			Type:        ActorTypePrivateSector,
			Motivation:  MotivationSurveillance,
			Country:     "Israel",
			Active:      true,
			TargetSectors: []string{"journalism", "activists", "government", "lawyers"},
		},
		{
			Name:        "Cytrox",
			Aliases:     []string{"Intellexa"},
			Description: "Spyware vendor known for Predator",
			Type:        ActorTypePrivateSector,
			Motivation:  MotivationSurveillance,
			Country:     "North Macedonia",
			Active:      true,
		},
		{
			Name:        "RCS Lab",
			Description: "Italian spyware company",
			Type:        ActorTypePrivateSector,
			Motivation:  MotivationSurveillance,
			Country:     "Italy",
			Active:      true,
		},
		{
			Name:        "FinFisher",
			Aliases:     []string{"Gamma Group"},
			Description: "Surveillance software company",
			Type:        ActorTypePrivateSector,
			Motivation:  MotivationSurveillance,
			Country:     "Germany",
			Active:      false, // Company shut down
		},
	}
}

// DefaultMalwareFamilies returns well-known malware families for initial seeding
func DefaultMalwareFamilies() []MalwareFamily {
	now := time.Now()
	return []MalwareFamily{
		{
			Name:        "Pegasus",
			Description: "Advanced mobile spyware by NSO Group",
			Type:        "spyware",
			Platforms:   []Platform{PlatformIOS, PlatformAndroid},
			Capabilities: []string{
				"keylogging",
				"screen_capture",
				"microphone_access",
				"camera_access",
				"location_tracking",
				"message_interception",
				"contact_exfiltration",
			},
			Techniques: []string{
				"T1430", "T1417", "T1636.004", "T1512", "T1429",
			},
			FirstSeen: time.Date(2016, 8, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:  now,
		},
		{
			Name:        "Predator",
			Description: "Mobile spyware by Cytrox/Intellexa",
			Type:        "spyware",
			Platforms:   []Platform{PlatformIOS, PlatformAndroid},
			FirstSeen:   time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:    now,
		},
		{
			Name:        "Hermit",
			Description: "Mobile spyware by RCS Lab",
			Type:        "spyware",
			Platforms:   []Platform{PlatformIOS, PlatformAndroid},
			FirstSeen:   time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:    now,
		},
	}
}
