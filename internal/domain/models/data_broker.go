package models

import (
	"time"

	"github.com/google/uuid"
)

// DataBrokerCategory represents the category of data broker
type DataBrokerCategory string

const (
	BrokerPeopleSearch   DataBrokerCategory = "people_search"   // Spokeo, BeenVerified
	BrokerMarketing      DataBrokerCategory = "marketing"       // Acxiom, Experian Marketing
	BrokerB2BLead        DataBrokerCategory = "b2b_lead"        // ZoomInfo, Apollo
	BrokerRiskMitigation DataBrokerCategory = "risk_mitigation" // LexisNexis
	BrokerFinancial      DataBrokerCategory = "financial"       // Credit bureaus
	BrokerRecruitment    DataBrokerCategory = "recruitment"     // LinkedIn scrapers
	BrokerHealthcare     DataBrokerCategory = "healthcare"      // Medical data
	BrokerLocation       DataBrokerCategory = "location"        // Location data sellers
	BrokerBackground     DataBrokerCategory = "background"      // Background check
	BrokerPublicRecords  DataBrokerCategory = "public_records"  // Court, property records
	BrokerSocialMedia    DataBrokerCategory = "social_media"    // Social media aggregators
	BrokerIdentity       DataBrokerCategory = "identity"        // Identity verification
)

// OptOutMethod represents how to opt out from a broker
type OptOutMethod string

const (
	OptOutMethodWebForm    OptOutMethod = "web_form"    // Fill out web form
	OptOutMethodEmail      OptOutMethod = "email"       // Send email request
	OptOutMethodMail       OptOutMethod = "mail"        // Physical mail required
	OptOutMethodPhone      OptOutMethod = "phone"       // Call to opt out
	OptOutMethodAutomated  OptOutMethod = "automated"   // Can be automated
	OptOutMethodAccountReq OptOutMethod = "account_req" // Requires account creation
	OptOutMethodIDRequired OptOutMethod = "id_required" // ID verification required
	OptOutMethodNone       OptOutMethod = "none"        // No opt-out available
)

// OptOutDifficulty represents how hard it is to opt out
type OptOutDifficulty string

const (
	OptOutDifficultyEasy    OptOutDifficulty = "easy"       // < 5 minutes, automated
	OptOutDifficultyMedium  OptOutDifficulty = "medium"     // 5-15 minutes, some steps
	OptOutDifficultyHard    OptOutDifficulty = "hard"       // > 15 minutes, ID required
	OptOutDifficultyVeryHard OptOutDifficulty = "very_hard" // Mail/phone required
)

// DataBroker represents a data broker that sells personal information
type DataBroker struct {
	ID          uuid.UUID          `json:"id" db:"id"`
	Name        string             `json:"name" db:"name"`
	Domain      string             `json:"domain" db:"domain"`
	Category    DataBrokerCategory `json:"category" db:"category"`
	Description string             `json:"description,omitempty" db:"description"`

	// Data they collect
	DataTypes      []ExposureType `json:"data_types" db:"data_types"`
	DataSources    []string       `json:"data_sources,omitempty" db:"data_sources"` // Where they get data

	// Coverage
	Countries      []string `json:"countries" db:"countries"`     // Countries covered
	RecordCount    string   `json:"record_count,omitempty" db:"record_count"` // e.g., "200+ million"

	// URLs
	SiteURL        string `json:"site_url" db:"site_url"`
	SearchURL      string `json:"search_url,omitempty" db:"search_url"`       // Direct search URL
	OptOutURL      string `json:"opt_out_url,omitempty" db:"opt_out_url"`
	PrivacyURL     string `json:"privacy_url,omitempty" db:"privacy_url"`

	// Opt-out process
	OptOutMethod     OptOutMethod     `json:"opt_out_method" db:"opt_out_method"`
	OptOutDifficulty OptOutDifficulty `json:"opt_out_difficulty" db:"opt_out_difficulty"`
	OptOutSteps      []string         `json:"opt_out_steps,omitempty" db:"opt_out_steps"`
	RequiresID       bool             `json:"requires_id" db:"requires_id"`
	RequiresAccount  bool             `json:"requires_account" db:"requires_account"`
	ProcessingDays   int              `json:"processing_days" db:"processing_days"` // Days to complete

	// Automation
	CanAutomate      bool   `json:"can_automate" db:"can_automate"`
	AutomationMethod string `json:"automation_method,omitempty" db:"automation_method"`

	// Legal
	CCPACompliant    bool `json:"ccpa_compliant" db:"ccpa_compliant"`
	GDPRCompliant    bool `json:"gdpr_compliant" db:"gdpr_compliant"`
	HonorsRequests   bool `json:"honors_requests" db:"honors_requests"` // Actually honors opt-out

	// Metadata
	Priority    int       `json:"priority" db:"priority"`       // Higher = more important to remove
	Popularity  int       `json:"popularity" db:"popularity"`   // How commonly found
	LastVerified time.Time `json:"last_verified" db:"last_verified"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// DataBrokerSearchResult represents a search result from a data broker
type DataBrokerSearchResult struct {
	BrokerID     uuid.UUID `json:"broker_id"`
	BrokerName   string    `json:"broker_name"`
	ProfileURL   string    `json:"profile_url"`
	Found        bool      `json:"found"`
	Confidence   float64   `json:"confidence"` // 0-1, how sure we are this is the user
	DataPreview  map[string]string `json:"data_preview,omitempty"`
	SearchedAt   time.Time `json:"searched_at"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// DataBrokerFilter represents filter options for querying brokers
type DataBrokerFilter struct {
	Categories       []DataBrokerCategory `json:"categories,omitempty"`
	Countries        []string             `json:"countries,omitempty"`
	OptOutMethods    []OptOutMethod       `json:"opt_out_methods,omitempty"`
	CanAutomate      *bool                `json:"can_automate,omitempty"`
	CCPACompliant    *bool                `json:"ccpa_compliant,omitempty"`
	MaxDifficulty    *OptOutDifficulty    `json:"max_difficulty,omitempty"`
	MinPriority      *int                 `json:"min_priority,omitempty"`
	Search           string               `json:"search,omitempty"`
	Limit            int                  `json:"limit,omitempty"`
	Offset           int                  `json:"offset,omitempty"`
}

// GetDifficultyScore returns a numeric score for sorting
func (d OptOutDifficulty) Score() int {
	switch d {
	case OptOutDifficultyEasy:
		return 1
	case OptOutDifficultyMedium:
		return 2
	case OptOutDifficultyHard:
		return 3
	case OptOutDifficultyVeryHard:
		return 4
	default:
		return 5
	}
}

// IsEasierThan compares two difficulties
func (d OptOutDifficulty) IsEasierThan(other OptOutDifficulty) bool {
	return d.Score() < other.Score()
}
