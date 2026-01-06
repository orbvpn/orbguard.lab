package models

import (
	"time"

	"github.com/google/uuid"
)

// ExposureType represents the type of data exposure
type ExposureType string

const (
	ExposureTypeEmail          ExposureType = "email"
	ExposureTypePhone          ExposureType = "phone"
	ExposureTypeAddress        ExposureType = "address"
	ExposureTypeSSN            ExposureType = "ssn"
	ExposureTypeDateOfBirth    ExposureType = "dob"
	ExposureTypeName           ExposureType = "name"
	ExposureTypeUsername       ExposureType = "username"
	ExposureTypePassword       ExposureType = "password"
	ExposureTypeCreditCard     ExposureType = "credit_card"
	ExposureTypeBankAccount    ExposureType = "bank_account"
	ExposureTypeDriverLicense  ExposureType = "driver_license"
	ExposureTypePassport       ExposureType = "passport"
	ExposureTypeIPAddress      ExposureType = "ip_address"
	ExposureTypePhoto          ExposureType = "photo"
	ExposureTypeEmployment     ExposureType = "employment"
	ExposureTypeEducation      ExposureType = "education"
	ExposureTypeRelatives      ExposureType = "relatives"
	ExposureTypePropertyRecord ExposureType = "property"
	ExposureTypeCourtRecord    ExposureType = "court_record"
	ExposureTypeSocialProfile  ExposureType = "social_profile"
	ExposureTypeLocation       ExposureType = "location"
)

// ExposureSeverity represents the severity of data exposure
type ExposureSeverity string

const (
	ExposureSeverityCritical ExposureSeverity = "critical" // SSN, passwords, financial
	ExposureSeverityHigh     ExposureSeverity = "high"     // Full address, DOB, phone
	ExposureSeverityMedium   ExposureSeverity = "medium"   // Partial info, employment
	ExposureSeverityLow      ExposureSeverity = "low"      // Public info, name
	ExposureSeverityInfo     ExposureSeverity = "info"     // Non-sensitive data
)

// ExposureSource represents where the exposure was found
type ExposureSource string

const (
	ExposureSourceDataBroker  ExposureSource = "data_broker"
	ExposureSourceDarkWeb     ExposureSource = "dark_web"
	ExposureSourceBreach      ExposureSource = "breach"
	ExposureSourcePasteSite   ExposureSource = "paste_site"
	ExposureSourceSocialMedia ExposureSource = "social_media"
	ExposureSourcePublicRecord ExposureSource = "public_record"
	ExposureSourceSearchEngine ExposureSource = "search_engine"
)

// DigitalFootprint represents a user's digital footprint scan result
type DigitalFootprint struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`

	// Scan metadata
	ScanType      string    `json:"scan_type" db:"scan_type"` // full, quick, targeted
	Status        string    `json:"status" db:"status"`       // pending, running, completed, failed
	StartedAt     time.Time `json:"started_at" db:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty" db:"completed_at"`

	// Input data (encrypted)
	SearchEmail     string   `json:"search_email,omitempty" db:"search_email"`
	SearchPhone     string   `json:"search_phone,omitempty" db:"search_phone"`
	SearchName      string   `json:"search_name,omitempty" db:"search_name"`
	SearchAddresses []string `json:"search_addresses,omitempty" db:"search_addresses"`

	// Results summary
	TotalExposures     int     `json:"total_exposures" db:"total_exposures"`
	CriticalExposures  int     `json:"critical_exposures" db:"critical_exposures"`
	HighExposures      int     `json:"high_exposures" db:"high_exposures"`
	MediumExposures    int     `json:"medium_exposures" db:"medium_exposures"`
	LowExposures       int     `json:"low_exposures" db:"low_exposures"`
	DataBrokersFound   int     `json:"data_brokers_found" db:"data_brokers_found"`
	BreachesFound      int     `json:"breaches_found" db:"breaches_found"`
	DarkWebExposures   int     `json:"dark_web_exposures" db:"dark_web_exposures"`
	SocialMediaRisks   int     `json:"social_media_risks" db:"social_media_risks"`

	// Risk score (0-100)
	RiskScore          float64 `json:"risk_score" db:"risk_score"`
	RiskLevel          string  `json:"risk_level" db:"risk_level"` // critical, high, medium, low

	// Detailed results (stored as JSON)
	Exposures          []DataExposure     `json:"exposures,omitempty" db:"-"`
	BrokerFindings     []BrokerFinding    `json:"broker_findings,omitempty" db:"-"`
	BreachFindings     []BreachFinding    `json:"breach_findings,omitempty" db:"-"`
	SocialMediaFindings []SocialMediaFinding `json:"social_media_findings,omitempty" db:"-"`

	// Recommendations
	Recommendations    []FootprintRecommendation `json:"recommendations,omitempty" db:"-"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// DataExposure represents a single data exposure finding
type DataExposure struct {
	ID          uuid.UUID        `json:"id"`
	FootprintID uuid.UUID        `json:"footprint_id"`
	Type        ExposureType     `json:"type"`
	Severity    ExposureSeverity `json:"severity"`
	Source      ExposureSource   `json:"source"`
	SourceName  string           `json:"source_name"`  // e.g., "Spokeo", "LinkedIn breach"
	SourceURL   string           `json:"source_url,omitempty"`

	// Exposed data (redacted for display)
	ExposedValue    string `json:"exposed_value"`     // e.g., "j***@email.com"
	ExposedValueFull string `json:"-"`                // Full value (not sent to client)

	// Context
	Context          string    `json:"context,omitempty"`      // Where/how it was found
	AssociatedData   []string  `json:"associated_data,omitempty"` // Other data linked
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`

	// Remediation
	CanAutoRemove    bool      `json:"can_auto_remove"`
	RemovalStatus    string    `json:"removal_status,omitempty"` // pending, requested, completed, failed
	RemovalRequestID *uuid.UUID `json:"removal_request_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// BrokerFinding represents data found on a data broker
type BrokerFinding struct {
	BrokerID      uuid.UUID `json:"broker_id"`
	BrokerName    string    `json:"broker_name"`
	BrokerURL     string    `json:"broker_url"`
	Category      string    `json:"category"`

	// What was found
	Found         bool            `json:"found"`
	ProfileURL    string          `json:"profile_url,omitempty"`
	DataTypes     []ExposureType  `json:"data_types"`
	DataPreview   map[string]string `json:"data_preview"` // Redacted preview

	// Removal info
	OptOutURL     string `json:"opt_out_url,omitempty"`
	OptOutMethod  string `json:"opt_out_method"` // web_form, email, mail, automated
	OptOutDifficulty string `json:"opt_out_difficulty"` // easy, medium, hard
	EstimatedDays int    `json:"estimated_days"` // Days to complete removal

	// Status
	CanAutoRemove bool   `json:"can_auto_remove"`
	RemovalStatus string `json:"removal_status,omitempty"`

	FoundAt time.Time `json:"found_at"`
}

// BreachFinding represents data found in a breach
type BreachFinding struct {
	BreachID      string    `json:"breach_id"`
	BreachName    string    `json:"breach_name"`
	BreachDate    time.Time `json:"breach_date"`
	Domain        string    `json:"domain"`

	// What was exposed
	ExposedDataTypes []ExposureType `json:"exposed_data_types"`
	RecordCount      int64          `json:"record_count,omitempty"`

	// Context
	Description   string `json:"description"`
	IsSensitive   bool   `json:"is_sensitive"`  // Contains sensitive data
	IsVerified    bool   `json:"is_verified"`   // Verified breach
	IsSpamList    bool   `json:"is_spam_list"`  // Spam list vs real breach

	// Source
	Source        string `json:"source"` // HIBP, dark web, etc.

	DiscoveredAt time.Time `json:"discovered_at"`
}

// SocialMediaFinding represents a social media exposure risk
type SocialMediaFinding struct {
	Platform      string   `json:"platform"` // facebook, linkedin, instagram, twitter
	ProfileURL    string   `json:"profile_url,omitempty"`
	Username      string   `json:"username,omitempty"`

	// Privacy issues
	PrivacyIssues []SocialMediaPrivacyIssue `json:"privacy_issues"`

	// Overall risk
	RiskScore     float64 `json:"risk_score"` // 0-100
	RiskLevel     string  `json:"risk_level"` // high, medium, low

	FoundAt time.Time `json:"found_at"`
}

// SocialMediaPrivacyIssue represents a specific privacy issue
type SocialMediaPrivacyIssue struct {
	Type        string `json:"type"`        // public_profile, location_exposed, etc.
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// FootprintRecommendation represents a recommendation to reduce footprint
type FootprintRecommendation struct {
	Priority    int    `json:"priority"` // 1 = highest
	Category    string `json:"category"` // data_broker, breach, social_media, general
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`      // What to do
	ActionURL   string `json:"action_url,omitempty"`
	Impact      string `json:"impact"`      // high, medium, low
	Effort      string `json:"effort"`      // easy, medium, hard
	CanAutomate bool   `json:"can_automate"`
}

// FootprintScanRequest represents a request to scan digital footprint
type FootprintScanRequest struct {
	UserID    uuid.UUID `json:"user_id"`
	ScanType  string    `json:"scan_type"` // full, quick, data_broker_only, breach_only

	// User info to search for
	Email       string   `json:"email"`
	Phone       string   `json:"phone,omitempty"`
	FullName    string   `json:"full_name,omitempty"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	DateOfBirth string   `json:"date_of_birth,omitempty"` // YYYY-MM-DD
	Addresses   []AddressInfo `json:"addresses,omitempty"`

	// Social media accounts to check
	SocialProfiles []SocialProfileInfo `json:"social_profiles,omitempty"`

	// Options
	IncludeDarkWeb     bool `json:"include_dark_web"`
	IncludeDataBrokers bool `json:"include_data_brokers"`
	IncludeSocialMedia bool `json:"include_social_media"`
	IncludeBreaches    bool `json:"include_breaches"`
}

// AddressInfo represents an address to search for
type AddressInfo struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zip_code"`
	Country string `json:"country"`
}

// SocialProfileInfo represents a social media profile
type SocialProfileInfo struct {
	Platform string `json:"platform"`
	Username string `json:"username,omitempty"`
	URL      string `json:"url,omitempty"`
}

// FootprintStats represents overall footprint statistics
type FootprintStats struct {
	TotalScans         int     `json:"total_scans"`
	TotalExposures     int     `json:"total_exposures"`
	RemovalsRequested  int     `json:"removals_requested"`
	RemovalsCompleted  int     `json:"removals_completed"`
	RemovalsPending    int     `json:"removals_pending"`
	AverageRiskScore   float64 `json:"average_risk_score"`
	MostCommonBrokers  []string `json:"most_common_brokers"`
	MostExposedTypes   []ExposureType `json:"most_exposed_types"`
}

// CalculateRiskScore calculates overall risk score based on exposures
func (f *DigitalFootprint) CalculateRiskScore() {
	var score float64

	// Critical exposures (SSN, passwords, financial) - 25 points each
	score += float64(f.CriticalExposures) * 25.0

	// High exposures (addresses, DOB, phone) - 10 points each
	score += float64(f.HighExposures) * 10.0

	// Medium exposures (employment, education) - 5 points each
	score += float64(f.MediumExposures) * 5.0

	// Low exposures (public info) - 2 points each
	score += float64(f.LowExposures) * 2.0

	// Data broker presence - 3 points each
	score += float64(f.DataBrokersFound) * 3.0

	// Dark web exposure multiplier
	if f.DarkWebExposures > 0 {
		score *= 1.5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	f.RiskScore = score

	// Set risk level
	switch {
	case score >= 75:
		f.RiskLevel = "critical"
	case score >= 50:
		f.RiskLevel = "high"
	case score >= 25:
		f.RiskLevel = "medium"
	default:
		f.RiskLevel = "low"
	}
}

// RedactValue returns a redacted version of a sensitive value
func RedactValue(value string, exposureType ExposureType) string {
	if len(value) == 0 {
		return ""
	}

	switch exposureType {
	case ExposureTypeEmail:
		// j***@email.com
		parts := splitEmail(value)
		if len(parts) == 2 {
			if len(parts[0]) <= 1 {
				return value[:1] + "***@" + parts[1]
			}
			return parts[0][:1] + "***@" + parts[1]
		}
		return value[:1] + "***"

	case ExposureTypePhone:
		// ***-***-1234
		if len(value) >= 4 {
			return "***-***-" + value[len(value)-4:]
		}
		return "***"

	case ExposureTypeSSN:
		// ***-**-1234
		if len(value) >= 4 {
			return "***-**-" + value[len(value)-4:]
		}
		return "***"

	case ExposureTypeAddress:
		// *** Main St, City, ST
		return "*** " + value[min(10, len(value)):]

	case ExposureTypeCreditCard:
		// ****-****-****-1234
		if len(value) >= 4 {
			return "****-****-****-" + value[len(value)-4:]
		}
		return "****"

	case ExposureTypePassword:
		return "********"

	default:
		// Generic redaction - show first and last char
		if len(value) <= 2 {
			return "***"
		}
		return value[:1] + "***" + value[len(value)-1:]
	}
}

func splitEmail(email string) []string {
	for i, c := range email {
		if c == '@' {
			return []string{email[:i], email[i+1:]}
		}
	}
	return []string{email}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
