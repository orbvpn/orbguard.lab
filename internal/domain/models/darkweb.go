package models

import (
	"time"

	"github.com/google/uuid"
)

// BreachType represents the type of data breach
type BreachType string

const (
	BreachTypeEmail      BreachType = "email"
	BreachTypePassword   BreachType = "password"
	BreachTypePhone      BreachType = "phone"
	BreachTypeCreditCard BreachType = "credit_card"
	BreachTypeSSN        BreachType = "ssn"
	BreachTypePII        BreachType = "pii"
	BreachTypeUsername   BreachType = "username"
	BreachTypeAddress    BreachType = "address"
	BreachTypePassport   BreachType = "passport"
	BreachTypeDriverLicense BreachType = "driver_license"
)

// BreachSeverity represents the severity of a breach
type BreachSeverity string

const (
	BreachSeverityLow      BreachSeverity = "low"
	BreachSeverityMedium   BreachSeverity = "medium"
	BreachSeverityHigh     BreachSeverity = "high"
	BreachSeverityCritical BreachSeverity = "critical"
)

// Breach represents a data breach from HIBP or other sources
type Breach struct {
	ID           uuid.UUID      `json:"id"`
	Name         string         `json:"name"`
	Title        string         `json:"title"`
	Domain       string         `json:"domain"`
	BreachDate   time.Time      `json:"breach_date"`
	AddedDate    time.Time      `json:"added_date"`
	ModifiedDate time.Time      `json:"modified_date"`
	PwnCount     int64          `json:"pwn_count"`
	Description  string         `json:"description"`
	LogoPath     string         `json:"logo_path,omitempty"`
	DataClasses  []string       `json:"data_classes"` // "Email addresses", "Passwords", etc.
	IsVerified   bool           `json:"is_verified"`
	IsFabricated bool           `json:"is_fabricated"`
	IsSensitive  bool           `json:"is_sensitive"`
	IsRetired    bool           `json:"is_retired"`
	IsSpamList   bool           `json:"is_spam_list"`
	IsMalware    bool           `json:"is_malware"`
	Severity     BreachSeverity `json:"severity"`
}

// BreachCheckRequest represents a request to check for breaches
type BreachCheckRequest struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Username string `json:"username,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}

// BreachCheckResponse represents the response to a breach check
type BreachCheckResponse struct {
	Email            string           `json:"email,omitempty"`
	IsBreached       bool             `json:"is_breached"`
	BreachCount      int              `json:"breach_count"`
	Breaches         []Breach         `json:"breaches,omitempty"`
	ExposedDataTypes []string         `json:"exposed_data_types,omitempty"`
	FirstBreach      *time.Time       `json:"first_breach,omitempty"`
	LatestBreach     *time.Time       `json:"latest_breach,omitempty"`
	RiskLevel        BreachSeverity   `json:"risk_level"`
	Recommendations  []string         `json:"recommendations,omitempty"`
	CheckedAt        time.Time        `json:"checked_at"`
}

// PasswordCheckRequest represents a request to check if a password has been breached
type PasswordCheckRequest struct {
	Password string `json:"password"` // This will be hashed before sending
	DeviceID string `json:"device_id,omitempty"`
}

// PasswordCheckResponse represents the response to a password check
type PasswordCheckResponse struct {
	IsBreached   bool      `json:"is_breached"`
	BreachCount  int       `json:"breach_count"` // How many times this password was seen
	RiskLevel    string    `json:"risk_level"`   // "safe", "weak", "compromised", "critical"
	Message      string    `json:"message"`
	CheckedAt    time.Time `json:"checked_at"`
}

// MonitoredAsset represents an asset being monitored on the dark web
type MonitoredAsset struct {
	ID          uuid.UUID      `json:"id"`
	UserID      string         `json:"user_id"`
	DeviceID    string         `json:"device_id"`
	AssetType   BreachType     `json:"asset_type"`
	AssetValue  string         `json:"asset_value"`       // Encrypted/hashed for sensitive data
	AssetHash   string         `json:"asset_hash"`        // SHA256 for quick lookup
	DisplayName string         `json:"display_name"`      // Masked display (e.g., j***@gmail.com)
	IsActive    bool           `json:"is_active"`
	CreatedAt   time.Time      `json:"created_at"`
	LastChecked *time.Time     `json:"last_checked,omitempty"`
	BreachCount int            `json:"breach_count"`
	Alerts      []BreachAlert  `json:"alerts,omitempty"`
}

// BreachAlert represents an alert for a detected breach
type BreachAlert struct {
	ID          uuid.UUID      `json:"id"`
	AssetID     uuid.UUID      `json:"asset_id"`
	BreachID    uuid.UUID      `json:"breach_id"`
	BreachName  string         `json:"breach_name"`
	Severity    BreachSeverity `json:"severity"`
	DataExposed []string       `json:"data_exposed"`
	DetectedAt  time.Time      `json:"detected_at"`
	AckedAt     *time.Time     `json:"acked_at,omitempty"`
	IsRead      bool           `json:"is_read"`
	Actions     []AlertAction  `json:"actions,omitempty"`
}

// AlertAction represents an action for a breach alert
type AlertAction struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Action      string `json:"action"` // "change_password", "enable_2fa", "view_details", "dismiss"
	URL         string `json:"url,omitempty"`
	IsCompleted bool   `json:"is_completed"`
}

// DarkWebMonitoringStatus represents the overall monitoring status
type DarkWebMonitoringStatus struct {
	IsEnabled       bool             `json:"is_enabled"`
	MonitoredAssets int              `json:"monitored_assets"`
	TotalBreaches   int              `json:"total_breaches"`
	UnreadAlerts    int              `json:"unread_alerts"`
	LastScan        *time.Time       `json:"last_scan,omitempty"`
	NextScan        *time.Time       `json:"next_scan,omitempty"`
	RiskLevel       BreachSeverity   `json:"risk_level"`
	Assets          []MonitoredAsset `json:"assets,omitempty"`
}

// DarkWebStats represents statistics for dark web monitoring
type DarkWebStats struct {
	TotalChecks      int64            `json:"total_checks"`
	BreachesFound    int64            `json:"breaches_found"`
	PasswordsChecked int64            `json:"passwords_checked"`
	CompromisedCount int64            `json:"compromised_count"`
	ByAssetType      map[string]int64 `json:"by_asset_type"`
	BySeverity       map[string]int64 `json:"by_severity"`
	TopBreaches      []Breach         `json:"top_breaches"`
	Last24Hours      struct {
		Checks   int64 `json:"checks"`
		Breaches int64 `json:"breaches"`
	} `json:"last_24_hours"`
}

// PasteEntry represents a paste that contains leaked data
type PasteEntry struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"` // "Pastebin", "Ghostbin", etc.
	Title     string    `json:"title,omitempty"`
	Date      time.Time `json:"date"`
	EmailCount int      `json:"email_count"`
}

// DataClassRisk maps data classes to risk levels
var DataClassRisk = map[string]BreachSeverity{
	"Passwords":                     BreachSeverityCritical,
	"Password hints":                BreachSeverityHigh,
	"Credit cards":                  BreachSeverityCritical,
	"Bank account numbers":          BreachSeverityCritical,
	"Social security numbers":       BreachSeverityCritical,
	"Passport numbers":              BreachSeverityCritical,
	"Driver's licenses":             BreachSeverityCritical,
	"Financial data":                BreachSeverityCritical,
	"Credit card CVVs":              BreachSeverityCritical,
	"PIN codes":                     BreachSeverityCritical,
	"Auth tokens":                   BreachSeverityCritical,
	"Private keys":                  BreachSeverityCritical,
	"Security questions and answers": BreachSeverityHigh,
	"Phone numbers":                 BreachSeverityMedium,
	"Dates of birth":                BreachSeverityMedium,
	"Physical addresses":            BreachSeverityMedium,
	"IP addresses":                  BreachSeverityLow,
	"Email addresses":               BreachSeverityLow,
	"Usernames":                     BreachSeverityLow,
	"Names":                         BreachSeverityLow,
	"Genders":                       BreachSeverityLow,
}

// CalculateBreachSeverity determines the severity based on exposed data classes
func CalculateBreachSeverity(dataClasses []string) BreachSeverity {
	maxSeverity := BreachSeverityLow

	for _, dataClass := range dataClasses {
		if severity, ok := DataClassRisk[dataClass]; ok {
			if CompareSeverity(severity, maxSeverity) > 0 {
				maxSeverity = severity
			}
		}
	}

	return maxSeverity
}

// CompareSeverity compares two severities, returns 1 if a > b, -1 if a < b, 0 if equal
func CompareSeverity(a, b BreachSeverity) int {
	order := map[BreachSeverity]int{
		BreachSeverityLow:      1,
		BreachSeverityMedium:   2,
		BreachSeverityHigh:     3,
		BreachSeverityCritical: 4,
	}

	if order[a] > order[b] {
		return 1
	} else if order[a] < order[b] {
		return -1
	}
	return 0
}
