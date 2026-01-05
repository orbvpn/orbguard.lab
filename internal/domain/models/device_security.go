package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceStatus represents the current status of a device
type DeviceStatus string

const (
	DeviceStatusActive   DeviceStatus = "active"
	DeviceStatusLocked   DeviceStatus = "locked"
	DeviceStatusWiped    DeviceStatus = "wiped"
	DeviceStatusLost     DeviceStatus = "lost"
	DeviceStatusStolen   DeviceStatus = "stolen"
	DeviceStatusInactive DeviceStatus = "inactive"
)

// CommandType represents the type of remote command
type CommandType string

const (
	CommandLocate      CommandType = "locate"
	CommandLock        CommandType = "lock"
	CommandUnlock      CommandType = "unlock"
	CommandWipe        CommandType = "wipe"
	CommandRing        CommandType = "ring"
	CommandTakeSelfie  CommandType = "take_selfie"
	CommandMessage     CommandType = "message"
	CommandBackup      CommandType = "backup"
	CommandGetStatus   CommandType = "get_status"
)

// CommandStatus represents the status of a remote command
type CommandStatus string

const (
	CommandStatusPending   CommandStatus = "pending"
	CommandStatusSent      CommandStatus = "sent"
	CommandStatusDelivered CommandStatus = "delivered"
	CommandStatusExecuted  CommandStatus = "executed"
	CommandStatusFailed    CommandStatus = "failed"
	CommandStatusExpired   CommandStatus = "expired"
)

// SecureDeviceInfo represents device information for security tracking
type SecureDeviceInfo struct {
	ID              uuid.UUID    `json:"id" db:"id"`
	UserID          uuid.UUID    `json:"user_id" db:"user_id"`
	DeviceID        string       `json:"device_id" db:"device_id"`
	Name            string       `json:"name" db:"name"`
	Model           string       `json:"model" db:"model"`
	Manufacturer    string       `json:"manufacturer" db:"manufacturer"`
	Platform        string       `json:"platform" db:"platform"` // android, ios
	OSVersion       string       `json:"os_version" db:"os_version"`
	SecurityPatch   string       `json:"security_patch" db:"security_patch"`
	APILevel        int          `json:"api_level" db:"api_level"`
	Status          DeviceStatus `json:"status" db:"status"`
	IsRooted        bool         `json:"is_rooted" db:"is_rooted"`
	IsEncrypted     bool         `json:"is_encrypted" db:"is_encrypted"`
	HasScreenLock   bool         `json:"has_screen_lock" db:"has_screen_lock"`
	BiometricType   string       `json:"biometric_type" db:"biometric_type"` // fingerprint, face, iris, none
	LastSeen        time.Time    `json:"last_seen" db:"last_seen"`
	LastLocation    *Location    `json:"last_location,omitempty" db:"-"`
	PushToken       string       `json:"-" db:"push_token"`
	RegisteredAt    time.Time    `json:"registered_at" db:"registered_at"`
	UpdatedAt       time.Time    `json:"updated_at" db:"updated_at"`
}

// Location represents a geographic location
type Location struct {
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	Accuracy  float64   `json:"accuracy_meters"`
	Altitude  float64   `json:"altitude,omitempty"`
	Speed     float64   `json:"speed,omitempty"`
	Bearing   float64   `json:"bearing,omitempty"`
	Provider  string    `json:"provider"` // gps, network, fused
	Timestamp time.Time `json:"timestamp"`
	Address   string    `json:"address,omitempty"`
	Battery   int       `json:"battery_percent,omitempty"`
}

// RemoteCommand represents a command to be executed on a device
type RemoteCommand struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	UserID      uuid.UUID     `json:"user_id" db:"user_id"`
	DeviceID    string        `json:"device_id" db:"device_id"`
	Type        CommandType   `json:"type" db:"type"`
	Status      CommandStatus `json:"status" db:"status"`
	Payload     string        `json:"payload,omitempty" db:"payload"` // JSON payload for command params
	Result      string        `json:"result,omitempty" db:"result"`   // JSON result
	Error       string        `json:"error,omitempty" db:"error"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	SentAt      *time.Time    `json:"sent_at,omitempty" db:"sent_at"`
	ExecutedAt  *time.Time    `json:"executed_at,omitempty" db:"executed_at"`
	ExpiresAt   time.Time     `json:"expires_at" db:"expires_at"`
}

// LockCommandPayload represents the payload for a lock command
type LockCommandPayload struct {
	PIN     string `json:"pin,omitempty"`      // Optional PIN to set
	Message string `json:"message,omitempty"`  // Message to display on lock screen
	Phone   string `json:"phone,omitempty"`    // Contact phone to display
}

// WipeCommandPayload represents the payload for a wipe command
type WipeCommandPayload struct {
	WipeSDCard     bool `json:"wipe_sd_card"`
	WipeESIM       bool `json:"wipe_esim"`
	FactoryReset   bool `json:"factory_reset"`
	ConfirmationID string `json:"confirmation_id"` // Required for safety
}

// MessageCommandPayload represents the payload for a message command
type MessageCommandPayload struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Duration int    `json:"duration_seconds"` // How long to display
}

// SIMInfo represents SIM card information
type SIMInfo struct {
	ID             uuid.UUID `json:"id" db:"id"`
	DeviceID       string    `json:"device_id" db:"device_id"`
	SlotIndex      int       `json:"slot_index" db:"slot_index"`
	ICCID          string    `json:"iccid" db:"iccid"`         // Integrated Circuit Card ID
	IMSI           string    `json:"imsi,omitempty" db:"imsi"` // International Mobile Subscriber Identity
	Carrier        string    `json:"carrier" db:"carrier"`
	CountryCode    string    `json:"country_code" db:"country_code"`
	PhoneNumber    string    `json:"phone_number,omitempty" db:"phone_number"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	IsESIM         bool      `json:"is_esim" db:"is_esim"`
	FirstSeen      time.Time `json:"first_seen" db:"first_seen"`
	LastSeen       time.Time `json:"last_seen" db:"last_seen"`
}

// SIMChangeEvent represents a SIM change or swap event
type SIMChangeEvent struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	DeviceID     string          `json:"device_id" db:"device_id"`
	EventType    SIMEventType    `json:"event_type" db:"event_type"`
	OldSIM       *SIMInfo        `json:"old_sim,omitempty" db:"-"`
	NewSIM       *SIMInfo        `json:"new_sim,omitempty" db:"-"`
	RiskLevel    SIMRiskLevel    `json:"risk_level" db:"risk_level"`
	IsAlerted    bool            `json:"is_alerted" db:"is_alerted"`
	AlertedAt    *time.Time      `json:"alerted_at,omitempty" db:"alerted_at"`
	Location     *Location       `json:"location,omitempty" db:"-"`
	DetectedAt   time.Time       `json:"detected_at" db:"detected_at"`
}

// SIMEventType represents the type of SIM event
type SIMEventType string

const (
	SIMEventInserted SIMEventType = "inserted"
	SIMEventRemoved  SIMEventType = "removed"
	SIMEventSwapped  SIMEventType = "swapped"
	SIMEventChanged  SIMEventType = "changed" // Same slot, different SIM
)

// SIMRiskLevel represents the risk level of a SIM change
type SIMRiskLevel string

const (
	SIMRiskCritical SIMRiskLevel = "critical" // SIM swap attack suspected
	SIMRiskHigh     SIMRiskLevel = "high"     // Unexpected change
	SIMRiskMedium   SIMRiskLevel = "medium"   // Possible user action
	SIMRiskLow      SIMRiskLevel = "low"      // Normal behavior
)

// ThiefSelfie represents a photo taken when unauthorized access is detected
type ThiefSelfie struct {
	ID         uuid.UUID `json:"id" db:"id"`
	DeviceID   string    `json:"device_id" db:"device_id"`
	ImageURL   string    `json:"image_url" db:"image_url"`
	ImageHash  string    `json:"image_hash" db:"image_hash"`
	TriggerType string   `json:"trigger_type" db:"trigger_type"` // wrong_pin, wrong_pattern, wrong_face
	AttemptCount int     `json:"attempt_count" db:"attempt_count"`
	Location   *Location `json:"location,omitempty" db:"-"`
	CapturedAt time.Time `json:"captured_at" db:"captured_at"`
}

// AntiTheftSettings represents user settings for anti-theft features
type AntiTheftSettings struct {
	DeviceID              string    `json:"device_id" db:"device_id"`

	// Feature toggles
	EnableRemoteLocate    bool      `json:"enable_remote_locate" db:"enable_remote_locate"`
	EnableRemoteLock      bool      `json:"enable_remote_lock" db:"enable_remote_lock"`
	EnableRemoteWipe      bool      `json:"enable_remote_wipe" db:"enable_remote_wipe"`
	EnableThiefSelfie     bool      `json:"enable_thief_selfie" db:"enable_thief_selfie"`
	EnableSIMAlert        bool      `json:"enable_sim_alert" db:"enable_sim_alert"`

	// Thief selfie settings
	SelfieOnWrongPIN      bool      `json:"selfie_on_wrong_pin" db:"selfie_on_wrong_pin"`
	SelfieOnWrongPattern  bool      `json:"selfie_on_wrong_pattern" db:"selfie_on_wrong_pattern"`
	SelfieAfterAttempts   int       `json:"selfie_after_attempts" db:"selfie_after_attempts"` // Take selfie after N failed attempts

	// Alert settings
	AlertEmail            string    `json:"alert_email" db:"alert_email"`
	AlertPhone            string    `json:"alert_phone" db:"alert_phone"`
	AlertPushEnabled      bool      `json:"alert_push_enabled" db:"alert_push_enabled"`

	// Trusted SIMs (whitelist)
	TrustedSIMICCIDs      []string  `json:"trusted_sim_iccids" db:"-"`

	UpdatedAt             time.Time `json:"updated_at" db:"updated_at"`
}

// OSVulnerability represents a known vulnerability in an OS version
type OSVulnerability struct {
	ID              string          `json:"id"`              // CVE ID
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Severity        VulnSeverity    `json:"severity"`
	CVSSScore       float64         `json:"cvss_score"`
	AffectedOS      []string        `json:"affected_os"`      // android, ios
	AffectedVersions []VersionRange `json:"affected_versions"`
	PatchedIn       string          `json:"patched_in,omitempty"` // Version where fixed
	SecurityPatch   string          `json:"security_patch,omitempty"` // Android security patch level
	IsExploited     bool            `json:"is_exploited"`     // Known to be exploited in the wild
	ExploitType     string          `json:"exploit_type,omitempty"` // remote, local, physical
	References      []string        `json:"references"`
	MITREAttackIDs  []string        `json:"mitre_attack_ids,omitempty"`
	PublishedAt     time.Time       `json:"published_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// VersionRange represents a range of affected versions
type VersionRange struct {
	MinVersion string `json:"min_version,omitempty"`
	MaxVersion string `json:"max_version,omitempty"`
	APILevel   int    `json:"api_level,omitempty"` // For Android
}

// VulnSeverity represents vulnerability severity
type VulnSeverity string

const (
	VulnSeverityCritical VulnSeverity = "critical" // CVSS 9.0-10.0
	VulnSeverityHigh     VulnSeverity = "high"     // CVSS 7.0-8.9
	VulnSeverityMedium   VulnSeverity = "medium"   // CVSS 4.0-6.9
	VulnSeverityLow      VulnSeverity = "low"      // CVSS 0.1-3.9
)

// OSSecurityAuditResult represents the result of an OS security audit
type OSSecurityAuditResult struct {
	DeviceID           string             `json:"device_id"`
	Platform           string             `json:"platform"`
	OSVersion          string             `json:"os_version"`
	SecurityPatch      string             `json:"security_patch,omitempty"`
	APILevel           int                `json:"api_level,omitempty"`
	AuditedAt          time.Time          `json:"audited_at"`

	// Overall assessment
	RiskScore          float64            `json:"risk_score"` // 0-100
	RiskLevel          VulnSeverity       `json:"risk_level"`
	IsUpToDate         bool               `json:"is_up_to_date"`
	DaysBehind         int                `json:"days_behind"` // Days behind latest patch

	// Vulnerability summary
	TotalVulns         int                `json:"total_vulnerabilities"`
	CriticalVulns      int                `json:"critical_vulnerabilities"`
	HighVulns          int                `json:"high_vulnerabilities"`
	MediumVulns        int                `json:"medium_vulnerabilities"`
	LowVulns           int                `json:"low_vulnerabilities"`
	ExploitedVulns     int                `json:"exploited_vulnerabilities"`

	// Detailed vulnerabilities
	Vulnerabilities    []OSVulnerability  `json:"vulnerabilities,omitempty"`

	// Recommendations
	Recommendations    []SecurityRecommendation `json:"recommendations"`

	// Latest available
	LatestOSVersion    string             `json:"latest_os_version,omitempty"`
	LatestPatchDate    string             `json:"latest_patch_date,omitempty"`
}

// SecurityRecommendation represents a security recommendation
type SecurityRecommendation struct {
	ID          string       `json:"id"`
	Priority    int          `json:"priority"` // 1 = highest
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Action      string       `json:"action"`
	AutoFixable bool         `json:"auto_fixable"`
	RelatedCVEs []string     `json:"related_cves,omitempty"`
}

// DeviceSecurityStatus represents the overall security status of a device
type DeviceSecurityStatus struct {
	DeviceID         string            `json:"device_id"`
	DeviceInfo       *SecureDeviceInfo `json:"device_info"`
	LastCheck        time.Time         `json:"last_check"`

	// Security scores (0-100)
	OverallScore     float64           `json:"overall_score"`
	OSSecurityScore  float64           `json:"os_security_score"`
	AppSecurityScore float64           `json:"app_security_score"`
	NetworkScore     float64           `json:"network_score"`
	PrivacyScore     float64           `json:"privacy_score"`

	// Flags
	IsCompromised    bool              `json:"is_compromised"`
	HasMalware       bool              `json:"has_malware"`
	IsRooted         bool              `json:"is_rooted"`
	HasOSVulns       bool              `json:"has_os_vulnerabilities"`

	// Anti-theft status
	AntiTheftEnabled bool              `json:"anti_theft_enabled"`
	LastLocation     *Location         `json:"last_location,omitempty"`
	PendingCommands  int               `json:"pending_commands"`

	// SIM status
	CurrentSIM       *SIMInfo          `json:"current_sim,omitempty"`
	SIMChangeAlerts  int               `json:"sim_change_alerts"`

	// Issues and recommendations
	Issues           []SecurityIssue   `json:"issues"`
	TopRecommendations []SecurityRecommendation `json:"top_recommendations"`
}

// SecurityIssue represents a security issue found on the device
type SecurityIssue struct {
	ID          string       `json:"id"`
	Type        string       `json:"type"` // os_vuln, malware, root, network, privacy
	Severity    VulnSeverity `json:"severity"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	DetectedAt  time.Time    `json:"detected_at"`
	IsResolved  bool         `json:"is_resolved"`
	ResolvedAt  *time.Time   `json:"resolved_at,omitempty"`
}

// KnownAndroidVulnerabilities contains known Android vulnerabilities for offline checking
var KnownAndroidVulnerabilities = []OSVulnerability{
	{
		ID:          "CVE-2024-32896",
		Title:       "Android Kernel Privilege Escalation",
		Description: "A privilege escalation vulnerability in the Android kernel allowing local attackers to gain root access.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"android"},
		AffectedVersions: []VersionRange{
			{MinVersion: "11", MaxVersion: "14", APILevel: 34},
		},
		PatchedIn:     "2024-06-05",
		SecurityPatch: "2024-06-05",
		IsExploited:   true,
		ExploitType:   "local",
		MITREAttackIDs: []string{"T1068"},
		PublishedAt:   time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2024-29748",
		Title:       "Pixel Firmware Information Disclosure",
		Description: "Information disclosure vulnerability in Pixel firmware bootloader.",
		Severity:    VulnSeverityHigh,
		CVSSScore:   7.5,
		AffectedOS:  []string{"android"},
		AffectedVersions: []VersionRange{
			{MinVersion: "12", MaxVersion: "14"},
		},
		PatchedIn:     "2024-04-01",
		SecurityPatch: "2024-04-01",
		IsExploited:   true,
		ExploitType:   "local",
		PublishedAt:   time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2024-0031",
		Title:       "Android System Remote Code Execution",
		Description: "Remote code execution vulnerability in Android System component via Bluetooth.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"android"},
		AffectedVersions: []VersionRange{
			{MinVersion: "11", MaxVersion: "14"},
		},
		PatchedIn:     "2024-01-05",
		SecurityPatch: "2024-01-05",
		IsExploited:   false,
		ExploitType:   "remote",
		MITREAttackIDs: []string{"T1190", "T1203"},
		PublishedAt:   time.Date(2024, 1, 5, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2023-45779",
		Title:       "Android APEX Installation Bypass",
		Description: "Vulnerability allowing unsigned APEX modules to be installed on rooted devices.",
		Severity:    VulnSeverityHigh,
		CVSSScore:   8.1,
		AffectedOS:  []string{"android"},
		AffectedVersions: []VersionRange{
			{MinVersion: "12", MaxVersion: "14"},
		},
		PatchedIn:     "2023-12-01",
		SecurityPatch: "2023-12-01",
		IsExploited:   true,
		ExploitType:   "local",
		PublishedAt:   time.Date(2023, 12, 1, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2023-4863",
		Title:       "libwebp Heap Buffer Overflow",
		Description: "Heap buffer overflow in libwebp allowing remote code execution via malicious WebP images.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"android", "ios"},
		AffectedVersions: []VersionRange{
			{MinVersion: "0", MaxVersion: "14"},
		},
		PatchedIn:     "2023-09-11",
		SecurityPatch: "2023-09-05",
		IsExploited:   true,
		ExploitType:   "remote",
		MITREAttackIDs: []string{"T1203"},
		PublishedAt:   time.Date(2023, 9, 11, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2023-35674",
		Title:       "Android Framework Privilege Escalation",
		Description: "Privilege escalation in Android Framework allowing app to gain system privileges.",
		Severity:    VulnSeverityHigh,
		CVSSScore:   7.8,
		AffectedOS:  []string{"android"},
		AffectedVersions: []VersionRange{
			{MinVersion: "11", MaxVersion: "13"},
		},
		PatchedIn:     "2023-09-01",
		SecurityPatch: "2023-09-01",
		IsExploited:   true,
		ExploitType:   "local",
		PublishedAt:   time.Date(2023, 9, 1, 0, 0, 0, 0, time.UTC),
	},
}

// KnowniOSVulnerabilities contains known iOS vulnerabilities for offline checking
var KnowniOSVulnerabilities = []OSVulnerability{
	{
		ID:          "CVE-2024-23296",
		Title:       "iOS Kernel Memory Corruption",
		Description: "Memory corruption vulnerability in iOS kernel allowing arbitrary code execution.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"ios"},
		AffectedVersions: []VersionRange{
			{MinVersion: "16.0", MaxVersion: "17.3"},
		},
		PatchedIn:   "17.4",
		IsExploited: true,
		ExploitType: "remote",
		MITREAttackIDs: []string{"T1203"},
		PublishedAt: time.Date(2024, 3, 5, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2024-23225",
		Title:       "iOS RTKit Arbitrary Code Execution",
		Description: "RTKit vulnerability allowing attackers to execute arbitrary code with kernel privileges.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"ios"},
		AffectedVersions: []VersionRange{
			{MinVersion: "16.0", MaxVersion: "17.3"},
		},
		PatchedIn:   "17.4",
		IsExploited: true,
		ExploitType: "local",
		PublishedAt: time.Date(2024, 3, 5, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2023-42917",
		Title:       "WebKit Arbitrary Code Execution",
		Description: "Memory corruption issue in WebKit allowing arbitrary code execution when processing web content.",
		Severity:    VulnSeverityHigh,
		CVSSScore:   8.8,
		AffectedOS:  []string{"ios"},
		AffectedVersions: []VersionRange{
			{MinVersion: "16.0", MaxVersion: "17.1"},
		},
		PatchedIn:   "17.1.2",
		IsExploited: true,
		ExploitType: "remote",
		MITREAttackIDs: []string{"T1189"},
		PublishedAt: time.Date(2023, 11, 30, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2023-41993",
		Title:       "WebKit Zero-Day (Pegasus)",
		Description: "Zero-click WebKit vulnerability exploited by Pegasus spyware for remote code execution.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"ios"},
		AffectedVersions: []VersionRange{
			{MinVersion: "15.0", MaxVersion: "16.6"},
		},
		PatchedIn:   "16.7",
		IsExploited: true,
		ExploitType: "remote",
		MITREAttackIDs: []string{"T1189", "T1203"},
		References:  []string{"https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/"},
		PublishedAt: time.Date(2023, 9, 7, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "CVE-2023-32434",
		Title:       "iOS Kernel Integer Overflow (Triangulation)",
		Description: "Integer overflow in iOS kernel exploited in Operation Triangulation spyware campaign.",
		Severity:    VulnSeverityCritical,
		CVSSScore:   9.8,
		AffectedOS:  []string{"ios"},
		AffectedVersions: []VersionRange{
			{MinVersion: "15.0", MaxVersion: "15.7"},
		},
		PatchedIn:   "15.7.7",
		IsExploited: true,
		ExploitType: "remote",
		MITREAttackIDs: []string{"T1203"},
		References:  []string{"https://securelist.com/operation-triangulation/109842/"},
		PublishedAt: time.Date(2023, 6, 21, 0, 0, 0, 0, time.UTC),
	},
}

// LatestSecurityInfo contains information about latest security updates
type LatestSecurityInfo struct {
	Platform          string    `json:"platform"`
	LatestVersion     string    `json:"latest_version"`
	LatestPatchDate   string    `json:"latest_patch_date"`
	ReleaseDate       time.Time `json:"release_date"`
	SecurityBulletin  string    `json:"security_bulletin_url"`
}

// LatestAndroidSecurity holds the latest Android security information
var LatestAndroidSecurity = LatestSecurityInfo{
	Platform:         "android",
	LatestVersion:    "14",
	LatestPatchDate:  "2024-12-05",
	ReleaseDate:      time.Date(2024, 12, 5, 0, 0, 0, 0, time.UTC),
	SecurityBulletin: "https://source.android.com/docs/security/bulletin",
}

// LatestiOSSecurity holds the latest iOS security information
var LatestiOSSecurity = LatestSecurityInfo{
	Platform:         "ios",
	LatestVersion:    "18.2",
	LatestPatchDate:  "2024-12-11",
	ReleaseDate:      time.Date(2024, 12, 11, 0, 0, 0, 0, time.UTC),
	SecurityBulletin: "https://support.apple.com/en-us/HT201222",
}
