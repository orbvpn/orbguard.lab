package models

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// MDM/UEM Integration
// ============================================================================

// MDMProvider represents supported MDM/UEM providers
type MDMProvider string

const (
	MDMProviderIntune       MDMProvider = "intune"
	MDMProviderWorkspaceONE MDMProvider = "workspace_one"
	MDMProviderJamf         MDMProvider = "jamf"
	MDMProviderMobileIron   MDMProvider = "mobileiron"
	MDMProviderMaaS360      MDMProvider = "maas360"
	MDMProviderCustom       MDMProvider = "custom"
)

// MDMIntegrationConfig represents MDM integration configuration
type MDMIntegrationConfig struct {
	ID          uuid.UUID   `json:"id"`
	Provider    MDMProvider `json:"provider"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`

	// Connection settings
	TenantID     string `json:"tenant_id,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"-"` // Never expose
	BaseURL      string `json:"base_url,omitempty"`
	APIVersion   string `json:"api_version,omitempty"`

	// Sync settings
	SyncInterval    time.Duration `json:"sync_interval"`
	LastSyncAt      *time.Time    `json:"last_sync_at,omitempty"`
	LastSyncStatus  string        `json:"last_sync_status,omitempty"`
	LastSyncError   string        `json:"last_sync_error,omitempty"`
	DevicesSynced   int           `json:"devices_synced"`
	PoliciesSynced  int           `json:"policies_synced"`

	// Feature toggles
	SyncDevices          bool `json:"sync_devices"`
	SyncCompliance       bool `json:"sync_compliance"`
	PushThreatAlerts     bool `json:"push_threat_alerts"`
	EnforceCompliance    bool `json:"enforce_compliance"`
	AutoRemediate        bool `json:"auto_remediate"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MDMDevice represents a device managed by MDM
type MDMDevice struct {
	ID               uuid.UUID   `json:"id"`
	MDMConfigID      uuid.UUID   `json:"mdm_config_id"`
	ExternalID       string      `json:"external_id"` // ID in MDM system
	DeviceID         uuid.UUID   `json:"device_id,omitempty"` // OrbGuard device ID

	// Device info from MDM
	DeviceName       string      `json:"device_name"`
	Model            string      `json:"model"`
	Manufacturer     string      `json:"manufacturer"`
	OSVersion        string      `json:"os_version"`
	SerialNumber     string      `json:"serial_number,omitempty"`
	IMEI             string      `json:"imei,omitempty"`

	// MDM status
	EnrollmentStatus string      `json:"enrollment_status"` // enrolled, pending, unenrolled
	ComplianceStatus string      `json:"compliance_status"` // compliant, non_compliant, unknown
	ManagementStatus string      `json:"management_status"` // managed, unmanaged, partial

	// Ownership
	Ownership        string      `json:"ownership"` // corporate, byod, unknown
	UserID           string      `json:"user_id,omitempty"`
	UserEmail        string      `json:"user_email,omitempty"`
	UserName         string      `json:"user_name,omitempty"`

	// Timestamps
	EnrolledAt       *time.Time  `json:"enrolled_at,omitempty"`
	LastCheckIn      *time.Time  `json:"last_check_in,omitempty"`
	LastSyncAt       *time.Time  `json:"last_sync_at,omitempty"`

	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
}

// MDMCompliancePolicy represents a compliance policy from MDM
type MDMCompliancePolicy struct {
	ID              uuid.UUID   `json:"id"`
	MDMConfigID     uuid.UUID   `json:"mdm_config_id"`
	ExternalID      string      `json:"external_id"`
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`

	// Policy details
	Platform        Platform    `json:"platform"`
	Rules           []MDMComplianceRule `json:"rules"`
	Actions         []MDMComplianceAction `json:"actions"`

	// Assignment
	AssignedGroups  []string    `json:"assigned_groups,omitempty"`
	AssignedUsers   []string    `json:"assigned_users,omitempty"`

	Enabled         bool        `json:"enabled"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// MDMComplianceRule represents a single compliance rule
type MDMComplianceRule struct {
	Type        string      `json:"type"` // os_version, encryption, passcode, jailbreak, app_installed, etc.
	Operator    string      `json:"operator"` // equals, not_equals, greater_than, less_than, contains
	Value       string      `json:"value"`
	Severity    Severity    `json:"severity"`
}

// MDMComplianceAction represents action taken for non-compliance
type MDMComplianceAction struct {
	Type        string        `json:"type"` // notify, restrict, wipe, block_access
	Delay       time.Duration `json:"delay,omitempty"`
	Message     string        `json:"message,omitempty"`
}

// MDMThreatAlert represents a threat alert sent to MDM
type MDMThreatAlert struct {
	ID              uuid.UUID   `json:"id"`
	MDMConfigID     uuid.UUID   `json:"mdm_config_id"`
	DeviceID        uuid.UUID   `json:"device_id"`
	ExternalDeviceID string     `json:"external_device_id"`

	// Threat details
	ThreatType      string      `json:"threat_type"`
	ThreatName      string      `json:"threat_name"`
	Severity        Severity    `json:"severity"`
	Description     string      `json:"description"`
	Indicators      []string    `json:"indicators,omitempty"`

	// Status
	Status          string      `json:"status"` // pending, sent, delivered, failed
	SentAt          *time.Time  `json:"sent_at,omitempty"`
	DeliveredAt     *time.Time  `json:"delivered_at,omitempty"`
	Error           string      `json:"error,omitempty"`

	// Remediation
	RemediationTaken    bool    `json:"remediation_taken"`
	RemediationAction   string  `json:"remediation_action,omitempty"`
	RemediationAt       *time.Time `json:"remediation_at,omitempty"`

	CreatedAt       time.Time   `json:"created_at"`
}

// ============================================================================
// Zero Trust / Conditional Access
// ============================================================================

// DevicePosture represents the security posture of a device
type DevicePosture struct {
	DeviceID        uuid.UUID   `json:"device_id"`

	// Overall scores (0-100)
	OverallScore    int         `json:"overall_score"`
	TrustLevel      TrustLevel  `json:"trust_level"`

	// Component scores
	OSSecurityScore     int     `json:"os_security_score"`
	AppSecurityScore    int     `json:"app_security_score"`
	NetworkSecurityScore int    `json:"network_security_score"`
	BehaviorScore       int     `json:"behavior_score"`
	ComplianceScore     int     `json:"compliance_score"`

	// Risk factors (negative)
	RiskFactors     []RiskFactor `json:"risk_factors"`

	// Trust signals (positive)
	TrustSignals    []TrustSignal `json:"trust_signals"`

	// Recommendations
	Recommendations []string    `json:"recommendations"`

	// Metadata
	LastAssessedAt  time.Time   `json:"last_assessed_at"`
	NextAssessmentAt time.Time  `json:"next_assessment_at"`
	AssessmentVersion string    `json:"assessment_version"`
}

// TrustLevel represents device trust level
type TrustLevel string

const (
	TrustLevelHigh     TrustLevel = "high"
	TrustLevelMedium   TrustLevel = "medium"
	TrustLevelLow      TrustLevel = "low"
	TrustLevelUntrusted TrustLevel = "untrusted"
	TrustLevelBlocked  TrustLevel = "blocked"
)

// RiskFactor represents a risk factor affecting trust
type RiskFactor struct {
	Type        string      `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	Impact      int         `json:"impact"` // Score reduction
	DetectedAt  time.Time   `json:"detected_at"`
	Remediation string      `json:"remediation,omitempty"`
}

// TrustSignal represents a positive trust indicator
type TrustSignal struct {
	Type        string      `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Value       int         `json:"value"` // Score boost
	ValidUntil  *time.Time  `json:"valid_until,omitempty"`
}

// ConditionalAccessPolicy represents an access policy
type ConditionalAccessPolicy struct {
	ID              uuid.UUID   `json:"id"`
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`
	Enabled         bool        `json:"enabled"`
	Priority        int         `json:"priority"` // Lower = higher priority

	// Conditions
	Conditions      AccessConditions `json:"conditions"`

	// Grant/Block
	GrantControls   GrantControls   `json:"grant_controls"`
	SessionControls SessionControls `json:"session_controls,omitempty"`

	// Assignment
	IncludeUsers    []string    `json:"include_users,omitempty"`
	ExcludeUsers    []string    `json:"exclude_users,omitempty"`
	IncludeGroups   []string    `json:"include_groups,omitempty"`
	ExcludeGroups   []string    `json:"exclude_groups,omitempty"`
	IncludeApps     []string    `json:"include_apps,omitempty"`
	ExcludeApps     []string    `json:"exclude_apps,omitempty"`

	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// AccessConditions defines when policy applies
type AccessConditions struct {
	// Device conditions
	MinTrustLevel       *TrustLevel `json:"min_trust_level,omitempty"`
	MinPostureScore     *int        `json:"min_posture_score,omitempty"`
	RequireCompliance   bool        `json:"require_compliance"`
	RequireManaged      bool        `json:"require_managed"`
	AllowedPlatforms    []Platform  `json:"allowed_platforms,omitempty"`
	BlockedPlatforms    []Platform  `json:"blocked_platforms,omitempty"`

	// Location conditions
	AllowedLocations    []string    `json:"allowed_locations,omitempty"`
	BlockedLocations    []string    `json:"blocked_locations,omitempty"`
	AllowedCountries    []string    `json:"allowed_countries,omitempty"`
	BlockedCountries    []string    `json:"blocked_countries,omitempty"`

	// Network conditions
	AllowedNetworks     []string    `json:"allowed_networks,omitempty"` // CIDR ranges
	BlockedNetworks     []string    `json:"blocked_networks,omitempty"`
	RequireVPN          bool        `json:"require_vpn"`
	RequireSecureNetwork bool       `json:"require_secure_network"`

	// Risk conditions
	MaxRiskLevel        *Severity   `json:"max_risk_level,omitempty"`
	BlockOnActiveThreats bool       `json:"block_on_active_threats"`

	// Time conditions
	AllowedTimeRanges   []AccessTimeRange `json:"allowed_time_ranges,omitempty"`
}

// AccessTimeRange represents a time window for access policies
type AccessTimeRange struct {
	StartTime   string   `json:"start_time"` // HH:MM format
	EndTime     string   `json:"end_time"`
	Days        []string `json:"days"` // monday, tuesday, etc.
	Timezone    string   `json:"timezone"`
}

// GrantControls defines access grant behavior
type GrantControls struct {
	Operator        string   `json:"operator"` // AND, OR
	RequireMFA      bool     `json:"require_mfa"`
	RequireApprovedApp bool  `json:"require_approved_app"`
	RequirePasswordChange bool `json:"require_password_change"`
	TermsOfUse      string   `json:"terms_of_use,omitempty"`
	CustomControls  []string `json:"custom_controls,omitempty"`
}

// SessionControls defines session behavior
type SessionControls struct {
	SignInFrequency     *time.Duration `json:"sign_in_frequency,omitempty"`
	PersistentBrowser   *bool          `json:"persistent_browser,omitempty"`
	CloudAppSecurity    string         `json:"cloud_app_security,omitempty"`
	DisableResilience   bool           `json:"disable_resilience"`
}

// AccessDecision represents an access decision
type AccessDecision struct {
	ID              uuid.UUID   `json:"id"`
	DeviceID        uuid.UUID   `json:"device_id"`
	UserID          string      `json:"user_id"`
	ResourceID      string      `json:"resource_id"`
	PolicyID        *uuid.UUID  `json:"policy_id,omitempty"`

	// Decision
	Decision        string      `json:"decision"` // allow, deny, challenge
	Reason          string      `json:"reason"`

	// Context
	DevicePosture   *DevicePosture `json:"device_posture,omitempty"`
	Location        string      `json:"location,omitempty"`
	IPAddress       string      `json:"ip_address,omitempty"`
	UserAgent       string      `json:"user_agent,omitempty"`

	// Challenge
	ChallengeType   string      `json:"challenge_type,omitempty"` // mfa, reauthenticate, accept_terms
	ChallengeStatus string      `json:"challenge_status,omitempty"`

	CreatedAt       time.Time   `json:"created_at"`
}

// ============================================================================
// SIEM Integration
// ============================================================================

// SIEMProvider represents supported SIEM providers
type SIEMProvider string

const (
	SIEMProviderSplunk    SIEMProvider = "splunk"
	SIEMProviderElastic   SIEMProvider = "elastic"
	SIEMProviderSentinel  SIEMProvider = "sentinel"
	SIEMProviderQRadar    SIEMProvider = "qradar"
	SIEMProviderChronicle SIEMProvider = "chronicle"
	SIEMProviderWebhook   SIEMProvider = "webhook"
)

// SIEMIntegrationConfig represents SIEM integration configuration
type SIEMIntegrationConfig struct {
	ID          uuid.UUID    `json:"id"`
	Provider    SIEMProvider `json:"provider"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Enabled     bool         `json:"enabled"`

	// Connection
	Endpoint    string       `json:"endpoint"`
	Token       string       `json:"-"` // Never expose
	Username    string       `json:"username,omitempty"`
	Password    string       `json:"-"`
	Index       string       `json:"index,omitempty"` // For Splunk/Elastic

	// TLS
	TLSEnabled      bool     `json:"tls_enabled"`
	TLSSkipVerify   bool     `json:"tls_skip_verify"`
	TLSCertPath     string   `json:"tls_cert_path,omitempty"`

	// Event settings
	EventTypes      []string `json:"event_types"` // threat, compliance, access, audit
	MinSeverity     Severity `json:"min_severity"`
	BatchSize       int      `json:"batch_size"`
	FlushInterval   time.Duration `json:"flush_interval"`

	// Status
	LastEventAt     *time.Time `json:"last_event_at,omitempty"`
	EventsSent      int64    `json:"events_sent"`
	LastError       string   `json:"last_error,omitempty"`
	LastErrorAt     *time.Time `json:"last_error_at,omitempty"`

	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SIEMEvent represents an event to send to SIEM
type SIEMEvent struct {
	ID              string      `json:"id"`
	Timestamp       time.Time   `json:"timestamp"`
	EventType       string      `json:"event_type"`
	Severity        Severity    `json:"severity"`

	// Source
	Source          string      `json:"source"`
	SourceIP        string      `json:"source_ip,omitempty"`
	SourceHost      string      `json:"source_host,omitempty"`

	// Target
	DestIP          string      `json:"dest_ip,omitempty"`
	DestHost        string      `json:"dest_host,omitempty"`
	DestPort        int         `json:"dest_port,omitempty"`

	// User/Device
	UserID          string      `json:"user_id,omitempty"`
	UserName        string      `json:"user_name,omitempty"`
	DeviceID        string      `json:"device_id,omitempty"`
	DeviceName      string      `json:"device_name,omitempty"`

	// Event details
	Category        string      `json:"category"`
	Action          string      `json:"action"`
	Outcome         string      `json:"outcome"` // success, failure, unknown
	Message         string      `json:"message"`

	// Threat-specific
	ThreatName      string      `json:"threat_name,omitempty"`
	ThreatType      string      `json:"threat_type,omitempty"`
	Indicators      []string    `json:"indicators,omitempty"`
	MITRETechniques []string    `json:"mitre_techniques,omitempty"`

	// Additional data
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
	Tags            []string    `json:"tags,omitempty"`
}

// SIEMEventBatch represents a batch of events
type SIEMEventBatch struct {
	ConfigID    uuid.UUID   `json:"config_id"`
	Events      []SIEMEvent `json:"events"`
	CreatedAt   time.Time   `json:"created_at"`
}

// ============================================================================
// Compliance Reporting
// ============================================================================

// ComplianceFramework represents a compliance framework
type ComplianceFramework string

const (
	ComplianceGDPR      ComplianceFramework = "gdpr"
	ComplianceSOC2      ComplianceFramework = "soc2"
	ComplianceHIPAA     ComplianceFramework = "hipaa"
	CompliancePCIDSS    ComplianceFramework = "pci_dss"
	ComplianceISO27001  ComplianceFramework = "iso27001"
	ComplianceNIST      ComplianceFramework = "nist"
	ComplianceCIS       ComplianceFramework = "cis"
)

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID              uuid.UUID           `json:"id"`
	Framework       ComplianceFramework `json:"framework"`
	Name            string              `json:"name"`
	Description     string              `json:"description,omitempty"`

	// Scope
	StartDate       time.Time           `json:"start_date"`
	EndDate         time.Time           `json:"end_date"`
	DeviceScope     []uuid.UUID         `json:"device_scope,omitempty"` // Empty = all devices

	// Results
	OverallStatus   ComplianceStatus    `json:"overall_status"`
	OverallScore    float64             `json:"overall_score"` // 0-100
	Controls        []ControlAssessment `json:"controls"`

	// Summary
	TotalControls       int             `json:"total_controls"`
	PassedControls      int             `json:"passed_controls"`
	FailedControls      int             `json:"failed_controls"`
	PartialControls     int             `json:"partial_controls"`
	NotApplicable       int             `json:"not_applicable"`

	// Findings
	Findings        []ComplianceFinding `json:"findings"`

	// Metadata
	GeneratedAt     time.Time           `json:"generated_at"`
	GeneratedBy     string              `json:"generated_by"`
	Version         string              `json:"version"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus string

const (
	ComplianceStatusCompliant    ComplianceStatus = "compliant"
	ComplianceStatusNonCompliant ComplianceStatus = "non_compliant"
	ComplianceStatusPartial      ComplianceStatus = "partial"
	ComplianceStatusUnknown      ComplianceStatus = "unknown"
)

// ControlAssessment represents assessment of a single control
type ControlAssessment struct {
	ControlID       string           `json:"control_id"`
	ControlName     string           `json:"control_name"`
	Category        string           `json:"category"`
	Description     string           `json:"description"`

	// Assessment
	Status          ComplianceStatus `json:"status"`
	Score           float64          `json:"score"` // 0-100
	Evidence        []string         `json:"evidence,omitempty"`

	// Details
	Requirements    []string         `json:"requirements"`
	Implementation  string           `json:"implementation,omitempty"`
	Gaps            []string         `json:"gaps,omitempty"`
	Remediation     []string         `json:"remediation,omitempty"`

	// Metadata
	LastAssessedAt  time.Time        `json:"last_assessed_at"`
	Assessor        string           `json:"assessor,omitempty"`
}

// ComplianceFinding represents a compliance finding
type ComplianceFinding struct {
	ID              uuid.UUID   `json:"id"`
	ControlID       string      `json:"control_id"`
	Type            string      `json:"type"` // gap, observation, recommendation
	Severity        Severity    `json:"severity"`
	Title           string      `json:"title"`
	Description     string      `json:"description"`

	// Impact
	Impact          string      `json:"impact"`
	AffectedDevices int         `json:"affected_devices"`

	// Remediation
	Remediation     string      `json:"remediation"`
	DueDate         *time.Time  `json:"due_date,omitempty"`
	Status          string      `json:"status"` // open, in_progress, resolved, accepted

	// Assignment
	AssignedTo      string      `json:"assigned_to,omitempty"`
	ResolvedAt      *time.Time  `json:"resolved_at,omitempty"`
	ResolvedBy      string      `json:"resolved_by,omitempty"`

	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// DeviceComplianceStatus represents device compliance state
type DeviceComplianceStatus struct {
	DeviceID        uuid.UUID           `json:"device_id"`

	// Overall
	IsCompliant     bool                `json:"is_compliant"`
	ComplianceScore float64             `json:"compliance_score"`

	// Per-framework
	FrameworkStatus map[ComplianceFramework]FrameworkComplianceStatus `json:"framework_status"`

	// Issues
	Issues          []ComplianceIssue   `json:"issues"`

	// Timestamps
	LastCheckedAt   time.Time           `json:"last_checked_at"`
	NextCheckAt     time.Time           `json:"next_check_at"`
}

// FrameworkComplianceStatus represents compliance for a specific framework
type FrameworkComplianceStatus struct {
	Framework       ComplianceFramework `json:"framework"`
	Status          ComplianceStatus    `json:"status"`
	Score           float64             `json:"score"`
	PassedControls  int                 `json:"passed_controls"`
	FailedControls  int                 `json:"failed_controls"`
	LastCheckedAt   time.Time           `json:"last_checked_at"`
}

// ComplianceIssue represents a compliance issue on a device
type ComplianceIssue struct {
	ID              uuid.UUID           `json:"id"`
	Framework       ComplianceFramework `json:"framework"`
	ControlID       string              `json:"control_id"`
	Severity        Severity            `json:"severity"`
	Title           string              `json:"title"`
	Description     string              `json:"description"`
	Remediation     string              `json:"remediation"`
	AutoRemediable  bool                `json:"auto_remediable"`
	DetectedAt      time.Time           `json:"detected_at"`
}

// ============================================================================
// Common Enterprise Types
// ============================================================================

// AuditLog represents an audit log entry
type AuditLog struct {
	ID              uuid.UUID   `json:"id"`
	Timestamp       time.Time   `json:"timestamp"`

	// Actor
	ActorType       string      `json:"actor_type"` // user, system, api
	ActorID         string      `json:"actor_id"`
	ActorName       string      `json:"actor_name,omitempty"`
	ActorIP         string      `json:"actor_ip,omitempty"`

	// Action
	Action          string      `json:"action"`
	Resource        string      `json:"resource"`
	ResourceID      string      `json:"resource_id,omitempty"`

	// Result
	Outcome         string      `json:"outcome"` // success, failure
	Details         string      `json:"details,omitempty"`
	Changes         map[string]interface{} `json:"changes,omitempty"`

	// Context
	SessionID       string      `json:"session_id,omitempty"`
	RequestID       string      `json:"request_id,omitempty"`
	UserAgent       string      `json:"user_agent,omitempty"`
}

// EnterpriseStats represents enterprise statistics
type EnterpriseStats struct {
	// MDM
	MDMIntegrations     int     `json:"mdm_integrations"`
	MDMDevices          int     `json:"mdm_devices"`
	MDMCompliantDevices int     `json:"mdm_compliant_devices"`

	// Zero Trust
	AveragePostureScore float64 `json:"average_posture_score"`
	HighTrustDevices    int     `json:"high_trust_devices"`
	LowTrustDevices     int     `json:"low_trust_devices"`
	AccessDecisionsToday int    `json:"access_decisions_today"`
	BlockedAccessToday  int     `json:"blocked_access_today"`

	// SIEM
	SIEMIntegrations    int     `json:"siem_integrations"`
	EventsSentToday     int64   `json:"events_sent_today"`

	// Compliance
	OverallComplianceScore float64 `json:"overall_compliance_score"`
	ComplianceReports      int     `json:"compliance_reports"`
	OpenFindings           int     `json:"open_findings"`
	CriticalFindings       int     `json:"critical_findings"`

	Timestamp           time.Time `json:"timestamp"`
}

// ============================================================================
// Control Definitions by Framework
// ============================================================================

// GDPRControl represents a GDPR control
var GDPRControls = []ControlAssessment{
	{ControlID: "GDPR-5.1", ControlName: "Lawfulness of Processing", Category: "Principles", Description: "Personal data must be processed lawfully"},
	{ControlID: "GDPR-5.2", ControlName: "Purpose Limitation", Category: "Principles", Description: "Data collected for specified, explicit and legitimate purposes"},
	{ControlID: "GDPR-5.3", ControlName: "Data Minimization", Category: "Principles", Description: "Data must be adequate, relevant and limited"},
	{ControlID: "GDPR-25", ControlName: "Data Protection by Design", Category: "Technical", Description: "Implement technical measures for data protection"},
	{ControlID: "GDPR-32", ControlName: "Security of Processing", Category: "Security", Description: "Implement appropriate security measures"},
	{ControlID: "GDPR-33", ControlName: "Breach Notification", Category: "Incident Response", Description: "Notify supervisory authority of breaches within 72 hours"},
	{ControlID: "GDPR-35", ControlName: "Data Protection Impact Assessment", Category: "Risk Management", Description: "Conduct DPIA for high-risk processing"},
}

// SOC2Controls represents SOC 2 Trust Service Criteria
var SOC2Controls = []ControlAssessment{
	// Security
	{ControlID: "CC1.1", ControlName: "Control Environment", Category: "Security", Description: "Entity demonstrates commitment to integrity and ethical values"},
	{ControlID: "CC2.1", ControlName: "Communication and Information", Category: "Security", Description: "Entity obtains/generates relevant information"},
	{ControlID: "CC3.1", ControlName: "Risk Assessment", Category: "Security", Description: "Entity specifies objectives with sufficient clarity"},
	{ControlID: "CC4.1", ControlName: "Monitoring Activities", Category: "Security", Description: "Entity selects and develops monitoring activities"},
	{ControlID: "CC5.1", ControlName: "Control Activities", Category: "Security", Description: "Entity selects and develops control activities"},
	{ControlID: "CC6.1", ControlName: "Logical and Physical Access", Category: "Security", Description: "Entity implements logical access security"},
	{ControlID: "CC6.6", ControlName: "System Operations", Category: "Security", Description: "Entity prevents unauthorized access"},
	{ControlID: "CC6.7", ControlName: "Change Management", Category: "Security", Description: "Entity manages system changes"},
	{ControlID: "CC7.1", ControlName: "System Monitoring", Category: "Security", Description: "Entity detects configuration changes"},
	{ControlID: "CC7.2", ControlName: "Incident Response", Category: "Security", Description: "Entity monitors for anomalies and evaluates security events"},
	// Availability
	{ControlID: "A1.1", ControlName: "Capacity Planning", Category: "Availability", Description: "Entity maintains system availability"},
	{ControlID: "A1.2", ControlName: "Environmental Protections", Category: "Availability", Description: "Entity implements environmental protections"},
	// Confidentiality
	{ControlID: "C1.1", ControlName: "Confidential Information", Category: "Confidentiality", Description: "Entity identifies confidential information"},
	{ControlID: "C1.2", ControlName: "Disposal of Confidential Information", Category: "Confidentiality", Description: "Entity disposes of confidential information"},
}

// CISControls represents CIS Critical Security Controls
var CISControls = []ControlAssessment{
	{ControlID: "CIS-1", ControlName: "Inventory of Enterprise Assets", Category: "Inventory", Description: "Actively manage all enterprise assets"},
	{ControlID: "CIS-2", ControlName: "Inventory of Software Assets", Category: "Inventory", Description: "Actively manage all software on the network"},
	{ControlID: "CIS-3", ControlName: "Data Protection", Category: "Data", Description: "Develop processes to identify, classify, and protect data"},
	{ControlID: "CIS-4", ControlName: "Secure Configuration", Category: "Configuration", Description: "Establish secure configuration for enterprise assets"},
	{ControlID: "CIS-5", ControlName: "Account Management", Category: "Access Control", Description: "Use processes to manage credentials"},
	{ControlID: "CIS-6", ControlName: "Access Control Management", Category: "Access Control", Description: "Use processes to grant/revoke access"},
	{ControlID: "CIS-7", ControlName: "Continuous Vulnerability Management", Category: "Vulnerability", Description: "Continuously assess and remediate vulnerabilities"},
	{ControlID: "CIS-8", ControlName: "Audit Log Management", Category: "Logging", Description: "Collect, alert, review audit logs"},
	{ControlID: "CIS-9", ControlName: "Email and Browser Protections", Category: "Protection", Description: "Improve protections for email and web browsers"},
	{ControlID: "CIS-10", ControlName: "Malware Defenses", Category: "Protection", Description: "Prevent or control malware installation"},
	{ControlID: "CIS-11", ControlName: "Data Recovery", Category: "Recovery", Description: "Establish data recovery practices"},
	{ControlID: "CIS-12", ControlName: "Network Infrastructure Management", Category: "Network", Description: "Establish secure network configuration"},
	{ControlID: "CIS-13", ControlName: "Network Monitoring and Defense", Category: "Network", Description: "Operate network monitoring and defense"},
	{ControlID: "CIS-14", ControlName: "Security Awareness Training", Category: "Training", Description: "Establish security awareness program"},
	{ControlID: "CIS-15", ControlName: "Service Provider Management", Category: "Third Party", Description: "Evaluate and manage service providers"},
	{ControlID: "CIS-16", ControlName: "Application Software Security", Category: "Application", Description: "Manage security of in-house developed software"},
	{ControlID: "CIS-17", ControlName: "Incident Response Management", Category: "Incident Response", Description: "Establish incident response program"},
	{ControlID: "CIS-18", ControlName: "Penetration Testing", Category: "Testing", Description: "Test effectiveness of security controls"},
}
