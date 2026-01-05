package models

import (
	"time"

	"github.com/google/uuid"
)

// AppRiskLevel represents the risk level of an app
type AppRiskLevel string

const (
	AppRiskLevelSafe     AppRiskLevel = "safe"
	AppRiskLevelLow      AppRiskLevel = "low"
	AppRiskLevelMedium   AppRiskLevel = "medium"
	AppRiskLevelHigh     AppRiskLevel = "high"
	AppRiskLevelCritical AppRiskLevel = "critical"
)

// AppInstallSource represents how an app was installed
type AppInstallSource string

const (
	AppInstallSourcePlayStore  AppInstallSource = "play_store"
	AppInstallSourceAppStore   AppInstallSource = "app_store"
	AppInstallSourceSideloaded AppInstallSource = "sideloaded"
	AppInstallSourceADB        AppInstallSource = "adb"
	AppInstallSourcePreloaded  AppInstallSource = "preloaded"
	AppInstallSourceEnterprise AppInstallSource = "enterprise"
	AppInstallSourceUnknown    AppInstallSource = "unknown"
)

// AppInfo represents basic information about an installed app
type AppInfo struct {
	ID              uuid.UUID        `json:"id"`
	PackageName     string           `json:"package_name"`
	AppName         string           `json:"app_name"`
	VersionName     string           `json:"version_name"`
	VersionCode     int64            `json:"version_code"`
	InstallSource   AppInstallSource `json:"install_source"`
	InstalledAt     time.Time        `json:"installed_at"`
	LastUpdated     time.Time        `json:"last_updated"`
	TargetSDK       int              `json:"target_sdk"`
	MinSDK          int              `json:"min_sdk"`
	IsSystemApp     bool             `json:"is_system_app"`
	IsEnabled       bool             `json:"is_enabled"`
	SignatureHash   string           `json:"signature_hash"`
	APKHash         string           `json:"apk_hash,omitempty"`
	APKSize         int64            `json:"apk_size"`
	DataDir         string           `json:"data_dir,omitempty"`
	DeviceID        string           `json:"device_id"`
}

// AppPermission represents a permission requested by an app
type AppPermission struct {
	Name        string `json:"name"`
	Group       string `json:"group,omitempty"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	IsGranted   bool   `json:"is_granted"`
	IsDangerous bool   `json:"is_dangerous"`
	IsRuntime   bool   `json:"is_runtime"`
}

// PermissionCategory represents categories of permissions
type PermissionCategory string

const (
	PermissionCategoryLocation      PermissionCategory = "location"
	PermissionCategoryCamera        PermissionCategory = "camera"
	PermissionCategoryMicrophone    PermissionCategory = "microphone"
	PermissionCategoryContacts      PermissionCategory = "contacts"
	PermissionCategoryCalendar      PermissionCategory = "calendar"
	PermissionCategoryStorage       PermissionCategory = "storage"
	PermissionCategorySMS           PermissionCategory = "sms"
	PermissionCategoryPhone         PermissionCategory = "phone"
	PermissionCategorySensors       PermissionCategory = "sensors"
	PermissionCategoryNetwork       PermissionCategory = "network"
	PermissionCategoryBluetooth     PermissionCategory = "bluetooth"
	PermissionCategoryNotifications PermissionCategory = "notifications"
	PermissionCategoryAccessibility PermissionCategory = "accessibility"
	PermissionCategoryAdmin         PermissionCategory = "admin"
	PermissionCategoryOther         PermissionCategory = "other"
)

// AppAnalysisRequest represents a request to analyze an app
type AppAnalysisRequest struct {
	PackageName  string          `json:"package_name"`
	AppName      string          `json:"app_name"`
	VersionName  string          `json:"version_name"`
	VersionCode  int64           `json:"version_code"`
	Permissions  []AppPermission `json:"permissions"`
	InstallSource AppInstallSource `json:"install_source"`
	TargetSDK    int             `json:"target_sdk"`
	MinSDK       int             `json:"min_sdk"`
	IsSystemApp  bool            `json:"is_system_app"`
	SignatureHash string         `json:"signature_hash,omitempty"`
	APKHash      string          `json:"apk_hash,omitempty"`
	DeviceID     string          `json:"device_id,omitempty"`
}

// AppAnalysisResult contains the complete security analysis of an app
type AppAnalysisResult struct {
	ID              uuid.UUID           `json:"id"`
	PackageName     string              `json:"package_name"`
	AppName         string              `json:"app_name"`
	RiskLevel       AppRiskLevel        `json:"risk_level"`
	RiskScore       float64             `json:"risk_score"` // 0-100
	OverallVerdict  string              `json:"overall_verdict"`

	// Permission analysis
	PermissionRisk   PermissionRiskAnalysis `json:"permission_risk"`

	// Privacy analysis
	PrivacyRisk      PrivacyRiskAnalysis    `json:"privacy_risk"`

	// Security analysis
	SecurityRisk     SecurityRiskAnalysis   `json:"security_risk"`

	// Behavioral analysis
	BehavioralRisk   BehavioralRiskAnalysis `json:"behavioral_risk,omitempty"`

	// Threat intelligence match
	ThreatIntelMatch *ThreatIntelMatch      `json:"threat_intel_match,omitempty"`

	// Recommendations
	Recommendations  []AppRecommendation    `json:"recommendations"`

	// Metadata
	AnalyzedAt       time.Time              `json:"analyzed_at"`
	AnalysisVersion  string                 `json:"analysis_version"`
}

// PermissionRiskAnalysis contains permission-based risk analysis
type PermissionRiskAnalysis struct {
	Score             float64                    `json:"score"` // 0-100
	DangerousCount    int                        `json:"dangerous_count"`
	GrantedDangerous  int                        `json:"granted_dangerous"`
	PermissionGroups  map[string]int             `json:"permission_groups"`
	DangerousCombos   []DangerousPermissionCombo `json:"dangerous_combos,omitempty"`
	Concerns          []string                   `json:"concerns"`
}

// DangerousPermissionCombo represents a risky combination of permissions
type DangerousPermissionCombo struct {
	Permissions []string `json:"permissions"`
	RiskLevel   string   `json:"risk_level"`
	Description string   `json:"description"`
}

// PrivacyRiskAnalysis contains privacy-focused risk analysis
type PrivacyRiskAnalysis struct {
	Score            float64           `json:"score"` // 0-100
	DataAccessTypes  []string          `json:"data_access_types"`
	TrackerSDKs      []TrackerSDK      `json:"tracker_sdks,omitempty"`
	NetworkDestinations []string       `json:"network_destinations,omitempty"`
	DataCollection   DataCollectionInfo `json:"data_collection"`
	Concerns         []string          `json:"concerns"`
}

// TrackerSDK represents a tracking SDK found in an app
type TrackerSDK struct {
	Name        string   `json:"name"`
	Company     string   `json:"company"`
	Category    string   `json:"category"` // "analytics", "advertising", "social", "crash_reporting"
	DataTypes   []string `json:"data_types"`
	Website     string   `json:"website,omitempty"`
}

// DataCollectionInfo describes what data an app may collect
type DataCollectionInfo struct {
	CollectsLocation     bool `json:"collects_location"`
	CollectsContacts     bool `json:"collects_contacts"`
	CollectsCallLogs     bool `json:"collects_call_logs"`
	CollectsSMS          bool `json:"collects_sms"`
	CollectsCamera       bool `json:"collects_camera"`
	CollectsMicrophone   bool `json:"collects_microphone"`
	CollectsStorage      bool `json:"collects_storage"`
	CollectsDeviceInfo   bool `json:"collects_device_info"`
	CollectsUsageStats   bool `json:"collects_usage_stats"`
	CollectsBiometrics   bool `json:"collects_biometrics"`
	HasInternetAccess    bool `json:"has_internet_access"`
	CanRunInBackground   bool `json:"can_run_in_background"`
}

// SecurityRiskAnalysis contains security-focused risk analysis
type SecurityRiskAnalysis struct {
	Score              float64  `json:"score"` // 0-100
	IsSideloaded       bool     `json:"is_sideloaded"`
	IsObfuscated       bool     `json:"is_obfuscated"`
	HasDebugEnabled    bool     `json:"has_debug_enabled"`
	HasBackupAllowed   bool     `json:"has_backup_allowed"`
	UsesHTTP           bool     `json:"uses_http"`
	HasWeakCrypto      bool     `json:"has_weak_crypto"`
	TargetsOldSDK      bool     `json:"targets_old_sdk"`
	SignatureValid     bool     `json:"signature_valid"`
	SignatureTrusted   bool     `json:"signature_trusted"`
	KnownVulnerabilities []string `json:"known_vulnerabilities,omitempty"`
	Concerns           []string `json:"concerns"`
}

// BehavioralRiskAnalysis contains behavioral analysis results
type BehavioralRiskAnalysis struct {
	Score                float64  `json:"score"` // 0-100
	BatteryUsage         string   `json:"battery_usage"` // "low", "medium", "high", "excessive"
	DataUsage            string   `json:"data_usage"`
	BackgroundActivity   string   `json:"background_activity"`
	WakeLocksExcessive   bool     `json:"wake_locks_excessive"`
	FrequentNetworkCalls bool     `json:"frequent_network_calls"`
	SuspiciousBehaviors  []string `json:"suspicious_behaviors,omitempty"`
	Concerns             []string `json:"concerns"`
}

// ThreatIntelMatch represents a match against threat intelligence
type ThreatIntelMatch struct {
	IsKnownMalware     bool      `json:"is_known_malware"`
	IsPotentiallyHarmful bool    `json:"is_potentially_harmful"`
	MalwareFamily      string    `json:"malware_family,omitempty"`
	CampaignID         string    `json:"campaign_id,omitempty"`
	ThreatActorID      string    `json:"threat_actor_id,omitempty"`
	IndicatorIDs       []string  `json:"indicator_ids,omitempty"`
	DetectionSource    string    `json:"detection_source"`
	FirstSeen          time.Time `json:"first_seen,omitempty"`
}

// AppRecommendation represents a security recommendation for an app
type AppRecommendation struct {
	ID          string       `json:"id"`
	Priority    string       `json:"priority"` // "critical", "high", "medium", "low"
	Category    string       `json:"category"` // "permission", "privacy", "security", "update"
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Action      string       `json:"action"` // "uninstall", "revoke_permission", "update", "review"
	ActionData  interface{}  `json:"action_data,omitempty"`
}

// AppBatchAnalysisRequest represents a batch analysis request
type AppBatchAnalysisRequest struct {
	Apps     []AppAnalysisRequest `json:"apps"`
	DeviceID string               `json:"device_id"`
}

// AppBatchAnalysisResult contains results for batch analysis
type AppBatchAnalysisResult struct {
	Results      []AppAnalysisResult `json:"results"`
	TotalCount   int                 `json:"total_count"`
	SafeCount    int                 `json:"safe_count"`
	RiskyCount   int                 `json:"risky_count"`
	CriticalCount int                `json:"critical_count"`
	AnalyzedAt   time.Time           `json:"analyzed_at"`
}

// AppReputation represents the reputation of an app
type AppReputation struct {
	PackageName    string       `json:"package_name"`
	AppName        string       `json:"app_name"`
	Developer      string       `json:"developer"`
	Category       string       `json:"category"`
	RiskLevel      AppRiskLevel `json:"risk_level"`
	RiskScore      float64      `json:"risk_score"`
	ReportCount    int          `json:"report_count"`
	DownloadCount  int64        `json:"download_count,omitempty"`
	PlayStoreRating float64     `json:"play_store_rating,omitempty"`
	FirstSeen      time.Time    `json:"first_seen"`
	LastUpdated    time.Time    `json:"last_updated"`
	IsVerified     bool         `json:"is_verified"`
	IsBlacklisted  bool         `json:"is_blacklisted"`
}

// SideloadedAppReport represents a report on sideloaded apps
type SideloadedAppReport struct {
	DeviceID       string              `json:"device_id"`
	TotalApps      int                 `json:"total_apps"`
	SideloadedCount int                `json:"sideloaded_count"`
	RiskyCount     int                 `json:"risky_count"`
	SideloadedApps []SideloadedAppInfo `json:"sideloaded_apps"`
	GeneratedAt    time.Time           `json:"generated_at"`
}

// SideloadedAppInfo contains information about a sideloaded app
type SideloadedAppInfo struct {
	PackageName   string       `json:"package_name"`
	AppName       string       `json:"app_name"`
	InstallSource AppInstallSource `json:"install_source"`
	RiskLevel     AppRiskLevel `json:"risk_level"`
	RiskScore     float64      `json:"risk_score"`
	Concerns      []string     `json:"concerns"`
	InstalledAt   time.Time    `json:"installed_at"`
}

// PrivacyReport represents a privacy audit report for all apps
type PrivacyReport struct {
	DeviceID          string                 `json:"device_id"`
	TotalApps         int                    `json:"total_apps"`
	AppsWithTrackers  int                    `json:"apps_with_trackers"`
	TotalTrackers     int                    `json:"total_trackers"`
	TrackersByCategory map[string]int        `json:"trackers_by_category"`
	TopTrackers       []TrackerStats         `json:"top_trackers"`
	AppPrivacyScores  []AppPrivacyScore      `json:"app_privacy_scores"`
	Recommendations   []AppRecommendation    `json:"recommendations"`
	GeneratedAt       time.Time              `json:"generated_at"`
}

// TrackerStats represents statistics for a tracker
type TrackerStats struct {
	Name      string `json:"name"`
	Company   string `json:"company"`
	AppCount  int    `json:"app_count"`
	Category  string `json:"category"`
}

// AppPrivacyScore represents the privacy score of an app
type AppPrivacyScore struct {
	PackageName  string   `json:"package_name"`
	AppName      string   `json:"app_name"`
	PrivacyScore float64  `json:"privacy_score"` // 0-100 (higher is better)
	TrackerCount int      `json:"tracker_count"`
	DataTypes    []string `json:"data_types"`
}

// AppSecurityStats represents overall app security statistics
type AppSecurityStats struct {
	TotalAppsAnalyzed  int64            `json:"total_apps_analyzed"`
	BySafetyLevel      map[string]int64 `json:"by_safety_level"`
	ByInstallSource    map[string]int64 `json:"by_install_source"`
	MalwareDetected    int64            `json:"malware_detected"`
	SideloadedApps     int64            `json:"sideloaded_apps"`
	AppsWithTrackers   int64            `json:"apps_with_trackers"`
	AverageRiskScore   float64          `json:"average_risk_score"`
	TopRiskyApps       []AppRiskSummary `json:"top_risky_apps"`
}

// AppRiskSummary is a brief summary of app risk
type AppRiskSummary struct {
	PackageName string       `json:"package_name"`
	AppName     string       `json:"app_name"`
	RiskLevel   AppRiskLevel `json:"risk_level"`
	RiskScore   float64      `json:"risk_score"`
}

// KnownTrackers is a list of known tracker SDKs
var KnownTrackers = map[string]TrackerSDK{
	"com.google.firebase.analytics": {
		Name:     "Firebase Analytics",
		Company:  "Google",
		Category: "analytics",
		DataTypes: []string{"device_info", "app_usage", "events"},
	},
	"com.google.android.gms.ads": {
		Name:     "Google Ads",
		Company:  "Google",
		Category: "advertising",
		DataTypes: []string{"device_id", "location", "interests"},
	},
	"com.facebook.ads": {
		Name:     "Facebook Ads",
		Company:  "Meta",
		Category: "advertising",
		DataTypes: []string{"device_id", "app_usage", "demographics"},
	},
	"com.facebook.appevents": {
		Name:     "Facebook Analytics",
		Company:  "Meta",
		Category: "analytics",
		DataTypes: []string{"app_events", "device_info", "user_actions"},
	},
	"com.appsflyer": {
		Name:     "AppsFlyer",
		Company:  "AppsFlyer",
		Category: "analytics",
		DataTypes: []string{"install_attribution", "device_info", "events"},
	},
	"com.adjust.sdk": {
		Name:     "Adjust",
		Company:  "Adjust",
		Category: "analytics",
		DataTypes: []string{"install_attribution", "device_info", "events"},
	},
	"io.branch": {
		Name:     "Branch",
		Company:  "Branch",
		Category: "analytics",
		DataTypes: []string{"deep_links", "attribution", "device_info"},
	},
	"com.crashlytics": {
		Name:     "Crashlytics",
		Company:  "Google",
		Category: "crash_reporting",
		DataTypes: []string{"crash_logs", "device_info", "app_state"},
	},
	"com.amplitude": {
		Name:     "Amplitude",
		Company:  "Amplitude",
		Category: "analytics",
		DataTypes: []string{"events", "user_properties", "device_info"},
	},
	"com.mixpanel": {
		Name:     "Mixpanel",
		Company:  "Mixpanel",
		Category: "analytics",
		DataTypes: []string{"events", "user_properties", "device_info"},
	},
	"com.unity3d.ads": {
		Name:     "Unity Ads",
		Company:  "Unity",
		Category: "advertising",
		DataTypes: []string{"device_id", "game_data", "ad_interactions"},
	},
	"com.mopub": {
		Name:     "MoPub",
		Company:  "Twitter/AppLovin",
		Category: "advertising",
		DataTypes: []string{"device_id", "location", "ad_interactions"},
	},
}

// DangerousPermissionCombos defines risky permission combinations
var DangerousPermissionCombos = []DangerousPermissionCombo{
	{
		Permissions: []string{"android.permission.READ_SMS", "android.permission.INTERNET"},
		RiskLevel:   "critical",
		Description: "Can read SMS and send data to internet - potential banking trojan behavior",
	},
	{
		Permissions: []string{"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
		RiskLevel:   "high",
		Description: "Can read contacts and send data to internet - potential data harvesting",
	},
	{
		Permissions: []string{"android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
		RiskLevel:   "high",
		Description: "Can record audio and send data to internet - potential spyware behavior",
	},
	{
		Permissions: []string{"android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
		RiskLevel:   "critical",
		Description: "Full audio/video recording with internet access - potential surveillance",
	},
	{
		Permissions: []string{"android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"},
		RiskLevel:   "high",
		Description: "Background location tracking with internet access - potential stalkerware",
	},
	{
		Permissions: []string{"android.permission.READ_CALL_LOG", "android.permission.INTERNET"},
		RiskLevel:   "high",
		Description: "Can read call logs and send data to internet - potential spyware",
	},
	{
		Permissions: []string{"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"},
		RiskLevel:   "critical",
		Description: "Accessibility service with internet - can monitor all screen content",
	},
	{
		Permissions: []string{"android.permission.BIND_DEVICE_ADMIN", "android.permission.INTERNET"},
		RiskLevel:   "critical",
		Description: "Device admin with internet - full device control capability",
	},
	{
		Permissions: []string{"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
		RiskLevel:   "critical",
		Description: "Overlay + accessibility - can intercept all user input (potential keylogger)",
	},
}
