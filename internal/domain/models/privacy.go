package models

import (
	"time"

	"github.com/google/uuid"
)

// PrivacyEventType represents the type of privacy event
type PrivacyEventType string

const (
	PrivacyEventCameraAccess     PrivacyEventType = "camera_access"
	PrivacyEventMicrophoneAccess PrivacyEventType = "microphone_access"
	PrivacyEventLocationAccess   PrivacyEventType = "location_access"
	PrivacyEventClipboardRead    PrivacyEventType = "clipboard_read"
	PrivacyEventClipboardWrite   PrivacyEventType = "clipboard_write"
	PrivacyEventScreenCapture    PrivacyEventType = "screen_capture"
	PrivacyEventScreenRecording  PrivacyEventType = "screen_recording"
	PrivacyEventContactsAccess   PrivacyEventType = "contacts_access"
	PrivacyEventCalendarAccess   PrivacyEventType = "calendar_access"
	PrivacyEventCallLogAccess    PrivacyEventType = "call_log_access"
	PrivacyEventSMSAccess        PrivacyEventType = "sms_access"
	PrivacyEventStorageAccess    PrivacyEventType = "storage_access"
	PrivacyEventNetworkAccess    PrivacyEventType = "network_access"
	PrivacyEventSensorAccess     PrivacyEventType = "sensor_access"
)

// PrivacyRiskLevel represents the risk level of a privacy event
type PrivacyRiskLevel string

const (
	PrivacyRiskCritical PrivacyRiskLevel = "critical"
	PrivacyRiskHigh     PrivacyRiskLevel = "high"
	PrivacyRiskMedium   PrivacyRiskLevel = "medium"
	PrivacyRiskLow      PrivacyRiskLevel = "low"
	PrivacyRiskInfo     PrivacyRiskLevel = "info"
)

// PrivacyEvent represents a privacy-related event from an app
type PrivacyEvent struct {
	ID            uuid.UUID        `json:"id" db:"id"`
	DeviceID      string           `json:"device_id" db:"device_id"`
	PackageName   string           `json:"package_name" db:"package_name"`
	AppName       string           `json:"app_name" db:"app_name"`
	EventType     PrivacyEventType `json:"event_type" db:"event_type"`
	RiskLevel     PrivacyRiskLevel `json:"risk_level" db:"risk_level"`
	IsBackground  bool             `json:"is_background" db:"is_background"`
	Duration      int64            `json:"duration_ms" db:"duration_ms"`
	Details       string           `json:"details,omitempty" db:"details"`
	Timestamp     time.Time        `json:"timestamp" db:"timestamp"`
	WasBlocked    bool             `json:"was_blocked" db:"was_blocked"`
	UserNotified  bool             `json:"user_notified" db:"user_notified"`
}

// CameraAccessEvent represents a camera access event
type CameraAccessEvent struct {
	PrivacyEvent
	CameraID      string `json:"camera_id"`      // front, back, etc.
	Resolution    string `json:"resolution"`     // e.g., "1920x1080"
	WasRecording  bool   `json:"was_recording"`
	PhotosTaken   int    `json:"photos_taken"`
	VideoDuration int64  `json:"video_duration_ms"`
}

// MicrophoneAccessEvent represents a microphone access event
type MicrophoneAccessEvent struct {
	PrivacyEvent
	AudioSource   string  `json:"audio_source"`   // mic, voice_call, etc.
	SampleRate    int     `json:"sample_rate"`
	WasRecording  bool    `json:"was_recording"`
	RecordingPath string  `json:"recording_path,omitempty"`
	VolumeLevel   float64 `json:"volume_level"`
}

// ClipboardEvent represents a clipboard access event
type ClipboardEvent struct {
	PrivacyEvent
	DataType         string `json:"data_type"`          // text, image, uri
	DataLength       int    `json:"data_length"`
	ContainsSensitive bool   `json:"contains_sensitive"`
	SensitiveType    string `json:"sensitive_type,omitempty"` // password, credit_card, ssn, etc.
	SourceApp        string `json:"source_app,omitempty"`
	WasHijacked      bool   `json:"was_hijacked"`
}

// ScreenEvent represents a screen capture/recording event
type ScreenEvent struct {
	PrivacyEvent
	CaptureType   string `json:"capture_type"` // screenshot, recording, casting
	TargetApp     string `json:"target_app,omitempty"`
	WasSensitive  bool   `json:"was_sensitive"` // Was sensitive content visible
	Duration      int64  `json:"duration_ms"`
	DestinationIP string `json:"destination_ip,omitempty"` // For screen casting
}

// LocationAccessEvent represents a location access event
type LocationAccessEvent struct {
	PrivacyEvent
	Latitude     float64 `json:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty"`
	Accuracy     float64 `json:"accuracy_meters"`
	Provider     string  `json:"provider"` // gps, network, fused
	IsContinuous bool    `json:"is_continuous"`
}

// TrackerInfo represents information about an ad tracker
type TrackerInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Company      string   `json:"company"`
	Category     string   `json:"category"` // advertising, analytics, social, etc.
	Domains      []string `json:"domains"`
	SDKNames     []string `json:"sdk_names"`
	Description  string   `json:"description"`
	PrivacyRisk  PrivacyRiskLevel `json:"privacy_risk"`
	DataCollected []string `json:"data_collected"` // device_id, location, contacts, etc.
	Website      string   `json:"website,omitempty"`
}

// TrackerDetection represents a detected tracker in an app or network request
type TrackerDetection struct {
	ID          uuid.UUID    `json:"id"`
	DeviceID    string       `json:"device_id"`
	PackageName string       `json:"package_name"`
	AppName     string       `json:"app_name"`
	Tracker     TrackerInfo  `json:"tracker"`
	DetectedAt  time.Time    `json:"detected_at"`
	DetectedVia string       `json:"detected_via"` // sdk, network, manifest
	WasBlocked  bool         `json:"was_blocked"`
	Domain      string       `json:"domain,omitempty"`
	Endpoint    string       `json:"endpoint,omitempty"`
}

// TrackerBlockRule represents a rule for blocking trackers
type TrackerBlockRule struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TrackerID   string    `json:"tracker_id" db:"tracker_id"`
	Domain      string    `json:"domain" db:"domain"`
	IsRegex     bool      `json:"is_regex" db:"is_regex"`
	Action      string    `json:"action" db:"action"` // block, allow, log
	Enabled     bool      `json:"enabled" db:"enabled"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// PrivacyAuditResult represents the result of a privacy audit
type PrivacyAuditResult struct {
	DeviceID          string             `json:"device_id"`
	AuditedAt         time.Time          `json:"audited_at"`
	OverallScore      float64            `json:"overall_score"` // 0-100
	OverallGrade      string             `json:"overall_grade"` // A-F
	RiskLevel         PrivacyRiskLevel   `json:"risk_level"`

	// Category scores
	CameraPrivacy     CategoryScore      `json:"camera_privacy"`
	MicrophonePrivacy CategoryScore      `json:"microphone_privacy"`
	LocationPrivacy   CategoryScore      `json:"location_privacy"`
	DataPrivacy       CategoryScore      `json:"data_privacy"`
	NetworkPrivacy    CategoryScore      `json:"network_privacy"`

	// Issues found
	Issues            []PrivacyIssue     `json:"issues"`
	Recommendations   []string           `json:"recommendations"`

	// App breakdown
	RiskyApps         []AppPrivacyInfo   `json:"risky_apps"`
	TrackerCount      int                `json:"tracker_count"`
	BlockedTrackers   int                `json:"blocked_trackers"`
}

// CategoryScore represents a score for a privacy category
type CategoryScore struct {
	Score          float64 `json:"score"`
	Grade          string  `json:"grade"`
	EventCount     int     `json:"event_count"`
	BackgroundUse  int     `json:"background_use"`
	RiskyApps      int     `json:"risky_apps"`
}

// PrivacyIssue represents a privacy issue found during audit
type PrivacyIssue struct {
	ID          string           `json:"id"`
	Type        PrivacyEventType `json:"type"`
	Severity    PrivacyRiskLevel `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	AffectedApp string           `json:"affected_app,omitempty"`
	Remediation string           `json:"remediation"`
	AutoFixable bool             `json:"auto_fixable"`
}

// AppPrivacyInfo represents privacy information about an app
type AppPrivacyInfo struct {
	PackageName       string             `json:"package_name"`
	AppName           string             `json:"app_name"`
	PrivacyScore      float64            `json:"privacy_score"`
	RiskLevel         PrivacyRiskLevel   `json:"risk_level"`
	CameraAccess      AccessSummary      `json:"camera_access"`
	MicrophoneAccess  AccessSummary      `json:"microphone_access"`
	LocationAccess    AccessSummary      `json:"location_access"`
	ClipboardAccess   AccessSummary      `json:"clipboard_access"`
	TrackerCount      int                `json:"tracker_count"`
	BackgroundActivity int               `json:"background_activity"`
	LastActivity      time.Time          `json:"last_activity"`
}

// AccessSummary summarizes access for a permission type
type AccessSummary struct {
	TotalAccess    int       `json:"total_access"`
	BackgroundUse  int       `json:"background_use"`
	LastAccess     time.Time `json:"last_access,omitempty"`
	IsGranted      bool      `json:"is_granted"`
	WasDenied      bool      `json:"was_denied"`
}

// PrivacySettings represents user privacy settings
type PrivacySettings struct {
	DeviceID              string    `json:"device_id" db:"device_id"`

	// Monitoring toggles
	MonitorCamera         bool      `json:"monitor_camera" db:"monitor_camera"`
	MonitorMicrophone     bool      `json:"monitor_microphone" db:"monitor_microphone"`
	MonitorClipboard      bool      `json:"monitor_clipboard" db:"monitor_clipboard"`
	MonitorLocation       bool      `json:"monitor_location" db:"monitor_location"`
	MonitorScreen         bool      `json:"monitor_screen" db:"monitor_screen"`

	// Alert settings
	AlertBackgroundCamera bool      `json:"alert_background_camera" db:"alert_background_camera"`
	AlertBackgroundMic    bool      `json:"alert_background_mic" db:"alert_background_mic"`
	AlertClipboardHijack  bool      `json:"alert_clipboard_hijack" db:"alert_clipboard_hijack"`
	AlertScreenRecording  bool      `json:"alert_screen_recording" db:"alert_screen_recording"`

	// Blocking settings
	BlockTrackers         bool      `json:"block_trackers" db:"block_trackers"`
	BlockAds              bool      `json:"block_ads" db:"block_ads"`
	BlockAnalytics        bool      `json:"block_analytics" db:"block_analytics"`

	// Whitelist
	WhitelistedApps       []string  `json:"whitelisted_apps" db:"-"`

	UpdatedAt             time.Time `json:"updated_at" db:"updated_at"`
}

// PrivacyStats represents privacy monitoring statistics
type PrivacyStats struct {
	DeviceID           string                      `json:"device_id"`
	Period             string                      `json:"period"` // day, week, month

	// Access counts
	CameraAccessCount    int                       `json:"camera_access_count"`
	MicrophoneAccessCount int                      `json:"microphone_access_count"`
	LocationAccessCount  int                       `json:"location_access_count"`
	ClipboardAccessCount int                       `json:"clipboard_access_count"`
	ScreenCaptureCount   int                       `json:"screen_capture_count"`

	// Background access (higher risk)
	BackgroundCameraUse  int                       `json:"background_camera_use"`
	BackgroundMicUse     int                       `json:"background_mic_use"`
	BackgroundLocationUse int                      `json:"background_location_use"`

	// Trackers
	TrackersDetected     int                       `json:"trackers_detected"`
	TrackersBlocked      int                       `json:"trackers_blocked"`
	TrackerRequests      int                       `json:"tracker_requests"`

	// Alerts
	AlertsSent           int                       `json:"alerts_sent"`
	AlertsAcknowledged   int                       `json:"alerts_acknowledged"`

	// Top offenders
	TopCameraApps        []AppAccessCount          `json:"top_camera_apps"`
	TopMicrophoneApps    []AppAccessCount          `json:"top_microphone_apps"`
	TopLocationApps      []AppAccessCount          `json:"top_location_apps"`
	TopTrackerApps       []AppAccessCount          `json:"top_tracker_apps"`

	// Timeline
	AccessByHour         map[int]int               `json:"access_by_hour"`
	AccessByDay          map[string]int            `json:"access_by_day"`

	GeneratedAt          time.Time                 `json:"generated_at"`
}

// AppAccessCount represents access count for an app
type AppAccessCount struct {
	PackageName string `json:"package_name"`
	AppName     string `json:"app_name"`
	Count       int    `json:"count"`
	Background  int    `json:"background"`
}

// SensitiveDataPattern represents a pattern for detecting sensitive data
type SensitiveDataPattern struct {
	Type        string `json:"type"`        // credit_card, ssn, phone, email, password
	Pattern     string `json:"pattern"`     // Regex pattern
	Description string `json:"description"`
	RiskLevel   PrivacyRiskLevel `json:"risk_level"`
}

// ClipboardProtectionResult represents the result of clipboard scanning
type ClipboardProtectionResult struct {
	IsSafe           bool                   `json:"is_safe"`
	SensitiveData    []SensitiveDataMatch   `json:"sensitive_data,omitempty"`
	WasHijacked      bool                   `json:"was_hijacked"`
	HijackingApp     string                 `json:"hijacking_app,omitempty"`
	Recommendations  []string               `json:"recommendations,omitempty"`
}

// SensitiveDataMatch represents a match of sensitive data
type SensitiveDataMatch struct {
	Type       string           `json:"type"`
	Masked     string           `json:"masked"` // Masked value for display
	Position   int              `json:"position"`
	RiskLevel  PrivacyRiskLevel `json:"risk_level"`
}

// PrivacyAlert represents an alert sent to the user
type PrivacyAlert struct {
	ID           uuid.UUID        `json:"id" db:"id"`
	DeviceID     string           `json:"device_id" db:"device_id"`
	Type         PrivacyEventType `json:"type" db:"type"`
	Severity     PrivacyRiskLevel `json:"severity" db:"severity"`
	Title        string           `json:"title" db:"title"`
	Message      string           `json:"message" db:"message"`
	PackageName  string           `json:"package_name,omitempty" db:"package_name"`
	AppName      string           `json:"app_name,omitempty" db:"app_name"`
	ActionTaken  string           `json:"action_taken,omitempty" db:"action_taken"`
	Acknowledged bool             `json:"acknowledged" db:"acknowledged"`
	CreatedAt    time.Time        `json:"created_at" db:"created_at"`
	AckedAt      *time.Time       `json:"acked_at,omitempty" db:"acked_at"`
}

// PrivacyTrackers contains information about well-known ad trackers with domain info
var PrivacyTrackers = map[string]TrackerInfo{
	"facebook": {
		ID:       "facebook",
		Name:     "Facebook Analytics",
		Company:  "Meta Platforms",
		Category: "social",
		Domains: []string{
			"graph.facebook.com",
			"connect.facebook.net",
			"pixel.facebook.com",
			"an.facebook.com",
			"ads.facebook.com",
		},
		SDKNames:      []string{"com.facebook.appevents", "com.facebook.analytics"},
		Description:   "Facebook's analytics and advertising SDK",
		PrivacyRisk:   PrivacyRiskHigh,
		DataCollected: []string{"device_id", "app_usage", "location", "contacts"},
	},
	"google_ads": {
		ID:       "google_ads",
		Name:     "Google Ads",
		Company:  "Google",
		Category: "advertising",
		Domains: []string{
			"googleads.g.doubleclick.net",
			"pagead2.googlesyndication.com",
			"adservice.google.com",
			"www.googleadservices.com",
		},
		SDKNames:      []string{"com.google.android.gms.ads"},
		Description:   "Google's advertising platform",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "app_usage", "location"},
	},
	"google_analytics": {
		ID:       "google_analytics",
		Name:     "Google Analytics",
		Company:  "Google",
		Category: "analytics",
		Domains: []string{
			"www.google-analytics.com",
			"analytics.google.com",
			"firebase.google.com",
		},
		SDKNames:      []string{"com.google.firebase.analytics"},
		Description:   "Google's analytics platform",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "app_usage", "screen_views"},
	},
	"appsflyer": {
		ID:       "appsflyer",
		Name:     "AppsFlyer",
		Company:  "AppsFlyer",
		Category: "attribution",
		Domains: []string{
			"t.appsflyer.com",
			"conversions.appsflyer.com",
			"launches.appsflyer.com",
		},
		SDKNames:      []string{"com.appsflyer.AppsFlyerLib"},
		Description:   "Mobile attribution and marketing analytics",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "install_source", "app_usage"},
	},
	"adjust": {
		ID:       "adjust",
		Name:     "Adjust",
		Company:  "Adjust GmbH",
		Category: "attribution",
		Domains: []string{
			"app.adjust.com",
			"control.adjust.com",
		},
		SDKNames:      []string{"com.adjust.sdk"},
		Description:   "Mobile measurement and fraud prevention",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "install_source", "app_usage"},
	},
	"mixpanel": {
		ID:       "mixpanel",
		Name:     "Mixpanel",
		Company:  "Mixpanel Inc",
		Category: "analytics",
		Domains: []string{
			"api.mixpanel.com",
			"decide.mixpanel.com",
		},
		SDKNames:      []string{"com.mixpanel.android.mpmetrics"},
		Description:   "Product analytics platform",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "app_usage", "user_actions"},
	},
	"amplitude": {
		ID:       "amplitude",
		Name:     "Amplitude",
		Company:  "Amplitude Inc",
		Category: "analytics",
		Domains: []string{
			"api.amplitude.com",
			"api2.amplitude.com",
		},
		SDKNames:      []string{"com.amplitude.android.sdk"},
		Description:   "Product analytics platform",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "app_usage", "user_actions"},
	},
	"crashlytics": {
		ID:       "crashlytics",
		Name:     "Firebase Crashlytics",
		Company:  "Google",
		Category: "crash_reporting",
		Domains: []string{
			"firebase-settings.crashlytics.com",
			"api.crashlytics.com",
		},
		SDKNames:      []string{"com.google.firebase.crashlytics"},
		Description:   "Crash reporting and analysis",
		PrivacyRisk:   PrivacyRiskLow,
		DataCollected: []string{"device_info", "crash_logs"},
	},
	"branch": {
		ID:       "branch",
		Name:     "Branch",
		Company:  "Branch Metrics",
		Category: "attribution",
		Domains: []string{
			"api.branch.io",
			"api2.branch.io",
		},
		SDKNames:      []string{"io.branch.sdk"},
		Description:   "Deep linking and attribution",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "referrer", "app_usage"},
	},
	"mopub": {
		ID:       "mopub",
		Name:     "MoPub",
		Company:  "Twitter",
		Category: "advertising",
		Domains: []string{
			"ads.mopub.com",
			"mopub.com",
		},
		SDKNames:      []string{"com.mopub.mobileads"},
		Description:   "Mobile advertising platform",
		PrivacyRisk:   PrivacyRiskHigh,
		DataCollected: []string{"device_id", "location", "app_usage"},
	},
	"unity_ads": {
		ID:       "unity_ads",
		Name:     "Unity Ads",
		Company:  "Unity Technologies",
		Category: "advertising",
		Domains: []string{
			"unityads.unity3d.com",
			"auction.unityads.unity3d.com",
		},
		SDKNames:      []string{"com.unity3d.ads"},
		Description:   "Unity's mobile advertising network",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "app_usage"},
	},
	"ironsource": {
		ID:       "ironsource",
		Name:     "ironSource",
		Company:  "Unity Technologies",
		Category: "advertising",
		Domains: []string{
			"outcome-ssp.supersonicads.com",
			"init.supersonicads.com",
		},
		SDKNames:      []string{"com.ironsource.mediationsdk"},
		Description:   "Mobile advertising and mediation platform",
		PrivacyRisk:   PrivacyRiskMedium,
		DataCollected: []string{"device_id", "app_usage"},
	},
}

// SensitivePatterns defines patterns for detecting sensitive data
var SensitivePatterns = []SensitiveDataPattern{
	{
		Type:        "credit_card",
		Pattern:     `\b(?:\d{4}[- ]?){3}\d{4}\b`,
		Description: "Credit card number",
		RiskLevel:   PrivacyRiskCritical,
	},
	{
		Type:        "ssn",
		Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
		Description: "Social Security Number",
		RiskLevel:   PrivacyRiskCritical,
	},
	{
		Type:        "phone",
		Pattern:     `\b(?:\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b`,
		Description: "Phone number",
		RiskLevel:   PrivacyRiskMedium,
	},
	{
		Type:        "email",
		Pattern:     `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		Description: "Email address",
		RiskLevel:   PrivacyRiskMedium,
	},
	{
		Type:        "password",
		Pattern:     `(?i)(?:password|passwd|pwd|secret|token|api.?key)[:=]\s*\S+`,
		Description: "Password or secret",
		RiskLevel:   PrivacyRiskCritical,
	},
	{
		Type:        "crypto_wallet",
		Pattern:     `\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b`,
		Description: "Cryptocurrency wallet address",
		RiskLevel:   PrivacyRiskHigh,
	},
	{
		Type:        "ip_address",
		Pattern:     `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
		Description: "IP address",
		RiskLevel:   PrivacyRiskLow,
	},
}
