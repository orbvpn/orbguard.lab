package models

import (
	"time"

	"github.com/google/uuid"
)

// DesktopPlatform represents the operating system platform for desktop security
type DesktopPlatform string

const (
	DesktopPlatformMacOS   DesktopPlatform = "macos"
	DesktopPlatformWindows DesktopPlatform = "windows"
	DesktopPlatformLinux   DesktopPlatform = "linux"
)

// PersistenceType represents the type of persistence mechanism
type PersistenceType string

const (
	// macOS persistence types
	PersistenceLaunchAgent         PersistenceType = "launch_agent"
	PersistenceLaunchDaemon        PersistenceType = "launch_daemon"
	PersistenceLoginItem           PersistenceType = "login_item"
	PersistenceKernelExtension     PersistenceType = "kernel_extension"
	PersistenceSystemExtension     PersistenceType = "system_extension"
	PersistenceBrowserExtension    PersistenceType = "browser_extension"
	PersistenceCronJob             PersistenceType = "cron_job"
	PersistenceAuthorizationPlugin PersistenceType = "authorization_plugin"
	PersistenceDirectoryService    PersistenceType = "directory_service"
	PersistenceSpotlightImporter   PersistenceType = "spotlight_importer"
	PersistenceQuickLookPlugin     PersistenceType = "quicklook_plugin"
	PersistenceScreenSaver         PersistenceType = "screensaver"
	PersistenceShellConfig         PersistenceType = "shell_config"
	PersistencePeriodicScript      PersistenceType = "periodic_script"
	PersistenceAtJob               PersistenceType = "at_job"
	PersistenceEmond               PersistenceType = "emond"

	// Windows persistence types
	PersistenceRegistryRun        PersistenceType = "registry_run"
	PersistenceRegistryRunOnce    PersistenceType = "registry_runonce"
	PersistenceScheduledTask      PersistenceType = "scheduled_task"
	PersistenceStartupFolder      PersistenceType = "startup_folder"
	PersistenceService            PersistenceType = "service"
	PersistenceWMISubscription    PersistenceType = "wmi_subscription"
	PersistenceAppInit            PersistenceType = "appinit_dlls"
	PersistenceImageFileExecution PersistenceType = "image_file_execution"
	PersistencePrintMonitor       PersistenceType = "print_monitor"
	PersistenceLSAPackage         PersistenceType = "lsa_package"
	PersistenceWinlogon           PersistenceType = "winlogon"
	PersistenceNetshHelper        PersistenceType = "netsh_helper"
	PersistenceCOMHijack          PersistenceType = "com_hijack"
	PersistenceBITSJob            PersistenceType = "bits_job"

	// Linux persistence types
	PersistenceSystemdService  PersistenceType = "systemd_service"
	PersistenceSystemdTimer    PersistenceType = "systemd_timer"
	PersistenceInitD           PersistenceType = "init_d"
	PersistenceRcLocal         PersistenceType = "rc_local"
	PersistenceCrontab         PersistenceType = "crontab"
	PersistenceAnacron         PersistenceType = "anacron"
	PersistenceXDGAutostart    PersistenceType = "xdg_autostart"
	PersistenceBashProfile     PersistenceType = "bash_profile"
	PersistenceModprobe        PersistenceType = "modprobe"
	PersistenceUdevRule        PersistenceType = "udev_rule"
	PersistenceMotd            PersistenceType = "motd"
	PersistenceSSHRC           PersistenceType = "sshrc"
	PersistenceAPTHook         PersistenceType = "apt_hook"
	PersistencePackageManager  PersistenceType = "package_manager"
)

// PersistenceRiskLevel represents the risk level of a persistence item
type PersistenceRiskLevel string

const (
	PersistenceRiskCritical PersistenceRiskLevel = "critical"
	PersistenceRiskHigh     PersistenceRiskLevel = "high"
	PersistenceRiskMedium   PersistenceRiskLevel = "medium"
	PersistenceRiskLow      PersistenceRiskLevel = "low"
	PersistenceRiskInfo     PersistenceRiskLevel = "info"
	PersistenceRiskClean    PersistenceRiskLevel = "clean"
)

// CodeSigningStatus represents the code signing verification status
type CodeSigningStatus string

const (
	CodeSigningValid       CodeSigningStatus = "valid"
	CodeSigningInvalid     CodeSigningStatus = "invalid"
	CodeSigningNotSigned   CodeSigningStatus = "not_signed"
	CodeSigningAdHoc       CodeSigningStatus = "ad_hoc"
	CodeSigningExpired     CodeSigningStatus = "expired"
	CodeSigningRevoked     CodeSigningStatus = "revoked"
	CodeSigningUnknown     CodeSigningStatus = "unknown"
	CodeSigningAppleSystem CodeSigningStatus = "apple_system"
	CodeSigningAppleStore  CodeSigningStatus = "apple_store"
	CodeSigningDeveloperID CodeSigningStatus = "developer_id"
	CodeSigningMicrosoft   CodeSigningStatus = "microsoft"
)

// PersistenceItem represents a single persistence mechanism found on the system
type PersistenceItem struct {
	ID          uuid.UUID           `json:"id"`
	Platform    DesktopPlatform     `json:"platform"`
	Type        PersistenceType     `json:"type"`
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	Command     string              `json:"command,omitempty"`
	Arguments   []string            `json:"arguments,omitempty"`
	Scope       string              `json:"scope"` // user, system, global

	// Binary info
	BinaryPath  string            `json:"binary_path,omitempty"`
	BinaryHash  string            `json:"binary_hash,omitempty"` // SHA256
	BinarySize  int64             `json:"binary_size,omitempty"`
	BinaryOwner string            `json:"binary_owner,omitempty"`

	// Code signing
	CodeSigning     CodeSigningStatus `json:"code_signing"`
	SigningTeamID   string            `json:"signing_team_id,omitempty"`
	SigningIdentity string            `json:"signing_identity,omitempty"`
	SigningAuthority string           `json:"signing_authority,omitempty"`

	// Risk assessment
	RiskLevel   PersistenceRiskLevel `json:"risk_level"`
	RiskReasons []string             `json:"risk_reasons,omitempty"`
	IsKnownGood bool                 `json:"is_known_good"`
	IsKnownBad  bool                 `json:"is_known_bad"`

	// VirusTotal
	VTDetections   int     `json:"vt_detections,omitempty"`
	VTTotalEngines int     `json:"vt_total_engines,omitempty"`
	VTLink         string  `json:"vt_link,omitempty"`
	VTLastScan     *time.Time `json:"vt_last_scan,omitempty"`

	// Metadata
	Enabled     bool       `json:"enabled"`
	RunAtLoad   bool       `json:"run_at_load,omitempty"`
	KeepAlive   bool       `json:"keep_alive,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`
	Description string     `json:"description,omitempty"`

	// Raw data
	RawContent  string `json:"raw_content,omitempty"` // plist, registry, etc.

	FoundAt time.Time `json:"found_at"`
}

// PersistenceLocation represents a location to scan for persistence
type PersistenceLocation struct {
	ID          uuid.UUID       `json:"id"`
	Platform    DesktopPlatform `json:"platform"`
	Type        PersistenceType `json:"type"`
	Path        string          `json:"path"`
	Description string          `json:"description"`
	Scope       string          `json:"scope"` // user, system
	FilePattern string          `json:"file_pattern,omitempty"` // glob pattern
	Priority    int             `json:"priority"` // scan priority
	RiskFactor  float64         `json:"risk_factor"` // base risk multiplier
}

// PersistenceScanResult represents the results of a persistence scan
type PersistenceScanResult struct {
	ID          uuid.UUID          `json:"id"`
	Platform    DesktopPlatform    `json:"platform"`
	DeviceID    string             `json:"device_id,omitempty"`
	Hostname    string             `json:"hostname,omitempty"`
	OSVersion   string             `json:"os_version,omitempty"`

	// Results
	Items         []PersistenceItem `json:"items"`
	TotalItems    int               `json:"total_items"`
	CriticalItems int               `json:"critical_items"`
	HighRiskItems int               `json:"high_risk_items"`
	MediumRiskItems int             `json:"medium_risk_items"`
	LowRiskItems  int               `json:"low_risk_items"`
	CleanItems    int               `json:"clean_items"`

	// Summary
	OverallRisk   PersistenceRiskLevel `json:"overall_risk"`
	RiskScore     float64              `json:"risk_score"` // 0-100
	Recommendations []string           `json:"recommendations,omitempty"`

	// Timing
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Duration    string     `json:"duration,omitempty"`

	// Errors
	Errors []string `json:"errors,omitempty"`
}

// NetworkConnection represents a network connection
type NetworkConnection struct {
	ID            uuid.UUID `json:"id"`
	Protocol      string    `json:"protocol"` // tcp, udp, tcp6, udp6
	LocalAddress  string    `json:"local_address"`
	LocalPort     int       `json:"local_port"`
	RemoteAddress string    `json:"remote_address"`
	RemotePort    int       `json:"remote_port"`
	State         string    `json:"state"` // ESTABLISHED, LISTEN, etc.

	// Process info
	ProcessID   int    `json:"process_id"`
	ProcessName string `json:"process_name"`
	ProcessPath string `json:"process_path,omitempty"`
	ProcessUser string `json:"process_user,omitempty"`

	// Code signing
	CodeSigning CodeSigningStatus `json:"code_signing,omitempty"`

	// Threat intel
	RemoteHostname  string   `json:"remote_hostname,omitempty"`
	RemoteCountry   string   `json:"remote_country,omitempty"`
	RemoteASN       string   `json:"remote_asn,omitempty"`
	IsKnownBad      bool     `json:"is_known_bad"`
	IsCnC           bool     `json:"is_cnc"`       // Command & Control
	ThreatTags      []string `json:"threat_tags,omitempty"`
	ThreatConfidence float64 `json:"threat_confidence,omitempty"`

	// Traffic stats
	BytesSent     int64 `json:"bytes_sent,omitempty"`
	BytesReceived int64 `json:"bytes_received,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID          uuid.UUID       `json:"id"`
	Platform    DesktopPlatform `json:"platform"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`

	// Rule definition
	Action      string   `json:"action"` // allow, block
	Direction   string   `json:"direction"` // inbound, outbound, both
	Protocol    string   `json:"protocol,omitempty"` // tcp, udp, any

	// Source
	SourceAddress string `json:"source_address,omitempty"` // IP, CIDR, any
	SourcePort    string `json:"source_port,omitempty"`    // port, range, any

	// Destination
	DestAddress string `json:"dest_address,omitempty"`
	DestPort    string `json:"dest_port,omitempty"`
	DestDomain  string `json:"dest_domain,omitempty"` // for domain-based blocking

	// Process
	ProcessPath string `json:"process_path,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// Metadata
	Enabled   bool      `json:"enabled"`
	Priority  int       `json:"priority"`
	IsSystem  bool      `json:"is_system"` // System-managed rule
	IsFromIOC bool      `json:"is_from_ioc"` // Auto-generated from IOC feed
	IOCSource string    `json:"ioc_source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Stats
	HitCount    int64      `json:"hit_count"`
	LastHit     *time.Time `json:"last_hit,omitempty"`
}

// NetworkMonitorConfig represents network monitor configuration
type NetworkMonitorConfig struct {
	Enabled           bool     `json:"enabled"`
	MonitorOutbound   bool     `json:"monitor_outbound"`
	MonitorInbound    bool     `json:"monitor_inbound"`
	BlockUnknown      bool     `json:"block_unknown"` // Block unknown connections
	AlertOnBadIP      bool     `json:"alert_on_bad_ip"`
	AlertOnCnC        bool     `json:"alert_on_cnc"`
	WhitelistApple    bool     `json:"whitelist_apple"` // Auto-allow Apple signed
	WhitelistMicrosoft bool    `json:"whitelist_microsoft"`
	LogConnections    bool     `json:"log_connections"`
	ExcludedProcesses []string `json:"excluded_processes,omitempty"`
	ExcludedPorts     []int    `json:"excluded_ports,omitempty"`
}

// BrowserExtension represents a browser extension
type BrowserExtension struct {
	ID          uuid.UUID `json:"id"`
	Browser     string    `json:"browser"` // chrome, firefox, safari, edge
	ExtensionID string    `json:"extension_id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	Author      string    `json:"author,omitempty"`
	Homepage    string    `json:"homepage,omitempty"`

	// Permissions
	Permissions    []string `json:"permissions,omitempty"`
	HostPermissions []string `json:"host_permissions,omitempty"`

	// Risk assessment
	RiskLevel      PersistenceRiskLevel `json:"risk_level"`
	RiskReasons    []string             `json:"risk_reasons,omitempty"`
	IsKnownMalware bool                 `json:"is_known_malware"`
	IsFromStore    bool                 `json:"is_from_store"`

	// Paths
	InstallPath string `json:"install_path"`
	ProfilePath string `json:"profile_path,omitempty"`

	Enabled   bool      `json:"enabled"`
	FoundAt   time.Time `json:"found_at"`
}

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line,omitempty"`
	User        string    `json:"user"`

	// Resource usage
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryRSS     int64   `json:"memory_rss"`

	// Code signing
	CodeSigning     CodeSigningStatus `json:"code_signing"`
	SigningIdentity string            `json:"signing_identity,omitempty"`

	// Network
	NetworkConnections int `json:"network_connections"`
	ListeningPorts     []int `json:"listening_ports,omitempty"`

	// Risk
	RiskLevel   PersistenceRiskLevel `json:"risk_level,omitempty"`
	IsKnownGood bool                 `json:"is_known_good"`
	IsKnownBad  bool                 `json:"is_known_bad"`

	StartTime time.Time `json:"start_time"`
}

// DesktopSecurityScan represents a comprehensive desktop security scan
type DesktopSecurityScan struct {
	ID          uuid.UUID       `json:"id"`
	Platform    DesktopPlatform `json:"platform"`
	DeviceID    string          `json:"device_id"`
	Hostname    string          `json:"hostname"`
	OSVersion   string          `json:"os_version"`

	// Results
	PersistenceScan   *PersistenceScanResult `json:"persistence_scan,omitempty"`
	BrowserExtensions []BrowserExtension     `json:"browser_extensions,omitempty"`
	NetworkConnections []NetworkConnection   `json:"network_connections,omitempty"`
	SuspiciousProcesses []ProcessInfo        `json:"suspicious_processes,omitempty"`

	// Summary
	OverallRisk     PersistenceRiskLevel `json:"overall_risk"`
	RiskScore       float64              `json:"risk_score"`
	CriticalFindings int                 `json:"critical_findings"`
	Recommendations []string             `json:"recommendations,omitempty"`

	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// KnownGoodHash represents a known good binary hash
type KnownGoodHash struct {
	Hash        string          `json:"hash"` // SHA256
	Name        string          `json:"name"`
	Publisher   string          `json:"publisher"`
	Version     string          `json:"version,omitempty"`
	Platform    DesktopPlatform `json:"platform"`
	Source      string          `json:"source"` // apple, microsoft, homebrew, etc.
	VerifiedAt  time.Time       `json:"verified_at"`
}

// KnownBadHash represents a known malicious binary hash
type KnownBadHash struct {
	Hash        string          `json:"hash"` // SHA256
	Name        string          `json:"name,omitempty"`
	MalwareFamily string        `json:"malware_family,omitempty"`
	Platform    DesktopPlatform `json:"platform"`
	Source      string          `json:"source"` // VT, internal, etc.
	Severity    string          `json:"severity"`
	FirstSeen   time.Time       `json:"first_seen"`
}

// CalculateRiskScore calculates the risk score for a persistence scan
func (r *PersistenceScanResult) CalculateRiskScore() {
	var score float64

	// Critical items - 25 points each
	score += float64(r.CriticalItems) * 25.0

	// High risk items - 15 points each
	score += float64(r.HighRiskItems) * 15.0

	// Medium risk items - 5 points each
	score += float64(r.MediumRiskItems) * 5.0

	// Low risk items - 1 point each
	score += float64(r.LowRiskItems) * 1.0

	// Cap at 100
	if score > 100 {
		score = 100
	}

	r.RiskScore = score

	// Set overall risk level
	switch {
	case r.CriticalItems > 0 || score >= 75:
		r.OverallRisk = PersistenceRiskCritical
	case r.HighRiskItems > 0 || score >= 50:
		r.OverallRisk = PersistenceRiskHigh
	case r.MediumRiskItems > 0 || score >= 25:
		r.OverallRisk = PersistenceRiskMedium
	case score > 0:
		r.OverallRisk = PersistenceRiskLow
	default:
		r.OverallRisk = PersistenceRiskClean
	}
}
