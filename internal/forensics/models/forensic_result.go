package models

import (
	"time"

	"github.com/google/uuid"
)

// ForensicScanType represents the type of forensic scan
type ForensicScanType string

const (
	ForensicScanTypeShutdownLog ForensicScanType = "shutdown_log"
	ForensicScanTypeBackup      ForensicScanType = "backup"
	ForensicScanTypeSysdiagnose ForensicScanType = "sysdiagnose"
	ForensicScanTypeDataUsage   ForensicScanType = "data_usage"
	ForensicScanTypeLogcat      ForensicScanType = "logcat"
	ForensicScanTypePackages    ForensicScanType = "packages"
	ForensicScanTypeFull        ForensicScanType = "full"
)

// ForensicSeverity represents the severity of forensic findings
type ForensicSeverity string

const (
	ForensicSeverityCritical ForensicSeverity = "critical"
	ForensicSeverityHigh     ForensicSeverity = "high"
	ForensicSeverityMedium   ForensicSeverity = "medium"
	ForensicSeverityLow      ForensicSeverity = "low"
	ForensicSeverityInfo     ForensicSeverity = "info"
)

// InfectionType represents the type of infection detected
type InfectionType string

const (
	InfectionTypePegasus    InfectionType = "pegasus"
	InfectionTypePredator   InfectionType = "predator"
	InfectionTypeReign      InfectionType = "reign"
	InfectionTypeCandiru    InfectionType = "candiru"
	InfectionTypeQuaDream   InfectionType = "quadream"
	InfectionTypeUnknownAPT InfectionType = "unknown_apt"
	InfectionTypeStalkerware InfectionType = "stalkerware"
	InfectionTypeGenericSpyware InfectionType = "generic_spyware"
)

// ForensicResult represents the result of a forensic scan
type ForensicResult struct {
	ID              uuid.UUID          `json:"id"`
	DeviceID        string             `json:"device_id"`
	Platform        string             `json:"platform"` // ios, android
	ScanType        ForensicScanType   `json:"scan_type"`
	StartedAt       time.Time          `json:"started_at"`
	CompletedAt     time.Time          `json:"completed_at"`
	Duration        time.Duration      `json:"duration_ms"`
	TotalAnomalies  int                `json:"total_anomalies"`
	CriticalCount   int                `json:"critical_count"`
	HighCount       int                `json:"high_count"`
	MediumCount     int                `json:"medium_count"`
	LowCount        int                `json:"low_count"`
	Anomalies       []Anomaly          `json:"anomalies"`
	Timeline        []TimelineEvent    `json:"timeline,omitempty"`
	InfectionLikelihood float64        `json:"infection_likelihood"` // 0.0 - 1.0
	DetectedThreats []DetectedThreat   `json:"detected_threats,omitempty"`
	Recommendations []string           `json:"recommendations"`
	RawData         map[string]any     `json:"raw_data,omitempty"`
}

// Anomaly represents a detected forensic anomaly
type Anomaly struct {
	ID              string           `json:"id"`
	Type            AnomalyType      `json:"type"`
	Severity        ForensicSeverity `json:"severity"`
	Confidence      float64          `json:"confidence"` // 0.0 - 1.0
	Title           string           `json:"title"`
	Description     string           `json:"description"`
	Path            string           `json:"path,omitempty"`
	ProcessName     string           `json:"process_name,omitempty"`
	ProcessPID      int              `json:"process_pid,omitempty"`
	Timestamp       *time.Time       `json:"timestamp,omitempty"`
	Duration        *time.Duration   `json:"duration_ms,omitempty"`
	IOCMatch        *IOCMatch        `json:"ioc_match,omitempty"`
	MITRETechniques []string         `json:"mitre_techniques,omitempty"`
	RelatedEvents   []string         `json:"related_events,omitempty"`
	Evidence        map[string]any   `json:"evidence,omitempty"`
}

// AnomalyType represents the type of anomaly detected
type AnomalyType string

const (
	AnomalyTypeStickyProcess    AnomalyType = "sticky_process"
	AnomalyTypePathAnomaly      AnomalyType = "path_anomaly"
	AnomalyTypeNetworkAnomaly   AnomalyType = "network_anomaly"
	AnomalyTypeFileAnomaly      AnomalyType = "file_anomaly"
	AnomalyTypeProcessAnomaly   AnomalyType = "process_anomaly"
	AnomalyTypeBootAnomaly      AnomalyType = "boot_anomaly"
	AnomalyTypeCrashAnomaly     AnomalyType = "crash_anomaly"
	AnomalyTypeBackupAnomaly    AnomalyType = "backup_anomaly"
	AnomalyTypePermissionAnomaly AnomalyType = "permission_anomaly"
	AnomalyTypeDataExfiltration AnomalyType = "data_exfiltration"
	AnomalyTypeIOCMatch         AnomalyType = "ioc_match"
)

// IOCMatch represents a match against known IOCs
type IOCMatch struct {
	IOCType     string   `json:"ioc_type"`
	Value       string   `json:"value"`
	Source      string   `json:"source"` // citizenlab, amnesty_mvt, etc.
	Campaign    string   `json:"campaign,omitempty"`
	Attribution string   `json:"attribution,omitempty"`
	FirstSeen   string   `json:"first_seen,omitempty"`
	References  []string `json:"references,omitempty"`
}

// DetectedThreat represents a detected threat/infection
type DetectedThreat struct {
	Type            InfectionType    `json:"type"`
	Name            string           `json:"name"`
	Confidence      float64          `json:"confidence"` // 0.0 - 1.0
	Severity        ForensicSeverity `json:"severity"`
	Description     string           `json:"description"`
	Attribution     string           `json:"attribution,omitempty"`
	FirstDetected   *time.Time       `json:"first_detected,omitempty"`
	LastActive      *time.Time       `json:"last_active,omitempty"`
	AnomalyIDs      []string         `json:"anomaly_ids"`
	MITRETechniques []string         `json:"mitre_techniques"`
	IOCs            []IOCMatch       `json:"iocs,omitempty"`
	Remediation     []string         `json:"remediation"`
}

// ShutdownLogEntry represents an entry from iOS shutdown.log
type ShutdownLogEntry struct {
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"` // client, shutdown, reboot, etc.
	ProcessName    string    `json:"process_name,omitempty"`
	PID            int       `json:"pid,omitempty"`
	Path           string    `json:"path,omitempty"`
	DelaySeconds   float64   `json:"delay_seconds,omitempty"`
	WasResponsive  bool      `json:"was_responsive"`
	RawLine        string    `json:"raw_line"`
}

// StickyProcess represents a process that persisted across reboots
type StickyProcess struct {
	ProcessName     string    `json:"process_name"`
	Path            string    `json:"path"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	RebootCount     int       `json:"reboot_count"`
	TotalDelayMs    int64     `json:"total_delay_ms"`
	AvgDelayMs      int64     `json:"avg_delay_ms"`
	IsSuspicious    bool      `json:"is_suspicious"`
	SuspiciousScore float64   `json:"suspicious_score"`
	Reason          string    `json:"reason,omitempty"`
}

// BackupFileInfo represents metadata about a file in an iOS backup
type BackupFileInfo struct {
	RelativePath   string    `json:"relative_path"`
	Domain         string    `json:"domain"`
	FileID         string    `json:"file_id"`
	Size           int64     `json:"size"`
	ModifiedAt     time.Time `json:"modified_at"`
	CreatedAt      time.Time `json:"created_at,omitempty"`
	Permissions    string    `json:"permissions,omitempty"`
	IsEncrypted    bool      `json:"is_encrypted"`
	IsSuspicious   bool      `json:"is_suspicious"`
	SuspiciousScore float64  `json:"suspicious_score,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

// DataUsageEntry represents network usage data from DataUsage.sqlite
type DataUsageEntry struct {
	BundleID       string    `json:"bundle_id"`
	ProcessName    string    `json:"process_name"`
	FirstTimestamp time.Time `json:"first_timestamp"`
	LastTimestamp  time.Time `json:"last_timestamp"`
	WiFiIn         int64     `json:"wifi_in"`
	WiFiOut        int64     `json:"wifi_out"`
	CellularIn     int64     `json:"cellular_in"`
	CellularOut    int64     `json:"cellular_out"`
	TotalBytes     int64     `json:"total_bytes"`
	IsSuspicious   bool      `json:"is_suspicious"`
	SuspiciousScore float64  `json:"suspicious_score,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

// AndroidPackageInfo represents info about an installed Android package
type AndroidPackageInfo struct {
	PackageName    string    `json:"package_name"`
	AppName        string    `json:"app_name"`
	VersionCode    int       `json:"version_code"`
	VersionName    string    `json:"version_name"`
	InstalledAt    time.Time `json:"installed_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Installer      string    `json:"installer"`
	IsSystem       bool      `json:"is_system"`
	IsDisabled     bool      `json:"is_disabled"`
	Permissions    []string  `json:"permissions"`
	Signature      string    `json:"signature,omitempty"`
	IsSuspicious   bool      `json:"is_suspicious"`
	SuspiciousScore float64  `json:"suspicious_score,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

// LogcatEntry represents a parsed logcat entry
type LogcatEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         int       `json:"pid"`
	TID         int       `json:"tid"`
	Priority    string    `json:"priority"` // V, D, I, W, E, F
	Tag         string    `json:"tag"`
	Message     string    `json:"message"`
	IsSuspicious bool     `json:"is_suspicious"`
	Reason      string    `json:"reason,omitempty"`
}

// ForensicScanRequest represents a request to perform forensic scan
type ForensicScanRequest struct {
	DeviceID        string            `json:"device_id"`
	Platform        string            `json:"platform"`
	ScanTypes       []ForensicScanType `json:"scan_types,omitempty"`
	ShutdownLogData []byte            `json:"shutdown_log_data,omitempty"`
	BackupPath      string            `json:"backup_path,omitempty"`
	SysdiagnosePath string            `json:"sysdiagnose_path,omitempty"`
	DataUsagePath   string            `json:"data_usage_path,omitempty"`
	LogcatData      []byte            `json:"logcat_data,omitempty"`
	PackageList     []byte            `json:"package_list,omitempty"`
	IncludeTimeline bool              `json:"include_timeline"`
}

// NewForensicResult creates a new forensic result
func NewForensicResult(deviceID, platform string, scanType ForensicScanType) *ForensicResult {
	return &ForensicResult{
		ID:              uuid.New(),
		DeviceID:        deviceID,
		Platform:        platform,
		ScanType:        scanType,
		StartedAt:       time.Now(),
		Anomalies:       make([]Anomaly, 0),
		Timeline:        make([]TimelineEvent, 0),
		DetectedThreats: make([]DetectedThreat, 0),
		Recommendations: make([]string, 0),
		RawData:         make(map[string]any),
	}
}

// Complete finalizes the forensic result
func (r *ForensicResult) Complete() {
	r.CompletedAt = time.Now()
	r.Duration = r.CompletedAt.Sub(r.StartedAt)

	// Count anomalies by severity
	r.TotalAnomalies = len(r.Anomalies)
	for _, a := range r.Anomalies {
		switch a.Severity {
		case ForensicSeverityCritical:
			r.CriticalCount++
		case ForensicSeverityHigh:
			r.HighCount++
		case ForensicSeverityMedium:
			r.MediumCount++
		case ForensicSeverityLow:
			r.LowCount++
		}
	}

	// Calculate infection likelihood
	r.calculateInfectionLikelihood()

	// Generate recommendations
	r.generateRecommendations()
}

// calculateInfectionLikelihood calculates overall infection probability
func (r *ForensicResult) calculateInfectionLikelihood() {
	if r.TotalAnomalies == 0 {
		r.InfectionLikelihood = 0.0
		return
	}

	// Weight by severity and confidence
	totalScore := 0.0
	for _, a := range r.Anomalies {
		weight := 0.0
		switch a.Severity {
		case ForensicSeverityCritical:
			weight = 1.0
		case ForensicSeverityHigh:
			weight = 0.7
		case ForensicSeverityMedium:
			weight = 0.4
		case ForensicSeverityLow:
			weight = 0.2
		}
		totalScore += weight * a.Confidence
	}

	// Normalize (sigmoid-like function)
	r.InfectionLikelihood = totalScore / (totalScore + 2.0)
	if r.InfectionLikelihood > 1.0 {
		r.InfectionLikelihood = 1.0
	}
}

// generateRecommendations generates recommendations based on findings
func (r *ForensicResult) generateRecommendations() {
	if r.InfectionLikelihood >= 0.8 {
		r.Recommendations = append(r.Recommendations,
			"CRITICAL: High likelihood of sophisticated spyware infection detected",
			"Immediately disconnect device from network",
			"Do NOT factory reset - preserve evidence for forensic analysis",
			"Contact a security professional or digital forensics expert",
			"If targeted individual (journalist, activist, etc.), contact Citizen Lab or Access Now",
		)
	} else if r.InfectionLikelihood >= 0.5 {
		r.Recommendations = append(r.Recommendations,
			"HIGH: Suspicious activity detected that warrants investigation",
			"Backup device data securely (encrypted)",
			"Review all installed applications and permissions",
			"Consider factory reset after backup",
			"Enable automatic security updates",
		)
	} else if r.InfectionLikelihood >= 0.2 {
		r.Recommendations = append(r.Recommendations,
			"MODERATE: Some anomalies detected, may be benign",
			"Review flagged items for legitimacy",
			"Ensure device is running latest security patches",
			"Review app permissions and remove unused apps",
		)
	} else {
		r.Recommendations = append(r.Recommendations,
			"No significant threats detected",
			"Continue regular security hygiene practices",
			"Keep device updated with latest security patches",
		)
	}

	// Add specific recommendations based on detected threats
	for _, threat := range r.DetectedThreats {
		switch threat.Type {
		case InfectionTypePegasus:
			r.Recommendations = append(r.Recommendations,
				"PEGASUS INDICATORS DETECTED - This is a state-sponsored spyware",
				"Contact Amnesty Tech or Citizen Lab for assistance",
			)
		case InfectionTypePredator:
			r.Recommendations = append(r.Recommendations,
				"PREDATOR INDICATORS DETECTED - Intellexa/Cytrox spyware",
				"Seek professional forensic analysis immediately",
			)
		case InfectionTypeStalkerware:
			r.Recommendations = append(r.Recommendations,
				"STALKERWARE DETECTED - Someone may be monitoring your device",
				"If you feel unsafe, contact local authorities or domestic violence hotline",
				"Do NOT confront the installer until you have a safety plan",
			)
		}
	}
}

// AddAnomaly adds an anomaly to the result
func (r *ForensicResult) AddAnomaly(anomaly Anomaly) {
	if anomaly.ID == "" {
		anomaly.ID = uuid.New().String()
	}
	r.Anomalies = append(r.Anomalies, anomaly)
}

// AddThreat adds a detected threat to the result
func (r *ForensicResult) AddThreat(threat DetectedThreat) {
	r.DetectedThreats = append(r.DetectedThreats, threat)
}
