package models

import (
	"time"
)

// AnalyticsTimeRange represents a time range for analytics queries
type AnalyticsTimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ThreatAnalytics contains aggregated threat analytics
type ThreatAnalytics struct {
	TimeRange       AnalyticsTimeRange    `json:"time_range"`
	GeneratedAt     time.Time             `json:"generated_at"`

	// Summary metrics
	Summary         *AnalyticsSummary     `json:"summary"`

	// Trend data
	TrendData       []TrendDataPoint      `json:"trend_data,omitempty"`

	// Distribution data
	BySeverity      []CategoryCount       `json:"by_severity,omitempty"`
	ByType          []CategoryCount       `json:"by_type,omitempty"`
	ByPlatform      []CategoryCount       `json:"by_platform,omitempty"`
	BySource        []CategoryCount       `json:"by_source,omitempty"`
	ByCampaign      []CategoryCount       `json:"by_campaign,omitempty"`
	ByCountry       []CategoryCount       `json:"by_country,omitempty"`

	// Top indicators
	TopIndicators   []AnalyticsIndicatorSummary    `json:"top_indicators,omitempty"`
	TopDomains      []DomainSummary                `json:"top_domains,omitempty"`
	TopIPs          []IPSummary                    `json:"top_ips,omitempty"`

	// Campaign insights
	ActiveCampaigns []CampaignInsight     `json:"active_campaigns,omitempty"`

	// Threat actors
	ThreatActors    []ThreatActorSummary  `json:"threat_actors,omitempty"`

	// MITRE ATT&CK
	MitreTopTechniques []MitreTechniqueSummary `json:"mitre_top_techniques,omitempty"`
}

// AnalyticsSummary contains summary metrics
type AnalyticsSummary struct {
	TotalIndicators     int64   `json:"total_indicators"`
	NewIndicators       int64   `json:"new_indicators"`
	ActiveIndicators    int64   `json:"active_indicators"`
	ExpiredIndicators   int64   `json:"expired_indicators"`

	TotalCampaigns      int64   `json:"total_campaigns"`
	ActiveCampaigns     int64   `json:"active_campaigns"`

	CriticalThreats     int64   `json:"critical_threats"`
	HighThreats         int64   `json:"high_threats"`
	MediumThreats       int64   `json:"medium_threats"`
	LowThreats          int64   `json:"low_threats"`

	PegasusIndicators   int64   `json:"pegasus_indicators"`
	MobileThreats       int64   `json:"mobile_threats"`

	BlockedDomains      int64   `json:"blocked_domains"`
	BlockedIPs          int64   `json:"blocked_ips"`

	DetectionRate       float64 `json:"detection_rate"`
	FalsePositiveRate   float64 `json:"false_positive_rate"`

	ChangeFromPrevious  *ChangeMetrics `json:"change_from_previous,omitempty"`
}

// ChangeMetrics shows change from previous period
type ChangeMetrics struct {
	IndicatorsChange    float64 `json:"indicators_change_pct"`
	CampaignsChange     float64 `json:"campaigns_change_pct"`
	CriticalChange      float64 `json:"critical_change_pct"`
	Direction           string  `json:"direction"` // up, down, stable
}

// TrendDataPoint represents a single point in trend data
type TrendDataPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	Count        int64     `json:"count"`
	Critical     int64     `json:"critical,omitempty"`
	High         int64     `json:"high,omitempty"`
	Medium       int64     `json:"medium,omitempty"`
	Low          int64     `json:"low,omitempty"`
}

// CategoryCount represents a count by category
type CategoryCount struct {
	Category    string  `json:"category"`
	Count       int64   `json:"count"`
	Percentage  float64 `json:"percentage"`
	Change      float64 `json:"change,omitempty"` // Change from previous period
}

// AnalyticsIndicatorSummary contains summary info for an indicator in analytics
type AnalyticsIndicatorSummary struct {
	Value       string    `json:"value"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	HitCount    int64     `json:"hit_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Campaign    string    `json:"campaign,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
}

// DomainSummary contains summary info for a domain
type DomainSummary struct {
	Domain      string    `json:"domain"`
	Category    string    `json:"category"`
	HitCount    int64     `json:"hit_count"`
	BlockCount  int64     `json:"block_count"`
	LastSeen    time.Time `json:"last_seen"`
	ThreatTypes []string  `json:"threat_types,omitempty"`
}

// IPSummary contains summary info for an IP
type IPSummary struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	HitCount    int64     `json:"hit_count"`
	BlockCount  int64     `json:"block_count"`
	LastSeen    time.Time `json:"last_seen"`
	ThreatTypes []string  `json:"threat_types,omitempty"`
}

// CampaignInsight contains insights about a campaign
type CampaignInsight struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	IndicatorCount  int64     `json:"indicator_count"`
	NewIndicators   int64     `json:"new_indicators"`
	Severity        string    `json:"severity"`
	TargetSectors   []string  `json:"target_sectors,omitempty"`
	TargetCountries []string  `json:"target_countries,omitempty"`
	FirstSeen       time.Time `json:"first_seen"`
	LastActivity    time.Time `json:"last_activity"`
	MitreTactics    []string  `json:"mitre_tactics,omitempty"`
}

// ThreatActorSummary contains summary info about a threat actor
type ThreatActorSummary struct {
	Name            string   `json:"name"`
	Aliases         []string `json:"aliases,omitempty"`
	Type            string   `json:"type"` // apt, criminal, hacktivist
	Attribution     string   `json:"attribution,omitempty"`
	CampaignCount   int64    `json:"campaign_count"`
	IndicatorCount  int64    `json:"indicator_count"`
	TargetSectors   []string `json:"target_sectors,omitempty"`
	ActiveSince     string   `json:"active_since,omitempty"`
}

// MitreTechniqueSummary contains MITRE ATT&CK technique stats
type MitreTechniqueSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Count       int64  `json:"count"`
	Campaigns   int64  `json:"campaigns"`
}

// AnalyticsReport represents a generated analytics report
type AnalyticsReport struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        ReportType             `json:"type"`
	Format      ReportFormat           `json:"format"`
	Status      AnalyticsReportStatus  `json:"status"`
	TimeRange   AnalyticsTimeRange     `json:"time_range"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	GeneratedAt time.Time              `json:"generated_at,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
	FileSize    int64                  `json:"file_size,omitempty"`
	DownloadURL string                 `json:"download_url,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedBy   string                 `json:"created_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// ReportType represents the type of report
type ReportType string

const (
	ReportTypeExecutiveSummary   ReportType = "executive_summary"
	ReportTypeThreatLandscape    ReportType = "threat_landscape"
	ReportTypeCampaignAnalysis   ReportType = "campaign_analysis"
	ReportTypeIndicatorReport    ReportType = "indicator_report"
	ReportTypeComplianceReport   ReportType = "compliance_report"
	ReportTypeIncidentReport     ReportType = "incident_report"
	ReportTypeTrendAnalysis      ReportType = "trend_analysis"
	ReportTypeSourceHealth       ReportType = "source_health"
	ReportTypeCustom             ReportType = "custom"
)

// ReportFormat represents the format of a report
type ReportFormat string

const (
	ReportFormatJSON ReportFormat = "json"
	ReportFormatPDF  ReportFormat = "pdf"
	ReportFormatCSV  ReportFormat = "csv"
	ReportFormatHTML ReportFormat = "html"
	ReportFormatSTIX ReportFormat = "stix"
)

// AnalyticsReportStatus represents the status of an analytics report
type AnalyticsReportStatus string

const (
	AnalyticsReportStatusPending    AnalyticsReportStatus = "pending"
	AnalyticsReportStatusGenerating AnalyticsReportStatus = "generating"
	AnalyticsReportStatusCompleted  AnalyticsReportStatus = "completed"
	AnalyticsReportStatusFailed     AnalyticsReportStatus = "failed"
	AnalyticsReportStatusExpired    AnalyticsReportStatus = "expired"
)

// Dashboard represents a dashboard configuration
type Dashboard struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Widgets     []DashboardWidget `json:"widgets"`
	Layout      *DashboardLayout  `json:"layout,omitempty"`
	RefreshRate int               `json:"refresh_rate,omitempty"` // seconds
	IsDefault   bool              `json:"is_default,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// DashboardWidget represents a widget on a dashboard
type DashboardWidget struct {
	ID           string                 `json:"id"`
	Type         WidgetType             `json:"type"`
	Title        string                 `json:"title"`
	Position     WidgetPosition         `json:"position"`
	Size         WidgetSize             `json:"size"`
	DataSource   string                 `json:"data_source"`
	Query        map[string]interface{} `json:"query,omitempty"`
	Visualization string               `json:"visualization,omitempty"` // chart, table, metric, map
	RefreshRate  int                    `json:"refresh_rate,omitempty"`
}

// WidgetType represents the type of dashboard widget
type WidgetType string

const (
	WidgetTypeMetric       WidgetType = "metric"
	WidgetTypeChart        WidgetType = "chart"
	WidgetTypeTable        WidgetType = "table"
	WidgetTypeMap          WidgetType = "map"
	WidgetTypeThreatFeed   WidgetType = "threat_feed"
	WidgetTypeCampaignList WidgetType = "campaign_list"
	WidgetTypeAlertList    WidgetType = "alert_list"
	WidgetTypeTrend        WidgetType = "trend"
)

// WidgetPosition represents widget position on dashboard
type WidgetPosition struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// WidgetSize represents widget size
type WidgetSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// DashboardLayout represents the dashboard layout configuration
type DashboardLayout struct {
	Columns int    `json:"columns"`
	Theme   string `json:"theme,omitempty"`
}

// SourceHealthReport contains health information for data sources
type SourceHealthReport struct {
	GeneratedAt    time.Time           `json:"generated_at"`
	TotalSources   int                 `json:"total_sources"`
	HealthySources int                 `json:"healthy_sources"`
	DegradedSources int                `json:"degraded_sources"`
	FailedSources  int                 `json:"failed_sources"`
	Sources        []SourceHealthEntry `json:"sources"`
}

// SourceHealthEntry contains health info for a single source
type SourceHealthEntry struct {
	Slug            string    `json:"slug"`
	Name            string    `json:"name"`
	Status          string    `json:"status"` // healthy, degraded, failed, disabled
	LastSuccess     time.Time `json:"last_success,omitempty"`
	LastFailure     time.Time `json:"last_failure,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	IndicatorCount  int64     `json:"indicator_count"`
	NewToday        int64     `json:"new_today"`
	SuccessRate     float64   `json:"success_rate"`
	AverageLatency  int64     `json:"average_latency_ms"`
	NextScheduled   time.Time `json:"next_scheduled,omitempty"`
}

// AlertMetrics contains alert-related metrics
type AlertMetrics struct {
	TimeRange         AnalyticsTimeRange `json:"time_range"`
	TotalAlerts       int64              `json:"total_alerts"`
	OpenAlerts        int64              `json:"open_alerts"`
	AcknowledgedAlerts int64             `json:"acknowledged_alerts"`
	ResolvedAlerts    int64              `json:"resolved_alerts"`
	MTTR              float64            `json:"mttr_minutes"` // Mean Time To Resolve
	MTTA              float64            `json:"mtta_minutes"` // Mean Time To Acknowledge
	AlertsBySeverity  []CategoryCount    `json:"alerts_by_severity"`
	AlertsByCategory  []CategoryCount    `json:"alerts_by_category"`
	AlertsTrend       []TrendDataPoint   `json:"alerts_trend"`
}

// DetectionMetrics contains detection-related metrics
type DetectionMetrics struct {
	TimeRange           AnalyticsTimeRange `json:"time_range"`
	TotalChecks         int64              `json:"total_checks"`
	TotalDetections     int64              `json:"total_detections"`
	DetectionRate       float64            `json:"detection_rate"`
	FalsePositives      int64              `json:"false_positives"`
	FalsePositiveRate   float64            `json:"false_positive_rate"`
	AverageResponseTime float64            `json:"average_response_time_ms"`
	DetectionsByType    []CategoryCount    `json:"detections_by_type"`
	DetectionsTrend     []TrendDataPoint   `json:"detections_trend"`
}

// GeoDistribution contains geographic distribution data
type GeoDistribution struct {
	Countries []GeoCountryData `json:"countries"`
	Cities    []GeoCityData    `json:"cities,omitempty"`
}

// GeoCountryData contains data for a country
type GeoCountryData struct {
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Count       int64   `json:"count"`
	Percentage  float64 `json:"percentage"`
	Severity    string  `json:"top_severity,omitempty"`
}

// GeoCityData contains data for a city
type GeoCityData struct {
	City        string  `json:"city"`
	Country     string  `json:"country"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Count       int64   `json:"count"`
}
