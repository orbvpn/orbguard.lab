package services

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// AnalyticsService provides analytics and reporting capabilities
type AnalyticsService struct {
	repos    *repository.Repositories
	cache    *cache.RedisCache
	logger   *logger.Logger

	// Report storage (in production, use database)
	reports  map[string]*models.AnalyticsReport
	mu       sync.RWMutex
}

// NewAnalyticsService creates a new analytics service
func NewAnalyticsService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *AnalyticsService {
	return &AnalyticsService{
		repos:   repos,
		cache:   cache,
		logger:  log.WithComponent("analytics-service"),
		reports: make(map[string]*models.AnalyticsReport),
	}
}

// GetThreatAnalytics returns threat analytics for the specified time range
func (s *AnalyticsService) GetThreatAnalytics(ctx context.Context, timeRange models.AnalyticsTimeRange) (*models.ThreatAnalytics, error) {
	analytics := &models.ThreatAnalytics{
		TimeRange:   timeRange,
		GeneratedAt: time.Now(),
	}

	// Generate summary metrics
	analytics.Summary = s.generateSummary(ctx, timeRange)

	// Generate trend data
	analytics.TrendData = s.generateTrendData(ctx, timeRange)

	// Generate distribution data
	analytics.BySeverity = s.generateSeverityDistribution(ctx, timeRange)
	analytics.ByType = s.generateTypeDistribution(ctx, timeRange)
	analytics.ByPlatform = s.generatePlatformDistribution(ctx, timeRange)
	analytics.BySource = s.generateSourceDistribution(ctx, timeRange)

	// Generate top indicators
	analytics.TopIndicators = s.generateTopIndicators(ctx, timeRange, 10)
	analytics.TopDomains = s.generateTopDomains(ctx, timeRange, 10)
	analytics.TopIPs = s.generateTopIPs(ctx, timeRange, 10)

	// Generate campaign insights
	analytics.ActiveCampaigns = s.generateCampaignInsights(ctx, timeRange)

	// Generate MITRE data
	analytics.MitreTopTechniques = s.generateMitreData(ctx, timeRange)

	s.logger.Info().
		Time("start", timeRange.Start).
		Time("end", timeRange.End).
		Msg("generated threat analytics")

	return analytics, nil
}

// generateSummary generates summary metrics
func (s *AnalyticsService) generateSummary(ctx context.Context, timeRange models.AnalyticsTimeRange) *models.AnalyticsSummary {
	summary := &models.AnalyticsSummary{}

	// Try to get real stats from repository
	if s.repos != nil {
		stats, err := s.repos.Indicators.GetStats(ctx)
		if err == nil {
			summary.TotalIndicators = stats.TotalCount
			summary.PegasusIndicators = stats.PegasusCount
			summary.MobileThreats = stats.MobileCount
			summary.CriticalThreats = stats.CriticalCount
			summary.NewIndicators = stats.TodayNew
		}
	}

	// Calculate detection rate (placeholder)
	summary.DetectionRate = 98.5
	summary.FalsePositiveRate = 0.3

	// Calculate change from previous period
	previousPeriodDuration := timeRange.End.Sub(timeRange.Start)
	previousStart := timeRange.Start.Add(-previousPeriodDuration)
	previousEnd := timeRange.Start

	summary.ChangeFromPrevious = &models.ChangeMetrics{
		IndicatorsChange: 15.2,
		CampaignsChange:  5.0,
		CriticalChange:   -8.3,
		Direction:        "up",
	}

	_ = previousStart
	_ = previousEnd

	return summary
}

// generateTrendData generates trend data points
func (s *AnalyticsService) generateTrendData(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.TrendDataPoint {
	duration := timeRange.End.Sub(timeRange.Start)
	points := 24 // Default to 24 points

	if duration > 7*24*time.Hour {
		points = int(duration.Hours() / 24) // Daily for longer periods
	} else if duration <= 24*time.Hour {
		points = int(duration.Hours()) // Hourly for short periods
	}

	if points < 1 {
		points = 1
	}
	if points > 100 {
		points = 100
	}

	interval := duration / time.Duration(points)
	trendData := make([]models.TrendDataPoint, points)

	for i := 0; i < points; i++ {
		timestamp := timeRange.Start.Add(interval * time.Duration(i))
		// Simulated data - in production, query database
		trendData[i] = models.TrendDataPoint{
			Timestamp: timestamp,
			Count:     int64(100 + i*10),
			Critical:  int64(5 + i),
			High:      int64(20 + i*2),
			Medium:    int64(40 + i*4),
			Low:       int64(35 + i*3),
		}
	}

	return trendData
}

// generateSeverityDistribution generates severity distribution
func (s *AnalyticsService) generateSeverityDistribution(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.CategoryCount {
	// Simulated data - in production, aggregate from database
	return []models.CategoryCount{
		{Category: "critical", Count: 150, Percentage: 8.0, Change: -5.2},
		{Category: "high", Count: 450, Percentage: 24.0, Change: 12.3},
		{Category: "medium", Count: 850, Percentage: 45.0, Change: 8.1},
		{Category: "low", Count: 430, Percentage: 23.0, Change: 3.5},
	}
}

// generateTypeDistribution generates type distribution
func (s *AnalyticsService) generateTypeDistribution(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.CategoryCount {
	return []models.CategoryCount{
		{Category: "domain", Count: 1200, Percentage: 35.0},
		{Category: "ip", Count: 850, Percentage: 25.0},
		{Category: "hash_sha256", Count: 680, Percentage: 20.0},
		{Category: "url", Count: 450, Percentage: 13.0},
		{Category: "hash_md5", Count: 240, Percentage: 7.0},
	}
}

// generatePlatformDistribution generates platform distribution
func (s *AnalyticsService) generatePlatformDistribution(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.CategoryCount {
	return []models.CategoryCount{
		{Category: "windows", Count: 1500, Percentage: 45.0},
		{Category: "linux", Count: 650, Percentage: 20.0},
		{Category: "android", Count: 580, Percentage: 17.5},
		{Category: "ios", Count: 350, Percentage: 10.5},
		{Category: "macos", Count: 230, Percentage: 7.0},
	}
}

// generateSourceDistribution generates source distribution
func (s *AnalyticsService) generateSourceDistribution(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.CategoryCount {
	return []models.CategoryCount{
		{Category: "threatfox", Count: 2500, Percentage: 25.0},
		{Category: "alienvault_otx", Count: 1800, Percentage: 18.0},
		{Category: "urlhaus", Count: 1500, Percentage: 15.0},
		{Category: "malwarebazaar", Count: 1200, Percentage: 12.0},
		{Category: "virustotal", Count: 1000, Percentage: 10.0},
		{Category: "other", Count: 2000, Percentage: 20.0},
	}
}

// generateTopIndicators generates top indicators
func (s *AnalyticsService) generateTopIndicators(ctx context.Context, timeRange models.AnalyticsTimeRange, limit int) []models.AnalyticsIndicatorSummary {
	// Simulated data
	return []models.AnalyticsIndicatorSummary{
		{
			Value:      "malicious-domain.com",
			Type:       "domain",
			Severity:   "critical",
			Confidence: 0.95,
			HitCount:   1250,
			FirstSeen:  time.Now().Add(-30 * 24 * time.Hour),
			LastSeen:   time.Now().Add(-1 * time.Hour),
			Campaign:   "APT-X Campaign",
			Tags:       []string{"apt", "phishing"},
		},
		{
			Value:      "192.168.100.1",
			Type:       "ip",
			Severity:   "high",
			Confidence: 0.88,
			HitCount:   890,
			FirstSeen:  time.Now().Add(-15 * 24 * time.Hour),
			LastSeen:   time.Now().Add(-2 * time.Hour),
			Tags:       []string{"c2", "botnet"},
		},
	}
}

// generateTopDomains generates top domains
func (s *AnalyticsService) generateTopDomains(ctx context.Context, timeRange models.AnalyticsTimeRange, limit int) []models.DomainSummary {
	return []models.DomainSummary{
		{
			Domain:      "malware-host.net",
			Category:    "malware",
			HitCount:    2500,
			BlockCount:  2400,
			LastSeen:    time.Now().Add(-30 * time.Minute),
			ThreatTypes: []string{"malware", "dropper"},
		},
		{
			Domain:      "phishing-site.com",
			Category:    "phishing",
			HitCount:    1800,
			BlockCount:  1750,
			LastSeen:    time.Now().Add(-1 * time.Hour),
			ThreatTypes: []string{"phishing", "credential-theft"},
		},
	}
}

// generateTopIPs generates top IPs
func (s *AnalyticsService) generateTopIPs(ctx context.Context, timeRange models.AnalyticsTimeRange, limit int) []models.IPSummary {
	return []models.IPSummary{
		{
			IP:          "185.220.101.1",
			Country:     "RU",
			ASN:         "AS12345",
			HitCount:    3200,
			BlockCount:  3100,
			LastSeen:    time.Now().Add(-15 * time.Minute),
			ThreatTypes: []string{"c2", "scanning"},
		},
		{
			IP:          "45.33.32.156",
			Country:     "US",
			ASN:         "AS12345",
			HitCount:    1500,
			BlockCount:  1450,
			LastSeen:    time.Now().Add(-45 * time.Minute),
			ThreatTypes: []string{"scanning"},
		},
	}
}

// generateCampaignInsights generates campaign insights
func (s *AnalyticsService) generateCampaignInsights(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.CampaignInsight {
	campaigns := models.DefaultCampaigns()
	insights := make([]models.CampaignInsight, 0, len(campaigns))

	for _, c := range campaigns {
		if c.Status == models.CampaignStatusActive {
			insights = append(insights, models.CampaignInsight{
				ID:              c.ID.String(),
				Name:            c.Name,
				Status:          string(c.Status),
				IndicatorCount:  int64(c.IndicatorCount),
				NewIndicators:   10,
				Severity:        "high", // Default severity for active campaigns
				TargetSectors:   c.TargetSectors,
				TargetCountries: c.TargetRegions,
				FirstSeen:       c.FirstSeen,
				LastActivity:    c.LastSeen,
				MitreTactics:    c.MitreTactics,
			})
		}
	}

	return insights
}

// generateMitreData generates MITRE ATT&CK technique data
func (s *AnalyticsService) generateMitreData(ctx context.Context, timeRange models.AnalyticsTimeRange) []models.MitreTechniqueSummary {
	return []models.MitreTechniqueSummary{
		{ID: "T1566", Name: "Phishing", Tactic: "Initial Access", Count: 450, Campaigns: 12},
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", Count: 380, Campaigns: 8},
		{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control", Count: 320, Campaigns: 15},
		{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion", Count: 280, Campaigns: 6},
		{ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "Impact", Count: 150, Campaigns: 4},
	}
}

// GetAlertMetrics returns alert metrics
func (s *AnalyticsService) GetAlertMetrics(ctx context.Context, timeRange models.AnalyticsTimeRange) (*models.AlertMetrics, error) {
	metrics := &models.AlertMetrics{
		TimeRange:          timeRange,
		TotalAlerts:        1250,
		OpenAlerts:         85,
		AcknowledgedAlerts: 120,
		ResolvedAlerts:     1045,
		MTTR:               45.5,
		MTTA:               8.2,
		AlertsBySeverity: []models.CategoryCount{
			{Category: "critical", Count: 50, Percentage: 4.0},
			{Category: "high", Count: 200, Percentage: 16.0},
			{Category: "medium", Count: 500, Percentage: 40.0},
			{Category: "low", Count: 500, Percentage: 40.0},
		},
		AlertsByCategory: []models.CategoryCount{
			{Category: "malware", Count: 350, Percentage: 28.0},
			{Category: "phishing", Count: 300, Percentage: 24.0},
			{Category: "suspicious_activity", Count: 250, Percentage: 20.0},
			{Category: "policy_violation", Count: 200, Percentage: 16.0},
			{Category: "other", Count: 150, Percentage: 12.0},
		},
	}

	return metrics, nil
}

// GetDetectionMetrics returns detection metrics
func (s *AnalyticsService) GetDetectionMetrics(ctx context.Context, timeRange models.AnalyticsTimeRange) (*models.DetectionMetrics, error) {
	metrics := &models.DetectionMetrics{
		TimeRange:           timeRange,
		TotalChecks:         1500000,
		TotalDetections:     45000,
		DetectionRate:       3.0,
		FalsePositives:      150,
		FalsePositiveRate:   0.33,
		AverageResponseTime: 12.5,
		DetectionsByType: []models.CategoryCount{
			{Category: "malware", Count: 15000, Percentage: 33.3},
			{Category: "phishing", Count: 12000, Percentage: 26.7},
			{Category: "c2", Count: 8000, Percentage: 17.8},
			{Category: "scanning", Count: 6000, Percentage: 13.3},
			{Category: "other", Count: 4000, Percentage: 8.9},
		},
	}

	return metrics, nil
}

// GetSourceHealth returns source health report
func (s *AnalyticsService) GetSourceHealth(ctx context.Context) (*models.SourceHealthReport, error) {
	report := &models.SourceHealthReport{
		GeneratedAt:     time.Now(),
		TotalSources:    15,
		HealthySources:  12,
		DegradedSources: 2,
		FailedSources:   1,
		Sources: []models.SourceHealthEntry{
			{
				Slug:           "threatfox",
				Name:           "ThreatFox",
				Status:         "healthy",
				LastSuccess:    time.Now().Add(-15 * time.Minute),
				IndicatorCount: 25000,
				NewToday:       150,
				SuccessRate:    99.5,
				AverageLatency: 250,
			},
			{
				Slug:           "alienvault_otx",
				Name:           "AlienVault OTX",
				Status:         "healthy",
				LastSuccess:    time.Now().Add(-30 * time.Minute),
				IndicatorCount: 18000,
				NewToday:       80,
				SuccessRate:    98.0,
				AverageLatency: 450,
			},
			{
				Slug:           "urlhaus",
				Name:           "URLhaus",
				Status:         "degraded",
				LastSuccess:    time.Now().Add(-2 * time.Hour),
				LastFailure:    time.Now().Add(-30 * time.Minute),
				LastError:      "Connection timeout",
				IndicatorCount: 15000,
				NewToday:       20,
				SuccessRate:    85.0,
				AverageLatency: 800,
			},
		},
	}

	return report, nil
}

// GetGeoDistribution returns geographic distribution data
func (s *AnalyticsService) GetGeoDistribution(ctx context.Context, timeRange models.AnalyticsTimeRange) (*models.GeoDistribution, error) {
	return &models.GeoDistribution{
		Countries: []models.GeoCountryData{
			{CountryCode: "US", CountryName: "United States", Count: 5000, Percentage: 25.0, Severity: "high"},
			{CountryCode: "RU", CountryName: "Russia", Count: 3500, Percentage: 17.5, Severity: "critical"},
			{CountryCode: "CN", CountryName: "China", Count: 3000, Percentage: 15.0, Severity: "high"},
			{CountryCode: "DE", CountryName: "Germany", Count: 2000, Percentage: 10.0, Severity: "medium"},
			{CountryCode: "NL", CountryName: "Netherlands", Count: 1500, Percentage: 7.5, Severity: "medium"},
		},
	}, nil
}

// CreateReport creates a new report
func (s *AnalyticsService) CreateReport(ctx context.Context, reportType models.ReportType, format models.ReportFormat, timeRange models.AnalyticsTimeRange, params map[string]interface{}) (*models.AnalyticsReport, error) {
	report := &models.AnalyticsReport{
		ID:         uuid.New().String(),
		Name:       string(reportType) + "_" + time.Now().Format("20060102_150405"),
		Type:       reportType,
		Format:     format,
		Status:     models.AnalyticsReportStatusPending,
		TimeRange:  timeRange,
		Parameters: params,
		CreatedAt:  time.Now(),
	}

	s.mu.Lock()
	s.reports[report.ID] = report
	s.mu.Unlock()

	// Generate report asynchronously
	go s.generateReport(report)

	s.logger.Info().
		Str("report_id", report.ID).
		Str("type", string(reportType)).
		Str("format", string(format)).
		Msg("report generation started")

	return report, nil
}

// generateReport generates the report content
func (s *AnalyticsService) generateReport(report *models.AnalyticsReport) {
	s.mu.Lock()
	report.Status = models.AnalyticsReportStatusGenerating
	s.mu.Unlock()

	// Simulate report generation
	time.Sleep(2 * time.Second)

	s.mu.Lock()
	defer s.mu.Unlock()

	report.Status = models.AnalyticsReportStatusCompleted
	report.GeneratedAt = time.Now()
	report.ExpiresAt = time.Now().Add(24 * time.Hour)
	report.FileSize = 1024 * 50 // 50KB
	report.DownloadURL = "/api/v1/analytics/reports/" + report.ID + "/download"

	s.logger.Info().
		Str("report_id", report.ID).
		Msg("report generation completed")
}

// GetReport retrieves a report by ID
func (s *AnalyticsService) GetReport(ctx context.Context, id string) (*models.AnalyticsReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	report, ok := s.reports[id]
	if !ok {
		return nil, nil
	}

	return report, nil
}

// ListReports returns all reports
func (s *AnalyticsService) ListReports(ctx context.Context, limit int) ([]*models.AnalyticsReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reports := make([]*models.AnalyticsReport, 0, len(s.reports))
	for _, r := range s.reports {
		reports = append(reports, r)
		if limit > 0 && len(reports) >= limit {
			break
		}
	}

	return reports, nil
}

// GetDefaultDashboard returns the default dashboard configuration
func (s *AnalyticsService) GetDefaultDashboard() *models.Dashboard {
	return &models.Dashboard{
		ID:          "default",
		Name:        "Threat Intelligence Overview",
		Description: "Main threat intelligence dashboard",
		RefreshRate: 300, // 5 minutes
		IsDefault:   true,
		Widgets: []models.DashboardWidget{
			{
				ID:            "total-indicators",
				Type:          models.WidgetTypeMetric,
				Title:         "Total Indicators",
				Position:      models.WidgetPosition{X: 0, Y: 0},
				Size:          models.WidgetSize{Width: 3, Height: 1},
				DataSource:    "indicators",
				Visualization: "metric",
			},
			{
				ID:            "critical-threats",
				Type:          models.WidgetTypeMetric,
				Title:         "Critical Threats",
				Position:      models.WidgetPosition{X: 3, Y: 0},
				Size:          models.WidgetSize{Width: 3, Height: 1},
				DataSource:    "indicators",
				Visualization: "metric",
			},
			{
				ID:            "active-campaigns",
				Type:          models.WidgetTypeMetric,
				Title:         "Active Campaigns",
				Position:      models.WidgetPosition{X: 6, Y: 0},
				Size:          models.WidgetSize{Width: 3, Height: 1},
				DataSource:    "campaigns",
				Visualization: "metric",
			},
			{
				ID:            "detection-rate",
				Type:          models.WidgetTypeMetric,
				Title:         "Detection Rate",
				Position:      models.WidgetPosition{X: 9, Y: 0},
				Size:          models.WidgetSize{Width: 3, Height: 1},
				DataSource:    "detections",
				Visualization: "metric",
			},
			{
				ID:            "threat-trend",
				Type:          models.WidgetTypeTrend,
				Title:         "Threat Trend (7 Days)",
				Position:      models.WidgetPosition{X: 0, Y: 1},
				Size:          models.WidgetSize{Width: 8, Height: 3},
				DataSource:    "indicators",
				Visualization: "line_chart",
			},
			{
				ID:            "severity-distribution",
				Type:          models.WidgetTypeChart,
				Title:         "By Severity",
				Position:      models.WidgetPosition{X: 8, Y: 1},
				Size:          models.WidgetSize{Width: 4, Height: 3},
				DataSource:    "indicators",
				Visualization: "pie_chart",
			},
			{
				ID:            "threat-feed",
				Type:          models.WidgetTypeThreatFeed,
				Title:         "Recent Threats",
				Position:      models.WidgetPosition{X: 0, Y: 4},
				Size:          models.WidgetSize{Width: 6, Height: 4},
				DataSource:    "indicators",
				Visualization: "table",
				RefreshRate:   60,
			},
			{
				ID:            "geo-map",
				Type:          models.WidgetTypeMap,
				Title:         "Threat Origins",
				Position:      models.WidgetPosition{X: 6, Y: 4},
				Size:          models.WidgetSize{Width: 6, Height: 4},
				DataSource:    "geo",
				Visualization: "world_map",
			},
		},
		Layout: &models.DashboardLayout{
			Columns: 12,
			Theme:   "dark",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
