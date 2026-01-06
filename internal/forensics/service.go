package forensics

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/forensics/android"
	"orbguard-lab/internal/forensics/ios"
	"orbguard-lab/internal/forensics/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// Service provides forensic analysis capabilities
type Service struct {
	logger *logger.Logger

	// iOS parsers
	shutdownLogParser  *ios.ShutdownLogParser
	backupParser       *ios.BackupParser
	dataUsageParser    *ios.DataUsageParser
	sysdiagnoseParser  *ios.SysdiagnoseParser

	// Android parsers
	logcatParser *android.LogcatParser

	// IOC Scanner
	iocScanner *IOCScanner
}

// NewService creates a new forensic analysis service
func NewService(log *logger.Logger) *Service {
	svcLogger := log.WithComponent("forensics")

	return &Service{
		logger:             svcLogger,
		shutdownLogParser:  ios.NewShutdownLogParser(svcLogger),
		backupParser:       ios.NewBackupParser(svcLogger),
		dataUsageParser:    ios.NewDataUsageParser(svcLogger),
		sysdiagnoseParser:  ios.NewSysdiagnoseParser(svcLogger),
		logcatParser:       android.NewLogcatParser(svcLogger),
		iocScanner:         NewIOCScanner(nil, svcLogger),
	}
}

// NewServiceWithCache creates a new forensic service with cache support
func NewServiceWithCache(cache *cache.RedisCache, log *logger.Logger) *Service {
	svcLogger := log.WithComponent("forensics")

	return &Service{
		logger:             svcLogger,
		shutdownLogParser:  ios.NewShutdownLogParser(svcLogger),
		backupParser:       ios.NewBackupParser(svcLogger),
		dataUsageParser:    ios.NewDataUsageParser(svcLogger),
		sysdiagnoseParser:  ios.NewSysdiagnoseParser(svcLogger),
		logcatParser:       android.NewLogcatParser(svcLogger),
		iocScanner:         NewIOCScanner(cache, svcLogger),
	}
}

// AnalyzeShutdownLog analyzes iOS shutdown.log for Pegasus indicators
func (s *Service) AnalyzeShutdownLog(ctx context.Context, data []byte, deviceID string) (*models.ForensicResult, error) {
	s.logger.Info().Str("device_id", deviceID).Msg("analyzing shutdown.log")

	result, err := s.shutdownLogParser.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse shutdown.log: %w", err)
	}

	result.DeviceID = deviceID
	s.logger.Info().
		Str("device_id", deviceID).
		Int("anomalies", result.TotalAnomalies).
		Int("threats", len(result.DetectedThreats)).
		Float64("infection_likelihood", result.InfectionLikelihood).
		Msg("shutdown.log analysis complete")

	return result, nil
}

// AnalyzeBackup analyzes an iOS backup for forensic indicators
func (s *Service) AnalyzeBackup(ctx context.Context, backupPath, deviceID string) (*models.ForensicResult, error) {
	s.logger.Info().
		Str("device_id", deviceID).
		Str("path", backupPath).
		Msg("analyzing iOS backup")

	result, err := s.backupParser.Parse(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iOS backup: %w", err)
	}

	result.DeviceID = deviceID
	s.logger.Info().
		Str("device_id", deviceID).
		Int("anomalies", result.TotalAnomalies).
		Int("threats", len(result.DetectedThreats)).
		Float64("infection_likelihood", result.InfectionLikelihood).
		Msg("iOS backup analysis complete")

	return result, nil
}

// AnalyzeDataUsage analyzes iOS DataUsage.sqlite for network anomalies
func (s *Service) AnalyzeDataUsage(ctx context.Context, dbPath, deviceID string) (*models.ForensicResult, error) {
	s.logger.Info().
		Str("device_id", deviceID).
		Str("path", dbPath).
		Msg("analyzing DataUsage.sqlite")

	result, err := s.dataUsageParser.Parse(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DataUsage.sqlite: %w", err)
	}

	result.DeviceID = deviceID
	s.logger.Info().
		Str("device_id", deviceID).
		Int("anomalies", result.TotalAnomalies).
		Int("threats", len(result.DetectedThreats)).
		Float64("infection_likelihood", result.InfectionLikelihood).
		Msg("DataUsage.sqlite analysis complete")

	return result, nil
}

// AnalyzeLogcat analyzes Android logcat output for forensic indicators
func (s *Service) AnalyzeLogcat(ctx context.Context, data []byte, deviceID string) (*models.ForensicResult, error) {
	s.logger.Info().Str("device_id", deviceID).Msg("analyzing Android logcat")

	result, err := s.logcatParser.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse logcat: %w", err)
	}

	result.DeviceID = deviceID
	s.logger.Info().
		Str("device_id", deviceID).
		Int("anomalies", result.TotalAnomalies).
		Int("threats", len(result.DetectedThreats)).
		Float64("infection_likelihood", result.InfectionLikelihood).
		Msg("Android logcat analysis complete")

	return result, nil
}

// RunFullAnalysis performs a comprehensive forensic analysis based on available data
func (s *Service) RunFullAnalysis(ctx context.Context, req models.ForensicScanRequest) (*models.ForensicResult, error) {
	start := time.Now()
	s.logger.Info().
		Str("device_id", req.DeviceID).
		Str("platform", req.Platform).
		Msg("starting full forensic analysis")

	// Create combined result
	combinedResult := &models.ForensicResult{
		ID:              uuid.New(),
		DeviceID:        req.DeviceID,
		Platform:        req.Platform,
		ScanType:        models.ForensicScanTypeFull,
		StartedAt:       start,
		Anomalies:       make([]models.Anomaly, 0),
		Timeline:        make([]models.TimelineEvent, 0),
		DetectedThreats: make([]models.DetectedThreat, 0),
		Recommendations: make([]string, 0),
		RawData:         make(map[string]any),
	}

	combinedTimeline := models.NewTimeline()
	scansPerformed := make([]string, 0)

	// iOS Analysis
	if req.Platform == "ios" {
		// Shutdown.log analysis
		if len(req.ShutdownLogData) > 0 {
			result, err := s.shutdownLogParser.Parse(req.ShutdownLogData)
			if err != nil {
				s.logger.Warn().Err(err).Msg("shutdown.log analysis failed")
			} else {
				s.mergeResults(combinedResult, result, combinedTimeline)
				scansPerformed = append(scansPerformed, "shutdown_log")
			}
		}

		// Backup analysis
		if req.BackupPath != "" {
			result, err := s.backupParser.Parse(req.BackupPath)
			if err != nil {
				s.logger.Warn().Err(err).Msg("backup analysis failed")
			} else {
				s.mergeResults(combinedResult, result, combinedTimeline)
				scansPerformed = append(scansPerformed, "backup")
			}
		}

		// DataUsage analysis
		if req.DataUsagePath != "" {
			result, err := s.dataUsageParser.Parse(req.DataUsagePath)
			if err != nil {
				s.logger.Warn().Err(err).Msg("DataUsage.sqlite analysis failed")
			} else {
				s.mergeResults(combinedResult, result, combinedTimeline)
				scansPerformed = append(scansPerformed, "data_usage")
			}
		}

		// Sysdiagnose archive analysis
		if req.SysdiagnosePath != "" {
			result, err := s.sysdiagnoseParser.Parse(req.SysdiagnosePath)
			if err != nil {
				s.logger.Warn().Err(err).Msg("sysdiagnose analysis failed")
			} else {
				s.mergeResults(combinedResult, result, combinedTimeline)
				scansPerformed = append(scansPerformed, "sysdiagnose")
			}
		}
	}

	// Android Analysis
	if req.Platform == "android" {
		// Logcat analysis
		if len(req.LogcatData) > 0 {
			result, err := s.logcatParser.Parse(req.LogcatData)
			if err != nil {
				s.logger.Warn().Err(err).Msg("logcat analysis failed")
			} else {
				s.mergeResults(combinedResult, result, combinedTimeline)
				scansPerformed = append(scansPerformed, "logcat")
			}
		}
	}

	// Sort and finalize timeline
	combinedTimeline.Sort()
	if req.IncludeTimeline {
		combinedResult.Timeline = combinedTimeline.ToEvents()
	}

	// Analyze patterns across all data sources
	patterns := combinedTimeline.FindSuspiciousPatterns()
	for _, pattern := range patterns {
		if pattern.Confidence >= 0.6 {
			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeProcessAnomaly,
				Severity:    pattern.Severity,
				Confidence:  pattern.Confidence,
				Title:       "Cross-Source Pattern: " + pattern.Name,
				Description: pattern.Description,
				RelatedEvents: pattern.EventIDs,
			}
			combinedResult.AddAnomaly(anomaly)
		}
	}

	// Consolidate threats and deduplicate
	combinedResult.DetectedThreats = s.consolidateThreats(combinedResult.DetectedThreats)

	// Enhance with IOC scanner (Citizen Lab/Amnesty MVT integration)
	s.iocScanner.EnhanceForensicResult(combinedResult)

	// Store metadata
	combinedResult.RawData["scans_performed"] = scansPerformed
	combinedResult.RawData["timeline_events"] = len(combinedTimeline.Events)
	combinedResult.RawData["ioc_stats"] = s.iocScanner.GetStats()

	// Complete the result
	combinedResult.Complete()

	s.logger.Info().
		Str("device_id", req.DeviceID).
		Int("anomalies", combinedResult.TotalAnomalies).
		Int("threats", len(combinedResult.DetectedThreats)).
		Float64("infection_likelihood", combinedResult.InfectionLikelihood).
		Dur("duration", combinedResult.Duration).
		Msg("full forensic analysis complete")

	return combinedResult, nil
}

// mergeResults merges a single result into the combined result
func (s *Service) mergeResults(combined *models.ForensicResult, result *models.ForensicResult, timeline *models.Timeline) {
	// Merge anomalies
	for _, a := range result.Anomalies {
		combined.Anomalies = append(combined.Anomalies, a)
	}

	// Merge threats
	for _, t := range result.DetectedThreats {
		combined.DetectedThreats = append(combined.DetectedThreats, t)
	}

	// Merge timeline
	for _, e := range result.Timeline {
		timeline.AddEvent(e)
	}

	// Merge raw data
	for k, v := range result.RawData {
		combined.RawData[string(result.ScanType)+"_"+k] = v
	}
}

// consolidateThreats deduplicates and consolidates detected threats
func (s *Service) consolidateThreats(threats []models.DetectedThreat) []models.DetectedThreat {
	// Group by type
	byType := make(map[models.InfectionType][]models.DetectedThreat)
	for _, t := range threats {
		byType[t.Type] = append(byType[t.Type], t)
	}

	consolidated := make([]models.DetectedThreat, 0)

	for infType, typeThreats := range byType {
		if len(typeThreats) == 1 {
			consolidated = append(consolidated, typeThreats[0])
			continue
		}

		// Merge multiple threats of same type
		merged := models.DetectedThreat{
			Type:            infType,
			Name:            typeThreats[0].Name,
			Severity:        typeThreats[0].Severity,
			Description:     typeThreats[0].Description,
			Attribution:     typeThreats[0].Attribution,
			AnomalyIDs:      make([]string, 0),
			MITRETechniques: make([]string, 0),
			IOCs:            make([]models.IOCMatch, 0),
			Remediation:     make([]string, 0),
		}

		// Take highest confidence
		maxConfidence := 0.0
		mitreSeen := make(map[string]bool)
		remediationSeen := make(map[string]bool)

		for _, t := range typeThreats {
			if t.Confidence > maxConfidence {
				maxConfidence = t.Confidence
			}

			merged.AnomalyIDs = append(merged.AnomalyIDs, t.AnomalyIDs...)
			merged.IOCs = append(merged.IOCs, t.IOCs...)

			for _, tech := range t.MITRETechniques {
				if !mitreSeen[tech] {
					mitreSeen[tech] = true
					merged.MITRETechniques = append(merged.MITRETechniques, tech)
				}
			}

			for _, rem := range t.Remediation {
				if !remediationSeen[rem] {
					remediationSeen[rem] = true
					merged.Remediation = append(merged.Remediation, rem)
				}
			}

			if t.FirstDetected != nil {
				if merged.FirstDetected == nil || t.FirstDetected.Before(*merged.FirstDetected) {
					merged.FirstDetected = t.FirstDetected
				}
			}
			if t.LastActive != nil {
				if merged.LastActive == nil || t.LastActive.After(*merged.LastActive) {
					merged.LastActive = t.LastActive
				}
			}
		}

		merged.Confidence = maxConfidence
		merged.Description = fmt.Sprintf("%s (evidence from %d sources)", merged.Description, len(typeThreats))

		consolidated = append(consolidated, merged)
	}

	return consolidated
}

// AnalyzeSysdiagnose analyzes an iOS sysdiagnose archive
func (s *Service) AnalyzeSysdiagnose(ctx context.Context, archivePath, deviceID string) (*models.ForensicResult, error) {
	s.logger.Info().
		Str("device_id", deviceID).
		Str("path", archivePath).
		Msg("analyzing sysdiagnose archive")

	result, err := s.sysdiagnoseParser.Parse(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sysdiagnose: %w", err)
	}

	result.DeviceID = deviceID

	// Enhance with IOC scanner
	s.iocScanner.EnhanceForensicResult(result)

	s.logger.Info().
		Str("device_id", deviceID).
		Int("anomalies", result.TotalAnomalies).
		Int("threats", len(result.DetectedThreats)).
		Float64("infection_likelihood", result.InfectionLikelihood).
		Msg("sysdiagnose analysis complete")

	return result, nil
}

// GetIOCStats returns IOC scanner statistics
func (s *Service) GetIOCStats() map[string]any {
	return s.iocScanner.GetStats()
}

// QuickCheck performs a quick check for obvious indicators
func (s *Service) QuickCheck(ctx context.Context, platform string, data []byte) (*QuickCheckResult, error) {
	s.logger.Debug().Str("platform", platform).Msg("performing quick check")

	result := &QuickCheckResult{
		Platform:           platform,
		CheckedAt:          time.Now(),
		IsSuspicious:       false,
		IndicatorsFound:    0,
		RecommendFullScan:  false,
		Indicators:         make([]QuickIndicator, 0),
	}

	// Quick pattern matching without full parsing
	if platform == "ios" {
		// Check for known Pegasus paths in shutdown.log
		pegasusPaths := []string{
			"/private/var/db/",
			"/private/var/tmp/",
			"roleaccount",
			"bh",
			"pcsd",
		}

		dataStr := string(data)
		for _, path := range pegasusPaths {
			if contains(dataStr, path) {
				result.IsSuspicious = true
				result.IndicatorsFound++
				result.Indicators = append(result.Indicators, QuickIndicator{
					Type:        "path",
					Value:       path,
					Confidence:  0.85,
					Description: "Known spyware path indicator",
				})
			}
		}
	}

	if platform == "android" {
		// Check for known spyware indicators
		spywareIndicators := []string{
			"pegasus",
			"chrysaor",
			"predator",
			"mspy",
			"flexispy",
			"root shell",
			"su root",
		}

		dataStr := string(data)
		for _, indicator := range spywareIndicators {
			if containsI(dataStr, indicator) {
				result.IsSuspicious = true
				result.IndicatorsFound++
				result.Indicators = append(result.Indicators, QuickIndicator{
					Type:        "keyword",
					Value:       indicator,
					Confidence:  0.90,
					Description: "Known spyware keyword",
				})
			}
		}
	}

	if result.IndicatorsFound > 0 {
		result.RecommendFullScan = true
	}

	return result, nil
}

// QuickCheckResult represents the result of a quick check
type QuickCheckResult struct {
	Platform          string           `json:"platform"`
	CheckedAt         time.Time        `json:"checked_at"`
	IsSuspicious      bool             `json:"is_suspicious"`
	IndicatorsFound   int              `json:"indicators_found"`
	RecommendFullScan bool             `json:"recommend_full_scan"`
	Indicators        []QuickIndicator `json:"indicators,omitempty"`
}

// QuickIndicator represents a quick check indicator
type QuickIndicator struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsI(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return contains(s, substr)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		b[i] = c
	}
	return string(b)
}
