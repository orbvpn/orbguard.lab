package services

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// AppAnalyzer provides app security analysis services
type AppAnalyzer struct {
	repos  *repository.Repositories
	cache  *cache.RedisCache
	logger *logger.Logger

	// Known dangerous permissions
	dangerousPermissions map[string]bool
	// Permission to category mapping
	permissionCategories map[string]models.PermissionCategory
}

// NewAppAnalyzer creates a new app analyzer
func NewAppAnalyzer(repos *repository.Repositories, redisCache *cache.RedisCache, log *logger.Logger) *AppAnalyzer {
	analyzer := &AppAnalyzer{
		repos:                repos,
		cache:                redisCache,
		logger:               log.WithComponent("app-analyzer"),
		dangerousPermissions: make(map[string]bool),
		permissionCategories: make(map[string]models.PermissionCategory),
	}

	analyzer.initPermissionMaps()
	return analyzer
}

// initPermissionMaps initializes permission classification maps
func (a *AppAnalyzer) initPermissionMaps() {
	// Dangerous permissions
	dangerous := []string{
		"android.permission.READ_CONTACTS",
		"android.permission.WRITE_CONTACTS",
		"android.permission.READ_CALL_LOG",
		"android.permission.WRITE_CALL_LOG",
		"android.permission.PROCESS_OUTGOING_CALLS",
		"android.permission.READ_SMS",
		"android.permission.SEND_SMS",
		"android.permission.RECEIVE_SMS",
		"android.permission.READ_PHONE_STATE",
		"android.permission.CALL_PHONE",
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.ACCESS_COARSE_LOCATION",
		"android.permission.ACCESS_BACKGROUND_LOCATION",
		"android.permission.CAMERA",
		"android.permission.RECORD_AUDIO",
		"android.permission.READ_EXTERNAL_STORAGE",
		"android.permission.WRITE_EXTERNAL_STORAGE",
		"android.permission.READ_CALENDAR",
		"android.permission.WRITE_CALENDAR",
		"android.permission.BODY_SENSORS",
		"android.permission.ACTIVITY_RECOGNITION",
		"android.permission.READ_MEDIA_IMAGES",
		"android.permission.READ_MEDIA_VIDEO",
		"android.permission.READ_MEDIA_AUDIO",
	}

	for _, p := range dangerous {
		a.dangerousPermissions[p] = true
	}

	// Permission categories
	a.permissionCategories["android.permission.ACCESS_FINE_LOCATION"] = models.PermissionCategoryLocation
	a.permissionCategories["android.permission.ACCESS_COARSE_LOCATION"] = models.PermissionCategoryLocation
	a.permissionCategories["android.permission.ACCESS_BACKGROUND_LOCATION"] = models.PermissionCategoryLocation
	a.permissionCategories["android.permission.CAMERA"] = models.PermissionCategoryCamera
	a.permissionCategories["android.permission.RECORD_AUDIO"] = models.PermissionCategoryMicrophone
	a.permissionCategories["android.permission.READ_CONTACTS"] = models.PermissionCategoryContacts
	a.permissionCategories["android.permission.WRITE_CONTACTS"] = models.PermissionCategoryContacts
	a.permissionCategories["android.permission.READ_CALENDAR"] = models.PermissionCategoryCalendar
	a.permissionCategories["android.permission.WRITE_CALENDAR"] = models.PermissionCategoryCalendar
	a.permissionCategories["android.permission.READ_EXTERNAL_STORAGE"] = models.PermissionCategoryStorage
	a.permissionCategories["android.permission.WRITE_EXTERNAL_STORAGE"] = models.PermissionCategoryStorage
	a.permissionCategories["android.permission.READ_SMS"] = models.PermissionCategorySMS
	a.permissionCategories["android.permission.SEND_SMS"] = models.PermissionCategorySMS
	a.permissionCategories["android.permission.RECEIVE_SMS"] = models.PermissionCategorySMS
	a.permissionCategories["android.permission.READ_PHONE_STATE"] = models.PermissionCategoryPhone
	a.permissionCategories["android.permission.CALL_PHONE"] = models.PermissionCategoryPhone
	a.permissionCategories["android.permission.READ_CALL_LOG"] = models.PermissionCategoryPhone
	a.permissionCategories["android.permission.BODY_SENSORS"] = models.PermissionCategorySensors
	a.permissionCategories["android.permission.INTERNET"] = models.PermissionCategoryNetwork
	a.permissionCategories["android.permission.ACCESS_NETWORK_STATE"] = models.PermissionCategoryNetwork
	a.permissionCategories["android.permission.BLUETOOTH"] = models.PermissionCategoryBluetooth
	a.permissionCategories["android.permission.BLUETOOTH_ADMIN"] = models.PermissionCategoryBluetooth
	a.permissionCategories["android.permission.BIND_ACCESSIBILITY_SERVICE"] = models.PermissionCategoryAccessibility
	a.permissionCategories["android.permission.BIND_DEVICE_ADMIN"] = models.PermissionCategoryAdmin
}

// AnalyzeApp performs a complete security analysis of an app
func (a *AppAnalyzer) AnalyzeApp(ctx context.Context, req *models.AppAnalysisRequest) (*models.AppAnalysisResult, error) {
	result := &models.AppAnalysisResult{
		ID:              uuid.New(),
		PackageName:     req.PackageName,
		AppName:         req.AppName,
		AnalyzedAt:      time.Now(),
		AnalysisVersion: "1.0.0",
	}

	// 1. Analyze permissions
	result.PermissionRisk = a.analyzePermissions(req.Permissions)

	// 2. Analyze privacy risks
	result.PrivacyRisk = a.analyzePrivacy(req)

	// 3. Analyze security risks
	result.SecurityRisk = a.analyzeSecurityRisks(req)

	// 4. Check threat intelligence
	result.ThreatIntelMatch = a.checkThreatIntelligence(ctx, req)

	// 5. Calculate overall risk score
	result.RiskScore, result.RiskLevel = a.calculateOverallRisk(result)

	// 6. Generate recommendations
	result.Recommendations = a.generateRecommendations(result, req)

	// 7. Set overall verdict
	result.OverallVerdict = a.generateVerdict(result)

	a.logger.Info().
		Str("package", req.PackageName).
		Str("risk_level", string(result.RiskLevel)).
		Float64("risk_score", result.RiskScore).
		Msg("app analysis completed")

	return result, nil
}

// AnalyzeBatch analyzes multiple apps
func (a *AppAnalyzer) AnalyzeBatch(ctx context.Context, req *models.AppBatchAnalysisRequest) (*models.AppBatchAnalysisResult, error) {
	result := &models.AppBatchAnalysisResult{
		Results:    make([]models.AppAnalysisResult, 0, len(req.Apps)),
		TotalCount: len(req.Apps),
		AnalyzedAt: time.Now(),
	}

	for _, app := range req.Apps {
		appResult, err := a.AnalyzeApp(ctx, &app)
		if err != nil {
			a.logger.Warn().Err(err).Str("package", app.PackageName).Msg("failed to analyze app")
			continue
		}

		result.Results = append(result.Results, *appResult)

		switch appResult.RiskLevel {
		case models.AppRiskLevelSafe, models.AppRiskLevelLow:
			result.SafeCount++
		case models.AppRiskLevelMedium, models.AppRiskLevelHigh:
			result.RiskyCount++
		case models.AppRiskLevelCritical:
			result.CriticalCount++
		}
	}

	return result, nil
}

// analyzePermissions analyzes app permissions for risks
func (a *AppAnalyzer) analyzePermissions(permissions []models.AppPermission) models.PermissionRiskAnalysis {
	analysis := models.PermissionRiskAnalysis{
		PermissionGroups: make(map[string]int),
		Concerns:         []string{},
	}

	grantedPerms := make(map[string]bool)

	for _, perm := range permissions {
		// Count dangerous permissions
		if a.dangerousPermissions[perm.Name] || perm.IsDangerous {
			analysis.DangerousCount++
			if perm.IsGranted {
				analysis.GrantedDangerous++
				grantedPerms[perm.Name] = true
			}
		}

		// Categorize permissions
		if cat, ok := a.permissionCategories[perm.Name]; ok {
			analysis.PermissionGroups[string(cat)]++
		}
	}

	// Check for dangerous combinations
	for _, combo := range models.DangerousPermissionCombos {
		allGranted := true
		for _, p := range combo.Permissions {
			if !grantedPerms[p] {
				allGranted = false
				break
			}
		}
		if allGranted {
			analysis.DangerousCombos = append(analysis.DangerousCombos, combo)
			analysis.Concerns = append(analysis.Concerns, combo.Description)
		}
	}

	// Add specific concerns
	if grantedPerms["android.permission.READ_SMS"] {
		analysis.Concerns = append(analysis.Concerns, "Can read your SMS messages")
	}
	if grantedPerms["android.permission.ACCESS_BACKGROUND_LOCATION"] {
		analysis.Concerns = append(analysis.Concerns, "Can track your location in background")
	}
	if grantedPerms["android.permission.BIND_ACCESSIBILITY_SERVICE"] {
		analysis.Concerns = append(analysis.Concerns, "Has accessibility service access - can monitor screen content")
	}
	if grantedPerms["android.permission.BIND_DEVICE_ADMIN"] {
		analysis.Concerns = append(analysis.Concerns, "Has device admin rights - can perform administrative actions")
	}

	// Calculate permission risk score
	analysis.Score = a.calculatePermissionScore(analysis)

	return analysis
}

// analyzePrivacy analyzes privacy risks
func (a *AppAnalyzer) analyzePrivacy(req *models.AppAnalysisRequest) models.PrivacyRiskAnalysis {
	analysis := models.PrivacyRiskAnalysis{
		DataAccessTypes: []string{},
		TrackerSDKs:     []models.TrackerSDK{},
		DataCollection:  models.DataCollectionInfo{},
		Concerns:        []string{},
	}

	// Build permission set
	permSet := make(map[string]bool)
	for _, p := range req.Permissions {
		if p.IsGranted {
			permSet[p.Name] = true
		}
	}

	// Determine data collection capabilities
	if permSet["android.permission.ACCESS_FINE_LOCATION"] || permSet["android.permission.ACCESS_COARSE_LOCATION"] {
		analysis.DataCollection.CollectsLocation = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "Location")
	}
	if permSet["android.permission.READ_CONTACTS"] {
		analysis.DataCollection.CollectsContacts = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "Contacts")
	}
	if permSet["android.permission.READ_CALL_LOG"] {
		analysis.DataCollection.CollectsCallLogs = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "Call Logs")
	}
	if permSet["android.permission.READ_SMS"] {
		analysis.DataCollection.CollectsSMS = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "SMS")
	}
	if permSet["android.permission.CAMERA"] {
		analysis.DataCollection.CollectsCamera = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "Camera")
	}
	if permSet["android.permission.RECORD_AUDIO"] {
		analysis.DataCollection.CollectsMicrophone = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "Microphone")
	}
	if permSet["android.permission.READ_EXTERNAL_STORAGE"] || permSet["android.permission.WRITE_EXTERNAL_STORAGE"] {
		analysis.DataCollection.CollectsStorage = true
		analysis.DataAccessTypes = append(analysis.DataAccessTypes, "Storage")
	}
	if permSet["android.permission.INTERNET"] {
		analysis.DataCollection.HasInternetAccess = true
	}
	if permSet["android.permission.RECEIVE_BOOT_COMPLETED"] || permSet["android.permission.FOREGROUND_SERVICE"] {
		analysis.DataCollection.CanRunInBackground = true
	}

	// Check for known trackers based on package name patterns
	for pkgPrefix, tracker := range models.KnownTrackers {
		if strings.Contains(req.PackageName, pkgPrefix) {
			analysis.TrackerSDKs = append(analysis.TrackerSDKs, tracker)
		}
	}

	// Generate privacy concerns
	if analysis.DataCollection.CollectsLocation && analysis.DataCollection.HasInternetAccess {
		analysis.Concerns = append(analysis.Concerns, "Can collect and transmit your location data")
	}
	if analysis.DataCollection.CollectsContacts && analysis.DataCollection.HasInternetAccess {
		analysis.Concerns = append(analysis.Concerns, "Can access and potentially upload your contacts")
	}
	if len(analysis.TrackerSDKs) > 0 {
		analysis.Concerns = append(analysis.Concerns, "Contains tracking SDKs that may collect your data")
	}
	if analysis.DataCollection.CanRunInBackground && len(analysis.DataAccessTypes) > 2 {
		analysis.Concerns = append(analysis.Concerns, "Can collect data even when not in use")
	}

	// Calculate privacy score
	analysis.Score = a.calculatePrivacyScore(analysis)

	return analysis
}

// analyzeSecurityRisks analyzes security-related risks
func (a *AppAnalyzer) analyzeSecurityRisks(req *models.AppAnalysisRequest) models.SecurityRiskAnalysis {
	analysis := models.SecurityRiskAnalysis{
		Concerns: []string{},
	}

	// Check install source
	analysis.IsSideloaded = req.InstallSource == models.AppInstallSourceSideloaded ||
		req.InstallSource == models.AppInstallSourceADB ||
		req.InstallSource == models.AppInstallSourceUnknown

	if analysis.IsSideloaded {
		analysis.Concerns = append(analysis.Concerns, "App was not installed from official app store")
	}

	// Check target SDK (old SDKs have known vulnerabilities)
	if req.TargetSDK > 0 && req.TargetSDK < 28 { // Android 9 (Pie)
		analysis.TargetsOldSDK = true
		analysis.Concerns = append(analysis.Concerns, "App targets an outdated Android version with known security issues")
	}

	// Check for signature
	if req.SignatureHash != "" {
		analysis.SignatureValid = true
		// In production, we'd verify against known trusted signatures
	}

	// Additional security checks would include:
	// - APK decompilation for obfuscation detection
	// - Manifest analysis for debug/backup flags
	// - Network security config analysis
	// For now, we'll set sensible defaults

	analysis.HasDebugEnabled = false
	analysis.HasBackupAllowed = true // Most apps allow backup by default

	// Calculate security score
	analysis.Score = a.calculateSecurityScore(analysis)

	return analysis
}

// checkThreatIntelligence checks the app against threat intelligence
func (a *AppAnalyzer) checkThreatIntelligence(ctx context.Context, req *models.AppAnalysisRequest) *models.ThreatIntelMatch {
	if a.repos == nil {
		return nil
	}

	// Check package name against indicators
	indicator, err := a.repos.Indicators.GetByValue(ctx, req.PackageName, models.IndicatorTypePackage)
	if err == nil && indicator != nil {
		return &models.ThreatIntelMatch{
			IsKnownMalware:     indicator.Severity == models.SeverityCritical,
			IsPotentiallyHarmful: indicator.Severity >= models.SeverityMedium,
			IndicatorIDs:       []string{indicator.ID.String()},
			DetectionSource:    "threat_intel_db",
			FirstSeen:          indicator.FirstSeen,
		}
	}

	// Check APK hash if available
	if req.APKHash != "" {
		indicator, err = a.repos.Indicators.GetByValue(ctx, req.APKHash, models.IndicatorTypeHash)
		if err == nil && indicator != nil {
			match := &models.ThreatIntelMatch{
				IsKnownMalware:     indicator.Severity == models.SeverityCritical,
				IsPotentiallyHarmful: indicator.Severity >= models.SeverityMedium,
				IndicatorIDs:       []string{indicator.ID.String()},
				DetectionSource:    "threat_intel_db",
				FirstSeen:          indicator.FirstSeen,
			}

			// Check for campaign association
			if indicator.CampaignID != nil {
				match.CampaignID = indicator.CampaignID.String()
				campaign, err := a.repos.Campaigns.GetByID(ctx, *indicator.CampaignID)
				if err == nil && campaign != nil {
					match.MalwareFamily = campaign.Name // Use campaign name as malware family
				}
			}

			return match
		}
	}

	return nil
}

// calculateOverallRisk calculates the overall risk score and level
func (a *AppAnalyzer) calculateOverallRisk(result *models.AppAnalysisResult) (float64, models.AppRiskLevel) {
	// Weighted average of different risk components
	permWeight := 0.30
	privWeight := 0.25
	secWeight := 0.25
	threatWeight := 0.20

	score := result.PermissionRisk.Score*permWeight +
		result.PrivacyRisk.Score*privWeight +
		result.SecurityRisk.Score*secWeight

	// Threat intel match is binary but weighted heavily
	if result.ThreatIntelMatch != nil {
		if result.ThreatIntelMatch.IsKnownMalware {
			score += 100 * threatWeight
		} else if result.ThreatIntelMatch.IsPotentiallyHarmful {
			score += 70 * threatWeight
		}
	}

	// Determine risk level
	var level models.AppRiskLevel
	switch {
	case result.ThreatIntelMatch != nil && result.ThreatIntelMatch.IsKnownMalware:
		level = models.AppRiskLevelCritical
	case score >= 80:
		level = models.AppRiskLevelCritical
	case score >= 60:
		level = models.AppRiskLevelHigh
	case score >= 40:
		level = models.AppRiskLevelMedium
	case score >= 20:
		level = models.AppRiskLevelLow
	default:
		level = models.AppRiskLevelSafe
	}

	return score, level
}

// Score calculation helpers

func (a *AppAnalyzer) calculatePermissionScore(analysis models.PermissionRiskAnalysis) float64 {
	score := 0.0

	// Base score from dangerous permissions
	score += float64(analysis.GrantedDangerous) * 5

	// Extra for dangerous combos
	for _, combo := range analysis.DangerousCombos {
		switch combo.RiskLevel {
		case "critical":
			score += 30
		case "high":
			score += 20
		case "medium":
			score += 10
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (a *AppAnalyzer) calculatePrivacyScore(analysis models.PrivacyRiskAnalysis) float64 {
	score := 0.0

	// Data collection types
	score += float64(len(analysis.DataAccessTypes)) * 8

	// Trackers
	score += float64(len(analysis.TrackerSDKs)) * 10

	// Background capability with data access
	if analysis.DataCollection.CanRunInBackground {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (a *AppAnalyzer) calculateSecurityScore(analysis models.SecurityRiskAnalysis) float64 {
	score := 0.0

	if analysis.IsSideloaded {
		score += 30
	}
	if analysis.TargetsOldSDK {
		score += 20
	}
	if analysis.HasDebugEnabled {
		score += 25
	}
	if analysis.UsesHTTP {
		score += 15
	}
	if analysis.HasWeakCrypto {
		score += 20
	}
	if !analysis.SignatureValid {
		score += 25
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// generateRecommendations creates actionable recommendations
func (a *AppAnalyzer) generateRecommendations(result *models.AppAnalysisResult, req *models.AppAnalysisRequest) []models.AppRecommendation {
	recommendations := []models.AppRecommendation{}

	// Critical: Known malware
	if result.ThreatIntelMatch != nil && result.ThreatIntelMatch.IsKnownMalware {
		recommendations = append(recommendations, models.AppRecommendation{
			ID:          "uninstall_malware",
			Priority:    "critical",
			Category:    "security",
			Title:       "Uninstall Malicious App",
			Description: "This app has been identified as malware. Uninstall it immediately.",
			Action:      "uninstall",
		})
	}

	// High: Sideloaded with risky permissions
	if result.SecurityRisk.IsSideloaded && result.RiskLevel >= models.AppRiskLevelMedium {
		recommendations = append(recommendations, models.AppRecommendation{
			ID:          "review_sideloaded",
			Priority:    "high",
			Category:    "security",
			Title:       "Review Sideloaded App",
			Description: "This app was not installed from an official store and has concerning permissions.",
			Action:      "review",
		})
	}

	// Medium: Excessive permissions
	if result.PermissionRisk.GrantedDangerous > 5 {
		recommendations = append(recommendations, models.AppRecommendation{
			ID:          "review_permissions",
			Priority:    "medium",
			Category:    "permission",
			Title:       "Review App Permissions",
			Description: "This app has access to many sensitive permissions. Consider revoking unnecessary ones.",
			Action:      "revoke_permission",
		})
	}

	// Privacy: Too many trackers
	if len(result.PrivacyRisk.TrackerSDKs) > 3 {
		recommendations = append(recommendations, models.AppRecommendation{
			ID:          "privacy_concern",
			Priority:    "medium",
			Category:    "privacy",
			Title:       "High Tracker Count",
			Description: "This app contains multiple tracking SDKs that may be collecting your data.",
			Action:      "review",
		})
	}

	// Old SDK target
	if result.SecurityRisk.TargetsOldSDK {
		recommendations = append(recommendations, models.AppRecommendation{
			ID:          "update_app",
			Priority:    "low",
			Category:    "update",
			Title:       "App Needs Update",
			Description: "This app targets an old Android version. Look for updates or alternatives.",
			Action:      "update",
		})
	}

	return recommendations
}

// generateVerdict creates a human-readable verdict
func (a *AppAnalyzer) generateVerdict(result *models.AppAnalysisResult) string {
	switch result.RiskLevel {
	case models.AppRiskLevelCritical:
		if result.ThreatIntelMatch != nil && result.ThreatIntelMatch.IsKnownMalware {
			return "DANGEROUS: This app is known malware. Uninstall immediately."
		}
		return "CRITICAL RISK: This app has severe security concerns and should be removed."
	case models.AppRiskLevelHigh:
		return "HIGH RISK: This app has significant security or privacy concerns. Review carefully."
	case models.AppRiskLevelMedium:
		return "MODERATE RISK: This app has some concerning behaviors. Monitor its activity."
	case models.AppRiskLevelLow:
		return "LOW RISK: This app has minor concerns but is generally acceptable."
	default:
		return "SAFE: No significant security or privacy concerns detected."
	}
}

// GetSideloadedApps returns a report on sideloaded apps
func (a *AppAnalyzer) GetSideloadedApps(ctx context.Context, apps []models.AppInfo) (*models.SideloadedAppReport, error) {
	report := &models.SideloadedAppReport{
		TotalApps:       len(apps),
		SideloadedApps:  []models.SideloadedAppInfo{},
		GeneratedAt:     time.Now(),
	}

	for _, app := range apps {
		if app.InstallSource == models.AppInstallSourceSideloaded ||
			app.InstallSource == models.AppInstallSourceADB ||
			app.InstallSource == models.AppInstallSourceUnknown {

			report.SideloadedCount++

			info := models.SideloadedAppInfo{
				PackageName:   app.PackageName,
				AppName:       app.AppName,
				InstallSource: app.InstallSource,
				InstalledAt:   app.InstalledAt,
				Concerns:      []string{"Not installed from official app store"},
			}

			// Quick risk assessment
			if app.InstallSource == models.AppInstallSourceUnknown {
				info.RiskLevel = models.AppRiskLevelHigh
				info.RiskScore = 70
				info.Concerns = append(info.Concerns, "Install source unknown")
			} else {
				info.RiskLevel = models.AppRiskLevelMedium
				info.RiskScore = 40
			}

			if !app.IsSystemApp {
				report.RiskyCount++
			}

			report.SideloadedApps = append(report.SideloadedApps, info)
		}
	}

	if len(report.SideloadedApps) > 0 {
		report.DeviceID = apps[0].DeviceID
	}

	return report, nil
}

// GeneratePrivacyReport generates a privacy audit report
func (a *AppAnalyzer) GeneratePrivacyReport(ctx context.Context, results []models.AppAnalysisResult, deviceID string) (*models.PrivacyReport, error) {
	report := &models.PrivacyReport{
		DeviceID:           deviceID,
		TotalApps:          len(results),
		TrackersByCategory: make(map[string]int),
		AppPrivacyScores:   []models.AppPrivacyScore{},
		GeneratedAt:        time.Now(),
	}

	trackerCounts := make(map[string]int)

	for _, result := range results {
		// Count trackers
		if len(result.PrivacyRisk.TrackerSDKs) > 0 {
			report.AppsWithTrackers++
		}

		for _, tracker := range result.PrivacyRisk.TrackerSDKs {
			report.TotalTrackers++
			trackerCounts[tracker.Name]++
			report.TrackersByCategory[tracker.Category]++
		}

		// Calculate privacy score (inverted - higher is better)
		privacyScore := 100 - result.PrivacyRisk.Score
		if privacyScore < 0 {
			privacyScore = 0
		}

		report.AppPrivacyScores = append(report.AppPrivacyScores, models.AppPrivacyScore{
			PackageName:  result.PackageName,
			AppName:      result.AppName,
			PrivacyScore: privacyScore,
			TrackerCount: len(result.PrivacyRisk.TrackerSDKs),
			DataTypes:    result.PrivacyRisk.DataAccessTypes,
		})
	}

	// Top trackers
	for name, count := range trackerCounts {
		if tracker, ok := models.KnownTrackers[name]; ok {
			report.TopTrackers = append(report.TopTrackers, models.TrackerStats{
				Name:     name,
				Company:  tracker.Company,
				AppCount: count,
				Category: tracker.Category,
			})
		}
	}

	// Generate recommendations
	if report.AppsWithTrackers > report.TotalApps/2 {
		report.Recommendations = append(report.Recommendations, models.AppRecommendation{
			ID:          "many_trackers",
			Priority:    "medium",
			Category:    "privacy",
			Title:       "High Tracker Prevalence",
			Description: "More than half of your apps contain tracking SDKs.",
			Action:      "review",
		})
	}

	return report, nil
}

// GetStats returns app security statistics
func (a *AppAnalyzer) GetStats(ctx context.Context) (*models.AppSecurityStats, error) {
	// In production, this would query the database
	stats := &models.AppSecurityStats{
		BySafetyLevel:   make(map[string]int64),
		ByInstallSource: make(map[string]int64),
	}

	return stats, nil
}
