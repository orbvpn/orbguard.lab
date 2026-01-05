package services

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// PrivacyService handles privacy monitoring and protection
type PrivacyService struct {
	cache              *cache.RedisCache
	logger             *logger.Logger
	sensitivePatterns  []*regexp.Regexp
	trackerDomains     map[string]string // domain -> tracker ID
	mu                 sync.RWMutex

	// Stats
	eventsProcessed    atomic.Int64
	alertsSent         atomic.Int64
	trackersBlocked    atomic.Int64
	sensitiveDetected  atomic.Int64
}

// NewPrivacyService creates a new privacy service
func NewPrivacyService(c *cache.RedisCache, log *logger.Logger) *PrivacyService {
	ps := &PrivacyService{
		cache:             c,
		logger:            log.WithComponent("privacy-service"),
		trackerDomains:    make(map[string]string),
	}

	ps.compileSensitivePatterns()
	ps.loadTrackerDomains()

	return ps
}

// compileSensitivePatterns compiles regex patterns for sensitive data detection
func (ps *PrivacyService) compileSensitivePatterns() {
	ps.sensitivePatterns = make([]*regexp.Regexp, 0, len(models.SensitivePatterns))

	for _, pattern := range models.SensitivePatterns {
		compiled, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			ps.logger.Error().Err(err).Str("type", pattern.Type).Msg("failed to compile sensitive pattern")
			continue
		}
		ps.sensitivePatterns = append(ps.sensitivePatterns, compiled)
	}
}

// loadTrackerDomains builds a domain -> tracker ID map
func (ps *PrivacyService) loadTrackerDomains() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	for trackerID, tracker := range models.PrivacyTrackers {
		for _, domain := range tracker.Domains {
			ps.trackerDomains[domain] = trackerID
		}
	}

	ps.logger.Info().Int("domains", len(ps.trackerDomains)).Msg("loaded tracker domains")
}

// RecordPrivacyEvent records a privacy event
func (ps *PrivacyService) RecordPrivacyEvent(ctx context.Context, event *models.PrivacyEvent) error {
	ps.eventsProcessed.Add(1)

	// Determine risk level based on event type and context
	event.RiskLevel = ps.calculateRiskLevel(event)

	// Check if alert should be sent
	if ps.shouldAlert(event) {
		ps.sendAlert(ctx, event)
	}

	// Cache recent events using SetJSON (store latest event)
	if ps.cache != nil {
		cacheKey := "privacy:events:" + event.DeviceID + ":" + event.ID.String()
		_ = ps.cache.SetJSON(ctx, cacheKey, event, 24*time.Hour)
	}

	return nil
}

// RecordCameraAccess records a camera access event
func (ps *PrivacyService) RecordCameraAccess(ctx context.Context, event *models.CameraAccessEvent) error {
	event.EventType = models.PrivacyEventCameraAccess

	// Background camera access is high risk
	if event.IsBackground {
		event.RiskLevel = models.PrivacyRiskHigh
		if event.WasRecording {
			event.RiskLevel = models.PrivacyRiskCritical
		}
	}

	return ps.RecordPrivacyEvent(ctx, &event.PrivacyEvent)
}

// RecordMicrophoneAccess records a microphone access event
func (ps *PrivacyService) RecordMicrophoneAccess(ctx context.Context, event *models.MicrophoneAccessEvent) error {
	event.EventType = models.PrivacyEventMicrophoneAccess

	// Background mic access is high risk
	if event.IsBackground {
		event.RiskLevel = models.PrivacyRiskHigh
		if event.WasRecording {
			event.RiskLevel = models.PrivacyRiskCritical
		}
	}

	return ps.RecordPrivacyEvent(ctx, &event.PrivacyEvent)
}

// RecordClipboardAccess records a clipboard access event
func (ps *PrivacyService) RecordClipboardAccess(ctx context.Context, event *models.ClipboardEvent) error {
	event.EventType = models.PrivacyEventClipboardRead

	// Check for clipboard hijacking
	if event.WasHijacked {
		event.RiskLevel = models.PrivacyRiskCritical
	} else if event.ContainsSensitive {
		event.RiskLevel = models.PrivacyRiskHigh
	}

	return ps.RecordPrivacyEvent(ctx, &event.PrivacyEvent)
}

// RecordScreenEvent records a screen capture/recording event
func (ps *PrivacyService) RecordScreenEvent(ctx context.Context, event *models.ScreenEvent) error {
	event.EventType = models.PrivacyEventScreenRecording

	// Screen casting to external IP is high risk
	if event.DestinationIP != "" {
		event.RiskLevel = models.PrivacyRiskHigh
	}
	if event.WasSensitive {
		event.RiskLevel = models.PrivacyRiskCritical
	}

	return ps.RecordPrivacyEvent(ctx, &event.PrivacyEvent)
}

// CheckClipboard checks clipboard content for sensitive data
func (ps *PrivacyService) CheckClipboard(ctx context.Context, content string, sourceApp string) *models.ClipboardProtectionResult {
	result := &models.ClipboardProtectionResult{
		IsSafe:        true,
		SensitiveData: make([]models.SensitiveDataMatch, 0),
	}

	// Check for sensitive patterns
	for i, pattern := range ps.sensitivePatterns {
		if i >= len(models.SensitivePatterns) {
			break
		}

		matches := pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			result.IsSafe = false
			ps.sensitiveDetected.Add(1)

			matchedText := content[match[0]:match[1]]
			result.SensitiveData = append(result.SensitiveData, models.SensitiveDataMatch{
				Type:      models.SensitivePatterns[i].Type,
				Masked:    maskSensitiveData(matchedText, models.SensitivePatterns[i].Type),
				Position:  match[0],
				RiskLevel: models.SensitivePatterns[i].RiskLevel,
			})
		}
	}

	// Check for clipboard hijacking patterns
	if ps.isClipboardHijacking(content, sourceApp) {
		result.WasHijacked = true
		result.HijackingApp = sourceApp
		result.IsSafe = false
	}

	// Add recommendations
	if !result.IsSafe {
		result.Recommendations = ps.getClipboardRecommendations(result)
	}

	return result
}

// CheckDomain checks if a domain is a known tracker
func (ps *PrivacyService) CheckDomain(domain string) (*models.TrackerInfo, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	// Direct match
	if trackerID, exists := ps.trackerDomains[domain]; exists {
		if tracker, ok := models.PrivacyTrackers[trackerID]; ok {
			return &tracker, true
		}
	}

	// Subdomain match
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		checkDomain := strings.Join(parts[i:], ".")
		if trackerID, exists := ps.trackerDomains[checkDomain]; exists {
			if tracker, ok := models.PrivacyTrackers[trackerID]; ok {
				return &tracker, true
			}
		}
	}

	return nil, false
}

// ShouldBlockDomain checks if a domain should be blocked
func (ps *PrivacyService) ShouldBlockDomain(ctx context.Context, domain string, settings *models.PrivacySettings) bool {
	if settings == nil || !settings.BlockTrackers {
		return false
	}

	tracker, isTracker := ps.CheckDomain(domain)
	if !isTracker {
		return false
	}

	// Block based on category and settings
	switch tracker.Category {
	case "advertising":
		if settings.BlockAds {
			ps.trackersBlocked.Add(1)
			return true
		}
	case "analytics":
		if settings.BlockAnalytics {
			ps.trackersBlocked.Add(1)
			return true
		}
	default:
		if settings.BlockTrackers {
			ps.trackersBlocked.Add(1)
			return true
		}
	}

	return false
}

// GetTrackerBlockList returns list of tracker domains to block
func (ps *PrivacyService) GetTrackerBlockList(ctx context.Context, settings *models.PrivacySettings) []models.TrackerBlockRule {
	rules := make([]models.TrackerBlockRule, 0)

	for trackerID, tracker := range models.PrivacyTrackers {
		// Check if this category should be blocked
		shouldBlock := false
		if settings != nil {
			switch tracker.Category {
			case "advertising":
				shouldBlock = settings.BlockAds
			case "analytics":
				shouldBlock = settings.BlockAnalytics
			default:
				shouldBlock = settings.BlockTrackers
			}
		}

		if shouldBlock {
			for _, domain := range tracker.Domains {
				rules = append(rules, models.TrackerBlockRule{
					ID:        uuid.New(),
					TrackerID: trackerID,
					Domain:    domain,
					IsRegex:   false,
					Action:    "block",
					Enabled:   true,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				})
			}
		}
	}

	return rules
}

// AuditPrivacy performs a comprehensive privacy audit
func (ps *PrivacyService) AuditPrivacy(ctx context.Context, deviceID string, apps []models.AppPrivacyInfo) *models.PrivacyAuditResult {
	result := &models.PrivacyAuditResult{
		DeviceID:        deviceID,
		AuditedAt:       time.Now(),
		Issues:          make([]models.PrivacyIssue, 0),
		Recommendations: make([]string, 0),
		RiskyApps:       make([]models.AppPrivacyInfo, 0),
	}

	// Calculate category scores
	result.CameraPrivacy = ps.calculateCategoryScore(apps, models.PrivacyEventCameraAccess)
	result.MicrophonePrivacy = ps.calculateCategoryScore(apps, models.PrivacyEventMicrophoneAccess)
	result.LocationPrivacy = ps.calculateCategoryScore(apps, models.PrivacyEventLocationAccess)
	result.DataPrivacy = ps.calculateDataPrivacyScore(apps)
	result.NetworkPrivacy = ps.calculateNetworkPrivacyScore(apps)

	// Calculate overall score
	scores := []float64{
		result.CameraPrivacy.Score,
		result.MicrophonePrivacy.Score,
		result.LocationPrivacy.Score,
		result.DataPrivacy.Score,
		result.NetworkPrivacy.Score,
	}
	sum := 0.0
	for _, s := range scores {
		sum += s
	}
	result.OverallScore = sum / float64(len(scores))
	result.OverallGrade = scoreToGrade(result.OverallScore)

	// Determine overall risk level
	result.RiskLevel = scoreToRiskLevel(result.OverallScore)

	// Identify issues
	result.Issues = ps.identifyIssues(apps, result)

	// Generate recommendations
	result.Recommendations = ps.generateRecommendations(result)

	// Identify risky apps
	for _, app := range apps {
		if app.RiskLevel == models.PrivacyRiskHigh || app.RiskLevel == models.PrivacyRiskCritical {
			result.RiskyApps = append(result.RiskyApps, app)
		}
	}

	// Count trackers
	for _, app := range apps {
		result.TrackerCount += app.TrackerCount
	}

	return result
}

// GetPrivacyStats returns privacy statistics for a device
func (ps *PrivacyService) GetPrivacyStats(ctx context.Context, deviceID string, period string) *models.PrivacyStats {
	stats := &models.PrivacyStats{
		DeviceID:     deviceID,
		Period:       period,
		AccessByHour: make(map[int]int),
		AccessByDay:  make(map[string]int),
		GeneratedAt:  time.Now(),
	}

	// In production, this would query from database/cache
	// For now, return service-level stats
	stats.TrackersDetected = int(ps.trackersBlocked.Load())
	stats.TrackersBlocked = int(ps.trackersBlocked.Load())
	stats.AlertsSent = int(ps.alertsSent.Load())

	return stats
}

// GetKnownTrackers returns list of known trackers
func (ps *PrivacyService) GetKnownTrackers() map[string]models.TrackerInfo {
	return models.PrivacyTrackers
}

// GetTrackerByID returns a tracker by ID
func (ps *PrivacyService) GetTrackerByID(trackerID string) *models.TrackerInfo {
	if tracker, exists := models.PrivacyTrackers[trackerID]; exists {
		return &tracker
	}
	return nil
}

// GetStats returns service statistics
func (ps *PrivacyService) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"events_processed":   ps.eventsProcessed.Load(),
		"alerts_sent":        ps.alertsSent.Load(),
		"trackers_blocked":   ps.trackersBlocked.Load(),
		"sensitive_detected": ps.sensitiveDetected.Load(),
		"known_trackers":     len(models.PrivacyTrackers),
		"tracker_domains":    len(ps.trackerDomains),
	}
}

// Helper functions

func (ps *PrivacyService) calculateRiskLevel(event *models.PrivacyEvent) models.PrivacyRiskLevel {
	// Background access is always higher risk
	if event.IsBackground {
		switch event.EventType {
		case models.PrivacyEventCameraAccess, models.PrivacyEventMicrophoneAccess:
			return models.PrivacyRiskHigh
		case models.PrivacyEventLocationAccess:
			return models.PrivacyRiskMedium
		default:
			return models.PrivacyRiskMedium
		}
	}

	// Default risk levels by event type
	switch event.EventType {
	case models.PrivacyEventCameraAccess:
		return models.PrivacyRiskMedium
	case models.PrivacyEventMicrophoneAccess:
		return models.PrivacyRiskMedium
	case models.PrivacyEventClipboardRead:
		return models.PrivacyRiskLow
	case models.PrivacyEventScreenRecording:
		return models.PrivacyRiskMedium
	case models.PrivacyEventLocationAccess:
		return models.PrivacyRiskLow
	default:
		return models.PrivacyRiskInfo
	}
}

func (ps *PrivacyService) shouldAlert(event *models.PrivacyEvent) bool {
	// Alert on high/critical background access
	if event.IsBackground && (event.RiskLevel == models.PrivacyRiskHigh || event.RiskLevel == models.PrivacyRiskCritical) {
		return true
	}
	return false
}

func (ps *PrivacyService) sendAlert(ctx context.Context, event *models.PrivacyEvent) {
	ps.alertsSent.Add(1)

	alert := &models.PrivacyAlert{
		ID:          uuid.New(),
		DeviceID:    event.DeviceID,
		Type:        event.EventType,
		Severity:    event.RiskLevel,
		Title:       ps.getAlertTitle(event),
		Message:     ps.getAlertMessage(event),
		PackageName: event.PackageName,
		AppName:     event.AppName,
		CreatedAt:   time.Now(),
	}

	ps.logger.Warn().
		Str("device_id", event.DeviceID).
		Str("app", event.AppName).
		Str("event_type", string(event.EventType)).
		Str("risk_level", string(event.RiskLevel)).
		Msg("privacy alert sent")

	// In production, would send push notification and store alert
	_ = alert
}

func (ps *PrivacyService) getAlertTitle(event *models.PrivacyEvent) string {
	switch event.EventType {
	case models.PrivacyEventCameraAccess:
		if event.IsBackground {
			return "Background Camera Access Detected"
		}
		return "Camera Access"
	case models.PrivacyEventMicrophoneAccess:
		if event.IsBackground {
			return "Background Microphone Access Detected"
		}
		return "Microphone Access"
	case models.PrivacyEventClipboardRead:
		return "Clipboard Access Detected"
	case models.PrivacyEventScreenRecording:
		return "Screen Recording Detected"
	default:
		return "Privacy Event Detected"
	}
}

func (ps *PrivacyService) getAlertMessage(event *models.PrivacyEvent) string {
	if event.IsBackground {
		return event.AppName + " accessed " + string(event.EventType) + " in the background"
	}
	return event.AppName + " accessed " + string(event.EventType)
}

func (ps *PrivacyService) isClipboardHijacking(content string, sourceApp string) bool {
	// Known hijacking patterns
	hijackPatterns := []string{
		`^[13][a-zA-HJ-NP-Z0-9]{25,34}$`, // Bitcoin address replacement
		`^0x[a-fA-F0-9]{40}$`,            // Ethereum address replacement
	}

	for _, pattern := range hijackPatterns {
		matched, _ := regexp.MatchString(pattern, strings.TrimSpace(content))
		if matched {
			return true
		}
	}

	return false
}

func (ps *PrivacyService) getClipboardRecommendations(result *models.ClipboardProtectionResult) []string {
	recommendations := make([]string, 0)

	if result.WasHijacked {
		recommendations = append(recommendations, "Warning: Clipboard content may have been modified by a malicious app")
		recommendations = append(recommendations, "Verify any cryptocurrency addresses before sending funds")
	}

	for _, match := range result.SensitiveData {
		switch match.Type {
		case "credit_card":
			recommendations = append(recommendations, "Credit card number detected - clear clipboard after use")
		case "ssn":
			recommendations = append(recommendations, "SSN detected - clear clipboard immediately")
		case "password":
			recommendations = append(recommendations, "Password detected - use a password manager instead")
		case "crypto_wallet":
			recommendations = append(recommendations, "Cryptocurrency address detected - verify before pasting")
		}
	}

	return recommendations
}

func (ps *PrivacyService) calculateCategoryScore(apps []models.AppPrivacyInfo, eventType models.PrivacyEventType) models.CategoryScore {
	score := models.CategoryScore{
		Score: 100.0,
		Grade: "A",
	}

	for _, app := range apps {
		var access models.AccessSummary
		switch eventType {
		case models.PrivacyEventCameraAccess:
			access = app.CameraAccess
		case models.PrivacyEventMicrophoneAccess:
			access = app.MicrophoneAccess
		case models.PrivacyEventLocationAccess:
			access = app.LocationAccess
		case models.PrivacyEventClipboardRead:
			access = app.ClipboardAccess
		}

		score.EventCount += access.TotalAccess
		score.BackgroundUse += access.BackgroundUse
		if access.BackgroundUse > 0 {
			score.RiskyApps++
		}
	}

	// Deduct points for background access
	score.Score -= float64(score.BackgroundUse) * 5.0
	if score.Score < 0 {
		score.Score = 0
	}

	score.Grade = scoreToGrade(score.Score)

	return score
}

func (ps *PrivacyService) calculateDataPrivacyScore(apps []models.AppPrivacyInfo) models.CategoryScore {
	score := models.CategoryScore{
		Score: 100.0,
	}

	totalTrackers := 0
	for _, app := range apps {
		totalTrackers += app.TrackerCount
	}

	// Deduct points for trackers
	score.Score -= float64(totalTrackers) * 2.0
	if score.Score < 0 {
		score.Score = 0
	}

	score.Grade = scoreToGrade(score.Score)

	return score
}

func (ps *PrivacyService) calculateNetworkPrivacyScore(apps []models.AppPrivacyInfo) models.CategoryScore {
	score := models.CategoryScore{
		Score: 100.0,
	}

	// Would analyze network access patterns
	score.Grade = scoreToGrade(score.Score)

	return score
}

func (ps *PrivacyService) identifyIssues(apps []models.AppPrivacyInfo, result *models.PrivacyAuditResult) []models.PrivacyIssue {
	issues := make([]models.PrivacyIssue, 0)

	for _, app := range apps {
		// Background camera access
		if app.CameraAccess.BackgroundUse > 0 {
			issues = append(issues, models.PrivacyIssue{
				ID:          "bg_camera_" + app.PackageName,
				Type:        models.PrivacyEventCameraAccess,
				Severity:    models.PrivacyRiskHigh,
				Title:       "Background Camera Access",
				Description: app.AppName + " accessed the camera in the background",
				AffectedApp: app.AppName,
				Remediation: "Review app permissions and consider revoking camera access",
				AutoFixable: false,
			})
		}

		// Background mic access
		if app.MicrophoneAccess.BackgroundUse > 0 {
			issues = append(issues, models.PrivacyIssue{
				ID:          "bg_mic_" + app.PackageName,
				Type:        models.PrivacyEventMicrophoneAccess,
				Severity:    models.PrivacyRiskHigh,
				Title:       "Background Microphone Access",
				Description: app.AppName + " accessed the microphone in the background",
				AffectedApp: app.AppName,
				Remediation: "Review app permissions and consider revoking microphone access",
				AutoFixable: false,
			})
		}

		// Excessive trackers
		if app.TrackerCount > 5 {
			issues = append(issues, models.PrivacyIssue{
				ID:          "trackers_" + app.PackageName,
				Type:        models.PrivacyEventNetworkAccess,
				Severity:    models.PrivacyRiskMedium,
				Title:       "Excessive Trackers",
				Description: app.AppName + " contains " + string(rune(app.TrackerCount+'0')) + " trackers",
				AffectedApp: app.AppName,
				Remediation: "Enable tracker blocking in privacy settings",
				AutoFixable: true,
			})
		}
	}

	return issues
}

func (ps *PrivacyService) generateRecommendations(result *models.PrivacyAuditResult) []string {
	recommendations := make([]string, 0)

	if result.CameraPrivacy.BackgroundUse > 0 {
		recommendations = append(recommendations, "Review apps with background camera access")
	}

	if result.MicrophonePrivacy.BackgroundUse > 0 {
		recommendations = append(recommendations, "Review apps with background microphone access")
	}

	if result.TrackerCount > 10 {
		recommendations = append(recommendations, "Enable tracker blocking to improve privacy")
	}

	if result.OverallScore < 60 {
		recommendations = append(recommendations, "Consider uninstalling high-risk apps")
	}

	return recommendations
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func scoreToRiskLevel(score float64) models.PrivacyRiskLevel {
	switch {
	case score >= 80:
		return models.PrivacyRiskLow
	case score >= 60:
		return models.PrivacyRiskMedium
	case score >= 40:
		return models.PrivacyRiskHigh
	default:
		return models.PrivacyRiskCritical
	}
}

func maskSensitiveData(value string, dataType string) string {
	if len(value) < 4 {
		return "****"
	}

	switch dataType {
	case "credit_card":
		// Show last 4 digits
		return "****-****-****-" + value[len(value)-4:]
	case "ssn":
		return "***-**-" + value[len(value)-4:]
	case "phone":
		return "***-***-" + value[len(value)-4:]
	case "email":
		parts := strings.Split(value, "@")
		if len(parts) == 2 && len(parts[0]) > 2 {
			return parts[0][:2] + "***@" + parts[1]
		}
		return "***@***"
	default:
		if len(value) > 8 {
			return value[:2] + "****" + value[len(value)-2:]
		}
		return "****"
	}
}
