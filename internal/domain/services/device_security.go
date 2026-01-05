package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// DeviceSecurityService handles device security operations
type DeviceSecurityService struct {
	cache  *cache.RedisCache
	logger *logger.Logger
	mu     sync.RWMutex

	// In-memory stores (in production, these would be database-backed)
	devices      map[string]*models.SecureDeviceInfo
	commands     map[string][]*models.RemoteCommand
	simInfo      map[string][]*models.SIMInfo
	simEvents    map[string][]*models.SIMChangeEvent
	selfies      map[string][]*models.ThiefSelfie
	settings     map[string]*models.AntiTheftSettings
	locations    map[string][]*models.Location

	// Stats
	commandsIssued   atomic.Int64
	commandsExecuted atomic.Int64
	simAlertsRaised  atomic.Int64
	selfiesTaken     atomic.Int64
	devicesTracked   atomic.Int64
}

// NewDeviceSecurityService creates a new device security service
func NewDeviceSecurityService(c *cache.RedisCache, log *logger.Logger) *DeviceSecurityService {
	return &DeviceSecurityService{
		cache:     c,
		logger:    log.WithComponent("device-security"),
		devices:   make(map[string]*models.SecureDeviceInfo),
		commands:  make(map[string][]*models.RemoteCommand),
		simInfo:   make(map[string][]*models.SIMInfo),
		simEvents: make(map[string][]*models.SIMChangeEvent),
		selfies:   make(map[string][]*models.ThiefSelfie),
		settings:  make(map[string]*models.AntiTheftSettings),
		locations: make(map[string][]*models.Location),
	}
}

// RegisterDevice registers a new device for tracking
func (s *DeviceSecurityService) RegisterDevice(ctx context.Context, device *models.SecureDeviceInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}
	device.RegisteredAt = time.Now()
	device.UpdatedAt = time.Now()
	device.LastSeen = time.Now()
	device.Status = models.DeviceStatusActive

	s.devices[device.DeviceID] = device
	s.devicesTracked.Add(1)

	// Initialize default settings
	s.settings[device.DeviceID] = &models.AntiTheftSettings{
		DeviceID:             device.DeviceID,
		EnableRemoteLocate:   true,
		EnableRemoteLock:     true,
		EnableRemoteWipe:     false, // Disabled by default for safety
		EnableThiefSelfie:    true,
		EnableSIMAlert:       true,
		SelfieOnWrongPIN:     true,
		SelfieOnWrongPattern: true,
		SelfieAfterAttempts:  3,
		AlertPushEnabled:     true,
		UpdatedAt:            time.Now(),
	}

	s.logger.Info().
		Str("device_id", device.DeviceID).
		Str("model", device.Model).
		Str("platform", device.Platform).
		Msg("device registered")

	return nil
}

// UpdateDevice updates device information
func (s *DeviceSecurityService) UpdateDevice(ctx context.Context, deviceID string, update *models.SecureDeviceInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	// Update fields
	if update.Name != "" {
		device.Name = update.Name
	}
	if update.OSVersion != "" {
		device.OSVersion = update.OSVersion
	}
	if update.SecurityPatch != "" {
		device.SecurityPatch = update.SecurityPatch
	}
	if update.APILevel > 0 {
		device.APILevel = update.APILevel
	}
	device.IsRooted = update.IsRooted
	device.IsEncrypted = update.IsEncrypted
	device.HasScreenLock = update.HasScreenLock
	if update.BiometricType != "" {
		device.BiometricType = update.BiometricType
	}
	device.LastSeen = time.Now()
	device.UpdatedAt = time.Now()

	return nil
}

// GetDevice returns device information
func (s *DeviceSecurityService) GetDevice(ctx context.Context, deviceID string) (*models.SecureDeviceInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	return device, nil
}

// UpdateLocation updates device location
func (s *DeviceSecurityService) UpdateLocation(ctx context.Context, deviceID string, location *models.Location) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	location.Timestamp = time.Now()
	device.LastLocation = location
	device.LastSeen = time.Now()

	// Store location history (keep last 100)
	s.locations[deviceID] = append(s.locations[deviceID], location)
	if len(s.locations[deviceID]) > 100 {
		s.locations[deviceID] = s.locations[deviceID][1:]
	}

	return nil
}

// GetLocationHistory returns location history for a device
func (s *DeviceSecurityService) GetLocationHistory(ctx context.Context, deviceID string, limit int) ([]*models.Location, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	locations := s.locations[deviceID]
	if limit > 0 && len(locations) > limit {
		locations = locations[len(locations)-limit:]
	}

	return locations, nil
}

// IssueCommand issues a remote command to a device
func (s *DeviceSecurityService) IssueCommand(ctx context.Context, cmd *models.RemoteCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate device exists
	device, exists := s.devices[cmd.DeviceID]
	if !exists {
		return fmt.Errorf("device not found: %s", cmd.DeviceID)
	}

	// Check settings
	settings := s.settings[cmd.DeviceID]
	if settings != nil {
		switch cmd.Type {
		case models.CommandLocate:
			if !settings.EnableRemoteLocate {
				return fmt.Errorf("remote locate is disabled for this device")
			}
		case models.CommandLock, models.CommandUnlock:
			if !settings.EnableRemoteLock {
				return fmt.Errorf("remote lock is disabled for this device")
			}
		case models.CommandWipe:
			if !settings.EnableRemoteWipe {
				return fmt.Errorf("remote wipe is disabled for this device")
			}
			// Require confirmation for wipe
			var payload models.WipeCommandPayload
			if err := json.Unmarshal([]byte(cmd.Payload), &payload); err != nil || payload.ConfirmationID == "" {
				return fmt.Errorf("wipe command requires valid confirmation_id")
			}
		case models.CommandTakeSelfie:
			if !settings.EnableThiefSelfie {
				return fmt.Errorf("thief selfie is disabled for this device")
			}
		}
	}

	// Initialize command
	if cmd.ID == uuid.Nil {
		cmd.ID = uuid.New()
	}
	cmd.Status = models.CommandStatusPending
	cmd.CreatedAt = time.Now()
	cmd.ExpiresAt = time.Now().Add(24 * time.Hour) // Commands expire after 24 hours

	// Store command
	s.commands[cmd.DeviceID] = append(s.commands[cmd.DeviceID], cmd)
	s.commandsIssued.Add(1)

	// Update device status based on command
	switch cmd.Type {
	case models.CommandLock:
		device.Status = models.DeviceStatusLocked
	case models.CommandWipe:
		device.Status = models.DeviceStatusWiped
	}

	s.logger.Info().
		Str("device_id", cmd.DeviceID).
		Str("command", string(cmd.Type)).
		Str("command_id", cmd.ID.String()).
		Msg("command issued")

	return nil
}

// GetPendingCommands returns pending commands for a device
func (s *DeviceSecurityService) GetPendingCommands(ctx context.Context, deviceID string) ([]*models.RemoteCommand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	commands := s.commands[deviceID]
	pending := make([]*models.RemoteCommand, 0)

	now := time.Now()
	for _, cmd := range commands {
		if cmd.Status == models.CommandStatusPending && cmd.ExpiresAt.After(now) {
			pending = append(pending, cmd)
		}
	}

	return pending, nil
}

// AcknowledgeCommand marks a command as executed
func (s *DeviceSecurityService) AcknowledgeCommand(ctx context.Context, deviceID string, commandID uuid.UUID, result string, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	commands := s.commands[deviceID]
	for _, cmd := range commands {
		if cmd.ID == commandID {
			now := time.Now()
			cmd.ExecutedAt = &now
			cmd.Result = result
			if err != nil {
				cmd.Status = models.CommandStatusFailed
				cmd.Error = err.Error()
			} else {
				cmd.Status = models.CommandStatusExecuted
				s.commandsExecuted.Add(1)
			}
			return nil
		}
	}

	return fmt.Errorf("command not found: %s", commandID)
}

// ReportSIMInfo reports current SIM information
func (s *DeviceSecurityService) ReportSIMInfo(ctx context.Context, deviceID string, sims []*models.SIMInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldSIMs := s.simInfo[deviceID]

	// Check for changes
	for _, newSIM := range sims {
		if newSIM.ID == uuid.Nil {
			newSIM.ID = uuid.New()
		}
		newSIM.LastSeen = time.Now()

		// Check if this is a new SIM
		isNew := true
		for _, oldSIM := range oldSIMs {
			if oldSIM.ICCID == newSIM.ICCID {
				isNew = false
				oldSIM.LastSeen = time.Now()
				oldSIM.IsActive = newSIM.IsActive
				break
			}
		}

		if isNew {
			newSIM.FirstSeen = time.Now()

			// Create SIM change event
			event := &models.SIMChangeEvent{
				ID:         uuid.New(),
				DeviceID:   deviceID,
				EventType:  models.SIMEventInserted,
				NewSIM:     newSIM,
				DetectedAt: time.Now(),
			}

			// Calculate risk level
			event.RiskLevel = s.calculateSIMRisk(deviceID, event)

			s.simEvents[deviceID] = append(s.simEvents[deviceID], event)

			// Alert if high risk
			if event.RiskLevel == models.SIMRiskCritical || event.RiskLevel == models.SIMRiskHigh {
				s.simAlertsRaised.Add(1)
				event.IsAlerted = true
				now := time.Now()
				event.AlertedAt = &now

				s.logger.Warn().
					Str("device_id", deviceID).
					Str("iccid", newSIM.ICCID).
					Str("carrier", newSIM.Carrier).
					Str("risk", string(event.RiskLevel)).
					Msg("SIM change alert")
			}
		}
	}

	// Check for removed SIMs
	for _, oldSIM := range oldSIMs {
		found := false
		for _, newSIM := range sims {
			if oldSIM.ICCID == newSIM.ICCID {
				found = true
				break
			}
		}
		if !found && oldSIM.IsActive {
			event := &models.SIMChangeEvent{
				ID:         uuid.New(),
				DeviceID:   deviceID,
				EventType:  models.SIMEventRemoved,
				OldSIM:     oldSIM,
				RiskLevel:  models.SIMRiskHigh,
				DetectedAt: time.Now(),
			}
			s.simEvents[deviceID] = append(s.simEvents[deviceID], event)
			s.simAlertsRaised.Add(1)

			s.logger.Warn().
				Str("device_id", deviceID).
				Str("iccid", oldSIM.ICCID).
				Msg("SIM removed alert")
		}
	}

	s.simInfo[deviceID] = sims
	return nil
}

// calculateSIMRisk calculates the risk level of a SIM change
func (s *DeviceSecurityService) calculateSIMRisk(deviceID string, event *models.SIMChangeEvent) models.SIMRiskLevel {
	settings := s.settings[deviceID]

	// Check if SIM is in trusted list
	if settings != nil && event.NewSIM != nil {
		for _, trustedICCID := range settings.TrustedSIMICCIDs {
			if event.NewSIM.ICCID == trustedICCID {
				return models.SIMRiskLow
			}
		}
	}

	// Check for suspicious patterns
	device := s.devices[deviceID]
	if device != nil {
		// If device was reported lost/stolen, any SIM change is critical
		if device.Status == models.DeviceStatusLost || device.Status == models.DeviceStatusStolen {
			return models.SIMRiskCritical
		}
	}

	// Check timing - SIM changes at unusual hours are higher risk
	hour := time.Now().Hour()
	if hour >= 0 && hour < 6 {
		return models.SIMRiskHigh
	}

	// Check if location changed significantly
	if event.Location != nil && device != nil && device.LastLocation != nil {
		// Simple distance check (would use proper haversine in production)
		latDiff := event.Location.Latitude - device.LastLocation.Latitude
		lonDiff := event.Location.Longitude - device.LastLocation.Longitude
		if latDiff*latDiff+lonDiff*lonDiff > 0.01 { // ~1km at equator
			return models.SIMRiskHigh
		}
	}

	// Default to medium risk for unknown SIMs
	return models.SIMRiskMedium
}

// GetSIMHistory returns SIM change history for a device
func (s *DeviceSecurityService) GetSIMHistory(ctx context.Context, deviceID string) ([]*models.SIMChangeEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.simEvents[deviceID], nil
}

// GetCurrentSIMs returns current SIM information for a device
func (s *DeviceSecurityService) GetCurrentSIMs(ctx context.Context, deviceID string) ([]*models.SIMInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.simInfo[deviceID], nil
}

// AddTrustedSIM adds a SIM to the trusted list
func (s *DeviceSecurityService) AddTrustedSIM(ctx context.Context, deviceID string, iccid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	settings := s.settings[deviceID]
	if settings == nil {
		settings = &models.AntiTheftSettings{DeviceID: deviceID}
		s.settings[deviceID] = settings
	}

	// Check if already trusted
	for _, trusted := range settings.TrustedSIMICCIDs {
		if trusted == iccid {
			return nil
		}
	}

	settings.TrustedSIMICCIDs = append(settings.TrustedSIMICCIDs, iccid)
	settings.UpdatedAt = time.Now()

	return nil
}

// RecordThiefSelfie records a thief selfie capture
func (s *DeviceSecurityService) RecordThiefSelfie(ctx context.Context, selfie *models.ThiefSelfie) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if selfie.ID == uuid.Nil {
		selfie.ID = uuid.New()
	}
	selfie.CapturedAt = time.Now()

	s.selfies[selfie.DeviceID] = append(s.selfies[selfie.DeviceID], selfie)
	s.selfiesTaken.Add(1)

	s.logger.Warn().
		Str("device_id", selfie.DeviceID).
		Str("trigger", selfie.TriggerType).
		Int("attempts", selfie.AttemptCount).
		Msg("thief selfie captured")

	return nil
}

// GetThiefSelfies returns thief selfies for a device
func (s *DeviceSecurityService) GetThiefSelfies(ctx context.Context, deviceID string) ([]*models.ThiefSelfie, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.selfies[deviceID], nil
}

// GetSettings returns anti-theft settings for a device
func (s *DeviceSecurityService) GetSettings(ctx context.Context, deviceID string) (*models.AntiTheftSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	settings := s.settings[deviceID]
	if settings == nil {
		// Return default settings
		return &models.AntiTheftSettings{
			DeviceID:             deviceID,
			EnableRemoteLocate:   true,
			EnableRemoteLock:     true,
			EnableRemoteWipe:     false,
			EnableThiefSelfie:    true,
			EnableSIMAlert:       true,
			SelfieOnWrongPIN:     true,
			SelfieOnWrongPattern: true,
			SelfieAfterAttempts:  3,
			AlertPushEnabled:     true,
		}, nil
	}

	return settings, nil
}

// UpdateSettings updates anti-theft settings
func (s *DeviceSecurityService) UpdateSettings(ctx context.Context, deviceID string, update *models.AntiTheftSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	settings := s.settings[deviceID]
	if settings == nil {
		settings = &models.AntiTheftSettings{DeviceID: deviceID}
		s.settings[deviceID] = settings
	}

	settings.EnableRemoteLocate = update.EnableRemoteLocate
	settings.EnableRemoteLock = update.EnableRemoteLock
	settings.EnableRemoteWipe = update.EnableRemoteWipe
	settings.EnableThiefSelfie = update.EnableThiefSelfie
	settings.EnableSIMAlert = update.EnableSIMAlert
	settings.SelfieOnWrongPIN = update.SelfieOnWrongPIN
	settings.SelfieOnWrongPattern = update.SelfieOnWrongPattern
	settings.SelfieAfterAttempts = update.SelfieAfterAttempts
	settings.AlertEmail = update.AlertEmail
	settings.AlertPhone = update.AlertPhone
	settings.AlertPushEnabled = update.AlertPushEnabled
	settings.UpdatedAt = time.Now()

	return nil
}

// MarkDeviceLost marks a device as lost
func (s *DeviceSecurityService) MarkDeviceLost(ctx context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	device.Status = models.DeviceStatusLost
	device.UpdatedAt = time.Now()

	s.logger.Warn().Str("device_id", deviceID).Msg("device marked as lost")

	return nil
}

// MarkDeviceStolen marks a device as stolen
func (s *DeviceSecurityService) MarkDeviceStolen(ctx context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	device.Status = models.DeviceStatusStolen
	device.UpdatedAt = time.Now()

	s.logger.Warn().Str("device_id", deviceID).Msg("device marked as stolen")

	return nil
}

// MarkDeviceRecovered marks a device as recovered/active
func (s *DeviceSecurityService) MarkDeviceRecovered(ctx context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, exists := s.devices[deviceID]
	if !exists {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	device.Status = models.DeviceStatusActive
	device.UpdatedAt = time.Now()

	s.logger.Info().Str("device_id", deviceID).Msg("device marked as recovered")

	return nil
}

// AuditOSVulnerabilities checks device OS for known vulnerabilities
func (s *DeviceSecurityService) AuditOSVulnerabilities(ctx context.Context, deviceID string, platform string, osVersion string, securityPatch string, apiLevel int) *models.OSSecurityAuditResult {
	result := &models.OSSecurityAuditResult{
		DeviceID:      deviceID,
		Platform:      platform,
		OSVersion:     osVersion,
		SecurityPatch: securityPatch,
		APILevel:      apiLevel,
		AuditedAt:     time.Now(),
		Vulnerabilities: make([]models.OSVulnerability, 0),
		Recommendations: make([]models.SecurityRecommendation, 0),
	}

	// Get relevant vulnerabilities
	var vulns []models.OSVulnerability
	var latestInfo models.LatestSecurityInfo

	if strings.ToLower(platform) == "android" {
		vulns = models.KnownAndroidVulnerabilities
		latestInfo = models.LatestAndroidSecurity
	} else if strings.ToLower(platform) == "ios" {
		vulns = models.KnowniOSVulnerabilities
		latestInfo = models.LatestiOSSecurity
	}

	result.LatestOSVersion = latestInfo.LatestVersion
	result.LatestPatchDate = latestInfo.LatestPatchDate

	// Check each vulnerability
	for _, vuln := range vulns {
		if s.isAffected(platform, osVersion, securityPatch, apiLevel, &vuln) {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)

			switch vuln.Severity {
			case models.VulnSeverityCritical:
				result.CriticalVulns++
			case models.VulnSeverityHigh:
				result.HighVulns++
			case models.VulnSeverityMedium:
				result.MediumVulns++
			case models.VulnSeverityLow:
				result.LowVulns++
			}

			if vuln.IsExploited {
				result.ExploitedVulns++
			}
		}
	}

	result.TotalVulns = len(result.Vulnerabilities)

	// Calculate risk score
	result.RiskScore = s.calculateOSRiskScore(result)
	result.RiskLevel = s.scoreToSeverity(result.RiskScore)

	// Check if up to date
	result.IsUpToDate = s.isOSUpToDate(platform, osVersion, securityPatch, latestInfo)

	// Calculate days behind
	result.DaysBehind = s.calculateDaysBehind(platform, securityPatch, latestInfo)

	// Generate recommendations
	result.Recommendations = s.generateOSRecommendations(result)

	return result
}

// isAffected checks if a device is affected by a vulnerability
func (s *DeviceSecurityService) isAffected(platform, osVersion, securityPatch string, apiLevel int, vuln *models.OSVulnerability) bool {
	// Check platform
	platformMatch := false
	for _, p := range vuln.AffectedOS {
		if strings.EqualFold(p, platform) {
			platformMatch = true
			break
		}
	}
	if !platformMatch {
		return false
	}

	// Check if patched
	if vuln.PatchedIn != "" && compareVersions(osVersion, vuln.PatchedIn) >= 0 {
		return false
	}

	if vuln.SecurityPatch != "" && securityPatch != "" && securityPatch >= vuln.SecurityPatch {
		return false
	}

	// Check version range
	for _, vr := range vuln.AffectedVersions {
		if vr.APILevel > 0 && apiLevel > 0 {
			if apiLevel >= vr.APILevel {
				continue // Not affected
			}
		}

		if vr.MinVersion != "" && compareVersions(osVersion, vr.MinVersion) < 0 {
			continue
		}
		if vr.MaxVersion != "" && compareVersions(osVersion, vr.MaxVersion) > 0 {
			continue
		}

		return true
	}

	return len(vuln.AffectedVersions) == 0 // If no specific versions, assume all affected
}

// compareVersions compares two version strings (simplified)
func compareVersions(v1, v2 string) int {
	// Split by common delimiters
	parts1 := strings.FieldsFunc(v1, func(r rune) bool { return r == '.' || r == '-' })
	parts2 := strings.FieldsFunc(v2, func(r rune) bool { return r == '.' || r == '-' })

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		if parts1[i] < parts2[i] {
			return -1
		}
		if parts1[i] > parts2[i] {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// calculateOSRiskScore calculates risk score based on vulnerabilities
func (s *DeviceSecurityService) calculateOSRiskScore(result *models.OSSecurityAuditResult) float64 {
	// Start with perfect score
	score := 100.0

	// Deduct for vulnerabilities
	score -= float64(result.CriticalVulns) * 25.0
	score -= float64(result.HighVulns) * 15.0
	score -= float64(result.MediumVulns) * 8.0
	score -= float64(result.LowVulns) * 3.0

	// Extra penalty for exploited vulnerabilities
	score -= float64(result.ExploitedVulns) * 10.0

	// Penalty for being behind on updates
	score -= float64(result.DaysBehind) * 0.5

	if score < 0 {
		score = 0
	}

	return score
}

// scoreToSeverity converts score to severity level
func (s *DeviceSecurityService) scoreToSeverity(score float64) models.VulnSeverity {
	switch {
	case score < 40:
		return models.VulnSeverityCritical
	case score < 60:
		return models.VulnSeverityHigh
	case score < 80:
		return models.VulnSeverityMedium
	default:
		return models.VulnSeverityLow
	}
}

// isOSUpToDate checks if OS is up to date
func (s *DeviceSecurityService) isOSUpToDate(platform, osVersion, securityPatch string, latest models.LatestSecurityInfo) bool {
	if platform == "android" && securityPatch != "" {
		return securityPatch >= latest.LatestPatchDate
	}
	return compareVersions(osVersion, latest.LatestVersion) >= 0
}

// calculateDaysBehind calculates how many days behind on security patches
func (s *DeviceSecurityService) calculateDaysBehind(platform, securityPatch string, latest models.LatestSecurityInfo) int {
	if securityPatch == "" {
		return 365 // Unknown, assume very old
	}

	// Parse security patch date (format: YYYY-MM-DD)
	patchDate, err := time.Parse("2006-01-02", securityPatch)
	if err != nil {
		return 90 // Unknown format
	}

	diff := time.Since(patchDate)
	days := int(diff.Hours() / 24)
	if days < 0 {
		days = 0
	}

	return days
}

// generateOSRecommendations generates security recommendations
func (s *DeviceSecurityService) generateOSRecommendations(result *models.OSSecurityAuditResult) []models.SecurityRecommendation {
	recs := make([]models.SecurityRecommendation, 0)
	priority := 1

	// Critical vulnerabilities
	if result.CriticalVulns > 0 {
		criticalCVEs := make([]string, 0)
		for _, v := range result.Vulnerabilities {
			if v.Severity == models.VulnSeverityCritical {
				criticalCVEs = append(criticalCVEs, v.ID)
			}
		}
		recs = append(recs, models.SecurityRecommendation{
			ID:          "update_critical",
			Priority:    priority,
			Title:       "Critical Security Update Required",
			Description: fmt.Sprintf("Your device has %d critical vulnerabilities that could allow attackers to take full control.", result.CriticalVulns),
			Action:      "Update your operating system immediately to the latest version.",
			AutoFixable: false,
			RelatedCVEs: criticalCVEs,
		})
		priority++
	}

	// Exploited vulnerabilities
	if result.ExploitedVulns > 0 {
		exploitedCVEs := make([]string, 0)
		for _, v := range result.Vulnerabilities {
			if v.IsExploited {
				exploitedCVEs = append(exploitedCVEs, v.ID)
			}
		}
		recs = append(recs, models.SecurityRecommendation{
			ID:          "exploited_vulns",
			Priority:    priority,
			Title:       "Actively Exploited Vulnerabilities",
			Description: fmt.Sprintf("Your device has %d vulnerabilities that are being actively exploited in the wild.", result.ExploitedVulns),
			Action:      "These vulnerabilities are being used by attackers. Update immediately.",
			AutoFixable: false,
			RelatedCVEs: exploitedCVEs,
		})
		priority++
	}

	// Outdated OS
	if !result.IsUpToDate {
		recs = append(recs, models.SecurityRecommendation{
			ID:          "outdated_os",
			Priority:    priority,
			Title:       "Operating System Out of Date",
			Description: fmt.Sprintf("Your device is %d days behind on security updates.", result.DaysBehind),
			Action:      fmt.Sprintf("Update to %s %s for the latest security patches.", result.Platform, result.LatestOSVersion),
			AutoFixable: false,
		})
		priority++
	}

	// High vulnerabilities
	if result.HighVulns > 0 {
		recs = append(recs, models.SecurityRecommendation{
			ID:          "high_vulns",
			Priority:    priority,
			Title:       "High Severity Vulnerabilities Present",
			Description: fmt.Sprintf("Your device has %d high severity vulnerabilities.", result.HighVulns),
			Action:      "Consider updating your device to address these security issues.",
			AutoFixable: false,
		})
		priority++
	}

	// Sort by priority
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].Priority < recs[j].Priority
	})

	return recs
}

// GetDeviceSecurityStatus returns comprehensive security status
func (s *DeviceSecurityService) GetDeviceSecurityStatus(ctx context.Context, deviceID string) (*models.DeviceSecurityStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	device := s.devices[deviceID]
	if device == nil {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	status := &models.DeviceSecurityStatus{
		DeviceID:   deviceID,
		DeviceInfo: device,
		LastCheck:  time.Now(),
		Issues:     make([]models.SecurityIssue, 0),
	}

	// Check if rooted
	if device.IsRooted {
		status.IsRooted = true
		status.Issues = append(status.Issues, models.SecurityIssue{
			ID:          "rooted_device",
			Type:        "root",
			Severity:    models.VulnSeverityHigh,
			Title:       "Device is Rooted/Jailbroken",
			Description: "Your device has root access enabled which increases security risks.",
			DetectedAt:  time.Now(),
		})
	}

	// Get anti-theft status
	settings := s.settings[deviceID]
	if settings != nil {
		status.AntiTheftEnabled = settings.EnableRemoteLocate || settings.EnableRemoteLock || settings.EnableRemoteWipe
	}

	// Get location
	status.LastLocation = device.LastLocation

	// Count pending commands
	for _, cmd := range s.commands[deviceID] {
		if cmd.Status == models.CommandStatusPending {
			status.PendingCommands++
		}
	}

	// Get SIM info
	sims := s.simInfo[deviceID]
	for _, sim := range sims {
		if sim.IsActive {
			status.CurrentSIM = sim
			break
		}
	}

	// Count SIM alerts
	for _, event := range s.simEvents[deviceID] {
		if event.IsAlerted {
			status.SIMChangeAlerts++
		}
	}

	// Run OS vulnerability audit
	osAudit := s.AuditOSVulnerabilities(ctx, deviceID, device.Platform, device.OSVersion, device.SecurityPatch, device.APILevel)
	status.OSSecurityScore = osAudit.RiskScore
	status.HasOSVulns = osAudit.TotalVulns > 0

	// Add OS vulnerability issues
	for _, vuln := range osAudit.Vulnerabilities {
		if vuln.Severity == models.VulnSeverityCritical || vuln.Severity == models.VulnSeverityHigh {
			status.Issues = append(status.Issues, models.SecurityIssue{
				ID:          vuln.ID,
				Type:        "os_vuln",
				Severity:    vuln.Severity,
				Title:       vuln.Title,
				Description: vuln.Description,
				DetectedAt:  time.Now(),
			})
		}
	}

	// Calculate overall score (weighted average)
	status.OverallScore = status.OSSecurityScore * 0.4
	if !device.IsRooted {
		status.OverallScore += 20.0
	}
	if device.IsEncrypted {
		status.OverallScore += 15.0
	}
	if device.HasScreenLock {
		status.OverallScore += 15.0
	}
	if status.AntiTheftEnabled {
		status.OverallScore += 10.0
	}

	// Top recommendations
	status.TopRecommendations = osAudit.Recommendations
	if len(status.TopRecommendations) > 3 {
		status.TopRecommendations = status.TopRecommendations[:3]
	}

	return status, nil
}

// GetStats returns service statistics
func (s *DeviceSecurityService) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"devices_tracked":     s.devicesTracked.Load(),
		"commands_issued":     s.commandsIssued.Load(),
		"commands_executed":   s.commandsExecuted.Load(),
		"sim_alerts_raised":   s.simAlertsRaised.Load(),
		"selfies_taken":       s.selfiesTaken.Load(),
		"android_vulns":       len(models.KnownAndroidVulnerabilities),
		"ios_vulns":           len(models.KnowniOSVulnerabilities),
	}
}
