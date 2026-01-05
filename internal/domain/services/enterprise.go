package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// ============================================================================
// MDM Service
// ============================================================================

// MDMService handles MDM/UEM integrations
type MDMService struct {
	repos   *repository.Repositories
	cache   *cache.RedisCache
	logger  *logger.Logger

	// In-memory config store (in production, use database)
	configs map[uuid.UUID]*models.MDMIntegrationConfig
	devices map[uuid.UUID]*models.MDMDevice
	mu      sync.RWMutex

	// HTTP client for MDM API calls
	httpClient *http.Client
}

// NewMDMService creates a new MDM service
func NewMDMService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *MDMService {
	return &MDMService{
		repos:   repos,
		cache:   cache,
		logger:  log.WithComponent("mdm"),
		configs: make(map[uuid.UUID]*models.MDMIntegrationConfig),
		devices: make(map[uuid.UUID]*models.MDMDevice),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateIntegration creates a new MDM integration
func (s *MDMService) CreateIntegration(ctx context.Context, config *models.MDMIntegrationConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config.ID = uuid.New()
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	s.configs[config.ID] = config

	s.logger.Info().
		Str("id", config.ID.String()).
		Str("provider", string(config.Provider)).
		Str("name", config.Name).
		Msg("MDM integration created")

	return nil
}

// GetIntegration retrieves an MDM integration
func (s *MDMService) GetIntegration(id uuid.UUID) (*models.MDMIntegrationConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	config, ok := s.configs[id]
	if !ok {
		return nil, fmt.Errorf("integration not found: %s", id)
	}
	return config, nil
}

// ListIntegrations lists all MDM integrations
func (s *MDMService) ListIntegrations() []*models.MDMIntegrationConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.MDMIntegrationConfig, 0, len(s.configs))
	for _, config := range s.configs {
		result = append(result, config)
	}
	return result
}

// UpdateIntegration updates an MDM integration
func (s *MDMService) UpdateIntegration(ctx context.Context, config *models.MDMIntegrationConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.configs[config.ID]; !ok {
		return fmt.Errorf("integration not found: %s", config.ID)
	}

	config.UpdatedAt = time.Now()
	s.configs[config.ID] = config
	return nil
}

// DeleteIntegration deletes an MDM integration
func (s *MDMService) DeleteIntegration(id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.configs[id]; !ok {
		return fmt.Errorf("integration not found: %s", id)
	}

	delete(s.configs, id)
	return nil
}

// SyncDevices syncs devices from MDM provider
func (s *MDMService) SyncDevices(ctx context.Context, configID uuid.UUID) error {
	config, err := s.GetIntegration(configID)
	if err != nil {
		return err
	}

	s.logger.Info().
		Str("config_id", configID.String()).
		Str("provider", string(config.Provider)).
		Msg("starting device sync")

	var syncErr error
	var deviceCount int

	switch config.Provider {
	case models.MDMProviderIntune:
		deviceCount, syncErr = s.syncIntuneDevices(ctx, config)
	case models.MDMProviderWorkspaceONE:
		deviceCount, syncErr = s.syncWorkspaceONEDevices(ctx, config)
	case models.MDMProviderJamf:
		deviceCount, syncErr = s.syncJamfDevices(ctx, config)
	default:
		syncErr = fmt.Errorf("unsupported provider: %s", config.Provider)
	}

	// Update sync status
	s.mu.Lock()
	now := time.Now()
	config.LastSyncAt = &now
	if syncErr != nil {
		config.LastSyncStatus = "failed"
		config.LastSyncError = syncErr.Error()
	} else {
		config.LastSyncStatus = "success"
		config.LastSyncError = ""
		config.DevicesSynced = deviceCount
	}
	s.mu.Unlock()

	return syncErr
}

// syncIntuneDevices syncs devices from Microsoft Intune
func (s *MDMService) syncIntuneDevices(ctx context.Context, config *models.MDMIntegrationConfig) (int, error) {
	// In production, this would call the Microsoft Graph API
	// GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices

	s.logger.Debug().
		Str("tenant_id", config.TenantID).
		Msg("syncing Intune devices (simulated)")

	// Simulated response for development
	return 0, nil
}

// syncWorkspaceONEDevices syncs devices from VMware Workspace ONE
func (s *MDMService) syncWorkspaceONEDevices(ctx context.Context, config *models.MDMIntegrationConfig) (int, error) {
	// In production, this would call the Workspace ONE API
	// GET {baseURL}/api/mdm/devices/search

	s.logger.Debug().
		Str("base_url", config.BaseURL).
		Msg("syncing Workspace ONE devices (simulated)")

	return 0, nil
}

// syncJamfDevices syncs devices from Jamf Pro
func (s *MDMService) syncJamfDevices(ctx context.Context, config *models.MDMIntegrationConfig) (int, error) {
	// In production, this would call the Jamf Pro API
	// GET {baseURL}/JSSResource/mobiledevices

	s.logger.Debug().
		Str("base_url", config.BaseURL).
		Msg("syncing Jamf devices (simulated)")

	return 0, nil
}

// SendThreatAlert sends a threat alert to MDM
func (s *MDMService) SendThreatAlert(ctx context.Context, alert *models.MDMThreatAlert) error {
	config, err := s.GetIntegration(alert.MDMConfigID)
	if err != nil {
		return err
	}

	if !config.PushThreatAlerts {
		return fmt.Errorf("threat alerts disabled for this integration")
	}

	s.logger.Info().
		Str("device_id", alert.DeviceID.String()).
		Str("threat_type", alert.ThreatType).
		Str("severity", string(alert.Severity)).
		Msg("sending threat alert to MDM")

	var sendErr error
	switch config.Provider {
	case models.MDMProviderIntune:
		sendErr = s.sendIntuneAlert(ctx, config, alert)
	case models.MDMProviderWorkspaceONE:
		sendErr = s.sendWorkspaceONEAlert(ctx, config, alert)
	case models.MDMProviderJamf:
		sendErr = s.sendJamfAlert(ctx, config, alert)
	default:
		sendErr = fmt.Errorf("unsupported provider: %s", config.Provider)
	}

	// Update alert status
	now := time.Now()
	if sendErr != nil {
		alert.Status = "failed"
		alert.Error = sendErr.Error()
	} else {
		alert.Status = "sent"
		alert.SentAt = &now
	}

	return sendErr
}

func (s *MDMService) sendIntuneAlert(ctx context.Context, config *models.MDMIntegrationConfig, alert *models.MDMThreatAlert) error {
	// Microsoft Defender for Endpoint integration
	s.logger.Debug().Msg("sending Intune threat alert (simulated)")
	return nil
}

func (s *MDMService) sendWorkspaceONEAlert(ctx context.Context, config *models.MDMIntegrationConfig, alert *models.MDMThreatAlert) error {
	s.logger.Debug().Msg("sending Workspace ONE threat alert (simulated)")
	return nil
}

func (s *MDMService) sendJamfAlert(ctx context.Context, config *models.MDMIntegrationConfig, alert *models.MDMThreatAlert) error {
	s.logger.Debug().Msg("sending Jamf threat alert (simulated)")
	return nil
}

// GetMDMDevice retrieves an MDM device
func (s *MDMService) GetMDMDevice(deviceID uuid.UUID) (*models.MDMDevice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	device, ok := s.devices[deviceID]
	if !ok {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}
	return device, nil
}

// ListMDMDevices lists MDM devices for a config
func (s *MDMService) ListMDMDevices(configID uuid.UUID) []*models.MDMDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.MDMDevice, 0)
	for _, device := range s.devices {
		if device.MDMConfigID == configID {
			result = append(result, device)
		}
	}
	return result
}

// GetMDMStats returns MDM statistics
func (s *MDMService) GetMDMStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	compliantCount := 0
	for _, device := range s.devices {
		if device.ComplianceStatus == "compliant" {
			compliantCount++
		}
	}

	return map[string]interface{}{
		"total_integrations": len(s.configs),
		"total_devices":      len(s.devices),
		"compliant_devices":  compliantCount,
	}
}

// ============================================================================
// Zero Trust Service
// ============================================================================

// ZeroTrustService handles Zero Trust / Conditional Access
type ZeroTrustService struct {
	repos   *repository.Repositories
	cache   *cache.RedisCache
	logger  *logger.Logger

	// Policies
	policies map[uuid.UUID]*models.ConditionalAccessPolicy
	mu       sync.RWMutex
}

// NewZeroTrustService creates a new Zero Trust service
func NewZeroTrustService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *ZeroTrustService {
	svc := &ZeroTrustService{
		repos:    repos,
		cache:    cache,
		logger:   log.WithComponent("zero-trust"),
		policies: make(map[uuid.UUID]*models.ConditionalAccessPolicy),
	}

	// Add default policies
	svc.initDefaultPolicies()

	return svc
}

// initDefaultPolicies creates default conditional access policies
func (s *ZeroTrustService) initDefaultPolicies() {
	minScore := 70
	lowTrust := models.TrustLevelLow

	policies := []*models.ConditionalAccessPolicy{
		{
			ID:          uuid.New(),
			Name:        "Block Untrusted Devices",
			Description: "Block access from devices with low trust scores",
			Enabled:     true,
			Priority:    1,
			Conditions: models.AccessConditions{
				MinTrustLevel:    &lowTrust,
				MinPostureScore:  &minScore,
			},
			GrantControls: models.GrantControls{
				Operator:   "AND",
				RequireMFA: true,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Require MFA for External Networks",
			Description: "Require MFA when accessing from non-corporate networks",
			Enabled:     true,
			Priority:    2,
			Conditions: models.AccessConditions{
				RequireSecureNetwork: true,
			},
			GrantControls: models.GrantControls{
				Operator:   "AND",
				RequireMFA: true,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Block on Active Threats",
			Description: "Block access when device has active threats",
			Enabled:     true,
			Priority:    0, // Highest priority
			Conditions: models.AccessConditions{
				BlockOnActiveThreats: true,
			},
			GrantControls: models.GrantControls{
				Operator: "AND",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, policy := range policies {
		s.policies[policy.ID] = policy
	}
}

// AssessDevicePosture evaluates device security posture
func (s *ZeroTrustService) AssessDevicePosture(ctx context.Context, deviceID uuid.UUID) (*models.DevicePosture, error) {
	s.logger.Debug().
		Str("device_id", deviceID.String()).
		Msg("assessing device posture")

	posture := &models.DevicePosture{
		DeviceID:           deviceID,
		LastAssessedAt:     time.Now(),
		NextAssessmentAt:   time.Now().Add(15 * time.Minute),
		AssessmentVersion:  "1.0",
		RiskFactors:        make([]models.RiskFactor, 0),
		TrustSignals:       make([]models.TrustSignal, 0),
		Recommendations:    make([]string, 0),
	}

	// Calculate component scores (simulated - in production would query device state)
	posture.OSSecurityScore = 85
	posture.AppSecurityScore = 78
	posture.NetworkSecurityScore = 90
	posture.BehaviorScore = 82
	posture.ComplianceScore = 88

	// Calculate overall score (weighted average)
	posture.OverallScore = (posture.OSSecurityScore*25 +
		posture.AppSecurityScore*20 +
		posture.NetworkSecurityScore*20 +
		posture.BehaviorScore*15 +
		posture.ComplianceScore*20) / 100

	// Determine trust level
	switch {
	case posture.OverallScore >= 90:
		posture.TrustLevel = models.TrustLevelHigh
	case posture.OverallScore >= 70:
		posture.TrustLevel = models.TrustLevelMedium
	case posture.OverallScore >= 50:
		posture.TrustLevel = models.TrustLevelLow
	default:
		posture.TrustLevel = models.TrustLevelUntrusted
	}

	// Add trust signals
	posture.TrustSignals = append(posture.TrustSignals, models.TrustSignal{
		Type:        "encryption",
		Name:        "Device Encryption Enabled",
		Description: "Device storage is encrypted",
		Value:       10,
	})

	// Generate recommendations
	if posture.OSSecurityScore < 80 {
		posture.Recommendations = append(posture.Recommendations, "Update device to latest OS version")
	}
	if posture.AppSecurityScore < 80 {
		posture.Recommendations = append(posture.Recommendations, "Review and remove high-risk applications")
	}

	// Cache the posture
	if s.cache != nil {
		cacheKey := fmt.Sprintf("posture:%s", deviceID.String())
		data, _ := json.Marshal(posture)
		s.cache.Set(ctx, cacheKey, string(data), 15*time.Minute)
	}

	return posture, nil
}

// EvaluateAccess evaluates access request against policies
func (s *ZeroTrustService) EvaluateAccess(ctx context.Context, req *AccessRequest) (*models.AccessDecision, error) {
	s.logger.Debug().
		Str("device_id", req.DeviceID.String()).
		Str("resource", req.ResourceID).
		Msg("evaluating access request")

	decision := &models.AccessDecision{
		ID:         uuid.New(),
		DeviceID:   req.DeviceID,
		UserID:     req.UserID,
		ResourceID: req.ResourceID,
		Location:   req.Location,
		IPAddress:  req.IPAddress,
		UserAgent:  req.UserAgent,
		CreatedAt:  time.Now(),
	}

	// Get device posture
	posture, err := s.AssessDevicePosture(ctx, req.DeviceID)
	if err != nil {
		decision.Decision = "deny"
		decision.Reason = "Failed to assess device posture"
		return decision, nil
	}
	decision.DevicePosture = posture

	// Check for active threats
	if req.HasActiveThreats {
		decision.Decision = "deny"
		decision.Reason = "Device has active security threats"
		return decision, nil
	}

	// Evaluate policies in priority order
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, policy := range s.policies {
		if !policy.Enabled {
			continue
		}

		if s.policyApplies(policy, req, posture) {
			if s.conditionsMet(policy, req, posture) {
				decision.PolicyID = &policy.ID
				decision.Decision = "allow"
				decision.Reason = fmt.Sprintf("Policy '%s' conditions met", policy.Name)

				// Check if MFA required
				if policy.GrantControls.RequireMFA && !req.MFACompleted {
					decision.Decision = "challenge"
					decision.ChallengeType = "mfa"
					decision.ChallengeStatus = "pending"
					decision.Reason = "MFA required"
				}
				return decision, nil
			} else {
				decision.PolicyID = &policy.ID
				decision.Decision = "deny"
				decision.Reason = fmt.Sprintf("Policy '%s' conditions not met", policy.Name)
				return decision, nil
			}
		}
	}

	// Default allow if no policies match
	decision.Decision = "allow"
	decision.Reason = "No blocking policies applied"
	return decision, nil
}

// AccessRequest represents an access request
type AccessRequest struct {
	DeviceID         uuid.UUID
	UserID           string
	ResourceID       string
	Location         string
	IPAddress        string
	UserAgent        string
	HasActiveThreats bool
	MFACompleted     bool
}

func (s *ZeroTrustService) policyApplies(policy *models.ConditionalAccessPolicy, req *AccessRequest, posture *models.DevicePosture) bool {
	// Check user/group assignments
	if len(policy.IncludeUsers) > 0 {
		found := false
		for _, u := range policy.IncludeUsers {
			if u == req.UserID || u == "all" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check app assignments
	if len(policy.IncludeApps) > 0 {
		found := false
		for _, app := range policy.IncludeApps {
			if app == req.ResourceID || app == "all" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (s *ZeroTrustService) conditionsMet(policy *models.ConditionalAccessPolicy, req *AccessRequest, posture *models.DevicePosture) bool {
	cond := policy.Conditions

	// Check trust level
	if cond.MinTrustLevel != nil {
		if !s.trustLevelSufficient(posture.TrustLevel, *cond.MinTrustLevel) {
			return false
		}
	}

	// Check posture score
	if cond.MinPostureScore != nil && posture.OverallScore < *cond.MinPostureScore {
		return false
	}

	// Check active threats
	if cond.BlockOnActiveThreats && req.HasActiveThreats {
		return false
	}

	return true
}

func (s *ZeroTrustService) trustLevelSufficient(actual, required models.TrustLevel) bool {
	levels := map[models.TrustLevel]int{
		models.TrustLevelHigh:      4,
		models.TrustLevelMedium:    3,
		models.TrustLevelLow:       2,
		models.TrustLevelUntrusted: 1,
		models.TrustLevelBlocked:   0,
	}
	return levels[actual] >= levels[required]
}

// CreatePolicy creates a conditional access policy
func (s *ZeroTrustService) CreatePolicy(policy *models.ConditionalAccessPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	policy.ID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	s.policies[policy.ID] = policy
	return nil
}

// GetPolicy retrieves a policy
func (s *ZeroTrustService) GetPolicy(id uuid.UUID) (*models.ConditionalAccessPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policy, ok := s.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return policy, nil
}

// ListPolicies lists all policies
func (s *ZeroTrustService) ListPolicies() []*models.ConditionalAccessPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.ConditionalAccessPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, p)
	}
	return result
}

// UpdatePolicy updates a policy
func (s *ZeroTrustService) UpdatePolicy(policy *models.ConditionalAccessPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[policy.ID]; !ok {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}

	policy.UpdatedAt = time.Now()
	s.policies[policy.ID] = policy
	return nil
}

// DeletePolicy deletes a policy
func (s *ZeroTrustService) DeletePolicy(id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[id]; !ok {
		return fmt.Errorf("policy not found: %s", id)
	}

	delete(s.policies, id)
	return nil
}

// GetZeroTrustStats returns Zero Trust statistics
func (s *ZeroTrustService) GetZeroTrustStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enabledCount := 0
	for _, p := range s.policies {
		if p.Enabled {
			enabledCount++
		}
	}

	return map[string]interface{}{
		"total_policies":   len(s.policies),
		"enabled_policies": enabledCount,
	}
}

// ============================================================================
// SIEM Service
// ============================================================================

// SIEMService handles SIEM integrations
type SIEMService struct {
	repos   *repository.Repositories
	cache   *cache.RedisCache
	logger  *logger.Logger

	configs     map[uuid.UUID]*models.SIEMIntegrationConfig
	eventQueues map[uuid.UUID][]models.SIEMEvent
	mu          sync.RWMutex

	httpClient *http.Client

	// Flush control
	flushTicker *time.Ticker
	stopCh      chan struct{}
}

// NewSIEMService creates a new SIEM service
func NewSIEMService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *SIEMService {
	svc := &SIEMService{
		repos:       repos,
		cache:       cache,
		logger:      log.WithComponent("siem"),
		configs:     make(map[uuid.UUID]*models.SIEMIntegrationConfig),
		eventQueues: make(map[uuid.UUID][]models.SIEMEvent),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}

	return svc
}

// Start starts the SIEM service background processing
func (s *SIEMService) Start(ctx context.Context) {
	s.flushTicker = time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-s.flushTicker.C:
				s.flushAllQueues(ctx)
			case <-s.stopCh:
				s.flushTicker.Stop()
				return
			case <-ctx.Done():
				s.flushTicker.Stop()
				return
			}
		}
	}()
}

// Stop stops the SIEM service
func (s *SIEMService) Stop() {
	close(s.stopCh)
}

// CreateIntegration creates a SIEM integration
func (s *SIEMService) CreateIntegration(config *models.SIEMIntegrationConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config.ID = uuid.New()
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 10 * time.Second
	}

	s.configs[config.ID] = config
	s.eventQueues[config.ID] = make([]models.SIEMEvent, 0)

	s.logger.Info().
		Str("id", config.ID.String()).
		Str("provider", string(config.Provider)).
		Str("name", config.Name).
		Msg("SIEM integration created")

	return nil
}

// GetIntegration retrieves a SIEM integration
func (s *SIEMService) GetIntegration(id uuid.UUID) (*models.SIEMIntegrationConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	config, ok := s.configs[id]
	if !ok {
		return nil, fmt.Errorf("integration not found: %s", id)
	}
	return config, nil
}

// ListIntegrations lists all SIEM integrations
func (s *SIEMService) ListIntegrations() []*models.SIEMIntegrationConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.SIEMIntegrationConfig, 0, len(s.configs))
	for _, config := range s.configs {
		result = append(result, config)
	}
	return result
}

// DeleteIntegration deletes a SIEM integration
func (s *SIEMService) DeleteIntegration(id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.configs[id]; !ok {
		return fmt.Errorf("integration not found: %s", id)
	}

	delete(s.configs, id)
	delete(s.eventQueues, id)
	return nil
}

// SendEvent queues an event for sending to SIEM
func (s *SIEMService) SendEvent(ctx context.Context, event *models.SIEMEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, config := range s.configs {
		if !config.Enabled {
			continue
		}

		// Check if event type is enabled
		if !s.eventTypeEnabled(config, event.EventType) {
			continue
		}

		// Check severity filter
		if !s.severityAllowed(config.MinSeverity, event.Severity) {
			continue
		}

		// Add to queue
		s.eventQueues[id] = append(s.eventQueues[id], *event)

		// Flush if queue is full
		if len(s.eventQueues[id]) >= config.BatchSize {
			go s.flushQueue(ctx, id)
		}
	}
}

func (s *SIEMService) eventTypeEnabled(config *models.SIEMIntegrationConfig, eventType string) bool {
	if len(config.EventTypes) == 0 {
		return true // All types enabled
	}
	for _, t := range config.EventTypes {
		if t == eventType || t == "all" {
			return true
		}
	}
	return false
}

func (s *SIEMService) severityAllowed(minSeverity, eventSeverity models.Severity) bool {
	severityOrder := map[models.Severity]int{
		models.SeverityInfo:     0,
		models.SeverityLow:      1,
		models.SeverityMedium:   2,
		models.SeverityHigh:     3,
		models.SeverityCritical: 4,
	}
	return severityOrder[eventSeverity] >= severityOrder[minSeverity]
}

func (s *SIEMService) flushAllQueues(ctx context.Context) {
	s.mu.RLock()
	ids := make([]uuid.UUID, 0, len(s.eventQueues))
	for id := range s.eventQueues {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	for _, id := range ids {
		s.flushQueue(ctx, id)
	}
}

func (s *SIEMService) flushQueue(ctx context.Context, configID uuid.UUID) {
	s.mu.Lock()
	events := s.eventQueues[configID]
	if len(events) == 0 {
		s.mu.Unlock()
		return
	}

	// Clear queue
	s.eventQueues[configID] = make([]models.SIEMEvent, 0)
	config := s.configs[configID]
	s.mu.Unlock()

	if config == nil {
		return
	}

	// Send events
	var err error
	switch config.Provider {
	case models.SIEMProviderSplunk:
		err = s.sendToSplunk(ctx, config, events)
	case models.SIEMProviderElastic:
		err = s.sendToElastic(ctx, config, events)
	case models.SIEMProviderSentinel:
		err = s.sendToSentinel(ctx, config, events)
	case models.SIEMProviderWebhook:
		err = s.sendToWebhook(ctx, config, events)
	default:
		err = fmt.Errorf("unsupported provider: %s", config.Provider)
	}

	// Update status
	s.mu.Lock()
	now := time.Now()
	if err != nil {
		config.LastError = err.Error()
		config.LastErrorAt = &now
		s.logger.Error().Err(err).Str("provider", string(config.Provider)).Msg("failed to send events to SIEM")
	} else {
		config.LastEventAt = &now
		config.EventsSent += int64(len(events))
	}
	s.mu.Unlock()
}

func (s *SIEMService) sendToSplunk(ctx context.Context, config *models.SIEMIntegrationConfig, events []models.SIEMEvent) error {
	// Splunk HEC format
	// POST https://splunk-server:8088/services/collector/event
	// Header: Authorization: Splunk <token>

	for _, event := range events {
		payload := map[string]interface{}{
			"time":       event.Timestamp.Unix(),
			"host":       event.SourceHost,
			"source":     event.Source,
			"sourcetype": "orbguard:security",
			"index":      config.Index,
			"event":      event,
		}

		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, "POST", config.Endpoint, bytes.NewReader(data))
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", "Splunk "+config.Token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			return fmt.Errorf("splunk returned status %d", resp.StatusCode)
		}
	}

	s.logger.Debug().Int("count", len(events)).Msg("sent events to Splunk")
	return nil
}

func (s *SIEMService) sendToElastic(ctx context.Context, config *models.SIEMIntegrationConfig, events []models.SIEMEvent) error {
	// Elasticsearch bulk API
	// POST /_bulk

	var buf bytes.Buffer
	for _, event := range events {
		// Index action
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": config.Index,
			},
		}
		actionLine, _ := json.Marshal(action)
		buf.Write(actionLine)
		buf.WriteByte('\n')

		// Document
		docLine, _ := json.Marshal(event)
		buf.Write(docLine)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Endpoint+"/_bulk", &buf)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if config.Token != "" {
		req.Header.Set("Authorization", "ApiKey "+config.Token)
	} else if config.Username != "" {
		req.SetBasicAuth(config.Username, config.Password)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("elasticsearch returned status %d", resp.StatusCode)
	}

	s.logger.Debug().Int("count", len(events)).Msg("sent events to Elasticsearch")
	return nil
}

func (s *SIEMService) sendToSentinel(ctx context.Context, config *models.SIEMIntegrationConfig, events []models.SIEMEvent) error {
	// Azure Sentinel Log Analytics
	// POST https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01

	data, err := json.Marshal(events)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", "OrbGuard")
	req.Header.Set("Authorization", "SharedKey "+config.Token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	s.logger.Debug().Int("count", len(events)).Msg("sent events to Sentinel")
	return nil
}

func (s *SIEMService) sendToWebhook(ctx context.Context, config *models.SIEMIntegrationConfig, events []models.SIEMEvent) error {
	// Generic webhook
	data, err := json.Marshal(map[string]interface{}{
		"source": "orbguard",
		"events": events,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	s.logger.Debug().Int("count", len(events)).Msg("sent events to webhook")
	return nil
}

// GetSIEMStats returns SIEM statistics
func (s *SIEMService) GetSIEMStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalEvents := int64(0)
	for _, config := range s.configs {
		totalEvents += config.EventsSent
	}

	return map[string]interface{}{
		"total_integrations": len(s.configs),
		"total_events_sent":  totalEvents,
	}
}

// ============================================================================
// Compliance Service
// ============================================================================

// ComplianceService handles compliance reporting
type ComplianceService struct {
	repos   *repository.Repositories
	cache   *cache.RedisCache
	logger  *logger.Logger

	reports  map[uuid.UUID]*models.ComplianceReport
	findings map[uuid.UUID]*models.ComplianceFinding
	mu       sync.RWMutex
}

// NewComplianceService creates a new compliance service
func NewComplianceService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *ComplianceService {
	return &ComplianceService{
		repos:    repos,
		cache:    cache,
		logger:   log.WithComponent("compliance"),
		reports:  make(map[uuid.UUID]*models.ComplianceReport),
		findings: make(map[uuid.UUID]*models.ComplianceFinding),
	}
}

// GenerateReport generates a compliance report for a framework
func (s *ComplianceService) GenerateReport(ctx context.Context, framework models.ComplianceFramework, startDate, endDate time.Time) (*models.ComplianceReport, error) {
	s.logger.Info().
		Str("framework", string(framework)).
		Time("start_date", startDate).
		Time("end_date", endDate).
		Msg("generating compliance report")

	report := &models.ComplianceReport{
		ID:          uuid.New(),
		Framework:   framework,
		Name:        fmt.Sprintf("%s Compliance Report", framework),
		Description: fmt.Sprintf("Compliance assessment for %s framework", framework),
		StartDate:   startDate,
		EndDate:     endDate,
		GeneratedAt: time.Now(),
		GeneratedBy: "system",
		Version:     "1.0",
		Controls:    make([]models.ControlAssessment, 0),
		Findings:    make([]models.ComplianceFinding, 0),
	}

	// Get controls for framework
	var controls []models.ControlAssessment
	switch framework {
	case models.ComplianceGDPR:
		controls = models.GDPRControls
	case models.ComplianceSOC2:
		controls = models.SOC2Controls
	case models.ComplianceCIS:
		controls = models.CISControls
	default:
		return nil, fmt.Errorf("unsupported framework: %s", framework)
	}

	// Assess each control
	for _, control := range controls {
		assessment := s.assessControl(ctx, control, framework)
		report.Controls = append(report.Controls, assessment)

		// Track counts
		report.TotalControls++
		switch assessment.Status {
		case models.ComplianceStatusCompliant:
			report.PassedControls++
		case models.ComplianceStatusNonCompliant:
			report.FailedControls++
		case models.ComplianceStatusPartial:
			report.PartialControls++
		default:
			report.NotApplicable++
		}
	}

	// Calculate overall score
	if report.TotalControls > 0 {
		report.OverallScore = float64(report.PassedControls*100+report.PartialControls*50) / float64(report.TotalControls)
	}

	// Determine overall status
	if report.FailedControls == 0 && report.PartialControls == 0 {
		report.OverallStatus = models.ComplianceStatusCompliant
	} else if report.FailedControls > 0 {
		report.OverallStatus = models.ComplianceStatusNonCompliant
	} else {
		report.OverallStatus = models.ComplianceStatusPartial
	}

	// Store report
	s.mu.Lock()
	s.reports[report.ID] = report
	s.mu.Unlock()

	s.logger.Info().
		Str("report_id", report.ID.String()).
		Float64("score", report.OverallScore).
		Str("status", string(report.OverallStatus)).
		Msg("compliance report generated")

	return report, nil
}

// assessControl assesses a single compliance control
func (s *ComplianceService) assessControl(ctx context.Context, control models.ControlAssessment, framework models.ComplianceFramework) models.ControlAssessment {
	assessment := control
	assessment.LastAssessedAt = time.Now()
	assessment.Assessor = "automated"

	// Simulated assessment logic - in production, this would check actual device/system state
	// For now, assign random scores for demonstration
	assessment.Score = 75.0 + float64(len(control.ControlID)%25) // 75-100 range based on control ID

	if assessment.Score >= 90 {
		assessment.Status = models.ComplianceStatusCompliant
		assessment.Evidence = []string{"Automated assessment passed", "All requirements met"}
	} else if assessment.Score >= 70 {
		assessment.Status = models.ComplianceStatusPartial
		assessment.Gaps = []string{"Some controls require manual verification"}
		assessment.Remediation = []string{"Complete manual assessment of affected controls"}
	} else {
		assessment.Status = models.ComplianceStatusNonCompliant
		assessment.Gaps = []string{"Control requirements not fully met"}
		assessment.Remediation = []string{"Implement missing controls", "Update security policies"}
	}

	return assessment
}

// GetReport retrieves a compliance report
func (s *ComplianceService) GetReport(id uuid.UUID) (*models.ComplianceReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	report, ok := s.reports[id]
	if !ok {
		return nil, fmt.Errorf("report not found: %s", id)
	}
	return report, nil
}

// ListReports lists all compliance reports
func (s *ComplianceService) ListReports() []*models.ComplianceReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.ComplianceReport, 0, len(s.reports))
	for _, r := range s.reports {
		result = append(result, r)
	}
	return result
}

// GetDeviceComplianceStatus gets compliance status for a device
func (s *ComplianceService) GetDeviceComplianceStatus(ctx context.Context, deviceID uuid.UUID) (*models.DeviceComplianceStatus, error) {
	status := &models.DeviceComplianceStatus{
		DeviceID:        deviceID,
		FrameworkStatus: make(map[models.ComplianceFramework]models.FrameworkComplianceStatus),
		Issues:          make([]models.ComplianceIssue, 0),
		LastCheckedAt:   time.Now(),
		NextCheckAt:     time.Now().Add(24 * time.Hour),
	}

	// Assess against each framework
	frameworks := []models.ComplianceFramework{
		models.ComplianceGDPR,
		models.ComplianceSOC2,
		models.ComplianceCIS,
	}

	totalScore := 0.0
	for _, fw := range frameworks {
		fwStatus := s.assessDeviceForFramework(ctx, deviceID, fw)
		status.FrameworkStatus[fw] = fwStatus
		totalScore += fwStatus.Score
	}

	status.ComplianceScore = totalScore / float64(len(frameworks))
	status.IsCompliant = status.ComplianceScore >= 70

	return status, nil
}

func (s *ComplianceService) assessDeviceForFramework(ctx context.Context, deviceID uuid.UUID, framework models.ComplianceFramework) models.FrameworkComplianceStatus {
	// Simulated assessment
	status := models.FrameworkComplianceStatus{
		Framework:     framework,
		Score:         80.0,
		PassedControls: 8,
		FailedControls: 2,
		LastCheckedAt: time.Now(),
	}

	if status.FailedControls == 0 {
		status.Status = models.ComplianceStatusCompliant
	} else if status.FailedControls > 3 {
		status.Status = models.ComplianceStatusNonCompliant
	} else {
		status.Status = models.ComplianceStatusPartial
	}

	return status
}

// CreateFinding creates a compliance finding
func (s *ComplianceService) CreateFinding(finding *models.ComplianceFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	finding.ID = uuid.New()
	finding.CreatedAt = time.Now()
	finding.UpdatedAt = time.Now()
	finding.Status = "open"

	s.findings[finding.ID] = finding
	return nil
}

// GetFinding retrieves a finding
func (s *ComplianceService) GetFinding(id uuid.UUID) (*models.ComplianceFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	finding, ok := s.findings[id]
	if !ok {
		return nil, fmt.Errorf("finding not found: %s", id)
	}
	return finding, nil
}

// ListFindings lists all findings
func (s *ComplianceService) ListFindings(status string) []*models.ComplianceFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.ComplianceFinding, 0)
	for _, f := range s.findings {
		if status == "" || f.Status == status {
			result = append(result, f)
		}
	}
	return result
}

// UpdateFinding updates a finding
func (s *ComplianceService) UpdateFinding(finding *models.ComplianceFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.findings[finding.ID]; !ok {
		return fmt.Errorf("finding not found: %s", finding.ID)
	}

	finding.UpdatedAt = time.Now()
	s.findings[finding.ID] = finding
	return nil
}

// ResolveFinding marks a finding as resolved
func (s *ComplianceService) ResolveFinding(id uuid.UUID, resolvedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	finding, ok := s.findings[id]
	if !ok {
		return fmt.Errorf("finding not found: %s", id)
	}

	now := time.Now()
	finding.Status = "resolved"
	finding.ResolvedAt = &now
	finding.ResolvedBy = resolvedBy
	finding.UpdatedAt = now

	return nil
}

// GetSupportedFrameworks returns list of supported compliance frameworks
func (s *ComplianceService) GetSupportedFrameworks() []map[string]string {
	return []map[string]string{
		{"id": string(models.ComplianceGDPR), "name": "GDPR", "description": "General Data Protection Regulation"},
		{"id": string(models.ComplianceSOC2), "name": "SOC 2", "description": "Service Organization Control 2"},
		{"id": string(models.ComplianceHIPAA), "name": "HIPAA", "description": "Health Insurance Portability and Accountability Act"},
		{"id": string(models.CompliancePCIDSS), "name": "PCI DSS", "description": "Payment Card Industry Data Security Standard"},
		{"id": string(models.ComplianceISO27001), "name": "ISO 27001", "description": "Information Security Management System"},
		{"id": string(models.ComplianceNIST), "name": "NIST", "description": "National Institute of Standards and Technology"},
		{"id": string(models.ComplianceCIS), "name": "CIS", "description": "Center for Internet Security Controls"},
	}
}

// GetComplianceStats returns compliance statistics
func (s *ComplianceService) GetComplianceStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	openFindings := 0
	criticalFindings := 0
	for _, f := range s.findings {
		if f.Status == "open" {
			openFindings++
			if f.Severity == models.SeverityCritical {
				criticalFindings++
			}
		}
	}

	return map[string]interface{}{
		"total_reports":     len(s.reports),
		"total_findings":    len(s.findings),
		"open_findings":     openFindings,
		"critical_findings": criticalFindings,
	}
}

// ============================================================================
// Enterprise Service (Combines all enterprise services)
// ============================================================================

// EnterpriseService combines all enterprise services
type EnterpriseService struct {
	MDM        *MDMService
	ZeroTrust  *ZeroTrustService
	SIEM       *SIEMService
	Compliance *ComplianceService

	repos  *repository.Repositories
	cache  *cache.RedisCache
	logger *logger.Logger
}

// NewEnterpriseService creates a new enterprise service
func NewEnterpriseService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *EnterpriseService {
	return &EnterpriseService{
		MDM:        NewMDMService(repos, cache, log),
		ZeroTrust:  NewZeroTrustService(repos, cache, log),
		SIEM:       NewSIEMService(repos, cache, log),
		Compliance: NewComplianceService(repos, cache, log),
		repos:      repos,
		cache:      cache,
		logger:     log.WithComponent("enterprise"),
	}
}

// Start starts all enterprise services
func (s *EnterpriseService) Start(ctx context.Context) {
	s.SIEM.Start(ctx)
	s.logger.Info().Msg("enterprise services started")
}

// Stop stops all enterprise services
func (s *EnterpriseService) Stop() {
	s.SIEM.Stop()
	s.logger.Info().Msg("enterprise services stopped")
}

// GetStats returns combined enterprise statistics
func (s *EnterpriseService) GetStats() *models.EnterpriseStats {
	mdmStats := s.MDM.GetMDMStats()
	_ = s.ZeroTrust.GetZeroTrustStats() // Zero Trust stats tracked separately via posture assessments
	siemStats := s.SIEM.GetSIEMStats()
	compStats := s.Compliance.GetComplianceStats()

	return &models.EnterpriseStats{
		MDMIntegrations:     mdmStats["total_integrations"].(int),
		MDMDevices:          mdmStats["total_devices"].(int),
		MDMCompliantDevices: mdmStats["compliant_devices"].(int),

		SIEMIntegrations: siemStats["total_integrations"].(int),
		EventsSentToday:  siemStats["total_events_sent"].(int64),

		ComplianceReports: compStats["total_reports"].(int),
		OpenFindings:      compStats["open_findings"].(int),
		CriticalFindings:  compStats["critical_findings"].(int),

		Timestamp: time.Now(),
	}
}

// LogAuditEvent logs an audit event and sends to SIEM
func (s *EnterpriseService) LogAuditEvent(ctx context.Context, log *models.AuditLog) {
	// Convert to SIEM event and send
	event := &models.SIEMEvent{
		ID:         log.ID.String(),
		Timestamp:  log.Timestamp,
		EventType:  "audit",
		Severity:   models.SeverityInfo,
		Source:     "orbguard",
		SourceHost: log.ActorIP,
		UserID:     log.ActorID,
		UserName:   log.ActorName,
		Category:   "audit",
		Action:     log.Action,
		Outcome:    log.Outcome,
		Message:    log.Details,
	}

	s.SIEM.SendEvent(ctx, event)
}
