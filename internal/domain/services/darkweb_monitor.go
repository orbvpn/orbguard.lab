package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// DarkWebMonitor provides dark web and breach monitoring services
type DarkWebMonitor struct {
	hibpClient *HIBPClient
	cache      *cache.RedisCache
	logger     *logger.Logger

	// In-memory storage for monitored assets (would be database in production)
	assets     map[string]*models.MonitoredAsset
	assetsMu   sync.RWMutex
	alerts     map[uuid.UUID]*models.BreachAlert
	alertsMu   sync.RWMutex

	// Stats
	totalChecks      int64
	breachesFound    int64
	passwordsChecked int64
	compromisedCount int64
	statsMu          sync.RWMutex
}

// NewDarkWebMonitor creates a new dark web monitor
func NewDarkWebMonitor(hibpClient *HIBPClient, redisCache *cache.RedisCache, log *logger.Logger) *DarkWebMonitor {
	return &DarkWebMonitor{
		hibpClient: hibpClient,
		cache:      redisCache,
		logger:     log.WithComponent("darkweb-monitor"),
		assets:     make(map[string]*models.MonitoredAsset),
		alerts:     make(map[uuid.UUID]*models.BreachAlert),
	}
}

// CheckEmail checks if an email has been breached
func (m *DarkWebMonitor) CheckEmail(ctx context.Context, req *models.BreachCheckRequest) (*models.BreachCheckResponse, error) {
	// Check cache first
	cacheKey := m.getCacheKey("email", req.Email)
	var cachedResult models.BreachCheckResponse
	if err := m.cache.GetJSON(ctx, cacheKey, &cachedResult); err == nil {
		return &cachedResult, nil
	}

	// Query HIBP
	result, err := m.hibpClient.CheckEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	// Update stats
	m.statsMu.Lock()
	m.totalChecks++
	if result.IsBreached {
		m.breachesFound += int64(result.BreachCount)
	}
	m.statsMu.Unlock()

	// Cache result for 1 hour
	_ = m.cache.SetJSON(ctx, cacheKey, result, 1*time.Hour)

	return result, nil
}

// CheckPassword checks if a password has been compromised
func (m *DarkWebMonitor) CheckPassword(ctx context.Context, req *models.PasswordCheckRequest) (*models.PasswordCheckResponse, error) {
	// Don't cache password results for security

	result, err := m.hibpClient.CheckPassword(ctx, req.Password)
	if err != nil {
		return nil, err
	}

	// Update stats
	m.statsMu.Lock()
	m.passwordsChecked++
	if result.IsBreached {
		m.compromisedCount++
	}
	m.statsMu.Unlock()

	return result, nil
}

// AddMonitoredAsset adds an asset for continuous monitoring
func (m *DarkWebMonitor) AddMonitoredAsset(ctx context.Context, userID, deviceID string, assetType models.BreachType, value string) (*models.MonitoredAsset, error) {
	// Hash the value for lookup
	hash := sha256.Sum256([]byte(strings.ToLower(value)))
	hashStr := hex.EncodeToString(hash[:])

	asset := &models.MonitoredAsset{
		ID:          uuid.New(),
		UserID:      userID,
		DeviceID:    deviceID,
		AssetType:   assetType,
		AssetValue:  value,
		AssetHash:   hashStr,
		DisplayName: m.maskValue(assetType, value),
		IsActive:    true,
		CreatedAt:   time.Now(),
	}

	// Perform initial check
	if assetType == models.BreachTypeEmail {
		result, err := m.CheckEmail(ctx, &models.BreachCheckRequest{
			Email:    value,
			DeviceID: deviceID,
		})
		if err == nil {
			asset.BreachCount = result.BreachCount
			now := time.Now()
			asset.LastChecked = &now

			// Create alerts for any breaches
			for _, breach := range result.Breaches {
				alert := m.createAlertForBreach(asset.ID, &breach)
				m.alertsMu.Lock()
				m.alerts[alert.ID] = alert
				m.alertsMu.Unlock()
				asset.Alerts = append(asset.Alerts, *alert)
			}
		}
	}

	// Store asset
	m.assetsMu.Lock()
	m.assets[hashStr] = asset
	m.assetsMu.Unlock()

	m.logger.Info().
		Str("asset_type", string(assetType)).
		Str("display", asset.DisplayName).
		Int("breach_count", asset.BreachCount).
		Msg("added monitored asset")

	return asset, nil
}

// RemoveMonitoredAsset removes an asset from monitoring
func (m *DarkWebMonitor) RemoveMonitoredAsset(ctx context.Context, assetID uuid.UUID) error {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()

	for hash, asset := range m.assets {
		if asset.ID == assetID {
			delete(m.assets, hash)
			m.logger.Info().Str("id", assetID.String()).Msg("removed monitored asset")
			return nil
		}
	}

	return nil
}

// GetMonitoredAssets returns all monitored assets for a user
func (m *DarkWebMonitor) GetMonitoredAssets(ctx context.Context, userID string) ([]models.MonitoredAsset, error) {
	m.assetsMu.RLock()
	defer m.assetsMu.RUnlock()

	var assets []models.MonitoredAsset
	for _, asset := range m.assets {
		if asset.UserID == userID {
			assets = append(assets, *asset)
		}
	}

	return assets, nil
}

// GetMonitoringStatus returns the overall monitoring status for a user
func (m *DarkWebMonitor) GetMonitoringStatus(ctx context.Context, userID string) (*models.DarkWebMonitoringStatus, error) {
	assets, _ := m.GetMonitoredAssets(ctx, userID)

	status := &models.DarkWebMonitoringStatus{
		IsEnabled:       len(assets) > 0,
		MonitoredAssets: len(assets),
		Assets:          assets,
	}

	// Calculate totals and risk level
	maxSeverity := models.BreachSeverityLow
	for _, asset := range assets {
		status.TotalBreaches += asset.BreachCount

		// Count unread alerts
		m.alertsMu.RLock()
		for _, alert := range m.alerts {
			if alert.AssetID == asset.ID && !alert.IsRead {
				status.UnreadAlerts++
				if models.CompareSeverity(alert.Severity, maxSeverity) > 0 {
					maxSeverity = alert.Severity
				}
			}
		}
		m.alertsMu.RUnlock()

		if asset.LastChecked != nil && (status.LastScan == nil || asset.LastChecked.After(*status.LastScan)) {
			status.LastScan = asset.LastChecked
		}
	}

	status.RiskLevel = maxSeverity

	// Calculate next scan time (every 24 hours)
	if status.LastScan != nil {
		nextScan := status.LastScan.Add(24 * time.Hour)
		status.NextScan = &nextScan
	}

	return status, nil
}

// GetAlerts returns all alerts for a user
func (m *DarkWebMonitor) GetAlerts(ctx context.Context, userID string) ([]models.BreachAlert, error) {
	assets, _ := m.GetMonitoredAssets(ctx, userID)

	assetIDs := make(map[uuid.UUID]bool)
	for _, asset := range assets {
		assetIDs[asset.ID] = true
	}

	m.alertsMu.RLock()
	defer m.alertsMu.RUnlock()

	var alerts []models.BreachAlert
	for _, alert := range m.alerts {
		if assetIDs[alert.AssetID] {
			alerts = append(alerts, *alert)
		}
	}

	return alerts, nil
}

// AcknowledgeAlert marks an alert as read
func (m *DarkWebMonitor) AcknowledgeAlert(ctx context.Context, alertID uuid.UUID) error {
	m.alertsMu.Lock()
	defer m.alertsMu.Unlock()

	if alert, ok := m.alerts[alertID]; ok {
		now := time.Now()
		alert.AckedAt = &now
		alert.IsRead = true
		m.logger.Info().Str("alert_id", alertID.String()).Msg("alert acknowledged")
	}

	return nil
}

// GetStats returns dark web monitoring statistics
func (m *DarkWebMonitor) GetStats(ctx context.Context) (*models.DarkWebStats, error) {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()

	stats := &models.DarkWebStats{
		TotalChecks:      m.totalChecks,
		BreachesFound:    m.breachesFound,
		PasswordsChecked: m.passwordsChecked,
		CompromisedCount: m.compromisedCount,
		ByAssetType:      make(map[string]int64),
		BySeverity:       make(map[string]int64),
	}

	// Count by asset type
	m.assetsMu.RLock()
	for _, asset := range m.assets {
		stats.ByAssetType[string(asset.AssetType)]++
	}
	m.assetsMu.RUnlock()

	// Count by severity
	m.alertsMu.RLock()
	for _, alert := range m.alerts {
		stats.BySeverity[string(alert.Severity)]++
	}
	m.alertsMu.RUnlock()

	return stats, nil
}

// RefreshMonitoredAssets re-checks all monitored assets for new breaches
func (m *DarkWebMonitor) RefreshMonitoredAssets(ctx context.Context) error {
	m.assetsMu.RLock()
	assets := make([]*models.MonitoredAsset, 0, len(m.assets))
	for _, asset := range m.assets {
		if asset.IsActive {
			assets = append(assets, asset)
		}
	}
	m.assetsMu.RUnlock()

	for _, asset := range assets {
		if asset.AssetType == models.BreachTypeEmail {
			result, err := m.hibpClient.CheckEmail(ctx, asset.AssetValue)
			if err != nil {
				m.logger.Warn().Err(err).Str("asset_id", asset.ID.String()).Msg("failed to refresh asset")
				continue
			}

			// Check for new breaches
			existingBreachNames := make(map[string]bool)
			for _, alert := range asset.Alerts {
				existingBreachNames[alert.BreachName] = true
			}

			for _, breach := range result.Breaches {
				if !existingBreachNames[breach.Name] {
					// New breach found!
					alert := m.createAlertForBreach(asset.ID, &breach)
					m.alertsMu.Lock()
					m.alerts[alert.ID] = alert
					m.alertsMu.Unlock()

					m.logger.Warn().
						Str("asset_id", asset.ID.String()).
						Str("breach", breach.Name).
						Msg("new breach detected for monitored asset")
				}
			}

			// Update asset
			m.assetsMu.Lock()
			asset.BreachCount = result.BreachCount
			now := time.Now()
			asset.LastChecked = &now
			m.assetsMu.Unlock()
		}
	}

	return nil
}

// Helper functions

func (m *DarkWebMonitor) getCacheKey(keyType, value string) string {
	hash := sha256.Sum256([]byte(value))
	return "darkweb:" + keyType + ":" + hex.EncodeToString(hash[:8])
}

func (m *DarkWebMonitor) maskValue(assetType models.BreachType, value string) string {
	switch assetType {
	case models.BreachTypeEmail:
		return maskEmail(value)
	case models.BreachTypePhone:
		if len(value) > 4 {
			return "***" + value[len(value)-4:]
		}
		return "***"
	case models.BreachTypeCreditCard:
		if len(value) > 4 {
			return "****-****-****-" + value[len(value)-4:]
		}
		return "****"
	default:
		if len(value) > 4 {
			return value[:2] + "***" + value[len(value)-2:]
		}
		return "***"
	}
}

func (m *DarkWebMonitor) createAlertForBreach(assetID uuid.UUID, breach *models.Breach) *models.BreachAlert {
	return &models.BreachAlert{
		ID:          uuid.New(),
		AssetID:     assetID,
		BreachID:    breach.ID,
		BreachName:  breach.Name,
		Severity:    breach.Severity,
		DataExposed: breach.DataClasses,
		DetectedAt:  time.Now(),
		IsRead:      false,
		Actions:     m.getActionsForBreach(breach),
	}
}

func (m *DarkWebMonitor) getActionsForBreach(breach *models.Breach) []models.AlertAction {
	actions := []models.AlertAction{
		{
			ID:     "view_details",
			Label:  "View Details",
			Action: "view_details",
		},
	}

	// Add specific actions based on data classes
	for _, dataClass := range breach.DataClasses {
		switch dataClass {
		case "Passwords":
			actions = append(actions, models.AlertAction{
				ID:     "change_password",
				Label:  "Change Password",
				Action: "change_password",
				URL:    breach.Domain,
			})
		case "Credit cards", "Bank account numbers":
			actions = append(actions, models.AlertAction{
				ID:     "contact_bank",
				Label:  "Contact Your Bank",
				Action: "contact_bank",
			})
		}
	}

	// Always add enable 2FA action
	actions = append(actions, models.AlertAction{
		ID:     "enable_2fa",
		Label:  "Enable 2FA",
		Action: "enable_2fa",
	})

	// Add dismiss action
	actions = append(actions, models.AlertAction{
		ID:     "dismiss",
		Label:  "Dismiss",
		Action: "dismiss",
	})

	return actions
}
