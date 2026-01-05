package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// DarkWebHandler handles dark web monitoring API requests
type DarkWebHandler struct {
	monitor *services.DarkWebMonitor
	logger  *logger.Logger
}

// NewDarkWebHandler creates a new dark web handler
func NewDarkWebHandler(monitor *services.DarkWebMonitor, log *logger.Logger) *DarkWebHandler {
	return &DarkWebHandler{
		monitor: monitor,
		logger:  log.WithComponent("darkweb-handler"),
	}
}

// CheckEmail handles POST /api/v1/darkweb/check/email
func (h *DarkWebHandler) CheckEmail(w http.ResponseWriter, r *http.Request) {
	var req models.BreachCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		h.respondError(w, http.StatusBadRequest, "email is required")
		return
	}

	result, err := h.monitor.CheckEmail(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to check email")
		h.respondError(w, http.StatusInternalServerError, "failed to check email")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// CheckPassword handles POST /api/v1/darkweb/check/password
func (h *DarkWebHandler) CheckPassword(w http.ResponseWriter, r *http.Request) {
	var req models.PasswordCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		h.respondError(w, http.StatusBadRequest, "password is required")
		return
	}

	result, err := h.monitor.CheckPassword(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to check password")
		h.respondError(w, http.StatusInternalServerError, "failed to check password")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// AddMonitoredAsset handles POST /api/v1/darkweb/monitor
func (h *DarkWebHandler) AddMonitoredAsset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AssetType string `json:"asset_type"` // "email", "phone", etc.
		Value     string `json:"value"`
		UserID    string `json:"user_id,omitempty"`
		DeviceID  string `json:"device_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Value == "" {
		h.respondError(w, http.StatusBadRequest, "value is required")
		return
	}

	assetType := models.BreachType(req.AssetType)
	if assetType == "" {
		assetType = models.BreachTypeEmail
	}

	asset, err := h.monitor.AddMonitoredAsset(r.Context(), req.UserID, req.DeviceID, assetType, req.Value)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to add monitored asset")
		h.respondError(w, http.StatusInternalServerError, "failed to add monitored asset")
		return
	}

	h.respondJSON(w, http.StatusCreated, asset)
}

// RemoveMonitoredAsset handles DELETE /api/v1/darkweb/monitor/{id}
func (h *DarkWebHandler) RemoveMonitoredAsset(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.monitor.RemoveMonitoredAsset(r.Context(), id); err != nil {
		h.logger.Error().Err(err).Msg("failed to remove monitored asset")
		h.respondError(w, http.StatusInternalServerError, "failed to remove monitored asset")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetMonitoredAssets handles GET /api/v1/darkweb/monitor
func (h *DarkWebHandler) GetMonitoredAssets(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = "default"
	}

	assets, err := h.monitor.GetMonitoredAssets(r.Context(), userID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get monitored assets")
		h.respondError(w, http.StatusInternalServerError, "failed to get monitored assets")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"assets": assets,
		"count":  len(assets),
	})
}

// GetMonitoringStatus handles GET /api/v1/darkweb/status
func (h *DarkWebHandler) GetMonitoringStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = "default"
	}

	status, err := h.monitor.GetMonitoringStatus(r.Context(), userID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get monitoring status")
		h.respondError(w, http.StatusInternalServerError, "failed to get status")
		return
	}

	h.respondJSON(w, http.StatusOK, status)
}

// GetAlerts handles GET /api/v1/darkweb/alerts
func (h *DarkWebHandler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = "default"
	}

	alerts, err := h.monitor.GetAlerts(r.Context(), userID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get alerts")
		h.respondError(w, http.StatusInternalServerError, "failed to get alerts")
		return
	}

	// Separate by read status
	unread := []models.BreachAlert{}
	read := []models.BreachAlert{}
	for _, alert := range alerts {
		if alert.IsRead {
			read = append(read, alert)
		} else {
			unread = append(unread, alert)
		}
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"unread":       unread,
		"read":         read,
		"unread_count": len(unread),
		"total_count":  len(alerts),
	})
}

// AcknowledgeAlert handles POST /api/v1/darkweb/alerts/{id}/ack
func (h *DarkWebHandler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.monitor.AcknowledgeAlert(r.Context(), id); err != nil {
		h.logger.Error().Err(err).Msg("failed to acknowledge alert")
		h.respondError(w, http.StatusInternalServerError, "failed to acknowledge alert")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// GetStats handles GET /api/v1/darkweb/stats
func (h *DarkWebHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.monitor.GetStats(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get stats")
		h.respondError(w, http.StatusInternalServerError, "failed to get stats")
		return
	}

	h.respondJSON(w, http.StatusOK, stats)
}

// GetBreaches handles GET /api/v1/darkweb/breaches
func (h *DarkWebHandler) GetBreaches(w http.ResponseWriter, r *http.Request) {
	// This would typically query all known breaches
	// For now, return a message that HIBP API key is needed
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "To list all breaches, configure HIBP API key",
		"count":   0,
	})
}

// GetBreachByName handles GET /api/v1/darkweb/breaches/{name}
func (h *DarkWebHandler) GetBreachByName(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		h.respondError(w, http.StatusBadRequest, "breach name is required")
		return
	}

	// This would query HIBP for breach details
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Breach details would be fetched from HIBP",
		"name":    name,
	})
}

// RefreshMonitoring handles POST /api/v1/darkweb/refresh
func (h *DarkWebHandler) RefreshMonitoring(w http.ResponseWriter, r *http.Request) {
	if err := h.monitor.RefreshMonitoredAssets(r.Context()); err != nil {
		h.logger.Error().Err(err).Msg("failed to refresh monitored assets")
		h.respondError(w, http.StatusInternalServerError, "failed to refresh")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "refreshed"})
}

func (h *DarkWebHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *DarkWebHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}
