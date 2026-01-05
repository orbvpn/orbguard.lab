package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// PrivacyHandler handles privacy protection API requests
type PrivacyHandler struct {
	service *services.PrivacyService
	logger  *logger.Logger
}

// NewPrivacyHandler creates a new privacy handler
func NewPrivacyHandler(service *services.PrivacyService, log *logger.Logger) *PrivacyHandler {
	return &PrivacyHandler{
		service: service,
		logger:  log.WithComponent("privacy-handler"),
	}
}

// RecordEvent handles POST /api/v1/privacy/events
func (h *PrivacyHandler) RecordEvent(w http.ResponseWriter, r *http.Request) {
	var event models.PrivacyEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if event.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.RecordPrivacyEvent(r.Context(), &event); err != nil {
		h.logger.Error().Err(err).Msg("failed to record privacy event")
		h.respondError(w, http.StatusInternalServerError, "failed to record event")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status": "recorded",
		"event":  event,
	})
}

// RecordCameraAccess handles POST /api/v1/privacy/camera
func (h *PrivacyHandler) RecordCameraAccess(w http.ResponseWriter, r *http.Request) {
	var event models.CameraAccessEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if event.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.RecordCameraAccess(r.Context(), &event); err != nil {
		h.logger.Error().Err(err).Msg("failed to record camera access")
		h.respondError(w, http.StatusInternalServerError, "failed to record event")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":     "recorded",
		"risk_level": event.RiskLevel,
		"event":      event,
	})
}

// RecordMicrophoneAccess handles POST /api/v1/privacy/microphone
func (h *PrivacyHandler) RecordMicrophoneAccess(w http.ResponseWriter, r *http.Request) {
	var event models.MicrophoneAccessEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if event.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.RecordMicrophoneAccess(r.Context(), &event); err != nil {
		h.logger.Error().Err(err).Msg("failed to record microphone access")
		h.respondError(w, http.StatusInternalServerError, "failed to record event")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":     "recorded",
		"risk_level": event.RiskLevel,
		"event":      event,
	})
}

// RecordClipboardAccess handles POST /api/v1/privacy/clipboard
func (h *PrivacyHandler) RecordClipboardAccess(w http.ResponseWriter, r *http.Request) {
	var event models.ClipboardEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if event.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.RecordClipboardAccess(r.Context(), &event); err != nil {
		h.logger.Error().Err(err).Msg("failed to record clipboard access")
		h.respondError(w, http.StatusInternalServerError, "failed to record event")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":     "recorded",
		"risk_level": event.RiskLevel,
		"event":      event,
	})
}

// RecordScreenEvent handles POST /api/v1/privacy/screen
func (h *PrivacyHandler) RecordScreenEvent(w http.ResponseWriter, r *http.Request) {
	var event models.ScreenEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if event.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.RecordScreenEvent(r.Context(), &event); err != nil {
		h.logger.Error().Err(err).Msg("failed to record screen event")
		h.respondError(w, http.StatusInternalServerError, "failed to record event")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":     "recorded",
		"risk_level": event.RiskLevel,
		"event":      event,
	})
}

// CheckClipboard handles POST /api/v1/privacy/clipboard/check
func (h *PrivacyHandler) CheckClipboard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content   string `json:"content"`
		SourceApp string `json:"source_app"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Content == "" {
		h.respondError(w, http.StatusBadRequest, "content is required")
		return
	}

	result := h.service.CheckClipboard(r.Context(), req.Content, req.SourceApp)
	h.respondJSON(w, http.StatusOK, result)
}

// CheckDomain handles GET /api/v1/privacy/trackers/check/{domain}
func (h *PrivacyHandler) CheckDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		h.respondError(w, http.StatusBadRequest, "domain is required")
		return
	}

	tracker, isTracker := h.service.CheckDomain(domain)
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"domain":     domain,
		"is_tracker": isTracker,
		"tracker":    tracker,
	})
}

// ShouldBlockDomain handles POST /api/v1/privacy/trackers/should-block
func (h *PrivacyHandler) ShouldBlockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string                  `json:"domain"`
		Settings *models.PrivacySettings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Domain == "" {
		h.respondError(w, http.StatusBadRequest, "domain is required")
		return
	}

	shouldBlock := h.service.ShouldBlockDomain(r.Context(), req.Domain, req.Settings)
	tracker, _ := h.service.CheckDomain(req.Domain)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"domain":       req.Domain,
		"should_block": shouldBlock,
		"tracker":      tracker,
	})
}

// GetBlockList handles POST /api/v1/privacy/trackers/blocklist
func (h *PrivacyHandler) GetBlockList(w http.ResponseWriter, r *http.Request) {
	var settings models.PrivacySettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		// Use default settings if none provided
		settings = models.PrivacySettings{
			BlockTrackers:  true,
			BlockAds:       true,
			BlockAnalytics: false,
		}
	}

	rules := h.service.GetTrackerBlockList(r.Context(), &settings)
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"rules":    rules,
		"count":    len(rules),
		"settings": settings,
	})
}

// GetTrackers handles GET /api/v1/privacy/trackers
func (h *PrivacyHandler) GetTrackers(w http.ResponseWriter, r *http.Request) {
	trackers := h.service.GetKnownTrackers()
	trackerList := make([]models.TrackerInfo, 0, len(trackers))
	for _, tracker := range trackers {
		trackerList = append(trackerList, tracker)
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"trackers": trackerList,
		"count":    len(trackerList),
	})
}

// GetTracker handles GET /api/v1/privacy/trackers/{id}
func (h *PrivacyHandler) GetTracker(w http.ResponseWriter, r *http.Request) {
	trackerID := chi.URLParam(r, "id")
	if trackerID == "" {
		h.respondError(w, http.StatusBadRequest, "tracker id is required")
		return
	}

	tracker := h.service.GetTrackerByID(trackerID)
	if tracker == nil {
		h.respondError(w, http.StatusNotFound, "tracker not found")
		return
	}

	h.respondJSON(w, http.StatusOK, tracker)
}

// AuditPrivacy handles POST /api/v1/privacy/audit
func (h *PrivacyHandler) AuditPrivacy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string                   `json:"device_id"`
		Apps     []models.AppPrivacyInfo  `json:"apps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	result := h.service.AuditPrivacy(r.Context(), req.DeviceID, req.Apps)
	h.respondJSON(w, http.StatusOK, result)
}

// GetStats handles GET /api/v1/privacy/stats/{device_id}
func (h *PrivacyHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}

	stats := h.service.GetPrivacyStats(r.Context(), deviceID, period)
	h.respondJSON(w, http.StatusOK, stats)
}

// GetServiceStats handles GET /api/v1/privacy/service/stats
func (h *PrivacyHandler) GetServiceStats(w http.ResponseWriter, r *http.Request) {
	stats := h.service.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// GetSensitivePatterns handles GET /api/v1/privacy/patterns
func (h *PrivacyHandler) GetSensitivePatterns(w http.ResponseWriter, r *http.Request) {
	patterns := make([]map[string]interface{}, 0, len(models.SensitivePatterns))
	for _, pattern := range models.SensitivePatterns {
		patterns = append(patterns, map[string]interface{}{
			"type":        pattern.Type,
			"description": pattern.Description,
			"risk_level":  pattern.RiskLevel,
		})
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"patterns": patterns,
		"count":    len(patterns),
	})
}

// GetPrivacyEventTypes handles GET /api/v1/privacy/event-types
func (h *PrivacyHandler) GetPrivacyEventTypes(w http.ResponseWriter, r *http.Request) {
	eventTypes := []map[string]interface{}{
		{"type": models.PrivacyEventCameraAccess, "description": "Camera access by an app"},
		{"type": models.PrivacyEventMicrophoneAccess, "description": "Microphone access by an app"},
		{"type": models.PrivacyEventLocationAccess, "description": "Location access by an app"},
		{"type": models.PrivacyEventClipboardRead, "description": "Clipboard read by an app"},
		{"type": models.PrivacyEventClipboardWrite, "description": "Clipboard write by an app"},
		{"type": models.PrivacyEventScreenCapture, "description": "Screen capture by an app"},
		{"type": models.PrivacyEventScreenRecording, "description": "Screen recording by an app"},
		{"type": models.PrivacyEventContactsAccess, "description": "Contacts access by an app"},
		{"type": models.PrivacyEventCalendarAccess, "description": "Calendar access by an app"},
		{"type": models.PrivacyEventCallLogAccess, "description": "Call log access by an app"},
		{"type": models.PrivacyEventSMSAccess, "description": "SMS access by an app"},
		{"type": models.PrivacyEventStorageAccess, "description": "Storage access by an app"},
		{"type": models.PrivacyEventNetworkAccess, "description": "Network access by an app"},
		{"type": models.PrivacyEventSensorAccess, "description": "Sensor access by an app"},
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"event_types": eventTypes,
		"count":       len(eventTypes),
	})
}

// GetRiskLevels handles GET /api/v1/privacy/risk-levels
func (h *PrivacyHandler) GetRiskLevels(w http.ResponseWriter, r *http.Request) {
	riskLevels := []map[string]interface{}{
		{"level": models.PrivacyRiskCritical, "description": "Critical risk - immediate action required", "score_range": "0-39"},
		{"level": models.PrivacyRiskHigh, "description": "High risk - review and address soon", "score_range": "40-59"},
		{"level": models.PrivacyRiskMedium, "description": "Medium risk - monitor and review", "score_range": "60-79"},
		{"level": models.PrivacyRiskLow, "description": "Low risk - acceptable level", "score_range": "80-89"},
		{"level": models.PrivacyRiskInfo, "description": "Informational - no action needed", "score_range": "90-100"},
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"risk_levels": riskLevels,
		"count":       len(riskLevels),
	})
}

func (h *PrivacyHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *PrivacyHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}
