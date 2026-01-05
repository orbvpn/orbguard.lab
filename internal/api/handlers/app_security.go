package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// AppSecurityHandler handles app security API requests
type AppSecurityHandler struct {
	analyzer *services.AppAnalyzer
	logger   *logger.Logger
}

// NewAppSecurityHandler creates a new app security handler
func NewAppSecurityHandler(analyzer *services.AppAnalyzer, log *logger.Logger) *AppSecurityHandler {
	return &AppSecurityHandler{
		analyzer: analyzer,
		logger:   log.WithComponent("app-security-handler"),
	}
}

// AnalyzeApp handles POST /api/v1/apps/analyze
func (h *AppSecurityHandler) AnalyzeApp(w http.ResponseWriter, r *http.Request) {
	var req models.AppAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PackageName == "" {
		h.respondError(w, http.StatusBadRequest, "package_name is required")
		return
	}

	result, err := h.analyzer.AnalyzeApp(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Str("package", req.PackageName).Msg("failed to analyze app")
		h.respondError(w, http.StatusInternalServerError, "failed to analyze app")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// AnalyzeBatch handles POST /api/v1/apps/analyze/batch
func (h *AppSecurityHandler) AnalyzeBatch(w http.ResponseWriter, r *http.Request) {
	var req models.AppBatchAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Apps) == 0 {
		h.respondError(w, http.StatusBadRequest, "apps array is required")
		return
	}

	if len(req.Apps) > 100 {
		h.respondError(w, http.StatusBadRequest, "maximum 100 apps per batch")
		return
	}

	result, err := h.analyzer.AnalyzeBatch(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Int("count", len(req.Apps)).Msg("failed to analyze apps batch")
		h.respondError(w, http.StatusInternalServerError, "failed to analyze apps")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// GetAppReputation handles GET /api/v1/apps/reputation/{package}
func (h *AppSecurityHandler) GetAppReputation(w http.ResponseWriter, r *http.Request) {
	packageName := chi.URLParam(r, "package")
	if packageName == "" {
		h.respondError(w, http.StatusBadRequest, "package name is required")
		return
	}

	// In production, this would query a reputation database
	reputation := &models.AppReputation{
		PackageName: packageName,
		RiskLevel:   models.AppRiskLevelSafe,
		RiskScore:   0,
		IsVerified:  false,
	}

	h.respondJSON(w, http.StatusOK, reputation)
}

// CheckSideloaded handles POST /api/v1/apps/sideloaded
func (h *AppSecurityHandler) CheckSideloaded(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Apps     []models.AppInfo `json:"apps"`
		DeviceID string           `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Apps) == 0 {
		h.respondError(w, http.StatusBadRequest, "apps array is required")
		return
	}

	report, err := h.analyzer.GetSideloadedApps(r.Context(), req.Apps)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to check sideloaded apps")
		h.respondError(w, http.StatusInternalServerError, "failed to check sideloaded apps")
		return
	}

	if req.DeviceID != "" {
		report.DeviceID = req.DeviceID
	}

	h.respondJSON(w, http.StatusOK, report)
}

// GetPrivacyReport handles POST /api/v1/apps/privacy-report
func (h *AppSecurityHandler) GetPrivacyReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Apps     []models.AppAnalysisRequest `json:"apps"`
		DeviceID string                      `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Apps) == 0 {
		h.respondError(w, http.StatusBadRequest, "apps array is required")
		return
	}

	// Analyze all apps first
	batchResult, err := h.analyzer.AnalyzeBatch(r.Context(), &models.AppBatchAnalysisRequest{
		Apps:     req.Apps,
		DeviceID: req.DeviceID,
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to analyze apps for privacy report")
		h.respondError(w, http.StatusInternalServerError, "failed to generate privacy report")
		return
	}

	// Generate privacy report
	report, err := h.analyzer.GeneratePrivacyReport(r.Context(), batchResult.Results, req.DeviceID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to generate privacy report")
		h.respondError(w, http.StatusInternalServerError, "failed to generate privacy report")
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// GetStats handles GET /api/v1/apps/stats
func (h *AppSecurityHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.analyzer.GetStats(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get app stats")
		h.respondError(w, http.StatusInternalServerError, "failed to get stats")
		return
	}

	h.respondJSON(w, http.StatusOK, stats)
}

// GetKnownTrackers handles GET /api/v1/apps/trackers
func (h *AppSecurityHandler) GetKnownTrackers(w http.ResponseWriter, r *http.Request) {
	trackers := make([]models.TrackerSDK, 0, len(models.KnownTrackers))
	for _, tracker := range models.KnownTrackers {
		trackers = append(trackers, tracker)
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"trackers": trackers,
		"count":    len(trackers),
	})
}

// GetDangerousPermissions handles GET /api/v1/apps/permissions/dangerous
func (h *AppSecurityHandler) GetDangerousPermissions(w http.ResponseWriter, r *http.Request) {
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"dangerous_combos": models.DangerousPermissionCombos,
		"count":            len(models.DangerousPermissionCombos),
	})
}

// ReportApp handles POST /api/v1/apps/report
func (h *AppSecurityHandler) ReportApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PackageName string `json:"package_name"`
		ReportType  string `json:"report_type"` // "malware", "privacy", "scam", "other"
		Description string `json:"description"`
		DeviceID    string `json:"device_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PackageName == "" || req.ReportType == "" {
		h.respondError(w, http.StatusBadRequest, "package_name and report_type are required")
		return
	}

	h.logger.Info().
		Str("package", req.PackageName).
		Str("type", req.ReportType).
		Msg("app report received")

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "received",
		"message": "Thank you for your report. It will be reviewed by our team.",
	})
}

func (h *AppSecurityHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AppSecurityHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}
