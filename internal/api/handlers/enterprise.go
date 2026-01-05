package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// EnterpriseHandler handles enterprise API endpoints
type EnterpriseHandler struct {
	enterprise *services.EnterpriseService
	logger     *logger.Logger
}

// NewEnterpriseHandler creates a new enterprise handler
func NewEnterpriseHandler(enterprise *services.EnterpriseService, log *logger.Logger) *EnterpriseHandler {
	return &EnterpriseHandler{
		enterprise: enterprise,
		logger:     log.WithComponent("enterprise-api"),
	}
}

// ============================================================================
// MDM Endpoints
// ============================================================================

// ListMDMIntegrations handles GET /api/v1/enterprise/mdm/integrations
func (h *EnterpriseHandler) ListMDMIntegrations(w http.ResponseWriter, r *http.Request) {
	integrations := h.enterprise.MDM.ListIntegrations()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"integrations": integrations,
		"count":        len(integrations),
	})
}

// CreateMDMIntegration handles POST /api/v1/enterprise/mdm/integrations
func (h *EnterpriseHandler) CreateMDMIntegration(w http.ResponseWriter, r *http.Request) {
	var config models.MDMIntegrationConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.enterprise.MDM.CreateIntegration(r.Context(), &config); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, config)
}

// GetMDMIntegration handles GET /api/v1/enterprise/mdm/integrations/{id}
func (h *EnterpriseHandler) GetMDMIntegration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid integration ID")
		return
	}

	config, err := h.enterprise.MDM.GetIntegration(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, config)
}

// DeleteMDMIntegration handles DELETE /api/v1/enterprise/mdm/integrations/{id}
func (h *EnterpriseHandler) DeleteMDMIntegration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid integration ID")
		return
	}

	if err := h.enterprise.MDM.DeleteIntegration(id); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SyncMDMDevices handles POST /api/v1/enterprise/mdm/integrations/{id}/sync
func (h *EnterpriseHandler) SyncMDMDevices(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid integration ID")
		return
	}

	if err := h.enterprise.MDM.SyncDevices(r.Context(), id); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Device sync initiated",
	})
}

// ListMDMDevices handles GET /api/v1/enterprise/mdm/integrations/{id}/devices
func (h *EnterpriseHandler) ListMDMDevices(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid integration ID")
		return
	}

	devices := h.enterprise.MDM.ListMDMDevices(id)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
	})
}

// SendMDMThreatAlert handles POST /api/v1/enterprise/mdm/alerts
func (h *EnterpriseHandler) SendMDMThreatAlert(w http.ResponseWriter, r *http.Request) {
	var alert models.MDMThreatAlert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	alert.ID = uuid.New()
	alert.CreatedAt = time.Now()
	alert.Status = "pending"

	if err := h.enterprise.MDM.SendThreatAlert(r.Context(), &alert); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, alert)
}

// GetMDMStats handles GET /api/v1/enterprise/mdm/stats
func (h *EnterpriseHandler) GetMDMStats(w http.ResponseWriter, r *http.Request) {
	stats := h.enterprise.MDM.GetMDMStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// ============================================================================
// Zero Trust Endpoints
// ============================================================================

// AssessDevicePosture handles POST /api/v1/enterprise/zerotrust/posture
func (h *EnterpriseHandler) AssessDevicePosture(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid device ID")
		return
	}

	posture, err := h.enterprise.ZeroTrust.AssessDevicePosture(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, posture)
}

// EvaluateAccess handles POST /api/v1/enterprise/zerotrust/evaluate
func (h *EnterpriseHandler) EvaluateAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID         string `json:"device_id"`
		UserID           string `json:"user_id"`
		ResourceID       string `json:"resource_id"`
		Location         string `json:"location"`
		IPAddress        string `json:"ip_address"`
		HasActiveThreats bool   `json:"has_active_threats"`
		MFACompleted     bool   `json:"mfa_completed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid device ID")
		return
	}

	accessReq := &services.AccessRequest{
		DeviceID:         deviceID,
		UserID:           req.UserID,
		ResourceID:       req.ResourceID,
		Location:         req.Location,
		IPAddress:        req.IPAddress,
		HasActiveThreats: req.HasActiveThreats,
		MFACompleted:     req.MFACompleted,
	}

	decision, err := h.enterprise.ZeroTrust.EvaluateAccess(r.Context(), accessReq)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, decision)
}

// ListPolicies handles GET /api/v1/enterprise/zerotrust/policies
func (h *EnterpriseHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := h.enterprise.ZeroTrust.ListPolicies()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	})
}

// CreatePolicy handles POST /api/v1/enterprise/zerotrust/policies
func (h *EnterpriseHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var policy models.ConditionalAccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.enterprise.ZeroTrust.CreatePolicy(&policy); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, policy)
}

// GetPolicy handles GET /api/v1/enterprise/zerotrust/policies/{id}
func (h *EnterpriseHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid policy ID")
		return
	}

	policy, err := h.enterprise.ZeroTrust.GetPolicy(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, policy)
}

// UpdatePolicy handles PUT /api/v1/enterprise/zerotrust/policies/{id}
func (h *EnterpriseHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid policy ID")
		return
	}

	var policy models.ConditionalAccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	policy.ID = id
	if err := h.enterprise.ZeroTrust.UpdatePolicy(&policy); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, policy)
}

// DeletePolicy handles DELETE /api/v1/enterprise/zerotrust/policies/{id}
func (h *EnterpriseHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid policy ID")
		return
	}

	if err := h.enterprise.ZeroTrust.DeletePolicy(id); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetZeroTrustStats handles GET /api/v1/enterprise/zerotrust/stats
func (h *EnterpriseHandler) GetZeroTrustStats(w http.ResponseWriter, r *http.Request) {
	stats := h.enterprise.ZeroTrust.GetZeroTrustStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// ============================================================================
// SIEM Endpoints
// ============================================================================

// ListSIEMIntegrations handles GET /api/v1/enterprise/siem/integrations
func (h *EnterpriseHandler) ListSIEMIntegrations(w http.ResponseWriter, r *http.Request) {
	integrations := h.enterprise.SIEM.ListIntegrations()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"integrations": integrations,
		"count":        len(integrations),
	})
}

// CreateSIEMIntegration handles POST /api/v1/enterprise/siem/integrations
func (h *EnterpriseHandler) CreateSIEMIntegration(w http.ResponseWriter, r *http.Request) {
	var config models.SIEMIntegrationConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.enterprise.SIEM.CreateIntegration(&config); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, config)
}

// GetSIEMIntegration handles GET /api/v1/enterprise/siem/integrations/{id}
func (h *EnterpriseHandler) GetSIEMIntegration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid integration ID")
		return
	}

	config, err := h.enterprise.SIEM.GetIntegration(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, config)
}

// DeleteSIEMIntegration handles DELETE /api/v1/enterprise/siem/integrations/{id}
func (h *EnterpriseHandler) DeleteSIEMIntegration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid integration ID")
		return
	}

	if err := h.enterprise.SIEM.DeleteIntegration(id); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SendSIEMEvent handles POST /api/v1/enterprise/siem/events
func (h *EnterpriseHandler) SendSIEMEvent(w http.ResponseWriter, r *http.Request) {
	var event models.SIEMEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	h.enterprise.SIEM.SendEvent(r.Context(), &event)

	h.respondJSON(w, http.StatusAccepted, map[string]string{
		"status":   "queued",
		"event_id": event.ID,
	})
}

// GetSIEMStats handles GET /api/v1/enterprise/siem/stats
func (h *EnterpriseHandler) GetSIEMStats(w http.ResponseWriter, r *http.Request) {
	stats := h.enterprise.SIEM.GetSIEMStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// ============================================================================
// Compliance Endpoints
// ============================================================================

// ListComplianceReports handles GET /api/v1/enterprise/compliance/reports
func (h *EnterpriseHandler) ListComplianceReports(w http.ResponseWriter, r *http.Request) {
	reports := h.enterprise.Compliance.ListReports()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"reports": reports,
		"count":   len(reports),
	})
}

// GenerateComplianceReport handles POST /api/v1/enterprise/compliance/reports
func (h *EnterpriseHandler) GenerateComplianceReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Framework string `json:"framework"`
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	framework := models.ComplianceFramework(req.Framework)

	// Parse dates
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		startDate = time.Now().AddDate(0, -1, 0) // Default to 1 month ago
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		endDate = time.Now()
	}

	report, err := h.enterprise.Compliance.GenerateReport(r.Context(), framework, startDate, endDate)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, report)
}

// GetComplianceReport handles GET /api/v1/enterprise/compliance/reports/{id}
func (h *EnterpriseHandler) GetComplianceReport(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid report ID")
		return
	}

	report, err := h.enterprise.Compliance.GetReport(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// GetDeviceComplianceStatus handles GET /api/v1/enterprise/compliance/devices/{id}
func (h *EnterpriseHandler) GetDeviceComplianceStatus(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid device ID")
		return
	}

	status, err := h.enterprise.Compliance.GetDeviceComplianceStatus(r.Context(), id)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, status)
}

// ListFindings handles GET /api/v1/enterprise/compliance/findings
func (h *EnterpriseHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	findings := h.enterprise.Compliance.ListFindings(status)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}

// CreateFinding handles POST /api/v1/enterprise/compliance/findings
func (h *EnterpriseHandler) CreateFinding(w http.ResponseWriter, r *http.Request) {
	var finding models.ComplianceFinding
	if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.enterprise.Compliance.CreateFinding(&finding); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, finding)
}

// GetFinding handles GET /api/v1/enterprise/compliance/findings/{id}
func (h *EnterpriseHandler) GetFinding(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid finding ID")
		return
	}

	finding, err := h.enterprise.Compliance.GetFinding(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, finding)
}

// ResolveFinding handles POST /api/v1/enterprise/compliance/findings/{id}/resolve
func (h *EnterpriseHandler) ResolveFinding(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid finding ID")
		return
	}

	var req struct {
		ResolvedBy string `json:"resolved_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.ResolvedBy = "system"
	}

	if err := h.enterprise.Compliance.ResolveFinding(id, req.ResolvedBy); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "resolved",
		"message": "Finding marked as resolved",
	})
}

// GetSupportedFrameworks handles GET /api/v1/enterprise/compliance/frameworks
func (h *EnterpriseHandler) GetSupportedFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := h.enterprise.Compliance.GetSupportedFrameworks()
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"frameworks": frameworks,
	})
}

// GetComplianceStats handles GET /api/v1/enterprise/compliance/stats
func (h *EnterpriseHandler) GetComplianceStats(w http.ResponseWriter, r *http.Request) {
	stats := h.enterprise.Compliance.GetComplianceStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// ============================================================================
// Combined Enterprise Endpoints
// ============================================================================

// GetEnterpriseStats handles GET /api/v1/enterprise/stats
func (h *EnterpriseHandler) GetEnterpriseStats(w http.ResponseWriter, r *http.Request) {
	stats := h.enterprise.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// GetEnterpriseOverview handles GET /api/v1/enterprise/overview
func (h *EnterpriseHandler) GetEnterpriseOverview(w http.ResponseWriter, r *http.Request) {
	overview := map[string]interface{}{
		"mdm": map[string]interface{}{
			"enabled":      len(h.enterprise.MDM.ListIntegrations()) > 0,
			"integrations": len(h.enterprise.MDM.ListIntegrations()),
			"stats":        h.enterprise.MDM.GetMDMStats(),
		},
		"zero_trust": map[string]interface{}{
			"enabled":  true,
			"policies": len(h.enterprise.ZeroTrust.ListPolicies()),
			"stats":    h.enterprise.ZeroTrust.GetZeroTrustStats(),
		},
		"siem": map[string]interface{}{
			"enabled":      len(h.enterprise.SIEM.ListIntegrations()) > 0,
			"integrations": len(h.enterprise.SIEM.ListIntegrations()),
			"stats":        h.enterprise.SIEM.GetSIEMStats(),
		},
		"compliance": map[string]interface{}{
			"enabled":    true,
			"reports":    len(h.enterprise.Compliance.ListReports()),
			"frameworks": h.enterprise.Compliance.GetSupportedFrameworks(),
			"stats":      h.enterprise.Compliance.GetComplianceStats(),
		},
	}

	h.respondJSON(w, http.StatusOK, overview)
}

// ============================================================================
// Helper methods
// ============================================================================

func (h *EnterpriseHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *EnterpriseHandler) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
