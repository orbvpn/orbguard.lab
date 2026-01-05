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

// DeviceSecurityHandler handles device security API requests
type DeviceSecurityHandler struct {
	service *services.DeviceSecurityService
	logger  *logger.Logger
}

// NewDeviceSecurityHandler creates a new device security handler
func NewDeviceSecurityHandler(service *services.DeviceSecurityService, log *logger.Logger) *DeviceSecurityHandler {
	return &DeviceSecurityHandler{
		service: service,
		logger:  log.WithComponent("device-security-handler"),
	}
}

// RegisterDevice handles POST /api/v1/device/register
func (h *DeviceSecurityHandler) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	var device models.SecureDeviceInfo
	if err := json.NewDecoder(r.Body).Decode(&device); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if device.DeviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.RegisterDevice(r.Context(), &device); err != nil {
		h.logger.Error().Err(err).Msg("failed to register device")
		h.respondError(w, http.StatusInternalServerError, "failed to register device")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":  "registered",
		"device":  device,
	})
}

// UpdateDevice handles PUT /api/v1/device/{device_id}
func (h *DeviceSecurityHandler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var update models.SecureDeviceInfo
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.service.UpdateDevice(r.Context(), deviceID, &update); err != nil {
		h.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to update device")
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "updated",
		"device_id": deviceID,
	})
}

// GetDevice handles GET /api/v1/device/{device_id}
func (h *DeviceSecurityHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	device, err := h.service.GetDevice(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, device)
}

// UpdateLocation handles POST /api/v1/device/{device_id}/location
func (h *DeviceSecurityHandler) UpdateLocation(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var location models.Location
	if err := json.NewDecoder(r.Body).Decode(&location); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.service.UpdateLocation(r.Context(), deviceID, &location); err != nil {
		h.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to update location")
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "updated",
		"location": location,
	})
}

// GetLocationHistory handles GET /api/v1/device/{device_id}/location/history
func (h *DeviceSecurityHandler) GetLocationHistory(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	limit := 50 // Default limit
	locations, err := h.service.GetLocationHistory(r.Context(), deviceID, limit)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"locations": locations,
		"count":     len(locations),
	})
}

// IssueCommand handles POST /api/v1/device/{device_id}/command
func (h *DeviceSecurityHandler) IssueCommand(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var cmd models.RemoteCommand
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cmd.DeviceID = deviceID

	if err := h.service.IssueCommand(r.Context(), &cmd); err != nil {
		h.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to issue command")
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":     "issued",
		"command_id": cmd.ID,
		"type":       cmd.Type,
		"expires_at": cmd.ExpiresAt,
	})
}

// GetPendingCommands handles GET /api/v1/device/{device_id}/commands/pending
func (h *DeviceSecurityHandler) GetPendingCommands(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	commands, err := h.service.GetPendingCommands(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"commands":  commands,
		"count":     len(commands),
	})
}

// AcknowledgeCommand handles POST /api/v1/device/{device_id}/command/{command_id}/ack
func (h *DeviceSecurityHandler) AcknowledgeCommand(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	commandIDStr := chi.URLParam(r, "command_id")

	if deviceID == "" || commandIDStr == "" {
		h.respondError(w, http.StatusBadRequest, "device_id and command_id are required")
		return
	}

	commandID, err := uuid.Parse(commandIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid command_id")
		return
	}

	var req struct {
		Result string `json:"result"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var ackErr error
	if req.Error != "" {
		ackErr = &commandError{message: req.Error}
	}

	if err := h.service.AcknowledgeCommand(r.Context(), deviceID, commandID, req.Result, ackErr); err != nil {
		h.logger.Error().Err(err).Msg("failed to acknowledge command")
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "acknowledged",
		"command_id": commandID,
	})
}

// commandError implements error interface
type commandError struct {
	message string
}

func (e *commandError) Error() string {
	return e.message
}

// Locate handles POST /api/v1/device/{device_id}/locate
func (h *DeviceSecurityHandler) Locate(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	cmd := &models.RemoteCommand{
		DeviceID: deviceID,
		Type:     models.CommandLocate,
	}

	if err := h.service.IssueCommand(r.Context(), cmd); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "locate_requested",
		"command_id": cmd.ID,
	})
}

// Lock handles POST /api/v1/device/{device_id}/lock
func (h *DeviceSecurityHandler) Lock(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var payload models.LockCommandPayload
	_ = json.NewDecoder(r.Body).Decode(&payload)

	payloadJSON, _ := json.Marshal(payload)
	cmd := &models.RemoteCommand{
		DeviceID: deviceID,
		Type:     models.CommandLock,
		Payload:  string(payloadJSON),
	}

	if err := h.service.IssueCommand(r.Context(), cmd); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "lock_requested",
		"command_id": cmd.ID,
	})
}

// Wipe handles POST /api/v1/device/{device_id}/wipe
func (h *DeviceSecurityHandler) Wipe(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var payload models.WipeCommandPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if payload.ConfirmationID == "" {
		h.respondError(w, http.StatusBadRequest, "confirmation_id is required for wipe command")
		return
	}

	payloadJSON, _ := json.Marshal(payload)
	cmd := &models.RemoteCommand{
		DeviceID: deviceID,
		Type:     models.CommandWipe,
		Payload:  string(payloadJSON),
	}

	if err := h.service.IssueCommand(r.Context(), cmd); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "wipe_requested",
		"command_id": cmd.ID,
		"warning":    "This action cannot be undone. Device will be factory reset.",
	})
}

// Ring handles POST /api/v1/device/{device_id}/ring
func (h *DeviceSecurityHandler) Ring(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	cmd := &models.RemoteCommand{
		DeviceID: deviceID,
		Type:     models.CommandRing,
	}

	if err := h.service.IssueCommand(r.Context(), cmd); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ring_requested",
		"command_id": cmd.ID,
	})
}

// ReportSIM handles POST /api/v1/device/{device_id}/sim
func (h *DeviceSecurityHandler) ReportSIM(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var sims []*models.SIMInfo
	if err := json.NewDecoder(r.Body).Decode(&sims); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.service.ReportSIMInfo(r.Context(), deviceID, sims); err != nil {
		h.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to report SIM")
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "reported",
		"device_id": deviceID,
		"sim_count": len(sims),
	})
}

// GetSIMHistory handles GET /api/v1/device/{device_id}/sim/history
func (h *DeviceSecurityHandler) GetSIMHistory(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	events, err := h.service.GetSIMHistory(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"events":    events,
		"count":     len(events),
	})
}

// GetCurrentSIMs handles GET /api/v1/device/{device_id}/sim
func (h *DeviceSecurityHandler) GetCurrentSIMs(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	sims, err := h.service.GetCurrentSIMs(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"sims":      sims,
		"count":     len(sims),
	})
}

// AddTrustedSIM handles POST /api/v1/device/{device_id}/sim/trusted
func (h *DeviceSecurityHandler) AddTrustedSIM(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var req struct {
		ICCID string `json:"iccid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ICCID == "" {
		h.respondError(w, http.StatusBadRequest, "iccid is required")
		return
	}

	if err := h.service.AddTrustedSIM(r.Context(), deviceID, req.ICCID); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "added",
		"device_id": deviceID,
		"iccid":     req.ICCID,
	})
}

// RecordThiefSelfie handles POST /api/v1/device/{device_id}/selfie
func (h *DeviceSecurityHandler) RecordThiefSelfie(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var selfie models.ThiefSelfie
	if err := json.NewDecoder(r.Body).Decode(&selfie); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	selfie.DeviceID = deviceID

	if err := h.service.RecordThiefSelfie(r.Context(), &selfie); err != nil {
		h.logger.Error().Err(err).Str("device_id", deviceID).Msg("failed to record selfie")
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"status":    "recorded",
		"selfie_id": selfie.ID,
	})
}

// GetThiefSelfies handles GET /api/v1/device/{device_id}/selfies
func (h *DeviceSecurityHandler) GetThiefSelfies(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	selfies, err := h.service.GetThiefSelfies(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"selfies":   selfies,
		"count":     len(selfies),
	})
}

// GetSettings handles GET /api/v1/device/{device_id}/settings
func (h *DeviceSecurityHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	settings, err := h.service.GetSettings(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, settings)
}

// UpdateSettings handles PUT /api/v1/device/{device_id}/settings
func (h *DeviceSecurityHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var settings models.AntiTheftSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.service.UpdateSettings(r.Context(), deviceID, &settings); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "updated",
		"device_id": deviceID,
	})
}

// MarkLost handles POST /api/v1/device/{device_id}/mark-lost
func (h *DeviceSecurityHandler) MarkLost(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.MarkDeviceLost(r.Context(), deviceID); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "marked_lost",
		"device_id": deviceID,
	})
}

// MarkStolen handles POST /api/v1/device/{device_id}/mark-stolen
func (h *DeviceSecurityHandler) MarkStolen(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.MarkDeviceStolen(r.Context(), deviceID); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "marked_stolen",
		"device_id": deviceID,
	})
}

// MarkRecovered handles POST /api/v1/device/{device_id}/mark-recovered
func (h *DeviceSecurityHandler) MarkRecovered(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	if err := h.service.MarkDeviceRecovered(r.Context(), deviceID); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "marked_recovered",
		"device_id": deviceID,
	})
}

// AuditOSVulnerabilities handles POST /api/v1/device/vulnerabilities/audit
func (h *DeviceSecurityHandler) AuditOSVulnerabilities(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID      string `json:"device_id"`
		Platform      string `json:"platform"`
		OSVersion     string `json:"os_version"`
		SecurityPatch string `json:"security_patch"`
		APILevel      int    `json:"api_level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Platform == "" || req.OSVersion == "" {
		h.respondError(w, http.StatusBadRequest, "platform and os_version are required")
		return
	}

	result := h.service.AuditOSVulnerabilities(r.Context(), req.DeviceID, req.Platform, req.OSVersion, req.SecurityPatch, req.APILevel)
	h.respondJSON(w, http.StatusOK, result)
}

// GetKnownVulnerabilities handles GET /api/v1/device/vulnerabilities
func (h *DeviceSecurityHandler) GetKnownVulnerabilities(w http.ResponseWriter, r *http.Request) {
	platform := r.URL.Query().Get("platform")

	var vulns []models.OSVulnerability

	switch platform {
	case "android":
		vulns = models.KnownAndroidVulnerabilities
	case "ios":
		vulns = models.KnowniOSVulnerabilities
	default:
		// Return all
		vulns = append(vulns, models.KnownAndroidVulnerabilities...)
		vulns = append(vulns, models.KnowniOSVulnerabilities...)
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"vulnerabilities": vulns,
		"count":           len(vulns),
		"platform":        platform,
	})
}

// GetSecurityStatus handles GET /api/v1/device/{device_id}/security-status
func (h *DeviceSecurityHandler) GetSecurityStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		h.respondError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	status, err := h.service.GetDeviceSecurityStatus(r.Context(), deviceID)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, status)
}

// GetLatestSecurityInfo handles GET /api/v1/device/security-info
func (h *DeviceSecurityHandler) GetLatestSecurityInfo(w http.ResponseWriter, r *http.Request) {
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"android": models.LatestAndroidSecurity,
		"ios":     models.LatestiOSSecurity,
	})
}

// GetStats handles GET /api/v1/device/stats
func (h *DeviceSecurityHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.service.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

func (h *DeviceSecurityHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *DeviceSecurityHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}
