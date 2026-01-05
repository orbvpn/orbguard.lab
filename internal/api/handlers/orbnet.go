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

// OrbNetHandler handles OrbNet VPN integration endpoints
type OrbNetHandler struct {
	orbnet *services.OrbNetService
	logger *logger.Logger
}

// NewOrbNetHandler creates a new OrbNet handler
func NewOrbNetHandler(orbnet *services.OrbNetService, log *logger.Logger) *OrbNetHandler {
	return &OrbNetHandler{
		orbnet: orbnet,
		logger: log.WithComponent("orbnet-api"),
	}
}

// ============================================================================
// DNS Filtering
// ============================================================================

// ShouldBlockDomain handles POST /api/v1/orbnet/dns/block
func (h *OrbNetHandler) ShouldBlockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Domain == "" {
		h.respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	response := h.orbnet.ShouldBlockDomain(r.Context(), req.Domain)
	h.respondJSON(w, http.StatusOK, response)
}

// CheckDomainBatch handles POST /api/v1/orbnet/dns/block/batch
func (h *OrbNetHandler) CheckDomainBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Domains) == 0 {
		h.respondError(w, http.StatusBadRequest, "At least one domain is required")
		return
	}

	if len(req.Domains) > 1000 {
		h.respondError(w, http.StatusBadRequest, "Maximum 1000 domains per batch")
		return
	}

	results := make([]*models.DNSBlockResponse, len(req.Domains))
	for i, domain := range req.Domains {
		results[i] = h.orbnet.ShouldBlockDomain(r.Context(), domain)
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"count":   len(results),
		"blocked": countBlocked(results),
	})
}

func countBlocked(results []*models.DNSBlockResponse) int {
	count := 0
	for _, r := range results {
		if r.Blocked {
			count++
		}
	}
	return count
}

// ============================================================================
// Block Rules
// ============================================================================

// ListBlockRules handles GET /api/v1/orbnet/rules
func (h *OrbNetHandler) ListBlockRules(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	rules := h.orbnet.ListBlockRules(category)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

// GetBlockRule handles GET /api/v1/orbnet/rules/{id}
func (h *OrbNetHandler) GetBlockRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	rule, err := h.orbnet.GetBlockRule(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, rule)
}

// AddBlockRule handles POST /api/v1/orbnet/rules
func (h *OrbNetHandler) AddBlockRule(w http.ResponseWriter, r *http.Request) {
	var rule models.DNSBlockRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if rule.Domain == "" {
		h.respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	if err := h.orbnet.AddBlockRule(&rule); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, rule)
}

// RemoveBlockRule handles DELETE /api/v1/orbnet/rules/{id}
func (h *OrbNetHandler) RemoveBlockRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	if err := h.orbnet.RemoveBlockRule(id); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EmergencyBlock handles POST /api/v1/orbnet/emergency-block
func (h *OrbNetHandler) EmergencyBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains  []string `json:"domains"`
		Reason   string   `json:"reason"`
		Duration string   `json:"duration,omitempty"` // e.g., "24h", "1h"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Domains) == 0 {
		h.respondError(w, http.StatusBadRequest, "At least one domain is required")
		return
	}

	var duration time.Duration
	if req.Duration != "" {
		var err error
		duration, err = time.ParseDuration(req.Duration)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "Invalid duration format")
			return
		}
	}

	if err := h.orbnet.EmergencyBlock(r.Context(), req.Domains, req.Reason, duration); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "blocked",
		"domains": req.Domains,
		"reason":  req.Reason,
		"message": "Emergency block activated",
	})
}

// ============================================================================
// Servers
// ============================================================================

// RegisterServer handles POST /api/v1/orbnet/servers
func (h *OrbNetHandler) RegisterServer(w http.ResponseWriter, r *http.Request) {
	var server models.OrbNetServer
	if err := json.NewDecoder(r.Body).Decode(&server); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if server.Hostname == "" {
		h.respondError(w, http.StatusBadRequest, "Hostname is required")
		return
	}

	if err := h.orbnet.RegisterServer(&server); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, server)
}

// ListServers handles GET /api/v1/orbnet/servers
func (h *OrbNetHandler) ListServers(w http.ResponseWriter, r *http.Request) {
	servers := h.orbnet.ListServers()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"servers": servers,
		"count":   len(servers),
	})
}

// GetServer handles GET /api/v1/orbnet/servers/{id}
func (h *OrbNetHandler) GetServer(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	server, err := h.orbnet.GetServer(id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, server)
}

// UpdateServerStatus handles PUT /api/v1/orbnet/servers/{id}/status
func (h *OrbNetHandler) UpdateServerStatus(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	var req struct {
		Status      string  `json:"status"`
		Load        float64 `json:"load"`
		Connections int     `json:"connections"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.orbnet.UpdateServerStatus(id, req.Status, req.Load, req.Connections); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "updated",
		"message": "Server status updated",
	})
}

// ============================================================================
// Threat Sync
// ============================================================================

// SyncThreatData handles POST /api/v1/orbnet/sync
func (h *OrbNetHandler) SyncThreatData(w http.ResponseWriter, r *http.Request) {
	var req models.ThreatSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ServerID == uuid.Nil {
		h.respondError(w, http.StatusBadRequest, "Server ID is required")
		return
	}

	response, err := h.orbnet.SyncThreatData(r.Context(), &req)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// ============================================================================
// Dashboard & Stats
// ============================================================================

// GetDashboardStats handles GET /api/v1/orbnet/dashboard
func (h *OrbNetHandler) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats := h.orbnet.GetDashboardStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// GetCategories handles GET /api/v1/orbnet/categories
func (h *OrbNetHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories := h.orbnet.GetCategories()
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"categories": categories,
	})
}

// ============================================================================
// Helper methods
// ============================================================================

func (h *OrbNetHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *OrbNetHandler) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
