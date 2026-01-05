package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// MITREHandler handles MITRE ATT&CK API requests
type MITREHandler struct {
	service *services.MITREService
	logger  *logger.Logger
}

// NewMITREHandler creates a new MITRE handler
func NewMITREHandler(service *services.MITREService, log *logger.Logger) *MITREHandler {
	return &MITREHandler{
		service: service,
		logger:  log.WithComponent("mitre-handler"),
	}
}

// ListTactics lists all MITRE ATT&CK tactics
func (h *MITREHandler) ListTactics(w http.ResponseWriter, r *http.Request) {
	domain := models.MITREDomain(r.URL.Query().Get("domain"))

	tactics := h.service.ListTactics(domain)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"tactics": tactics,
		"count":   len(tactics),
	})
}

// GetTactic gets a specific tactic by ID
func (h *MITREHandler) GetTactic(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	tactic := h.service.GetTactic(id)
	if tactic == nil {
		// Try by short name
		tactic = h.service.GetTacticByShortName(id)
	}

	if tactic == nil {
		h.respondError(w, http.StatusNotFound, "tactic not found", nil)
		return
	}

	// Include techniques for this tactic
	techniques := h.service.GetTechniquesByTactic(tactic.ShortName)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"tactic":     tactic,
		"techniques": techniques,
	})
}

// ListTechniques lists MITRE ATT&CK techniques with filtering
func (h *MITREHandler) ListTechniques(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	filter := &models.MITRETechniqueFilter{
		TacticID: query.Get("tactic"),
		Platform: query.Get("platform"),
		Domain:   models.MITREDomain(query.Get("domain")),
		Query:    query.Get("q"),
	}

	if query.Get("include_revoked") == "true" {
		filter.IncludeRevoked = true
	}

	if query.Get("sub_techniques") == "true" {
		isSubTech := true
		filter.IsSubTechnique = &isSubTech
	} else if query.Get("sub_techniques") == "false" {
		isSubTech := false
		filter.IsSubTechnique = &isSubTech
	}

	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	techniques := h.service.ListTechniques(filter)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"techniques": techniques,
		"count":      len(techniques),
		"filter":     filter,
	})
}

// GetTechnique gets a specific technique by ID
func (h *MITREHandler) GetTechnique(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	technique := h.service.GetTechnique(id)
	if technique == nil {
		h.respondError(w, http.StatusNotFound, "technique not found", nil)
		return
	}

	// Include sub-techniques if this is a parent technique
	var subTechniques []*models.MITRETechnique
	if !technique.IsSubTechnique {
		isSubTech := true
		allTech := h.service.ListTechniques(&models.MITRETechniqueFilter{
			IsSubTechnique: &isSubTech,
		})
		for _, t := range allTech {
			if t.ParentID == technique.ID {
				subTechniques = append(subTechniques, t)
			}
		}
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"technique":      technique,
		"sub_techniques": subTechniques,
	})
}

// SearchTechniques searches techniques
func (h *MITREHandler) SearchTechniques(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondError(w, http.StatusBadRequest, "query parameter 'q' required", nil)
		return
	}

	techniques := h.service.SearchTechniques(query)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"query":      query,
		"techniques": techniques,
		"count":      len(techniques),
	})
}

// ListMitigations lists all mitigations
func (h *MITREHandler) ListMitigations(w http.ResponseWriter, r *http.Request) {
	mitigations := h.service.ListMitigations()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"mitigations": mitigations,
		"count":       len(mitigations),
	})
}

// GetMitigation gets a specific mitigation
func (h *MITREHandler) GetMitigation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	mitigation := h.service.GetMitigation(id)
	if mitigation == nil {
		h.respondError(w, http.StatusNotFound, "mitigation not found", nil)
		return
	}

	h.respondJSON(w, http.StatusOK, mitigation)
}

// ListGroups lists all threat groups
func (h *MITREHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	groups := h.service.ListGroups()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"groups": groups,
		"count":  len(groups),
	})
}

// GetGroup gets a specific threat group
func (h *MITREHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	group := h.service.GetGroup(id)
	if group == nil {
		h.respondError(w, http.StatusNotFound, "group not found", nil)
		return
	}

	h.respondJSON(w, http.StatusOK, group)
}

// ListSoftware lists all software (malware/tools)
func (h *MITREHandler) ListSoftware(w http.ResponseWriter, r *http.Request) {
	software := h.service.ListSoftware()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"software": software,
		"count":    len(software),
	})
}

// GetSoftware gets specific software
func (h *MITREHandler) GetSoftware(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	software := h.service.GetSoftware(id)
	if software == nil {
		h.respondError(w, http.StatusNotFound, "software not found", nil)
		return
	}

	h.respondJSON(w, http.StatusOK, software)
}

// GetMatrix returns the full ATT&CK matrix
func (h *MITREHandler) GetMatrix(w http.ResponseWriter, r *http.Request) {
	domain := models.MITREDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		domain = models.MITREDomainMobile
	}

	tactics := h.service.ListTactics(domain)
	techniques := h.service.ListTechniques(&models.MITRETechniqueFilter{
		Domain: domain,
	})
	mitigations := h.service.ListMitigations()
	groups := h.service.ListGroups()
	software := h.service.ListSoftware()

	matrix := models.MITREMatrix{
		Domain:      domain,
		Name:        string(domain) + " Matrix",
		Tactics:     make([]models.MITRETactic, 0, len(tactics)),
		Techniques:  make([]models.MITRETechnique, 0, len(techniques)),
		Mitigations: make([]models.MITREMitigation, 0, len(mitigations)),
		Groups:      make([]models.MITREGroup, 0, len(groups)),
		Software:    make([]models.MITRESoftware, 0, len(software)),
	}

	for _, t := range tactics {
		matrix.Tactics = append(matrix.Tactics, *t)
	}
	for _, t := range techniques {
		matrix.Techniques = append(matrix.Techniques, *t)
	}
	for _, m := range mitigations {
		matrix.Mitigations = append(matrix.Mitigations, *m)
	}
	for _, g := range groups {
		matrix.Groups = append(matrix.Groups, *g)
	}
	for _, s := range software {
		matrix.Software = append(matrix.Software, *s)
	}

	h.respondJSON(w, http.StatusOK, matrix)
}

// ExportNavigatorLayer exports techniques as ATT&CK Navigator layer
func (h *MITREHandler) ExportNavigatorLayer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Techniques  []string `json:"techniques"`
		Domain      string   `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if req.Name == "" {
		req.Name = "OrbGuard Threat Layer"
	}
	if req.Description == "" {
		req.Description = "Generated by OrbGuard"
	}

	domain := models.MITREDomain(req.Domain)
	if domain == "" {
		domain = models.MITREDomainMobile
	}

	layer := h.service.GenerateNavigatorLayer(req.Name, req.Description, req.Techniques, domain)

	// Set download headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"navigator_layer.json\"")

	json.NewEncoder(w).Encode(layer)
}

// GetStats returns MITRE service statistics
func (h *MITREHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.service.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// Reload reloads MITRE data
func (h *MITREHandler) Reload(w http.ResponseWriter, r *http.Request) {
	// This would reload from files if configured
	if err := h.service.LoadEmbeddedData(); err != nil {
		h.respondError(w, http.StatusInternalServerError, "failed to reload MITRE data", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "MITRE data reloaded",
		"stats":   h.service.GetStats(),
	})
}

// respondJSON sends a JSON response
func (h *MITREHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error().Err(err).Msg("failed to encode JSON response")
	}
}

// respondError sends an error response
func (h *MITREHandler) respondError(w http.ResponseWriter, status int, message string, err error) {
	if err != nil {
		h.logger.Error().Err(err).Msg(message)
	}

	h.respondJSON(w, status, map[string]interface{}{
		"error":   message,
		"details": func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})
}
