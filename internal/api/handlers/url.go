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

// URLHandler handles URL protection API requests
type URLHandler struct {
	urlService *services.URLReputationService
	logger     *logger.Logger
}

// NewURLHandler creates a new URL handler
func NewURLHandler(urlService *services.URLReputationService, log *logger.Logger) *URLHandler {
	return &URLHandler{
		urlService: urlService,
		logger:     log.WithComponent("url-handler"),
	}
}

// CheckURL handles POST /api/v1/url/check
func (h *URLHandler) CheckURL(w http.ResponseWriter, r *http.Request) {
	var req models.URLCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" {
		h.respondError(w, http.StatusBadRequest, "url is required")
		return
	}

	result, err := h.urlService.CheckURL(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Str("url", req.URL).Msg("failed to check URL")
		h.respondError(w, http.StatusInternalServerError, "failed to check URL")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// BatchCheckURLs handles POST /api/v1/url/check/batch
func (h *URLHandler) BatchCheckURLs(w http.ResponseWriter, r *http.Request) {
	var req models.URLBatchCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.URLs) == 0 {
		h.respondError(w, http.StatusBadRequest, "urls array is required")
		return
	}

	if len(req.URLs) > 100 {
		h.respondError(w, http.StatusBadRequest, "maximum 100 URLs per batch")
		return
	}

	result, err := h.urlService.BatchCheckURLs(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Int("count", len(req.URLs)).Msg("failed to batch check URLs")
		h.respondError(w, http.StatusInternalServerError, "failed to check URLs")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// GetReputation handles GET /api/v1/url/reputation/{domain}
func (h *URLHandler) GetReputation(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		h.respondError(w, http.StatusBadRequest, "domain is required")
		return
	}

	rep, err := h.urlService.GetDomainReputation(r.Context(), domain)
	if err != nil {
		h.logger.Error().Err(err).Str("domain", domain).Msg("failed to get domain reputation")
		h.respondError(w, http.StatusInternalServerError, "failed to get reputation")
		return
	}

	if rep == nil {
		h.respondError(w, http.StatusNotFound, "no reputation data for domain")
		return
	}

	h.respondJSON(w, http.StatusOK, rep)
}

// GetStats handles GET /api/v1/url/stats
func (h *URLHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.urlService.GetStats(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get URL stats")
		h.respondError(w, http.StatusInternalServerError, "failed to get stats")
		return
	}

	h.respondJSON(w, http.StatusOK, stats)
}

// GetDNSBlockRules handles GET /api/v1/url/dns-rules
func (h *URLHandler) GetDNSBlockRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.urlService.GetDNSBlockRules(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get DNS block rules")
		h.respondError(w, http.StatusInternalServerError, "failed to get DNS rules")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"rules":      rules,
		"count":      len(rules),
		"updated_at": time.Now(),
	})
}

// AddToWhitelist handles POST /api/v1/url/whitelist
func (h *URLHandler) AddToWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL     string `json:"url,omitempty"`
		Domain  string `json:"domain,omitempty"`
		Pattern string `json:"pattern,omitempty"`
		Reason  string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" && req.Domain == "" && req.Pattern == "" {
		h.respondError(w, http.StatusBadRequest, "url, domain, or pattern is required")
		return
	}

	entry := &models.URLListEntry{
		ID:        uuid.New(),
		URL:       req.URL,
		Domain:    req.Domain,
		Pattern:   req.Pattern,
		ListType:  models.URLListTypeWhitelist,
		Reason:    req.Reason,
		CreatedBy: "api",
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	if err := h.urlService.AddToList(r.Context(), entry); err != nil {
		h.logger.Error().Err(err).Msg("failed to add to whitelist")
		h.respondError(w, http.StatusInternalServerError, "failed to add to whitelist")
		return
	}

	h.respondJSON(w, http.StatusCreated, entry)
}

// AddToBlacklist handles POST /api/v1/url/blacklist
func (h *URLHandler) AddToBlacklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL     string `json:"url,omitempty"`
		Domain  string `json:"domain,omitempty"`
		Pattern string `json:"pattern,omitempty"`
		Reason  string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" && req.Domain == "" && req.Pattern == "" {
		h.respondError(w, http.StatusBadRequest, "url, domain, or pattern is required")
		return
	}

	entry := &models.URLListEntry{
		ID:        uuid.New(),
		URL:       req.URL,
		Domain:    req.Domain,
		Pattern:   req.Pattern,
		ListType:  models.URLListTypeBlacklist,
		Reason:    req.Reason,
		CreatedBy: "api",
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	if err := h.urlService.AddToList(r.Context(), entry); err != nil {
		h.logger.Error().Err(err).Msg("failed to add to blacklist")
		h.respondError(w, http.StatusInternalServerError, "failed to add to blacklist")
		return
	}

	h.respondJSON(w, http.StatusCreated, entry)
}

// GetWhitelist handles GET /api/v1/url/whitelist
func (h *URLHandler) GetWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := h.urlService.GetList(r.Context(), models.URLListTypeWhitelist)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get whitelist")
		h.respondError(w, http.StatusInternalServerError, "failed to get whitelist")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// GetBlacklist handles GET /api/v1/url/blacklist
func (h *URLHandler) GetBlacklist(w http.ResponseWriter, r *http.Request) {
	entries, err := h.urlService.GetList(r.Context(), models.URLListTypeBlacklist)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get blacklist")
		h.respondError(w, http.StatusInternalServerError, "failed to get blacklist")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// RemoveFromList handles DELETE /api/v1/url/list/{id}
func (h *URLHandler) RemoveFromList(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.urlService.RemoveFromList(r.Context(), id); err != nil {
		h.logger.Error().Err(err).Str("id", idStr).Msg("failed to remove from list")
		h.respondError(w, http.StatusInternalServerError, "failed to remove from list")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetBlockPage handles GET /api/v1/url/block-page
func (h *URLHandler) GetBlockPage(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	if url == "" {
		h.respondError(w, http.StatusBadRequest, "url query parameter is required")
		return
	}

	// Check the URL to get threat details
	result, err := h.urlService.CheckURL(r.Context(), &models.URLCheckRequest{URL: url})
	if err != nil {
		h.logger.Error().Err(err).Str("url", url).Msg("failed to check URL for block page")
		h.respondError(w, http.StatusInternalServerError, "failed to generate block page")
		return
	}

	blockData := &models.BlockPageData{
		URL:           url,
		Domain:        result.Domain,
		Category:      result.Category,
		ThreatLevel:   result.ThreatLevel,
		Reason:        result.BlockReason,
		AllowOverride: result.AllowOverride,
		ReportURL:     "/api/v1/url/report",
		Timestamp:     time.Now(),
	}

	h.respondJSON(w, http.StatusOK, blockData)
}

// ReportURL handles POST /api/v1/url/report
func (h *URLHandler) ReportURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL        string `json:"url"`
		ReportType string `json:"report_type"` // "false_positive", "missed_threat", "feedback"
		Comment    string `json:"comment,omitempty"`
		DeviceID   string `json:"device_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" || req.ReportType == "" {
		h.respondError(w, http.StatusBadRequest, "url and report_type are required")
		return
	}

	// Log the report
	h.logger.Info().
		Str("url", req.URL).
		Str("report_type", req.ReportType).
		Str("device_id", req.DeviceID).
		Msg("URL report received")

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "received",
		"message": "Thank you for your report. It will be reviewed.",
	})
}

func (h *URLHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *URLHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}
