package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// CorrelationHandler handles correlation API requests
type CorrelationHandler struct {
	engine *services.CorrelationEngine
	logger *logger.Logger
}

// NewCorrelationHandler creates a new correlation handler
func NewCorrelationHandler(engine *services.CorrelationEngine, log *logger.Logger) *CorrelationHandler {
	return &CorrelationHandler{
		engine: engine,
		logger: log.WithComponent("correlation-handler"),
	}
}

// Correlate performs correlation analysis on provided indicators
func (h *CorrelationHandler) Correlate(w http.ResponseWriter, r *http.Request) {
	var req models.CorrelationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.IndicatorIDs) == 0 && len(req.IndicatorValues) == 0 {
		h.respondError(w, http.StatusBadRequest, "at least one indicator_id or indicator_value required", nil)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &req)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "correlation failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// CorrelateIndicator correlates a single indicator by ID
func (h *CorrelationHandler) CorrelateIndicator(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID", err)
		return
	}

	response, err := h.engine.CorrelateIndicator(r.Context(), id)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "correlation failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// CorrelateBatch correlates multiple indicators
func (h *CorrelationHandler) CorrelateBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorIDs []uuid.UUID `json:"indicator_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.IndicatorIDs) == 0 {
		h.respondError(w, http.StatusBadRequest, "indicator_ids required", nil)
		return
	}

	if len(req.IndicatorIDs) > 100 {
		h.respondError(w, http.StatusBadRequest, "maximum 100 indicators per batch", nil)
		return
	}

	response, err := h.engine.CorrelateBatch(r.Context(), req.IndicatorIDs)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "batch correlation failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// DetectCampaigns auto-detects potential campaigns
func (h *CorrelationHandler) DetectCampaigns(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	suggestions, err := h.engine.DetectCampaigns(r.Context(), limit)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "campaign detection failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"suggestions": suggestions,
		"count":       len(suggestions),
	})
}

// GetTemporalCorrelation finds indicators correlated by time
func (h *CorrelationHandler) GetTemporalCorrelation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID", err)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &models.CorrelationRequest{
		IndicatorIDs:    []uuid.UUID{id},
		Types:           []models.CorrelationType{models.CorrelationTemporal},
		IncludeEvidence: true,
	})
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "temporal correlation failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// GetInfrastructureOverlap finds indicators sharing infrastructure
func (h *CorrelationHandler) GetInfrastructureOverlap(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID", err)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &models.CorrelationRequest{
		IndicatorIDs:    []uuid.UUID{id},
		Types:           []models.CorrelationType{models.CorrelationInfrastructure},
		IncludeEvidence: true,
	})
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "infrastructure correlation failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// GetTTPCorrelation finds indicators with similar TTPs
func (h *CorrelationHandler) GetTTPCorrelation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID", err)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &models.CorrelationRequest{
		IndicatorIDs:    []uuid.UUID{id},
		Types:           []models.CorrelationType{models.CorrelationTTP},
		IncludeEvidence: true,
	})
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "TTP correlation failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// MatchCampaigns matches indicators to existing campaigns
func (h *CorrelationHandler) MatchCampaigns(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorIDs []uuid.UUID `json:"indicator_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.IndicatorIDs) == 0 {
		h.respondError(w, http.StatusBadRequest, "indicator_ids required", nil)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &models.CorrelationRequest{
		IndicatorIDs:    req.IndicatorIDs,
		Types:           []models.CorrelationType{models.CorrelationCampaign},
		IncludeEvidence: true,
	})
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "campaign matching failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"campaign_matches": response.CampaignMatches,
		"actor_matches":    response.ActorMatches,
	})
}

// GetStats returns correlation engine statistics
func (h *CorrelationHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.engine.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// AnalyzeValue analyzes a single indicator value
func (h *CorrelationHandler) AnalyzeValue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if req.Value == "" {
		h.respondError(w, http.StatusBadRequest, "value required", nil)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &models.CorrelationRequest{
		IndicatorValues: []string{req.Value},
		IncludeEvidence: true,
	})
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "analysis failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, response)
}

// ClusterIndicators clusters a set of indicators
func (h *CorrelationHandler) ClusterIndicators(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorIDs []uuid.UUID `json:"indicator_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.IndicatorIDs) < 3 {
		h.respondError(w, http.StatusBadRequest, "at least 3 indicators required for clustering", nil)
		return
	}

	response, err := h.engine.Correlate(r.Context(), &models.CorrelationRequest{
		IndicatorIDs: req.IndicatorIDs,
		Types: []models.CorrelationType{
			models.CorrelationInfrastructure,
			models.CorrelationTemporal,
		},
		IncludeEvidence: true,
	})
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "clustering failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"clusters":   response.Clusters,
		"statistics": response.Statistics,
	})
}

// respondJSON sends a JSON response
func (h *CorrelationHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error().Err(err).Msg("failed to encode JSON response")
	}
}

// respondError sends an error response
func (h *CorrelationHandler) respondError(w http.ResponseWriter, status int, message string, err error) {
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
