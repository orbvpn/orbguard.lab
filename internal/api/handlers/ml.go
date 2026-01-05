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

// MLHandler handles Machine Learning API requests
type MLHandler struct {
	service *services.MLService
	logger  *logger.Logger
}

// NewMLHandler creates a new ML handler
func NewMLHandler(service *services.MLService, log *logger.Logger) *MLHandler {
	return &MLHandler{
		service: service,
		logger:  log.WithComponent("ml-handler"),
	}
}

// EnrichIndicator enriches an indicator with ML analysis
func (h *MLHandler) EnrichIndicator(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID", err)
		return
	}

	result, err := h.service.AnalyzeIndicator(r.Context(), id)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "failed to analyze indicator", err)
		return
	}

	if result == nil {
		h.respondError(w, http.StatusNotFound, "indicator not found", nil)
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// DetectAnomalies runs anomaly detection on indicators
func (h *MLHandler) DetectAnomalies(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorIDs []uuid.UUID `json:"indicator_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Note: In production, would fetch indicators from database
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "anomaly detection requires indicators to be fetched from database",
		"count":   len(req.IndicatorIDs),
	})
}

// ClusterIndicators clusters indicators into groups
func (h *MLHandler) ClusterIndicators(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorIDs []uuid.UUID `json:"indicator_ids"`
		K            int         `json:"k"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if req.K <= 0 {
		req.K = 5 // Default
	}

	// Note: In production, would fetch indicators and cluster
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "clustering requires indicators to be fetched from database",
		"requested_k":   req.K,
		"indicator_ids": len(req.IndicatorIDs),
	})
}

// PredictSeverity predicts severity for indicators
func (h *MLHandler) PredictSeverity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorIDs []uuid.UUID `json:"indicator_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "severity prediction requires indicators to be fetched from database",
		"count":   len(req.IndicatorIDs),
	})
}

// ExtractEntities extracts entities from text
func (h *MLHandler) ExtractEntities(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if req.Text == "" {
		h.respondError(w, http.StatusBadRequest, "text is required", nil)
		return
	}

	result := h.service.ExtractEntities(req.Text)
	h.respondJSON(w, http.StatusOK, result)
}

// ExtractIndicators extracts IOCs from text
func (h *MLHandler) ExtractIndicators(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if req.Text == "" {
		h.respondError(w, http.StatusBadRequest, "text is required", nil)
		return
	}

	indicators := h.service.ExtractIndicatorsFromText(req.Text)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"indicators": indicators,
		"count":      len(indicators),
	})
}

// Train trains all ML models
func (h *MLHandler) Train(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.Train(r.Context())
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "training failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// TrainModel trains a specific model
func (h *MLHandler) TrainModel(w http.ResponseWriter, r *http.Request) {
	modelType := chi.URLParam(r, "model")

	result, err := h.service.TrainModel(r.Context(), modelType)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "training failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// GetStats returns ML service statistics
func (h *MLHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.service.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// GetModelInfo returns information about a specific model
func (h *MLHandler) GetModelInfo(w http.ResponseWriter, r *http.Request) {
	modelType := chi.URLParam(r, "model")

	info := h.service.GetModelInfo(modelType)
	if info == nil {
		h.respondError(w, http.StatusNotFound, "model not found", nil)
		return
	}

	h.respondJSON(w, http.StatusOK, info)
}

// GetFeatures returns the list of features used by ML models
func (h *MLHandler) GetFeatures(w http.ResponseWriter, r *http.Request) {
	features := h.service.GetFeatureNames()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"features": features,
		"count":    len(features),
	})
}

// AnalyzeValue performs ML analysis on a raw value
func (h *MLHandler) AnalyzeValue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value string              `json:"value"`
		Type  models.IndicatorType `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if req.Value == "" {
		h.respondError(w, http.StatusBadRequest, "value is required", nil)
		return
	}

	// Create temporary indicator for analysis
	indicator := &models.Indicator{
		ID:    uuid.New(),
		Value: req.Value,
		Type:  req.Type,
	}

	result, err := h.service.EnrichIndicator(r.Context(), indicator)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "analysis failed", err)
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// respondJSON sends a JSON response
func (h *MLHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error().Err(err).Msg("failed to encode JSON response")
	}
}

// respondError sends an error response
func (h *MLHandler) respondError(w http.ResponseWriter, status int, message string, err error) {
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
