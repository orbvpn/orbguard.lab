package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// GraphHandler handles graph-related HTTP requests
type GraphHandler struct {
	graphService *services.GraphService
	logger       *logger.Logger
}

// NewGraphHandler creates a new graph handler
func NewGraphHandler(graphService *services.GraphService, log *logger.Logger) *GraphHandler {
	return &GraphHandler{
		graphService: graphService,
		logger:       log.WithComponent("graph-handler"),
	}
}

// respondJSON sends a JSON response
func (h *GraphHandler) respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondError sends an error response
func (h *GraphHandler) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// GetCorrelation returns correlation data for an indicator
// @Summary Get indicator correlation
// @Description Get related indicators, campaigns, and actors for an indicator
// @Tags graph
// @Accept json
// @Produce json
// @Param id path string true "Indicator UUID"
// @Success 200 {object} models.CorrelationResult
// @Router /api/v1/graph/correlation/{id} [get]
func (h *GraphHandler) GetCorrelation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	indicatorID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID")
		return
	}

	correlation, err := h.graphService.GetCorrelation(r.Context(), indicatorID)
	if err != nil {
		h.logger.Error().Err(err).Str("indicator_id", idStr).Msg("failed to get correlation")
		h.respondError(w, http.StatusInternalServerError, "failed to get correlation")
		return
	}

	h.respondJSON(w, http.StatusOK, correlation)
}

// FindRelated finds indicators related to a given indicator
// @Summary Find related indicators
// @Description Find indicators that are related through the threat graph
// @Tags graph
// @Accept json
// @Produce json
// @Param id path string true "Indicator UUID"
// @Param max_depth query int false "Maximum traversal depth" default(2)
// @Param limit query int false "Maximum results" default(50)
// @Success 200 {array} models.RelatedIndicator
// @Router /api/v1/graph/related/{id} [get]
func (h *GraphHandler) FindRelated(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	indicatorID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID")
		return
	}

	maxDepth := 2
	if d := r.URL.Query().Get("max_depth"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 5 {
			maxDepth = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	related, err := h.graphService.FindRelated(r.Context(), indicatorID, maxDepth, limit)
	if err != nil {
		h.logger.Error().Err(err).Str("indicator_id", idStr).Msg("failed to find related indicators")
		h.respondError(w, http.StatusInternalServerError, "failed to find related indicators")
		return
	}

	h.respondJSON(w, http.StatusOK, related)
}

// FindSharedInfrastructure finds indicators sharing infrastructure
// @Summary Find shared infrastructure
// @Description Find indicators that share infrastructure (IPs, domains, ASNs)
// @Tags graph
// @Accept json
// @Produce json
// @Param limit query int false "Maximum results" default(50)
// @Success 200 {object} models.InfrastructureOverlapResult
// @Router /api/v1/graph/shared-infrastructure [get]
func (h *GraphHandler) FindSharedInfrastructure(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	result, err := h.graphService.FindSharedInfrastructure(r.Context(), limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to find shared infrastructure")
		h.respondError(w, http.StatusInternalServerError, "failed to find shared infrastructure")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// DetectCampaigns attempts to auto-detect new campaigns
// @Summary Detect campaigns
// @Description Auto-detect potential new campaigns based on shared infrastructure and patterns
// @Tags graph
// @Accept json
// @Produce json
// @Param min_shared query int false "Minimum shared infrastructure" default(2)
// @Param limit query int false "Maximum results" default(20)
// @Success 200 {array} models.CampaignDetection
// @Router /api/v1/graph/detect-campaigns [get]
func (h *GraphHandler) DetectCampaigns(w http.ResponseWriter, r *http.Request) {
	minShared := 2
	if m := r.URL.Query().Get("min_shared"); m != "" {
		if parsed, err := strconv.Atoi(m); err == nil && parsed > 0 {
			minShared = parsed
		}
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	campaigns, err := h.graphService.DetectCampaigns(r.Context(), minShared, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to detect campaigns")
		h.respondError(w, http.StatusInternalServerError, "failed to detect campaigns")
		return
	}

	h.respondJSON(w, http.StatusOK, campaigns)
}

// TraverseGraph performs a graph traversal
// @Summary Traverse graph
// @Description Perform a custom graph traversal from a starting node
// @Tags graph
// @Accept json
// @Produce json
// @Param body body models.GraphTraversalRequest true "Traversal request"
// @Success 200 {object} models.GraphQueryResult
// @Router /api/v1/graph/traverse [post]
func (h *GraphHandler) TraverseGraph(w http.ResponseWriter, r *http.Request) {
	var req models.GraphTraversalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Set defaults
	if req.MaxDepth <= 0 || req.MaxDepth > 5 {
		req.MaxDepth = 2
	}
	if req.Limit <= 0 || req.Limit > 200 {
		req.Limit = 50
	}
	if req.Direction == "" {
		req.Direction = "both"
	}

	result, err := h.graphService.TraverseGraph(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Str("start_node", req.StartNodeID).Msg("failed to traverse graph")
		h.respondError(w, http.StatusInternalServerError, "failed to traverse graph")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// GetStats returns graph statistics
// @Summary Get graph statistics
// @Description Get statistics about the threat graph (node counts, relationships, etc.)
// @Tags graph
// @Accept json
// @Produce json
// @Success 200 {object} models.GraphStats
// @Router /api/v1/graph/stats [get]
func (h *GraphHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.graphService.GetStats(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get graph stats")
		h.respondError(w, http.StatusInternalServerError, "failed to get graph stats")
		return
	}

	h.respondJSON(w, http.StatusOK, stats)
}

// SyncFromPostgres triggers a sync from PostgreSQL to Neo4j
// @Summary Sync data to graph
// @Description Sync indicators, campaigns, and actors from PostgreSQL to Neo4j
// @Tags graph
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/v1/graph/sync [post]
func (h *GraphHandler) SyncFromPostgres(w http.ResponseWriter, r *http.Request) {
	if err := h.graphService.SyncFromPostgres(r.Context()); err != nil {
		h.logger.Error().Err(err).Msg("failed to sync to graph")
		h.respondError(w, http.StatusInternalServerError, "failed to sync to graph")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "sync completed",
	})
}

// GetTemporalCorrelation finds indicators that appeared around the same time
// @Summary Get temporal correlation
// @Description Find indicators correlated by time proximity
// @Tags graph
// @Accept json
// @Produce json
// @Param id path string true "Indicator UUID"
// @Param window query string false "Time window (e.g., 24h, 7d)" default(24h)
// @Success 200 {object} models.TemporalCorrelation
// @Router /api/v1/graph/temporal/{id} [get]
func (h *GraphHandler) GetTemporalCorrelation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	indicatorID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid indicator ID")
		return
	}

	window := 24 * time.Hour
	if w := r.URL.Query().Get("window"); w != "" {
		if parsed, err := time.ParseDuration(w); err == nil && parsed > 0 {
			window = parsed
		}
	}

	correlation, err := h.graphService.FindTemporalCorrelation(r.Context(), indicatorID, window)
	if err != nil {
		h.logger.Error().Err(err).Str("indicator_id", idStr).Msg("failed to find temporal correlation")
		h.respondError(w, http.StatusInternalServerError, "failed to find temporal correlation")
		return
	}

	h.respondJSON(w, http.StatusOK, correlation)
}

// GetTTPSimilarity calculates TTP similarity between threat actors
// @Summary Get TTP similarity
// @Description Calculate TTP (Tactics, Techniques, Procedures) similarity between two actors
// @Tags graph
// @Accept json
// @Produce json
// @Param actor1 query string true "First actor UUID"
// @Param actor2 query string true "Second actor UUID"
// @Success 200 {object} models.TTPSimilarity
// @Router /api/v1/graph/ttp-similarity [get]
func (h *GraphHandler) GetTTPSimilarity(w http.ResponseWriter, r *http.Request) {
	actor1Str := r.URL.Query().Get("actor1")
	actor2Str := r.URL.Query().Get("actor2")

	actor1ID, err := uuid.Parse(actor1Str)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid actor1 ID")
		return
	}

	actor2ID, err := uuid.Parse(actor2Str)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid actor2 ID")
		return
	}

	similarity, err := h.graphService.CalculateTTPSimilarity(r.Context(), actor1ID, actor2ID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to calculate TTP similarity")
		h.respondError(w, http.StatusInternalServerError, "failed to calculate TTP similarity")
		return
	}

	h.respondJSON(w, http.StatusOK, similarity)
}

// CreateRelationship creates a relationship between entities
// @Summary Create relationship
// @Description Create a relationship between two entities in the graph
// @Tags graph
// @Accept json
// @Produce json
// @Param body body CreateRelationshipRequest true "Relationship request"
// @Success 201 {object} map[string]string
// @Router /api/v1/graph/relationship [post]
func (h *GraphHandler) CreateRelationship(w http.ResponseWriter, r *http.Request) {
	var req CreateRelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sourceID, err := uuid.Parse(req.SourceID)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid source_id")
		return
	}

	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid target_id")
		return
	}

	if req.Confidence <= 0 || req.Confidence > 1.0 {
		req.Confidence = 0.5
	}

	if err := h.graphService.CreateRelationship(r.Context(), sourceID, targetID, models.GraphRelationType(req.RelationType), req.Confidence); err != nil {
		h.logger.Error().Err(err).Msg("failed to create relationship")
		h.respondError(w, http.StatusInternalServerError, "failed to create relationship")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]string{
		"status":  "success",
		"message": "relationship created",
	})
}

// CreateRelationshipRequest represents a request to create a graph relationship
type CreateRelationshipRequest struct {
	SourceID     string  `json:"source_id"`
	TargetID     string  `json:"target_id"`
	RelationType string  `json:"relation_type"`
	Confidence   float64 `json:"confidence"`
}

// SearchGraph performs a graph-wide search
// @Summary Search graph
// @Description Search across all node types in the threat graph
// @Tags graph
// @Accept json
// @Produce json
// @Param body body models.GraphSearchRequest true "Search request"
// @Success 200 {object} models.GraphQueryResult
// @Router /api/v1/graph/search [post]
func (h *GraphHandler) SearchGraph(w http.ResponseWriter, r *http.Request) {
	var req models.GraphSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Set defaults
	if req.Limit <= 0 || req.Limit > 200 {
		req.Limit = 50
	}
	if req.MaxDepth <= 0 || req.MaxDepth > 5 {
		req.MaxDepth = 2
	}

	// Convert to traversal request for now
	// A more sophisticated implementation would use Neo4j full-text search
	traversalReq := &models.GraphTraversalRequest{
		StartNodeID: req.Query, // Use query as starting point
		Direction:   "both",
		MaxDepth:    req.MaxDepth,
		Limit:       req.Limit,
	}

	result, err := h.graphService.TraverseGraph(r.Context(), traversalReq)
	if err != nil {
		h.logger.Error().Err(err).Str("query", req.Query).Msg("failed to search graph")
		h.respondError(w, http.StatusInternalServerError, "failed to search graph")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}
