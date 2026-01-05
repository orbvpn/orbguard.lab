package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// IntelligenceHandler handles intelligence endpoints
type IntelligenceHandler struct {
	repos  *repository.Repositories
	cache  *cache.RedisCache
	logger *logger.Logger
}

// NewIntelligenceHandler creates a new IntelligenceHandler
func NewIntelligenceHandler(repos *repository.Repositories, c *cache.RedisCache, log *logger.Logger) *IntelligenceHandler {
	return &IntelligenceHandler{
		repos:  repos,
		cache:  c,
		logger: log.WithComponent("intelligence"),
	}
}

// ListResponse represents a paginated list response
type ListResponse struct {
	Data       any    `json:"data"`
	Total      int    `json:"total"`
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// List handles GET /api/v1/intelligence
func (h *IntelligenceHandler) List(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	// Build filter from query params
	filter := repository.IndicatorFilter{
		Limit:  limit,
		Offset: offset,
	}

	// Parse optional filters
	if types := r.URL.Query()["type"]; len(types) > 0 {
		for _, t := range types {
			filter.Types = append(filter.Types, models.ParseIndicatorType(t))
		}
	}
	if severities := r.URL.Query()["severity"]; len(severities) > 0 {
		for _, s := range severities {
			filter.Severities = append(filter.Severities, models.ParseSeverity(s))
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Value = search
	}

	var data []*models.Indicator
	var total int64
	var err error

	if h.repos != nil {
		data, total, err = h.repos.Indicators.List(r.Context(), filter)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to list indicators")
			h.respondError(w, http.StatusInternalServerError, "failed to fetch indicators")
			return
		}
	}

	response := ListResponse{
		Data:    data,
		Total:   int(total),
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+len(data) < int(total),
	}

	h.respondJSON(w, http.StatusOK, response)
}

// ListPegasus handles GET /api/v1/intelligence/pegasus
func (h *IntelligenceHandler) ListPegasus(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	var data []*models.Indicator
	var total int64
	var err error

	if h.repos != nil {
		data, total, err = h.repos.Indicators.ListPegasus(r.Context(), limit, offset)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to list pegasus indicators")
			h.respondError(w, http.StatusInternalServerError, "failed to fetch pegasus indicators")
			return
		}
	}

	response := ListResponse{
		Data:    data,
		Total:   int(total),
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+len(data) < int(total),
	}

	h.respondJSON(w, http.StatusOK, response)
}

// ListMobile handles GET /api/v1/intelligence/mobile
func (h *IntelligenceHandler) ListMobile(w http.ResponseWriter, r *http.Request) {
	// platform := r.URL.Query().Get("platform") // TODO: Filter by platform
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	var data []*models.Indicator
	var total int64
	var err error

	if h.repos != nil {
		data, total, err = h.repos.Indicators.ListMobile(r.Context(), limit, offset)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to list mobile indicators")
			h.respondError(w, http.StatusInternalServerError, "failed to fetch mobile indicators")
			return
		}
	}

	response := ListResponse{
		Data:    data,
		Total:   int(total),
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+len(data) < int(total),
	}

	h.respondJSON(w, http.StatusOK, response)
}

// MobileSync handles GET /api/v1/intelligence/mobile/sync
// Optimized sync endpoint for mobile apps
func (h *IntelligenceHandler) MobileSync(w http.ResponseWriter, r *http.Request) {
	// Get last sync version from client
	lastVersion, _ := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	platform := r.URL.Query().Get("platform") // android or ios
	fullSync := r.URL.Query().Get("full") == "true"

	_ = platform // TODO: Use in query

	// Get current version
	currentVersion, _ := h.cache.GetSyncVersion(r.Context())

	response := models.MobileSyncResponse{
		Version:     currentVersion,
		LastUpdated: time.Now(),
		HasMore:     false,
	}

	if fullSync || lastVersion == 0 {
		// Full sync - return all indicators
		response.Indicators = []models.MobileIndicator{}
	} else if lastVersion < currentVersion {
		// Delta sync - return only changed indicators
		response.NewIndicators = []models.MobileIndicator{}
		response.UpdatedIndicators = []models.MobileIndicator{}
		response.RemovedIDs = []string{}
	}
	// If lastVersion == currentVersion, no changes

	h.respondJSON(w, http.StatusOK, response)
}

// ListCommunity handles GET /api/v1/intelligence/community
func (h *IntelligenceHandler) ListCommunity(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	response := ListResponse{
		Data:    []models.Indicator{},
		Total:   0,
		Limit:   limit,
		Offset:  offset,
		HasMore: false,
	}

	h.respondJSON(w, http.StatusOK, response)
}

// Check handles GET /api/v1/intelligence/check?value=...&type=...
func (h *IntelligenceHandler) Check(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	iocType := r.URL.Query().Get("type")

	if value == "" || iocType == "" {
		h.respondError(w, http.StatusBadRequest, "missing value or type parameter")
		return
	}

	result := models.CheckResult{
		Value:       value,
		Type:        models.IndicatorType(iocType),
		IsMalicious: false,
	}

	if h.repos != nil {
		// Compute hash for lookup
		hash := sha256.Sum256([]byte(value))
		hashStr := hex.EncodeToString(hash[:])

		indicator, err := h.repos.Indicators.GetByHash(r.Context(), hashStr)
		if err == nil && indicator != nil {
			result.IsMalicious = true
			result.Indicator = indicator
		}
	}

	h.respondJSON(w, http.StatusOK, result)
}

// CheckBatch handles POST /api/v1/intelligence/check/batch
func (h *IntelligenceHandler) CheckBatch(w http.ResponseWriter, r *http.Request) {
	var req models.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Indicators) == 0 {
		h.respondError(w, http.StatusBadRequest, "no indicators provided")
		return
	}

	if len(req.Indicators) > 100 {
		h.respondError(w, http.StatusBadRequest, "maximum 100 indicators per request")
		return
	}

	// Compute hashes for all values
	hashes := make([]string, len(req.Indicators))
	hashToIndex := make(map[string]int)
	for i, ind := range req.Indicators {
		hash := sha256.Sum256([]byte(ind.Value))
		hashStr := hex.EncodeToString(hash[:])
		hashes[i] = hashStr
		hashToIndex[hashStr] = i
	}

	// Initialize results
	results := make([]models.CheckResult, len(req.Indicators))
	for i, ind := range req.Indicators {
		results[i] = models.CheckResult{
			Value:       ind.Value,
			Type:        ind.Type,
			IsMalicious: false,
		}
	}

	// Batch check in database
	if h.repos != nil {
		matches, err := h.repos.Indicators.CheckBatch(r.Context(), hashes)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to batch check indicators")
		} else {
			for _, indicator := range matches {
				if idx, ok := hashToIndex[indicator.ValueHash]; ok {
					results[idx].IsMalicious = true
					results[idx].Indicator = indicator
				}
			}
		}
	}

	h.respondJSON(w, http.StatusOK, models.CheckResponse{Results: results})
}

// Report handles POST /api/v1/intelligence/report
func (h *IntelligenceHandler) Report(w http.ResponseWriter, r *http.Request) {
	var req models.CreateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate request
	if req.IndicatorValue == "" {
		h.respondError(w, http.StatusBadRequest, "indicator_value is required")
		return
	}
	if req.IndicatorType == "" {
		h.respondError(w, http.StatusBadRequest, "indicator_type is required")
		return
	}
	if req.Description == "" {
		h.respondError(w, http.StatusBadRequest, "description is required")
		return
	}
	if len(req.Description) < 10 {
		h.respondError(w, http.StatusBadRequest, "description must be at least 10 characters")
		return
	}

	// TODO: Store report in database
	h.logger.Info().
		Str("value", req.IndicatorValue).
		Str("type", string(req.IndicatorType)).
		Msg("received threat report")

	h.respondJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"message": "Report received and queued for review",
	})
}

// respondJSON sends a JSON response
func (h *IntelligenceHandler) respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondError sends an error response
func (h *IntelligenceHandler) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
