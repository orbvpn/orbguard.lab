package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// TAXIIHandler handles TAXII 2.1 endpoints
type TAXIIHandler struct {
	service *services.STIXTAXIIService
	logger  *logger.Logger
}

// NewTAXIIHandler creates a new TAXIIHandler
func NewTAXIIHandler(service *services.STIXTAXIIService, log *logger.Logger) *TAXIIHandler {
	return &TAXIIHandler{
		service: service,
		logger:  log.WithComponent("taxii"),
	}
}

// Discovery handles GET /taxii2/
func (h *TAXIIHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	baseURL := "https://" + r.Host
	if r.TLS == nil {
		baseURL = "http://" + r.Host
	}

	discovery := h.service.GetDiscovery(baseURL)

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	json.NewEncoder(w).Encode(discovery)
}

// GetAPIRoot handles GET /taxii2/
func (h *TAXIIHandler) GetAPIRoot(w http.ResponseWriter, r *http.Request) {
	apiRoot := h.service.GetAPIRoot()

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	json.NewEncoder(w).Encode(apiRoot)
}

// ListCollections handles GET /taxii2/collections/
func (h *TAXIIHandler) ListCollections(w http.ResponseWriter, r *http.Request) {
	collections := h.service.GetCollections()

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	json.NewEncoder(w).Encode(collections)
}

// GetCollection handles GET /taxii2/collections/{id}
func (h *TAXIIHandler) GetCollection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	collection, err := h.service.GetCollection(id)
	if err != nil {
		h.respondTAXIIError(w, models.ErrTAXIINotFound)
		return
	}

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	json.NewEncoder(w).Encode(collection)
}

// GetObjects handles GET /taxii2/collections/{id}/objects
func (h *TAXIIHandler) GetObjects(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Parse filters from query parameters
	filters := h.parseFilters(r)

	envelope, err := h.service.GetObjects(r.Context(), id, filters)
	if err != nil {
		h.logger.Error().Err(err).Str("collection", id).Msg("failed to get objects")
		h.respondTAXIIError(w, models.ErrTAXIINotFound)
		return
	}

	w.Header().Set("Content-Type", models.STIXMediaType)
	json.NewEncoder(w).Encode(envelope)
}

// AddObjects handles POST /taxii2/collections/{id}/objects
func (h *TAXIIHandler) AddObjects(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Parse request body
	var envelope models.TAXIIEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		h.respondTAXIIError(w, models.ErrTAXIIBadRequest)
		return
	}

	// Check content length
	if r.ContentLength > 10*1024*1024 { // 10MB
		h.respondTAXIIError(w, models.ErrTAXIITooLarge)
		return
	}

	status, err := h.service.AddObjects(r.Context(), id, &envelope)
	if err != nil {
		h.logger.Error().Err(err).Str("collection", id).Msg("failed to add objects")
		if err.Error() == "collection is not writable" {
			h.respondTAXIIError(w, models.ErrTAXIIForbidden)
			return
		}
		h.respondTAXIIError(w, models.ErrTAXIINotFound)
		return
	}

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(status)
}

// GetManifest handles GET /taxii2/collections/{id}/manifest
func (h *TAXIIHandler) GetManifest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	filters := h.parseFilters(r)

	manifest, err := h.service.GetManifest(r.Context(), id, filters)
	if err != nil {
		h.logger.Error().Err(err).Str("collection", id).Msg("failed to get manifest")
		h.respondTAXIIError(w, models.ErrTAXIINotFound)
		return
	}

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	json.NewEncoder(w).Encode(manifest)
}

// GetStatus handles GET /taxii2/status/{status_id}
func (h *TAXIIHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	statusID := chi.URLParam(r, "status_id")

	status, err := h.service.GetStatus(statusID)
	if err != nil {
		h.respondTAXIIError(w, models.ErrTAXIINotFound)
		return
	}

	w.Header().Set("Content-Type", models.TAXIIMediaType)
	json.NewEncoder(w).Encode(status)
}

// GetStats handles GET /taxii2/stats (custom endpoint)
func (h *TAXIIHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.service.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// parseFilters parses TAXII filters from query parameters
func (h *TAXIIHandler) parseFilters(r *http.Request) *models.TAXIIObjectFilters {
	filters := &models.TAXIIObjectFilters{}

	// Parse added_after
	if addedAfter := r.URL.Query().Get("added_after"); addedAfter != "" {
		if t, err := time.Parse(time.RFC3339, addedAfter); err == nil {
			filters.AddedAfter = &t
		}
	}

	// Parse limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filters.Limit = limit
		}
	}

	// Parse next (pagination cursor)
	if next := r.URL.Query().Get("next"); next != "" {
		filters.Next = next
	}

	// Parse match filters
	matchTypes := r.URL.Query()["match[type]"]
	matchIDs := r.URL.Query()["match[id]"]
	matchVersions := r.URL.Query()["match[version]"]

	if len(matchTypes) > 0 || len(matchIDs) > 0 || len(matchVersions) > 0 {
		filters.Match = make(map[string][]string)
		if len(matchTypes) > 0 {
			filters.Match["type"] = matchTypes
		}
		if len(matchIDs) > 0 {
			filters.Match["id"] = matchIDs
		}
		if len(matchVersions) > 0 {
			filters.Match["version"] = matchVersions
		}
	}

	return filters
}

// respondTAXIIError sends a TAXII error response
func (h *TAXIIHandler) respondTAXIIError(w http.ResponseWriter, taxiiErr *models.TAXIIError) {
	w.Header().Set("Content-Type", models.TAXIIMediaType)
	w.WriteHeader(taxiiErr.HTTPStatus)
	json.NewEncoder(w).Encode(taxiiErr)
}
