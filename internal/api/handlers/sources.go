package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// SourcesHandler handles source endpoints
type SourcesHandler struct {
	repos      *repository.Repositories
	aggregator *services.Aggregator
	logger     *logger.Logger
}

// NewSourcesHandler creates a new SourcesHandler
func NewSourcesHandler(repos *repository.Repositories, agg *services.Aggregator, log *logger.Logger) *SourcesHandler {
	return &SourcesHandler{
		repos:      repos,
		aggregator: agg,
		logger:     log.WithComponent("sources"),
	}
}

// List handles GET /api/v1/sources
func (h *SourcesHandler) List(w http.ResponseWriter, r *http.Request) {
	var sources []*models.Source
	var err error

	if h.repos != nil {
		sources, err = h.repos.Sources.List(r.Context())
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to list sources")
			defaults := models.DefaultSources()
			for i := range defaults {
				sources = append(sources, &defaults[i])
			}
		}
	} else {
		defaults := models.DefaultSources()
		for i := range defaults {
			sources = append(sources, &defaults[i])
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data":  sources,
		"total": len(sources),
	})
}

// Get handles GET /api/v1/sources/{slug}
func (h *SourcesHandler) Get(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")

	if h.repos != nil {
		source, err := h.repos.Sources.GetBySlug(r.Context(), slug)
		if err == nil && source != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(source)
			return
		}
	}

	// Fall back to defaults
	for _, s := range models.DefaultSources() {
		if s.Slug == slug {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "source not found"})
}
