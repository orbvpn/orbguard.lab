package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// ActorsHandler handles threat actor endpoints
type ActorsHandler struct {
	repos  *repository.Repositories
	logger *logger.Logger
}

// NewActorsHandler creates a new ActorsHandler
func NewActorsHandler(repos *repository.Repositories, log *logger.Logger) *ActorsHandler {
	return &ActorsHandler{
		repos:  repos,
		logger: log.WithComponent("actors"),
	}
}

// List handles GET /api/v1/actors
func (h *ActorsHandler) List(w http.ResponseWriter, r *http.Request) {
	var actors []*models.ThreatActor
	var total int64
	var err error

	if h.repos != nil {
		actors, total, err = h.repos.Actors.List(r.Context(), false, 100, 0)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to list actors")
			defaults := models.DefaultThreatActors()
			for i := range defaults {
				actors = append(actors, &defaults[i])
			}
			total = int64(len(defaults))
		}
	} else {
		defaults := models.DefaultThreatActors()
		for i := range defaults {
			actors = append(actors, &defaults[i])
		}
		total = int64(len(defaults))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data":  actors,
		"total": total,
	})
}

// Get handles GET /api/v1/actors/{id}
func (h *ActorsHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.repos != nil {
		// Try to parse as UUID
		if actorID, err := uuid.Parse(id); err == nil {
			actor, err := h.repos.Actors.GetByID(r.Context(), actorID)
			if err == nil && actor != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(actor)
				return
			}
		}
		// Try by name
		actor, err := h.repos.Actors.GetByName(r.Context(), id)
		if err == nil && actor != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(actor)
			return
		}
	}

	// Fall back to defaults
	for _, a := range models.DefaultThreatActors() {
		if a.ID.String() == id || a.Name == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(a)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "threat actor not found"})
}
