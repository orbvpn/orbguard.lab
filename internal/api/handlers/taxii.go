package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// TAXIIHandler handles TAXII 2.1 endpoints
type TAXIIHandler struct {
	repos  *repository.Repositories
	logger *logger.Logger
}

// NewTAXIIHandler creates a new TAXIIHandler
func NewTAXIIHandler(repos *repository.Repositories, log *logger.Logger) *TAXIIHandler {
	return &TAXIIHandler{
		repos:  repos,
		logger: log.WithComponent("taxii"),
	}
}

// TAXIIDiscovery represents the TAXII discovery response
type TAXIIDiscovery struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Contact     string `json:"contact,omitempty"`
	Default     string `json:"default,omitempty"`
	APIRoots    []string `json:"api_roots,omitempty"`
}

// TAXIICollection represents a TAXII collection
type TAXIICollection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	MediaTypes  []string `json:"media_types,omitempty"`
}

// Discovery handles GET /taxii2/
func (h *TAXIIHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	discovery := TAXIIDiscovery{
		Title:       "OrbGuard Threat Intelligence",
		Description: "Threat intelligence feed for OrbGuard mobile security",
		Contact:     "security@orbai.world",
		Default:     "/taxii2/",
		APIRoots:    []string{"/taxii2/"},
	}

	w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
	json.NewEncoder(w).Encode(discovery)
}

// ListCollections handles GET /taxii2/collections/
func (h *TAXIIHandler) ListCollections(w http.ResponseWriter, r *http.Request) {
	collections := []TAXIICollection{
		{
			ID:          "pegasus",
			Title:       "Pegasus Indicators",
			Description: "NSO Group Pegasus spyware indicators",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
		{
			ID:          "mobile-threats",
			Title:       "Mobile Threats",
			Description: "Mobile-specific threat indicators (Android/iOS)",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
		{
			ID:          "all-threats",
			Title:       "All Threats",
			Description: "Complete threat intelligence feed",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
	}

	w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
	json.NewEncoder(w).Encode(map[string]any{
		"collections": collections,
	})
}

// GetCollection handles GET /taxii2/collections/{id}
func (h *TAXIIHandler) GetCollection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	collections := map[string]TAXIICollection{
		"pegasus": {
			ID:          "pegasus",
			Title:       "Pegasus Indicators",
			Description: "NSO Group Pegasus spyware indicators",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
		"mobile-threats": {
			ID:          "mobile-threats",
			Title:       "Mobile Threats",
			Description: "Mobile-specific threat indicators",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
		"all-threats": {
			ID:          "all-threats",
			Title:       "All Threats",
			Description: "Complete threat intelligence feed",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
	}

	if collection, ok := collections[id]; ok {
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(collection)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "collection not found"})
}

// GetObjects handles GET /taxii2/collections/{id}/objects
func (h *TAXIIHandler) GetObjects(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// TODO: Convert indicators to STIX and return
	_ = id

	// Return empty STIX bundle for now
	bundle := map[string]any{
		"type":        "bundle",
		"id":          "bundle--placeholder",
		"spec_version": "2.1",
		"objects":     []any{},
	}

	w.Header().Set("Content-Type", "application/stix+json;version=2.1")
	json.NewEncoder(w).Encode(bundle)
}

// AddObjects handles POST /taxii2/collections/{id}/objects
func (h *TAXIIHandler) AddObjects(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// TAXII write is not supported in this implementation
	_ = id

	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "write access not permitted",
	})
}
