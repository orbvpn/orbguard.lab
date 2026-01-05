package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// CampaignsHandler handles campaign endpoints
type CampaignsHandler struct {
	repos  *repository.Repositories
	logger *logger.Logger
}

// NewCampaignsHandler creates a new CampaignsHandler
func NewCampaignsHandler(repos *repository.Repositories, log *logger.Logger) *CampaignsHandler {
	return &CampaignsHandler{
		repos:  repos,
		logger: log.WithComponent("campaigns"),
	}
}

// List handles GET /api/v1/campaigns
func (h *CampaignsHandler) List(w http.ResponseWriter, r *http.Request) {
	var campaigns []*models.Campaign
	var total int64
	var err error

	if h.repos != nil {
		campaigns, total, err = h.repos.Campaigns.List(r.Context(), false, 100, 0)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to list campaigns")
			// Fall back to defaults
			defaults := models.DefaultCampaigns()
			for i := range defaults {
				campaigns = append(campaigns, &defaults[i])
			}
			total = int64(len(defaults))
		}
	} else {
		defaults := models.DefaultCampaigns()
		for i := range defaults {
			campaigns = append(campaigns, &defaults[i])
		}
		total = int64(len(defaults))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data":  campaigns,
		"total": total,
	})
}

// Get handles GET /api/v1/campaigns/{slug}
func (h *CampaignsHandler) Get(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")

	if h.repos != nil {
		campaign, err := h.repos.Campaigns.GetBySlug(r.Context(), slug)
		if err == nil && campaign != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(campaign)
			return
		}
	}

	// Fall back to defaults
	for _, c := range models.DefaultCampaigns() {
		if c.Slug == slug {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(c)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "campaign not found"})
}

// ListIndicators handles GET /api/v1/campaigns/{slug}/indicators
func (h *CampaignsHandler) ListIndicators(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")

	var indicators []*models.Indicator
	var total int64

	if h.repos != nil {
		// First get campaign by slug to get its ID
		campaign, err := h.repos.Campaigns.GetBySlug(r.Context(), slug)
		if err == nil && campaign != nil {
			indicators, total, err = h.repos.Indicators.ListByCampaign(r.Context(), campaign.ID, 100, 0)
			if err != nil {
				h.logger.Error().Err(err).Str("slug", slug).Msg("failed to list campaign indicators")
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data":     indicators,
		"total":    total,
		"limit":    100,
		"offset":   0,
		"has_more": len(indicators) < int(total),
	})
}
