package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// AdminHandler handles admin endpoints
type AdminHandler struct {
	aggregator *services.Aggregator
	scheduler  *services.Scheduler
	logger     *logger.Logger
}

// NewAdminHandler creates a new AdminHandler
func NewAdminHandler(agg *services.Aggregator, sched *services.Scheduler, log *logger.Logger) *AdminHandler {
	return &AdminHandler{
		aggregator: agg,
		scheduler:  sched,
		logger:     log.WithComponent("admin"),
	}
}

// TriggerUpdate handles POST /api/v1/admin/update
func (h *AdminHandler) TriggerUpdate(w http.ResponseWriter, r *http.Request) {
	h.logger.Info().Msg("triggering full update")

	if h.aggregator != nil {
		go func() {
			if err := h.aggregator.RunOnce(r.Context()); err != nil {
				h.logger.Error().Err(err).Msg("update failed")
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Update triggered",
	})
}

// TriggerSourceUpdate handles POST /api/v1/admin/update/{source}
func (h *AdminHandler) TriggerSourceUpdate(w http.ResponseWriter, r *http.Request) {
	source := chi.URLParam(r, "source")
	h.logger.Info().Str("source", source).Msg("triggering source update")

	if h.aggregator != nil {
		go func() {
			if err := h.aggregator.RunSource(r.Context(), source); err != nil {
				h.logger.Error().Err(err).Str("source", source).Msg("source update failed")
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Source update triggered",
		"source":  source,
	})
}

// ListReports handles GET /api/v1/admin/reports
func (h *AdminHandler) ListReports(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")

	// TODO: Fetch from database
	_ = status

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data":    []any{},
		"total":   0,
		"pending": 0,
	})
}

// GetReport handles GET /api/v1/admin/reports/{id}
func (h *AdminHandler) GetReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// TODO: Fetch from database
	_ = id

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "report not found"})
}

// ApproveReport handles POST /api/v1/admin/reports/{id}/approve
func (h *AdminHandler) ApproveReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.logger.Info().Str("report_id", id).Msg("approving report")

	// TODO: Update in database

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Report approved",
	})
}

// RejectReport handles POST /api/v1/admin/reports/{id}/reject
func (h *AdminHandler) RejectReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.logger.Info().Str("report_id", id).Msg("rejecting report")

	// TODO: Update in database

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Report rejected",
	})
}

// DetailedStats handles GET /api/v1/admin/stats/detailed
func (h *AdminHandler) DetailedStats(w http.ResponseWriter, r *http.Request) {
	stats := make(map[string]any)

	if h.aggregator != nil {
		stats["aggregator"] = h.aggregator.Stats()
	}

	if h.scheduler != nil {
		stats["scheduler"] = h.scheduler.Stats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
