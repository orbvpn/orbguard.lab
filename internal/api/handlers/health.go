package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	cache     *cache.RedisCache
	repos     *repository.Repositories
	logger    *logger.Logger
	startTime time.Time
}

// NewHealthHandler creates a new HealthHandler
func NewHealthHandler(c *cache.RedisCache, repos *repository.Repositories, log *logger.Logger) *HealthHandler {
	return &HealthHandler{
		cache:     c,
		repos:     repos,
		logger:    log.WithComponent("health"),
		startTime: time.Now(),
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// Check handles GET /health
func (h *HealthHandler) Check(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Uptime:    time.Since(h.startTime).String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Ready handles GET /ready - checks all dependencies
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	status := http.StatusOK
	overallStatus := "ready"

	// Check Redis
	if h.cache != nil {
		if err := h.cache.Client().Ping(r.Context()).Err(); err != nil {
			checks["redis"] = "unhealthy: " + err.Error()
			status = http.StatusServiceUnavailable
			overallStatus = "not ready"
		} else {
			checks["redis"] = "healthy"
		}
	}

	// Check PostgreSQL via repository
	if h.repos != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		// Try a simple query to verify connection
		if _, err := h.repos.Indicators.GetStats(ctx); err != nil {
			checks["postgres"] = "unhealthy: " + err.Error()
			status = http.StatusServiceUnavailable
			overallStatus = "not ready"
		} else {
			checks["postgres"] = "healthy"
		}
	} else {
		checks["postgres"] = "not configured"
	}

	checks["aggregator"] = "healthy"

	response := HealthResponse{
		Status:    overallStatus,
		Version:   "1.0.0",
		Uptime:    time.Since(h.startTime).String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}
