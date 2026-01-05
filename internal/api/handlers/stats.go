package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// StatsHandler handles statistics endpoints
type StatsHandler struct {
	repos  *repository.Repositories
	cache  *cache.RedisCache
	logger *logger.Logger
}

// NewStatsHandler creates a new StatsHandler
func NewStatsHandler(repos *repository.Repositories, c *cache.RedisCache, log *logger.Logger) *StatsHandler {
	return &StatsHandler{
		repos:  repos,
		cache:  c,
		logger: log.WithComponent("stats"),
	}
}

// Get handles GET /api/v1/stats
func (h *StatsHandler) Get(w http.ResponseWriter, r *http.Request) {
	// Try to get from cache first
	var stats models.Stats
	err := h.cache.GetJSON(r.Context(), cache.KeyStats, &stats)
	if err != nil {
		// Cache miss - compute stats
		stats = h.computeStats()

		// Cache for 5 minutes
		_ = h.cache.SetJSON(r.Context(), cache.KeyStats, stats, 5*time.Minute)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // 5 min cache
	json.NewEncoder(w).Encode(stats)
}

// computeStats computes statistics from database
func (h *StatsHandler) computeStats() models.Stats {
	ctx := context.Background()
	version, _ := h.cache.GetSyncVersion(ctx)

	stats := models.Stats{
		TotalIndicators: 0,
		IndicatorsByType: map[string]int{
			"domain":  0,
			"ip":      0,
			"hash":    0,
			"url":     0,
			"process": 0,
			"package": 0,
		},
		IndicatorsBySeverity: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
		IndicatorsByPlatform: map[string]int{
			"android": 0,
			"ios":     0,
			"windows": 0,
			"macos":   0,
			"linux":   0,
		},
		TotalSources:        0,
		ActiveSources:       0,
		TotalCampaigns:      0,
		ActiveCampaigns:     0,
		TotalReports:        0,
		PendingReports:      0,
		PegasusIndicators:   0,
		MobileIndicators:    0,
		CriticalIndicators:  0,
		LastUpdate:          time.Now(),
		TodayNewIOCs:        0,
		WeeklyNewIOCs:       0,
		MonthlyNewIOCs:      0,
		DataVersion:         version,
	}

	// Fetch real stats from database
	if h.repos != nil {
		ctx := context.Background()
		if dbStats, err := h.repos.Indicators.GetStats(ctx); err == nil {
			stats.TotalIndicators = int(dbStats.TotalCount)
			for k, v := range dbStats.ByType {
				stats.IndicatorsByType[k] = int(v)
			}
			for k, v := range dbStats.BySeverity {
				stats.IndicatorsBySeverity[k] = int(v)
			}
			stats.PegasusIndicators = int(dbStats.PegasusCount)
			stats.MobileIndicators = int(dbStats.MobileCount)
			stats.CriticalIndicators = int(dbStats.CriticalCount)
			stats.TodayNewIOCs = int(dbStats.TodayNew)
			stats.WeeklyNewIOCs = int(dbStats.WeeklyNew)
			stats.MonthlyNewIOCs = int(dbStats.MonthlyNew)
		} else {
			h.logger.Warn().Err(err).Msg("failed to fetch indicator stats")
		}

		// Fetch source stats
		if sources, err := h.repos.Sources.ListActive(ctx); err == nil {
			stats.ActiveSources = len(sources)
		}
		if allSources, err := h.repos.Sources.List(ctx); err == nil {
			stats.TotalSources = len(allSources)
		}

		// Fetch campaign stats
		if campaigns, _, err := h.repos.Campaigns.List(ctx, true, 1000, 0); err == nil {
			stats.ActiveCampaigns = len(campaigns)
		}
		if _, total, err := h.repos.Campaigns.List(ctx, false, 1, 0); err == nil {
			stats.TotalCampaigns = int(total)
		}
	}

	return stats
}
