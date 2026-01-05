package handlers

import (
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// Handlers holds all API handlers
type Handlers struct {
	Health       *HealthHandler
	Intelligence *IntelligenceHandler
	Stats        *StatsHandler
	Campaigns    *CampaignsHandler
	Actors       *ActorsHandler
	Sources      *SourcesHandler
	Admin        *AdminHandler
	TAXII        *TAXIIHandler
}

// Dependencies holds dependencies for handlers
type Dependencies struct {
	Aggregator   *services.Aggregator
	Normalizer   *services.Normalizer
	Deduplicator *services.Deduplicator
	Scorer       *services.Scorer
	Scheduler    *services.Scheduler
	Cache        *cache.RedisCache
	Logger       *logger.Logger
	Repos        *repository.Repositories
}

// NewHandlers creates all handlers
func NewHandlers(deps Dependencies) *Handlers {
	return &Handlers{
		Health:       NewHealthHandler(deps.Cache, deps.Repos, deps.Logger),
		Intelligence: NewIntelligenceHandler(deps.Repos, deps.Cache, deps.Logger),
		Stats:        NewStatsHandler(deps.Repos, deps.Cache, deps.Logger),
		Campaigns:    NewCampaignsHandler(deps.Repos, deps.Logger),
		Actors:       NewActorsHandler(deps.Repos, deps.Logger),
		Sources:      NewSourcesHandler(deps.Repos, deps.Aggregator, deps.Logger),
		Admin:        NewAdminHandler(deps.Aggregator, deps.Scheduler, deps.Logger),
		TAXII:        NewTAXIIHandler(deps.Repos, deps.Logger),
	}
}
