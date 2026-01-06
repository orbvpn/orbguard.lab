package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/internal/infrastructure/graph"
	"orbguard-lab/pkg/logger"
)

// GraphService provides threat graph operations
type GraphService struct {
	graphRepo *graph.GraphRepository
	sqlRepos  *repository.Repositories
	cache     *cache.RedisCache
	logger    *logger.Logger
}

// NewGraphService creates a new graph service
func NewGraphService(
	graphRepo *graph.GraphRepository,
	sqlRepos *repository.Repositories,
	cache *cache.RedisCache,
	log *logger.Logger,
) *GraphService {
	return &GraphService{
		graphRepo: graphRepo,
		sqlRepos:  sqlRepos,
		cache:     cache,
		logger:    log.WithComponent("graph-service"),
	}
}

// SyncFromPostgres syncs data from PostgreSQL to Neo4j
func (s *GraphService) SyncFromPostgres(ctx context.Context) error {
	s.logger.Info().Msg("starting PostgreSQL to Neo4j sync")
	start := time.Now()

	// Sync campaigns
	campaignCount, err := s.syncCampaigns(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to sync campaigns")
	}

	// Sync threat actors
	actorCount, err := s.syncActors(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to sync threat actors")
	}

	// Sync indicators (paginated)
	indicatorCount, err := s.syncIndicators(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to sync indicators")
	}

	s.logger.Info().
		Int("campaigns", campaignCount).
		Int("actors", actorCount).
		Int("indicators", indicatorCount).
		Dur("duration", time.Since(start)).
		Msg("PostgreSQL to Neo4j sync complete")

	return nil
}

func (s *GraphService) syncCampaigns(ctx context.Context) (int, error) {
	if s.sqlRepos == nil || s.sqlRepos.Campaigns == nil {
		return 0, nil
	}

	campaigns, _, err := s.sqlRepos.Campaigns.List(ctx, false, 1000, 0)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, c := range campaigns {
		node := &models.CampaignNode{
			ID:          c.ID,
			Slug:        c.Slug,
			Name:        c.Name,
			Description: c.Description,
			FirstSeen:   c.FirstSeen,
			LastSeen:    c.LastSeen,
			IsActive:    c.IsActive,
		}

		if err := s.graphRepo.CreateCampaign(ctx, node); err != nil {
			s.logger.Warn().Err(err).Str("campaign", c.Name).Msg("failed to sync campaign")
			continue
		}
		count++
	}

	return count, nil
}

func (s *GraphService) syncActors(ctx context.Context) (int, error) {
	if s.sqlRepos == nil || s.sqlRepos.Actors == nil {
		return 0, nil
	}

	actors, _, err := s.sqlRepos.Actors.List(ctx, false, 1000, 0)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, a := range actors {
		node := &models.ThreatActorNode{
			ID:          a.ID,
			Name:        a.Name,
			Aliases:     a.Aliases,
			Description: a.Description,
			Motivation:  string(a.Motivation),
			Country:     a.Country,
			FirstSeen:   a.CreatedAt,
			LastSeen:    a.UpdatedAt,
			IsActive:    a.Active,
		}

		if err := s.graphRepo.CreateThreatActor(ctx, node); err != nil {
			s.logger.Warn().Err(err).Str("actor", a.Name).Msg("failed to sync actor")
			continue
		}
		count++
	}

	return count, nil
}

func (s *GraphService) syncIndicators(ctx context.Context) (int, error) {
	if s.sqlRepos == nil || s.sqlRepos.Indicators == nil {
		return 0, nil
	}

	// Use smaller batch size for DB fetch and even smaller for Neo4j writes
	fetchBatchSize := 1000
	neo4jBatchSize := 100 // Smaller batches for Neo4j to avoid timeouts
	offset := 0
	totalCount := 0
	failedBatches := 0
	maxFailedBatches := 5 // Stop if too many consecutive failures

	for {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			s.logger.Warn().Int("synced", totalCount).Msg("sync cancelled")
			return totalCount, ctx.Err()
		default:
		}

		filter := repository.IndicatorFilter{
			Limit:  fetchBatchSize,
			Offset: offset,
		}
		indicators, _, err := s.sqlRepos.Indicators.List(ctx, filter)
		if err != nil {
			return totalCount, err
		}

		if len(indicators) == 0 {
			break
		}

		// Convert to nodes
		nodes := make([]*models.IndicatorNode, 0, len(indicators))
		campaignLinks := make([]struct {
			indicatorID uuid.UUID
			campaignID  uuid.UUID
			confidence  float64
		}, 0)

		for _, ind := range indicators {
			sourceName := ""
			if len(ind.Sources) > 0 {
				sourceName = ind.Sources[0].SourceName
			}

			nodes = append(nodes, &models.IndicatorNode{
				ID:         ind.ID,
				Type:       ind.Type,
				Value:      ind.Value,
				Severity:   ind.Severity,
				Confidence: ind.Confidence,
				FirstSeen:  ind.FirstSeen,
				LastSeen:   ind.LastSeen,
				Tags:       ind.Tags,
				Source:     sourceName,
			})

			if ind.CampaignID != nil && *ind.CampaignID != uuid.Nil {
				campaignLinks = append(campaignLinks, struct {
					indicatorID uuid.UUID
					campaignID  uuid.UUID
					confidence  float64
				}{ind.ID, *ind.CampaignID, ind.Confidence})
			}
		}

		// Batch create indicators in smaller chunks
		for i := 0; i < len(nodes); i += neo4jBatchSize {
			end := i + neo4jBatchSize
			if end > len(nodes) {
				end = len(nodes)
			}

			batch := nodes[i:end]

			// Create a timeout context for this batch
			batchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			count, err := s.graphRepo.CreateIndicatorsBatch(batchCtx, batch)
			cancel()

			if err != nil {
				failedBatches++
				s.logger.Warn().
					Err(err).
					Int("batch_start", offset+i).
					Int("batch_size", len(batch)).
					Int("failed_batches", failedBatches).
					Msg("failed to sync indicator batch")

				if failedBatches >= maxFailedBatches {
					s.logger.Error().
						Int("synced", totalCount).
						Int("failed_batches", failedBatches).
						Msg("too many failed batches, stopping sync")
					return totalCount, fmt.Errorf("too many failed batches: %d", failedBatches)
				}
				continue
			}

			failedBatches = 0 // Reset on success
			totalCount += count
		}

		// Create campaign relationships (these are typically few)
		for _, link := range campaignLinks {
			linkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := s.graphRepo.LinkIndicatorToCampaign(linkCtx, link.indicatorID, link.campaignID, link.confidence); err != nil {
				s.logger.Warn().Err(err).Msg("failed to link indicator to campaign")
			}
			cancel()
		}

		s.logger.Info().
			Int("offset", offset).
			Int("batch_count", len(indicators)).
			Int("total_synced", totalCount).
			Msg("sync progress")

		offset += fetchBatchSize

		if len(indicators) < fetchBatchSize {
			break
		}
	}

	return totalCount, nil
}

// GetCorrelation returns correlation data for an indicator
func (s *GraphService) GetCorrelation(ctx context.Context, indicatorID uuid.UUID) (*models.CorrelationResult, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("graph:correlation:%s", indicatorID.String())
	if s.cache != nil {
		if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
			var result models.CorrelationResult
			if err := json.Unmarshal([]byte(cached), &result); err == nil {
				return &result, nil
			}
		}
	}

	// Get from graph
	correlation, err := s.graphRepo.GetCorrelation(ctx, indicatorID)
	if err != nil {
		return nil, err
	}

	// Cache for 5 minutes
	if s.cache != nil {
		if data, err := json.Marshal(correlation); err == nil {
			s.cache.Set(ctx, cacheKey, string(data), 5*time.Minute)
		}
	}

	return correlation, nil
}

// FindRelated finds indicators related to a given indicator
func (s *GraphService) FindRelated(ctx context.Context, indicatorID uuid.UUID, maxDepth, limit int) ([]models.RelatedIndicator, error) {
	return s.graphRepo.FindRelatedIndicators(ctx, indicatorID, maxDepth, limit)
}

// FindSharedInfrastructure finds indicators sharing infrastructure
func (s *GraphService) FindSharedInfrastructure(ctx context.Context, limit int) (*models.InfrastructureOverlapResult, error) {
	return s.graphRepo.FindSharedInfrastructure(ctx, limit)
}

// DetectCampaigns attempts to auto-detect new campaigns
func (s *GraphService) DetectCampaigns(ctx context.Context, minSharedInfra, limit int) ([]models.CampaignDetection, error) {
	return s.graphRepo.DetectCampaigns(ctx, minSharedInfra, limit)
}

// TraverseGraph performs a graph traversal
func (s *GraphService) TraverseGraph(ctx context.Context, req *models.GraphTraversalRequest) (*models.GraphQueryResult, error) {
	return s.graphRepo.Traverse(ctx, req)
}

// GetStats returns graph statistics
func (s *GraphService) GetStats(ctx context.Context) (*models.GraphStats, error) {
	// Check cache first
	cacheKey := "graph:stats"
	if s.cache != nil {
		if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
			var result models.GraphStats
			if err := json.Unmarshal([]byte(cached), &result); err == nil {
				return &result, nil
			}
		}
	}

	stats, err := s.graphRepo.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	// Cache for 1 minute
	if s.cache != nil {
		if data, err := json.Marshal(stats); err == nil {
			s.cache.Set(ctx, cacheKey, string(data), time.Minute)
		}
	}

	return stats, nil
}

// CalculateTTPSimilarity calculates TTP similarity between threat actors
func (s *GraphService) CalculateTTPSimilarity(ctx context.Context, actor1ID, actor2ID uuid.UUID) (*models.TTPSimilarity, error) {
	// This would query the graph for shared MITRE techniques between actors
	// For now, return a placeholder
	return &models.TTPSimilarity{
		Actor1:           actor1ID.String(),
		Actor2:           actor2ID.String(),
		SharedTactics:    []string{},
		SharedTechniques: []string{},
		Similarity:       0.0,
	}, nil
}

// FindTemporalCorrelation finds indicators that appeared around the same time
func (s *GraphService) FindTemporalCorrelation(ctx context.Context, indicatorID uuid.UUID, window time.Duration) (*models.TemporalCorrelation, error) {
	// Get the base indicator
	correlation, err := s.graphRepo.GetCorrelation(ctx, indicatorID)
	if err != nil {
		return nil, err
	}

	if correlation.PrimaryIndicator == nil {
		return nil, fmt.Errorf("indicator not found")
	}

	// Find indicators within the time window
	temporal := &models.TemporalCorrelation{
		TimeWindow: window,
		Indicators: []models.IndicatorNode{*correlation.PrimaryIndicator},
		FirstSeen:  correlation.PrimaryIndicator.FirstSeen,
		LastSeen:   correlation.PrimaryIndicator.LastSeen,
	}

	// Add related indicators that fall within the time window
	for _, related := range correlation.RelatedIndicators {
		indicatorTime := related.Indicator.FirstSeen
		baseTime := correlation.PrimaryIndicator.FirstSeen

		if indicatorTime.After(baseTime.Add(-window)) && indicatorTime.Before(baseTime.Add(window)) {
			temporal.Indicators = append(temporal.Indicators, related.Indicator)

			if indicatorTime.Before(temporal.FirstSeen) {
				temporal.FirstSeen = indicatorTime
			}
			if indicatorTime.After(temporal.LastSeen) {
				temporal.LastSeen = indicatorTime
			}
		}
	}

	return temporal, nil
}

// EnrichIndicator enriches an indicator with graph data
func (s *GraphService) EnrichIndicator(ctx context.Context, indicator *models.Indicator) (*models.Indicator, error) {
	correlation, err := s.graphRepo.GetCorrelation(ctx, indicator.ID)
	if err != nil {
		return indicator, nil // Return original if graph enrichment fails
	}

	// Add campaign info
	if len(correlation.Campaigns) > 0 {
		for _, c := range correlation.Campaigns {
			indicator.Tags = append(indicator.Tags, fmt.Sprintf("campaign:%s", c.Slug))
		}
	}

	// Add actor info
	if len(correlation.ThreatActors) > 0 {
		for _, a := range correlation.ThreatActors {
			indicator.Tags = append(indicator.Tags, fmt.Sprintf("actor:%s", a.Name))
		}
	}

	// Note: RiskScore is part of CorrelationResult, not Indicator
	// Caller can use correlation.RiskScore if needed

	return indicator, nil
}

// CreateRelationship creates a relationship between entities
func (s *GraphService) CreateRelationship(ctx context.Context, sourceID, targetID uuid.UUID, relType models.GraphRelationType, confidence float64) error {
	return s.graphRepo.LinkIndicators(ctx, sourceID, targetID, relType, confidence)
}

// BuildRelationships creates relationships between indicators based on various criteria
func (s *GraphService) BuildRelationships(ctx context.Context) (*models.RelationshipBuildResult, error) {
	s.logger.Info().Msg("starting relationship building")
	start := time.Now()

	result := &models.RelationshipBuildResult{
		StartedAt: start,
	}

	// Create relationships by shared tags (most valuable)
	s.logger.Info().Msg("creating relationships by shared tags")
	tagCtx, tagCancel := context.WithTimeout(ctx, 5*time.Minute)
	tagCount, err := s.graphRepo.CreateRelationshipsBySharedTags(tagCtx, nil, 10)
	tagCancel()
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to create tag relationships")
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.TagRelationships = tagCount
		s.logger.Info().Int("count", tagCount).Msg("tag relationships created")
	}

	result.TotalCreated = result.TagRelationships
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now()

	s.logger.Info().
		Int("total", result.TotalCreated).
		Int("by_tags", result.TagRelationships).
		Dur("duration", result.Duration).
		Msg("relationship building complete")

	return result, nil
}

// BulkSync syncs a batch of indicators to the graph
func (s *GraphService) BulkSync(ctx context.Context, indicators []*models.Indicator) error {
	s.logger.Info().Int("count", len(indicators)).Msg("bulk syncing indicators to graph")

	for _, ind := range indicators {
		// Get source name from sources array
		sourceName := ""
		if len(ind.Sources) > 0 {
			sourceName = ind.Sources[0].SourceName
		}

		node := &models.IndicatorNode{
			ID:         ind.ID,
			Type:       ind.Type,
			Value:      ind.Value,
			Severity:   ind.Severity,
			Confidence: ind.Confidence,
			FirstSeen:  ind.FirstSeen,
			LastSeen:   ind.LastSeen,
			Tags:       ind.Tags,
			Source:     sourceName,
		}

		if err := s.graphRepo.CreateIndicator(ctx, node); err != nil {
			s.logger.Warn().Err(err).Str("indicator", ind.Value).Msg("failed to sync indicator")
			continue
		}

		// Create campaign relationship
		if ind.CampaignID != nil && *ind.CampaignID != uuid.Nil {
			if err := s.graphRepo.LinkIndicatorToCampaign(ctx, ind.ID, *ind.CampaignID, ind.Confidence); err != nil {
				s.logger.Warn().Err(err).Msg("failed to link indicator to campaign")
			}
		}
	}

	return nil
}
