package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/database/db"
)

// AggregatorRepositoryAdapter adapts IndicatorRepository to the interface
// expected by the Aggregator service
type AggregatorRepositoryAdapter struct {
	indicators *IndicatorRepository
	sources    *SourceRepository
	pool       *pgxpool.Pool
	queries    *db.Queries
}

// NewAggregatorRepositoryAdapter creates a new adapter
func NewAggregatorRepositoryAdapter(
	pool *pgxpool.Pool,
	indicators *IndicatorRepository,
	sources *SourceRepository,
) *AggregatorRepositoryAdapter {
	return &AggregatorRepositoryAdapter{
		indicators: indicators,
		sources:    sources,
		pool:       pool,
		queries:    db.New(pool),
	}
}

// UpsertIndicator creates or updates an indicator
func (a *AggregatorRepositoryAdapter) UpsertIndicator(ctx context.Context, indicator *models.Indicator) (*models.Indicator, error) {
	return a.indicators.Upsert(ctx, indicator)
}

// AddIndicatorSource links an indicator to a source
func (a *AggregatorRepositoryAdapter) AddIndicatorSource(ctx context.Context, indicatorID, sourceID uuid.UUID, confidence float64, rawData string) error {
	return a.indicators.AddIndicatorSource(ctx, indicatorID, sourceID, confidence, rawData)
}

// GetIndicatorByHash retrieves an indicator by its hash
func (a *AggregatorRepositoryAdapter) GetIndicatorByHash(ctx context.Context, hash string) (*models.Indicator, error) {
	return a.indicators.GetByHash(ctx, hash)
}

// UpdateSourceAfterFetch updates source metadata after a fetch
func (a *AggregatorRepositoryAdapter) UpdateSourceAfterFetch(ctx context.Context, sourceID uuid.UUID) error {
	return a.queries.UpdateSourceAfterFetch(ctx, sourceID)
}

// RecordFetchHistory records the result of a fetch operation
func (a *AggregatorRepositoryAdapter) RecordFetchHistory(ctx context.Context, result *models.SourceFetchResult) error {
	_, err := a.queries.CreateUpdateHistory(ctx, &db.CreateUpdateHistoryParams{
		SourceID:          result.SourceID,
		SourceSlug:        result.SourceSlug,
		StartedAt:         timeToTimestamptz(result.StartedAt()),
		CompletedAt:       timeToTimestamptz(result.CompletedAt()),
		Duration:          durationToInterval(result.Duration),
		Success:           result.Success,
		Error:             textOrNull(result.ErrorString()),
		TotalFetched:      int32(result.TotalFetched),
		NewIndicators:     int32(result.NewIndicators),
		UpdatedIndicators: int32(result.UpdatedIndicators),
		SkippedIndicators: int32(result.SkippedIndicators),
		Metadata:          nil, // Can be extended later
	})
	return err
}

// GetDueSources returns sources that are due for fetching
func (a *AggregatorRepositoryAdapter) GetDueSources(ctx context.Context) ([]*models.Source, error) {
	return a.sources.ListDue(ctx)
}

// GetSourceBySlug returns a source by its slug
func (a *AggregatorRepositoryAdapter) GetSourceBySlug(ctx context.Context, slug string) (*models.Source, error) {
	return a.sources.GetBySlug(ctx, slug)
}

// UpdateSourceAfterSuccess updates source after successful fetch
func (a *AggregatorRepositoryAdapter) UpdateSourceAfterSuccess(ctx context.Context, sourceID uuid.UUID) error {
	return a.sources.UpdateAfterFetch(ctx, sourceID, 0) // indicatorCount will be updated separately
}

// UpdateSourceAfterError updates source after failed fetch
func (a *AggregatorRepositoryAdapter) UpdateSourceAfterError(ctx context.Context, sourceID uuid.UUID, errMsg string) error {
	return a.sources.UpdateAfterError(ctx, sourceID, errMsg)
}

// UpdateHistoryRepository handles update history operations
type UpdateHistoryRepository struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewUpdateHistoryRepository creates a new update history repository
func NewUpdateHistoryRepository(pool *pgxpool.Pool) *UpdateHistoryRepository {
	return &UpdateHistoryRepository{
		pool:    pool,
		queries: db.New(pool),
	}
}

// Create records a new update history entry
func (r *UpdateHistoryRepository) Create(ctx context.Context, result *models.SourceFetchResult) error {
	_, err := r.queries.CreateUpdateHistory(ctx, &db.CreateUpdateHistoryParams{
		SourceID:          result.SourceID,
		SourceSlug:        result.SourceSlug,
		StartedAt:         timeToTimestamptz(result.StartedAt()),
		CompletedAt:       timeToTimestamptz(result.CompletedAt()),
		Duration:          durationToInterval(result.Duration),
		Success:           result.Success,
		Error:             textOrNull(result.ErrorString()),
		TotalFetched:      int32(result.TotalFetched),
		NewIndicators:     int32(result.NewIndicators),
		UpdatedIndicators: int32(result.UpdatedIndicators),
		SkippedIndicators: int32(result.SkippedIndicators),
		Metadata:          nil,
	})
	return err
}

// ListBySource returns update history for a specific source
func (r *UpdateHistoryRepository) ListBySource(ctx context.Context, sourceID uuid.UUID, limit, offset int) ([]*models.SourceFetchResult, error) {
	results, err := r.queries.ListUpdateHistoryBySource(ctx, &db.ListUpdateHistoryBySourceParams{
		SourceID: sourceID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		return nil, err
	}

	history := make([]*models.SourceFetchResult, len(results))
	for i, r := range results {
		var err error
		if errStr := nullTextToString(r.Error); errStr != "" {
			err = fmt.Errorf("%s", errStr)
		}
		history[i] = &models.SourceFetchResult{
			SourceID:          r.SourceID,
			SourceSlug:        r.SourceSlug,
			FetchedAt:         timestamptzToTime(r.StartedAt),
			Duration:          intervalToDuration(r.Duration),
			Success:           r.Success,
			Error:             err,
			TotalFetched:      int(r.TotalFetched),
			NewIndicators:     int(r.NewIndicators),
			UpdatedIndicators: int(r.UpdatedIndicators),
			SkippedIndicators: int(r.SkippedIndicators),
		}
	}

	return history, nil
}

// GetLatestBySource returns the most recent update for a source
func (r *UpdateHistoryRepository) GetLatestBySource(ctx context.Context, sourceID uuid.UUID) (*models.SourceFetchResult, error) {
	result, err := r.queries.GetLatestUpdateBySource(ctx, sourceID)
	if err != nil {
		return nil, err
	}

	var fetchErr error
	if errStr := nullTextToString(result.Error); errStr != "" {
		fetchErr = fmt.Errorf("%s", errStr)
	}

	return &models.SourceFetchResult{
		SourceID:          result.SourceID,
		SourceSlug:        result.SourceSlug,
		FetchedAt:         timestamptzToTime(result.StartedAt),
		Duration:          intervalToDuration(result.Duration),
		Success:           result.Success,
		Error:             fetchErr,
		TotalFetched:      int(result.TotalFetched),
		NewIndicators:     int(result.NewIndicators),
		UpdatedIndicators: int(result.UpdatedIndicators),
		SkippedIndicators: int(result.SkippedIndicators),
	}, nil
}

// CountFailed counts failed updates in the last 24 hours
func (r *UpdateHistoryRepository) CountFailed(ctx context.Context) (int64, error) {
	return r.queries.CountFailedUpdates(ctx)
}

// DeleteOld removes history entries older than 30 days
func (r *UpdateHistoryRepository) DeleteOld(ctx context.Context) (int64, error) {
	return r.queries.DeleteOldUpdateHistory(ctx)
}

// Repositories holds all repository instances
type Repositories struct {
	Indicators    *IndicatorRepository
	Sources       *SourceRepository
	Campaigns     *CampaignRepository
	Actors        *ThreatActorRepository
	UpdateHistory *UpdateHistoryRepository
	// Adapter for aggregator
	AggregatorAdapter *AggregatorRepositoryAdapter
}

// NewRepositories creates all repository instances from a database pool
func NewRepositories(pool *pgxpool.Pool) *Repositories {
	indicators := NewIndicatorRepository(pool)
	sources := NewSourceRepository(pool)
	campaigns := NewCampaignRepository(pool)
	actors := NewThreatActorRepository(pool)
	updateHistory := NewUpdateHistoryRepository(pool)
	adapter := NewAggregatorRepositoryAdapter(pool, indicators, sources)

	return &Repositories{
		Indicators:        indicators,
		Sources:           sources,
		Campaigns:         campaigns,
		Actors:            actors,
		UpdateHistory:     updateHistory,
		AggregatorAdapter: adapter,
	}
}
