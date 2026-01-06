package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/config"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// SourceConnector defines the interface for threat intelligence sources
type SourceConnector interface {
	// Slug returns the unique identifier for this source
	Slug() string

	// Fetch retrieves indicators from the source
	Fetch(ctx context.Context) (*models.SourceFetchResult, error)

	// IsEnabled returns whether this source is enabled
	IsEnabled() bool

	// UpdateInterval returns how often this source should be updated
	UpdateInterval() time.Duration
}

// IndicatorRepository defines the interface for indicator storage
type IndicatorRepository interface {
	// UpsertIndicator creates or updates an indicator
	UpsertIndicator(ctx context.Context, indicator *models.Indicator) (*models.Indicator, error)

	// AddIndicatorSource links an indicator to a source
	AddIndicatorSource(ctx context.Context, indicatorID, sourceID uuid.UUID, confidence float64, rawData string) error

	// GetIndicatorByHash retrieves an indicator by its hash
	GetIndicatorByHash(ctx context.Context, hash string) (*models.Indicator, error)

	// UpdateSourceAfterFetch updates source metadata after a fetch
	UpdateSourceAfterFetch(ctx context.Context, sourceID uuid.UUID) error

	// RecordFetchHistory records the result of a fetch operation
	RecordFetchHistory(ctx context.Context, result *models.SourceFetchResult) error

	// GetDueSources returns sources that are due for fetching (incremental updates)
	GetDueSources(ctx context.Context) ([]*models.Source, error)

	// GetSourceBySlug returns a source by its slug
	GetSourceBySlug(ctx context.Context, slug string) (*models.Source, error)

	// UpdateSourceAfterSuccess updates source after successful fetch
	UpdateSourceAfterSuccess(ctx context.Context, sourceID uuid.UUID) error

	// UpdateSourceAfterError updates source after failed fetch
	UpdateSourceAfterError(ctx context.Context, sourceID uuid.UUID, errMsg string) error
}

// EventPublisher defines the interface for publishing threat events
type EventPublisher interface {
	// PublishNewThreat publishes an event for a new threat indicator
	PublishNewThreat(ctx context.Context, indicator *models.Indicator, sourceSlug, sourceName string) error

	// PublishSourceUpdate publishes a source update completion event
	PublishSourceUpdate(ctx context.Context, sourceSlug, sourceName string, success bool, newCount, updatedCount int, duration time.Duration, err error) error
}

// Aggregator orchestrates fetching from all sources
type Aggregator struct {
	config       config.AggregationConfig
	connectors   map[string]SourceConnector
	repository   IndicatorRepository
	normalizer   *Normalizer
	deduplicator *Deduplicator
	scorer       *Scorer
	cache        *cache.RedisCache
	publisher    EventPublisher
	logger       *logger.Logger

	mu           sync.RWMutex
	isRunning    bool
	lastRun      time.Time
	totalFetched int64
}

// NewAggregator creates a new Aggregator
func NewAggregator(
	cfg config.AggregationConfig,
	repo IndicatorRepository,
	normalizer *Normalizer,
	deduplicator *Deduplicator,
	scorer *Scorer,
	cache *cache.RedisCache,
	log *logger.Logger,
) *Aggregator {
	return &Aggregator{
		config:       cfg,
		connectors:   make(map[string]SourceConnector),
		repository:   repo,
		normalizer:   normalizer,
		deduplicator: deduplicator,
		scorer:       scorer,
		cache:        cache,
		logger:       log.WithComponent("aggregator"),
	}
}

// RegisterConnector registers a source connector
func (a *Aggregator) RegisterConnector(connector SourceConnector) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connectors[connector.Slug()] = connector
	a.logger.Info().Str("source", connector.Slug()).Msg("registered source connector")
}

// SetEventPublisher sets the event publisher for real-time updates
func (a *Aggregator) SetEventPublisher(publisher EventPublisher) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.publisher = publisher
	a.logger.Info().Msg("event publisher configured")
}

// GetConnector returns a connector by slug
func (a *Aggregator) GetConnector(slug string) (SourceConnector, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	conn, ok := a.connectors[slug]
	return conn, ok
}

// Run starts the aggregation loop
func (a *Aggregator) Run(ctx context.Context) error {
	if !a.config.Enabled {
		a.logger.Info().Msg("aggregation is disabled")
		return nil
	}

	a.logger.Info().
		Dur("initial_delay", a.config.InitialDelay).
		Int("worker_pool_size", a.config.WorkerPoolSize).
		Msg("starting aggregation loop")

	// Initial delay
	if a.config.InitialDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(a.config.InitialDelay):
		}
	}

	// Run immediately on start
	a.runAllSources(ctx)

	// Then run periodically
	ticker := time.NewTicker(15 * time.Minute) // Check every 15 minutes which sources need updating
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info().Msg("aggregation loop stopped")
			return ctx.Err()
		case <-ticker.C:
			a.runDueSources(ctx)
		}
	}
}

// RunOnce runs aggregation once for all sources
func (a *Aggregator) RunOnce(ctx context.Context) error {
	return a.runAllSources(ctx)
}

// RunSource runs aggregation for a specific source
func (a *Aggregator) RunSource(ctx context.Context, slug string) error {
	conn, ok := a.GetConnector(slug)
	if !ok {
		return fmt.Errorf("source not found: %s", slug)
	}

	return a.fetchFromSource(ctx, conn)
}

// runAllSources runs aggregation for all enabled sources
func (a *Aggregator) runAllSources(ctx context.Context) error {
	a.mu.Lock()
	if a.isRunning {
		a.mu.Unlock()
		a.logger.Warn().Msg("aggregation already running, skipping")
		return nil
	}
	a.isRunning = true
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.isRunning = false
		a.lastRun = time.Now()
		a.mu.Unlock()
	}()

	a.logger.Info().Int("connectors", len(a.connectors)).Msg("starting full aggregation run")

	// Create worker pool
	workerCount := a.config.WorkerPoolSize
	if workerCount <= 0 {
		workerCount = 5
	}

	jobs := make(chan SourceConnector, len(a.connectors))
	results := make(chan *AggregationResult, len(a.connectors))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for conn := range jobs {
				result := a.processSource(ctx, conn)
				results <- result
			}
		}(i)
	}

	// Send jobs
	a.mu.RLock()
	for _, conn := range a.connectors {
		if conn.IsEnabled() {
			jobs <- conn
		}
	}
	a.mu.RUnlock()
	close(jobs)

	// Wait for workers
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var totalNew, totalUpdated, totalErrors int
	for result := range results {
		if result.Error != nil {
			totalErrors++
		} else {
			totalNew += result.NewIndicators
			totalUpdated += result.UpdatedIndicators
		}
	}

	a.logger.Info().
		Int("new_indicators", totalNew).
		Int("updated_indicators", totalUpdated).
		Int("errors", totalErrors).
		Msg("aggregation run completed")

	return nil
}

// runDueSources runs aggregation only for sources that are due for update
func (a *Aggregator) runDueSources(ctx context.Context) error {
	// If we have a repository, use database-backed scheduling
	if a.repository != nil {
		dueSources, err := a.repository.GetDueSources(ctx)
		if err != nil {
			a.logger.Warn().Err(err).Msg("failed to get due sources from database, falling back to all sources")
		} else if len(dueSources) > 0 {
			a.logger.Info().Int("due_sources", len(dueSources)).Msg("processing due sources from database")

			for _, source := range dueSources {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					conn, ok := a.GetConnector(source.Slug)
					if ok && conn.IsEnabled() {
						_ = a.fetchFromSourceWithDB(ctx, conn, source)
					}
				}
			}
			return nil
		}
	}

	// Fallback: run all enabled connectors
	a.mu.RLock()
	var dueSources []SourceConnector
	for _, conn := range a.connectors {
		if conn.IsEnabled() {
			dueSources = append(dueSources, conn)
		}
	}
	a.mu.RUnlock()

	if len(dueSources) == 0 {
		return nil
	}

	a.logger.Info().Int("due_sources", len(dueSources)).Msg("processing due sources")

	for _, conn := range dueSources {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_ = a.fetchFromSource(ctx, conn)
		}
	}

	return nil
}

// processSource processes a single source and returns the result
func (a *Aggregator) processSource(ctx context.Context, conn SourceConnector) *AggregationResult {
	result := &AggregationResult{
		SourceSlug: conn.Slug(),
		StartedAt:  time.Now(),
	}

	err := a.fetchFromSource(ctx, conn)
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	if err != nil {
		result.Error = err
		a.logger.Error().Err(err).Str("source", conn.Slug()).Msg("failed to fetch from source")
	}

	return result
}

// fetchFromSourceWithDB fetches indicators with database tracking for incremental updates
func (a *Aggregator) fetchFromSourceWithDB(ctx context.Context, conn SourceConnector, source *models.Source) error {
	start := time.Now()
	log := a.logger.WithSourceID(conn.Slug())

	log.Info().
		Str("source_id", source.ID.String()).
		Msg("fetching from source (incremental)")

	// Fetch raw indicators
	fetchResult, err := conn.Fetch(ctx)
	if err != nil {
		log.Error().Err(err).Msg("fetch failed")

		// Update source with error
		if a.repository != nil {
			_ = a.repository.UpdateSourceAfterError(ctx, source.ID, err.Error())
		}

		// Record failed fetch in history
		if a.repository != nil && fetchResult != nil {
			fetchResult.SourceID = source.ID
			fetchResult.Success = false
			fetchResult.Error = err
			fetchResult.Duration = time.Since(start)
			_ = a.repository.RecordFetchHistory(ctx, fetchResult)
		}

		return err
	}

	// Set source ID for tracking
	fetchResult.SourceID = source.ID

	log.Info().
		Int("raw_count", len(fetchResult.RawIndicators)).
		Dur("fetch_duration", time.Since(start)).
		Msg("fetch completed")

	if len(fetchResult.RawIndicators) == 0 {
		// Update source after successful empty fetch
		if a.repository != nil {
			_ = a.repository.UpdateSourceAfterSuccess(ctx, source.ID)
			fetchResult.Success = true
			fetchResult.Duration = time.Since(start)
			_ = a.repository.RecordFetchHistory(ctx, fetchResult)
		}
		return nil
	}

	// Normalize indicators
	normalized, normErrors := a.normalizer.NormalizeBatch(fetchResult.RawIndicators)
	if len(normErrors) > 0 {
		log.Warn().Int("errors", len(normErrors)).Msg("normalization errors")
	}

	log.Info().Int("normalized_count", len(normalized)).Msg("normalization completed")

	// Deduplicate
	dedupResult, err := a.deduplicator.Deduplicate(ctx, normalized)
	if err != nil {
		log.Error().Err(err).Msg("deduplication failed")
		return err
	}

	log.Info().
		Int("new", len(dedupResult.NewIndicators)).
		Int("existing", len(dedupResult.ExistingIndicators)).
		Int("duplicates", dedupResult.DuplicateCount).
		Msg("deduplication completed")

	// Score and store new indicators
	for _, indicator := range dedupResult.NewIndicators {
		indicator.Confidence = a.scorer.ScoreIndicator(indicator, nil)
		if a.repository != nil {
			_, err := a.repository.UpsertIndicator(ctx, indicator)
			if err != nil {
				log.Warn().Err(err).Str("value", indicator.Value).Msg("failed to store indicator")
				continue
			}
		}

		// Mark as seen AFTER successful storage to avoid losing data on storage failures
		a.deduplicator.MarkSeen(ctx, indicator.ValueHash)

		// Publish real-time event for new threat
		if a.publisher != nil {
			if err := a.publisher.PublishNewThreat(ctx, indicator, source.Slug, source.Name); err != nil {
				log.Debug().Err(err).Str("value", indicator.Value).Msg("failed to publish threat event")
			}
		}
	}

	// Update source after successful fetch
	if a.repository != nil {
		_ = a.repository.UpdateSourceAfterSuccess(ctx, source.ID)
	}

	// Record successful fetch in history
	fetchResult.Success = true
	fetchResult.NewIndicators = len(dedupResult.NewIndicators)
	fetchResult.UpdatedIndicators = len(dedupResult.ExistingIndicators)
	fetchResult.SkippedIndicators = dedupResult.DuplicateCount
	fetchResult.Duration = time.Since(start)

	if a.repository != nil {
		_ = a.repository.RecordFetchHistory(ctx, fetchResult)
	}

	// Increment sync version for mobile apps
	_, _ = a.cache.IncrementSyncVersion(ctx)

	duration := time.Since(start)

	// Publish source update event
	if a.publisher != nil {
		_ = a.publisher.PublishSourceUpdate(ctx, source.Slug, source.Name, true, len(dedupResult.NewIndicators), len(dedupResult.ExistingIndicators), duration, nil)
	}

	log.Info().
		Int("new_indicators", len(dedupResult.NewIndicators)).
		Dur("total_duration", duration).
		Msg("source processing completed")

	return nil
}

// fetchFromSource fetches and processes indicators from a single source
func (a *Aggregator) fetchFromSource(ctx context.Context, conn SourceConnector) error {
	start := time.Now()
	log := a.logger.WithSourceID(conn.Slug())

	log.Info().Msg("fetching from source")

	// Fetch raw indicators
	fetchResult, err := conn.Fetch(ctx)
	if err != nil {
		log.Error().Err(err).Msg("fetch failed")
		return err
	}

	log.Info().
		Int("raw_count", len(fetchResult.RawIndicators)).
		Dur("fetch_duration", time.Since(start)).
		Msg("fetch completed")

	if len(fetchResult.RawIndicators) == 0 {
		return nil
	}

	// Normalize indicators
	normalized, normErrors := a.normalizer.NormalizeBatch(fetchResult.RawIndicators)
	if len(normErrors) > 0 {
		log.Warn().Int("errors", len(normErrors)).Msg("normalization errors")
	}

	log.Info().Int("normalized_count", len(normalized)).Msg("normalization completed")

	// Deduplicate
	dedupResult, err := a.deduplicator.Deduplicate(ctx, normalized)
	if err != nil {
		log.Error().Err(err).Msg("deduplication failed")
		return err
	}

	log.Info().
		Int("new", len(dedupResult.NewIndicators)).
		Int("existing", len(dedupResult.ExistingIndicators)).
		Int("duplicates", dedupResult.DuplicateCount).
		Msg("deduplication completed")

	// Score and store new indicators
	for _, indicator := range dedupResult.NewIndicators {
		// Score the indicator
		indicator.Confidence = a.scorer.ScoreIndicator(indicator, nil)

		// Store in repository
		if a.repository != nil {
			_, err := a.repository.UpsertIndicator(ctx, indicator)
			if err != nil {
				log.Warn().Err(err).Str("value", indicator.Value).Msg("failed to store indicator")
				continue
			}
		}

		// Mark as seen AFTER successful storage to avoid losing data on storage failures
		a.deduplicator.MarkSeen(ctx, indicator.ValueHash)

		// Publish real-time event for new threat
		if a.publisher != nil {
			if err := a.publisher.PublishNewThreat(ctx, indicator, conn.Slug(), conn.Slug()); err != nil {
				log.Debug().Err(err).Str("value", indicator.Value).Msg("failed to publish threat event")
			}
		}
	}

	// Update existing indicators
	for range dedupResult.ExistingIndicators {
		if a.repository != nil {
			// Just update the source relationship
			// The actual indicator update happens via UpsertIndicator's ON CONFLICT
		}
	}

	// Update source metadata
	if a.repository != nil {
		_ = a.repository.UpdateSourceAfterFetch(ctx, fetchResult.SourceID)
	}

	// Increment sync version for mobile apps
	_, _ = a.cache.IncrementSyncVersion(ctx)

	duration := time.Since(start)

	// Publish source update event
	if a.publisher != nil {
		_ = a.publisher.PublishSourceUpdate(ctx, conn.Slug(), conn.Slug(), true, len(dedupResult.NewIndicators), len(dedupResult.ExistingIndicators), duration, nil)
	}

	log.Info().
		Dur("total_duration", duration).
		Msg("source processing completed")

	return nil
}

// Stats returns aggregator statistics
func (a *Aggregator) Stats() AggregatorStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	enabledCount := 0
	for _, conn := range a.connectors {
		if conn.IsEnabled() {
			enabledCount++
		}
	}

	return AggregatorStats{
		TotalConnectors:   len(a.connectors),
		EnabledConnectors: enabledCount,
		IsRunning:         a.isRunning,
		LastRun:           a.lastRun,
		TotalFetched:      a.totalFetched,
	}
}

// AggregatorStats holds aggregator statistics
type AggregatorStats struct {
	TotalConnectors   int       `json:"total_connectors"`
	EnabledConnectors int       `json:"enabled_connectors"`
	IsRunning         bool      `json:"is_running"`
	LastRun           time.Time `json:"last_run"`
	TotalFetched      int64     `json:"total_fetched"`
}

// AggregationResult holds the result of processing a single source
type AggregationResult struct {
	SourceSlug        string        `json:"source_slug"`
	StartedAt         time.Time     `json:"started_at"`
	CompletedAt       time.Time     `json:"completed_at"`
	Duration          time.Duration `json:"duration"`
	TotalFetched      int           `json:"total_fetched"`
	NewIndicators     int           `json:"new_indicators"`
	UpdatedIndicators int           `json:"updated_indicators"`
	SkippedIndicators int           `json:"skipped_indicators"`
	Error             error         `json:"error,omitempty"`
}
