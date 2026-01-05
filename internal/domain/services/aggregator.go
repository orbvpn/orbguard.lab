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
	a.mu.RLock()
	var dueSources []SourceConnector
	for _, conn := range a.connectors {
		if conn.IsEnabled() {
			// In a full implementation, check the database for next_fetch time
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

	log.Info().
		Dur("total_duration", time.Since(start)).
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
