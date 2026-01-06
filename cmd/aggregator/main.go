package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"orbguard-lab/internal/config"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/internal/sources"
	"orbguard-lab/internal/sources/free/abusech"
	"orbguard-lab/internal/sources/free/government"
	"orbguard-lab/internal/sources/free/mobile"
	"orbguard-lab/internal/sources/free/phishing"
	"orbguard-lab/pkg/logger"
)

const (
	// Lock settings
	lockTTL     = 5 * time.Minute
	lockKey     = "aggregator:worker"
	lockRefresh = 1 * time.Minute

	// Retry settings
	maxRetries     = 3
	baseRetryDelay = 30 * time.Second
	maxRetryDelay  = 5 * time.Minute
)

func main() {
	// Load configuration
	cfg, err := config.LoadDefault()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	var log *logger.Logger
	if cfg.App.Environment == "production" {
		log = logger.NewProduction()
	} else {
		log = logger.NewDevelopment()
	}
	log = log.WithComponent("aggregator-worker")
	logger.SetGlobal(log)

	log.Info().
		Str("app", cfg.App.Name).
		Str("env", cfg.App.Environment).
		Str("version", cfg.App.Version).
		Msg("starting OrbGuard Aggregator Worker")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize infrastructure
	db, redisCache, err := initInfrastructure(ctx, cfg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize infrastructure")
	}
	defer func() {
		if db != nil {
			db.Close()
		}
		if redisCache != nil {
			redisCache.Close()
		}
	}()

	// Initialize repositories
	var repos *repository.Repositories
	if db != nil {
		repos = repository.NewRepositories(db.Pool())
		log.Info().Msg("repositories initialized with database")
	} else {
		log.Warn().Msg("running without database - repositories unavailable")
	}

	// Create worker
	worker := NewAggregatorWorker(cfg, repos, redisCache, log)

	// Handle shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start worker
	go func() {
		if err := worker.Run(ctx); err != nil && err != context.Canceled {
			log.Error().Err(err).Msg("worker stopped with error")
			cancel()
		}
	}()

	// Wait for shutdown signal
	<-quit
	log.Info().Msg("shutting down aggregator worker...")
	cancel()

	// Give time for graceful shutdown
	time.Sleep(2 * time.Second)
	log.Info().Msg("shutdown complete")
}

// AggregatorWorker is a standalone background worker for aggregation
type AggregatorWorker struct {
	config       *config.Config
	repos        *repository.Repositories
	cache        *cache.RedisCache
	logger       *logger.Logger
	aggregator   *services.Aggregator
	normalizer   *services.Normalizer
	deduplicator *services.Deduplicator
	scorer       *services.Scorer
}

// NewAggregatorWorker creates a new aggregator worker
func NewAggregatorWorker(
	cfg *config.Config,
	repos *repository.Repositories,
	cache *cache.RedisCache,
	log *logger.Logger,
) *AggregatorWorker {
	// Initialize services
	normalizer := services.NewNormalizer(log)
	deduplicator := services.NewDeduplicator(cache, log)
	scorer := services.NewScorer(cfg.Scoring, log)

	// Create aggregator with repository adapter (if available)
	var aggregatorRepo services.IndicatorRepository
	if repos != nil {
		aggregatorRepo = repos.AggregatorAdapter
	}
	aggregator := services.NewAggregator(cfg.Aggregation, aggregatorRepo, normalizer, deduplicator, scorer, cache, log)

	// Register source connectors
	registry := sources.NewRegistry(log)
	registerConnectors(registry, log)
	registry.ConfigureFromSourcesConfig(cfg.Sources)

	// Register connectors with aggregator
	for _, conn := range registry.List() {
		aggregator.RegisterConnector(conn)
	}

	return &AggregatorWorker{
		config:       cfg,
		repos:        repos,
		cache:        cache,
		logger:       log,
		aggregator:   aggregator,
		normalizer:   normalizer,
		deduplicator: deduplicator,
		scorer:       scorer,
	}
}

// Run starts the worker main loop
func (w *AggregatorWorker) Run(ctx context.Context) error {
	w.logger.Info().
		Dur("interval", 15*time.Minute).
		Int("max_retries", maxRetries).
		Msg("starting aggregation worker loop")

	// Run immediately on start
	w.runWithLockAndRetry(ctx)

	// Then run periodically
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info().Msg("aggregation worker stopped")
			return ctx.Err()
		case <-ticker.C:
			w.runWithLockAndRetry(ctx)
		}
	}
}

// runWithLockAndRetry attempts to acquire lock and run aggregation with retry
func (w *AggregatorWorker) runWithLockAndRetry(ctx context.Context) {
	// Try to acquire distributed lock
	acquired, err := w.cache.AcquireLock(ctx, lockKey, lockTTL)
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to acquire lock")
		return
	}

	if !acquired {
		w.logger.Debug().Msg("another worker is running, skipping")
		return
	}

	// Release lock when done
	defer func() {
		if err := w.cache.ReleaseLock(ctx, lockKey); err != nil {
			w.logger.Warn().Err(err).Msg("failed to release lock")
		}
	}()

	// Start lock refresh goroutine
	lockCtx, lockCancel := context.WithCancel(ctx)
	defer lockCancel()
	go w.refreshLock(lockCtx)

	// Run aggregation with retry
	w.runWithRetry(ctx)
}

// refreshLock periodically refreshes the distributed lock
func (w *AggregatorWorker) refreshLock(ctx context.Context) {
	ticker := time.NewTicker(lockRefresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Extend lock TTL
			if err := w.cache.Expire(ctx, cache.KeySchedulerLock+lockKey, lockTTL); err != nil {
				w.logger.Warn().Err(err).Msg("failed to refresh lock")
			}
		}
	}
}

// runWithRetry runs aggregation with exponential backoff retry
func (w *AggregatorWorker) runWithRetry(ctx context.Context) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := calculateBackoff(attempt)
			w.logger.Info().
				Int("attempt", attempt+1).
				Dur("delay", delay).
				Msg("retrying aggregation after delay")

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}

		err := w.runAggregation(ctx)
		if err == nil {
			return
		}

		lastErr = err
		w.logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_retries", maxRetries).
			Msg("aggregation failed")
	}

	w.logger.Error().
		Err(lastErr).
		Int("attempts", maxRetries+1).
		Msg("aggregation failed after all retries")
}

// runAggregation runs a single aggregation cycle
func (w *AggregatorWorker) runAggregation(ctx context.Context) error {
	start := time.Now()
	w.logger.Info().Msg("starting aggregation run")

	// Run the aggregator
	err := w.aggregator.RunOnce(ctx)

	duration := time.Since(start)
	if err != nil {
		w.logger.Error().
			Err(err).
			Dur("duration", duration).
			Msg("aggregation run failed")

		// Record failed run in history
		w.recordRunHistory(ctx, start, duration, false, err.Error())
		return err
	}

	w.logger.Info().
		Dur("duration", duration).
		Msg("aggregation run completed successfully")

	// Record successful run in history
	w.recordRunHistory(ctx, start, duration, true, "")
	return nil
}

// recordRunHistory records the aggregation run in update history
func (w *AggregatorWorker) recordRunHistory(ctx context.Context, startTime time.Time, duration time.Duration, success bool, errorMsg string) {
	history := map[string]any{
		"started_at":   startTime.Format(time.RFC3339),
		"completed_at": time.Now().Format(time.RFC3339),
		"duration_ms":  duration.Milliseconds(),
		"success":      success,
		"error":        errorMsg,
	}

	// Store in Redis (last 100 runs)
	historyKey := "aggregator:history"
	data := fmt.Sprintf("%s|%v|%d|%s",
		startTime.Format(time.RFC3339),
		success,
		duration.Milliseconds(),
		errorMsg,
	)

	pipe := w.cache.Pipeline()
	pipe.LPush(ctx, historyKey, data)
	pipe.LTrim(ctx, historyKey, 0, 99) // Keep last 100 entries
	_, err := pipe.Exec(ctx)
	if err != nil {
		w.logger.Warn().Err(err).Msg("failed to record run history")
	}

	// Also store in database if available
	if w.repos != nil {
		// Store as JSON in Redis for quick access
		if err := w.cache.SetJSON(ctx, "aggregator:last_run", history, 24*time.Hour); err != nil {
			w.logger.Warn().Err(err).Msg("failed to cache last run")
		}
	}
}

// calculateBackoff calculates exponential backoff delay
func calculateBackoff(attempt int) time.Duration {
	delay := baseRetryDelay * time.Duration(1<<uint(attempt-1)) // 2^(attempt-1) * baseDelay
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	return delay
}

// initInfrastructure initializes database and cache connections
func initInfrastructure(ctx context.Context, cfg *config.Config, log *logger.Logger) (*database.PostgresDB, *cache.RedisCache, error) {
	// Connect to PostgreSQL
	db, err := database.NewPostgres(ctx, cfg.Database, log)
	if err != nil {
		log.Warn().Err(err).Msg("failed to connect to PostgreSQL, continuing without database")
		// Don't fail, continue without database for development
	}

	// Connect to Redis (required for distributed locking)
	redisCache, err := cache.NewRedis(ctx, cfg.Redis, log)
	if err != nil {
		return db, nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return db, redisCache, nil
}

// registerConnectors registers all available source connectors
func registerConnectors(registry *sources.Registry, log *logger.Logger) {
	// Abuse.ch connectors
	if err := registry.Register(abusech.NewURLhausConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register URLhaus connector")
	}
	if err := registry.Register(abusech.NewThreatFoxConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register ThreatFox connector")
	}

	// Phishing connectors
	if err := registry.Register(phishing.NewOpenPhishConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register OpenPhish connector")
	}
	if err := registry.Register(phishing.NewSafeBrowsingConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register Google Safe Browsing connector")
	}

	// Government connectors
	if err := registry.Register(government.NewCISAKEVConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register CISA KEV connector")
	}

	// Mobile/Spyware connectors (HIGH PRIORITY)
	if err := registry.Register(mobile.NewCitizenLabConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register CitizenLab connector")
	}
	if err := registry.Register(mobile.NewAmnestyMVTConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register AmnestyMVT connector")
	}

	log.Info().
		Int("total", registry.Count()).
		Int("enabled", registry.CountEnabled()).
		Msg("registered source connectors")
}
