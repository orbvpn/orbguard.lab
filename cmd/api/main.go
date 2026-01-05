package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"orbguard-lab/internal/api"
	"orbguard-lab/internal/api/handlers"
	"orbguard-lab/internal/config"
	"orbguard-lab/internal/domain/services"
	grpcserver "orbguard-lab/internal/grpc/threatintel"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/internal/sources"
	"orbguard-lab/internal/sources/free/abusech"
	"orbguard-lab/internal/sources/free/mobile"
	"orbguard-lab/pkg/logger"
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
	logger.SetGlobal(log)

	log.Info().
		Str("app", cfg.App.Name).
		Str("env", cfg.App.Environment).
		Str("version", cfg.App.Version).
		Msg("starting OrbGuard Lab")

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

	// Initialize services
	normalizer := services.NewNormalizer(log)
	deduplicator := services.NewDeduplicator(redisCache, log)
	scorer := services.NewScorer(cfg.Scoring, log)

	// Create aggregator with repository adapter (if available)
	var aggregatorRepo services.IndicatorRepository
	if repos != nil {
		aggregatorRepo = repos.AggregatorAdapter
	}
	aggregator := services.NewAggregator(cfg.Aggregation, aggregatorRepo, normalizer, deduplicator, scorer, redisCache, log)
	scheduler := services.NewScheduler(aggregator, redisCache, log)

	// Register source connectors
	registry := sources.NewRegistry(log)
	registerConnectors(registry, log)
	registry.ConfigureFromSourcesConfig(cfg.Sources)

	// Register connectors with aggregator
	for _, conn := range registry.List() {
		aggregator.RegisterConnector(conn)
	}

	// Initialize handlers
	deps := handlers.Dependencies{
		Aggregator:   aggregator,
		Normalizer:   normalizer,
		Deduplicator: deduplicator,
		Scorer:       scorer,
		Scheduler:    scheduler,
		Cache:        redisCache,
		Logger:       log,
		Repos:        repos,
	}
	h := handlers.NewHandlers(deps)

	// Create router
	router := api.NewRouter(*cfg, h, redisCache, log)
	httpHandler := router.Setup()

	// Start HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.HTTPPort),
		Handler:      httpHandler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		log.Info().
			Str("addr", httpServer.Addr).
			Msg("starting HTTP server")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server failed")
		}
	}()

	// Start gRPC server
	grpcListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.GRPCPort))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create gRPC listener")
	}

	grpcServer := grpc.NewServer()
	threatIntelServer := grpcserver.NewServer(aggregator, redisCache, log)
	threatIntelServer.Register(grpcServer)

	go func() {
		log.Info().
			Str("addr", grpcListener.Addr().String()).
			Msg("starting gRPC server")
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Fatal().Err(err).Msg("gRPC server failed")
		}
	}()

	// Start background services
	if cfg.Aggregation.Enabled {
		go func() {
			if err := aggregator.Run(ctx); err != nil && err != context.Canceled {
				log.Error().Err(err).Msg("aggregator stopped with error")
			}
		}()

		go func() {
			if err := scheduler.Start(ctx); err != nil && err != context.Canceled {
				log.Error().Err(err).Msg("scheduler stopped with error")
			}
		}()
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("shutting down...")

	// Cancel context to stop background services
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	// Stop gRPC server
	grpcServer.GracefulStop()

	// Stop HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	// Stop scheduler
	scheduler.Stop()

	log.Info().Msg("shutdown complete")
}

// initInfrastructure initializes database and cache connections
func initInfrastructure(ctx context.Context, cfg *config.Config, log *logger.Logger) (*database.PostgresDB, *cache.RedisCache, error) {
	// Connect to PostgreSQL
	db, err := database.NewPostgres(ctx, cfg.Database, log)
	if err != nil {
		log.Warn().Err(err).Msg("failed to connect to PostgreSQL, continuing without database")
		// Don't fail, continue without database for development
	}

	// Connect to Redis
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

	// Mobile/Spyware connectors (HIGH PRIORITY)
	if err := registry.Register(mobile.NewCitizenLabConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register CitizenLab connector")
	}
	if err := registry.Register(mobile.NewAmnestyMVTConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register AmnestyMVT connector")
	}

	// TODO: Register more connectors:
	// - ThreatFox
	// - MalwareBazaar
	// - Feodo Tracker
	// - OpenPhish
	// - etc.

	log.Info().
		Int("total", registry.Count()).
		Int("enabled", registry.CountEnabled()).
		Msg("registered source connectors")
}
