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
	"orbguard-lab/internal/infrastructure/graph"
	"orbguard-lab/internal/sources"
	"orbguard-lab/internal/sources/free/abusech"
	"orbguard-lab/internal/sources/free/government"
	"orbguard-lab/internal/sources/free/ip"
	"orbguard-lab/internal/sources/free/mobile"
	"orbguard-lab/internal/sources/free/phishing"
	"orbguard-lab/internal/sources/premium"
	"orbguard-lab/internal/streaming"
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

	// Initialize streaming infrastructure
	var natsPublisher *streaming.NATSPublisher
	if cfg.NATS.Enabled {
		var err error
		natsPublisher, err = streaming.NewNATSPublisher(ctx, cfg.NATS, log)
		if err != nil {
			log.Warn().Err(err).Msg("failed to connect to NATS, continuing without real-time streaming")
		} else {
			log.Info().Str("url", cfg.NATS.URL).Msg("connected to NATS")
		}
	}

	// Create event bus for real-time updates
	eventBus := streaming.NewEventBus(natsPublisher, log)
	log.Info().Bool("nats_enabled", natsPublisher != nil).Msg("event bus initialized")

	// Create WebSocket hub for mobile app real-time updates
	wsHub := streaming.NewWebSocketHub(natsPublisher, log)
	go wsHub.Run(ctx)

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

	// Wire event publisher for real-time updates
	eventPublisher := streaming.NewEventBusPublisher(eventBus, wsHub)
	aggregator.SetEventPublisher(eventPublisher)

	// Initialize URL reputation service (Safe Web protection)
	urlService := services.NewURLReputationService(repos, redisCache, nil, log)
	log.Info().Msg("URL reputation service initialized")

	// Initialize dark web monitoring (HIBP integration)
	hibpClient := services.NewHIBPClient(services.HIBPConfig{
		APIKey: cfg.HIBP.APIKey,
	}, log)
	darkWebMonitor := services.NewDarkWebMonitor(hibpClient, redisCache, log)
	log.Info().Msg("dark web monitor initialized")

	// Initialize app security analyzer
	appAnalyzer := services.NewAppAnalyzer(repos, redisCache, log)
	log.Info().Msg("app security analyzer initialized")

	// Initialize network security service
	networkSecurity := services.NewNetworkSecurityService(repos, redisCache, log)
	log.Info().Msg("network security service initialized")

	// Initialize YARA scanning service
	yaraService := services.NewYARAService(cfg.Detection.YARA.RulesDir, redisCache, log)
	log.Info().Int("rules_loaded", len(yaraService.GetRules(nil))).Msg("YARA service initialized")

	// Initialize correlation engine
	correlationEngine := services.NewCorrelationEngine(repos, redisCache, log)
	log.Info().Msg("correlation engine initialized")

	// Initialize MITRE ATT&CK service
	mitreService := services.NewMITREService(cfg.MITRE.DataDir, redisCache, log)
	log.Info().
		Int("tactics", mitreService.GetStats().TotalTactics).
		Int("techniques", mitreService.GetStats().TotalTechniques).
		Msg("MITRE ATT&CK service initialized")

	// Initialize ML service
	mlService := services.NewMLService(services.DefaultMLServiceConfig(), repos, redisCache, log)
	log.Info().Msg("ML service initialized")

	// Initialize privacy protection service
	privacyService := services.NewPrivacyService(redisCache, log)
	log.Info().Msg("privacy protection service initialized")

	// Initialize device security service (anti-theft, SIM monitoring, OS vulnerabilities)
	deviceSecurityService := services.NewDeviceSecurityService(redisCache, log)
	log.Info().Msg("device security service initialized")

	// Initialize QR security service (quishing protection)
	qrSecurityService := services.NewQRSecurityService(urlService, redisCache, log)
	log.Info().Msg("QR security service initialized")

	// Initialize STIX/TAXII service (enterprise threat intel standard)
	stixTAXIIService := services.NewSTIXTAXIIService(repos, redisCache, log)
	log.Info().Msg("STIX/TAXII 2.1 service initialized")

	// Initialize Enterprise service (MDM, Zero Trust, SIEM, Compliance)
	enterpriseService := services.NewEnterpriseService(repos, redisCache, log)
	enterpriseService.Start(ctx)
	defer enterpriseService.Stop()
	log.Info().Msg("enterprise services initialized (MDM, Zero Trust, SIEM, Compliance)")

	// Initialize OrbNet VPN integration service
	orbnetService := services.NewOrbNetService(repos, redisCache, log)
	log.Info().Msg("OrbNet VPN integration service initialized")

	// Initialize Neo4j graph database (if enabled)
	var graphService *services.GraphService
	if cfg.Neo4j.Enabled {
		neo4jClient, err := graph.NewNeo4jClient(ctx, cfg.Neo4j, log)
		if err != nil {
			log.Warn().Err(err).Msg("failed to connect to Neo4j, graph features disabled")
		} else {
			defer neo4jClient.Close(ctx)
			graphRepo := graph.NewGraphRepository(neo4jClient, log)
			graphService = services.NewGraphService(graphRepo, repos, redisCache, log)
			log.Info().Str("uri", cfg.Neo4j.URI).Msg("Neo4j graph database initialized")
		}
	}

	// Initialize handlers
	deps := handlers.Dependencies{
		Aggregator:        aggregator,
		Normalizer:        normalizer,
		Deduplicator:      deduplicator,
		Scorer:            scorer,
		Scheduler:         scheduler,
		Cache:             redisCache,
		Logger:            log,
		Repos:             repos,
		EventBus:          eventBus,
		WSHub:             wsHub,
		URLService:        urlService,
		DarkWebMonitor:    darkWebMonitor,
		AppAnalyzer:       appAnalyzer,
		NetworkSecurity:   networkSecurity,
		GraphService:      graphService,
		YARAService:       yaraService,
		CorrelationEngine: correlationEngine,
		MITREService:          mitreService,
		MLService:             mlService,
		PrivacyService:        privacyService,
		DeviceSecurityService: deviceSecurityService,
		QRSecurityService:     qrSecurityService,
		STIXTAXIIService:      stixTAXIIService,
		EnterpriseService:     enterpriseService,
		OrbNetService:         orbnetService,
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
	threatIntelServer := grpcserver.NewServer(aggregator, repos, redisCache, eventBus, log)
	threatIntelServer.Register(grpcServer)

	// Register gRPC health check service
	grpcserver.RegisterHealthServer(grpcServer, db, redisCache)

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
	if err := registry.Register(abusech.NewThreatFoxConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register ThreatFox connector")
	}
	if err := registry.Register(abusech.NewMalwareBazaarConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register MalwareBazaar connector")
	}
	if err := registry.Register(abusech.NewFeodoTrackerConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register FeodoTracker connector")
	}
	// SSLBlacklist disabled - feed was deprecated by abuse.ch on 2025-01-03
	// if err := registry.Register(abusech.NewSSLBlacklistConnector(log)); err != nil {
	// 	log.Warn().Err(err).Msg("failed to register SSLBlacklist connector")
	// }

	// IP Reputation connectors
	if err := registry.Register(ip.NewAbuseIPDBConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register AbuseIPDB connector")
	}
	// GreyNoise: Auto-detects API tier - Enterprise enables bulk GNQL, Community enables single IP lookups
	if err := registry.Register(ip.NewGreyNoiseConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register GreyNoise connector")
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

	// Premium connectors (require API keys)
	if err := registry.Register(premium.NewVirusTotalConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register VirusTotal connector")
	}
	if err := registry.Register(premium.NewAlienVaultOTXConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register AlienVault OTX connector")
	}
	if err := registry.Register(premium.NewKoodousConnector(log)); err != nil {
		log.Warn().Err(err).Msg("failed to register Koodous connector")
	}

	log.Info().
		Int("total", registry.Count()).
		Int("enabled", registry.CountEnabled()).
		Msg("registered source connectors")
}
