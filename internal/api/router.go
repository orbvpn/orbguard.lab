package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"orbguard-lab/internal/api/handlers"
	apimiddleware "orbguard-lab/internal/api/middleware"
	"orbguard-lab/internal/config"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// Router holds dependencies for the API router
type Router struct {
	config   config.Config
	handlers *handlers.Handlers
	cache    *cache.RedisCache
	logger   *logger.Logger
}

// NewRouter creates a new Router instance
func NewRouter(cfg config.Config, h *handlers.Handlers, c *cache.RedisCache, log *logger.Logger) *Router {
	return &Router{
		config:   cfg,
		handlers: h,
		cache:    c,
		logger:   log.WithComponent("router"),
	}
}

// Setup sets up the Chi router with all routes and middleware
func (r *Router) Setup() http.Handler {
	router := chi.NewRouter()

	// Core middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(apimiddleware.Logger(r.logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   r.config.CORS.AllowedOrigins,
		AllowedMethods:   r.config.CORS.AllowedMethods,
		AllowedHeaders:   r.config.CORS.AllowedHeaders,
		AllowCredentials: r.config.CORS.AllowCredentials,
		MaxAge:           r.config.CORS.MaxAge,
	}))

	// Rate limiting
	if r.config.RateLimit.Enabled {
		router.Use(apimiddleware.RateLimiter(r.cache, r.config.RateLimit))
	}

	// Public routes
	router.Group(func(pub chi.Router) {
		// Health check
		pub.Get("/health", r.handlers.Health.Check)
		pub.Get("/ready", r.handlers.Health.Ready)

		// Public stats
		pub.Get("/api/v1/stats", r.handlers.Stats.Get)
	})

	// API v1 routes (authenticated)
	router.Route("/api/v1", func(api chi.Router) {
		// Auth middleware for protected routes
		api.Use(apimiddleware.APIKeyAuth(r.config.JWT.Secret))

		// Intelligence endpoints
		api.Route("/intelligence", func(intel chi.Router) {
			// Get all indicators
			intel.Get("/", r.handlers.Intelligence.List)

			// Pegasus-specific indicators
			intel.Get("/pegasus", r.handlers.Intelligence.ListPegasus)

			// Mobile-specific indicators
			intel.Get("/mobile", r.handlers.Intelligence.ListMobile)
			intel.Get("/mobile/sync", r.handlers.Intelligence.MobileSync)

			// Community-reported indicators
			intel.Get("/community", r.handlers.Intelligence.ListCommunity)

			// Check indicator(s)
			intel.Get("/check", r.handlers.Intelligence.Check)
			intel.Post("/check/batch", r.handlers.Intelligence.CheckBatch)

			// Report new threat
			intel.Post("/report", r.handlers.Intelligence.Report)
		})

		// Campaign endpoints
		api.Route("/campaigns", func(campaigns chi.Router) {
			campaigns.Get("/", r.handlers.Campaigns.List)
			campaigns.Get("/{slug}", r.handlers.Campaigns.Get)
			campaigns.Get("/{slug}/indicators", r.handlers.Campaigns.ListIndicators)
		})

		// Threat actors endpoints
		api.Route("/actors", func(actors chi.Router) {
			actors.Get("/", r.handlers.Actors.List)
			actors.Get("/{id}", r.handlers.Actors.Get)
		})

		// Sources endpoints
		api.Route("/sources", func(sources chi.Router) {
			sources.Get("/", r.handlers.Sources.List)
			sources.Get("/{slug}", r.handlers.Sources.Get)
		})

		// Admin endpoints
		api.Route("/admin", func(admin chi.Router) {
			// Require admin auth
			admin.Use(apimiddleware.AdminAuth(r.config.JWT.Secret))

			// Force update
			admin.Post("/update", r.handlers.Admin.TriggerUpdate)
			admin.Post("/update/{source}", r.handlers.Admin.TriggerSourceUpdate)

			// Reports management
			admin.Get("/reports", r.handlers.Admin.ListReports)
			admin.Get("/reports/{id}", r.handlers.Admin.GetReport)
			admin.Post("/reports/{id}/approve", r.handlers.Admin.ApproveReport)
			admin.Post("/reports/{id}/reject", r.handlers.Admin.RejectReport)

			// Stats
			admin.Get("/stats/detailed", r.handlers.Admin.DetailedStats)
		})
	})

	// TAXII 2.1 endpoints (optional)
	if r.config.STIX.Enabled && r.config.STIX.TAXIIServer.Enabled {
		router.Route("/taxii2", func(taxii chi.Router) {
			taxii.Get("/", r.handlers.TAXII.Discovery)
			taxii.Get("/collections", r.handlers.TAXII.ListCollections)
			taxii.Get("/collections/{id}", r.handlers.TAXII.GetCollection)
			taxii.Get("/collections/{id}/objects", r.handlers.TAXII.GetObjects)
			taxii.Post("/collections/{id}/objects", r.handlers.TAXII.AddObjects)
		})
	}

	return router
}
