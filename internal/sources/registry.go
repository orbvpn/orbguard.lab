package sources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"orbguard-lab/internal/config"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// Registry manages all source connectors
type Registry struct {
	connectors map[string]Connector
	mu         sync.RWMutex
	logger     *logger.Logger
}

// NewRegistry creates a new connector registry
func NewRegistry(log *logger.Logger) *Registry {
	return &Registry{
		connectors: make(map[string]Connector),
		logger:     log.WithComponent("source-registry"),
	}
}

// Register registers a connector
func (r *Registry) Register(connector Connector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	slug := connector.Slug()
	if _, exists := r.connectors[slug]; exists {
		return fmt.Errorf("connector already registered: %s", slug)
	}

	r.connectors[slug] = connector
	r.logger.Info().
		Str("slug", slug).
		Str("name", connector.Name()).
		Str("category", string(connector.Category())).
		Msg("registered connector")

	return nil
}

// Get returns a connector by slug
func (r *Registry) Get(slug string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	conn, ok := r.connectors[slug]
	return conn, ok
}

// List returns all registered connectors
func (r *Registry) List() []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conns := make([]Connector, 0, len(r.connectors))
	for _, conn := range r.connectors {
		conns = append(conns, conn)
	}
	return conns
}

// ListEnabled returns all enabled connectors
func (r *Registry) ListEnabled() []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conns := make([]Connector, 0)
	for _, conn := range r.connectors {
		if conn.IsEnabled() {
			conns = append(conns, conn)
		}
	}
	return conns
}

// ListByCategory returns connectors by category
func (r *Registry) ListByCategory(category models.SourceCategory) []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conns := make([]Connector, 0)
	for _, conn := range r.connectors {
		if conn.Category() == category {
			conns = append(conns, conn)
		}
	}
	return conns
}

// Count returns the number of registered connectors
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.connectors)
}

// CountEnabled returns the number of enabled connectors
func (r *Registry) CountEnabled() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, conn := range r.connectors {
		if conn.IsEnabled() {
			count++
		}
	}
	return count
}

// Configure configures a connector by slug
func (r *Registry) Configure(slug string, cfg ConnectorConfig) error {
	r.mu.RLock()
	conn, ok := r.connectors[slug]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("connector not found: %s", slug)
	}

	return conn.Configure(cfg)
}

// ConfigureFromSourcesConfig applies configuration from config file
func (r *Registry) ConfigureFromSourcesConfig(cfg config.SourcesConfig) {
	configs := map[string]config.SourceConfig{
		"urlhaus":            cfg.URLhaus,
		"threatfox":          cfg.ThreatFox,
		"malwarebazaar":      cfg.MalwareBazaar,
		"feodotracker":       cfg.FeodoTracker,
		"sslblacklist":       cfg.SSLBlacklist,
		"openphish":          cfg.OpenPhish,
		"phishtank":          cfg.PhishTank,
		"google_safebrowsing": cfg.GoogleSafeBrowsing,
		"abuseipdb":          cfg.AbuseIPDB,
		"greynoise":          cfg.GreyNoise,
		"citizenlab":         cfg.CitizenLab,
		"amnesty_mvt":        cfg.AmnestyMVT,
		"koodous":            cfg.Koodous,
		"alienvault_otx":     cfg.AlienVaultOTX,
		"virustotal":         cfg.VirusTotal,
	}

	for slug, srcCfg := range configs {
		connCfg := ConnectorConfig{
			Enabled:        srcCfg.Enabled,
			UpdateInterval: srcCfg.UpdateInterval,
			APIURL:         srcCfg.APIURL,
			FeedURL:        srcCfg.FeedURL,
			GithubURLs:     srcCfg.GithubURLs,
			APIKey:         srcCfg.APIKey,
			Timeout:        30 * time.Second,
		}

		if err := r.Configure(slug, connCfg); err != nil {
			r.logger.Debug().Str("slug", slug).Msg("connector not registered, skipping config")
		} else {
			r.logger.Debug().Str("slug", slug).Bool("enabled", srcCfg.Enabled).Msg("configured connector")
		}
	}
}

// Fetch fetches from a specific connector
func (r *Registry) Fetch(ctx context.Context, slug string) (*models.SourceFetchResult, error) {
	conn, ok := r.Get(slug)
	if !ok {
		return nil, fmt.Errorf("connector not found: %s", slug)
	}

	if !conn.IsEnabled() {
		return nil, fmt.Errorf("connector is disabled: %s", slug)
	}

	return conn.Fetch(ctx)
}

// FetchAll fetches from all enabled connectors
func (r *Registry) FetchAll(ctx context.Context) ([]*models.SourceFetchResult, []error) {
	connectors := r.ListEnabled()
	results := make([]*models.SourceFetchResult, 0, len(connectors))
	errors := make([]error, 0)

	for _, conn := range connectors {
		result, err := conn.Fetch(ctx)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", conn.Slug(), err))
			continue
		}
		results = append(results, result)
	}

	return results, errors
}

// Stats returns registry statistics
type RegistryStats struct {
	TotalConnectors   int            `json:"total_connectors"`
	EnabledConnectors int            `json:"enabled_connectors"`
	ByCategory        map[string]int `json:"by_category"`
}

// Stats returns registry statistics
func (r *Registry) Stats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{
		TotalConnectors:   len(r.connectors),
		EnabledConnectors: 0,
		ByCategory:        make(map[string]int),
	}

	for _, conn := range r.connectors {
		if conn.IsEnabled() {
			stats.EnabledConnectors++
		}
		cat := string(conn.Category())
		stats.ByCategory[cat]++
	}

	return stats
}
