package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/sources"
	"orbguard-lab/pkg/logger"
)

const (
	urlscanAPIURL  = "https://urlscan.io/api/v1"
	urlscanSlug    = "urlscan"
	urlscanFreeQPS = 2 // Free tier: 2 requests per second max
)

// URLScanConnector implements the source connector for URLScan.io
type URLScanConnector struct {
	client   *http.Client
	logger   *logger.Logger
	enabled  bool
	interval time.Duration
	sourceID uuid.UUID
	apiKey   string // Optional, increases rate limits
}

// NewURLScanConnector creates a new URLScan.io connector
func NewURLScanConnector(log *logger.Logger) *URLScanConnector {
	return &URLScanConnector{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger:   log.WithComponent("urlscan"),
		enabled:  true,
		interval: 6 * time.Hour,
	}
}

// Slug returns the unique identifier for this source
func (c *URLScanConnector) Slug() string {
	return urlscanSlug
}

// Name returns the human-readable name of this source
func (c *URLScanConnector) Name() string {
	return "URLScan.io"
}

// Category returns the category of this source
func (c *URLScanConnector) Category() models.SourceCategory {
	return models.SourceCategoryPhishing
}

// IsEnabled returns whether this source is enabled
func (c *URLScanConnector) IsEnabled() bool {
	return c.enabled
}

// SetEnabled sets the enabled state
func (c *URLScanConnector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// UpdateInterval returns how often this source should be updated
func (c *URLScanConnector) UpdateInterval() time.Duration {
	return c.interval
}

// SetSourceID sets the database source ID
func (c *URLScanConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Configure configures the connector with the given config
func (c *URLScanConnector) Configure(cfg sources.ConnectorConfig) error {
	c.enabled = cfg.Enabled
	if cfg.UpdateInterval > 0 {
		c.interval = cfg.UpdateInterval
	}
	if cfg.APIKey != "" {
		c.apiKey = cfg.APIKey
	}
	return nil
}

// Fetch retrieves malicious URL data from URLScan.io
func (c *URLScanConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: urlscanSlug,
		FetchedAt:  start,
	}

	c.logger.Info().Msg("fetching from URLScan.io")

	var allIndicators []models.RawIndicator

	// Search for malicious URLs from recent scans
	// Note: Free tier has limited search capabilities, using basic queries
	searches := []struct {
		query    string
		category string
	}{
		{"task.method:automatic", "recent"},           // Recent automatic scans
		{"page.server:nginx", "web-servers"},          // Common web server (for coverage)
		{"filename:malware", "malware"},               // Files with malware in name
		{"page.title:login", "potential-phishing"},    // Login pages (potential phishing)
		{"page.title:verify", "potential-phishing"},   // Verify pages
	}

	for _, search := range searches {
		indicators, err := c.searchURLs(ctx, search.query, search.category, 100)
		if err != nil {
			c.logger.Warn().Err(err).Str("query", search.query).Msg("search failed")
			continue
		}
		allIndicators = append(allIndicators, indicators...)

		// Rate limiting - be nice to free API
		time.Sleep(500 * time.Millisecond)
	}

	if len(allIndicators) == 0 {
		c.logger.Warn().Msg("no indicators fetched from URLScan.io")
	}

	result.RawIndicators = allIndicators
	result.TotalFetched = len(allIndicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("total", len(allIndicators)).
		Dur("duration", result.Duration).
		Msg("URLScan.io fetch completed")

	return result, nil
}

// URLScanSearchResponse represents the search API response
type URLScanSearchResponse struct {
	Results []URLScanResult `json:"results"`
	Total   int             `json:"total"`
}

// URLScanResult represents a single scan result
type URLScanResult struct {
	Task struct {
		UUID       string    `json:"uuid"`
		URL        string    `json:"url"`
		Domain     string    `json:"domain"`
		Time       time.Time `json:"time"`
		Visibility string    `json:"visibility"`
	} `json:"task"`
	Page struct {
		URL      string      `json:"url"`
		Domain   string      `json:"domain"`
		IP       string      `json:"ip"`
		Country  string      `json:"country"`
		ASN      string      `json:"asn"`
		ASNName  string      `json:"asnname"`
		Server   string      `json:"server"`
		MIMEType string      `json:"mimeType"`
		Title    string      `json:"title"`
		Status   interface{} `json:"status"` // Can be int or string
	} `json:"page"`
	Verdicts struct {
		Overall struct {
			Malicious bool     `json:"malicious"`
			Score     int      `json:"score"`
			Brands    []string `json:"brands"`
			Tags      []string `json:"tags"`
		} `json:"overall"`
		URLScan struct {
			Malicious bool     `json:"malicious"`
			Score     int      `json:"score"`
			Brands    []string `json:"brands"`
			Tags      []string `json:"tags"`
		} `json:"urlscan"`
		Community struct {
			Malicious  bool `json:"malicious"`
			Score      int  `json:"score"`
			VotesTotal int  `json:"votesTotal"`
		} `json:"community"`
	} `json:"verdicts,omitempty"`
	Stats struct {
		ResourcesTotal     int `json:"resourcesTotal"`
		MaliciousRequests  int `json:"maliciousRequests"`
		IPsTotal           int `json:"ipsTotal"`
		UniqueCountries    int `json:"uniqueCountries"`
		SecureRequests     int `json:"secureRequests"`
		InsecureRequests   int `json:"insecureRequests"`
	} `json:"stats,omitempty"`
}

// searchURLs searches URLScan.io for malicious URLs
func (c *URLScanConnector) searchURLs(ctx context.Context, query, category string, size int) ([]models.RawIndicator, error) {
	searchURL := fmt.Sprintf("%s/search/?q=%s&size=%d",
		urlscanAPIURL,
		url.QueryEscape(query),
		size,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search URLScan.io: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("URLScan.io returned status %d: %s", resp.StatusCode, string(body))
	}

	var searchResp URLScanSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseResults(searchResp.Results, category)
}

// parseResults converts URLScan results to indicators
func (c *URLScanConnector) parseResults(results []URLScanResult, category string) ([]models.RawIndicator, error) {
	var indicators []models.RawIndicator
	now := time.Now()

	for _, r := range results {
		// Skip if no URL
		if r.Task.URL == "" && r.Page.URL == "" {
			continue
		}

		scanURL := r.Task.URL
		if scanURL == "" {
			scanURL = r.Page.URL
		}

		// Determine severity based on verdict
		severity := models.SeverityMedium
		if r.Verdicts.Overall.Malicious || r.Verdicts.URLScan.Malicious {
			severity = models.SeverityHigh
		}
		if r.Verdicts.Overall.Score >= 80 {
			severity = models.SeverityCritical
		}

		// Calculate confidence
		conf := 0.70
		if r.Verdicts.Overall.Malicious && r.Verdicts.URLScan.Malicious {
			conf = 0.90
		} else if r.Verdicts.Overall.Malicious || r.Verdicts.URLScan.Malicious {
			conf = 0.80
		}

		// Build tags
		tags := []string{"urlscan", category}
		if len(r.Verdicts.Overall.Tags) > 0 {
			tags = append(tags, r.Verdicts.Overall.Tags...)
		}
		if len(r.Verdicts.Overall.Brands) > 0 {
			for _, brand := range r.Verdicts.Overall.Brands {
				tags = append(tags, "brand:"+brand)
			}
		}

		// Build description
		description := fmt.Sprintf("URLScan.io: %s scan", category)
		if r.Page.Title != "" {
			description = fmt.Sprintf("%s - %s", description, r.Page.Title)
		}

		scanTime := r.Task.Time
		if scanTime.IsZero() {
			scanTime = now
		}

		// Create URL indicator
		urlIndicator := models.RawIndicator{
			Value:       scanURL,
			Type:        models.IndicatorTypeURL,
			Severity:    severity,
			Description: description,
			Tags:        tags,
			FirstSeen:   &scanTime,
			LastSeen:    &now,
			Confidence:  &conf,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
			RawData: map[string]any{
				"source":      "urlscan",
				"scan_uuid":   r.Task.UUID,
				"category":    category,
				"verdicts":    r.Verdicts,
				"page":        r.Page,
				"stats":       r.Stats,
			},
		}
		indicators = append(indicators, urlIndicator)

		// Extract domain indicator
		domain := r.Page.Domain
		if domain == "" {
			domain = r.Task.Domain
		}
		if domain != "" {
			domainIndicator := models.RawIndicator{
				Value:       domain,
				Type:        models.IndicatorTypeDomain,
				Severity:    severity,
				Description: fmt.Sprintf("Domain from URLScan.io %s scan", category),
				Tags:        append(tags, "phishing-domain"),
				FirstSeen:   &scanTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":    "urlscan",
					"scan_uuid": r.Task.UUID,
					"from_url":  scanURL,
					"country":   r.Page.Country,
					"asn":       r.Page.ASN,
					"asn_name":  r.Page.ASNName,
				},
			}
			indicators = append(indicators, domainIndicator)
		}

		// Extract IP indicator if available
		if r.Page.IP != "" {
			ipIndicator := models.RawIndicator{
				Value:       r.Page.IP,
				Type:        models.IndicatorTypeIP,
				Severity:    severity,
				Description: fmt.Sprintf("IP hosting malicious URL from URLScan.io: %s", domain),
				Tags:        []string{"urlscan", category, "hosting-ip"},
				FirstSeen:   &scanTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":    "urlscan",
					"scan_uuid": r.Task.UUID,
					"from_url":  scanURL,
					"domain":    domain,
					"country":   r.Page.Country,
					"asn":       r.Page.ASN,
					"asn_name":  r.Page.ASNName,
				},
			}
			indicators = append(indicators, ipIndicator)
		}
	}

	return indicators, nil
}
