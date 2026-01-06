package phishing

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/sources"
	"orbguard-lab/pkg/logger"
)

const (
	openPhishFeedURL = "https://openphish.com/feed.txt"
	openPhishSlug    = "openphish"
)

// OpenPhishConnector implements the source connector for OpenPhish
type OpenPhishConnector struct {
	client   *http.Client
	logger   *logger.Logger
	enabled  bool
	interval time.Duration
	sourceID uuid.UUID
}

// NewOpenPhishConnector creates a new OpenPhish connector
func NewOpenPhishConnector(log *logger.Logger) *OpenPhishConnector {
	return &OpenPhishConnector{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger:   log.WithComponent("openphish"),
		enabled:  true,
		interval: 4 * time.Hour,
	}
}

// Slug returns the unique identifier for this source
func (c *OpenPhishConnector) Slug() string {
	return openPhishSlug
}

// Name returns the human-readable name of this source
func (c *OpenPhishConnector) Name() string {
	return "OpenPhish"
}

// Category returns the category of this source
func (c *OpenPhishConnector) Category() models.SourceCategory {
	return models.SourceCategoryPhishing
}

// IsEnabled returns whether this source is enabled
func (c *OpenPhishConnector) IsEnabled() bool {
	return c.enabled
}

// SetEnabled sets the enabled state
func (c *OpenPhishConnector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// UpdateInterval returns how often this source should be updated
func (c *OpenPhishConnector) UpdateInterval() time.Duration {
	return c.interval
}

// SetSourceID sets the database source ID
func (c *OpenPhishConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Configure configures the connector with the given config
func (c *OpenPhishConnector) Configure(cfg sources.ConnectorConfig) error {
	c.enabled = cfg.Enabled
	if cfg.UpdateInterval > 0 {
		c.interval = cfg.UpdateInterval
	}
	return nil
}

// Fetch retrieves phishing URLs from OpenPhish
func (c *OpenPhishConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: openPhishSlug,
		FetchedAt:  start,
	}

	c.logger.Info().Msg("fetching from OpenPhish feed")

	req, err := http.NewRequestWithContext(ctx, "GET", openPhishFeedURL, nil)
	if err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, fmt.Errorf("failed to fetch OpenPhish: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Errorf("OpenPhish returned status %d: %s", resp.StatusCode, string(body))
		result.Success = false
		result.Duration = time.Since(start)
		return result, result.Error
	}

	indicators, err := c.parsePhishingURLs(resp.Body)
	if err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, err
	}

	result.RawIndicators = indicators
	result.TotalFetched = len(indicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("total", len(indicators)).
		Dur("duration", result.Duration).
		Msg("OpenPhish fetch completed")

	return result, nil
}

// parsePhishingURLs parses the feed and extracts URLs and domains
func (c *OpenPhishConnector) parsePhishingURLs(reader io.Reader) ([]models.RawIndicator, error) {
	var indicators []models.RawIndicator
	now := time.Now()
	conf := 0.75 // OpenPhish confidence

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the URL
		parsedURL, err := url.Parse(line)
		if err != nil {
			c.logger.Warn().Str("url", line).Err(err).Msg("failed to parse URL")
			continue
		}

		// Create URL indicator
		urlIndicator := models.RawIndicator{
			Value:       line,
			Type:        models.IndicatorTypeURL,
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Phishing URL targeting: %s", detectTarget(parsedURL)),
			Tags:        []string{"openphish", "phishing"},
			FirstSeen:   &now,
			LastSeen:    &now,
			Confidence:  &conf,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
			RawData: map[string]any{
				"source": "openphish",
				"host":   parsedURL.Host,
				"path":   parsedURL.Path,
			},
		}

		// Add brand tag if detected
		if target := detectTarget(parsedURL); target != "" {
			urlIndicator.Tags = append(urlIndicator.Tags, strings.ToLower(target))
		}

		indicators = append(indicators, urlIndicator)

		// Extract domain indicator
		if parsedURL.Host != "" {
			domain := parsedURL.Hostname()
			domainIndicator := models.RawIndicator{
				Value:       domain,
				Type:        models.IndicatorTypeDomain,
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Phishing domain from OpenPhish"),
				Tags:        []string{"openphish", "phishing", "phishing-domain"},
				FirstSeen:   &now,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":   "openphish",
					"from_url": line,
				},
			}
			indicators = append(indicators, domainIndicator)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading feed: %w", err)
	}

	return indicators, nil
}

// detectTarget attempts to identify the targeted brand/service from the URL
func detectTarget(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	path := strings.ToLower(u.Path)
	combined := host + path

	// Common phishing targets
	targets := map[string][]string{
		"microsoft":  {"microsoft", "office365", "outlook", "onedrive", "sharepoint", "teams", "azure"},
		"google":     {"google", "gmail", "docs.google", "drive.google"},
		"apple":      {"apple", "icloud", "appleid"},
		"paypal":     {"paypal"},
		"amazon":     {"amazon", "aws"},
		"facebook":   {"facebook", "fb.com", "meta"},
		"instagram":  {"instagram"},
		"linkedin":   {"linkedin"},
		"netflix":    {"netflix"},
		"dropbox":    {"dropbox"},
		"dhl":        {"dhl"},
		"fedex":      {"fedex"},
		"ups":        {"ups"},
		"usps":       {"usps"},
		"bank":       {"bank", "banking", "secure", "login"},
		"crypto":     {"coinbase", "binance", "metamask", "wallet"},
	}

	for target, keywords := range targets {
		for _, keyword := range keywords {
			if strings.Contains(combined, keyword) {
				return target
			}
		}
	}

	return ""
}
