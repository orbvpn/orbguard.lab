package ip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/sources"
	"orbguard-lab/pkg/logger"
)

const (
	abuseIPDBAPIURL = "https://api.abuseipdb.com/api/v2/blacklist"
	abuseIPDBSlug   = "abuseipdb"
)

// AbuseIPDBConnector fetches malicious IPs from AbuseIPDB
type AbuseIPDBConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
	apiKey string
}

// NewAbuseIPDBConnector creates a new AbuseIPDB connector
func NewAbuseIPDBConnector(log *logger.Logger) *AbuseIPDBConnector {
	return &AbuseIPDBConnector{
		BaseConnector: sources.NewBaseConnector(
			abuseIPDBSlug,
			"AbuseIPDB",
			models.SourceCategoryIPRep,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("abuseipdb"),
	}
}

// Configure configures the connector with the given config
func (c *AbuseIPDBConnector) Configure(cfg sources.ConnectorConfig) error {
	if err := c.BaseConnector.Configure(cfg); err != nil {
		return err
	}
	c.apiKey = cfg.APIKey
	return nil
}

// abuseIPDBResponse represents the API response
type abuseIPDBResponse struct {
	Data []abuseIPDBEntry `json:"data"`
}

type abuseIPDBEntry struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	LastReportedAt       string `json:"lastReportedAt"`
}

// Fetch retrieves malicious IPs from AbuseIPDB
func (c *AbuseIPDBConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	if c.apiKey == "" {
		err := fmt.Errorf("AbuseIPDB API key not configured")
		result.Error = err
		c.logger.Warn().Msg("AbuseIPDB API key not configured, skipping")
		return result, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", abuseIPDBAPIURL, nil)
	if err != nil {
		result.Error = err
		return result, err
	}

	// Set headers
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	// Query params - get IPs with confidence score >= 90
	q := req.URL.Query()
	q.Set("confidenceMinimum", "90")
	q.Set("limit", "10000")
	req.URL.RawQuery = q.Encode()

	c.logger.Info().Str("url", abuseIPDBAPIURL).Msg("fetching AbuseIPDB blacklist")

	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("AbuseIPDB returned status %d: %s", resp.StatusCode, string(body))
		result.Error = err
		return result, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		return result, err
	}

	var apiResp abuseIPDBResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		result.Error = fmt.Errorf("failed to parse response: %w", err)
		return result, err
	}

	c.logger.Info().Int("entries", len(apiResp.Data)).Msg("parsing AbuseIPDB entries")

	for _, entry := range apiResp.Data {
		if entry.IPAddress == "" {
			continue
		}

		// Parse last reported time
		var lastSeen *time.Time
		if t, err := time.Parse(time.RFC3339, entry.LastReportedAt); err == nil {
			lastSeen = &t
		}

		// Build tags
		tags := []string{"abuseipdb", "malicious-ip"}
		if entry.CountryCode != "" {
			tags = append(tags, entry.CountryCode)
		}

		// Determine severity based on confidence score
		severity := models.SeverityMedium
		if entry.AbuseConfidenceScore >= 100 {
			severity = models.SeverityCritical
		} else if entry.AbuseConfidenceScore >= 90 {
			severity = models.SeverityHigh
		}

		// Confidence from AbuseIPDB score
		confidence := float64(entry.AbuseConfidenceScore) / 100.0

		result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
			Value:       entry.IPAddress,
			Type:        models.IndicatorTypeIP,
			Severity:    severity,
			Confidence:  &confidence,
			Description: fmt.Sprintf("AbuseIPDB: Confidence %d%% (%s)", entry.AbuseConfidenceScore, entry.CountryCode),
			Tags:        tags,
			LastSeen:    lastSeen,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
			RawData: map[string]any{
				"ip_address":             entry.IPAddress,
				"abuse_confidence_score": entry.AbuseConfidenceScore,
				"country_code":           entry.CountryCode,
				"last_reported_at":       entry.LastReportedAt,
			},
		})
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("entries", len(apiResp.Data)).
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("AbuseIPDB fetch completed")

	return result, nil
}
