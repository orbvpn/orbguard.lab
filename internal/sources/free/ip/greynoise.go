package ip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/sources"
	"orbguard-lab/pkg/logger"
)

const (
	greyNoiseGNQLURL      = "https://api.greynoise.io/v2/experimental/gnql" // Enterprise only
	greyNoiseCommunityURL = "https://api.greynoise.io/v3/community"         // Free tier
	greyNoiseSlug         = "greynoise"
)

// GreyNoiseConnector fetches malicious IPs from GreyNoise
type GreyNoiseConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
	apiKey string
}

// NewGreyNoiseConnector creates a new GreyNoise connector
func NewGreyNoiseConnector(log *logger.Logger) *GreyNoiseConnector {
	return &GreyNoiseConnector{
		BaseConnector: sources.NewBaseConnector(
			greyNoiseSlug,
			"GreyNoise",
			models.SourceCategoryIPRep,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("greynoise"),
	}
}

// Configure configures the connector with the given config
func (c *GreyNoiseConnector) Configure(cfg sources.ConnectorConfig) error {
	if err := c.BaseConnector.Configure(cfg); err != nil {
		return err
	}
	c.apiKey = cfg.APIKey
	return nil
}

// greyNoiseResponse represents the GNQL API response
type greyNoiseResponse struct {
	Complete bool              `json:"complete"`
	Count    int               `json:"count"`
	Data     []greyNoiseEntry  `json:"data"`
	Message  string            `json:"message"`
	Query    string            `json:"query"`
	Scroll   string            `json:"scroll"`
}

type greyNoiseEntry struct {
	IP               string   `json:"ip"`
	Seen             bool     `json:"seen"`
	Classification   string   `json:"classification"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	ActorName        string   `json:"actor"`
	Tags             []string `json:"tags"`
	CVE              []string `json:"cve"`
	Bot              bool     `json:"bot"`
	VPN              bool     `json:"vpn"`
	VPNService       string   `json:"vpn_service"`
	Metadata         greyNoiseMetadata `json:"metadata"`
}

type greyNoiseMetadata struct {
	ASN          string `json:"asn"`
	City         string `json:"city"`
	Country      string `json:"country"`
	CountryCode  string `json:"country_code"`
	Organization string `json:"organization"`
	OS           string `json:"os"`
	RDNS         string `json:"rdns"`
}

// CommunityLookupResult represents a single IP lookup from the Community API
type CommunityLookupResult struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	RIOT           bool   `json:"riot"`
	Classification string `json:"classification"` // benign, malicious, unknown
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

// LookupIP checks a single IP using the GreyNoise Community API (free tier)
func (c *GreyNoiseConnector) LookupIP(ctx context.Context, ipAddr string) (*CommunityLookupResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("GreyNoise API key not configured")
	}

	url := fmt.Sprintf("%s/%s", greyNoiseCommunityURL, ipAddr)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GreyNoise returned status %d: %s", resp.StatusCode, string(body))
	}

	var result CommunityLookupResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Fetch retrieves malicious IPs from GreyNoise using GNQL (requires Enterprise API)
// Note: This method requires an Enterprise API key. Community API keys will fail.
// Use LookupIP() for single IP lookups with Community API.
func (c *GreyNoiseConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	if c.apiKey == "" {
		err := fmt.Errorf("GreyNoise API key not configured")
		result.Error = err
		c.logger.Warn().Msg("GreyNoise API key not configured, skipping")
		return result, err
	}

	// Query for malicious IPs seen in the last 7 days
	query := "classification:malicious last_seen:7d"

	req, err := http.NewRequestWithContext(ctx, "GET", greyNoiseGNQLURL, nil)
	if err != nil {
		result.Error = err
		return result, err
	}

	// Set headers
	req.Header.Set("key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	// Query params
	q := req.URL.Query()
	q.Set("query", query)
	q.Set("size", "10000")
	req.URL.RawQuery = q.Encode()

	c.logger.Info().Str("query", query).Msg("fetching GreyNoise malicious IPs")

	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("GreyNoise returned status %d: %s", resp.StatusCode, string(body))
		result.Error = err
		return result, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		return result, err
	}

	var apiResp greyNoiseResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		result.Error = fmt.Errorf("failed to parse response: %w", err)
		return result, err
	}

	c.logger.Info().Int("count", apiResp.Count).Msg("parsing GreyNoise entries")

	for _, entry := range apiResp.Data {
		if entry.IP == "" {
			continue
		}

		// Parse dates
		var firstSeen, lastSeen *time.Time
		if t, err := time.Parse("2006-01-02", entry.FirstSeen); err == nil {
			firstSeen = &t
		}
		if t, err := time.Parse("2006-01-02", entry.LastSeen); err == nil {
			lastSeen = &t
		}

		// Build tags
		tags := []string{"greynoise", "scanner"}
		tags = append(tags, entry.Tags...)
		if entry.Bot {
			tags = append(tags, "bot")
		}
		if entry.Metadata.CountryCode != "" {
			tags = append(tags, strings.ToLower(entry.Metadata.CountryCode))
		}
		if entry.ActorName != "" {
			tags = append(tags, strings.ToLower(strings.ReplaceAll(entry.ActorName, " ", "-")))
		}

		// Determine severity based on classification and CVEs
		severity := models.SeverityMedium
		if entry.Classification == "malicious" {
			severity = models.SeverityHigh
			if len(entry.CVE) > 0 {
				severity = models.SeverityCritical
			}
		}

		// High confidence for GreyNoise data
		confidence := 0.85

		// Build description
		desc := fmt.Sprintf("GreyNoise: %s", entry.Classification)
		if entry.ActorName != "" {
			desc += fmt.Sprintf(" (Actor: %s)", entry.ActorName)
		}
		if len(entry.CVE) > 0 {
			desc += fmt.Sprintf(" [CVEs: %s]", strings.Join(entry.CVE, ", "))
		}

		result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
			Value:       entry.IP,
			Type:        models.IndicatorTypeIP,
			Severity:    severity,
			Confidence:  &confidence,
			Description: desc,
			Tags:        tags,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
			RawData: map[string]any{
				"ip":             entry.IP,
				"classification": entry.Classification,
				"actor":          entry.ActorName,
				"tags":           entry.Tags,
				"cve":            entry.CVE,
				"bot":            entry.Bot,
				"vpn":            entry.VPN,
				"vpn_service":    entry.VPNService,
				"asn":            entry.Metadata.ASN,
				"country":        entry.Metadata.Country,
				"organization":   entry.Metadata.Organization,
				"os":             entry.Metadata.OS,
				"rdns":           entry.Metadata.RDNS,
			},
		})
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("count", apiResp.Count).
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("GreyNoise fetch completed")

	return result, nil
}
