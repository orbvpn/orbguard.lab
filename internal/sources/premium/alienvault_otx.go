package premium

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
	alienVaultOTXAPIURL = "https://otx.alienvault.com/api/v1"
	alienVaultOTXSlug   = "alienvault_otx"
)

// AlienVaultOTXConnector fetches threat intelligence from AlienVault OTX
type AlienVaultOTXConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
	apiKey string
}

// NewAlienVaultOTXConnector creates a new AlienVault OTX connector
func NewAlienVaultOTXConnector(log *logger.Logger) *AlienVaultOTXConnector {
	return &AlienVaultOTXConnector{
		BaseConnector: sources.NewBaseConnector(
			alienVaultOTXSlug,
			"AlienVault OTX",
			models.SourceCategoryPremium,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
		logger: log.WithComponent("alienvault-otx"),
	}
}

// Configure configures the connector with the given config
func (c *AlienVaultOTXConnector) Configure(cfg sources.ConnectorConfig) error {
	if err := c.BaseConnector.Configure(cfg); err != nil {
		return err
	}
	c.apiKey = cfg.APIKey
	return nil
}

// otxPulseResponse represents the pulse feed response
type otxPulseResponse struct {
	Results []otxPulse `json:"results"`
	Count   int        `json:"count"`
	Next    string     `json:"next"`
}

type otxPulse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	AuthorName  string         `json:"author_name"`
	Created     string         `json:"created"`
	Modified    string         `json:"modified"`
	Indicators  []otxIndicator `json:"indicators"`
	Tags        []string       `json:"tags"`
	TLP         string         `json:"tlp"`
	Adversary   string         `json:"adversary"`
	Industries  []string       `json:"industries"`
}

type otxIndicator struct {
	ID          any    `json:"id"` // Can be string or number
	Indicator   string `json:"indicator"`
	Type        string `json:"type"`
	Created     string `json:"created"`
	Description string `json:"description"`
	Title       string `json:"title"`
	Role        string `json:"role"`
}

// Fetch retrieves threat intelligence from AlienVault OTX
func (c *AlienVaultOTXConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	if c.apiKey == "" {
		err := fmt.Errorf("AlienVault OTX API key not configured")
		result.Error = err
		c.logger.Warn().Msg("AlienVault OTX API key not configured, skipping")
		return result, err
	}

	// Fetch subscribed pulses (modified in last 7 days)
	indicators, err := c.fetchSubscribedPulses(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
			c.logger.Info().Msg("AlienVault OTX API access denied - check API key")
			result.Success = true
			result.Duration = time.Since(start)
			return result, nil
		}
		result.Error = err
		return result, err
	}

	result.RawIndicators = indicators
	result.Success = true
	result.TotalFetched = len(indicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("indicators", len(indicators)).
		Dur("duration", result.Duration).
		Msg("AlienVault OTX fetch completed")

	return result, nil
}

// fetchSubscribedPulses fetches pulses the user is subscribed to
func (c *AlienVaultOTXConnector) fetchSubscribedPulses(ctx context.Context) ([]models.RawIndicator, error) {
	// Get pulses modified in the last 7 days
	modifiedSince := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	url := fmt.Sprintf("%s/pulses/subscribed?modified_since=%s&limit=50", alienVaultOTXAPIURL, modifiedSince)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-OTX-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	c.logger.Info().Str("modified_since", modifiedSince).Msg("fetching AlienVault OTX subscribed pulses")

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
		return nil, fmt.Errorf("AlienVault OTX returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp otxPulseResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	c.logger.Info().Int("pulses", len(apiResp.Results)).Msg("parsing OTX pulses")

	var indicators []models.RawIndicator

	for _, pulse := range apiResp.Results {
		// Parse pulse timestamps
		var pulseCreated *time.Time
		if t, err := time.Parse(time.RFC3339, pulse.Created); err == nil {
			pulseCreated = &t
		}

		// Build base tags from pulse
		baseTags := []string{"alienvault-otx", "pulse"}
		baseTags = append(baseTags, pulse.Tags...)
		if pulse.Adversary != "" {
			baseTags = append(baseTags, strings.ToLower(strings.ReplaceAll(pulse.Adversary, " ", "-")))
		}

		for _, ind := range pulse.Indicators {
			// Map OTX indicator type to our type
			indType := mapOTXType(ind.Type)
			if indType == "" {
				continue // Skip unsupported types
			}

			// Parse indicator timestamp
			var firstSeen *time.Time
			if t, err := time.Parse(time.RFC3339, ind.Created); err == nil {
				firstSeen = &t
			} else {
				firstSeen = pulseCreated
			}

			// Build tags
			tags := make([]string, len(baseTags))
			copy(tags, baseTags)
			tags = append(tags, strings.ToLower(ind.Type))

			// Determine severity based on TLP and indicator role
			severity := models.SeverityMedium
			if pulse.TLP == "red" {
				severity = models.SeverityCritical
			} else if pulse.TLP == "amber" {
				severity = models.SeverityHigh
			}
			if ind.Role == "c2" || strings.Contains(strings.ToLower(ind.Description), "c2") {
				severity = models.SeverityCritical
			}

			confidence := 0.80 // OTX community-sourced

			// Build description
			desc := fmt.Sprintf("OTX Pulse: %s", pulse.Name)
			if ind.Description != "" {
				desc += fmt.Sprintf(" - %s", ind.Description)
			}

			indicators = append(indicators, models.RawIndicator{
				Value:       normalizeIndicator(ind.Indicator, indType),
				Type:        indType,
				Severity:    severity,
				Confidence:  &confidence,
				Description: desc,
				Tags:        tags,
				FirstSeen:   firstSeen,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"pulse_id":    pulse.ID,
					"pulse_name":  pulse.Name,
					"author":      pulse.AuthorName,
					"adversary":   pulse.Adversary,
					"tlp":         pulse.TLP,
					"industries":  pulse.Industries,
					"ind_type":    ind.Type,
					"ind_role":    ind.Role,
				},
			})
		}
	}

	return indicators, nil
}

// mapOTXType maps OTX indicator types to our indicator types
func mapOTXType(otxType string) models.IndicatorType {
	switch strings.ToLower(otxType) {
	case "ipv4", "ipv6":
		return models.IndicatorTypeIP
	case "domain", "hostname":
		return models.IndicatorTypeDomain
	case "url", "uri":
		return models.IndicatorTypeURL
	case "filehash-md5", "filehash-sha1", "filehash-sha256":
		return models.IndicatorTypeHash
	case "email":
		return models.IndicatorTypeEmail
	case "cve":
		return models.IndicatorTypeCVE
	default:
		return ""
	}
}

// normalizeIndicator normalizes indicator values
func normalizeIndicator(value string, indType models.IndicatorType) string {
	switch indType {
	case models.IndicatorTypeDomain, models.IndicatorTypeEmail:
		return strings.ToLower(value)
	case models.IndicatorTypeHash:
		return strings.ToLower(value)
	default:
		return value
	}
}
