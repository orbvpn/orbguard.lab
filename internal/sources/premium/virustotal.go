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
	virusTotalAPIURL = "https://www.virustotal.com/api/v3"
	virusTotalSlug   = "virustotal"
)

// VirusTotalConnector fetches malicious indicators from VirusTotal
type VirusTotalConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
	apiKey string
}

// NewVirusTotalConnector creates a new VirusTotal connector
func NewVirusTotalConnector(log *logger.Logger) *VirusTotalConnector {
	return &VirusTotalConnector{
		BaseConnector: sources.NewBaseConnector(
			virusTotalSlug,
			"VirusTotal",
			models.SourceCategoryPremium,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("virustotal"),
	}
}

// Configure configures the connector with the given config
func (c *VirusTotalConnector) Configure(cfg sources.ConnectorConfig) error {
	if err := c.BaseConnector.Configure(cfg); err != nil {
		return err
	}
	c.apiKey = cfg.APIKey
	return nil
}

// vtPopularThreatResponse represents the popular threat actors response
type vtPopularThreatResponse struct {
	Data []vtThreatActor `json:"data"`
}

type vtThreatActor struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes vtThreatAttributes `json:"attributes"`
}

type vtThreatAttributes struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	TargetedCountries []string `json:"targeted_countries"`
	LastModificationDate int64  `json:"last_modification_date"`
}

// vtFileFeedResponse represents file feed response
type vtFileFeedResponse struct {
	Data []vtFileEntry `json:"data"`
}

type vtFileEntry struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"`
	Attributes vtFileAttributes `json:"attributes"`
}

type vtFileAttributes struct {
	SHA256               string            `json:"sha256"`
	SHA1                 string            `json:"sha1"`
	MD5                  string            `json:"md5"`
	MeaningfulName       string            `json:"meaningful_name"`
	TypeDescription      string            `json:"type_description"`
	FirstSubmissionDate  int64             `json:"first_submission_date"`
	LastAnalysisDate     int64             `json:"last_analysis_date"`
	LastAnalysisStats    vtAnalysisStats   `json:"last_analysis_stats"`
	PopularThreatClassification vtThreatClass `json:"popular_threat_classification"`
	Tags                 []string          `json:"tags"`
}

type vtAnalysisStats struct {
	Malicious   int `json:"malicious"`
	Suspicious  int `json:"suspicious"`
	Undetected  int `json:"undetected"`
	Harmless    int `json:"harmless"`
}

type vtThreatClass struct {
	SuggestedThreatLabel string              `json:"suggested_threat_label"`
	PopularThreatCategory []vtThreatCategory `json:"popular_threat_category"`
}

type vtThreatCategory struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Fetch retrieves malicious indicators from VirusTotal
// Note: Free API has rate limits (4 requests/min). Enterprise API required for feeds.
func (c *VirusTotalConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	if c.apiKey == "" {
		err := fmt.Errorf("VirusTotal API key not configured")
		result.Error = err
		c.logger.Warn().Msg("VirusTotal API key not configured, skipping")
		return result, err
	}

	// Try to fetch hunting livehunt notifications (requires premium)
	// If that fails, gracefully return success with 0 indicators
	indicators, err := c.fetchPopularFiles(ctx)
	if err != nil {
		// Check if it's a rate limit or premium feature error
		if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "403") {
			c.logger.Info().Msg("VirusTotal API rate limited or premium feature required - skipping bulk fetch")
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
		Msg("VirusTotal fetch completed")

	return result, nil
}

// fetchPopularFiles fetches recently submitted malicious files
func (c *VirusTotalConnector) fetchPopularFiles(ctx context.Context) ([]models.RawIndicator, error) {
	// Use the search endpoint to find recent malicious files
	// This works with free API but has rate limits
	url := fmt.Sprintf("%s/intelligence/search?query=p:5+ type:file&limit=100", virusTotalAPIURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	c.logger.Info().Msg("fetching VirusTotal malicious files")

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
		return nil, fmt.Errorf("VirusTotal returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp vtFileFeedResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var indicators []models.RawIndicator

	for _, file := range apiResp.Data {
		attrs := file.Attributes

		// Skip if not enough detections
		if attrs.LastAnalysisStats.Malicious < 5 {
			continue
		}

		// Parse timestamps
		var firstSeen, lastSeen *time.Time
		if attrs.FirstSubmissionDate > 0 {
			t := time.Unix(attrs.FirstSubmissionDate, 0)
			firstSeen = &t
		}
		if attrs.LastAnalysisDate > 0 {
			t := time.Unix(attrs.LastAnalysisDate, 0)
			lastSeen = &t
		}

		// Build tags
		tags := []string{"virustotal", "malware"}
		tags = append(tags, attrs.Tags...)
		if attrs.PopularThreatClassification.SuggestedThreatLabel != "" {
			tags = append(tags, strings.ToLower(attrs.PopularThreatClassification.SuggestedThreatLabel))
		}

		// Determine severity based on detection ratio
		totalEngines := attrs.LastAnalysisStats.Malicious + attrs.LastAnalysisStats.Suspicious +
			attrs.LastAnalysisStats.Undetected + attrs.LastAnalysisStats.Harmless
		detectionRatio := float64(attrs.LastAnalysisStats.Malicious) / float64(totalEngines)

		severity := models.SeverityMedium
		if detectionRatio > 0.7 {
			severity = models.SeverityCritical
		} else if detectionRatio > 0.4 {
			severity = models.SeverityHigh
		}

		confidence := detectionRatio

		// Add SHA256 indicator
		if attrs.SHA256 != "" {
			desc := fmt.Sprintf("VirusTotal: %d/%d detections",
				attrs.LastAnalysisStats.Malicious, totalEngines)
			if attrs.PopularThreatClassification.SuggestedThreatLabel != "" {
				desc += fmt.Sprintf(" (%s)", attrs.PopularThreatClassification.SuggestedThreatLabel)
			}

			indicators = append(indicators, models.RawIndicator{
				Value:       strings.ToLower(attrs.SHA256),
				Type:        models.IndicatorTypeHash,
				Severity:    severity,
				Confidence:  &confidence,
				Description: desc,
				Tags:        append(tags, "sha256"),
				FirstSeen:   firstSeen,
				LastSeen:    lastSeen,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"sha256":          attrs.SHA256,
					"sha1":            attrs.SHA1,
					"md5":             attrs.MD5,
					"file_name":       attrs.MeaningfulName,
					"type":            attrs.TypeDescription,
					"malicious":       attrs.LastAnalysisStats.Malicious,
					"total_engines":   totalEngines,
					"detection_ratio": detectionRatio,
					"threat_label":    attrs.PopularThreatClassification.SuggestedThreatLabel,
				},
			})
		}
	}

	return indicators, nil
}

// LookupHash checks a single hash against VirusTotal
func (c *VirusTotalConnector) LookupHash(ctx context.Context, hash string) (*vtFileAttributes, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not configured")
	}

	url := fmt.Sprintf("%s/files/%s", virusTotalAPIURL, hash)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", c.apiKey)
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
		return nil, fmt.Errorf("VirusTotal returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Attributes vtFileAttributes `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result.Data.Attributes, nil
}
