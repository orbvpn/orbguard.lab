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
	koodousAPIURL = "https://developer.koodous.com"
	koodousSlug   = "koodous"
)

// KoodousConnector fetches Android malware intelligence from Koodous
type KoodousConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
	apiKey string
}

// NewKoodousConnector creates a new Koodous connector
func NewKoodousConnector(log *logger.Logger) *KoodousConnector {
	return &KoodousConnector{
		BaseConnector: sources.NewBaseConnector(
			koodousSlug,
			"Koodous",
			models.SourceCategoryMobile,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("koodous"),
	}
}

// Configure configures the connector with the given config
func (c *KoodousConnector) Configure(cfg sources.ConnectorConfig) error {
	if err := c.BaseConnector.Configure(cfg); err != nil {
		return err
	}
	c.apiKey = cfg.APIKey
	return nil
}

// koodousAPKResponse represents the APK search response
type koodousAPKResponse struct {
	Count   int           `json:"count"`
	Results []koodousAPK  `json:"results"`
	Next    string        `json:"next"`
}

type koodousAPK struct {
	SHA256      string   `json:"sha256"`
	SHA1        string   `json:"sha1"`
	MD5         string   `json:"md5"`
	App         string   `json:"app"`
	PackageName string   `json:"package_name"`
	Size        int64    `json:"size"`
	CreatedOn   string   `json:"created_on"`
	Analyzed    string   `json:"analyzed"`
	Rating      int      `json:"rating"`
	Detected    bool     `json:"detected"`
	Tags        []string `json:"tags"`
	Corrupted   bool     `json:"corrupted"`
}

// Fetch retrieves Android malware from Koodous
func (c *KoodousConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	if c.apiKey == "" {
		err := fmt.Errorf("Koodous API key not configured")
		result.Error = err
		c.logger.Warn().Msg("Koodous API key not configured, skipping")
		return result, err
	}

	// Fetch detected Android malware
	indicators, err := c.fetchDetectedMalware(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
			c.logger.Info().Msg("Koodous API access denied - check API key")
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
		Msg("Koodous fetch completed")

	return result, nil
}

// fetchDetectedMalware fetches recently detected Android malware
func (c *KoodousConnector) fetchDetectedMalware(ctx context.Context) ([]models.RawIndicator, error) {
	// Search for detected APKs
	url := fmt.Sprintf("%s/apks?search=detected:true&ordering=-analyzed&page_size=100", koodousAPIURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Token %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	c.logger.Info().Msg("fetching Koodous detected Android malware")

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
		return nil, fmt.Errorf("Koodous returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp koodousAPKResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	c.logger.Info().Int("count", len(apiResp.Results)).Msg("parsing Koodous APKs")

	var indicators []models.RawIndicator

	for _, apk := range apiResp.Results {
		if apk.Corrupted || apk.SHA256 == "" {
			continue
		}

		// Parse timestamp
		var firstSeen *time.Time
		if t, err := time.Parse(time.RFC3339, apk.CreatedOn); err == nil {
			firstSeen = &t
		}
		var lastSeen *time.Time
		if t, err := time.Parse(time.RFC3339, apk.Analyzed); err == nil {
			lastSeen = &t
		}

		// Build tags
		tags := []string{"koodous", "android", "apk", "mobile-malware"}
		tags = append(tags, apk.Tags...)
		if apk.PackageName != "" {
			tags = append(tags, "pkg:"+apk.PackageName)
		}

		// Determine severity based on rating and detection
		severity := models.SeverityMedium
		if apk.Detected {
			severity = models.SeverityHigh
			if apk.Rating < -5 {
				severity = models.SeverityCritical
			}
		}

		// Confidence based on detection status
		confidence := 0.75
		if apk.Detected {
			confidence = 0.90
		}

		// Build description
		desc := fmt.Sprintf("Koodous: %s", apk.App)
		if apk.PackageName != "" {
			desc += fmt.Sprintf(" (%s)", apk.PackageName)
		}
		if apk.Detected {
			desc += " [DETECTED]"
		}

		// Add SHA256 indicator
		indicators = append(indicators, models.RawIndicator{
			Value:       strings.ToLower(apk.SHA256),
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
				"sha256":       apk.SHA256,
				"sha1":         apk.SHA1,
				"md5":          apk.MD5,
				"app_name":     apk.App,
				"package_name": apk.PackageName,
				"size":         apk.Size,
				"rating":       apk.Rating,
				"detected":     apk.Detected,
				"tags":         apk.Tags,
			},
		})

		// Also add MD5 for broader matching
		if apk.MD5 != "" {
			md5Confidence := 0.70
			indicators = append(indicators, models.RawIndicator{
				Value:       strings.ToLower(apk.MD5),
				Type:        models.IndicatorTypeHash,
				Severity:    severity,
				Confidence:  &md5Confidence,
				Description: fmt.Sprintf("Koodous MD5: %s", apk.App),
				Tags:        append(tags, "md5"),
				FirstSeen:   firstSeen,
				LastSeen:    lastSeen,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
			})
		}
	}

	return indicators, nil
}

// LookupAPK looks up an APK by its SHA256 hash
func (c *KoodousConnector) LookupAPK(ctx context.Context, sha256 string) (*koodousAPK, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("Koodous API key not configured")
	}

	url := fmt.Sprintf("%s/apks/%s", koodousAPIURL, sha256)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Token %s", c.apiKey))
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
		return nil, fmt.Errorf("Koodous returned status %d: %s", resp.StatusCode, string(body))
	}

	var apk koodousAPK
	if err := json.Unmarshal(body, &apk); err != nil {
		return nil, err
	}

	return &apk, nil
}
