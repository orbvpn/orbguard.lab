package abusech

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

// URLhausConnector fetches data from Abuse.ch URLhaus
type URLhausConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
}

// NewURLhausConnector creates a new URLhaus connector
func NewURLhausConnector(log *logger.Logger) *URLhausConnector {
	return &URLhausConnector{
		BaseConnector: sources.NewBaseConnector(
			"urlhaus",
			"URLhaus",
			models.SourceCategoryAbuseCH,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.WithComponent("urlhaus"),
	}
}

// URLhausResponse represents the API response
type URLhausResponse struct {
	QueryStatus string           `json:"query_status"`
	URLs        []URLhausURL     `json:"urls"`
}

// URLhausURL represents a single URL entry
type URLhausURL struct {
	ID           string   `json:"id"`
	URL          string   `json:"url"`
	URLStatus    string   `json:"url_status"`
	DateAdded    string   `json:"dateadded"`
	Threat       string   `json:"threat"`
	Tags         []string `json:"tags"`
	URLhausLink  string   `json:"urlhaus_link"`
	Reporter     string   `json:"reporter"`
	LastOnline   string   `json:"last_online"`
}

// Fetch retrieves URLs from URLhaus
func (c *URLhausConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	cfg := c.Config()
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:     uuid.Nil, // Will be set by caller
		SourceSlug:   c.Slug(),
		FetchedAt:    start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	// Fetch recent URLs
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = "https://urlhaus-api.abuse.ch/v1"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL+"/urls/recent/", strings.NewReader(""))
	if err != nil {
		result.Error = err
		return result, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		result.Error = err
		return result, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		return result, err
	}

	var urlhausResp URLhausResponse
	if err := json.Unmarshal(body, &urlhausResp); err != nil {
		result.Error = err
		return result, err
	}

	if urlhausResp.QueryStatus != "ok" {
		err = fmt.Errorf("API error: %s", urlhausResp.QueryStatus)
		result.Error = err
		return result, err
	}

	// Convert to raw indicators
	for _, u := range urlhausResp.URLs {
		// Determine severity based on threat type
		severity := models.SeverityMedium
		switch strings.ToLower(u.Threat) {
		case "malware_download":
			severity = models.SeverityHigh
		case "phishing":
			severity = models.SeverityMedium
		}

		// Parse date
		var firstSeen *time.Time
		if t, err := time.Parse("2006-01-02 15:04:05", u.DateAdded); err == nil {
			firstSeen = &t
		}

		// Add URL indicator
		tags := append(u.Tags, "urlhaus", u.Threat)
		result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
			Value:       u.URL,
			Type:        models.IndicatorTypeURL,
			Severity:    severity,
			Description: fmt.Sprintf("URLhaus: %s - %s", u.Threat, u.Reporter),
			Tags:        tags,
			FirstSeen:   firstSeen,
			RawData: map[string]any{
				"urlhaus_id":   u.ID,
				"url_status":   u.URLStatus,
				"reporter":     u.Reporter,
				"urlhaus_link": u.URLhausLink,
			},
		})

		// Extract domain from URL for additional indicator
		domain := extractDomain(u.URL)
		if domain != "" && !isIPAddress(domain) {
			result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
				Value:       domain,
				Type:        models.IndicatorTypeDomain,
				Severity:    severity,
				Description: fmt.Sprintf("Domain from URLhaus: %s", u.Threat),
				Tags:        append(tags, "extracted"),
				FirstSeen:   firstSeen,
			})
		}
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("urls", len(urlhausResp.URLs)).
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("fetch completed")

	return result, nil
}

// extractDomain extracts the domain from a URL
func extractDomain(rawURL string) string {
	// Remove protocol
	url := rawURL
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}

	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return strings.ToLower(url)
}

// isIPAddress checks if a string looks like an IP address
func isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
