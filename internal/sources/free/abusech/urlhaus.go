package abusech

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
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
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("urlhaus"),
	}
}

// Fetch retrieves URLs from URLhaus CSV feed (public, no auth required)
func (c *URLhausConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil, // Will be set by caller
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	// Use public CSV feed (no auth required)
	csvURL := "https://urlhaus.abuse.ch/downloads/csv_recent/"

	req, err := http.NewRequestWithContext(ctx, "GET", csvURL, nil)
	if err != nil {
		result.Error = err
		return result, err
	}

	c.logger.Info().Str("url", csvURL).Msg("fetching URLhaus CSV feed")

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

	// Parse CSV (skip comment lines starting with #)
	scanner := bufio.NewScanner(resp.Body)
	var csvLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") && len(line) > 0 {
			csvLines = append(csvLines, line)
		}
	}

	if len(csvLines) == 0 {
		c.logger.Warn().Msg("no data in URLhaus feed")
		result.Success = true
		result.Duration = time.Since(start)
		return result, nil
	}

	// Parse CSV data
	// Format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
	reader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := reader.ReadAll()
	if err != nil {
		result.Error = err
		return result, err
	}

	c.logger.Info().Int("records", len(records)).Msg("parsing URLhaus CSV")

	for _, record := range records {
		if len(record) < 9 {
			continue
		}

		// Parse fields
		// id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
		urlID := record[0]
		dateAdded := record[1]
		urlValue := record[2]
		urlStatus := record[3]
		threat := record[5]
		tagsStr := record[6]
		urlhausLink := record[7]
		reporter := record[8]

		// Determine severity based on threat type
		severity := models.SeverityMedium
		switch strings.ToLower(threat) {
		case "malware_download":
			severity = models.SeverityHigh
		case "phishing":
			severity = models.SeverityMedium
		}

		// Parse date
		var firstSeen *time.Time
		if t, err := time.Parse("2006-01-02 15:04:05", dateAdded); err == nil {
			firstSeen = &t
		}

		// Parse tags
		tags := []string{"urlhaus", threat}
		if tagsStr != "" {
			for _, tag := range strings.Split(tagsStr, ",") {
				tags = append(tags, strings.TrimSpace(tag))
			}
		}

		// Add URL indicator
		urlConfidence := 0.85
		result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
			Value:       urlValue,
			Type:        models.IndicatorTypeURL,
			Severity:    severity,
			Confidence:  &urlConfidence,
			Description: fmt.Sprintf("URLhaus: %s - %s", threat, urlStatus),
			Tags:        tags,
			FirstSeen:   firstSeen,
			RawData: map[string]any{
				"urlhaus_id":   urlID,
				"url_status":   urlStatus,
				"reporter":     reporter,
				"urlhaus_link": urlhausLink,
			},
		})

		// Extract domain/IP from URL for additional indicator
		host := extractDomain(urlValue)
		if host != "" {
			extractedConfidence := 0.80
			if isIPAddress(host) {
				result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
					Value:       host,
					Type:        models.IndicatorTypeIP,
					Severity:    severity,
					Confidence:  &extractedConfidence,
					Description: fmt.Sprintf("IP from URLhaus: %s", threat),
					Tags:        append(tags, "extracted"),
					FirstSeen:   firstSeen,
				})
			} else {
				result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
					Value:       host,
					Type:        models.IndicatorTypeDomain,
					Severity:    severity,
					Confidence:  &extractedConfidence,
					Description: fmt.Sprintf("Domain from URLhaus: %s", threat),
					Tags:        append(tags, "extracted"),
					FirstSeen:   firstSeen,
				})
			}
		}
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("records", len(records)).
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("fetch completed")

	return result, nil
}

// extractDomain extracts the domain/IP from a URL
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
