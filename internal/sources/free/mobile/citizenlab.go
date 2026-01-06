package mobile

import (
	"bufio"
	"context"
	"encoding/csv"
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

// CitizenLabConnector fetches data from Citizen Lab's GitHub repository
type CitizenLabConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
}

// NewCitizenLabConnector creates a new Citizen Lab connector
func NewCitizenLabConnector(log *logger.Logger) *CitizenLabConnector {
	return &CitizenLabConnector{
		BaseConnector: sources.NewBaseConnector(
			"citizenlab",
			"Citizen Lab",
			models.SourceCategoryMobile,
			models.SourceTypeGithub,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("citizenlab"),
	}
}

// Known Citizen Lab indicator files (CSV format with columns: uuid,event_id,category,type,value,comment,to_ids,date)
var citizenLabFiles = []struct {
	URL         string
	Tags        []string
	Description string
	Format      string // "csv" or "text"
}{
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/201608_NSO_Group/iocs.csv",
		Tags:        []string{"pegasus", "nso-group", "spyware", "mobile"},
		Description: "NSO Group Pegasus indicators",
		Format:      "csv",
	},
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/201810_TheKingdomCameToCanada/iocs.csv",
		Tags:        []string{"nso-group", "spyware", "saudi", "mobile"},
		Description: "Saudi-linked NSO Group indicators",
		Format:      "csv",
	},
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/202006_DarkBasin/iocs.csv",
		Tags:        []string{"dark-basin", "hack-for-hire", "phishing"},
		Description: "Dark Basin hack-for-hire indicators",
		Format:      "csv",
	},
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/201909_MissingLink/iocs.csv",
		Tags:        []string{"missing-link", "mobile-exploit", "tibet"},
		Description: "Missing Link mobile exploit indicators",
		Format:      "csv",
	},
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/201712_Cyberbit/iocs.csv",
		Tags:        []string{"cyberbit", "spyware", "surveillance"},
		Description: "Cyberbit spyware indicators",
		Format:      "csv",
	},
}

// Fetch retrieves indicators from Citizen Lab's GitHub
func (c *CitizenLabConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	for _, file := range citizenLabFiles {
		var indicators []models.RawIndicator
		var err error

		if file.Format == "csv" {
			indicators, err = c.fetchCSVFile(ctx, file.URL, file.Tags, file.Description)
		} else {
			indicators, err = c.fetchTextFile(ctx, file.URL, file.Tags, file.Description)
		}

		if err != nil {
			c.logger.Warn().Err(err).Str("url", file.URL).Msg("failed to fetch file")
			continue
		}
		result.RawIndicators = append(result.RawIndicators, indicators...)
	}

	// Also try to fetch from custom GitHub URLs if configured
	cfg := c.Config()
	for _, baseURL := range cfg.GithubURLs {
		// Try known paths under the base URL
		paths := []string{
			"iocs.csv",
			"domains.txt",
			"indicators.txt",
		}
		for _, path := range paths {
			url := strings.TrimSuffix(baseURL, "/") + "/" + path
			var indicators []models.RawIndicator
			var err error
			if strings.HasSuffix(path, ".csv") {
				indicators, err = c.fetchCSVFile(ctx, url, []string{"citizenlab", "mobile"}, "Citizen Lab indicator")
			} else {
				indicators, err = c.fetchTextFile(ctx, url, []string{"citizenlab", "mobile"}, "Citizen Lab indicator")
			}
			if err != nil {
				continue // Silently skip non-existent files
			}
			result.RawIndicators = append(result.RawIndicators, indicators...)
		}
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("fetch completed")

	return result, nil
}

// fetchCSVFile fetches and parses a CSV indicator file
// CSV format: uuid,event_id,category,type,value,comment,to_ids,date
func (c *CitizenLabConnector) fetchCSVFile(ctx context.Context, url string, tags []string, description string) ([]models.RawIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	indicators := make([]models.RawIndicator, 0)
	confidence := 0.95 // Citizen Lab has high reliability

	// Skip header row if present
	startRow := 0
	if len(records) > 0 && (records[0][0] == "uuid" || records[0][0] == "UUID") {
		startRow = 1
	}

	for _, record := range records[startRow:] {
		if len(record) < 5 {
			continue
		}

		// CSV columns: uuid,event_id,category,type,value,comment,to_ids,date
		iocTypeStr := strings.TrimSpace(record[3])
		value := strings.TrimSpace(record[4])

		if value == "" {
			continue
		}

		// Map CSV type to our indicator type
		iocType := mapCSVType(iocTypeStr)
		if iocType == "" {
			continue // Skip unknown types
		}

		// Determine severity based on tags
		severity := models.SeverityHigh
		if containsAny(tags, "pegasus", "predator", "nso-group") {
			severity = models.SeverityCritical
		}

		// Build description with comment if available
		desc := description
		if len(record) > 5 && record[5] != "" {
			desc = fmt.Sprintf("%s - %s", description, strings.TrimSpace(record[5]))
		}

		indicators = append(indicators, models.RawIndicator{
			Value:       value,
			Type:        iocType,
			Severity:    severity,
			Description: desc,
			Tags:        tags,
			Confidence:  &confidence,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
		})
	}

	return indicators, nil
}

// fetchTextFile fetches a plain text indicator file (one indicator per line)
func (c *CitizenLabConnector) fetchTextFile(ctx context.Context, url string, tags []string, description string) ([]models.RawIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	indicators := make([]models.RawIndicator, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	confidence := 0.95 // Citizen Lab has high reliability

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Determine severity based on tags
		severity := models.SeverityHigh
		if containsAny(tags, "pegasus", "predator", "nso-group") {
			severity = models.SeverityCritical
		}

		indicators = append(indicators, models.RawIndicator{
			Value:       line,
			Type:        models.IndicatorTypeDomain, // Default to domain for text files
			Severity:    severity,
			Description: description,
			Tags:        tags,
			Confidence:  &confidence,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
		})
	}

	return indicators, nil
}

// mapCSVType maps Citizen Lab CSV type column to our indicator type
func mapCSVType(csvType string) models.IndicatorType {
	csvType = strings.ToLower(csvType)
	switch {
	case strings.Contains(csvType, "domain"):
		return models.IndicatorTypeDomain
	case strings.Contains(csvType, "ip-dst") || strings.Contains(csvType, "ip-src") || csvType == "ip":
		return models.IndicatorTypeIP
	case strings.Contains(csvType, "url"):
		return models.IndicatorTypeURL
	case strings.Contains(csvType, "md5") || strings.Contains(csvType, "sha1") || strings.Contains(csvType, "sha256"):
		return models.IndicatorTypeHash
	case strings.Contains(csvType, "email"):
		return models.IndicatorTypeEmail
	case strings.Contains(csvType, "filename") || strings.Contains(csvType, "filepath"):
		return models.IndicatorTypeFilePath
	default:
		// Return empty for unknown types - they'll be skipped
		return ""
	}
}

// containsAny checks if slice contains any of the given values
func containsAny(slice []string, values ...string) bool {
	for _, s := range slice {
		for _, v := range values {
			if strings.EqualFold(s, v) {
				return true
			}
		}
	}
	return false
}

// AmnestyMVTConnector fetches data from Amnesty Tech's MVT indicators
type AmnestyMVTConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
}

// NewAmnestyMVTConnector creates a new Amnesty MVT connector
func NewAmnestyMVTConnector(log *logger.Logger) *AmnestyMVTConnector {
	return &AmnestyMVTConnector{
		BaseConnector: sources.NewBaseConnector(
			"amnesty_mvt",
			"Amnesty MVT",
			models.SourceCategoryMobile,
			models.SourceTypeGithub,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("amnesty-mvt"),
	}
}

// Known MVT indicator files
var amnestyFiles = []struct {
	URL         string
	Type        models.IndicatorType
	Tags        []string
	Description string
}{
	{
		URL:         "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2",
		Type:        models.IndicatorTypeDomain, // We'll parse STIX
		Tags:        []string{"pegasus", "nso-group", "spyware", "mobile", "amnesty"},
		Description: "Pegasus indicator from Amnesty",
	},
	{
		URL:         "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt",
		Type:        models.IndicatorTypeDomain,
		Tags:        []string{"pegasus", "nso-group", "spyware", "mobile", "amnesty"},
		Description: "Pegasus C2 domain",
	},
	{
		URL:         "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/files.txt",
		Type:        models.IndicatorTypeFilePath,
		Tags:        []string{"pegasus", "nso-group", "spyware", "ios", "amnesty"},
		Description: "Pegasus iOS file path",
	},
	{
		URL:         "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/processes.txt",
		Type:        models.IndicatorTypeProcess,
		Tags:        []string{"pegasus", "nso-group", "spyware", "ios", "amnesty"},
		Description: "Pegasus iOS process name",
	},
}

// Fetch retrieves indicators from Amnesty's GitHub
func (c *AmnestyMVTConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	for _, file := range amnestyFiles {
		if strings.HasSuffix(file.URL, ".stix2") {
			// Skip STIX files for now (needs STIX parser)
			continue
		}

		indicators, err := c.fetchTextFile(ctx, file.URL, file.Type, file.Tags, file.Description)
		if err != nil {
			c.logger.Warn().Err(err).Str("url", file.URL).Msg("failed to fetch file")
			continue
		}
		result.RawIndicators = append(result.RawIndicators, indicators...)
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("fetch completed")

	return result, nil
}

// fetchTextFile fetches a plain text indicator file
func (c *AmnestyMVTConnector) fetchTextFile(ctx context.Context, url string, iocType models.IndicatorType, tags []string, description string) ([]models.RawIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	indicators := make([]models.RawIndicator, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		confidence := 0.95

		indicators = append(indicators, models.RawIndicator{
			Value:       line,
			Type:        iocType,
			Severity:    models.SeverityCritical,
			Description: description,
			Tags:        tags,
			Confidence:  &confidence,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
		})
	}

	return indicators, nil
}
