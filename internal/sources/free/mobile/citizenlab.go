package mobile

import (
	"bufio"
	"context"
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

// Known Citizen Lab indicator files
var citizenLabFiles = []struct {
	URL         string
	Type        models.IndicatorType
	Tags        []string
	Description string
}{
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/2016/pegasus-domains.txt",
		Type:        models.IndicatorTypeDomain,
		Tags:        []string{"pegasus", "nso-group", "spyware", "mobile"},
		Description: "Pegasus C2 domain",
	},
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/2018/predator/domains.txt",
		Type:        models.IndicatorTypeDomain,
		Tags:        []string{"predator", "cytrox", "spyware", "mobile"},
		Description: "Predator C2 domain",
	},
	{
		URL:         "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/2021/pegasus/domains.txt",
		Type:        models.IndicatorTypeDomain,
		Tags:        []string{"pegasus", "nso-group", "spyware", "mobile"},
		Description: "Pegasus C2 domain (2021)",
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
		indicators, err := c.fetchFile(ctx, file.URL, file.Type, file.Tags, file.Description)
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
			"pegasus-domains.txt",
			"domains.txt",
			"indicators.txt",
		}
		for _, path := range paths {
			url := strings.TrimSuffix(baseURL, "/") + "/" + path
			indicators, err := c.fetchFile(ctx, url, models.IndicatorTypeDomain, []string{"citizenlab", "mobile"}, "Citizen Lab indicator")
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

// fetchFile fetches a single indicator file
func (c *CitizenLabConnector) fetchFile(ctx context.Context, url string, iocType models.IndicatorType, tags []string, description string) ([]models.RawIndicator, error) {
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

	// Parse line by line
	indicators := make([]models.RawIndicator, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Some files might have CSV format
		parts := strings.Split(line, ",")
		value := strings.TrimSpace(parts[0])

		if value == "" {
			continue
		}

		// Determine severity based on tags
		severity := models.SeverityCritical
		if containsAny(tags, "pegasus", "predator", "hermit") {
			severity = models.SeverityCritical
		}

		confidence := 0.95 // Citizen Lab has high reliability

		indicators = append(indicators, models.RawIndicator{
			Value:       value,
			Type:        iocType,
			Severity:    severity,
			Description: description,
			Tags:        tags,
			Confidence:  &confidence,
		})
	}

	return indicators, nil
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
		})
	}

	return indicators, nil
}
