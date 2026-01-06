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

const (
	sslBlacklistCSVURL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
	sslBlacklistSlug   = "sslblacklist"
)

// SSLBlacklistConnector fetches malicious SSL certificates from Abuse.ch SSL Blacklist
type SSLBlacklistConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
}

// NewSSLBlacklistConnector creates a new SSL Blacklist connector
func NewSSLBlacklistConnector(log *logger.Logger) *SSLBlacklistConnector {
	return &SSLBlacklistConnector{
		BaseConnector: sources.NewBaseConnector(
			sslBlacklistSlug,
			"SSL Blacklist",
			models.SourceCategoryAbuseCH,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("sslblacklist"),
	}
}

// Fetch retrieves malicious IPs with SSL certificates from SSL Blacklist
func (c *SSLBlacklistConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", sslBlacklistCSVURL, nil)
	if err != nil {
		result.Error = err
		return result, err
	}

	c.logger.Info().Str("url", sslBlacklistCSVURL).Msg("fetching SSL Blacklist CSV feed")

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
		c.logger.Warn().Msg("no data in SSL Blacklist feed")
		result.Success = true
		result.Duration = time.Since(start)
		return result, nil
	}

	// Parse CSV data
	// Format: Firstseen,DstIP,DstPort
	reader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := reader.ReadAll()
	if err != nil {
		result.Error = err
		return result, err
	}

	c.logger.Info().Int("records", len(records)).Msg("parsing SSL Blacklist CSV")

	for _, record := range records {
		if len(record) < 3 {
			continue
		}

		firstSeenStr := record[0]
		dstIP := record[1]
		dstPort := record[2]

		// Skip header
		if dstIP == "DstIP" {
			continue
		}

		// Parse date
		var firstSeen *time.Time
		if t, err := time.Parse("2006-01-02 15:04:05", firstSeenStr); err == nil {
			firstSeen = &t
		}

		// Build tags
		tags := []string{"sslblacklist", "ssl", "c2", "botnet"}

		// High severity for SSL-based C2
		severity := models.SeverityHigh
		confidence := 0.90

		// Add IP indicator
		result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
			Value:       dstIP,
			Type:        models.IndicatorTypeIP,
			Severity:    severity,
			Confidence:  &confidence,
			Description: fmt.Sprintf("SSL Blacklist: Malicious SSL certificate (port %s)", dstPort),
			Tags:        tags,
			FirstSeen:   firstSeen,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
			RawData: map[string]any{
				"dst_ip":     dstIP,
				"dst_port":   dstPort,
				"first_seen": firstSeenStr,
			},
		})
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("records", len(records)).
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("SSL Blacklist fetch completed")

	return result, nil
}
