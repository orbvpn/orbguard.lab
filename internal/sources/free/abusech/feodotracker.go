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

const (
	feodoTrackerJSONURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
	feodoTrackerSlug    = "feodotracker"
)

// FeodoTrackerConnector fetches botnet C2 IPs from Abuse.ch Feodo Tracker
type FeodoTrackerConnector struct {
	*sources.BaseConnector
	client *http.Client
	logger *logger.Logger
}

// NewFeodoTrackerConnector creates a new FeodoTracker connector
func NewFeodoTrackerConnector(log *logger.Logger) *FeodoTrackerConnector {
	return &FeodoTrackerConnector{
		BaseConnector: sources.NewBaseConnector(
			feodoTrackerSlug,
			"Feodo Tracker",
			models.SourceCategoryAbuseCH,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("feodotracker"),
	}
}

// feodoEntry represents a single entry from the Feodo Tracker JSON feed
type feodoEntry struct {
	IPAddress   string `json:"ip_address"`
	Port        int    `json:"port"`
	Status      string `json:"status"`
	Hostname    string `json:"hostname"`
	ASNumber    int    `json:"as_number"`
	ASName      string `json:"as_name"`
	Country     string `json:"country"`
	FirstSeen   string `json:"first_seen"`
	LastOnline  string `json:"last_online"`
	Malware     string `json:"malware"`
}

// Fetch retrieves botnet C2 IPs from Feodo Tracker JSON feed
func (c *FeodoTrackerConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()

	result := &models.SourceFetchResult{
		SourceID:      uuid.Nil,
		SourceSlug:    c.Slug(),
		FetchedAt:     start,
		RawIndicators: make([]models.RawIndicator, 0),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", feodoTrackerJSONURL, nil)
	if err != nil {
		result.Error = err
		return result, err
	}

	c.logger.Info().Str("url", feodoTrackerJSONURL).Msg("fetching Feodo Tracker JSON feed")

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

	var entries []feodoEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		result.Error = fmt.Errorf("failed to parse JSON: %w", err)
		return result, err
	}

	c.logger.Info().Int("entries", len(entries)).Msg("parsing Feodo Tracker entries")

	for _, entry := range entries {
		if entry.IPAddress == "" {
			continue
		}

		// Parse dates
		var firstSeen, lastSeen *time.Time
		if t, err := time.Parse("2006-01-02 15:04:05", entry.FirstSeen); err == nil {
			firstSeen = &t
		}
		if t, err := time.Parse("2006-01-02", entry.LastOnline); err == nil {
			lastSeen = &t
		}

		// Build tags
		tags := []string{"feodotracker", "botnet", "c2"}
		if entry.Malware != "" {
			tags = append(tags, strings.ToLower(entry.Malware))
		}
		if entry.Country != "" {
			tags = append(tags, strings.ToLower(entry.Country))
		}

		// Determine severity - botnet C2s are always high/critical
		severity := models.SeverityCritical
		if entry.Status != "online" {
			severity = models.SeverityHigh
		}

		// Confidence based on status
		confidence := 0.95
		if entry.Status != "online" {
			confidence = 0.80
		}

		// Build description
		desc := fmt.Sprintf("Feodo Tracker: %s C2", entry.Malware)
		if entry.Status == "online" {
			desc += " (ACTIVE)"
		}

		// Add IP indicator
		result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
			Value:       entry.IPAddress,
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
				"ip_address":  entry.IPAddress,
				"port":        entry.Port,
				"status":      entry.Status,
				"hostname":    entry.Hostname,
				"as_number":   entry.ASNumber,
				"as_name":     entry.ASName,
				"country":     entry.Country,
				"malware":     entry.Malware,
				"first_seen":  entry.FirstSeen,
				"last_online": entry.LastOnline,
			},
		})

		// Add hostname as domain indicator if available
		if entry.Hostname != "" && entry.Hostname != entry.IPAddress {
			domainConfidence := 0.85
			result.RawIndicators = append(result.RawIndicators, models.RawIndicator{
				Value:       strings.ToLower(entry.Hostname),
				Type:        models.IndicatorTypeDomain,
				Severity:    severity,
				Confidence:  &domainConfidence,
				Description: fmt.Sprintf("Feodo Tracker hostname: %s C2", entry.Malware),
				Tags:        append(tags, "hostname"),
				FirstSeen:   firstSeen,
				LastSeen:    lastSeen,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
			})
		}
	}

	result.Success = true
	result.TotalFetched = len(result.RawIndicators)
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("entries", len(entries)).
		Int("indicators", len(result.RawIndicators)).
		Dur("duration", result.Duration).
		Msg("Feodo Tracker fetch completed")

	return result, nil
}
