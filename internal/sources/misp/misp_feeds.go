package misp

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
	mispSlug = "misp_feeds"
)

// Default public MISP feeds
var defaultMISPFeeds = []MISPFeedConfig{
	{
		Name:    "Botvrij.eu OSINT",
		URL:     "https://www.botvrij.eu/data/feed-osint/",
		Enabled: true,
	},
	// CIRCL OSINT now requires authentication, disabled by default
	// {
	// 	Name:    "CIRCL OSINT",
	// 	URL:     "https://www.circl.lu/doc/misp/feed-osint/",
	// 	Enabled: false,
	// },
}

// MISPFeedConfig represents a MISP feed configuration
type MISPFeedConfig struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// MISPFeedsConnector implements the source connector for MISP feeds
type MISPFeedsConnector struct {
	client   *http.Client
	logger   *logger.Logger
	enabled  bool
	interval time.Duration
	sourceID uuid.UUID
	feeds    []MISPFeedConfig
}

// NewMISPFeedsConnector creates a new MISP feeds connector
func NewMISPFeedsConnector(log *logger.Logger) *MISPFeedsConnector {
	return &MISPFeedsConnector{
		client: &http.Client{
			Timeout: 120 * time.Second, // MISP feeds can be large
		},
		logger:   log.WithComponent("misp-feeds"),
		enabled:  true,
		interval: 12 * time.Hour, // OSINT feeds update less frequently
		feeds:    defaultMISPFeeds,
	}
}

// Slug returns the unique identifier for this source
func (c *MISPFeedsConnector) Slug() string {
	return mispSlug
}

// Name returns the human-readable name of this source
func (c *MISPFeedsConnector) Name() string {
	return "MISP Public Feeds"
}

// Category returns the category of this source
func (c *MISPFeedsConnector) Category() models.SourceCategory {
	return models.SourceCategoryCommunity
}

// IsEnabled returns whether this source is enabled
func (c *MISPFeedsConnector) IsEnabled() bool {
	return c.enabled
}

// SetEnabled sets the enabled state
func (c *MISPFeedsConnector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// UpdateInterval returns how often this source should be updated
func (c *MISPFeedsConnector) UpdateInterval() time.Duration {
	return c.interval
}

// SetSourceID sets the database source ID
func (c *MISPFeedsConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Configure configures the connector with the given config
func (c *MISPFeedsConnector) Configure(cfg sources.ConnectorConfig) error {
	c.enabled = cfg.Enabled
	if cfg.UpdateInterval > 0 {
		c.interval = cfg.UpdateInterval
	}
	return nil
}

// Fetch retrieves indicators from MISP public feeds
func (c *MISPFeedsConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: mispSlug,
		FetchedAt:  start,
	}

	c.logger.Info().Msg("fetching from MISP public feeds")

	var allIndicators []models.RawIndicator

	for _, feed := range c.feeds {
		if !feed.Enabled {
			continue
		}

		indicators, err := c.fetchFeed(ctx, feed)
		if err != nil {
			c.logger.Warn().Err(err).Str("feed", feed.Name).Msg("failed to fetch MISP feed")
			continue
		}

		allIndicators = append(allIndicators, indicators...)
		c.logger.Info().Str("feed", feed.Name).Int("indicators", len(indicators)).Msg("fetched MISP feed")
	}

	result.RawIndicators = allIndicators
	result.TotalFetched = len(allIndicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("total", len(allIndicators)).
		Dur("duration", result.Duration).
		Msg("MISP feeds fetch completed")

	return result, nil
}

// MISPManifest represents the MISP feed manifest
type MISPManifest map[string]MISPEventInfo

// MISPEventInfo contains metadata about an event
type MISPEventInfo struct {
	UUID      string      `json:"uuid"`
	Timestamp interface{} `json:"timestamp"` // Can be string or number
	Date      string      `json:"date"`
	Info      string      `json:"info"`
}

// MISPEvent represents a MISP event
type MISPEvent struct {
	Event struct {
		ID           string          `json:"id"`
		UUID         string          `json:"uuid"`
		Info         string          `json:"info"`
		Date         string          `json:"date"`
		Timestamp    string          `json:"timestamp"`
		ThreatLevel  string          `json:"threat_level_id"`
		Analysis     string          `json:"analysis"`
		OrgName      string          `json:"org_name,omitempty"`
		Attribute    []MISPAttribute `json:"Attribute"`
		Tag          []MISPTag       `json:"Tag,omitempty"`
		Galaxy       []MISPGalaxy    `json:"Galaxy,omitempty"`
	} `json:"Event"`
}

// MISPAttribute represents an IOC attribute
type MISPAttribute struct {
	ID          string    `json:"id"`
	UUID        string    `json:"uuid"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Comment     string    `json:"comment,omitempty"`
	ToIDS       bool      `json:"to_ids"`
	Timestamp   string    `json:"timestamp"`
	Category    string    `json:"category"`
	Tag         []MISPTag `json:"Tag,omitempty"`
}

// MISPTag represents a tag
type MISPTag struct {
	Name   string `json:"name"`
	Colour string `json:"colour,omitempty"`
}

// MISPGalaxy represents MITRE ATT&CK and other taxonomies
type MISPGalaxy struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// fetchFeed fetches a single MISP feed
func (c *MISPFeedsConnector) fetchFeed(ctx context.Context, feed MISPFeedConfig) ([]models.RawIndicator, error) {
	// First fetch the manifest
	manifestURL := feed.URL + "manifest.json"
	manifest, err := c.fetchManifest(ctx, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	var indicators []models.RawIndicator

	// Fetch events (max 50 events per run to avoid rate limits)
	eventCount := 0
	maxEvents := 50

	for eventFile, eventInfo := range manifest {
		if eventCount >= maxEvents {
			break
		}

		// Skip very old events (before 2020) to focus on relevant threats
		if eventInfo.Date != "" {
			eventDate, err := time.Parse("2006-01-02", eventInfo.Date)
			if err == nil && eventDate.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
				continue
			}
		}

		// Event files are named as UUID.json
		eventURL := feed.URL + eventFile + ".json"
		eventIndicators, err := c.fetchEvent(ctx, eventURL, feed.Name)
		if err != nil {
			c.logger.Debug().Err(err).Str("event", eventFile).Msg("failed to fetch event")
			continue
		}

		indicators = append(indicators, eventIndicators...)
		eventCount++

		// Rate limiting - be nice to servers
		time.Sleep(200 * time.Millisecond)
	}

	return indicators, nil
}

// fetchManifest fetches the MISP feed manifest
func (c *MISPFeedsConnector) fetchManifest(ctx context.Context, url string) (MISPManifest, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("manifest returned status %d: %s", resp.StatusCode, string(body))
	}

	var manifest MISPManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	return manifest, nil
}

// fetchEvent fetches a single MISP event
func (c *MISPFeedsConnector) fetchEvent(ctx context.Context, url, feedName string) ([]models.RawIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("event returned status %d", resp.StatusCode)
	}

	var event MISPEvent
	if err := json.NewDecoder(resp.Body).Decode(&event); err != nil {
		return nil, fmt.Errorf("failed to decode event: %w", err)
	}

	return c.parseEvent(event, feedName)
}

// parseEvent converts a MISP event to indicators
func (c *MISPFeedsConnector) parseEvent(mispEvent MISPEvent, feedName string) ([]models.RawIndicator, error) {
	var indicators []models.RawIndicator
	now := time.Now()
	event := mispEvent.Event

	// Parse event date
	eventDate := now
	if event.Date != "" {
		if t, err := time.Parse("2006-01-02", event.Date); err == nil {
			eventDate = t
		}
	}

	// Determine severity from threat level
	severity := models.SeverityMedium
	switch event.ThreatLevel {
	case "1":
		severity = models.SeverityCritical
	case "2":
		severity = models.SeverityHigh
	case "3":
		severity = models.SeverityMedium
	case "4":
		severity = models.SeverityLow
	}

	// Extract event tags
	eventTags := []string{"misp", strings.ToLower(strings.ReplaceAll(feedName, " ", "-"))}
	for _, tag := range event.Tag {
		// Clean up tag name
		tagName := strings.ToLower(tag.Name)
		tagName = strings.ReplaceAll(tagName, ":", "_")
		tagName = strings.ReplaceAll(tagName, " ", "-")
		if len(tagName) <= 50 { // Limit tag length
			eventTags = append(eventTags, tagName)
		}
	}

	// Extract MITRE ATT&CK from galaxies
	var mitreTechniques []string
	for _, galaxy := range event.Galaxy {
		if strings.Contains(strings.ToLower(galaxy.Type), "mitre") {
			// Extract technique IDs from galaxy name
			if strings.Contains(galaxy.Name, "T") {
				mitreTechniques = append(mitreTechniques, galaxy.Name)
			}
		}
	}

	// Process attributes (IOCs)
	for _, attr := range event.Attribute {
		// Skip attributes not marked for IDS
		if !attr.ToIDS {
			continue
		}

		indicatorType := mapMISPTypeToIndicator(attr.Type)
		if indicatorType == "" {
			continue
		}

		// Build attribute tags
		attrTags := make([]string, len(eventTags))
		copy(attrTags, eventTags)
		attrTags = append(attrTags, strings.ToLower(attr.Category))
		for _, tag := range attr.Tag {
			tagName := strings.ToLower(tag.Name)
			if len(tagName) <= 50 {
				attrTags = append(attrTags, tagName)
			}
		}

		// Parse attribute timestamp
		attrTime := eventDate
		if attr.Timestamp != "" {
			if ts, err := parseTimestamp(attr.Timestamp); err == nil {
				attrTime = ts
			}
		}

		// Build description
		description := fmt.Sprintf("MISP: %s", event.Info)
		if attr.Comment != "" {
			description = fmt.Sprintf("%s - %s", description, attr.Comment)
		}

		conf := 0.75 // Default confidence for MISP feeds

		indicator := models.RawIndicator{
			Value:       attr.Value,
			Type:        indicatorType,
			Severity:    severity,
			Description: description,
			Tags:        attrTags,
			FirstSeen:   &attrTime,
			LastSeen:    &now,
			Confidence:  &conf,
			SourceID:    c.Slug(),
			SourceName:  c.Name(),
			RawData: map[string]any{
				"source":           "misp",
				"feed":             feedName,
				"event_uuid":       event.UUID,
				"event_info":       event.Info,
				"attribute_uuid":   attr.UUID,
				"attribute_type":   attr.Type,
				"category":         attr.Category,
				"threat_level":     event.ThreatLevel,
				"mitre_techniques": mitreTechniques,
			},
		}

		indicators = append(indicators, indicator)
	}

	return indicators, nil
}

// mapMISPTypeToIndicator maps MISP attribute types to indicator types
func mapMISPTypeToIndicator(mispType string) models.IndicatorType {
	switch mispType {
	case "domain", "hostname":
		return models.IndicatorTypeDomain
	case "ip-dst", "ip-src", "ip":
		return models.IndicatorTypeIP
	case "url", "link":
		return models.IndicatorTypeURL
	case "md5", "sha1", "sha256", "sha512", "ssdeep", "imphash":
		return models.IndicatorTypeHash
	case "filename":
		return models.IndicatorTypeFilePath
	case "email-src", "email-dst", "email":
		return models.IndicatorTypeEmail
	case "regkey", "regkey|value":
		return models.IndicatorTypeRegistry
	case "vulnerability":
		return models.IndicatorTypeCVE
	case "yara":
		return models.IndicatorTypeYARA
	case "x509-fingerprint-sha256", "x509-fingerprint-sha1", "x509-fingerprint-md5":
		return models.IndicatorTypeCertificate
	case "AS":
		return models.IndicatorTypeASN
	default:
		// Handle composite types
		if strings.Contains(mispType, "|") {
			parts := strings.Split(mispType, "|")
			return mapMISPTypeToIndicator(parts[0])
		}
		return ""
	}
}

// parseTimestamp parses a MISP timestamp (Unix timestamp or RFC3339)
func parseTimestamp(ts string) (time.Time, error) {
	// Try parsing as Unix timestamp
	if len(ts) == 10 {
		var unixTS int64
		if _, err := fmt.Sscanf(ts, "%d", &unixTS); err == nil {
			return time.Unix(unixTS, 0), nil
		}
	}

	// Try parsing as RFC3339
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", ts)
}
