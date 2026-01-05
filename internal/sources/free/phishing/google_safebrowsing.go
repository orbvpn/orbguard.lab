package phishing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/sources"
	"orbguard-lab/pkg/logger"
)

const (
	safeBrowsingSlug   = "google_safebrowsing"
	safeBrowsingAPIURL = "https://safebrowsing.googleapis.com/v4"
)

// ThreatType represents Google Safe Browsing threat types
type ThreatType string

const (
	ThreatTypeMalware       ThreatType = "MALWARE"
	ThreatTypeSocialEng     ThreatType = "SOCIAL_ENGINEERING"
	ThreatTypeUnwantedSW    ThreatType = "UNWANTED_SOFTWARE"
	ThreatTypePotentialHarm ThreatType = "POTENTIALLY_HARMFUL_APPLICATION"
)

// PlatformType represents platform types for Safe Browsing
type PlatformType string

const (
	PlatformAnyPlatform PlatformType = "ANY_PLATFORM"
	PlatformWindows     PlatformType = "WINDOWS"
	PlatformLinux       PlatformType = "LINUX"
	PlatformAndroid     PlatformType = "ANDROID"
	PlatformOSX         PlatformType = "OSX"
	PlatformIOS         PlatformType = "IOS"
	PlatformAllPlatforms PlatformType = "ALL_PLATFORMS"
)

// ThreatEntryType represents threat entry types
type ThreatEntryType string

const (
	ThreatEntryURL ThreatEntryType = "URL"
	ThreatEntryIP  ThreatEntryType = "IP_RANGE"
)

// SafeBrowsingConnector implements the source connector for Google Safe Browsing API v4
type SafeBrowsingConnector struct {
	*sources.BaseConnector
	client   *http.Client
	logger   *logger.Logger
	apiKey   string
	sourceID uuid.UUID
}

// NewSafeBrowsingConnector creates a new Google Safe Browsing connector
func NewSafeBrowsingConnector(log *logger.Logger) *SafeBrowsingConnector {
	return &SafeBrowsingConnector{
		BaseConnector: sources.NewBaseConnector(
			safeBrowsingSlug,
			"Google Safe Browsing",
			models.SourceCategoryPhishing,
			models.SourceTypeAPI,
		),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: log.WithComponent("google-safebrowsing"),
	}
}

// Configure configures the connector with the given config
func (c *SafeBrowsingConnector) Configure(cfg sources.ConnectorConfig) error {
	if err := c.BaseConnector.Configure(cfg); err != nil {
		return err
	}
	c.apiKey = cfg.APIKey
	return nil
}

// SetSourceID sets the database source ID
func (c *SafeBrowsingConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Name returns the human-readable name
func (c *SafeBrowsingConnector) Name() string {
	return "Google Safe Browsing"
}

// Category returns the source category
func (c *SafeBrowsingConnector) Category() models.SourceCategory {
	return models.SourceCategoryPhishing
}

// Fetch retrieves threat information from Google Safe Browsing
// Note: This connector is primarily designed for real-time URL lookups via LookupURLs().
// The Fetch method returns metadata about the connector's capabilities.
func (c *SafeBrowsingConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: safeBrowsingSlug,
		FetchedAt:  start,
	}

	if c.apiKey == "" {
		result.Error = fmt.Errorf("Google Safe Browsing API key not configured")
		result.Success = false
		result.Duration = time.Since(start)
		return result, result.Error
	}

	c.logger.Info().Msg("Google Safe Browsing connector active - use LookupURLs() for real-time checks")

	// Create metadata indicators representing our threat detection capabilities
	// Google Safe Browsing is primarily a lookup service, not a feed
	now := time.Now()
	conf := 0.90

	indicators := []models.RawIndicator{
		{
			Value:       "google_safebrowsing:MALWARE",
			Type:        models.IndicatorTypeHash,
			Severity:    models.SeverityHigh,
			Description: "Google Safe Browsing MALWARE detection capability active",
			Tags:        []string{"google-safebrowsing", "malware", "capability"},
			FirstSeen:   &now,
			LastSeen:    &now,
			Confidence:  &conf,
			RawData: map[string]any{
				"source":      "google_safebrowsing",
				"threat_type": "MALWARE",
				"status":      "active",
				"api_version": "v4",
			},
		},
		{
			Value:       "google_safebrowsing:SOCIAL_ENGINEERING",
			Type:        models.IndicatorTypeHash,
			Severity:    models.SeverityHigh,
			Description: "Google Safe Browsing PHISHING/SOCIAL_ENGINEERING detection capability active",
			Tags:        []string{"google-safebrowsing", "phishing", "social-engineering", "capability"},
			FirstSeen:   &now,
			LastSeen:    &now,
			Confidence:  &conf,
			RawData: map[string]any{
				"source":      "google_safebrowsing",
				"threat_type": "SOCIAL_ENGINEERING",
				"status":      "active",
				"api_version": "v4",
			},
		},
		{
			Value:       "google_safebrowsing:UNWANTED_SOFTWARE",
			Type:        models.IndicatorTypeHash,
			Severity:    models.SeverityMedium,
			Description: "Google Safe Browsing UNWANTED_SOFTWARE detection capability active",
			Tags:        []string{"google-safebrowsing", "pup", "unwanted-software", "capability"},
			FirstSeen:   &now,
			LastSeen:    &now,
			Confidence:  &conf,
			RawData: map[string]any{
				"source":      "google_safebrowsing",
				"threat_type": "UNWANTED_SOFTWARE",
				"status":      "active",
				"api_version": "v4",
			},
		},
		{
			Value:       "google_safebrowsing:POTENTIALLY_HARMFUL_APPLICATION",
			Type:        models.IndicatorTypeHash,
			Severity:    models.SeverityHigh,
			Description: "Google Safe Browsing PHA detection capability active (Android/iOS)",
			Tags:        []string{"google-safebrowsing", "pha", "mobile", "android", "ios", "capability"},
			FirstSeen:   &now,
			LastSeen:    &now,
			Confidence:  &conf,
			RawData: map[string]any{
				"source":      "google_safebrowsing",
				"threat_type": "POTENTIALLY_HARMFUL_APPLICATION",
				"status":      "active",
				"api_version": "v4",
				"platforms":   []string{"ANDROID", "IOS"},
			},
		},
	}

	result.RawIndicators = indicators
	result.TotalFetched = len(indicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("capabilities", len(indicators)).
		Dur("duration", result.Duration).
		Msg("Google Safe Browsing connector ready")

	return result, nil
}

// threatListUpdatesRequest represents the request to fetch threat list updates
type threatListUpdatesRequest struct {
	Client struct {
		ClientID      string `json:"clientId"`
		ClientVersion string `json:"clientVersion"`
	} `json:"client"`
	ListUpdateRequests []listUpdateRequest `json:"listUpdateRequests"`
}

type listUpdateRequest struct {
	ThreatType      ThreatType      `json:"threatType"`
	PlatformType    PlatformType    `json:"platformType"`
	ThreatEntryType ThreatEntryType `json:"threatEntryType"`
	State           string          `json:"state,omitempty"`
	Constraints     *constraints    `json:"constraints,omitempty"`
}

type constraints struct {
	MaxUpdateEntries      int      `json:"maxUpdateEntries,omitempty"`
	MaxDatabaseEntries    int      `json:"maxDatabaseEntries,omitempty"`
	SupportedCompressions []string `json:"supportedCompressions,omitempty"`
}

// threatListUpdatesResponse represents the response from threat list updates
type threatListUpdatesResponse struct {
	ListUpdateResponses []listUpdateResponse `json:"listUpdateResponses"`
	MinimumWaitDuration string               `json:"minimumWaitDuration"`
}

type listUpdateResponse struct {
	ThreatType      ThreatType      `json:"threatType"`
	PlatformType    PlatformType    `json:"platformType"`
	ThreatEntryType ThreatEntryType `json:"threatEntryType"`
	ResponseType    string          `json:"responseType"`
	Additions       []threatEntry   `json:"additions"`
	Removals        []threatEntry   `json:"removals"`
	NewClientState  string          `json:"newClientState"`
	Checksum        *checksum       `json:"checksum"`
}

type threatEntry struct {
	CompressionType string     `json:"compressionType"`
	RawHashes       *rawHashes `json:"rawHashes,omitempty"`
	RawIndices      *rawIndices `json:"rawIndices,omitempty"`
	RiceHashes      *riceHashes `json:"riceHashes,omitempty"`
	RiceIndices     *riceIndices `json:"riceIndices,omitempty"`
}

type rawHashes struct {
	PrefixSize int    `json:"prefixSize"`
	RawHashes  string `json:"rawHashes"` // base64 encoded
}

type rawIndices struct {
	Indices []int `json:"indices"`
}

type riceHashes struct {
	FirstValue    string `json:"firstValue"`
	RiceParameter int    `json:"riceParameter"`
	NumEntries    int    `json:"numEntries"`
	EncodedData   string `json:"encodedData"`
}

type riceIndices struct {
	FirstValue    int    `json:"firstValue"`
	RiceParameter int    `json:"riceParameter"`
	NumEntries    int    `json:"numEntries"`
	EncodedData   string `json:"encodedData"`
}

type checksum struct {
	SHA256 string `json:"sha256"`
}

// fetchThreatListUpdates fetches threat list updates from the API
func (c *SafeBrowsingConnector) fetchThreatListUpdates(ctx context.Context) ([]models.RawIndicator, error) {
	// Build request for all threat types we care about
	reqBody := threatListUpdatesRequest{}
	reqBody.Client.ClientID = "orbguard-lab"
	reqBody.Client.ClientVersion = "1.0.0"

	// Request updates for multiple threat types and platforms
	threatTypes := []ThreatType{
		ThreatTypeMalware,
		ThreatTypeSocialEng,
		ThreatTypeUnwantedSW,
		ThreatTypePotentialHarm,
	}

	platforms := []PlatformType{
		PlatformAndroid,
		PlatformIOS,
		PlatformAnyPlatform,
	}

	for _, tt := range threatTypes {
		for _, pt := range platforms {
			reqBody.ListUpdateRequests = append(reqBody.ListUpdateRequests, listUpdateRequest{
				ThreatType:      tt,
				PlatformType:    pt,
				ThreatEntryType: ThreatEntryURL,
				Constraints: &constraints{
					MaxUpdateEntries:      500, // Limit entries per request
					SupportedCompressions: []string{"RAW"},
				},
			})
		}
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/threatListUpdates:fetch?key=%s", safeBrowsingAPIURL, c.apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch threat lists: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Google Safe Browsing API returned status %d: %s", resp.StatusCode, string(body))
	}

	var response threatListUpdatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseListUpdates(response)
}

// parseListUpdates converts the API response to raw indicators
func (c *SafeBrowsingConnector) parseListUpdates(response threatListUpdatesResponse) ([]models.RawIndicator, error) {
	var indicators []models.RawIndicator
	now := time.Now()
	baseConf := 0.85 // Google Safe Browsing confidence

	for _, listResp := range response.ListUpdateResponses {
		severity := c.threatTypeToSeverity(listResp.ThreatType)
		tags := c.buildTags(listResp.ThreatType, listResp.PlatformType)

		// Process additions (new threats)
		for _, addition := range listResp.Additions {
			if addition.RawHashes != nil {
				// Create an indicator for this threat list entry
				// Note: Safe Browsing uses hash prefixes, not full URLs
				// This indicator represents membership in a threat list
				indicator := models.RawIndicator{
					Value:       fmt.Sprintf("gsb:%s:%s:%d", listResp.ThreatType, listResp.PlatformType, addition.RawHashes.PrefixSize),
					Type:        models.IndicatorTypeHash,
					Severity:    severity,
					Description: c.buildDescription(listResp.ThreatType, listResp.PlatformType),
					Tags:        tags,
					FirstSeen:   &now,
					LastSeen:    &now,
					Confidence:  &baseConf,
					RawData: map[string]any{
						"source":           "google_safebrowsing",
						"threat_type":      string(listResp.ThreatType),
						"platform_type":    string(listResp.PlatformType),
						"threat_entry_type": string(listResp.ThreatEntryType),
						"response_type":    listResp.ResponseType,
						"prefix_size":      addition.RawHashes.PrefixSize,
						"compression_type": addition.CompressionType,
						"new_client_state": listResp.NewClientState,
					},
				}
				indicators = append(indicators, indicator)
			}
		}

		// Log list update statistics
		c.logger.Debug().
			Str("threat_type", string(listResp.ThreatType)).
			Str("platform", string(listResp.PlatformType)).
			Int("additions", len(listResp.Additions)).
			Int("removals", len(listResp.Removals)).
			Msg("processed threat list update")
	}

	return indicators, nil
}

// threatTypeToSeverity maps threat types to severity levels
func (c *SafeBrowsingConnector) threatTypeToSeverity(tt ThreatType) models.Severity {
	switch tt {
	case ThreatTypeMalware:
		return models.SeverityHigh
	case ThreatTypeSocialEng:
		return models.SeverityHigh
	case ThreatTypePotentialHarm:
		return models.SeverityHigh
	case ThreatTypeUnwantedSW:
		return models.SeverityMedium
	default:
		return models.SeverityMedium
	}
}

// buildTags builds tags based on threat and platform type
func (c *SafeBrowsingConnector) buildTags(tt ThreatType, pt PlatformType) []string {
	tags := []string{"google-safebrowsing"}

	switch tt {
	case ThreatTypeMalware:
		tags = append(tags, "malware")
	case ThreatTypeSocialEng:
		tags = append(tags, "phishing", "social-engineering")
	case ThreatTypeUnwantedSW:
		tags = append(tags, "pup", "unwanted-software")
	case ThreatTypePotentialHarm:
		tags = append(tags, "pha", "potentially-harmful")
	}

	switch pt {
	case PlatformAndroid:
		tags = append(tags, "android", "mobile")
	case PlatformIOS:
		tags = append(tags, "ios", "mobile")
	case PlatformWindows:
		tags = append(tags, "windows")
	case PlatformOSX:
		tags = append(tags, "macos")
	case PlatformLinux:
		tags = append(tags, "linux")
	}

	return tags
}

// buildDescription creates a human-readable description
func (c *SafeBrowsingConnector) buildDescription(tt ThreatType, pt PlatformType) string {
	threatDesc := ""
	switch tt {
	case ThreatTypeMalware:
		threatDesc = "Malware distribution"
	case ThreatTypeSocialEng:
		threatDesc = "Social engineering/Phishing"
	case ThreatTypeUnwantedSW:
		threatDesc = "Unwanted software distribution"
	case ThreatTypePotentialHarm:
		threatDesc = "Potentially harmful application"
	default:
		threatDesc = "Threat"
	}

	platformDesc := ""
	switch pt {
	case PlatformAndroid:
		platformDesc = " targeting Android"
	case PlatformIOS:
		platformDesc = " targeting iOS"
	case PlatformWindows:
		platformDesc = " targeting Windows"
	case PlatformOSX:
		platformDesc = " targeting macOS"
	case PlatformLinux:
		platformDesc = " targeting Linux"
	case PlatformAnyPlatform, PlatformAllPlatforms:
		platformDesc = " (cross-platform)"
	}

	return fmt.Sprintf("%s%s detected by Google Safe Browsing", threatDesc, platformDesc)
}

// LookupURLs checks if URLs are in Google Safe Browsing threat lists
// This is useful for real-time URL checking
func (c *SafeBrowsingConnector) LookupURLs(ctx context.Context, urls []string) ([]URLThreatMatch, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("Google Safe Browsing API key not configured")
	}

	if len(urls) == 0 {
		return nil, nil
	}

	// Build lookup request
	reqBody := urlLookupRequest{
		ThreatInfo: threatInfo{
			ThreatTypes: []ThreatType{
				ThreatTypeMalware,
				ThreatTypeSocialEng,
				ThreatTypeUnwantedSW,
				ThreatTypePotentialHarm,
			},
			PlatformTypes: []PlatformType{
				PlatformAndroid,
				PlatformIOS,
				PlatformAnyPlatform,
			},
			ThreatEntryTypes: []ThreatEntryType{ThreatEntryURL},
		},
	}
	reqBody.Client.ClientID = "orbguard-lab"
	reqBody.Client.ClientVersion = "1.0.0"

	for _, u := range urls {
		reqBody.ThreatInfo.ThreatEntries = append(reqBody.ThreatInfo.ThreatEntries, threatEntryURL{URL: u})
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/threatMatches:find?key=%s", safeBrowsingAPIURL, c.apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup URLs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Google Safe Browsing API returned status %d: %s", resp.StatusCode, string(body))
	}

	var response urlLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseURLMatches(response)
}

// URL Lookup types
type urlLookupRequest struct {
	Client struct {
		ClientID      string `json:"clientId"`
		ClientVersion string `json:"clientVersion"`
	} `json:"client"`
	ThreatInfo threatInfo `json:"threatInfo"`
}

type threatInfo struct {
	ThreatTypes      []ThreatType      `json:"threatTypes"`
	PlatformTypes    []PlatformType    `json:"platformTypes"`
	ThreatEntryTypes []ThreatEntryType `json:"threatEntryTypes"`
	ThreatEntries    []threatEntryURL  `json:"threatEntries"`
}

type threatEntryURL struct {
	URL string `json:"url"`
}

type urlLookupResponse struct {
	Matches []threatMatch `json:"matches"`
}

type threatMatch struct {
	ThreatType      ThreatType      `json:"threatType"`
	PlatformType    PlatformType    `json:"platformType"`
	ThreatEntryType ThreatEntryType `json:"threatEntryType"`
	Threat          threatEntryURL  `json:"threat"`
	ThreatEntryMetadata *threatEntryMetadata `json:"threatEntryMetadata,omitempty"`
	CacheDuration   string          `json:"cacheDuration"`
}

type threatEntryMetadata struct {
	Entries []metadataEntry `json:"entries"`
}

type metadataEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// URLThreatMatch represents a URL that matched a threat list
type URLThreatMatch struct {
	URL          string       `json:"url"`
	ThreatType   ThreatType   `json:"threat_type"`
	PlatformType PlatformType `json:"platform_type"`
	Severity     models.Severity `json:"severity"`
	Description  string       `json:"description"`
	Tags         []string     `json:"tags"`
}

// parseURLMatches converts API matches to URLThreatMatch objects
func (c *SafeBrowsingConnector) parseURLMatches(response urlLookupResponse) ([]URLThreatMatch, error) {
	var matches []URLThreatMatch

	for _, m := range response.Matches {
		match := URLThreatMatch{
			URL:          m.Threat.URL,
			ThreatType:   m.ThreatType,
			PlatformType: m.PlatformType,
			Severity:     c.threatTypeToSeverity(m.ThreatType),
			Description:  c.buildDescription(m.ThreatType, m.PlatformType),
			Tags:         c.buildTags(m.ThreatType, m.PlatformType),
		}
		matches = append(matches, match)
	}

	return matches, nil
}
