package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// GoogleSafeBrowsingClient implements SafeBrowsingClient for Google Safe Browsing API
type GoogleSafeBrowsingClient struct {
	apiKey     string
	httpClient *http.Client
	logger     *logger.Logger
}

// SafeBrowsingConfig holds configuration for Google Safe Browsing
type SafeBrowsingConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewGoogleSafeBrowsingClient creates a new Google Safe Browsing client
func NewGoogleSafeBrowsingClient(config SafeBrowsingConfig, log *logger.Logger) *GoogleSafeBrowsingClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &GoogleSafeBrowsingClient{
		apiKey: config.APIKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: log.WithComponent("safe-browsing"),
	}
}

// CheckURLs checks multiple URLs against Google Safe Browsing API
func (c *GoogleSafeBrowsingClient) CheckURLs(ctx context.Context, urls []string) ([]models.SafeBrowsingResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("Safe Browsing API key not configured")
	}

	results := make([]models.SafeBrowsingResult, len(urls))
	for i, u := range urls {
		results[i] = models.SafeBrowsingResult{
			URL:       u,
			IsThreat:  false,
			CacheTime: 300, // 5 minutes default
		}
	}

	// Build request
	reqBody := safeBrowsingRequest{
		Client: safeBrowsingClient{
			ClientID:      "orbguard",
			ClientVersion: "1.0.0",
		},
		ThreatInfo: threatInfo{
			ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries:    make([]threatEntry, len(urls)),
		},
	}

	for i, u := range urls {
		reqBody.ThreatInfo.ThreatEntries[i] = threatEntry{URL: u}
	}

	// Make API request
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", c.apiKey),
		nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Body = newBodyReader(jsonBody)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var apiResp safeBrowsingResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process matches
	for _, match := range apiResp.Matches {
		for i, u := range urls {
			if u == match.Threat.URL {
				results[i].IsThreat = true
				results[i].ThreatTypes = append(results[i].ThreatTypes, match.ThreatType)
				results[i].Platforms = append(results[i].Platforms, match.PlatformType)
				if match.CacheDuration != "" {
					// Parse duration like "300s"
					results[i].CacheTime = parseCacheDuration(match.CacheDuration)
				}
			}
		}
	}

	c.logger.Debug().
		Int("url_count", len(urls)).
		Int("threats_found", len(apiResp.Matches)).
		Msg("Safe Browsing check completed")

	return results, nil
}

// API request/response types
type safeBrowsingRequest struct {
	Client     safeBrowsingClient `json:"client"`
	ThreatInfo threatInfo         `json:"threatInfo"`
}

type safeBrowsingClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type threatInfo struct {
	ThreatTypes      []string      `json:"threatTypes"`
	PlatformTypes    []string      `json:"platformTypes"`
	ThreatEntryTypes []string      `json:"threatEntryTypes"`
	ThreatEntries    []threatEntry `json:"threatEntries"`
}

type threatEntry struct {
	URL string `json:"url"`
}

type safeBrowsingResponse struct {
	Matches []threatMatch `json:"matches"`
}

type threatMatch struct {
	ThreatType      string      `json:"threatType"`
	PlatformType    string      `json:"platformType"`
	Threat          threatEntry `json:"threat"`
	CacheDuration   string      `json:"cacheDuration"`
}

// Helper functions

type bodyReader struct {
	data   []byte
	offset int
}

func newBodyReader(data []byte) *bodyReader {
	return &bodyReader{data: data}
}

func (r *bodyReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, nil
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *bodyReader) Close() error {
	return nil
}

func parseCacheDuration(s string) int {
	// Parse duration like "300s"
	var seconds int
	fmt.Sscanf(s, "%ds", &seconds)
	if seconds == 0 {
		return 300 // Default 5 minutes
	}
	return seconds
}

// MockSafeBrowsingClient is a mock implementation for testing
type MockSafeBrowsingClient struct {
	// Map of URLs to their threat results
	ThreatURLs map[string][]string
}

// NewMockSafeBrowsingClient creates a mock Safe Browsing client
func NewMockSafeBrowsingClient() *MockSafeBrowsingClient {
	return &MockSafeBrowsingClient{
		ThreatURLs: map[string][]string{
			"http://malware.testing.google.test/testing/malware/":       {"MALWARE"},
			"http://phishing.testing.google.test/testing/phishing/":     {"SOCIAL_ENGINEERING"},
			"http://unwanted.testing.google.test/testing/unwanted/":     {"UNWANTED_SOFTWARE"},
		},
	}
}

// CheckURLs implements SafeBrowsingClient for testing
func (c *MockSafeBrowsingClient) CheckURLs(ctx context.Context, urls []string) ([]models.SafeBrowsingResult, error) {
	results := make([]models.SafeBrowsingResult, len(urls))

	for i, u := range urls {
		results[i] = models.SafeBrowsingResult{
			URL:       u,
			IsThreat:  false,
			CacheTime: 300,
		}

		if threats, ok := c.ThreatURLs[u]; ok {
			results[i].IsThreat = true
			results[i].ThreatTypes = threats
		}
	}

	return results, nil
}
