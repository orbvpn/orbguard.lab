package premium

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/sources"
	"orbguard-lab/pkg/logger"
)

const (
	shodanAPIURL = "https://api.shodan.io"
	shodanSlug   = "shodan"
)

// Searches for known malicious services/C2 infrastructure
var shodanThreatSearches = []struct {
	Query       string
	Description string
	Tags        []string
	Severity    models.Severity
}{
	{
		Query:       "product:Cobalt Strike",
		Description: "Cobalt Strike C2 beacon",
		Tags:        []string{"c2", "cobalt-strike", "apt"},
		Severity:    models.SeverityCritical,
	},
	{
		Query:       "product:Metasploit",
		Description: "Metasploit framework",
		Tags:        []string{"c2", "metasploit", "exploitation"},
		Severity:    models.SeverityHigh,
	},
	{
		Query:       "http.html:Pegasus",
		Description: "Potential Pegasus spyware infrastructure",
		Tags:        []string{"pegasus", "spyware", "nso-group"},
		Severity:    models.SeverityCritical,
	},
	{
		Query:       "product:Sliver",
		Description: "Sliver C2 framework",
		Tags:        []string{"c2", "sliver", "apt"},
		Severity:    models.SeverityCritical,
	},
	{
		Query:       "product:Empire",
		Description: "Empire post-exploitation framework",
		Tags:        []string{"c2", "empire", "post-exploitation"},
		Severity:    models.SeverityHigh,
	},
	{
		Query:       "http.html:phishing",
		Description: "Phishing page indicator",
		Tags:        []string{"phishing", "credential-theft"},
		Severity:    models.SeverityMedium,
	},
	{
		Query:       "ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
		Description: "Havoc C2 JARM fingerprint",
		Tags:        []string{"c2", "havoc"},
		Severity:    models.SeverityCritical,
	},
}

// ShodanConnector implements the source connector for Shodan
type ShodanConnector struct {
	client   *http.Client
	logger   *logger.Logger
	enabled  bool
	interval time.Duration
	sourceID uuid.UUID
	apiKey   string
}

// NewShodanConnector creates a new Shodan connector
func NewShodanConnector(log *logger.Logger) *ShodanConnector {
	return &ShodanConnector{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger:   log.WithComponent("shodan"),
		enabled:  false, // Disabled by default, requires API key
		interval: 24 * time.Hour,
	}
}

// Slug returns the unique identifier for this source
func (c *ShodanConnector) Slug() string {
	return shodanSlug
}

// Name returns the human-readable name of this source
func (c *ShodanConnector) Name() string {
	return "Shodan"
}

// Category returns the category of this source
func (c *ShodanConnector) Category() models.SourceCategory {
	return models.SourceCategoryPremium
}

// IsEnabled returns whether this source is enabled
func (c *ShodanConnector) IsEnabled() bool {
	return c.enabled && c.apiKey != ""
}

// SetEnabled sets the enabled state
func (c *ShodanConnector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// UpdateInterval returns how often this source should be updated
func (c *ShodanConnector) UpdateInterval() time.Duration {
	return c.interval
}

// SetSourceID sets the database source ID
func (c *ShodanConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Configure configures the connector with the given config
func (c *ShodanConnector) Configure(cfg sources.ConnectorConfig) error {
	c.enabled = cfg.Enabled
	if cfg.UpdateInterval > 0 {
		c.interval = cfg.UpdateInterval
	}
	if cfg.APIKey != "" {
		c.apiKey = cfg.APIKey
	}
	return nil
}

// Fetch retrieves threat intelligence from Shodan
func (c *ShodanConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: shodanSlug,
		FetchedAt:  start,
	}

	if c.apiKey == "" {
		result.Error = fmt.Errorf("API key required for Shodan")
		result.Success = false
		result.Duration = time.Since(start)
		return result, result.Error
	}

	c.logger.Info().Msg("fetching from Shodan")

	// Check API credits first
	credits, err := c.checkAPICredits(ctx)
	if err != nil {
		c.logger.Warn().Err(err).Msg("failed to check API credits")
	} else if credits < len(shodanThreatSearches) {
		c.logger.Warn().Int("credits", credits).Msg("insufficient Shodan API credits")
	}

	var allIndicators []models.RawIndicator

	// Run threat searches
	for _, search := range shodanThreatSearches {
		indicators, err := c.searchHosts(ctx, search.Query, search.Description, search.Tags, search.Severity)
		if err != nil {
			c.logger.Warn().Err(err).Str("query", search.Query).Msg("search failed")
			continue
		}

		allIndicators = append(allIndicators, indicators...)

		// Rate limiting
		time.Sleep(1 * time.Second)
	}

	result.RawIndicators = allIndicators
	result.TotalFetched = len(allIndicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("total", len(allIndicators)).
		Dur("duration", result.Duration).
		Msg("Shodan fetch completed")

	return result, nil
}

// ShodanAPIInfo represents API info response
type ShodanAPIInfo struct {
	QueryCredits int `json:"query_credits"`
	ScanCredits  int `json:"scan_credits"`
	Plan         string `json:"plan"`
}

// ShodanSearchResponse represents the search API response
type ShodanSearchResponse struct {
	Matches []ShodanHost `json:"matches"`
	Total   int          `json:"total"`
}

// ShodanHost represents a single host result
type ShodanHost struct {
	IP        string   `json:"ip_str"`
	Port      int      `json:"port"`
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	Country   string   `json:"country_code"`
	City      string   `json:"city,omitempty"`
	ASN       string   `json:"asn"`
	ISP       string   `json:"isp"`
	Org       string   `json:"org"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	OS        string   `json:"os,omitempty"`
	Transport string   `json:"transport"`
	Timestamp string   `json:"timestamp"`
	SSL       *struct {
		JARM        string `json:"jarm,omitempty"`
		JA3S        string `json:"ja3s,omitempty"`
		Fingerprint string `json:"fingerprint,omitempty"`
		Cert        struct {
			Issuer  map[string]string `json:"issuer"`
			Subject map[string]string `json:"subject"`
			Serial  string            `json:"serial"`
		} `json:"cert,omitempty"`
	} `json:"ssl,omitempty"`
	HTTP *struct {
		Title    string `json:"title,omitempty"`
		Server   string `json:"server,omitempty"`
		Location string `json:"location,omitempty"`
		HTML     string `json:"html,omitempty"`
	} `json:"http,omitempty"`
	Data string `json:"data,omitempty"` // Raw banner
}

// checkAPICredits checks remaining API credits
func (c *ShodanConnector) checkAPICredits(ctx context.Context) (int, error) {
	infoURL := fmt.Sprintf("%s/api-info?key=%s", shodanAPIURL, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", infoURL, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var info ShodanAPIInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return 0, err
	}

	c.logger.Debug().
		Int("query_credits", info.QueryCredits).
		Int("scan_credits", info.ScanCredits).
		Str("plan", info.Plan).
		Msg("Shodan API credits")

	return info.QueryCredits, nil
}

// searchHosts searches Shodan for malicious hosts
func (c *ShodanConnector) searchHosts(ctx context.Context, query, description string, tags []string, severity models.Severity) ([]models.RawIndicator, error) {
	searchURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s",
		shodanAPIURL,
		c.apiKey,
		url.QueryEscape(query),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search Shodan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Shodan returned status %d: %s", resp.StatusCode, string(body))
	}

	var searchResp ShodanSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseHosts(searchResp.Matches, description, tags, severity)
}

// parseHosts converts Shodan hosts to indicators
func (c *ShodanConnector) parseHosts(hosts []ShodanHost, description string, baseTags []string, severity models.Severity) ([]models.RawIndicator, error) {
	var indicators []models.RawIndicator
	now := time.Now()
	conf := 0.85 // Shodan is reliable

	for _, host := range hosts {
		// Parse timestamp
		hostTime := now
		if host.Timestamp != "" {
			if t, err := time.Parse("2006-01-02T15:04:05.000000", host.Timestamp); err == nil {
				hostTime = t
			}
		}

		// Build tags
		tags := append([]string{"shodan"}, baseTags...)
		if host.Country != "" {
			tags = append(tags, "country:"+strings.ToLower(host.Country))
		}
		if host.Product != "" {
			tags = append(tags, "product:"+strings.ToLower(host.Product))
		}

		// Build description
		fullDescription := description
		if host.Product != "" {
			fullDescription = fmt.Sprintf("%s - Product: %s", description, host.Product)
		}
		if host.Org != "" {
			fullDescription = fmt.Sprintf("%s (Org: %s)", fullDescription, host.Org)
		}

		// Create IP indicator
		if host.IP != "" {
			ipIndicator := models.RawIndicator{
				Value:       host.IP,
				Type:        models.IndicatorTypeIP,
				Severity:    severity,
				Description: fullDescription,
				Tags:        tags,
				FirstSeen:   &hostTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":    "shodan",
					"ip":        host.IP,
					"port":      host.Port,
					"transport": host.Transport,
					"asn":       host.ASN,
					"isp":       host.ISP,
					"org":       host.Org,
					"country":   host.Country,
					"city":      host.City,
					"product":   host.Product,
					"version":   host.Version,
					"os":        host.OS,
				},
			}
			indicators = append(indicators, ipIndicator)
		}

		// Extract domain indicators
		for _, domain := range host.Domains {
			if domain == "" {
				continue
			}
			domainIndicator := models.RawIndicator{
				Value:       domain,
				Type:        models.IndicatorTypeDomain,
				Severity:    severity,
				Description: fmt.Sprintf("Domain associated with %s", description),
				Tags:        append(tags, "associated-domain"),
				FirstSeen:   &hostTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":    "shodan",
					"parent_ip": host.IP,
					"port":      host.Port,
				},
			}
			indicators = append(indicators, domainIndicator)
		}

		// Extract hostname indicators
		for _, hostname := range host.Hostnames {
			if hostname == "" {
				continue
			}
			hostnameIndicator := models.RawIndicator{
				Value:       hostname,
				Type:        models.IndicatorTypeDomain,
				Severity:    severity,
				Description: fmt.Sprintf("Hostname associated with %s", description),
				Tags:        append(tags, "associated-hostname"),
				FirstSeen:   &hostTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":    "shodan",
					"parent_ip": host.IP,
					"port":      host.Port,
				},
			}
			indicators = append(indicators, hostnameIndicator)
		}

		// Extract SSL certificate indicators
		if host.SSL != nil && host.SSL.Fingerprint != "" {
			certIndicator := models.RawIndicator{
				Value:       host.SSL.Fingerprint,
				Type:        models.IndicatorTypeCertificate,
				Severity:    severity,
				Description: fmt.Sprintf("SSL certificate from %s", description),
				Tags:        append(tags, "ssl-certificate"),
				FirstSeen:   &hostTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":      "shodan",
					"parent_ip":   host.IP,
					"port":        host.Port,
					"jarm":        host.SSL.JARM,
					"ja3s":        host.SSL.JA3S,
					"cert_issuer": host.SSL.Cert.Issuer,
					"cert_subject": host.SSL.Cert.Subject,
				},
			}
			indicators = append(indicators, certIndicator)
		}
	}

	return indicators, nil
}
