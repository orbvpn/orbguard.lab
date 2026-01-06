package analysis

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
	hybridAnalysisAPIURL = "https://www.hybrid-analysis.com/api/v2"
	hybridAnalysisSlug   = "hybrid_analysis"
)

// HybridAnalysisConnector implements the source connector for Hybrid Analysis
type HybridAnalysisConnector struct {
	client   *http.Client
	logger   *logger.Logger
	enabled  bool
	interval time.Duration
	sourceID uuid.UUID
	apiKey   string
}

// NewHybridAnalysisConnector creates a new Hybrid Analysis connector
func NewHybridAnalysisConnector(log *logger.Logger) *HybridAnalysisConnector {
	return &HybridAnalysisConnector{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger:   log.WithComponent("hybrid-analysis"),
		enabled:  false, // Disabled by default, requires API key
		interval: 4 * time.Hour,
	}
}

// Slug returns the unique identifier for this source
func (c *HybridAnalysisConnector) Slug() string {
	return hybridAnalysisSlug
}

// Name returns the human-readable name of this source
func (c *HybridAnalysisConnector) Name() string {
	return "Hybrid Analysis"
}

// Category returns the category of this source
func (c *HybridAnalysisConnector) Category() models.SourceCategory {
	return models.SourceCategoryGeneral
}

// IsEnabled returns whether this source is enabled
func (c *HybridAnalysisConnector) IsEnabled() bool {
	return c.enabled && c.apiKey != ""
}

// SetEnabled sets the enabled state
func (c *HybridAnalysisConnector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// UpdateInterval returns how often this source should be updated
func (c *HybridAnalysisConnector) UpdateInterval() time.Duration {
	return c.interval
}

// SetSourceID sets the database source ID
func (c *HybridAnalysisConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Configure configures the connector with the given config
func (c *HybridAnalysisConnector) Configure(cfg sources.ConnectorConfig) error {
	c.enabled = cfg.Enabled
	if cfg.UpdateInterval > 0 {
		c.interval = cfg.UpdateInterval
	}
	if cfg.APIKey != "" {
		c.apiKey = cfg.APIKey
	}
	return nil
}

// Fetch retrieves malware analysis data from Hybrid Analysis
func (c *HybridAnalysisConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: hybridAnalysisSlug,
		FetchedAt:  start,
	}

	if c.apiKey == "" {
		result.Error = fmt.Errorf("API key required for Hybrid Analysis")
		result.Success = false
		result.Duration = time.Since(start)
		return result, result.Error
	}

	c.logger.Info().Msg("fetching from Hybrid Analysis")

	var allIndicators []models.RawIndicator

	// Fetch latest samples from feed
	feedIndicators, err := c.fetchLatestFeed(ctx)
	if err != nil {
		c.logger.Warn().Err(err).Msg("failed to fetch latest feed")
	} else {
		allIndicators = append(allIndicators, feedIndicators...)
	}

	// Search for recent Android malware
	androidIndicators, err := c.searchSamples(ctx, "android", 50)
	if err != nil {
		c.logger.Warn().Err(err).Msg("failed to search Android malware")
	} else {
		allIndicators = append(allIndicators, androidIndicators...)
	}

	// Search for iOS malware
	iosIndicators, err := c.searchSamples(ctx, "ios", 50)
	if err != nil {
		c.logger.Warn().Err(err).Msg("failed to search iOS malware")
	} else {
		allIndicators = append(allIndicators, iosIndicators...)
	}

	result.RawIndicators = allIndicators
	result.TotalFetched = len(allIndicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("total", len(allIndicators)).
		Dur("duration", result.Duration).
		Msg("Hybrid Analysis fetch completed")

	return result, nil
}

// HybridAnalysisFeedResponse represents the feed API response
type HybridAnalysisFeedResponse struct {
	Data []HybridAnalysisSample `json:"data"`
}

// HybridAnalysisSample represents a malware sample
type HybridAnalysisSample struct {
	JobID             string    `json:"job_id"`
	SHA256            string    `json:"sha256"`
	SHA1              string    `json:"sha1"`
	MD5               string    `json:"md5"`
	Environment       string    `json:"environment"`
	EnvironmentDesc   string    `json:"environment_description"`
	SubmitName        string    `json:"submit_name"`
	Size              int       `json:"size"`
	Type              string    `json:"type"`
	TypeShort         []string  `json:"type_short"`
	AnalysisStartTime string    `json:"analysis_start_time"`
	ThreatScore       int       `json:"threat_score"`
	ThreatLevel       int       `json:"threat_level"`
	Verdict           string    `json:"verdict"`
	VXFamily          string    `json:"vx_family"`
	Tags              []string  `json:"tags"`
	MITREAttacks      []struct {
		TacticID   string `json:"tactic_id"`
		TacticName string `json:"tactic"`
		TechID     string `json:"technique_id"`
		TechName   string `json:"technique"`
	} `json:"mitre_attcks"`
	ExtractedFiles []struct {
		Name        string `json:"name"`
		SHA256      string `json:"sha256"`
		ThreatLevel int    `json:"threat_level"`
	} `json:"extracted_files"`
	Processes []struct {
		Name        string `json:"name"`
		SHA256      string `json:"sha256"`
		CommandLine string `json:"command_line"`
	} `json:"processes"`
	Hosts []string `json:"hosts"`
	Domains []struct {
		Domain string `json:"domain"`
		Port   int    `json:"port"`
	} `json:"domains"`
	CompromisedHosts []string `json:"compromised_hosts"`
}

// fetchLatestFeed fetches the latest malware samples from the feed
func (c *HybridAnalysisConnector) fetchLatestFeed(ctx context.Context) ([]models.RawIndicator, error) {
	feedURL := fmt.Sprintf("%s/feed/latest", hybridAnalysisAPIURL)

	req, err := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OrbGuard/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Hybrid Analysis returned status %d: %s", resp.StatusCode, string(body))
	}

	var feedResp HybridAnalysisFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseSamples(feedResp.Data)
}

// searchSamples searches for specific types of malware samples
func (c *HybridAnalysisConnector) searchSamples(ctx context.Context, platform string, limit int) ([]models.RawIndicator, error) {
	searchURL := fmt.Sprintf("%s/search/terms", hybridAnalysisAPIURL)

	payload := fmt.Sprintf("filetype=%s&verdict=malicious", platform)

	req, err := http.NewRequestWithContext(ctx, "POST", searchURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "OrbGuard/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search samples: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search returned status %d: %s", resp.StatusCode, string(body))
	}

	var results []HybridAnalysisSample
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}

	if len(results) > limit {
		results = results[:limit]
	}

	return c.parseSamples(results)
}

// parseSamples converts Hybrid Analysis samples to indicators
func (c *HybridAnalysisConnector) parseSamples(samples []HybridAnalysisSample) ([]models.RawIndicator, error) {
	var indicators []models.RawIndicator
	now := time.Now()

	for _, sample := range samples {
		// Determine severity based on threat level
		severity := models.SeverityMedium
		switch {
		case sample.ThreatLevel >= 80 || sample.ThreatScore >= 80:
			severity = models.SeverityCritical
		case sample.ThreatLevel >= 60 || sample.ThreatScore >= 60:
			severity = models.SeverityHigh
		case sample.ThreatLevel >= 40 || sample.ThreatScore >= 40:
			severity = models.SeverityMedium
		default:
			severity = models.SeverityLow
		}

		// Calculate confidence
		conf := float64(sample.ThreatScore) / 100.0
		if conf < 0.5 {
			conf = 0.5
		}

		// Build tags
		tags := []string{"hybrid-analysis", "malware-sandbox"}
		if sample.VXFamily != "" {
			tags = append(tags, "family:"+strings.ToLower(sample.VXFamily))
		}
		tags = append(tags, sample.Tags...)

		// Detect platform
		platforms := []models.Platform{models.PlatformAll}
		for _, t := range sample.TypeShort {
			switch strings.ToLower(t) {
			case "apk", "android":
				platforms = []models.Platform{models.PlatformAndroid}
				tags = append(tags, "android")
			case "ios", "ipa":
				platforms = []models.Platform{models.PlatformIOS}
				tags = append(tags, "ios")
			case "exe", "dll", "pe":
				platforms = []models.Platform{models.PlatformWindows}
				tags = append(tags, "windows")
			case "macho", "dmg":
				platforms = []models.Platform{models.PlatformMacOS}
				tags = append(tags, "macos")
			case "elf":
				platforms = []models.Platform{models.PlatformLinux}
				tags = append(tags, "linux")
			}
		}

		// Extract MITRE ATT&CK info
		var mitreTechniques []string
		var mitreTactics []string
		for _, attack := range sample.MITREAttacks {
			if attack.TechID != "" {
				mitreTechniques = append(mitreTechniques, attack.TechID)
			}
			if attack.TacticID != "" {
				mitreTactics = append(mitreTactics, attack.TacticID)
			}
		}

		// Parse analysis time
		analysisTime := now
		if sample.AnalysisStartTime != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", sample.AnalysisStartTime); err == nil {
				analysisTime = t
			}
		}

		// Build description
		description := fmt.Sprintf("Malware sample analyzed by Hybrid Analysis")
		if sample.VXFamily != "" {
			description = fmt.Sprintf("%s - Family: %s", description, sample.VXFamily)
		}
		if sample.SubmitName != "" {
			description = fmt.Sprintf("%s - Name: %s", description, sample.SubmitName)
		}

		// Create SHA256 hash indicator
		if sample.SHA256 != "" {
			sha256Indicator := models.RawIndicator{
				Value:       strings.ToLower(sample.SHA256),
				Type:        models.IndicatorTypeHash,
				Severity:    severity,
				Description: description,
				Tags:        append(tags, "sha256"),
				FirstSeen:   &analysisTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":           "hybrid-analysis",
					"job_id":           sample.JobID,
					"sha256":           sample.SHA256,
					"sha1":             sample.SHA1,
					"md5":              sample.MD5,
					"verdict":          sample.Verdict,
					"threat_score":     sample.ThreatScore,
					"threat_level":     sample.ThreatLevel,
					"vx_family":        sample.VXFamily,
					"environment":      sample.Environment,
					"file_type":        sample.Type,
					"mitre_techniques": mitreTechniques,
					"mitre_tactics":    mitreTactics,
					"platforms":        platforms,
				},
			}
			indicators = append(indicators, sha256Indicator)
		}

		// Create MD5 hash indicator
		if sample.MD5 != "" {
			md5Indicator := models.RawIndicator{
				Value:       strings.ToLower(sample.MD5),
				Type:        models.IndicatorTypeHash,
				Severity:    severity,
				Description: fmt.Sprintf("MD5 hash - %s", description),
				Tags:        append(tags, "md5"),
				FirstSeen:   &analysisTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":      "hybrid-analysis",
					"job_id":      sample.JobID,
					"parent_sha256": sample.SHA256,
				},
			}
			indicators = append(indicators, md5Indicator)
		}

		// Extract C2 domains
		for _, domain := range sample.Domains {
			if domain.Domain == "" {
				continue
			}
			domainIndicator := models.RawIndicator{
				Value:       domain.Domain,
				Type:        models.IndicatorTypeDomain,
				Severity:    severity,
				Description: fmt.Sprintf("C2 domain from malware sample: %s", sample.VXFamily),
				Tags:        append(tags, "c2-domain"),
				FirstSeen:   &analysisTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":        "hybrid-analysis",
					"job_id":        sample.JobID,
					"parent_sha256": sample.SHA256,
					"port":          domain.Port,
				},
			}
			indicators = append(indicators, domainIndicator)
		}

		// Extract C2 hosts (IPs)
		for _, host := range sample.Hosts {
			if host == "" {
				continue
			}
			hostIndicator := models.RawIndicator{
				Value:       host,
				Type:        models.IndicatorTypeIP,
				Severity:    severity,
				Description: fmt.Sprintf("C2 IP from malware sample: %s", sample.VXFamily),
				Tags:        append(tags, "c2-ip"),
				FirstSeen:   &analysisTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":        "hybrid-analysis",
					"job_id":        sample.JobID,
					"parent_sha256": sample.SHA256,
				},
			}
			indicators = append(indicators, hostIndicator)
		}

		// Extract dropped file hashes
		for _, file := range sample.ExtractedFiles {
			if file.SHA256 == "" {
				continue
			}
			droppedIndicator := models.RawIndicator{
				Value:       strings.ToLower(file.SHA256),
				Type:        models.IndicatorTypeHash,
				Severity:    severity,
				Description: fmt.Sprintf("Dropped/extracted file from %s: %s", sample.VXFamily, file.Name),
				Tags:        append(tags, "dropped-file", "sha256"),
				FirstSeen:   &analysisTime,
				LastSeen:    &now,
				Confidence:  &conf,
				SourceID:    c.Slug(),
				SourceName:  c.Name(),
				RawData: map[string]any{
					"source":        "hybrid-analysis",
					"job_id":        sample.JobID,
					"parent_sha256": sample.SHA256,
					"filename":      file.Name,
					"threat_level":  file.ThreatLevel,
				},
			}
			indicators = append(indicators, droppedIndicator)
		}
	}

	return indicators, nil
}
