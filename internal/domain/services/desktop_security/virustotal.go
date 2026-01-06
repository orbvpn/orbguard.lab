package desktop_security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// VirusTotalClient provides VirusTotal API integration for hash lookups
type VirusTotalClient struct {
	apiKey     string
	httpClient *http.Client
	cache      *cache.RedisCache
	logger     *logger.Logger

	// Rate limiting
	rateLimiter *RateLimiter
}

// VTFileReport represents a VirusTotal file report
type VTFileReport struct {
	Hash           string                 `json:"hash"`
	SHA256         string                 `json:"sha256"`
	SHA1           string                 `json:"sha1"`
	MD5            string                 `json:"md5"`
	FileName       string                 `json:"file_name,omitempty"`
	FileType       string                 `json:"file_type,omitempty"`
	FileSize       int64                  `json:"file_size,omitempty"`
	Detections     int                    `json:"detections"`
	TotalEngines   int                    `json:"total_engines"`
	DetectionRatio float64                `json:"detection_ratio"`
	Malicious      bool                   `json:"malicious"`
	Suspicious     bool                   `json:"suspicious"`
	Harmless       bool                   `json:"harmless"`
	ScanDate       *time.Time             `json:"scan_date,omitempty"`
	FirstSeen      *time.Time             `json:"first_seen,omitempty"`
	LastSeen       *time.Time             `json:"last_seen,omitempty"`
	EngineResults  map[string]EngineResult `json:"engine_results,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
	MalwareFamilies []string              `json:"malware_families,omitempty"`
	VTLink         string                 `json:"vt_link"`
	Found          bool                   `json:"found"`
	Error          string                 `json:"error,omitempty"`
}

// EngineResult represents a single AV engine result
type EngineResult struct {
	Category   string `json:"category"` // malicious, suspicious, harmless, undetected
	Result     string `json:"result,omitempty"`
	EngineName string `json:"engine_name"`
	Version    string `json:"version,omitempty"`
	UpdateDate string `json:"update_date,omitempty"`
}

// NewVirusTotalClient creates a new VirusTotal client
func NewVirusTotalClient(apiKey string, redisCache *cache.RedisCache, log *logger.Logger) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:       redisCache,
		logger:      log.WithComponent("virustotal"),
		rateLimiter: NewRateLimiter(4, time.Minute), // VT free tier: 4 requests/minute
	}
}

// LookupHash looks up a file hash on VirusTotal
func (c *VirusTotalClient) LookupHash(ctx context.Context, hash string) (*VTFileReport, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))

	// Check cache first
	cacheKey := fmt.Sprintf("vt:hash:%s", hash)
	if cached, err := c.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		var report VTFileReport
		if err := json.Unmarshal([]byte(cached), &report); err == nil {
			c.logger.Debug().Str("hash", hash[:12]).Msg("cache hit")
			return &report, nil
		}
	}

	// Rate limit
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Make API request
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle response
	if resp.StatusCode == http.StatusNotFound {
		report := &VTFileReport{
			Hash:  hash,
			Found: false,
		}
		// Cache not found for shorter time
		if data, err := json.Marshal(report); err == nil {
			_ = c.cache.Set(ctx, cacheKey, string(data), time.Hour)
		}
		return report, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("VT API error %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	report, err := c.parseFileReport(body, hash)
	if err != nil {
		return nil, err
	}

	// Cache result
	if data, err := json.Marshal(report); err == nil {
		_ = c.cache.Set(ctx, cacheKey, string(data), 24*time.Hour)
	}

	c.logger.Info().
		Str("hash", hash[:12]).
		Int("detections", report.Detections).
		Int("total", report.TotalEngines).
		Msg("VT lookup complete")

	return report, nil
}

// parseFileReport parses VT API response
func (c *VirusTotalClient) parseFileReport(body []byte, hash string) (*VTFileReport, error) {
	var response struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				SHA256               string            `json:"sha256"`
				SHA1                 string            `json:"sha1"`
				MD5                  string            `json:"md5"`
				Size                 int64             `json:"size"`
				TypeDescription      string            `json:"type_description"`
				TypeTag              string            `json:"type_tag"`
				Tags                 []string          `json:"tags"`
				Names                []string          `json:"names"`
				FirstSubmissionDate  int64             `json:"first_submission_date"`
				LastAnalysisDate     int64             `json:"last_analysis_date"`
				LastAnalysisStats    map[string]int    `json:"last_analysis_stats"`
				LastAnalysisResults  map[string]struct {
					Category   string `json:"category"`
					Result     string `json:"result"`
					EngineName string `json:"engine_name"`
					EngineVersion string `json:"engine_version"`
					EngineUpdate string `json:"engine_update"`
				} `json:"last_analysis_results"`
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
					PopularThreatCategory []struct {
						Value string `json:"value"`
						Count int    `json:"count"`
					} `json:"popular_threat_category"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	attrs := response.Data.Attributes
	stats := attrs.LastAnalysisStats

	report := &VTFileReport{
		Hash:         hash,
		SHA256:       attrs.SHA256,
		SHA1:         attrs.SHA1,
		MD5:          attrs.MD5,
		FileSize:     attrs.Size,
		FileType:     attrs.TypeDescription,
		Tags:         attrs.Tags,
		Found:        true,
		VTLink:       fmt.Sprintf("https://www.virustotal.com/gui/file/%s", attrs.SHA256),
	}

	// File name
	if len(attrs.Names) > 0 {
		report.FileName = attrs.Names[0]
	}

	// Detection stats
	report.Detections = stats["malicious"] + stats["suspicious"]
	report.TotalEngines = stats["malicious"] + stats["suspicious"] + stats["harmless"] + stats["undetected"]
	if report.TotalEngines > 0 {
		report.DetectionRatio = float64(report.Detections) / float64(report.TotalEngines)
	}

	report.Malicious = stats["malicious"] > 0
	report.Suspicious = stats["suspicious"] > 0
	report.Harmless = !report.Malicious && !report.Suspicious

	// Dates
	if attrs.FirstSubmissionDate > 0 {
		t := time.Unix(attrs.FirstSubmissionDate, 0)
		report.FirstSeen = &t
	}
	if attrs.LastAnalysisDate > 0 {
		t := time.Unix(attrs.LastAnalysisDate, 0)
		report.ScanDate = &t
		report.LastSeen = &t
	}

	// Engine results
	report.EngineResults = make(map[string]EngineResult)
	for engine, result := range attrs.LastAnalysisResults {
		report.EngineResults[engine] = EngineResult{
			Category:   result.Category,
			Result:     result.Result,
			EngineName: result.EngineName,
			Version:    result.EngineVersion,
			UpdateDate: result.EngineUpdate,
		}
	}

	// Malware families
	if attrs.PopularThreatClassification.SuggestedThreatLabel != "" {
		report.MalwareFamilies = append(report.MalwareFamilies, attrs.PopularThreatClassification.SuggestedThreatLabel)
	}

	return report, nil
}

// LookupFile hashes a file and looks it up on VirusTotal
func (c *VirusTotalClient) LookupFile(ctx context.Context, filePath string) (*VTFileReport, error) {
	// Hash the file
	hash, err := c.hashFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	// Look up the hash
	report, err := c.LookupHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	// Get file info
	if info, err := os.Stat(filePath); err == nil {
		report.FileSize = info.Size()
		report.FileName = info.Name()
	}

	return report, nil
}

// LookupBatch looks up multiple hashes in batch
func (c *VirusTotalClient) LookupBatch(ctx context.Context, hashes []string) map[string]*VTFileReport {
	results := make(map[string]*VTFileReport)
	var mu sync.Mutex

	// Process hashes with concurrency limit
	sem := make(chan struct{}, 2) // 2 concurrent requests

	var wg sync.WaitGroup
	for _, hash := range hashes {
		select {
		case <-ctx.Done():
			return results
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			report, err := c.LookupHash(ctx, h)
			mu.Lock()
			if err != nil {
				results[h] = &VTFileReport{
					Hash:  h,
					Found: false,
					Error: err.Error(),
				}
			} else {
				results[h] = report
			}
			mu.Unlock()
		}(hash)
	}

	wg.Wait()
	return results
}

// EnrichPersistenceItem enriches a persistence item with VT data
func (c *VirusTotalClient) EnrichPersistenceItem(ctx context.Context, item *models.PersistenceItem) error {
	if item.BinaryHash == "" {
		return nil
	}

	report, err := c.LookupHash(ctx, item.BinaryHash)
	if err != nil {
		c.logger.Debug().Err(err).Str("hash", item.BinaryHash[:12]).Msg("VT lookup failed")
		return err
	}

	if report.Found {
		item.VTDetections = report.Detections
		item.VTTotalEngines = report.TotalEngines
		item.VTLink = report.VTLink
		item.VTLastScan = report.ScanDate

		// Update risk based on VT results
		if report.Detections > 0 {
			item.IsKnownBad = true
			if report.Detections >= 10 {
				item.RiskLevel = models.PersistenceRiskCritical
				item.RiskReasons = append(item.RiskReasons, fmt.Sprintf("VirusTotal: %d/%d detections", report.Detections, report.TotalEngines))
			} else if report.Detections >= 3 {
				item.RiskLevel = models.PersistenceRiskHigh
				item.RiskReasons = append(item.RiskReasons, fmt.Sprintf("VirusTotal: %d/%d detections", report.Detections, report.TotalEngines))
			} else {
				item.RiskReasons = append(item.RiskReasons, fmt.Sprintf("VirusTotal: %d/%d detections (low confidence)", report.Detections, report.TotalEngines))
			}
		} else {
			item.IsKnownGood = true
		}
	}

	return nil
}

// hashFile computes SHA256 hash of a file
func (c *VirusTotalClient) hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// GetRiskLevel returns risk level based on VT detections
func GetVTRiskLevel(detections, total int) models.PersistenceRiskLevel {
	if total == 0 {
		return models.PersistenceRiskInfo
	}

	ratio := float64(detections) / float64(total)

	switch {
	case detections >= 15 || ratio >= 0.25:
		return models.PersistenceRiskCritical
	case detections >= 5 || ratio >= 0.10:
		return models.PersistenceRiskHigh
	case detections >= 2 || ratio >= 0.05:
		return models.PersistenceRiskMedium
	case detections >= 1:
		return models.PersistenceRiskLow
	default:
		return models.PersistenceRiskClean
	}
}

// RateLimiter provides simple rate limiting
type RateLimiter struct {
	limit    int
	window   time.Duration
	tokens   int
	lastTime time.Time
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:    limit,
		window:   window,
		tokens:   limit,
		lastTime: time.Now(),
	}
}

// Wait waits for a rate limit token
func (r *RateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Replenish tokens
	now := time.Now()
	elapsed := now.Sub(r.lastTime)
	tokensToAdd := int(elapsed.Seconds() * float64(r.limit) / r.window.Seconds())
	r.tokens += tokensToAdd
	if r.tokens > r.limit {
		r.tokens = r.limit
	}
	r.lastTime = now

	if r.tokens > 0 {
		r.tokens--
		return nil
	}

	// Need to wait
	waitTime := r.window / time.Duration(r.limit)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(waitTime):
		r.tokens = 0
		r.lastTime = time.Now()
		return nil
	}
}

// VTIPReport represents VirusTotal IP report
type VTIPReport struct {
	IP               string    `json:"ip"`
	Country          string    `json:"country"`
	ASOwner          string    `json:"as_owner"`
	ASN              int       `json:"asn"`
	Malicious        int       `json:"malicious"`
	Suspicious       int       `json:"suspicious"`
	Harmless         int       `json:"harmless"`
	Undetected       int       `json:"undetected"`
	IsKnownBad       bool      `json:"is_known_bad"`
	Tags             []string  `json:"tags"`
	LastAnalysisDate *time.Time `json:"last_analysis_date"`
	VTLink           string    `json:"vt_link"`
}

// LookupIP looks up an IP address on VirusTotal
func (c *VirusTotalClient) LookupIP(ctx context.Context, ip string) (*VTIPReport, error) {
	// Check cache
	cacheKey := fmt.Sprintf("vt:ip:%s", ip)
	if cached, err := c.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		var report VTIPReport
		if err := json.Unmarshal([]byte(cached), &report); err == nil {
			return &report, nil
		}
	}

	// Rate limit
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Make request
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VT API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var response struct {
		Data struct {
			Attributes struct {
				Country           string         `json:"country"`
				ASOwner           string         `json:"as_owner"`
				ASN               int            `json:"asn"`
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
				LastAnalysisDate  int64          `json:"last_analysis_date"`
				Tags              []string       `json:"tags"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	attrs := response.Data.Attributes
	stats := attrs.LastAnalysisStats

	report := &VTIPReport{
		IP:         ip,
		Country:    attrs.Country,
		ASOwner:    attrs.ASOwner,
		ASN:        attrs.ASN,
		Malicious:  stats["malicious"],
		Suspicious: stats["suspicious"],
		Harmless:   stats["harmless"],
		Undetected: stats["undetected"],
		IsKnownBad: stats["malicious"] > 0 || stats["suspicious"] > 0,
		Tags:       attrs.Tags,
		VTLink:     fmt.Sprintf("https://www.virustotal.com/gui/ip-address/%s", ip),
	}

	if attrs.LastAnalysisDate > 0 {
		t := time.Unix(attrs.LastAnalysisDate, 0)
		report.LastAnalysisDate = &t
	}

	// Cache
	if data, err := json.Marshal(report); err == nil {
		_ = c.cache.Set(ctx, cacheKey, string(data), 6*time.Hour)
	}

	return report, nil
}
