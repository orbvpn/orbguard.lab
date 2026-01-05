package government

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
	"orbguard-lab/pkg/logger"
)

const (
	cisaKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	cisaKEVSlug = "cisa_kev"
)

// CISAKEVConnector implements the source connector for CISA KEV catalog
type CISAKEVConnector struct {
	client   *http.Client
	logger   *logger.Logger
	enabled  bool
	interval time.Duration
	sourceID uuid.UUID
}

// NewCISAKEVConnector creates a new CISA KEV connector
func NewCISAKEVConnector(log *logger.Logger) *CISAKEVConnector {
	return &CISAKEVConnector{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger:   log.WithComponent("cisa_kev"),
		enabled:  true,
		interval: 24 * time.Hour, // Update daily
	}
}

// Slug returns the unique identifier for this source
func (c *CISAKEVConnector) Slug() string {
	return cisaKEVSlug
}

// IsEnabled returns whether this source is enabled
func (c *CISAKEVConnector) IsEnabled() bool {
	return c.enabled
}

// SetEnabled sets the enabled state
func (c *CISAKEVConnector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// UpdateInterval returns how often this source should be updated
func (c *CISAKEVConnector) UpdateInterval() time.Duration {
	return c.interval
}

// SetSourceID sets the database source ID
func (c *CISAKEVConnector) SetSourceID(id uuid.UUID) {
	c.sourceID = id
}

// Fetch retrieves vulnerabilities from CISA KEV catalog
func (c *CISAKEVConnector) Fetch(ctx context.Context) (*models.SourceFetchResult, error) {
	start := time.Now()
	result := &models.SourceFetchResult{
		SourceID:   c.sourceID,
		SourceSlug: cisaKEVSlug,
		FetchedAt:  start,
	}

	c.logger.Info().Msg("fetching from CISA KEV catalog")

	req, err := http.NewRequestWithContext(ctx, "GET", cisaKEVURL, nil)
	if err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, fmt.Errorf("failed to fetch CISA KEV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Errorf("CISA KEV returned status %d: %s", resp.StatusCode, string(body))
		result.Success = false
		result.Duration = time.Since(start)
		return result, result.Error
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, fmt.Errorf("failed to read response: %w", err)
	}

	var catalog cisaKEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, fmt.Errorf("failed to parse CISA KEV: %w", err)
	}

	indicators := c.parseVulnerabilities(catalog.Vulnerabilities)

	result.RawIndicators = indicators
	result.TotalFetched = len(indicators)
	result.Success = true
	result.Duration = time.Since(start)

	c.logger.Info().
		Int("total", len(indicators)).
		Str("catalog_version", catalog.CatalogVersion).
		Dur("duration", result.Duration).
		Msg("CISA KEV fetch completed")

	return result, nil
}

// parseVulnerabilities converts CISA KEV entries to raw indicators
func (c *CISAKEVConnector) parseVulnerabilities(vulns []cisaVulnerability) []models.RawIndicator {
	var indicators []models.RawIndicator

	for _, vuln := range vulns {
		// Create an indicator for the CVE itself
		indicator := models.RawIndicator{
			Value:       vuln.CVEID,
			Type:        models.IndicatorType("cve"), // Special type for CVEs
			Severity:    c.mapSeverity(vuln),
			Description: c.formatDescription(vuln),
			Tags:        c.buildTags(vuln),
			RawData: map[string]any{
				"cve_id":             vuln.CVEID,
				"vendor_project":     vuln.VendorProject,
				"product":            vuln.Product,
				"vulnerability_name": vuln.VulnerabilityName,
				"date_added":         vuln.DateAdded,
				"short_description":  vuln.ShortDescription,
				"required_action":    vuln.RequiredAction,
				"due_date":           vuln.DueDate,
				"known_ransomware":   vuln.KnownRansomwareCampaignUse,
				"notes":              vuln.Notes,
			},
		}

		// Parse date added
		if vuln.DateAdded != "" {
			if t, err := time.Parse("2006-01-02", vuln.DateAdded); err == nil {
				indicator.FirstSeen = &t
			}
		}

		// Set high confidence for CISA verified KEVs
		conf := 0.95
		indicator.Confidence = &conf

		indicators = append(indicators, indicator)
	}

	return indicators
}

// mapSeverity determines severity based on vulnerability characteristics
func (c *CISAKEVConnector) mapSeverity(vuln cisaVulnerability) models.Severity {
	// All KEV entries are critical by definition (actively exploited)
	// But ransomware campaigns get higher priority
	if strings.EqualFold(vuln.KnownRansomwareCampaignUse, "Known") {
		return models.SeverityCritical
	}

	// Check for keywords in description
	desc := strings.ToLower(vuln.ShortDescription)
	if strings.Contains(desc, "remote code execution") ||
		strings.Contains(desc, "rce") ||
		strings.Contains(desc, "arbitrary code") {
		return models.SeverityCritical
	}

	if strings.Contains(desc, "privilege escalation") ||
		strings.Contains(desc, "authentication bypass") {
		return models.SeverityHigh
	}

	// Default to high for actively exploited vulnerabilities
	return models.SeverityHigh
}

// formatDescription creates a description from the vulnerability data
func (c *CISAKEVConnector) formatDescription(vuln cisaVulnerability) string {
	parts := []string{vuln.ShortDescription}

	if vuln.VendorProject != "" && vuln.Product != "" {
		parts = append(parts, fmt.Sprintf("Affects: %s %s", vuln.VendorProject, vuln.Product))
	}

	if vuln.RequiredAction != "" {
		parts = append(parts, fmt.Sprintf("Required Action: %s", vuln.RequiredAction))
	}

	return strings.Join(parts, " | ")
}

// buildTags creates tags from the vulnerability data
func (c *CISAKEVConnector) buildTags(vuln cisaVulnerability) []string {
	tags := []string{
		"cisa-kev",
		"actively-exploited",
		"government",
	}

	if vuln.VendorProject != "" {
		tags = append(tags, strings.ToLower(vuln.VendorProject))
	}

	if strings.EqualFold(vuln.KnownRansomwareCampaignUse, "Known") {
		tags = append(tags, "ransomware")
	}

	// Detect common product categories
	product := strings.ToLower(vuln.Product)
	vendor := strings.ToLower(vuln.VendorProject)

	if strings.Contains(product, "windows") || vendor == "microsoft" {
		tags = append(tags, "windows", "microsoft")
	}
	if strings.Contains(product, "linux") || strings.Contains(product, "kernel") {
		tags = append(tags, "linux")
	}
	if strings.Contains(product, "ios") || strings.Contains(product, "iphone") {
		tags = append(tags, "ios", "mobile")
	}
	if strings.Contains(product, "android") {
		tags = append(tags, "android", "mobile")
	}
	if vendor == "apple" {
		tags = append(tags, "apple")
	}
	if vendor == "google" {
		tags = append(tags, "google")
	}

	return tags
}

// CISA KEV response structures
type cisaKEVCatalog struct {
	Title           string              `json:"title"`
	CatalogVersion  string              `json:"catalogVersion"`
	DateReleased    string              `json:"dateReleased"`
	Count           int                 `json:"count"`
	Vulnerabilities []cisaVulnerability `json:"vulnerabilities"`
}

type cisaVulnerability struct {
	CVEID                       string `json:"cveID"`
	VendorProject               string `json:"vendorProject"`
	Product                     string `json:"product"`
	VulnerabilityName           string `json:"vulnerabilityName"`
	DateAdded                   string `json:"dateAdded"`
	ShortDescription            string `json:"shortDescription"`
	RequiredAction              string `json:"requiredAction"`
	DueDate                     string `json:"dueDate"`
	KnownRansomwareCampaignUse  string `json:"knownRansomwareCampaignUse"`
	Notes                       string `json:"notes"`
}
