package digital_footprint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/brokers"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// BrokerScanner scans data brokers for personal information
type BrokerScanner struct {
	brokerDB   *brokers.BrokerDatabase
	httpClient *http.Client
	cache      *cache.RedisCache
	logger     *logger.Logger

	// Configuration
	maxConcurrent  int
	requestTimeout time.Duration
}

// BrokerScanRequest contains information to search for
type BrokerScanRequest struct {
	Email     string
	Phone     string
	FirstName string
	LastName  string
	FullName  string
	Addresses []models.AddressInfo
}

// NewBrokerScanner creates a new broker scanner
func NewBrokerScanner(brokerDB *brokers.BrokerDatabase, redisCache *cache.RedisCache, log *logger.Logger) *BrokerScanner {
	return &BrokerScanner{
		brokerDB: brokerDB,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cache:          redisCache,
		logger:         log.WithComponent("broker-scanner"),
		maxConcurrent:  5,
		requestTimeout: 15 * time.Second,
	}
}

// Scan checks multiple data brokers for the user's information
func (s *BrokerScanner) Scan(ctx context.Context, req BrokerScanRequest) ([]models.BrokerFinding, []models.DataExposure, error) {
	// Get priority brokers to scan
	allBrokers := s.brokerDB.GetAllBrokers()

	// Sort by priority (higher priority first) and filter to top brokers
	var priorityBrokers []*models.DataBroker
	for _, b := range allBrokers {
		if b.Priority >= 70 { // Only scan high-priority brokers
			priorityBrokers = append(priorityBrokers, b)
		}
	}

	s.logger.Info().
		Int("total_brokers", len(allBrokers)).
		Int("scanning", len(priorityBrokers)).
		Msg("starting broker scan")

	var findings []models.BrokerFinding
	var exposures []models.DataExposure
	var mu sync.Mutex

	// Use semaphore for concurrency control
	sem := make(chan struct{}, s.maxConcurrent)
	var wg sync.WaitGroup

	for _, broker := range priorityBrokers {
		broker := broker // capture
		wg.Add(1)

		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			finding, brokerExposures, err := s.checkBroker(ctx, broker, req)
			if err != nil {
				s.logger.Debug().
					Err(err).
					Str("broker", broker.Name).
					Msg("broker check failed")
				return
			}

			if finding != nil && finding.Found {
				mu.Lock()
				findings = append(findings, *finding)
				exposures = append(exposures, brokerExposures...)
				mu.Unlock()

				s.logger.Info().
					Str("broker", broker.Name).
					Int("data_types", len(finding.DataTypes)).
					Msg("found data on broker")
			}
		}()
	}

	wg.Wait()

	return findings, exposures, nil
}

// checkBroker checks a single broker for the user's information
func (s *BrokerScanner) checkBroker(ctx context.Context, broker *models.DataBroker, req BrokerScanRequest) (*models.BrokerFinding, []models.DataExposure, error) {
	// Check cache first
	cacheKey := s.getCacheKey(broker.Domain, req)
	if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		var finding models.BrokerFinding
		if err := json.Unmarshal([]byte(cached), &finding); err == nil {
			return &finding, nil, nil
		}
	}

	// Build search URL based on broker
	searchURL := s.buildSearchURL(broker, req)
	if searchURL == "" {
		return nil, nil, fmt.Errorf("no search URL available for %s", broker.Name)
	}

	// Make request with timeout
	reqCtx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "GET", searchURL, nil)
	if err != nil {
		return nil, nil, err
	}

	// Set headers to appear as a browser
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
	if err != nil {
		return nil, nil, err
	}

	// Analyze response for profile indicators
	found, profileURL, dataTypes, preview := s.analyzeResponse(broker, string(body), req)

	finding := &models.BrokerFinding{
		BrokerID:         broker.ID,
		BrokerName:       broker.Name,
		BrokerURL:        broker.SiteURL,
		Category:         string(broker.Category),
		ProfileURL:       profileURL,
		DataTypes:        dataTypes,
		DataPreview:      preview,
		OptOutURL:        broker.OptOutURL,
		OptOutMethod:     string(broker.OptOutMethod),
		OptOutDifficulty: string(broker.OptOutDifficulty),
		EstimatedDays:    broker.ProcessingDays,
		CanAutoRemove:    broker.CanAutomate,
		Found:            found,
		FoundAt:          time.Now(),
	}

	// Generate exposures for found data
	var exposures []models.DataExposure
	if found {
		for _, dt := range dataTypes {
			exposure := models.DataExposure{
				ID:           uuid.New(),
				Type:         dt,
				Severity:     s.getSeverityForType(dt),
				Source:       models.ExposureSourceDataBroker,
				SourceName:   broker.Name,
				SourceURL:    profileURL,
				ExposedValue: s.getRedactedPreview(preview, dt),
				Context:      fmt.Sprintf("Found on %s people search", broker.Name),
				FirstSeen:    time.Now(),
				LastSeen:     time.Now(),
				CanAutoRemove: broker.CanAutomate,
				CreatedAt:    time.Now(),
			}
			exposures = append(exposures, exposure)
		}
	}

	// Cache result
	if data, err := json.Marshal(finding); err == nil {
		_ = s.cache.Set(ctx, cacheKey, string(data), 24*time.Hour)
	}

	return finding, exposures, nil
}

// buildSearchURL builds a search URL for the broker
func (s *BrokerScanner) buildSearchURL(broker *models.DataBroker, req BrokerScanRequest) string {
	// Use the broker's search URL if available
	if broker.SearchURL != "" {
		searchURL := broker.SearchURL

		// Replace placeholders
		if req.FullName != "" {
			searchURL = strings.ReplaceAll(searchURL, "{name}", url.QueryEscape(req.FullName))
		} else if req.FirstName != "" && req.LastName != "" {
			searchURL = strings.ReplaceAll(searchURL, "{name}", url.QueryEscape(req.FirstName+" "+req.LastName))
			searchURL = strings.ReplaceAll(searchURL, "{first}", url.QueryEscape(req.FirstName))
			searchURL = strings.ReplaceAll(searchURL, "{last}", url.QueryEscape(req.LastName))
		}

		if len(req.Addresses) > 0 {
			addr := req.Addresses[0]
			searchURL = strings.ReplaceAll(searchURL, "{city}", url.QueryEscape(addr.City))
			searchURL = strings.ReplaceAll(searchURL, "{state}", url.QueryEscape(addr.State))
		}

		return searchURL
	}

	// Build default search URL based on broker patterns
	switch broker.Domain {
	case "spokeo.com":
		if req.FirstName != "" && req.LastName != "" {
			return fmt.Sprintf("https://www.spokeo.com/%s-%s", url.PathEscape(req.FirstName), url.PathEscape(req.LastName))
		}
	case "beenverified.com":
		if req.FirstName != "" && req.LastName != "" {
			return fmt.Sprintf("https://www.beenverified.com/people/%s-%s/", url.PathEscape(req.FirstName), url.PathEscape(req.LastName))
		}
	case "whitepages.com":
		if req.FirstName != "" && req.LastName != "" {
			return fmt.Sprintf("https://www.whitepages.com/name/%s-%s", url.PathEscape(req.FirstName), url.PathEscape(req.LastName))
		}
	case "truepeoplesearch.com":
		if req.FirstName != "" && req.LastName != "" {
			return fmt.Sprintf("https://www.truepeoplesearch.com/results?name=%s%%20%s", url.QueryEscape(req.FirstName), url.QueryEscape(req.LastName))
		}
	case "fastpeoplesearch.com":
		if req.FirstName != "" && req.LastName != "" {
			return fmt.Sprintf("https://www.fastpeoplesearch.com/name/%s-%s", url.PathEscape(strings.ToLower(req.FirstName)), url.PathEscape(strings.ToLower(req.LastName)))
		}
	default:
		// Try generic search pattern
		if req.FirstName != "" && req.LastName != "" {
			return fmt.Sprintf("https://%s/search?q=%s+%s", broker.Domain, url.QueryEscape(req.FirstName), url.QueryEscape(req.LastName))
		}
	}

	return ""
}

// analyzeResponse analyzes the HTTP response for profile indicators
func (s *BrokerScanner) analyzeResponse(broker *models.DataBroker, body string, req BrokerScanRequest) (found bool, profileURL string, dataTypes []models.ExposureType, preview map[string]string) {
	preview = make(map[string]string)
	bodyLower := strings.ToLower(body)

	// Check for common "no results" indicators
	noResultPatterns := []string{
		"no results found",
		"no records found",
		"we couldn't find",
		"no matches found",
		"0 results",
		"zero results",
		"try a different search",
		"no people found",
	}

	for _, pattern := range noResultPatterns {
		if strings.Contains(bodyLower, pattern) {
			return false, "", nil, nil
		}
	}

	// Check for profile indicators
	profileIndicators := []string{
		"view full report",
		"see full profile",
		"full background check",
		"view details",
		"see full results",
		"unlock report",
		"view profile",
	}

	hasProfile := false
	for _, indicator := range profileIndicators {
		if strings.Contains(bodyLower, indicator) {
			hasProfile = true
			break
		}
	}

	// Check for name match
	nameMatch := false
	if req.FullName != "" {
		nameMatch = strings.Contains(bodyLower, strings.ToLower(req.FullName))
	} else if req.FirstName != "" && req.LastName != "" {
		nameMatch = strings.Contains(bodyLower, strings.ToLower(req.FirstName)) &&
			strings.Contains(bodyLower, strings.ToLower(req.LastName))
	}

	// If we have profile indicators and name match, consider it found
	found = hasProfile && nameMatch

	if !found {
		return false, "", nil, nil
	}

	// Extract data types that might be exposed
	dataTypes = broker.DataTypes

	// Try to extract preview data using regex patterns
	if req.FirstName != "" && req.LastName != "" {
		preview["name"] = req.FirstName + " " + req.LastName[:1] + "."
	}

	// Look for age patterns
	ageRegex := regexp.MustCompile(`(?i)age[:\s]+(\d{1,3})`)
	if matches := ageRegex.FindStringSubmatch(body); len(matches) > 1 {
		preview["age"] = matches[1]
	}

	// Look for city/state patterns
	cityStateRegex := regexp.MustCompile(`(?i)([A-Za-z\s]+),\s*([A-Z]{2})\s*\d{5}`)
	if matches := cityStateRegex.FindStringSubmatch(body); len(matches) > 2 {
		preview["location"] = matches[1] + ", " + matches[2]
	}

	// Extract profile URL if possible
	profileURLRegex := regexp.MustCompile(`(?i)href=["']([^"']*(?:profile|view|report)[^"']*)["']`)
	if matches := profileURLRegex.FindStringSubmatch(body); len(matches) > 1 {
		profileURL = matches[1]
		if !strings.HasPrefix(profileURL, "http") {
			profileURL = "https://" + broker.Domain + profileURL
		}
	}

	return found, profileURL, dataTypes, preview
}

// getSeverityForType returns severity for exposure type
func (s *BrokerScanner) getSeverityForType(t models.ExposureType) models.ExposureSeverity {
	switch t {
	case models.ExposureTypeSSN, models.ExposureTypePassword, models.ExposureTypeCreditCard, models.ExposureTypeBankAccount:
		return models.ExposureSeverityCritical
	case models.ExposureTypeAddress, models.ExposureTypeDateOfBirth, models.ExposureTypePhone, models.ExposureTypeDriverLicense:
		return models.ExposureSeverityHigh
	case models.ExposureTypeEmail, models.ExposureTypeEmployment, models.ExposureTypeEducation, models.ExposureTypeRelatives:
		return models.ExposureSeverityMedium
	case models.ExposureTypeName, models.ExposureTypeUsername:
		return models.ExposureSeverityLow
	default:
		return models.ExposureSeverityInfo
	}
}

// getRedactedPreview gets a redacted preview value
func (s *BrokerScanner) getRedactedPreview(preview map[string]string, t models.ExposureType) string {
	switch t {
	case models.ExposureTypeName:
		if v, ok := preview["name"]; ok {
			return v
		}
		return "Name found"
	case models.ExposureTypeAddress:
		if v, ok := preview["location"]; ok {
			return v
		}
		return "Address found"
	case models.ExposureTypeDateOfBirth:
		if v, ok := preview["age"]; ok {
			return "Age: " + v
		}
		return "DOB found"
	default:
		return string(t) + " found"
	}
}

// getCacheKey generates a cache key for the search
func (s *BrokerScanner) getCacheKey(domain string, req BrokerScanRequest) string {
	// Create a deterministic key from the search parameters
	key := fmt.Sprintf("broker:%s:%s:%s:%s",
		domain,
		strings.ToLower(req.FirstName),
		strings.ToLower(req.LastName),
		strings.ToLower(req.Email),
	)
	return key
}

// ScanSingleBroker scans a single broker
func (s *BrokerScanner) ScanSingleBroker(ctx context.Context, brokerID uuid.UUID, req BrokerScanRequest) (*models.BrokerFinding, []models.DataExposure, error) {
	broker := s.brokerDB.GetBroker(brokerID)
	if broker == nil {
		return nil, nil, fmt.Errorf("broker not found: %s", brokerID)
	}

	return s.checkBroker(ctx, broker, req)
}

// GetOptOutInstructions returns detailed opt-out instructions for a broker
func (s *BrokerScanner) GetOptOutInstructions(brokerID uuid.UUID) (*OptOutInstructions, error) {
	broker := s.brokerDB.GetBroker(brokerID)
	if broker == nil {
		return nil, fmt.Errorf("broker not found: %s", brokerID)
	}

	return &OptOutInstructions{
		BrokerName:       broker.Name,
		Method:           string(broker.OptOutMethod),
		Difficulty:       string(broker.OptOutDifficulty),
		EstimatedDays:    broker.ProcessingDays,
		OptOutURL:        broker.OptOutURL,
		Steps:            broker.OptOutSteps,
		RequiresID:       broker.RequiresID,
		RequiresAccount:  broker.RequiresAccount,
		CanAutomate:      broker.CanAutomate,
		CCPACompliant:    broker.CCPACompliant,
		GDPRCompliant:    broker.GDPRCompliant,
	}, nil
}

// OptOutInstructions contains detailed opt-out information
type OptOutInstructions struct {
	BrokerName       string   `json:"broker_name"`
	Method           string   `json:"method"`
	Difficulty       string   `json:"difficulty"`
	EstimatedDays    int      `json:"estimated_days"`
	OptOutURL        string   `json:"opt_out_url"`
	Steps            []string `json:"steps"`
	RequiresID       bool     `json:"requires_id"`
	RequiresAccount  bool     `json:"requires_account"`
	CanAutomate      bool     `json:"can_automate"`
	CCPACompliant    bool     `json:"ccpa_compliant"`
	GDPRCompliant    bool     `json:"gdpr_compliant"`
}
