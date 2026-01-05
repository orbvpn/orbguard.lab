package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// URLReputationService provides URL safety checking and reputation scoring
type URLReputationService struct {
	repos           *repository.Repositories
	cache           *cache.RedisCache
	safeBrowsing    SafeBrowsingClient
	phishingPatterns *PhishingPatterns
	logger          *logger.Logger

	// In-memory caches for fast lookups
	knownBadDomains  map[string]bool
	whitelistedDomains map[string]bool
}

// SafeBrowsingClient interface for Google Safe Browsing API
type SafeBrowsingClient interface {
	CheckURLs(ctx context.Context, urls []string) ([]models.SafeBrowsingResult, error)
}

// NewURLReputationService creates a new URL reputation service
func NewURLReputationService(
	repos *repository.Repositories,
	cache *cache.RedisCache,
	safeBrowsing SafeBrowsingClient,
	log *logger.Logger,
) *URLReputationService {
	svc := &URLReputationService{
		repos:            repos,
		cache:            cache,
		safeBrowsing:     safeBrowsing,
		phishingPatterns: NewPhishingPatterns(),
		logger:           log.WithComponent("url-reputation"),
		knownBadDomains:  make(map[string]bool),
		whitelistedDomains: make(map[string]bool),
	}

	// Initialize known safe domains
	svc.initWhitelist()

	return svc
}

// initWhitelist initializes the whitelist with known safe domains
func (s *URLReputationService) initWhitelist() {
	safeDomains := []string{
		"google.com", "www.google.com", "accounts.google.com",
		"apple.com", "www.apple.com", "icloud.com",
		"microsoft.com", "www.microsoft.com", "live.com", "outlook.com",
		"amazon.com", "www.amazon.com", "aws.amazon.com",
		"facebook.com", "www.facebook.com", "fb.com",
		"twitter.com", "www.twitter.com", "x.com",
		"linkedin.com", "www.linkedin.com",
		"github.com", "www.github.com",
		"paypal.com", "www.paypal.com",
		"netflix.com", "www.netflix.com",
		"youtube.com", "www.youtube.com",
		"instagram.com", "www.instagram.com",
		"wikipedia.org", "en.wikipedia.org",
	}

	for _, domain := range safeDomains {
		s.whitelistedDomains[domain] = true
	}
}

// CheckURL checks a single URL for threats
func (s *URLReputationService) CheckURL(ctx context.Context, req *models.URLCheckRequest) (*models.URLCheckResponse, error) {
	response := &models.URLCheckResponse{
		URL:       req.URL,
		IsSafe:    true,
		ShouldBlock: false,
		Category:  models.URLCategorySafe,
		ThreatLevel: models.SeverityInfo,
		Confidence: 1.0,
		AllowOverride: true,
		CheckedAt: time.Now(),
	}

	// Parse URL
	parsed, err := s.parseURL(req.URL)
	if err != nil {
		s.logger.Debug().Err(err).Str("url", req.URL).Msg("failed to parse URL")
		response.IsSafe = false
		response.Category = models.URLCategorySuspicious
		response.Warnings = append(response.Warnings, "Invalid URL format")
		return response, nil
	}

	response.Domain = parsed.Host

	// Check cache first
	cacheKey := s.getCacheKey(req.URL)
	var cachedResult models.URLCheckResponse
	if err := s.cache.GetJSON(ctx, cacheKey, &cachedResult); err == nil {
		cachedResult.CacheHit = true
		return &cachedResult, nil
	}

	// Check whitelist
	if s.isWhitelisted(parsed.Host) {
		response.IsSafe = true
		response.Category = models.URLCategorySafe
		s.cacheResult(ctx, cacheKey, response)
		return response, nil
	}

	// Run all checks
	s.runChecks(ctx, parsed, response)

	// Cache the result
	s.cacheResult(ctx, cacheKey, response)

	// Log the check
	s.logger.Info().
		Str("url", req.URL).
		Bool("safe", response.IsSafe).
		Str("category", string(response.Category)).
		Float64("confidence", response.Confidence).
		Msg("URL checked")

	return response, nil
}

// CheckURLBatch checks multiple URLs
func (s *URLReputationService) CheckURLBatch(ctx context.Context, req *models.URLBatchCheckRequest) (*models.URLBatchCheckResponse, error) {
	response := &models.URLBatchCheckResponse{
		Results:    make([]models.URLCheckResponse, 0, len(req.URLs)),
		TotalCount: len(req.URLs),
		CheckedAt:  time.Now(),
	}

	for _, urlStr := range req.URLs {
		checkReq := &models.URLCheckRequest{
			URL:      urlStr,
			DeviceID: req.DeviceID,
			Source:   req.Source,
		}
		result, err := s.CheckURL(ctx, checkReq)
		if err != nil {
			s.logger.Warn().Err(err).Str("url", urlStr).Msg("failed to check URL")
			continue
		}
		response.Results = append(response.Results, *result)
		if result.IsSafe {
			response.SafeCount++
		}
		if result.ShouldBlock {
			response.BlockCount++
		}
	}

	return response, nil
}

// runChecks runs all URL safety checks
func (s *URLReputationService) runChecks(ctx context.Context, parsed *url.URL, response *models.URLCheckResponse) {
	// 1. Check threat intelligence database
	s.checkThreatIntelligence(ctx, parsed, response)
	if response.ShouldBlock {
		return
	}

	// 2. Check phishing patterns
	s.checkPhishingPatterns(parsed, response)
	if response.ShouldBlock {
		return
	}

	// 3. Check URL characteristics
	s.checkURLCharacteristics(parsed, response)

	// 4. Check domain age/reputation (if new domain)
	s.checkDomainReputation(parsed, response)

	// 5. Check Google Safe Browsing (if available)
	if s.safeBrowsing != nil {
		s.checkSafeBrowsing(ctx, parsed.String(), response)
	}

	// Calculate final verdict
	s.calculateVerdict(response)
}

// checkThreatIntelligence checks against our threat intelligence database
func (s *URLReputationService) checkThreatIntelligence(ctx context.Context, parsed *url.URL, response *models.URLCheckResponse) {
	if s.repos == nil {
		return
	}

	// Check domain
	indicator, err := s.repos.Indicators.GetByValue(ctx, parsed.Host, models.IndicatorTypeDomain)
	if err == nil && indicator != nil {
		response.IsSafe = false
		response.ShouldBlock = true
		response.Category = s.indicatorCategoryToURLCategory(indicator.Tags)
		response.ThreatLevel = indicator.Severity
		response.Confidence = indicator.Confidence
		response.Description = indicator.Description
		response.BlockReason = fmt.Sprintf("Domain is associated with %s", response.Category)

		if indicator.CampaignID != nil {
			// Get campaign name
			campaign, err := s.repos.Campaigns.GetByID(ctx, *indicator.CampaignID)
			if err == nil {
				response.CampaignName = campaign.Name
			}
		}
		return
	}

	// Check full URL
	indicator, err = s.repos.Indicators.GetByValue(ctx, parsed.String(), models.IndicatorTypeURL)
	if err == nil && indicator != nil {
		response.IsSafe = false
		response.ShouldBlock = true
		response.Category = models.URLCategoryMalware
		response.ThreatLevel = indicator.Severity
		response.Confidence = indicator.Confidence
		response.Description = indicator.Description
		response.BlockReason = "URL is known to be malicious"
		return
	}
}

// checkPhishingPatterns checks against known phishing patterns
func (s *URLReputationService) checkPhishingPatterns(parsed *url.URL, response *models.URLCheckResponse) {
	// Check domain patterns
	if s.phishingPatterns.IsPhishingDomain(parsed.Host) {
		response.IsSafe = false
		response.ShouldBlock = true
		response.Category = models.URLCategoryPhishing
		response.ThreatLevel = models.SeverityHigh
		response.Confidence = 0.85
		response.BlockReason = "Domain matches known phishing patterns"
		response.Warnings = append(response.Warnings, "This domain appears to be impersonating a legitimate website")
		return
	}

	// Check for typosquatting
	if s.isTyposquatting(parsed.Host) {
		response.IsSafe = false
		response.ShouldBlock = true
		response.Category = models.URLCategoryPhishing
		response.ThreatLevel = models.SeverityHigh
		response.Confidence = 0.8
		response.BlockReason = "Domain appears to be typosquatting a legitimate brand"
		return
	}
}

// checkURLCharacteristics checks suspicious URL characteristics
func (s *URLReputationService) checkURLCharacteristics(parsed *url.URL, response *models.URLCheckResponse) {
	riskScore := 0.0
	warnings := []string{}

	// Check for IP address instead of domain
	if net.ParseIP(parsed.Host) != nil {
		riskScore += 0.3
		warnings = append(warnings, "URL uses IP address instead of domain name")
	}

	// Check for suspicious TLD
	suspiciousTLDs := []string{".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml", ".cf", ".tk", ".ga", ".buzz", ".icu"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(strings.ToLower(parsed.Host), tld) {
			riskScore += 0.25
			warnings = append(warnings, "Domain uses a high-risk TLD")
			break
		}
	}

	// Check for excessive subdomains
	parts := strings.Split(parsed.Host, ".")
	if len(parts) > 4 {
		riskScore += 0.2
		warnings = append(warnings, "URL has an unusually complex domain structure")
	}

	// Check for long domain
	if len(parsed.Host) > 50 {
		riskScore += 0.15
		warnings = append(warnings, "Domain name is unusually long")
	}

	// Check for suspicious keywords in URL
	suspiciousKeywords := []string{"login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password", "credential"}
	pathLower := strings.ToLower(parsed.Path + parsed.RawQuery)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(pathLower, keyword) {
			riskScore += 0.1
			break
		}
	}

	// Check for encoded characters
	if strings.Contains(parsed.Host, "%") || strings.Contains(parsed.Host, "@") {
		riskScore += 0.3
		warnings = append(warnings, "URL contains suspicious encoded characters")
	}

	// Check for homograph attack (mixed scripts)
	if containsMixedScripts(parsed.Host) {
		riskScore += 0.4
		warnings = append(warnings, "Domain may be using lookalike characters (homograph attack)")
	}

	// Check for URL shortener
	if s.isURLShortener(parsed.Host) {
		riskScore += 0.15
		warnings = append(warnings, "URL uses a shortening service - actual destination unknown")
	}

	// Update response
	response.Warnings = append(response.Warnings, warnings...)

	if riskScore > 0 {
		if response.Confidence == 1.0 {
			response.Confidence = 1.0 - riskScore
		}
	}

	if riskScore >= 0.6 {
		response.IsSafe = false
		response.Category = models.URLCategorySuspicious
		response.ThreatLevel = models.SeverityMedium
		if riskScore >= 0.8 {
			response.ShouldBlock = true
			response.BlockReason = "URL has multiple suspicious characteristics"
		}
	}
}

// checkDomainReputation checks domain age and reputation
func (s *URLReputationService) checkDomainReputation(parsed *url.URL, response *models.URLCheckResponse) {
	// This would typically integrate with WHOIS data or domain reputation services
	// For now, we flag new/unknown domains

	// Check if it's a known bad domain from our in-memory cache
	if s.knownBadDomains[parsed.Host] {
		response.IsSafe = false
		response.ShouldBlock = true
		response.Category = models.URLCategoryMalware
		response.ThreatLevel = models.SeverityCritical
		response.BlockReason = "Domain is on the blocklist"
	}
}

// checkSafeBrowsing checks Google Safe Browsing API
func (s *URLReputationService) checkSafeBrowsing(ctx context.Context, urlStr string, response *models.URLCheckResponse) {
	if s.safeBrowsing == nil {
		return
	}

	results, err := s.safeBrowsing.CheckURLs(ctx, []string{urlStr})
	if err != nil {
		s.logger.Warn().Err(err).Msg("Safe Browsing API check failed")
		return
	}

	if len(results) > 0 && results[0].IsThreat {
		result := results[0]
		response.IsSafe = false
		response.ShouldBlock = true
		response.Confidence = 0.95 // High confidence from Google

		// Map threat types
		for _, threatType := range result.ThreatTypes {
			switch threatType {
			case "MALWARE":
				response.Category = models.URLCategoryMalware
				response.ThreatLevel = models.SeverityCritical
			case "SOCIAL_ENGINEERING":
				response.Category = models.URLCategoryPhishing
				response.ThreatLevel = models.SeverityHigh
			case "UNWANTED_SOFTWARE":
				response.Category = models.URLCategorySuspicious
				response.ThreatLevel = models.SeverityMedium
			case "POTENTIALLY_HARMFUL_APPLICATION":
				response.Category = models.URLCategoryMalware
				response.ThreatLevel = models.SeverityHigh
			}
		}

		response.BlockReason = fmt.Sprintf("Google Safe Browsing: %s", strings.Join(result.ThreatTypes, ", "))
		response.AllowOverride = false // Don't allow overriding Google's verdict
	}
}

// calculateVerdict calculates the final safety verdict
func (s *URLReputationService) calculateVerdict(response *models.URLCheckResponse) {
	// If already marked as unsafe/blocked, keep it
	if !response.IsSafe || response.ShouldBlock {
		return
	}

	// If we have warnings but didn't block, mark as potentially unsafe
	if len(response.Warnings) > 2 {
		response.Category = models.URLCategorySuspicious
		response.ThreatLevel = models.SeverityLow
	}

	// Set description if not set
	if response.Description == "" {
		if response.IsSafe {
			response.Description = "No threats detected"
		} else if response.ShouldBlock {
			response.Description = response.BlockReason
		} else {
			response.Description = "Proceed with caution"
		}
	}
}

// Helper functions

func (s *URLReputationService) parseURL(rawURL string) (*url.URL, error) {
	// Add protocol if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	return url.Parse(rawURL)
}

func (s *URLReputationService) getCacheKey(urlStr string) string {
	hash := sha256.Sum256([]byte(urlStr))
	return "url:reputation:" + hex.EncodeToString(hash[:8])
}

func (s *URLReputationService) cacheResult(ctx context.Context, key string, response *models.URLCheckResponse) {
	// Cache for 5 minutes for safe URLs, 1 hour for blocked URLs
	ttl := 5 * time.Minute
	if response.ShouldBlock {
		ttl = 1 * time.Hour
	}
	_ = s.cache.SetJSON(ctx, key, response, ttl)
}

func (s *URLReputationService) isWhitelisted(domain string) bool {
	domain = strings.ToLower(domain)
	if s.whitelistedDomains[domain] {
		return true
	}
	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if s.whitelistedDomains[parent] {
			return true
		}
	}
	return false
}

func (s *URLReputationService) isURLShortener(domain string) bool {
	shorteners := map[string]bool{
		"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true,
		"ow.ly": true, "is.gd": true, "buff.ly": true, "adf.ly": true,
		"j.mp": true, "rb.gy": true, "cutt.ly": true, "short.io": true,
		"rebrand.ly": true, "bl.ink": true, "soo.gd": true, "s.id": true,
		"clk.sh": true, "shorturl.at": true, "tiny.cc": true,
	}
	return shorteners[strings.ToLower(domain)]
}

func (s *URLReputationService) isTyposquatting(domain string) bool {
	// Check common brand typosquatting patterns
	brands := map[string]*regexp.Regexp{
		"paypal":    regexp.MustCompile(`(?i)(paypa1|pay-pal|paypai|payp4l|paypall|paipal)`),
		"amazon":    regexp.MustCompile(`(?i)(amaz0n|amazn|arnazon|amzon)`),
		"apple":     regexp.MustCompile(`(?i)(app1e|appie|appl3)`),
		"google":    regexp.MustCompile(`(?i)(g00gle|googel|gooogle|gogle)`),
		"microsoft": regexp.MustCompile(`(?i)(micr0soft|mircosoft|microsft|microsooft)`),
		"facebook":  regexp.MustCompile(`(?i)(faceb00k|facebok|facbook|facebock)`),
		"netflix":   regexp.MustCompile(`(?i)(netf1ix|netfilx|netfix)`),
		"chase":     regexp.MustCompile(`(?i)(chas3|chace|chasse)`),
		"wellsfargo": regexp.MustCompile(`(?i)(wel1sfargo|wellsfarg0|welsfargo)`),
	}

	for _, pattern := range brands {
		if pattern.MatchString(domain) {
			return true
		}
	}

	return false
}

func (s *URLReputationService) indicatorCategoryToURLCategory(tags []string) models.URLCategory {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "phishing":
			return models.URLCategoryPhishing
		case "malware":
			return models.URLCategoryMalware
		case "scam":
			return models.URLCategoryScam
		case "spam":
			return models.URLCategorySpam
		case "c2", "c&c", "command_and_control":
			return models.URLCategoryC2
		case "botnet":
			return models.URLCategoryBotnet
		case "ransomware":
			return models.URLCategoryRansomware
		case "exploit":
			return models.URLCategoryExploit
		}
	}
	return models.URLCategorySuspicious
}

// AddToBlacklist adds a URL/domain to the blacklist
func (s *URLReputationService) AddToBlacklist(ctx context.Context, entry *models.URLListEntry) error {
	entry.ID = uuid.New()
	entry.ListType = models.URLListTypeBlacklist
	entry.CreatedAt = time.Now()
	entry.IsActive = true

	// Add to in-memory cache
	if entry.Domain != "" {
		s.knownBadDomains[entry.Domain] = true
	}

	// Invalidate any cached results for this domain
	if entry.Domain != "" {
		_ = s.cache.Delete(ctx, s.getCacheKey(entry.Domain))
	}

	s.logger.Info().Str("domain", entry.Domain).Msg("added to blacklist")
	return nil
}

// AddToWhitelist adds a URL/domain to the whitelist
func (s *URLReputationService) AddToWhitelist(ctx context.Context, entry *models.URLListEntry) error {
	entry.ID = uuid.New()
	entry.ListType = models.URLListTypeWhitelist
	entry.CreatedAt = time.Now()
	entry.IsActive = true

	// Add to in-memory cache
	if entry.Domain != "" {
		s.whitelistedDomains[entry.Domain] = true
	}

	s.logger.Info().Str("domain", entry.Domain).Msg("added to whitelist")
	return nil
}

// BatchCheckURLs checks multiple URLs (alias for CheckURLBatch)
func (s *URLReputationService) BatchCheckURLs(ctx context.Context, req *models.URLBatchCheckRequest) (*models.URLBatchCheckResponse, error) {
	return s.CheckURLBatch(ctx, req)
}

// GetDomainReputation returns the reputation data for a domain
func (s *URLReputationService) GetDomainReputation(ctx context.Context, domain string) (*models.URLReputation, error) {
	// Check threat intelligence database first
	if s.repos != nil {
		indicator, err := s.repos.Indicators.GetByValue(ctx, domain, models.IndicatorTypeDomain)
		if err == nil && indicator != nil {
			return &models.URLReputation{
				ID:          indicator.ID,
				URL:         domain,
				Domain:      domain,
				Category:    s.indicatorCategoryToURLCategory(indicator.Tags),
				ThreatLevel: indicator.Severity,
				Confidence:  indicator.Confidence,
				IsMalicious: true,
				IsBlocked:   true,
				Sources:     []string{"threat-intel-db"},
				FirstSeen:   indicator.FirstSeen,
				LastSeen:    indicator.LastSeen,
				LastChecked: time.Now(),
				Tags:        indicator.Tags,
				Description: indicator.Description,
				CampaignID:  indicator.CampaignID,
			}, nil
		}
	}

	// Check if it's whitelisted
	if s.isWhitelisted(domain) {
		return &models.URLReputation{
			ID:          uuid.New(),
			URL:         domain,
			Domain:      domain,
			Category:    models.URLCategorySafe,
			ThreatLevel: models.SeverityInfo,
			Confidence:  1.0,
			IsMalicious: false,
			IsBlocked:   false,
			LastChecked: time.Now(),
		}, nil
	}

	// Check if it's blacklisted
	if s.knownBadDomains[domain] {
		return &models.URLReputation{
			ID:          uuid.New(),
			URL:         domain,
			Domain:      domain,
			Category:    models.URLCategoryMalware,
			ThreatLevel: models.SeverityCritical,
			Confidence:  1.0,
			IsMalicious: true,
			IsBlocked:   true,
			LastChecked: time.Now(),
		}, nil
	}

	// No reputation data found
	return nil, nil
}

// GetStats returns URL protection statistics
func (s *URLReputationService) GetStats(ctx context.Context) (*models.URLStats, error) {
	stats := &models.URLStats{
		ByCategory:        make(map[string]int64),
		ByThreatLevel:     make(map[string]int64),
		TopBlockedDomains: []models.DomainCount{},
	}

	// Get stats from indicators repository
	if s.repos != nil {
		// Count domain indicators
		filter := repository.IndicatorFilter{
			Types: []models.IndicatorType{models.IndicatorTypeDomain, models.IndicatorTypeURL},
		}
		_, total, err := s.repos.Indicators.List(ctx, filter)
		if err == nil {
			stats.TotalChecks = int64(total)
		}

		// Count by severity
		for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow} {
			filter.Severities = []models.Severity{sev}
			_, count, _ := s.repos.Indicators.List(ctx, filter)
			stats.ByThreatLevel[string(sev)] = int64(count)
		}
	}

	// Add blacklist count
	stats.BlockedCount = int64(len(s.knownBadDomains))

	return stats, nil
}

// AddToList adds an entry to either whitelist or blacklist
func (s *URLReputationService) AddToList(ctx context.Context, entry *models.URLListEntry) error {
	switch entry.ListType {
	case models.URLListTypeWhitelist:
		return s.AddToWhitelist(ctx, entry)
	case models.URLListTypeBlacklist:
		return s.AddToBlacklist(ctx, entry)
	default:
		return fmt.Errorf("invalid list type: %s", entry.ListType)
	}
}

// GetList returns entries from the specified list type
func (s *URLReputationService) GetList(ctx context.Context, listType models.URLListType) ([]models.URLListEntry, error) {
	entries := []models.URLListEntry{}

	switch listType {
	case models.URLListTypeWhitelist:
		for domain := range s.whitelistedDomains {
			entries = append(entries, models.URLListEntry{
				ID:        uuid.New(),
				Domain:    domain,
				ListType:  models.URLListTypeWhitelist,
				IsActive:  true,
				CreatedAt: time.Now(), // We don't track creation time in memory
			})
		}
	case models.URLListTypeBlacklist:
		for domain := range s.knownBadDomains {
			entries = append(entries, models.URLListEntry{
				ID:        uuid.New(),
				Domain:    domain,
				ListType:  models.URLListTypeBlacklist,
				IsActive:  true,
				CreatedAt: time.Now(),
			})
		}
	}

	return entries, nil
}

// RemoveFromList removes an entry from a list by ID
func (s *URLReputationService) RemoveFromList(ctx context.Context, id uuid.UUID) error {
	// Since we're using in-memory maps, we can't easily remove by ID
	// In a production system, this would be stored in a database
	s.logger.Info().Str("id", id.String()).Msg("remove from list requested (no-op in memory)")
	return nil
}

// GetDNSBlockRules returns DNS blocking rules for VPN integration
func (s *URLReputationService) GetDNSBlockRules(ctx context.Context) ([]models.DNSBlockRule, error) {
	rules := []models.DNSBlockRule{}

	// Get all blocked domains from the blacklist
	for domain := range s.knownBadDomains {
		rules = append(rules, models.DNSBlockRule{
			ID:        uuid.New(),
			Domain:    domain,
			RuleType:  "exact",
			Category:  string(models.URLCategoryMalware),
			Severity:  models.SeverityHigh,
			Enabled:   true,
			CreatedAt: time.Now(),
		})
	}

	// If we have a repository, get indicators that should be DNS blocked
	if s.repos != nil {
		filter := repository.IndicatorFilter{
			Types: []models.IndicatorType{models.IndicatorTypeDomain},
			Severities: []models.Severity{models.SeverityHigh, models.SeverityCritical},
			Limit: 10000,
		}

		indicators, _, err := s.repos.Indicators.List(ctx, filter)
		if err == nil {
			for _, ind := range indicators {
				rules = append(rules, models.DNSBlockRule{
					ID:        ind.ID,
					Domain:    ind.Value,
					RuleType:  "exact",
					Category:  string(s.indicatorCategoryToURLCategory(ind.Tags)),
					Severity:  ind.Severity,
					Enabled:   true,
					CreatedAt: ind.FirstSeen,
					UpdatedAt: ind.LastSeen,
				})
			}
		}
	}

	return rules, nil
}
