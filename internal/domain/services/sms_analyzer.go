package services

import (
	"context"
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

// SMSAnalyzer provides SMS/Smishing threat analysis
type SMSAnalyzer struct {
	repos                *repository.Repositories
	cache                *cache.RedisCache
	patterns             *PhishingPatterns
	impersonationDetector *ExecutiveImpersonationDetector
	logger               *logger.Logger
}

// NewSMSAnalyzer creates a new SMS analyzer
func NewSMSAnalyzer(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *SMSAnalyzer {
	return &SMSAnalyzer{
		repos:                 repos,
		cache:                 cache,
		patterns:              NewPhishingPatterns(),
		impersonationDetector: NewExecutiveImpersonationDetector(),
		logger:                log.WithComponent("sms-analyzer"),
	}
}

// SetExecutives configures known executives for impersonation detection
func (a *SMSAnalyzer) SetExecutives(executives []ExecutiveProfile) {
	a.impersonationDetector.SetExecutives(executives)
}

// SetCompanyDomains configures company domains for impersonation detection
func (a *SMSAnalyzer) SetCompanyDomains(domains []string) {
	a.impersonationDetector.SetCompanyDomains(domains)
}

// Analyze analyzes a single SMS message for threats
func (a *SMSAnalyzer) Analyze(ctx context.Context, msg *models.SMSMessage) (*models.SMSAnalysisResult, error) {
	result := &models.SMSAnalysisResult{
		ID:         uuid.New(),
		MessageID:  msg.ID,
		IsThreat:   false,
		ThreatLevel: models.ThreatLevelSafe,
		Confidence: 0,
		AnalyzedAt: time.Now(),
	}

	// 1. Extract URLs, phone numbers, emails
	result.URLs = a.extractURLs(ctx, msg.Body)
	result.PhoneNumbers = a.extractPhoneNumbers(msg.Body)
	result.Emails = a.extractEmails(msg.Body)

	// 2. Analyze sender
	result.SenderAnalysis = a.analyzeSender(msg.Sender)

	// 3. Check pattern matches
	result.PatternMatches = a.checkPatterns(msg.Body)

	// 4. Analyze intent
	result.IntentAnalysis = a.analyzeIntent(msg.Body)

	// 5. Check for executive impersonation (BEC attacks)
	a.impersonationDetector.AnalyzeSMSForImpersonation(result, msg.Sender, msg.Body)

	// 6. Calculate overall threat level (if not already set by impersonation)
	if result.ThreatType != models.SMSThreatTypeExecutiveImpersonation {
		a.calculateThreatLevel(result)
	}

	// 7. Generate recommendations
	result.Recommendations = a.generateRecommendations(result)

	return result, nil
}

// AnalyzeBatch analyzes multiple SMS messages
func (a *SMSAnalyzer) AnalyzeBatch(ctx context.Context, req *models.SMSBatchAnalysisRequest) (*models.SMSBatchAnalysisResult, error) {
	result := &models.SMSBatchAnalysisResult{
		Results:    make([]models.SMSAnalysisResult, 0, len(req.Messages)),
		TotalCount: len(req.Messages),
		AnalyzedAt: time.Now(),
	}

	for _, msg := range req.Messages {
		analysis, err := a.Analyze(ctx, &msg)
		if err != nil {
			a.logger.Warn().Err(err).Str("message_id", msg.ID.String()).Msg("failed to analyze message")
			continue
		}
		result.Results = append(result.Results, *analysis)
		if analysis.IsThreat {
			result.ThreatCount++
		}
	}

	return result, nil
}

// extractURLs extracts and analyzes URLs from message body
func (a *SMSAnalyzer) extractURLs(ctx context.Context, body string) []models.SMSExtractedURL {
	urlPattern := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+|www\.[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	matches := urlPattern.FindAllString(body, -1)

	urls := make([]models.SMSExtractedURL, 0, len(matches))
	for _, match := range matches {
		extracted := a.analyzeURL(ctx, match)
		urls = append(urls, extracted)
	}

	return urls
}

// analyzeURL analyzes a single URL for threats
func (a *SMSAnalyzer) analyzeURL(ctx context.Context, rawURL string) models.SMSExtractedURL {
	result := models.SMSExtractedURL{
		URL:        rawURL,
		Category:   models.URLCategoryUnknown,
		Confidence: 0,
	}

	// Add protocol if missing
	if strings.HasPrefix(rawURL, "www.") {
		rawURL = "https://" + rawURL
	}

	// Parse URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		result.Category = models.URLCategorySuspicious
		result.Confidence = 0.5
		return result
	}

	result.Domain = parsed.Host

	// Check if URL shortener
	result.IsShortened = a.isURLShortener(parsed.Host)

	// Check against threat intelligence database
	if a.repos != nil {
		// Check domain
		indicator, err := a.repos.Indicators.GetByValue(ctx, parsed.Host, models.IndicatorTypeDomain)
		if err == nil && indicator != nil {
			result.IsMalicious = true
			result.Category = models.URLCategoryPhishing
			result.ThreatDetails = indicator.Description
			result.Confidence = indicator.Confidence
			result.IndicatorID = indicator.ID.String()
			if indicator.CampaignID != nil {
				result.CampaignID = indicator.CampaignID.String()
			}
			return result
		}

		// Check full URL
		indicator, err = a.repos.Indicators.GetByValue(ctx, rawURL, models.IndicatorTypeURL)
		if err == nil && indicator != nil {
			result.IsMalicious = true
			result.Category = models.URLCategoryMalware
			result.ThreatDetails = indicator.Description
			result.Confidence = indicator.Confidence
			result.IndicatorID = indicator.ID.String()
			if indicator.CampaignID != nil {
				result.CampaignID = indicator.CampaignID.String()
			}
			return result
		}
	}

	// Check against phishing patterns
	if a.patterns.IsPhishingDomain(parsed.Host) {
		result.IsMalicious = true
		result.Category = models.URLCategoryPhishing
		result.Confidence = 0.8
		result.ThreatDetails = "Domain matches known phishing patterns"
		return result
	}

	// Check for suspicious URL characteristics
	suspiciousScore := a.calculateURLSuspiciousness(parsed)
	if suspiciousScore > 0.6 {
		result.Category = models.URLCategorySuspicious
		result.Confidence = suspiciousScore
	} else {
		result.Category = models.URLCategorySafe
		result.Confidence = 1 - suspiciousScore
	}

	return result
}

// isURLShortener checks if domain is a known URL shortener
func (a *SMSAnalyzer) isURLShortener(domain string) bool {
	shorteners := map[string]bool{
		"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true,
		"ow.ly": true, "is.gd": true, "buff.ly": true, "adf.ly": true,
		"j.mp": true, "rb.gy": true, "cutt.ly": true, "short.io": true,
		"rebrand.ly": true, "bl.ink": true, "soo.gd": true, "s.id": true,
		"clk.sh": true, "shorturl.at": true, "tiny.cc": true, "bc.vc": true,
	}
	return shorteners[strings.ToLower(domain)]
}

// calculateURLSuspiciousness calculates how suspicious a URL looks
func (a *SMSAnalyzer) calculateURLSuspiciousness(u *url.URL) float64 {
	score := 0.0
	host := strings.ToLower(u.Host)

	// IP address instead of domain
	if regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`).MatchString(host) {
		score += 0.4
	}

	// Unusual TLD
	unusualTLDs := []string{".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml", ".cf", ".tk", ".ga"}
	for _, tld := range unusualTLDs {
		if strings.HasSuffix(host, tld) {
			score += 0.2
			break
		}
	}

	// Homograph attack detection (mixed scripts)
	if containsMixedScripts(host) {
		score += 0.5
	}

	// Very long subdomain
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		score += 0.2
	}

	// Contains brand name as subdomain (potential typosquatting)
	brands := []string{"paypal", "amazon", "google", "apple", "microsoft", "facebook", "netflix", "bank"}
	for _, brand := range brands {
		if strings.Contains(host, brand) && !strings.HasSuffix(host, brand+".com") {
			score += 0.3
			break
		}
	}

	// Suspicious path keywords
	suspiciousPaths := []string{"login", "signin", "verify", "secure", "account", "update", "confirm", "wallet", "password"}
	pathLower := strings.ToLower(u.Path)
	for _, keyword := range suspiciousPaths {
		if strings.Contains(pathLower, keyword) {
			score += 0.1
			break
		}
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// extractPhoneNumbers extracts phone numbers from message
func (a *SMSAnalyzer) extractPhoneNumbers(body string) []string {
	// Match various phone formats
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`),
		regexp.MustCompile(`\+[0-9]{1,3}[-.\s]?[0-9]{6,14}`),
	}

	seen := make(map[string]bool)
	var phones []string

	for _, pattern := range patterns {
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			cleaned := regexp.MustCompile(`[^\d+]`).ReplaceAllString(match, "")
			if !seen[cleaned] && len(cleaned) >= 10 {
				seen[cleaned] = true
				phones = append(phones, cleaned)
			}
		}
	}

	return phones
}

// extractEmails extracts email addresses from message
func (a *SMSAnalyzer) extractEmails(body string) []string {
	pattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	return pattern.FindAllString(body, -1)
}

// analyzeSender analyzes the SMS sender
func (a *SMSAnalyzer) analyzeSender(sender string) *models.SenderAnalysis {
	analysis := &models.SenderAnalysis{
		RiskScore: 0,
	}

	// Check if short code (5-6 digits)
	if regexp.MustCompile(`^\d{5,6}$`).MatchString(sender) {
		analysis.IsShortCode = true
		// Short codes from businesses are usually legitimate
		analysis.RiskScore = 0.2
	}

	// Check if alphanumeric sender ID
	if regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(sender) && !regexp.MustCompile(`^\d+$`).MatchString(sender) {
		analysis.IsAlphanumeric = true
		// Alphanumeric IDs can be spoofed
		analysis.RiskScore = 0.4
	}

	// Check for brand spoofing
	knownBrands := map[string]string{
		"USPS":     "USPS",
		"FEDEX":    "FedEx",
		"UPS":      "UPS",
		"AMAZON":   "Amazon",
		"PAYPAL":   "PayPal",
		"NETFLIX":  "Netflix",
		"APPLE":    "Apple",
		"GOOGLE":   "Google",
		"BANKOFAMERICA": "Bank of America",
		"CHASE":    "Chase",
		"WELLS":    "Wells Fargo",
		"CITI":     "Citibank",
	}

	senderUpper := strings.ToUpper(sender)
	for pattern, brand := range knownBrands {
		if strings.Contains(senderUpper, pattern) {
			analysis.IsKnownBrand = true
			analysis.BrandName = brand
			// Could be legitimate or spoofed
			analysis.RiskScore = 0.5
			analysis.Notes = "Sender claims to be " + brand + " - verify authenticity"
			break
		}
	}

	return analysis
}

// checkPatterns checks message against known phishing patterns
func (a *SMSAnalyzer) checkPatterns(body string) []models.SMSPatternMatch {
	return a.patterns.Match(body)
}

// analyzeIntent analyzes the intent of the message
func (a *SMSAnalyzer) analyzeIntent(body string) *models.SMSIntentAnalysis {
	analysis := &models.SMSIntentAnalysis{
		PrimaryIntent:   "unknown",
		SuspiciousFlags: []string{},
	}

	bodyLower := strings.ToLower(body)

	// Urgency indicators
	urgencyWords := []string{"urgent", "immediately", "now", "asap", "expire", "today only", "limited time", "act now", "don't wait", "hurry"}
	for _, word := range urgencyWords {
		if strings.Contains(bodyLower, word) {
			analysis.Urgency += 0.2
			analysis.SuspiciousFlags = append(analysis.SuspiciousFlags, "urgency_language")
			break
		}
	}

	// Fear indicators
	fearWords := []string{"suspended", "blocked", "unauthorized", "breach", "fraud", "stolen", "hacked", "compromised", "alert", "warning", "verify your", "confirm your"}
	for _, word := range fearWords {
		if strings.Contains(bodyLower, word) {
			analysis.FearFactor += 0.25
			analysis.SuspiciousFlags = append(analysis.SuspiciousFlags, "fear_tactics")
			break
		}
	}

	// Reward indicators
	rewardWords := []string{"won", "winner", "prize", "gift", "free", "reward", "cash", "money", "bonus", "lucky"}
	for _, word := range rewardWords {
		if strings.Contains(bodyLower, word) {
			analysis.RewardPromise += 0.3
			analysis.SuspiciousFlags = append(analysis.SuspiciousFlags, "reward_promise")
			break
		}
	}

	// Action required indicators
	actionWords := []string{"click", "tap", "call", "reply", "visit", "go to", "log in", "sign in", "verify", "confirm", "update"}
	for _, word := range actionWords {
		if strings.Contains(bodyLower, word) {
			analysis.ActionRequired = true
			break
		}
	}

	// Personal data request
	personalWords := []string{"ssn", "social security", "password", "pin", "dob", "date of birth", "mother's maiden", "address"}
	for _, word := range personalWords {
		if strings.Contains(bodyLower, word) {
			analysis.PersonalData = true
			analysis.SuspiciousFlags = append(analysis.SuspiciousFlags, "personal_data_request")
			break
		}
	}

	// Financial data request
	financialWords := []string{"credit card", "debit card", "bank account", "routing number", "cvv", "expir", "billing"}
	for _, word := range financialWords {
		if strings.Contains(bodyLower, word) {
			analysis.FinancialData = true
			analysis.SuspiciousFlags = append(analysis.SuspiciousFlags, "financial_data_request")
			break
		}
	}

	// Determine primary intent
	if analysis.RewardPromise > 0.5 {
		analysis.PrimaryIntent = "prize_scam"
	} else if analysis.FearFactor > 0.5 {
		analysis.PrimaryIntent = "fear_based_phishing"
	} else if analysis.PersonalData || analysis.FinancialData {
		analysis.PrimaryIntent = "data_harvesting"
	} else if analysis.ActionRequired && analysis.Urgency > 0 {
		analysis.PrimaryIntent = "urgent_action_request"
	}

	// Cap values at 1.0
	if analysis.Urgency > 1.0 {
		analysis.Urgency = 1.0
	}
	if analysis.FearFactor > 1.0 {
		analysis.FearFactor = 1.0
	}
	if analysis.RewardPromise > 1.0 {
		analysis.RewardPromise = 1.0
	}

	return analysis
}

// calculateThreatLevel calculates overall threat level from analysis
func (a *SMSAnalyzer) calculateThreatLevel(result *models.SMSAnalysisResult) {
	score := 0.0

	// URL analysis (high weight)
	for _, u := range result.URLs {
		if u.IsMalicious {
			score += 0.5
			result.ThreatType = models.SMSThreatTypePhishing
		} else if u.Category == models.URLCategorySuspicious {
			score += 0.2
		}
		if u.IsShortened {
			score += 0.1
		}
	}

	// Pattern matches
	for _, p := range result.PatternMatches {
		score += p.Confidence * 0.3
	}

	// Sender analysis
	if result.SenderAnalysis != nil {
		score += result.SenderAnalysis.RiskScore * 0.2
		if result.SenderAnalysis.IsSpoofed {
			score += 0.3
			result.ThreatType = models.SMSThreatTypeImpersonation
		}
	}

	// Intent analysis
	if result.IntentAnalysis != nil {
		if result.IntentAnalysis.PersonalData || result.IntentAnalysis.FinancialData {
			score += 0.3
		}
		if result.IntentAnalysis.FearFactor > 0.5 {
			score += 0.2
		}
		if result.IntentAnalysis.RewardPromise > 0.5 {
			score += 0.2
			if result.ThreatType == "" {
				result.ThreatType = models.SMSThreatTypeScam
			}
		}
	}

	// Determine threat level
	result.Confidence = score
	if score >= 0.8 {
		result.ThreatLevel = models.ThreatLevelCritical
		result.IsThreat = true
		result.Description = "Critical threat detected - highly likely phishing/smishing attempt"
	} else if score >= 0.6 {
		result.ThreatLevel = models.ThreatLevelHigh
		result.IsThreat = true
		result.Description = "High threat level - message contains multiple suspicious indicators"
	} else if score >= 0.4 {
		result.ThreatLevel = models.ThreatLevelMedium
		result.IsThreat = true
		result.Description = "Medium threat level - message contains some suspicious elements"
	} else if score >= 0.2 {
		result.ThreatLevel = models.ThreatLevelLow
		result.Description = "Low threat level - minor suspicious indicators detected"
	} else {
		result.ThreatLevel = models.ThreatLevelSafe
		result.Description = "Message appears safe"
	}

	// Set threat type based on patterns if not already set
	if result.ThreatType == "" && result.IsThreat {
		result.ThreatType = models.SMSThreatTypeSmishing
	}
}

// generateRecommendations generates user recommendations
func (a *SMSAnalyzer) generateRecommendations(result *models.SMSAnalysisResult) []string {
	recommendations := []string{}

	if result.ThreatLevel == models.ThreatLevelSafe {
		return recommendations
	}

	// URL recommendations
	for _, u := range result.URLs {
		if u.IsMalicious {
			recommendations = append(recommendations, "Do NOT click the link to "+u.Domain+" - it is a known malicious domain")
		} else if u.IsShortened {
			recommendations = append(recommendations, "Be cautious - the message contains a shortened URL that hides the actual destination")
		} else if u.Category == models.URLCategorySuspicious {
			recommendations = append(recommendations, "The URL appears suspicious - do not enter any personal information")
		}
	}

	// Sender recommendations
	if result.SenderAnalysis != nil {
		if result.SenderAnalysis.IsAlphanumeric && result.SenderAnalysis.IsKnownBrand {
			recommendations = append(recommendations, "The sender claims to be "+result.SenderAnalysis.BrandName+" but this could be spoofed - contact them directly via official channels")
		}
	}

	// Intent recommendations
	if result.IntentAnalysis != nil {
		if result.IntentAnalysis.PersonalData {
			recommendations = append(recommendations, "Never share personal information (SSN, passwords, etc.) via SMS")
		}
		if result.IntentAnalysis.FinancialData {
			recommendations = append(recommendations, "Never share financial information (credit card, bank details) via SMS - legitimate companies never ask for this")
		}
		if result.IntentAnalysis.Urgency > 0.5 {
			recommendations = append(recommendations, "Be wary of urgent messages demanding immediate action - this is a common scam tactic")
		}
		if result.IntentAnalysis.RewardPromise > 0.5 {
			recommendations = append(recommendations, "Be skeptical of messages promising prizes or rewards - these are usually scams")
		}
	}

	// General recommendations
	if result.ThreatLevel == models.ThreatLevelCritical || result.ThreatLevel == models.ThreatLevelHigh {
		recommendations = append(recommendations, "Block this sender to prevent future messages")
		recommendations = append(recommendations, "Report this message as spam/phishing to your carrier")
	}

	return recommendations
}

// containsMixedScripts checks if a string contains mixed Unicode scripts
func containsMixedScripts(s string) bool {
	hasLatin := false
	hasCyrillic := false
	hasGreek := false

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLatin = true
		}
		if (r >= 0x0400 && r <= 0x04FF) { // Cyrillic
			hasCyrillic = true
		}
		if (r >= 0x0370 && r <= 0x03FF) { // Greek
			hasGreek = true
		}
	}

	return (hasLatin && hasCyrillic) || (hasLatin && hasGreek) || (hasCyrillic && hasGreek)
}
