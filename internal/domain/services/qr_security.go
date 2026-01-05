package services

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// QRSecurityService handles QR code security analysis
type QRSecurityService struct {
	cache  *cache.RedisCache
	logger *logger.Logger

	// In-memory stats
	mu    sync.RWMutex
	stats models.QRSecurityStats

	// URL reputation service for checking URLs
	urlService *URLReputationService

	// Compiled patterns
	urlPattern      *regexp.Regexp
	emailPattern    *regexp.Regexp
	phonePattern    *regexp.Regexp
	wifiPattern     *regexp.Regexp
	geoPattern      *regexp.Regexp
	bitcoinPattern  *regexp.Regexp
	ethereumPattern *regexp.Regexp
}

// NewQRSecurityService creates a new QR security service
func NewQRSecurityService(urlService *URLReputationService, cache *cache.RedisCache, log *logger.Logger) *QRSecurityService {
	svc := &QRSecurityService{
		cache:      cache,
		logger:     log.WithComponent("qr-security"),
		urlService: urlService,
		stats: models.QRSecurityStats{
			ByContentType: make(map[string]int64),
			ByThreatLevel: make(map[string]int64),
			ByThreatType:  make(map[string]int64),
		},
	}

	// Compile patterns
	svc.urlPattern = regexp.MustCompile(`^https?://`)
	svc.emailPattern = regexp.MustCompile(`^mailto:(.+)$`)
	svc.phonePattern = regexp.MustCompile(`^tel:(.+)$`)
	svc.wifiPattern = regexp.MustCompile(`^WIFI:(.+)$`)
	svc.geoPattern = regexp.MustCompile(`^geo:(.+)$`)
	svc.bitcoinPattern = regexp.MustCompile(`^bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})`)
	svc.ethereumPattern = regexp.MustCompile(`^ethereum:(0x[a-fA-F0-9]{40})`)

	return svc
}

// AnalyzeQRCode analyzes a QR code for security threats
func (s *QRSecurityService) AnalyzeQRCode(ctx context.Context, req *models.QRScanRequest) (*models.QRScanResult, error) {
	startTime := time.Now()

	result := &models.QRScanResult{
		ID:         uuid.New(),
		RawContent: req.Content,
		ScannedAt:  time.Now(),
		Threats:    []QRThreat{},
		Warnings:   []string{},
		Recommendations: []string{},
	}

	// Parse content type
	contentType, parsedContent := s.parseContent(req.Content)
	result.ContentType = contentType
	result.ParsedContent = parsedContent

	// Analyze based on content type
	switch contentType {
	case models.QRContentURL:
		s.analyzeURL(ctx, result, parsedContent.URL)
	case models.QRContentEmail:
		s.analyzeEmail(result, parsedContent.Email)
	case models.QRContentPhone:
		s.analyzePhone(result, parsedContent.Phone)
	case models.QRContentSMS:
		s.analyzeSMS(result, parsedContent.SMS)
	case models.QRContentWiFi:
		s.analyzeWiFi(result, parsedContent.WiFi)
	case models.QRContentCrypto:
		s.analyzeCrypto(result, parsedContent.Crypto)
	case models.QRContentAppLink:
		s.analyzeAppLink(result, parsedContent.AppLink)
	default:
		s.analyzeText(result, req.Content)
	}

	// Calculate overall threat level
	result.ThreatLevel, result.ThreatScore = s.calculateThreatLevel(result.Threats)
	result.IsSafe = result.ThreatLevel == models.QRThreatSafe || result.ThreatLevel == models.QRThreatLow
	result.ShouldBlock = result.ThreatLevel == models.QRThreatCritical || result.ThreatLevel == models.QRThreatHigh

	// Add recommendations
	s.addRecommendations(result)

	result.AnalysisDuration = time.Since(startTime)

	// Update stats
	s.updateStats(result)

	return result, nil
}

// parseContent parses the QR content and determines its type
func (s *QRSecurityService) parseContent(content string) (models.QRContentType, *models.QRParsedContent) {
	parsed := &models.QRParsedContent{}
	content = strings.TrimSpace(content)

	// Check for URL
	if s.urlPattern.MatchString(content) {
		parsedURL, err := url.Parse(content)
		if err == nil {
			parsed.URL = &models.QRURLContent{
				FullURL:  content,
				Scheme:   parsedURL.Scheme,
				Host:     parsedURL.Host,
				Path:     parsedURL.Path,
				Query:    parsedURL.RawQuery,
				Fragment: parsedURL.Fragment,
			}
			return models.QRContentURL, parsed
		}
	}

	// Check for mailto:
	if matches := s.emailPattern.FindStringSubmatch(content); len(matches) > 1 {
		emailParts := strings.Split(matches[1], "?")
		email := &models.QREmailContent{Address: emailParts[0]}
		if len(emailParts) > 1 {
			params, _ := url.ParseQuery(emailParts[1])
			email.Subject = params.Get("subject")
			email.Body = params.Get("body")
		}
		parsed.Email = email
		return models.QRContentEmail, parsed
	}

	// Check for tel:
	if matches := s.phonePattern.FindStringSubmatch(content); len(matches) > 1 {
		parsed.Phone = &models.QRPhoneContent{
			Number: matches[1],
		}
		// Check for premium rate
		for _, prefix := range models.PremiumRatePrefixes {
			if strings.HasPrefix(matches[1], prefix) {
				parsed.Phone.IsPremium = true
				break
			}
		}
		return models.QRContentPhone, parsed
	}

	// Check for SMS
	if strings.HasPrefix(strings.ToLower(content), "sms:") || strings.HasPrefix(strings.ToLower(content), "smsto:") {
		parts := strings.SplitN(content[4:], ":", 2)
		sms := &models.QRSMSContent{Number: parts[0]}
		if len(parts) > 1 {
			sms.Message = parts[1]
		}
		parsed.SMS = sms
		return models.QRContentSMS, parsed
	}

	// Check for WiFi
	if s.wifiPattern.MatchString(content) {
		wifi := s.parseWiFiContent(content)
		parsed.WiFi = wifi
		return models.QRContentWiFi, parsed
	}

	// Check for geo
	if s.geoPattern.MatchString(content) {
		geo := s.parseGeoContent(content)
		if geo != nil {
			parsed.Geo = geo
			return models.QRContentGeo, parsed
		}
	}

	// Check for Bitcoin
	if s.bitcoinPattern.MatchString(content) {
		crypto := s.parseCryptoContent(content, "bitcoin")
		parsed.Crypto = crypto
		return models.QRContentCrypto, parsed
	}

	// Check for Ethereum
	if s.ethereumPattern.MatchString(content) {
		crypto := s.parseCryptoContent(content, "ethereum")
		parsed.Crypto = crypto
		return models.QRContentCrypto, parsed
	}

	// Check for app deep links
	if strings.Contains(content, "://") && !s.urlPattern.MatchString(content) {
		appLink := s.parseAppLink(content)
		parsed.AppLink = appLink
		return models.QRContentAppLink, parsed
	}

	// Check for vCard
	if strings.HasPrefix(content, "BEGIN:VCARD") {
		vcard := s.parseVCard(content)
		parsed.VCard = vcard
		return models.QRContentVCard, parsed
	}

	// Check for calendar event
	if strings.HasPrefix(content, "BEGIN:VEVENT") || strings.HasPrefix(content, "BEGIN:VCALENDAR") {
		event := s.parseEvent(content)
		parsed.Event = event
		return models.QRContentEvent, parsed
	}

	// Default to text
	parsed.Text = content
	return models.QRContentText, parsed
}

// parseWiFiContent parses WiFi QR code content
func (s *QRSecurityService) parseWiFiContent(content string) *models.QRWiFiContent {
	wifi := &models.QRWiFiContent{}

	// Format: WIFI:S:<SSID>;T:<WPA|WEP|>;P:<password>;H:<true|false>;;
	parts := strings.Split(content[5:], ";")
	for _, part := range parts {
		if strings.HasPrefix(part, "S:") {
			wifi.SSID = part[2:]
		} else if strings.HasPrefix(part, "T:") {
			wifi.Security = part[2:]
		} else if strings.HasPrefix(part, "P:") {
			wifi.Password = part[2:]
		} else if strings.HasPrefix(part, "H:") {
			wifi.Hidden = strings.ToLower(part[2:]) == "true"
		}
	}

	// Analyze security
	wifi.IsOpenNetwork = wifi.Security == "" || strings.ToLower(wifi.Security) == "nopass"
	wifi.IsWeakSecurity = strings.ToUpper(wifi.Security) == "WEP"

	return wifi
}

// parseGeoContent parses geo location QR code content
func (s *QRSecurityService) parseGeoContent(content string) *models.QRGeoContent {
	// Format: geo:<lat>,<lon> or geo:<lat>,<lon>,<alt>
	parts := strings.Split(content[4:], ",")
	if len(parts) < 2 {
		return nil
	}

	geo := &models.QRGeoContent{}
	fmt.Sscanf(parts[0], "%f", &geo.Latitude)
	fmt.Sscanf(parts[1], "%f", &geo.Longitude)
	if len(parts) > 2 {
		fmt.Sscanf(parts[2], "%f", &geo.Altitude)
	}

	return geo
}

// parseCryptoContent parses cryptocurrency QR code content
func (s *QRSecurityService) parseCryptoContent(content string, currency string) *models.QRCryptoContent {
	crypto := &models.QRCryptoContent{
		Currency: currency,
	}

	// Parse address and parameters
	var addressPart string
	if idx := strings.Index(content, ":"); idx > 0 {
		addressPart = content[idx+1:]
	}

	if idx := strings.Index(addressPart, "?"); idx > 0 {
		crypto.Address = addressPart[:idx]
		params, _ := url.ParseQuery(addressPart[idx+1:])
		if amount := params.Get("amount"); amount != "" {
			fmt.Sscanf(amount, "%f", &crypto.Amount)
		}
		crypto.Label = params.Get("label")
		crypto.Message = params.Get("message")
	} else {
		crypto.Address = addressPart
	}

	// Validate address format
	crypto.IsValidAddress = s.validateCryptoAddress(crypto.Address, currency)

	return crypto
}

// validateCryptoAddress validates a cryptocurrency address format
func (s *QRSecurityService) validateCryptoAddress(address string, currency string) bool {
	prefixes, ok := models.CryptoCurrencyPrefixes[currency]
	if !ok {
		return false
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(address, prefix) {
			// Basic length validation
			switch currency {
			case "bitcoin":
				return len(address) >= 26 && len(address) <= 62
			case "ethereum":
				return len(address) == 42
			default:
				return len(address) > 20
			}
		}
	}

	return false
}

// parseAppLink parses app deep link content
func (s *QRSecurityService) parseAppLink(content string) *models.QRAppLinkContent {
	appLink := &models.QRAppLinkContent{}

	parsed, err := url.Parse(content)
	if err != nil {
		return appLink
	}

	appLink.Scheme = parsed.Scheme
	appLink.Host = parsed.Host
	appLink.Path = parsed.Path

	// Check if known app
	if name, ok := models.KnownSafeApps[strings.ToLower(parsed.Scheme)]; ok {
		appLink.AppName = name
		appLink.IsKnownApp = true
	}

	return appLink
}

// parseVCard parses vCard content
func (s *QRSecurityService) parseVCard(content string) *models.QRVCardContent {
	vcard := &models.QRVCardContent{}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FN:") {
			vcard.Name = line[3:]
		} else if strings.HasPrefix(line, "ORG:") {
			vcard.Organization = line[4:]
		} else if strings.HasPrefix(line, "TITLE:") {
			vcard.Title = line[6:]
		} else if strings.HasPrefix(line, "TEL") {
			if idx := strings.Index(line, ":"); idx > 0 {
				vcard.Phones = append(vcard.Phones, line[idx+1:])
			}
		} else if strings.HasPrefix(line, "EMAIL") {
			if idx := strings.Index(line, ":"); idx > 0 {
				vcard.Emails = append(vcard.Emails, line[idx+1:])
			}
		} else if strings.HasPrefix(line, "URL") {
			if idx := strings.Index(line, ":"); idx > 0 {
				vcard.URLs = append(vcard.URLs, line[idx+1:])
			}
		}
	}

	return vcard
}

// parseEvent parses calendar event content
func (s *QRSecurityService) parseEvent(content string) *models.QREventContent {
	event := &models.QREventContent{}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SUMMARY:") {
			event.Summary = line[8:]
		} else if strings.HasPrefix(line, "DESCRIPTION:") {
			event.Description = line[12:]
		} else if strings.HasPrefix(line, "LOCATION:") {
			event.Location = line[9:]
		} else if strings.HasPrefix(line, "URL:") {
			event.URL = line[4:]
		}
	}

	return event
}

// analyzeURL analyzes a URL for threats
func (s *QRSecurityService) analyzeURL(ctx context.Context, result *models.QRScanResult, urlContent *models.QRURLContent) {
	if urlContent == nil {
		return
	}

	host := strings.ToLower(urlContent.Host)

	// Check for URL shorteners
	for _, shortener := range models.KnownURLShorteners {
		if strings.Contains(host, shortener) {
			result.Threats = append(result.Threats, models.QRThreat{
				Type:        models.QRThreatURLShortener,
				Severity:    "medium",
				Description: "URL uses a shortening service which may hide the actual destination",
				Evidence:    fmt.Sprintf("Shortener: %s", shortener),
			})
			result.Warnings = append(result.Warnings, "This URL uses a shortening service. The actual destination may be different.")
			break
		}
	}

	// Check for suspicious TLDs
	for _, tld := range models.SuspiciousTLDs {
		if strings.HasSuffix(host, "."+tld) {
			result.Threats = append(result.Threats, models.QRThreat{
				Type:        models.QRThreatSuspiciousTLD,
				Severity:    "medium",
				Description: "Domain uses a TLD commonly associated with malicious sites",
				Evidence:    fmt.Sprintf("TLD: .%s", tld),
			})
			result.Warnings = append(result.Warnings, fmt.Sprintf("This URL uses a .%s domain which is often used for malicious purposes.", tld))
			break
		}
	}

	// Check for IP address instead of domain
	ipPattern := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$`)
	if ipPattern.MatchString(host) {
		result.Threats = append(result.Threats, models.QRThreat{
			Type:        models.QRThreatIPAddress,
			Severity:    "high",
			Description: "URL uses an IP address instead of a domain name",
			Evidence:    fmt.Sprintf("IP: %s", host),
		})
		result.Warnings = append(result.Warnings, "This URL uses an IP address instead of a domain name, which is suspicious.")
	}

	// Check for encoded/obfuscated URLs
	if strings.Contains(urlContent.FullURL, "%") {
		decoded, _ := url.QueryUnescape(urlContent.FullURL)
		if decoded != urlContent.FullURL && strings.Count(urlContent.FullURL, "%") > 5 {
			result.Threats = append(result.Threats, models.QRThreat{
				Type:        models.QRThreatEncodedURL,
				Severity:    "medium",
				Description: "URL contains excessive encoding which may be used to hide malicious content",
				Evidence:    "Multiple URL-encoded characters detected",
			})
		}
	}

	// Check for typosquatting of popular domains
	popularDomains := map[string]string{
		"google":   "google.com",
		"facebook": "facebook.com",
		"amazon":   "amazon.com",
		"apple":    "apple.com",
		"microsoft": "microsoft.com",
		"paypal":   "paypal.com",
		"netflix":  "netflix.com",
		"instagram": "instagram.com",
	}

	for brand, legitimate := range popularDomains {
		if strings.Contains(host, brand) && !strings.Contains(host, legitimate) {
			result.Threats = append(result.Threats, models.QRThreat{
				Type:        models.QRThreatTyposquatting,
				Severity:    "high",
				Description: fmt.Sprintf("Domain may be impersonating %s", legitimate),
				Evidence:    fmt.Sprintf("Contains '%s' but is not the official domain", brand),
			})
			result.Warnings = append(result.Warnings, fmt.Sprintf("This URL may be impersonating %s. Verify before proceeding.", legitimate))
			break
		}
	}

	// Check for login/signin in path (potential phishing)
	pathLower := strings.ToLower(urlContent.Path)
	if strings.Contains(pathLower, "login") || strings.Contains(pathLower, "signin") ||
		strings.Contains(pathLower, "verify") || strings.Contains(pathLower, "account") {
		result.Warnings = append(result.Warnings, "This URL appears to be a login page. Ensure you're on the legitimate website before entering credentials.")
	}

	// Check with URL reputation service if available
	if s.urlService != nil {
		checkReq := &models.URLCheckRequest{URL: urlContent.FullURL}
		checkResult, err := s.urlService.CheckURL(ctx, checkReq)
		if err == nil && checkResult != nil {
			if checkResult.ThreatLevel == models.SeverityCritical || checkResult.ThreatLevel == models.SeverityHigh {
				result.Threats = append(result.Threats, models.QRThreat{
					Type:        models.QRThreatPhishing,
					Severity:    string(checkResult.ThreatLevel),
					Description: "URL is flagged in threat intelligence database",
					Evidence:    fmt.Sprintf("Category: %s", checkResult.Category),
				})
			}
		}
	}
}

// analyzeEmail analyzes an email address for threats
func (s *QRSecurityService) analyzeEmail(result *models.QRScanResult, email *models.QREmailContent) {
	if email == nil {
		return
	}

	// Check for suspicious keywords in subject/body
	suspiciousKeywords := []string{"urgent", "verify", "account", "suspended", "winner", "prize", "click", "immediately"}

	content := strings.ToLower(email.Subject + " " + email.Body)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(content, keyword) {
			result.Warnings = append(result.Warnings, "Email contains language commonly used in phishing attempts.")
			break
		}
	}
}

// analyzePhone analyzes a phone number for threats
func (s *QRSecurityService) analyzePhone(result *models.QRScanResult, phone *models.QRPhoneContent) {
	if phone == nil {
		return
	}

	if phone.IsPremium {
		result.Threats = append(result.Threats, models.QRThreat{
			Type:        models.QRThreatScam,
			Severity:    "high",
			Description: "This is a premium rate phone number which may incur high charges",
			Evidence:    phone.Number,
		})
		result.Warnings = append(result.Warnings, "This is a premium rate number. Calling may result in significant charges.")
	}
}

// analyzeSMS analyzes SMS content for threats
func (s *QRSecurityService) analyzeSMS(result *models.QRScanResult, sms *models.QRSMSContent) {
	if sms == nil {
		return
	}

	// Check for premium rate number
	for _, prefix := range models.PremiumRatePrefixes {
		if strings.HasPrefix(sms.Number, prefix) {
			result.Threats = append(result.Threats, models.QRThreat{
				Type:        models.QRThreatScam,
				Severity:    "high",
				Description: "SMS destination is a premium rate number",
				Evidence:    sms.Number,
			})
			result.Warnings = append(result.Warnings, "Sending SMS to this number may incur charges.")
			break
		}
	}

	// Check for suspicious message content
	if strings.Contains(strings.ToLower(sms.Message), "subscribe") ||
		strings.Contains(strings.ToLower(sms.Message), "yes") {
		result.Warnings = append(result.Warnings, "This SMS may subscribe you to a service.")
	}
}

// analyzeWiFi analyzes WiFi credentials for security issues
func (s *QRSecurityService) analyzeWiFi(result *models.QRScanResult, wifi *models.QRWiFiContent) {
	if wifi == nil {
		return
	}

	if wifi.IsOpenNetwork {
		result.Threats = append(result.Threats, models.QRThreat{
			Type:        models.QRThreatSuspiciousWiFi,
			Severity:    "high",
			Description: "This is an open WiFi network without password protection",
			Evidence:    fmt.Sprintf("SSID: %s, Security: none", wifi.SSID),
		})
		result.Warnings = append(result.Warnings, "This is an open network. Your traffic may be monitored.")
	}

	if wifi.IsWeakSecurity {
		result.Threats = append(result.Threats, models.QRThreat{
			Type:        models.QRThreatSuspiciousWiFi,
			Severity:    "medium",
			Description: "This WiFi network uses weak WEP encryption",
			Evidence:    fmt.Sprintf("SSID: %s, Security: WEP", wifi.SSID),
		})
		result.Warnings = append(result.Warnings, "This network uses outdated WEP security which can be easily cracked.")
	}

	// Check for suspicious SSID names (mimicking popular networks)
	suspiciousPatterns := []string{"free", "guest", "airport", "hotel", "starbucks", "mcdonalds"}
	ssidLower := strings.ToLower(wifi.SSID)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ssidLower, pattern) && wifi.IsOpenNetwork {
			result.Warnings = append(result.Warnings, "This may be a fake hotspot mimicking a legitimate network.")
			break
		}
	}
}

// analyzeCrypto analyzes cryptocurrency address for threats
func (s *QRSecurityService) analyzeCrypto(result *models.QRScanResult, crypto *models.QRCryptoContent) {
	if crypto == nil {
		return
	}

	if !crypto.IsValidAddress {
		result.Threats = append(result.Threats, models.QRThreat{
			Type:        models.QRThreatCryptoScam,
			Severity:    "high",
			Description: "Invalid cryptocurrency address format",
			Evidence:    crypto.Address,
		})
		result.Warnings = append(result.Warnings, "This cryptocurrency address appears to be invalid.")
	}

	// Warn about crypto transactions in general
	result.Warnings = append(result.Warnings, "Cryptocurrency transactions are irreversible. Verify the recipient address carefully.")

	if crypto.Amount > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("This QR requests %.8f %s. Verify this is the intended amount.", crypto.Amount, crypto.Currency))
	}
}

// analyzeAppLink analyzes app deep link for threats
func (s *QRSecurityService) analyzeAppLink(result *models.QRScanResult, appLink *models.QRAppLinkContent) {
	if appLink == nil {
		return
	}

	if !appLink.IsKnownApp {
		result.Warnings = append(result.Warnings, fmt.Sprintf("This QR opens an unknown app (%s://). Verify you trust this app before proceeding.", appLink.Scheme))
	}
}

// analyzeText analyzes plain text content
func (s *QRSecurityService) analyzeText(result *models.QRScanResult, text string) {
	// Check for potential URLs in text
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	if urls := urlPattern.FindAllString(text, -1); len(urls) > 0 {
		result.Warnings = append(result.Warnings, "This text contains URLs. Review them carefully before accessing.")
	}

	// Check for potential phone numbers
	phonePattern := regexp.MustCompile(`\+?[0-9]{10,15}`)
	if phones := phonePattern.FindAllString(text, -1); len(phones) > 0 {
		result.Warnings = append(result.Warnings, "This text contains phone numbers. Verify before calling.")
	}
}

// calculateThreatLevel calculates overall threat level from individual threats
func (s *QRSecurityService) calculateThreatLevel(threats []models.QRThreat) (models.QRThreatLevel, float64) {
	if len(threats) == 0 {
		return models.QRThreatSafe, 0
	}

	var score float64
	hasCritical := false
	hasHigh := false

	for _, threat := range threats {
		switch threat.Severity {
		case "critical":
			score += 40
			hasCritical = true
		case "high":
			score += 25
			hasHigh = true
		case "medium":
			score += 15
		case "low":
			score += 5
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	// Determine level
	if hasCritical || score >= 80 {
		return models.QRThreatCritical, score
	}
	if hasHigh || score >= 50 {
		return models.QRThreatHigh, score
	}
	if score >= 25 {
		return models.QRThreatMedium, score
	}
	if score > 0 {
		return models.QRThreatLow, score
	}

	return models.QRThreatSafe, 0
}

// addRecommendations adds contextual recommendations to the result
func (s *QRSecurityService) addRecommendations(result *models.QRScanResult) {
	switch result.ThreatLevel {
	case models.QRThreatCritical:
		result.Recommendations = append(result.Recommendations, "Do not proceed with this QR code")
		result.Recommendations = append(result.Recommendations, "This QR code contains known malicious content")
	case models.QRThreatHigh:
		result.Recommendations = append(result.Recommendations, "Exercise extreme caution")
		result.Recommendations = append(result.Recommendations, "Verify the source of this QR code before proceeding")
	case models.QRThreatMedium:
		result.Recommendations = append(result.Recommendations, "Proceed with caution")
		result.Recommendations = append(result.Recommendations, "Double-check the destination before entering any information")
	case models.QRThreatLow:
		result.Recommendations = append(result.Recommendations, "Minor concerns detected")
		result.Recommendations = append(result.Recommendations, "Review the warnings before proceeding")
	case models.QRThreatSafe:
		result.Recommendations = append(result.Recommendations, "No threats detected")
		result.Recommendations = append(result.Recommendations, "Always verify URLs before entering sensitive information")
	}

	// Content-specific recommendations
	switch result.ContentType {
	case models.QRContentURL:
		result.Recommendations = append(result.Recommendations, "Check the URL carefully before clicking")
	case models.QRContentWiFi:
		result.Recommendations = append(result.Recommendations, "Use a VPN when connecting to public WiFi networks")
	case models.QRContentCrypto:
		result.Recommendations = append(result.Recommendations, "Triple-check the wallet address before sending funds")
	}
}

// updateStats updates internal statistics
func (s *QRSecurityService) updateStats(result *models.QRScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.TotalScans++
	s.stats.ByContentType[string(result.ContentType)]++
	s.stats.ByThreatLevel[string(result.ThreatLevel)]++

	for _, threat := range result.Threats {
		s.stats.ByThreatType[string(threat.Type)]++
	}

	if result.ShouldBlock {
		s.stats.ThreatsBlocked++
	}

	s.stats.Last24Hours++
	s.stats.Last7Days++
}

// GetStats returns QR security statistics
func (s *QRSecurityService) GetStats() *models.QRSecurityStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy
	stats := s.stats
	stats.ByContentType = make(map[string]int64)
	stats.ByThreatLevel = make(map[string]int64)
	stats.ByThreatType = make(map[string]int64)

	for k, v := range s.stats.ByContentType {
		stats.ByContentType[k] = v
	}
	for k, v := range s.stats.ByThreatLevel {
		stats.ByThreatLevel[k] = v
	}
	for k, v := range s.stats.ByThreatType {
		stats.ByThreatType[k] = v
	}

	return &stats
}

// GetContentTypes returns all supported QR content types
func (s *QRSecurityService) GetContentTypes() []models.QRContentType {
	return []models.QRContentType{
		models.QRContentURL,
		models.QRContentText,
		models.QRContentEmail,
		models.QRContentPhone,
		models.QRContentSMS,
		models.QRContentWiFi,
		models.QRContentVCard,
		models.QRContentGeo,
		models.QRContentEvent,
		models.QRContentCrypto,
		models.QRContentAppLink,
	}
}

// GetThreatTypes returns all QR threat types
func (s *QRSecurityService) GetThreatTypes() []models.QRThreatType {
	return []models.QRThreatType{
		models.QRThreatPhishing,
		models.QRThreatMalware,
		models.QRThreatScam,
		models.QRThreatCryptoScam,
		models.QRThreatFakeLogin,
		models.QRThreatDataHarvesting,
		models.QRThreatMaliciousRedirect,
		models.QRThreatSuspiciousWiFi,
		models.QRThreatTyposquatting,
		models.QRThreatURLShortener,
		models.QRThreatSuspiciousTLD,
		models.QRThreatIPAddress,
		models.QRThreatEncodedURL,
	}
}

// QRThreat type alias for models
type QRThreat = models.QRThreat
