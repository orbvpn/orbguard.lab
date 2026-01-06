package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// EntityExtractor extracts entities from text for scam analysis
type EntityExtractor struct {
	logger    *logger.Logger
	llmClient *LLMClient
}

// ExtractedEntities contains all entities extracted from content
type ExtractedEntities struct {
	URLs            []ExtractedURL         `json:"urls,omitempty"`
	Emails          []ExtractedEmail       `json:"emails,omitempty"`
	PhoneNumbers    []ExtractedPhone       `json:"phone_numbers,omitempty"`
	CryptoAddresses []ExtractedCrypto      `json:"crypto_addresses,omitempty"`
	IPAddresses     []ExtractedIP          `json:"ip_addresses,omitempty"`
	SocialMedias    []ExtractedSocialMedia `json:"social_media,omitempty"`
	BankAccounts    []ExtractedBankAccount `json:"bank_accounts,omitempty"`
	Names           []ExtractedName        `json:"names,omitempty"`
	Amounts         []ExtractedAmount      `json:"amounts,omitempty"`
	Dates           []ExtractedDate        `json:"dates,omitempty"`
	Organizations   []ExtractedOrg         `json:"organizations,omitempty"`

	// Summary statistics
	TotalEntities   int                    `json:"total_entities"`
	SuspiciousCount int                    `json:"suspicious_count"`
}

// ExtractedURL represents an extracted URL
type ExtractedURL struct {
	Raw           string   `json:"raw"`
	Normalized    string   `json:"normalized"`
	Domain        string   `json:"domain"`
	TLD           string   `json:"tld"`
	Path          string   `json:"path,omitempty"`
	QueryParams   []string `json:"query_params,omitempty"`
	IsSuspicious  bool     `json:"is_suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	IsShortened   bool     `json:"is_shortened"`
	IsIP          bool     `json:"is_ip"`
	HasPort       bool     `json:"has_port"`
	IsHTTPS       bool     `json:"is_https"`
	LooksLike     string   `json:"looks_like,omitempty"` // Brand it might be impersonating
}

// ExtractedEmail represents an extracted email address
type ExtractedEmail struct {
	Raw          string `json:"raw"`
	Local        string `json:"local"`
	Domain       string `json:"domain"`
	IsSuspicious bool   `json:"is_suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	IsDisposable bool   `json:"is_disposable"`
	IsFreemail   bool   `json:"is_freemail"`
}

// ExtractedPhone represents an extracted phone number
type ExtractedPhone struct {
	Raw          string `json:"raw"`
	Normalized   string `json:"normalized"`
	CountryCode  string `json:"country_code,omitempty"`
	NationalNum  string `json:"national_number,omitempty"`
	Type         string `json:"type,omitempty"` // mobile, landline, toll-free, premium
	IsSuspicious bool   `json:"is_suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	IsPremiumRate bool  `json:"is_premium_rate"`
}

// ExtractedCrypto represents an extracted cryptocurrency address
type ExtractedCrypto struct {
	Raw          string `json:"raw"`
	Currency     string `json:"currency"` // BTC, ETH, XRP, etc.
	AddressType  string `json:"address_type,omitempty"`
	IsSuspicious bool   `json:"is_suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
}

// ExtractedIP represents an extracted IP address
type ExtractedIP struct {
	Raw          string `json:"raw"`
	Version      int    `json:"version"` // 4 or 6
	IsPrivate    bool   `json:"is_private"`
	IsSuspicious bool   `json:"is_suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
}

// ExtractedSocialMedia represents an extracted social media handle
type ExtractedSocialMedia struct {
	Platform     string `json:"platform"`
	Handle       string `json:"handle"`
	ProfileURL   string `json:"profile_url,omitempty"`
	IsSuspicious bool   `json:"is_suspicious"`
}

// ExtractedBankAccount represents an extracted bank account number
type ExtractedBankAccount struct {
	Raw          string `json:"raw"`
	Type         string `json:"type"` // IBAN, routing, account
	Country      string `json:"country,omitempty"`
	IsSuspicious bool   `json:"is_suspicious"`
}

// ExtractedName represents an extracted person/entity name
type ExtractedName struct {
	Name         string `json:"name"`
	Type         string `json:"type"` // person, organization
	Context      string `json:"context,omitempty"`
}

// ExtractedAmount represents an extracted monetary amount
type ExtractedAmount struct {
	Raw          string  `json:"raw"`
	Value        float64 `json:"value"`
	Currency     string  `json:"currency"`
	Context      string  `json:"context,omitempty"`
	IsLarge      bool    `json:"is_large"`
}

// ExtractedDate represents an extracted date
type ExtractedDate struct {
	Raw          string `json:"raw"`
	Normalized   string `json:"normalized,omitempty"`
	IsDeadline   bool   `json:"is_deadline"`
	Context      string `json:"context,omitempty"`
}

// ExtractedOrg represents an extracted organization
type ExtractedOrg struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"` // bank, government, tech, etc.
	IsImpersonated bool `json:"is_impersonated"`
}

// NewEntityExtractor creates a new entity extractor
func NewEntityExtractor(log *logger.Logger, llmClient *LLMClient) *EntityExtractor {
	return &EntityExtractor{
		logger:    log.WithComponent("entity-extractor"),
		llmClient: llmClient,
	}
}

// Extract extracts all entities from content
func (e *EntityExtractor) Extract(ctx context.Context, content string) (*ExtractedEntities, error) {
	result := &ExtractedEntities{}

	// Rule-based extraction
	result.URLs = e.extractURLs(content)
	result.Emails = e.extractEmails(content)
	result.PhoneNumbers = e.extractPhones(content)
	result.CryptoAddresses = e.extractCryptoAddresses(content)
	result.IPAddresses = e.extractIPAddresses(content)
	result.SocialMedias = e.extractSocialMedia(content)
	result.BankAccounts = e.extractBankAccounts(content)
	result.Amounts = e.extractAmounts(content)

	// LLM-enhanced extraction for context and names
	if e.llmClient != nil {
		llmEntities, err := e.extractWithLLM(ctx, content)
		if err != nil {
			e.logger.Warn().Err(err).Msg("LLM extraction failed")
		} else {
			e.mergeLLMEntities(result, llmEntities)
		}
	}

	// Calculate statistics
	e.calculateStats(result)

	return result, nil
}

// extractURLs extracts URLs from content
func (e *EntityExtractor) extractURLs(content string) []ExtractedURL {
	var urls []ExtractedURL

	// Multiple URL patterns
	patterns := []string{
		`https?://[^\s<>"'}\]]+`,
		`www\.[^\s<>"'}\]]+`,
		`[a-zA-Z0-9][-a-zA-Z0-9]*\.(com|net|org|io|co|info|biz|xyz|online|site|app|dev)[^\s<>"'}\]]*`,
	}

	seen := make(map[string]bool)

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(content, -1)

		for _, match := range matches {
			match = strings.TrimRight(match, ".,;:!?)")

			if seen[match] {
				continue
			}
			seen[match] = true

			extractedURL := e.analyzeURL(match)
			urls = append(urls, extractedURL)
		}
	}

	return urls
}

// analyzeURL analyzes a URL for suspicious characteristics
func (e *EntityExtractor) analyzeURL(rawURL string) ExtractedURL {
	result := ExtractedURL{
		Raw: rawURL,
	}

	// Add scheme if missing
	normalizedURL := rawURL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		normalizedURL = "https://" + rawURL
	}
	result.Normalized = normalizedURL

	// Parse URL
	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		result.IsSuspicious = true
		result.SuspiciousReasons = append(result.SuspiciousReasons, "malformed_url")
		return result
	}

	result.Domain = parsed.Hostname()
	result.Path = parsed.Path
	result.IsHTTPS = parsed.Scheme == "https"

	// Extract TLD
	parts := strings.Split(result.Domain, ".")
	if len(parts) > 0 {
		result.TLD = parts[len(parts)-1]
	}

	// Extract query params
	for key := range parsed.Query() {
		result.QueryParams = append(result.QueryParams, key)
	}

	// Check if IP address
	if net.ParseIP(result.Domain) != nil {
		result.IsIP = true
		result.IsSuspicious = true
		result.SuspiciousReasons = append(result.SuspiciousReasons, "ip_address_url")
	}

	// Check for port
	if parsed.Port() != "" {
		result.HasPort = true
		port := parsed.Port()
		if port != "80" && port != "443" {
			result.IsSuspicious = true
			result.SuspiciousReasons = append(result.SuspiciousReasons, "unusual_port")
		}
	}

	// Check for URL shorteners
	shorteners := []string{
		"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
		"is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee",
		"su.pr", "bc.vc", "j.mp", "tiny.cc", "cutt.ly",
	}
	for _, shortener := range shorteners {
		if strings.Contains(result.Domain, shortener) {
			result.IsShortened = true
			result.IsSuspicious = true
			result.SuspiciousReasons = append(result.SuspiciousReasons, "shortened_url")
			break
		}
	}

	// Check for suspicious TLDs
	suspiciousTLDs := []string{"xyz", "top", "win", "loan", "click", "link", "gq", "ml", "cf", "tk", "ga"}
	for _, tld := range suspiciousTLDs {
		if result.TLD == tld {
			result.IsSuspicious = true
			result.SuspiciousReasons = append(result.SuspiciousReasons, "suspicious_tld")
			break
		}
	}

	// Check for brand impersonation (typosquatting)
	result.LooksLike = e.detectBrandImpersonation(result.Domain)
	if result.LooksLike != "" {
		result.IsSuspicious = true
		result.SuspiciousReasons = append(result.SuspiciousReasons, "possible_typosquatting")
	}

	// Check for suspicious patterns
	if strings.Contains(result.Domain, "-login") || strings.Contains(result.Domain, "login-") ||
		strings.Contains(result.Domain, "-verify") || strings.Contains(result.Domain, "secure-") ||
		strings.Contains(result.Domain, "-account") || strings.Contains(result.Domain, "update-") {
		result.IsSuspicious = true
		result.SuspiciousReasons = append(result.SuspiciousReasons, "suspicious_subdomain")
	}

	// Check for suspicious query params
	suspiciousParams := []string{"redirect", "url", "return", "next", "goto", "target"}
	for _, param := range result.QueryParams {
		for _, suspicious := range suspiciousParams {
			if strings.Contains(strings.ToLower(param), suspicious) {
				result.IsSuspicious = true
				result.SuspiciousReasons = append(result.SuspiciousReasons, "open_redirect_param")
				break
			}
		}
	}

	return result
}

// detectBrandImpersonation detects if a domain is impersonating a brand
func (e *EntityExtractor) detectBrandImpersonation(domain string) string {
	brands := map[string][]string{
		"Apple":     {"apple", "icloud", "itunes"},
		"Microsoft": {"microsoft", "outlook", "office365", "onedrive", "azure"},
		"Google":    {"google", "gmail", "youtube"},
		"Amazon":    {"amazon", "aws"},
		"PayPal":    {"paypal"},
		"Netflix":   {"netflix"},
		"Facebook":  {"facebook", "fb"},
		"Instagram": {"instagram"},
		"WhatsApp":  {"whatsapp"},
		"Chase":     {"chase"},
		"Wells Fargo": {"wellsfargo"},
		"Bank of America": {"bankofamerica", "bofa"},
		"Coinbase":  {"coinbase"},
		"Binance":   {"binance"},
	}

	domainLower := strings.ToLower(domain)

	for brand, keywords := range brands {
		for _, keyword := range keywords {
			// Check if domain contains the keyword but isn't the legitimate domain
			if strings.Contains(domainLower, keyword) {
				// Not the real domain
				legitimateDomains := map[string][]string{
					"Apple":     {"apple.com", "icloud.com", "itunes.com"},
					"Microsoft": {"microsoft.com", "outlook.com", "office.com", "live.com"},
					"Google":    {"google.com", "gmail.com", "youtube.com"},
					"Amazon":    {"amazon.com", "amazon.co.uk", "aws.amazon.com"},
					"PayPal":    {"paypal.com"},
					"Netflix":   {"netflix.com"},
					"Facebook":  {"facebook.com"},
					"Instagram": {"instagram.com"},
					"WhatsApp":  {"whatsapp.com"},
					"Chase":     {"chase.com"},
					"Wells Fargo": {"wellsfargo.com"},
					"Bank of America": {"bankofamerica.com"},
					"Coinbase":  {"coinbase.com"},
					"Binance":   {"binance.com"},
				}

				isLegit := false
				for _, legitDomain := range legitimateDomains[brand] {
					if domainLower == legitDomain || strings.HasSuffix(domainLower, "."+legitDomain) {
						isLegit = true
						break
					}
				}

				if !isLegit {
					return brand
				}
			}
		}
	}

	return ""
}

// extractEmails extracts email addresses from content
func (e *EntityExtractor) extractEmails(content string) []ExtractedEmail {
	var emails []ExtractedEmail

	pattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	matches := pattern.FindAllString(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		matchLower := strings.ToLower(match)
		if seen[matchLower] {
			continue
		}
		seen[matchLower] = true

		parts := strings.Split(matchLower, "@")
		if len(parts) != 2 {
			continue
		}

		email := ExtractedEmail{
			Raw:    match,
			Local:  parts[0],
			Domain: parts[1],
		}

		// Check for disposable email domains
		disposableDomains := []string{
			"tempmail.com", "throwaway.com", "mailinator.com", "guerrillamail.com",
			"10minutemail.com", "trashmail.com", "fakeinbox.com", "yopmail.com",
			"maildrop.cc", "temp-mail.org",
		}
		for _, d := range disposableDomains {
			if email.Domain == d {
				email.IsDisposable = true
				email.IsSuspicious = true
				email.SuspiciousReasons = append(email.SuspiciousReasons, "disposable_email")
				break
			}
		}

		// Check for free email services
		freemailDomains := []string{
			"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
			"aol.com", "protonmail.com", "icloud.com", "mail.com",
		}
		for _, d := range freemailDomains {
			if email.Domain == d {
				email.IsFreemail = true
				break
			}
		}

		// Check for suspicious local parts
		suspiciousLocals := []string{"admin", "support", "security", "verify", "account", "help"}
		for _, s := range suspiciousLocals {
			if strings.Contains(email.Local, s) && email.IsFreemail {
				email.IsSuspicious = true
				email.SuspiciousReasons = append(email.SuspiciousReasons, "impersonation_attempt")
				break
			}
		}

		emails = append(emails, email)
	}

	return emails
}

// extractPhones extracts phone numbers from content
func (e *EntityExtractor) extractPhones(content string) []ExtractedPhone {
	var phones []ExtractedPhone

	patterns := []string{
		`\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,
		`\+?[0-9]{1,3}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{4}`,
		`\+971[-.\s]?[0-9]{2}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,
		`\+44[-.\s]?[0-9]{4}[-.\s]?[0-9]{6}`,
		`\+91[-.\s]?[0-9]{10}`,
		`\+86[-.\s]?[0-9]{11}`,
	}

	seen := make(map[string]bool)

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(content, -1)

		for _, match := range matches {
			normalized := e.normalizePhone(match)
			if len(normalized) < 10 {
				continue
			}

			if seen[normalized] {
				continue
			}
			seen[normalized] = true

			phone := ExtractedPhone{
				Raw:        match,
				Normalized: normalized,
			}

			// Extract country code
			if strings.HasPrefix(normalized, "+") {
				phone.CountryCode = e.extractCountryCode(normalized)
			}

			// Check for premium rate numbers
			premiumPatterns := []string{
				"^\\+?1?900",      // US premium
				"^\\+?44?09",      // UK premium
				"^\\+?61?190",     // Australia premium
			}
			for _, p := range premiumPatterns {
				if matched, _ := regexp.MatchString(p, normalized); matched {
					phone.IsPremiumRate = true
					phone.IsSuspicious = true
					phone.SuspiciousReasons = append(phone.SuspiciousReasons, "premium_rate_number")
					break
				}
			}

			phones = append(phones, phone)
		}
	}

	return phones
}

// normalizePhone normalizes a phone number
func (e *EntityExtractor) normalizePhone(phone string) string {
	var result strings.Builder
	for _, c := range phone {
		if c == '+' && result.Len() == 0 {
			result.WriteRune(c)
		} else if unicode.IsDigit(c) {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// extractCountryCode extracts country code from phone
func (e *EntityExtractor) extractCountryCode(phone string) string {
	countryCodes := map[string]string{
		"+1":   "US/CA",
		"+44":  "UK",
		"+91":  "IN",
		"+86":  "CN",
		"+971": "UAE",
		"+966": "SA",
		"+49":  "DE",
		"+33":  "FR",
		"+81":  "JP",
		"+82":  "KR",
		"+61":  "AU",
		"+55":  "BR",
		"+52":  "MX",
		"+7":   "RU",
	}

	for code, country := range countryCodes {
		if strings.HasPrefix(phone, code) {
			return country
		}
	}
	return ""
}

// extractCryptoAddresses extracts cryptocurrency addresses
func (e *EntityExtractor) extractCryptoAddresses(content string) []ExtractedCrypto {
	var addresses []ExtractedCrypto

	cryptoPatterns := map[string]*regexp.Regexp{
		"BTC":  regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b`),
		"ETH":  regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`),
		"XRP":  regexp.MustCompile(`\br[0-9a-zA-Z]{24,34}\b`),
		"LTC":  regexp.MustCompile(`\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b`),
		"DOGE": regexp.MustCompile(`\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b`),
		"XMR":  regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`),
		"SOL":  regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`),
	}

	seen := make(map[string]bool)

	for currency, pattern := range cryptoPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true

			crypto := ExtractedCrypto{
				Raw:      match,
				Currency: currency,
			}

			// Determine address type
			if currency == "BTC" {
				if strings.HasPrefix(match, "bc1") {
					crypto.AddressType = "bech32"
				} else if strings.HasPrefix(match, "3") {
					crypto.AddressType = "p2sh"
				} else {
					crypto.AddressType = "p2pkh"
				}
			}

			// Crypto addresses in messages are suspicious by default
			crypto.IsSuspicious = true
			crypto.SuspiciousReasons = append(crypto.SuspiciousReasons, "unsolicited_crypto_address")

			addresses = append(addresses, crypto)
		}
	}

	return addresses
}

// extractIPAddresses extracts IP addresses
func (e *EntityExtractor) extractIPAddresses(content string) []ExtractedIP {
	var ips []ExtractedIP

	// IPv4 pattern
	ipv4Pattern := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// IPv6 pattern (simplified)
	ipv6Pattern := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)

	seen := make(map[string]bool)

	// Extract IPv4
	matches := ipv4Pattern.FindAllString(content, -1)
	for _, match := range matches {
		if seen[match] {
			continue
		}
		seen[match] = true

		ip := net.ParseIP(match)
		if ip == nil {
			continue
		}

		extracted := ExtractedIP{
			Raw:       match,
			Version:   4,
			IsPrivate: ip.IsPrivate() || ip.IsLoopback(),
		}

		if !extracted.IsPrivate {
			extracted.IsSuspicious = true
			extracted.SuspiciousReasons = append(extracted.SuspiciousReasons, "public_ip_in_message")
		}

		ips = append(ips, extracted)
	}

	// Extract IPv6
	matches = ipv6Pattern.FindAllString(content, -1)
	for _, match := range matches {
		if seen[match] {
			continue
		}
		seen[match] = true

		ip := net.ParseIP(match)
		if ip == nil {
			continue
		}

		extracted := ExtractedIP{
			Raw:       match,
			Version:   6,
			IsPrivate: ip.IsPrivate() || ip.IsLoopback(),
		}

		ips = append(ips, extracted)
	}

	return ips
}

// extractSocialMedia extracts social media handles
func (e *EntityExtractor) extractSocialMedia(content string) []ExtractedSocialMedia {
	var socials []ExtractedSocialMedia

	platforms := map[string]*regexp.Regexp{
		"Twitter":   regexp.MustCompile(`@([a-zA-Z0-9_]{1,15})\b`),
		"Instagram": regexp.MustCompile(`(?:instagram\.com/|@)([a-zA-Z0-9_.]{1,30})\b`),
		"Telegram":  regexp.MustCompile(`(?:t\.me/|@)([a-zA-Z0-9_]{5,32})\b`),
		"TikTok":    regexp.MustCompile(`(?:tiktok\.com/@|@)([a-zA-Z0-9_.]{1,24})\b`),
	}

	seen := make(map[string]bool)

	for platform, pattern := range platforms {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			handle := match[1]
			key := platform + ":" + handle

			if seen[key] {
				continue
			}
			seen[key] = true

			social := ExtractedSocialMedia{
				Platform: platform,
				Handle:   handle,
			}

			// Build profile URL
			switch platform {
			case "Twitter":
				social.ProfileURL = "https://twitter.com/" + handle
			case "Instagram":
				social.ProfileURL = "https://instagram.com/" + handle
			case "Telegram":
				social.ProfileURL = "https://t.me/" + handle
			case "TikTok":
				social.ProfileURL = "https://tiktok.com/@" + handle
			}

			socials = append(socials, social)
		}
	}

	return socials
}

// extractBankAccounts extracts bank account numbers
func (e *EntityExtractor) extractBankAccounts(content string) []ExtractedBankAccount {
	var accounts []ExtractedBankAccount

	// IBAN pattern
	ibanPattern := regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b`)

	// US routing number pattern
	routingPattern := regexp.MustCompile(`\b[0-9]{9}\b`)

	seen := make(map[string]bool)

	// Extract IBANs
	matches := ibanPattern.FindAllString(content, -1)
	for _, match := range matches {
		if seen[match] {
			continue
		}
		seen[match] = true

		accounts = append(accounts, ExtractedBankAccount{
			Raw:          match,
			Type:         "IBAN",
			Country:      match[:2],
			IsSuspicious: true,
		})
	}

	// Extract routing numbers (only if context suggests it's a routing number)
	if strings.Contains(strings.ToLower(content), "routing") {
		matches = routingPattern.FindAllString(content, -1)
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true

			accounts = append(accounts, ExtractedBankAccount{
				Raw:          match,
				Type:         "routing_number",
				Country:      "US",
				IsSuspicious: true,
			})
		}
	}

	return accounts
}

// extractAmounts extracts monetary amounts
func (e *EntityExtractor) extractAmounts(content string) []ExtractedAmount {
	var amounts []ExtractedAmount

	patterns := []struct {
		pattern  *regexp.Regexp
		currency string
	}{
		{regexp.MustCompile(`\$([0-9,]+(?:\.[0-9]{2})?)`), "USD"},
		{regexp.MustCompile(`€([0-9,]+(?:\.[0-9]{2})?)`), "EUR"},
		{regexp.MustCompile(`£([0-9,]+(?:\.[0-9]{2})?)`), "GBP"},
		{regexp.MustCompile(`AED\s*([0-9,]+(?:\.[0-9]{2})?)`), "AED"},
		{regexp.MustCompile(`([0-9,]+(?:\.[0-9]{2})?)\s*(?:dollars|usd)`), "USD"},
		{regexp.MustCompile(`([0-9,]+(?:\.[0-9]{2})?)\s*(?:bitcoin|btc)`), "BTC"},
	}

	seen := make(map[string]bool)

	for _, p := range patterns {
		matches := p.pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			amountStr := strings.ReplaceAll(match[1], ",", "")

			if seen[amountStr+p.currency] {
				continue
			}
			seen[amountStr+p.currency] = true

			var value float64
			fmt.Sscanf(amountStr, "%f", &value)

			amount := ExtractedAmount{
				Raw:      match[0],
				Value:    value,
				Currency: p.currency,
				IsLarge:  value >= 10000,
			}

			amounts = append(amounts, amount)
		}
	}

	return amounts
}

// extractWithLLM uses LLM for enhanced entity extraction
func (e *EntityExtractor) extractWithLLM(ctx context.Context, content string) (*ExtractedEntities, error) {
	systemPrompt := `You are an expert entity extractor. Extract all relevant entities from the text for scam detection analysis.

Provide your extraction in JSON format:
{
  "names": [{"name": "name", "type": "person|organization", "context": "how they appear"}],
  "organizations": [{"name": "name", "type": "bank|government|tech|other", "is_impersonated": boolean}],
  "dates": [{"raw": "date text", "normalized": "YYYY-MM-DD", "is_deadline": boolean, "context": "context"}],
  "additional_context": "any additional relevant context"
}`

	response, err := e.llmClient.Chat(ctx, []Message{NewTextMessage("user", content)}, systemPrompt)
	if err != nil {
		return nil, err
	}

	return e.parseLLMEntities(response)
}

// parseLLMEntities parses LLM response
func (e *EntityExtractor) parseLLMEntities(response string) (*ExtractedEntities, error) {
	result := &ExtractedEntities{}

	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return result, nil
	}

	var parsed struct {
		Names []struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Context string `json:"context"`
		} `json:"names"`
		Organizations []struct {
			Name          string `json:"name"`
			Type          string `json:"type"`
			IsImpersonated bool  `json:"is_impersonated"`
		} `json:"organizations"`
		Dates []struct {
			Raw        string `json:"raw"`
			Normalized string `json:"normalized"`
			IsDeadline bool   `json:"is_deadline"`
			Context    string `json:"context"`
		} `json:"dates"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return result, nil
	}

	for _, n := range parsed.Names {
		result.Names = append(result.Names, ExtractedName{
			Name:    n.Name,
			Type:    n.Type,
			Context: n.Context,
		})
	}

	for _, o := range parsed.Organizations {
		result.Organizations = append(result.Organizations, ExtractedOrg{
			Name:           o.Name,
			Type:           o.Type,
			IsImpersonated: o.IsImpersonated,
		})
	}

	for _, d := range parsed.Dates {
		result.Dates = append(result.Dates, ExtractedDate{
			Raw:        d.Raw,
			Normalized: d.Normalized,
			IsDeadline: d.IsDeadline,
			Context:    d.Context,
		})
	}

	return result, nil
}

// mergeLLMEntities merges LLM extracted entities
func (e *EntityExtractor) mergeLLMEntities(result *ExtractedEntities, llmResult *ExtractedEntities) {
	if llmResult == nil {
		return
	}

	result.Names = append(result.Names, llmResult.Names...)
	result.Organizations = append(result.Organizations, llmResult.Organizations...)
	result.Dates = append(result.Dates, llmResult.Dates...)
}

// calculateStats calculates entity statistics
func (e *EntityExtractor) calculateStats(result *ExtractedEntities) {
	result.TotalEntities = len(result.URLs) + len(result.Emails) + len(result.PhoneNumbers) +
		len(result.CryptoAddresses) + len(result.IPAddresses) + len(result.SocialMedias) +
		len(result.BankAccounts) + len(result.Names) + len(result.Amounts) +
		len(result.Dates) + len(result.Organizations)

	for _, url := range result.URLs {
		if url.IsSuspicious {
			result.SuspiciousCount++
		}
	}
	for _, email := range result.Emails {
		if email.IsSuspicious {
			result.SuspiciousCount++
		}
	}
	for _, phone := range result.PhoneNumbers {
		if phone.IsSuspicious {
			result.SuspiciousCount++
		}
	}
	for _, crypto := range result.CryptoAddresses {
		if crypto.IsSuspicious {
			result.SuspiciousCount++
		}
	}
	for _, ip := range result.IPAddresses {
		if ip.IsSuspicious {
			result.SuspiciousCount++
		}
	}
}

// ExtractFromRequest extracts entities from a scam analysis request
func (e *EntityExtractor) ExtractFromRequest(ctx context.Context, req *models.ScamAnalysisRequest) (*models.ExtractedEntities, error) {
	result, err := e.Extract(ctx, req.Content)
	if err != nil {
		return nil, err
	}

	// Convert to models.ExtractedEntities
	modelEntities := &models.ExtractedEntities{}

	for _, url := range result.URLs {
		modelEntities.URLs = append(modelEntities.URLs, models.URLEntity{
			URL:          url.Raw,
			Domain:       url.Domain,
			IsSuspicious: url.IsSuspicious,
			Reason:       strings.Join(url.SuspiciousReasons, ", "),
		})
	}

	for _, email := range result.Emails {
		modelEntities.Emails = append(modelEntities.Emails, models.EmailEntity{
			Email:        email.Raw,
			Domain:       email.Domain,
			IsSuspicious: email.IsSuspicious,
			Reason:       strings.Join(email.SuspiciousReasons, ", "),
		})
	}

	for _, phone := range result.PhoneNumbers {
		modelEntities.PhoneNumbers = append(modelEntities.PhoneNumbers, models.PhoneEntity{
			Number:       phone.Raw,
			CountryCode:  phone.CountryCode,
			IsSuspicious: phone.IsSuspicious,
			Reason:       strings.Join(phone.SuspiciousReasons, ", "),
		})
	}

	for _, crypto := range result.CryptoAddresses {
		modelEntities.CryptoAddresses = append(modelEntities.CryptoAddresses, models.CryptoEntity{
			Address:      crypto.Raw,
			Currency:     crypto.Currency,
			IsSuspicious: crypto.IsSuspicious,
			Reason:       strings.Join(crypto.SuspiciousReasons, ", "),
		})
	}

	return modelEntities, nil
}
