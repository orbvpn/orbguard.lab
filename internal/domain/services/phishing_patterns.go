package services

import (
	"regexp"
	"strings"

	"orbguard-lab/internal/domain/models"
)

// PhishingPatterns contains compiled patterns for detecting phishing/smishing
type PhishingPatterns struct {
	textPatterns    []TextPattern
	domainPatterns  []DomainPattern
	senderPatterns  []SenderPattern
}

// TextPattern represents a pattern to match in SMS text
type TextPattern struct {
	Name        string
	Type        string
	Pattern     *regexp.Regexp
	Confidence  float64
	Description string
}

// DomainPattern represents a pattern for suspicious domains
type DomainPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Confidence  float64
	Description string
}

// SenderPattern represents a pattern for suspicious senders
type SenderPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Confidence  float64
	Description string
}

// NewPhishingPatterns creates a new PhishingPatterns with default patterns
func NewPhishingPatterns() *PhishingPatterns {
	p := &PhishingPatterns{}
	p.initTextPatterns()
	p.initDomainPatterns()
	p.initSenderPatterns()
	return p
}

// initTextPatterns initializes text-based detection patterns
func (p *PhishingPatterns) initTextPatterns() {
	p.textPatterns = []TextPattern{
		// Delivery scams
		{
			Name:        "usps_delivery_scam",
			Type:        "delivery_scam",
			Pattern:     regexp.MustCompile(`(?i)(usps|ups|fedex|dhl|amazon).*(delivery|package|parcel).*(failed|pending|on hold|reschedule|update|track).*(click|tap|visit|http)`),
			Confidence:  0.85,
			Description: "Fake delivery notification with link",
		},
		{
			Name:        "package_notification",
			Type:        "delivery_scam",
			Pattern:     regexp.MustCompile(`(?i)your (package|parcel|order|delivery).*(has been|was|is).*(held|delayed|stopped|returned).*(click|confirm|verify)`),
			Confidence:  0.8,
			Description: "Fake package notification requesting action",
		},

		// Banking scams
		{
			Name:        "bank_alert_scam",
			Type:        "bank_fraud",
			Pattern:     regexp.MustCompile(`(?i)(bank|account|card).*(suspend|block|limit|unusual|unauthorized|fraud).*(verify|confirm|secure|click|call)`),
			Confidence:  0.9,
			Description: "Fake bank security alert",
		},
		{
			Name:        "payment_failed",
			Type:        "bank_fraud",
			Pattern:     regexp.MustCompile(`(?i)(payment|transaction|transfer).*(fail|decline|reject|unsuccessful).*(update|verify|confirm).*(card|account|billing)`),
			Confidence:  0.85,
			Description: "Fake payment failure requesting card update",
		},

		// Account verification scams
		{
			Name:        "verify_account",
			Type:        "phishing",
			Pattern:     regexp.MustCompile(`(?i)(verify|confirm|update|validate) your (account|identity|information).*(click|tap|visit|http)`),
			Confidence:  0.75,
			Description: "Request to verify account via link",
		},
		{
			Name:        "account_locked",
			Type:        "phishing",
			Pattern:     regexp.MustCompile(`(?i)your (account|access).*(locked|suspended|disabled|restricted).*(click|unlock|verify|restore)`),
			Confidence:  0.85,
			Description: "Fake account lockout notification",
		},

		// Prize/lottery scams
		{
			Name:        "prize_winner",
			Type:        "scam",
			Pattern:     regexp.MustCompile(`(?i)(congrat|winner|won|selected|chosen).*(prize|gift|reward|cash|lottery|sweepstakes).*(\$|dollar|claim|collect)`),
			Confidence:  0.9,
			Description: "Fake prize or lottery win notification",
		},
		{
			Name:        "free_gift",
			Type:        "scam",
			Pattern:     regexp.MustCompile(`(?i)free\s+(gift|iphone|samsung|ipad|airpods|tv|ps5).*(click|claim|get yours|visit)`),
			Confidence:  0.85,
			Description: "Fake free gift offer",
		},

		// IRS/Tax scams
		{
			Name:        "irs_scam",
			Type:        "impersonation",
			Pattern:     regexp.MustCompile(`(?i)(irs|internal revenue|tax refund|stimulus).*(verify|confirm|claim|pending|lawsuit|arrest)`),
			Confidence:  0.9,
			Description: "Fake IRS/tax authority notification",
		},

		// Tech support scams
		{
			Name:        "tech_support_scam",
			Type:        "tech_support_scam",
			Pattern:     regexp.MustCompile(`(?i)(virus|malware|hacked|compromised).*(detected|found|on your).*(call|contact|visit|click)`),
			Confidence:  0.85,
			Description: "Fake tech support alert",
		},

		// COVID/health scams
		{
			Name:        "covid_scam",
			Type:        "scam",
			Pattern:     regexp.MustCompile(`(?i)(covid|vaccine|booster|health\s*care).*(appointment|schedule|verify|confirm).*(click|visit|http)`),
			Confidence:  0.7,
			Description: "Fake health/vaccine notification",
		},

		// Employment scams
		{
			Name:        "job_scam",
			Type:        "scam",
			Pattern:     regexp.MustCompile(`(?i)(job offer|work from home|earn \$\d+|make money).*(click|apply|reply|visit)`),
			Confidence:  0.75,
			Description: "Fake job offer or work from home scam",
		},

		// Netflix/streaming scams
		{
			Name:        "streaming_scam",
			Type:        "phishing",
			Pattern:     regexp.MustCompile(`(?i)(netflix|hulu|disney|spotify|amazon prime).*(suspend|cancel|expire|update|payment).*(click|verify|http)`),
			Confidence:  0.85,
			Description: "Fake streaming service notification",
		},

		// OTP/2FA interception
		{
			Name:        "otp_phishing",
			Type:        "phishing",
			Pattern:     regexp.MustCompile(`(?i)(verification code|otp|one.?time).*(share|send|forward|reply)`),
			Confidence:  0.8,
			Description: "Attempt to intercept one-time passwords",
		},

		// Romance/dating scams
		{
			Name:        "dating_scam",
			Type:        "scam",
			Pattern:     regexp.MustCompile(`(?i)(lonely|looking for|meet|date|singles in your area).*(click|visit|http)`),
			Confidence:  0.7,
			Description: "Dating/romance scam message",
		},

		// Cryptocurrency scams
		{
			Name:        "crypto_scam",
			Type:        "scam",
			Pattern:     regexp.MustCompile(`(?i)(bitcoin|btc|crypto|ethereum|nft).*(invest|profit|double|free|giveaway|elon)`),
			Confidence:  0.85,
			Description: "Cryptocurrency scam",
		},

		// Premium rate numbers
		{
			Name:        "premium_rate",
			Type:        "premium_rate",
			Pattern:     regexp.MustCompile(`(?i)(call|text|reply).*(900|976|\$\d+\s*per\s*(min|call|text)|premium)`),
			Confidence:  0.8,
			Description: "Premium rate number scam",
		},

		// Generic urgent action
		{
			Name:        "urgent_action",
			Type:        "smishing",
			Pattern:     regexp.MustCompile(`(?i)(urgent|immediate|asap|expires? (today|now|soon)|last chance|final warning).*(click|act|call|verify|confirm)`),
			Confidence:  0.65,
			Description: "Message uses urgency tactics",
		},
	}
}

// initDomainPatterns initializes domain-based patterns
func (p *PhishingPatterns) initDomainPatterns() {
	p.domainPatterns = []DomainPattern{
		// Typosquatting patterns for major brands
		{
			Name:        "paypal_typo",
			Pattern:     regexp.MustCompile(`(?i)(paypa1|pay-pal|paypai|payp4l|paypall|paipal)\.`),
			Confidence:  0.9,
			Description: "PayPal typosquatting domain",
		},
		{
			Name:        "amazon_typo",
			Pattern:     regexp.MustCompile(`(?i)(amaz0n|amazn|arnazon|amzon|amazon-[a-z]+)\.(com|net|org)`),
			Confidence:  0.9,
			Description: "Amazon typosquatting domain",
		},
		{
			Name:        "apple_typo",
			Pattern:     regexp.MustCompile(`(?i)(app1e|appie|appl3|apple-[a-z]+)\.(com|net|org)`),
			Confidence:  0.9,
			Description: "Apple typosquatting domain",
		},
		{
			Name:        "microsoft_typo",
			Pattern:     regexp.MustCompile(`(?i)(micr0soft|mircosoft|microsft|microsooft|microsoft-[a-z]+)\.(com|net|org)`),
			Confidence:  0.9,
			Description: "Microsoft typosquatting domain",
		},
		{
			Name:        "google_typo",
			Pattern:     regexp.MustCompile(`(?i)(g00gle|googel|gooogle|gogle|google-[a-z]+)\.(com|net|org)`),
			Confidence:  0.9,
			Description: "Google typosquatting domain",
		},
		{
			Name:        "netflix_typo",
			Pattern:     regexp.MustCompile(`(?i)(netf1ix|netfilx|netfix|netflix-[a-z]+)\.(com|net|org)`),
			Confidence:  0.9,
			Description: "Netflix typosquatting domain",
		},
		// Generic suspicious patterns
		{
			Name:        "login_subdomain",
			Pattern:     regexp.MustCompile(`(?i)(login|signin|secure|account|verify|update)\.[a-z0-9-]+\.(xyz|top|club|work|click|link|gq|ml|cf|tk|ga)`),
			Confidence:  0.85,
			Description: "Suspicious login subdomain on free TLD",
		},
		{
			Name:        "brand_subdomain",
			Pattern:     regexp.MustCompile(`(?i)(paypal|amazon|apple|google|microsoft|netflix|bank)[.-][a-z0-9-]+\.(xyz|top|club|work|click)`),
			Confidence:  0.9,
			Description: "Brand name on suspicious TLD",
		},
	}
}

// initSenderPatterns initializes sender-based patterns
func (p *PhishingPatterns) initSenderPatterns() {
	p.senderPatterns = []SenderPattern{
		{
			Name:        "spoofed_brand",
			Pattern:     regexp.MustCompile(`(?i)^(USPS|UPS|FEDEX|AMAZON|PAYPAL|NETFLIX|APPLE|GOOGLE|CHASE|WELLS|BOA|CITI)$`),
			Confidence:  0.6, // Could be legitimate or spoofed
			Description: "Sender appears to be major brand (may be spoofed)",
		},
	}
}

// Match finds all pattern matches in the given text
func (p *PhishingPatterns) Match(text string) []models.PatternMatch {
	matches := []models.PatternMatch{}

	for _, tp := range p.textPatterns {
		if tp.Pattern.MatchString(text) {
			matched := tp.Pattern.FindString(text)
			matches = append(matches, models.PatternMatch{
				PatternName: tp.Name,
				PatternType: tp.Type,
				MatchedText: matched,
				Confidence:  tp.Confidence,
				Description: tp.Description,
			})
		}
	}

	return matches
}

// IsPhishingDomain checks if a domain matches phishing patterns
func (p *PhishingPatterns) IsPhishingDomain(domain string) bool {
	for _, dp := range p.domainPatterns {
		if dp.Pattern.MatchString(domain) {
			return true
		}
	}
	return false
}

// MatchDomain returns domain pattern matches
func (p *PhishingPatterns) MatchDomain(domain string) []models.PatternMatch {
	matches := []models.PatternMatch{}

	for _, dp := range p.domainPatterns {
		if dp.Pattern.MatchString(domain) {
			matches = append(matches, models.PatternMatch{
				PatternName: dp.Name,
				PatternType: "domain",
				MatchedText: domain,
				Confidence:  dp.Confidence,
				Description: dp.Description,
			})
		}
	}

	return matches
}

// MatchSender checks if sender matches suspicious patterns
func (p *PhishingPatterns) MatchSender(sender string) []models.PatternMatch {
	matches := []models.PatternMatch{}

	for _, sp := range p.senderPatterns {
		if sp.Pattern.MatchString(sender) {
			matches = append(matches, models.PatternMatch{
				PatternName: sp.Name,
				PatternType: "sender",
				MatchedText: sender,
				Confidence:  sp.Confidence,
				Description: sp.Description,
			})
		}
	}

	return matches
}

// KnownPhishingDomains returns a list of known phishing domains for quick lookup
func KnownPhishingDomains() map[string]bool {
	// This would typically be loaded from a database or file
	// For now, returning some known bad domains
	return map[string]bool{
		// These are example domains - real list would be much larger
		"login-paypa1.com":    true,
		"secure-amaz0n.com":   true,
		"verify-apple.xyz":    true,
		"update-netflix.tk":   true,
		"usps-delivery.top":   true,
		"fedex-track.click":   true,
	}
}

// KnownBrandDomains returns legitimate brand domains
func KnownBrandDomains() map[string]string {
	return map[string]string{
		"paypal.com":       "PayPal",
		"amazon.com":       "Amazon",
		"apple.com":        "Apple",
		"google.com":       "Google",
		"microsoft.com":    "Microsoft",
		"netflix.com":      "Netflix",
		"usps.com":         "USPS",
		"ups.com":          "UPS",
		"fedex.com":        "FedEx",
		"chase.com":        "Chase",
		"wellsfargo.com":   "Wells Fargo",
		"bankofamerica.com": "Bank of America",
		"citibank.com":     "Citibank",
	}
}

// IsBrandDomain checks if a domain belongs to a known brand
func IsBrandDomain(domain string) (bool, string) {
	domain = strings.ToLower(domain)
	brands := KnownBrandDomains()

	// Check exact match
	if brand, ok := brands[domain]; ok {
		return true, brand
	}

	// Check if it's a subdomain of a known brand
	for brandDomain, brandName := range brands {
		if strings.HasSuffix(domain, "."+brandDomain) {
			return true, brandName
		}
	}

	return false, ""
}
