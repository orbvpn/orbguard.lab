package models

import (
	"time"

	"github.com/google/uuid"
)

// QRContentType represents the type of content in a QR code
type QRContentType string

const (
	QRContentURL      QRContentType = "url"
	QRContentText     QRContentType = "text"
	QRContentEmail    QRContentType = "email"
	QRContentPhone    QRContentType = "phone"
	QRContentSMS      QRContentType = "sms"
	QRContentWiFi     QRContentType = "wifi"
	QRContentVCard    QRContentType = "vcard"
	QRContentGeo      QRContentType = "geo"
	QRContentEvent    QRContentType = "event"
	QRContentCrypto   QRContentType = "crypto"
	QRContentAppLink  QRContentType = "app_link"
	QRContentUnknown  QRContentType = "unknown"
)

// QRThreatLevel represents the threat level of a QR code
type QRThreatLevel string

const (
	QRThreatCritical QRThreatLevel = "critical"
	QRThreatHigh     QRThreatLevel = "high"
	QRThreatMedium   QRThreatLevel = "medium"
	QRThreatLow      QRThreatLevel = "low"
	QRThreatSafe     QRThreatLevel = "safe"
	QRThreatUnknown  QRThreatLevel = "unknown"
)

// QRThreatType represents specific threat types found in QR codes
type QRThreatType string

const (
	QRThreatPhishing          QRThreatType = "phishing"
	QRThreatMalware           QRThreatType = "malware"
	QRThreatScam              QRThreatType = "scam"
	QRThreatCryptoScam        QRThreatType = "crypto_scam"
	QRThreatFakeLogin         QRThreatType = "fake_login"
	QRThreatDataHarvesting    QRThreatType = "data_harvesting"
	QRThreatMaliciousRedirect QRThreatType = "malicious_redirect"
	QRThreatSuspiciousWiFi    QRThreatType = "suspicious_wifi"
	QRThreatTyposquatting     QRThreatType = "typosquatting"
	QRThreatURLShortener      QRThreatType = "url_shortener"
	QRThreatSuspiciousTLD     QRThreatType = "suspicious_tld"
	QRThreatIPAddress         QRThreatType = "ip_address"
	QRThreatEncodedURL        QRThreatType = "encoded_url"
	QRThreatNone              QRThreatType = "none"
)

// QRScanRequest represents a request to scan a QR code
type QRScanRequest struct {
	// Raw content from QR code (base64 encoded image or raw text)
	Content   string `json:"content"`
	// If true, content is base64 encoded image data
	IsImage   bool   `json:"is_image"`
	// Device context
	DeviceID  string `json:"device_id,omitempty"`
	// Source app that initiated scan
	SourceApp string `json:"source_app,omitempty"`
	// Location where QR was scanned
	Location  *QRScanLocation `json:"location,omitempty"`
}

// QRScanLocation represents where a QR code was scanned
type QRScanLocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy"`
}

// QRScanResult represents the result of scanning a QR code
type QRScanResult struct {
	ID              uuid.UUID     `json:"id"`
	// Extracted content
	RawContent      string        `json:"raw_content"`
	ContentType     QRContentType `json:"content_type"`
	// Parsed content based on type
	ParsedContent   *QRParsedContent `json:"parsed_content,omitempty"`
	// Threat analysis
	ThreatLevel     QRThreatLevel `json:"threat_level"`
	ThreatScore     float64       `json:"threat_score"` // 0-100
	Threats         []QRThreat    `json:"threats"`
	// Recommendations
	IsSafe          bool     `json:"is_safe"`
	ShouldBlock     bool     `json:"should_block"`
	Warnings        []string `json:"warnings"`
	Recommendations []string `json:"recommendations"`
	// Preview info for URLs
	URLPreview      *URLPreview `json:"url_preview,omitempty"`
	// Metadata
	ScannedAt       time.Time `json:"scanned_at"`
	AnalysisDuration time.Duration `json:"analysis_duration"`
}

// QRParsedContent holds parsed content based on QR type
type QRParsedContent struct {
	// For URLs
	URL         *QRURLContent    `json:"url,omitempty"`
	// For emails
	Email       *QREmailContent  `json:"email,omitempty"`
	// For phone numbers
	Phone       *QRPhoneContent  `json:"phone,omitempty"`
	// For SMS
	SMS         *QRSMSContent    `json:"sms,omitempty"`
	// For WiFi
	WiFi        *QRWiFiContent   `json:"wifi,omitempty"`
	// For vCard contacts
	VCard       *QRVCardContent  `json:"vcard,omitempty"`
	// For geo locations
	Geo         *QRGeoContent    `json:"geo,omitempty"`
	// For calendar events
	Event       *QREventContent  `json:"event,omitempty"`
	// For cryptocurrency
	Crypto      *QRCryptoContent `json:"crypto,omitempty"`
	// For app deep links
	AppLink     *QRAppLinkContent `json:"app_link,omitempty"`
	// For plain text
	Text        string           `json:"text,omitempty"`
}

// QRURLContent represents a parsed URL from QR code
type QRURLContent struct {
	FullURL     string   `json:"full_url"`
	Scheme      string   `json:"scheme"`
	Host        string   `json:"host"`
	Path        string   `json:"path"`
	Query       string   `json:"query"`
	Fragment    string   `json:"fragment"`
	// Resolved URL if shortened
	ResolvedURL string   `json:"resolved_url,omitempty"`
	// Redirect chain if followed
	RedirectChain []string `json:"redirect_chain,omitempty"`
}

// QREmailContent represents a parsed email from QR code
type QREmailContent struct {
	Address string `json:"address"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
}

// QRPhoneContent represents a parsed phone number from QR code
type QRPhoneContent struct {
	Number      string `json:"number"`
	CountryCode string `json:"country_code,omitempty"`
	IsPremium   bool   `json:"is_premium"` // Premium rate number
}

// QRSMSContent represents a parsed SMS from QR code
type QRSMSContent struct {
	Number  string `json:"number"`
	Message string `json:"message,omitempty"`
}

// QRWiFiContent represents parsed WiFi credentials from QR code
type QRWiFiContent struct {
	SSID       string `json:"ssid"`
	Password   string `json:"password,omitempty"`
	Security   string `json:"security"` // WPA, WPA2, WEP, nopass
	Hidden     bool   `json:"hidden"`
	// Security analysis
	IsOpenNetwork   bool `json:"is_open_network"`
	IsWeakSecurity  bool `json:"is_weak_security"`
}

// QRVCardContent represents a parsed vCard contact from QR code
type QRVCardContent struct {
	Name         string   `json:"name"`
	Organization string   `json:"organization,omitempty"`
	Title        string   `json:"title,omitempty"`
	Phones       []string `json:"phones,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	URLs         []string `json:"urls,omitempty"`
	Address      string   `json:"address,omitempty"`
}

// QRGeoContent represents a parsed geo location from QR code
type QRGeoContent struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Altitude  float64 `json:"altitude,omitempty"`
	Label     string  `json:"label,omitempty"`
}

// QREventContent represents a parsed calendar event from QR code
type QREventContent struct {
	Summary     string    `json:"summary"`
	Description string    `json:"description,omitempty"`
	Location    string    `json:"location,omitempty"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time,omitempty"`
	URL         string    `json:"url,omitempty"`
}

// QRCryptoContent represents a parsed cryptocurrency address from QR code
type QRCryptoContent struct {
	Currency string  `json:"currency"` // bitcoin, ethereum, etc.
	Address  string  `json:"address"`
	Amount   float64 `json:"amount,omitempty"`
	Label    string  `json:"label,omitempty"`
	Message  string  `json:"message,omitempty"`
	// Validation
	IsValidAddress bool `json:"is_valid_address"`
}

// QRAppLinkContent represents a parsed app deep link from QR code
type QRAppLinkContent struct {
	Scheme    string `json:"scheme"`
	Host      string `json:"host,omitempty"`
	Path      string `json:"path,omitempty"`
	AppName   string `json:"app_name,omitempty"`
	IsKnownApp bool  `json:"is_known_app"`
}

// QRThreat represents a specific threat found in a QR code
type QRThreat struct {
	Type        QRThreatType `json:"type"`
	Severity    string       `json:"severity"` // critical, high, medium, low
	Description string       `json:"description"`
	Evidence    string       `json:"evidence,omitempty"`
	// For URL threats, reference to threat intel
	ThreatIntelMatch *QRThreatIntelMatch `json:"threat_intel_match,omitempty"`
}

// QRThreatIntelMatch represents a match from threat intelligence
type QRThreatIntelMatch struct {
	IndicatorID   uuid.UUID `json:"indicator_id"`
	IndicatorType string    `json:"indicator_type"`
	Campaign      string    `json:"campaign,omitempty"`
	ThreatActor   string    `json:"threat_actor,omitempty"`
	Confidence    int       `json:"confidence"` // 0-100
}

// URLPreview represents a safe preview of a URL
type URLPreview struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	ImageURL    string `json:"image_url,omitempty"`
	SiteName    string `json:"site_name,omitempty"`
	FaviconURL  string `json:"favicon_url,omitempty"`
	// Security info
	HasSSL      bool   `json:"has_ssl"`
	CertIssuer  string `json:"cert_issuer,omitempty"`
	// Domain info
	DomainAge   string `json:"domain_age,omitempty"`
	Registrar   string `json:"registrar,omitempty"`
}

// QRScanHistory represents a historical QR scan
type QRScanHistory struct {
	ID          uuid.UUID     `json:"id"`
	DeviceID    string        `json:"device_id"`
	ContentType QRContentType `json:"content_type"`
	RawContent  string        `json:"raw_content"`
	ThreatLevel QRThreatLevel `json:"threat_level"`
	WasBlocked  bool          `json:"was_blocked"`
	UserAction  string        `json:"user_action"` // opened, blocked, dismissed
	ScannedAt   time.Time     `json:"scanned_at"`
	Location    *QRScanLocation `json:"location,omitempty"`
}

// QRSecurityStats represents statistics for QR security
type QRSecurityStats struct {
	TotalScans        int64            `json:"total_scans"`
	ThreatsBlocked    int64            `json:"threats_blocked"`
	ByContentType     map[string]int64 `json:"by_content_type"`
	ByThreatLevel     map[string]int64 `json:"by_threat_level"`
	ByThreatType      map[string]int64 `json:"by_threat_type"`
	TopBlockedDomains []string         `json:"top_blocked_domains"`
	Last24Hours       int64            `json:"last_24_hours"`
	Last7Days         int64            `json:"last_7_days"`
}

// SuspiciousTLDs are TLDs commonly used in phishing/scam QR codes
var SuspiciousTLDs = []string{
	"xyz", "tk", "ml", "ga", "cf", "gq", "top", "work", "click", "link",
	"info", "online", "site", "website", "space", "fun", "icu", "buzz",
	"monster", "cam", "rest", "surf", "bar", "cyou",
}

// KnownURLShorteners are URL shortening services that may hide malicious URLs
var KnownURLShorteners = []string{
	"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
	"j.mp", "rb.gy", "shorturl.at", "tiny.cc", "cutt.ly", "v.gd", "t.ly",
	"clck.ru", "rebrand.ly", "bl.ink", "short.io", "lnkd.in", "youtu.be",
}

// KnownSafeApps are apps with known URL schemes
var KnownSafeApps = map[string]string{
	"whatsapp":    "WhatsApp",
	"telegram":    "Telegram",
	"instagram":   "Instagram",
	"twitter":     "Twitter",
	"facebook":    "Facebook",
	"linkedin":    "LinkedIn",
	"spotify":     "Spotify",
	"youtube":     "YouTube",
	"maps":        "Apple Maps",
	"comgooglemaps": "Google Maps",
	"uber":        "Uber",
	"lyft":        "Lyft",
	"venmo":       "Venmo",
	"paypal":      "PayPal",
	"cashapp":     "Cash App",
}

// PremiumRatePrefixes are phone prefixes for premium rate numbers
var PremiumRatePrefixes = []string{
	"1-900", "1-976", "44-9", "44-70", "44-84", "44-87",
	"33-89", "49-900", "39-899", "34-80", "34-90",
}

// CryptoCurrencyPrefixes help identify crypto addresses
var CryptoCurrencyPrefixes = map[string][]string{
	"bitcoin":  {"1", "3", "bc1"},
	"ethereum": {"0x"},
	"litecoin": {"L", "M", "ltc1"},
	"dogecoin": {"D"},
	"monero":   {"4"},
	"ripple":   {"r"},
}
