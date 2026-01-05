package models

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// NetworkRiskLevel represents the risk level of a network
type NetworkRiskLevel string

const (
	NetworkRiskLevelSafe     NetworkRiskLevel = "safe"
	NetworkRiskLevelLow      NetworkRiskLevel = "low"
	NetworkRiskLevelMedium   NetworkRiskLevel = "medium"
	NetworkRiskLevelHigh     NetworkRiskLevel = "high"
	NetworkRiskLevelCritical NetworkRiskLevel = "critical"
)

// WiFiSecurityType represents the security type of a Wi-Fi network
type WiFiSecurityType string

const (
	WiFiSecurityOpen    WiFiSecurityType = "open"
	WiFiSecurityWEP     WiFiSecurityType = "wep"
	WiFiSecurityWPA     WiFiSecurityType = "wpa"
	WiFiSecurityWPA2    WiFiSecurityType = "wpa2"
	WiFiSecurityWPA3    WiFiSecurityType = "wpa3"
	WiFiSecurityUnknown WiFiSecurityType = "unknown"
)

// NetworkAttackType represents types of network attacks
type NetworkAttackType string

const (
	NetworkAttackARPSpoofing   NetworkAttackType = "arp_spoofing"
	NetworkAttackDNSSpoofing   NetworkAttackType = "dns_spoofing"
	NetworkAttackSSLStripping  NetworkAttackType = "ssl_stripping"
	NetworkAttackMITM          NetworkAttackType = "mitm"
	NetworkAttackEvilTwin      NetworkAttackType = "evil_twin"
	NetworkAttackRogueAP       NetworkAttackType = "rogue_ap"
	NetworkAttackDNSHijacking  NetworkAttackType = "dns_hijacking"
	NetworkAttackCaptivePortal NetworkAttackType = "captive_portal"
	NetworkAttackDeauth        NetworkAttackType = "deauth"
)

// WiFiNetwork represents a scanned Wi-Fi network
type WiFiNetwork struct {
	SSID         string           `json:"ssid"`
	BSSID        string           `json:"bssid"`
	SecurityType WiFiSecurityType `json:"security_type"`
	SignalLevel  int              `json:"signal_level"` // dBm
	Frequency    int              `json:"frequency"`    // MHz
	Channel      int              `json:"channel"`
	IsConnected  bool             `json:"is_connected"`
	IsHidden     bool             `json:"is_hidden"`
	Capabilities string           `json:"capabilities,omitempty"`
}

// WiFiAuditRequest represents a request to audit Wi-Fi security
type WiFiAuditRequest struct {
	CurrentNetwork *WiFiNetwork  `json:"current_network,omitempty"`
	NearbyNetworks []WiFiNetwork `json:"nearby_networks,omitempty"`
	DeviceID       string        `json:"device_id,omitempty"`
	GatewayIP      string        `json:"gateway_ip,omitempty"`
	DNSIP          string        `json:"dns_ip,omitempty"`
	PublicIP       string        `json:"public_ip,omitempty"`
}

// WiFiAuditResult represents the result of a Wi-Fi security audit
type WiFiAuditResult struct {
	ID               uuid.UUID               `json:"id"`
	Network          *WiFiNetwork            `json:"network,omitempty"`
	RiskLevel        NetworkRiskLevel        `json:"risk_level"`
	RiskScore        float64                 `json:"risk_score"`
	SecurityIssues   []WiFiSecurityIssue     `json:"security_issues"`
	RogueAPDetected  []RogueAPAlert          `json:"rogue_ap_detected,omitempty"`
	EvilTwinDetected []EvilTwinAlert         `json:"evil_twin_detected,omitempty"`
	Recommendations  []NetworkRecommendation `json:"recommendations"`
	AuditedAt        time.Time               `json:"audited_at"`
}

// WiFiSecurityIssue represents a security issue found in Wi-Fi
type WiFiSecurityIssue struct {
	Type        string           `json:"type"`
	Severity    NetworkRiskLevel `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Mitigation  string           `json:"mitigation"`
}

// RogueAPAlert represents a detected rogue access point
type RogueAPAlert struct {
	SSID              string           `json:"ssid"`
	BSSID             string           `json:"bssid"`
	SignalStrength    int              `json:"signal_strength"`
	SecurityType      WiFiSecurityType `json:"security_type"`
	RiskLevel         NetworkRiskLevel `json:"risk_level"`
	Reason            string           `json:"reason"`
	LegitimateNetwork *WiFiNetwork     `json:"legitimate_network,omitempty"`
	DetectedAt        time.Time        `json:"detected_at"`
}

// EvilTwinAlert represents a detected evil twin attack
type EvilTwinAlert struct {
	SSID           string           `json:"ssid"`
	LegitBSSID     string           `json:"legit_bssid"`
	EvilBSSID      string           `json:"evil_bssid"`
	SignalDiff     int              `json:"signal_diff"`
	SecurityDiff   bool             `json:"security_diff"`
	RiskLevel      NetworkRiskLevel `json:"risk_level"`
	Confidence     float64          `json:"confidence"`
	Description    string           `json:"description"`
	Recommendation string           `json:"recommendation"`
	DetectedAt     time.Time        `json:"detected_at"`
}

// NetworkRecommendation represents a security recommendation
type NetworkRecommendation struct {
	Priority    string `json:"priority"` // critical, high, medium, low
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action,omitempty"`
}

// DNSConfig represents DNS configuration
type DNSConfig struct {
	PrimaryDNS      string   `json:"primary_dns"`
	SecondaryDNS    string   `json:"secondary_dns,omitempty"`
	IsEncrypted     bool     `json:"is_encrypted"`     // DoH or DoT
	EncryptionType  string   `json:"encryption_type"`  // doh, dot, none
	Provider        string   `json:"provider"`         // cloudflare, google, quad9, etc.
	CustomServers   []string `json:"custom_servers,omitempty"`
	BlockMalicious  bool     `json:"block_malicious"`
	BlockAds        bool     `json:"block_ads"`
	BlockTrackers   bool     `json:"block_trackers"`
	BlockAdultSites bool     `json:"block_adult_sites"`
}

// DNSCheckRequest represents a request to check DNS security
type DNSCheckRequest struct {
	CurrentDNS   string `json:"current_dns"`
	GatewayIP    string `json:"gateway_ip,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	TestDomains  bool   `json:"test_domains"` // run DNS resolution tests
	CheckLeaks   bool   `json:"check_leaks"`  // check for DNS leaks
	CheckHijack  bool   `json:"check_hijack"` // check for DNS hijacking
}

// DNSCheckResult represents the result of a DNS security check
type DNSCheckResult struct {
	ID              uuid.UUID               `json:"id"`
	CurrentDNS      string                  `json:"current_dns"`
	IsSecure        bool                    `json:"is_secure"`
	IsEncrypted     bool                    `json:"is_encrypted"`
	EncryptionType  string                  `json:"encryption_type"`
	Provider        *DNSProvider            `json:"provider,omitempty"`
	IsHijacked      bool                    `json:"is_hijacked"`
	HijackDetails   *DNSHijackDetails       `json:"hijack_details,omitempty"`
	LeakDetected    bool                    `json:"leak_detected"`
	LeakDetails     *DNSLeakDetails         `json:"leak_details,omitempty"`
	SecurityIssues  []DNSSecurityIssue      `json:"security_issues"`
	Recommendations []NetworkRecommendation `json:"recommendations"`
	CheckedAt       time.Time               `json:"checked_at"`
}

// DNSProvider represents a known DNS provider
type DNSProvider struct {
	Name           string   `json:"name"`
	PrimaryIP      string   `json:"primary_ip"`
	SecondaryIP    string   `json:"secondary_ip,omitempty"`
	DoHURL         string   `json:"doh_url,omitempty"`
	DoTHost        string   `json:"dot_host,omitempty"`
	SupportsDoH    bool     `json:"supports_doh"`
	SupportsDoT    bool     `json:"supports_dot"`
	BlocksMalware  bool     `json:"blocks_malware"`
	BlocksAds      bool     `json:"blocks_ads"`
	PrivacyRating  string   `json:"privacy_rating"` // excellent, good, fair, poor
	Country        string   `json:"country"`
	IsTrusted      bool     `json:"is_trusted"`
}

// DNSHijackDetails represents details of a DNS hijacking attack
type DNSHijackDetails struct {
	ExpectedIP    string    `json:"expected_ip"`
	ResolvedIP    string    `json:"resolved_ip"`
	TestDomain    string    `json:"test_domain"`
	HijackerIP    string    `json:"hijacker_ip,omitempty"`
	Confidence    float64   `json:"confidence"`
	Description   string    `json:"description"`
	DetectedAt    time.Time `json:"detected_at"`
}

// DNSLeakDetails represents details of a DNS leak
type DNSLeakDetails struct {
	LeakedQueries []string  `json:"leaked_queries"`
	LeakedToISP   bool      `json:"leaked_to_isp"`
	ISPName       string    `json:"isp_name,omitempty"`
	Description   string    `json:"description"`
	DetectedAt    time.Time `json:"detected_at"`
}

// DNSSecurityIssue represents a DNS security issue
type DNSSecurityIssue struct {
	Type        string           `json:"type"`
	Severity    NetworkRiskLevel `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Mitigation  string           `json:"mitigation"`
}

// NetworkAttackAlert represents a detected network attack
type NetworkAttackAlert struct {
	ID           uuid.UUID         `json:"id"`
	Type         NetworkAttackType `json:"type"`
	Severity     NetworkRiskLevel  `json:"severity"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	SourceIP     net.IP            `json:"source_ip,omitempty"`
	SourceMAC    string            `json:"source_mac,omitempty"`
	TargetIP     net.IP            `json:"target_ip,omitempty"`
	Evidence     []string          `json:"evidence"`
	Mitigation   string            `json:"mitigation"`
	IsBlocked    bool              `json:"is_blocked"`
	DetectedAt   time.Time         `json:"detected_at"`
}

// ARPEntry represents an ARP table entry
type ARPEntry struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Interface  string `json:"interface,omitempty"`
	IsGateway  bool   `json:"is_gateway"`
}

// ARPSpoofCheckRequest represents a request to check for ARP spoofing
type ARPSpoofCheckRequest struct {
	ARPTable   []ARPEntry `json:"arp_table"`
	GatewayIP  string     `json:"gateway_ip"`
	GatewayMAC string     `json:"gateway_mac,omitempty"`
	DeviceID   string     `json:"device_id,omitempty"`
}

// ARPSpoofCheckResult represents the result of an ARP spoofing check
type ARPSpoofCheckResult struct {
	ID              uuid.UUID               `json:"id"`
	IsSpoofDetected bool                    `json:"is_spoof_detected"`
	Alerts          []NetworkAttackAlert    `json:"alerts,omitempty"`
	SuspiciousMACs  []string                `json:"suspicious_macs,omitempty"`
	DuplicateIPs    []string                `json:"duplicate_ips,omitempty"`
	Recommendations []NetworkRecommendation `json:"recommendations"`
	CheckedAt       time.Time               `json:"checked_at"`
}

// SSLCertificate represents an SSL/TLS certificate
type SSLCertificate struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IsExpired    bool      `json:"is_expired"`
	IsSelfSigned bool      `json:"is_self_signed"`
	IsValid      bool      `json:"is_valid"`
	Fingerprint  string    `json:"fingerprint"`
	PublicKeyAlg string    `json:"public_key_algorithm"`
	KeySize      int       `json:"key_size"`
}

// SSLCheckRequest represents a request to check SSL/TLS security
type SSLCheckRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"` // defaults to 443
	DeviceID string `json:"device_id,omitempty"`
}

// SSLCheckResult represents the result of an SSL/TLS check
type SSLCheckResult struct {
	ID                uuid.UUID               `json:"id"`
	Host              string                  `json:"host"`
	Port              int                     `json:"port"`
	IsSecure          bool                    `json:"is_secure"`
	Certificate       *SSLCertificate         `json:"certificate,omitempty"`
	TLSVersion        string                  `json:"tls_version"`
	CipherSuite       string                  `json:"cipher_suite"`
	IsValidChain      bool                    `json:"is_valid_chain"`
	IsPinned          bool                    `json:"is_pinned,omitempty"`
	PinningViolation  bool                    `json:"pinning_violation,omitempty"`
	SecurityIssues    []SSLSecurityIssue      `json:"security_issues"`
	Recommendations   []NetworkRecommendation `json:"recommendations"`
	CheckedAt         time.Time               `json:"checked_at"`
}

// SSLSecurityIssue represents an SSL/TLS security issue
type SSLSecurityIssue struct {
	Type        string           `json:"type"`
	Severity    NetworkRiskLevel `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Mitigation  string           `json:"mitigation"`
}

// VPNStatus represents the current VPN status
type VPNStatus struct {
	IsConnected    bool      `json:"is_connected"`
	ServerLocation string    `json:"server_location,omitempty"`
	ServerIP       string    `json:"server_ip,omitempty"`
	Protocol       string    `json:"protocol,omitempty"` // wireguard, openvpn, etc.
	Latency        int       `json:"latency_ms,omitempty"`
	BytesSent      int64     `json:"bytes_sent,omitempty"`
	BytesReceived  int64     `json:"bytes_received,omitempty"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
}

// VPNConfig represents VPN configuration for OrbNet integration
type VPNConfig struct {
	AutoConnect          bool     `json:"auto_connect"`
	AutoConnectOnPublic  bool     `json:"auto_connect_on_public_wifi"`
	AutoConnectOnMobile  bool     `json:"auto_connect_on_mobile_data"`
	KillSwitch           bool     `json:"kill_switch"`
	DNSProtection        bool     `json:"dns_protection"`
	ThreatBlocking       bool     `json:"threat_blocking"`
	SplitTunneling       bool     `json:"split_tunneling"`
	ExcludedApps         []string `json:"excluded_apps,omitempty"`
	PreferredProtocol    string   `json:"preferred_protocol"`
	PreferredLocation    string   `json:"preferred_location,omitempty"`
}

// VPNRecommendation represents a VPN usage recommendation
type VPNRecommendation struct {
	ShouldConnect bool   `json:"should_connect"`
	Reason        string `json:"reason"`
	Priority      string `json:"priority"` // required, recommended, optional
	NetworkRisk   NetworkRiskLevel `json:"network_risk"`
}

// NetworkSecurityStats represents network security statistics
type NetworkSecurityStats struct {
	TotalScans          int64            `json:"total_scans"`
	WiFiAudits          int64            `json:"wifi_audits"`
	DNSChecks           int64            `json:"dns_checks"`
	AttacksDetected     int64            `json:"attacks_detected"`
	AttacksByType       map[string]int64 `json:"attacks_by_type"`
	RogueAPsDetected    int64            `json:"rogue_aps_detected"`
	EvilTwinsDetected   int64            `json:"evil_twins_detected"`
	DNSHijacksDetected  int64            `json:"dns_hijacks_detected"`
	UnsecureNetworks    int64            `json:"unsecure_networks"`
	VPNConnectionsForced int64           `json:"vpn_connections_forced"`
	Last24Hours         *NetworkStats24H `json:"last_24_hours,omitempty"`
}

// NetworkStats24H represents network stats for the last 24 hours
type NetworkStats24H struct {
	Scans           int64 `json:"scans"`
	AttacksDetected int64 `json:"attacks_detected"`
	RogueAPs        int64 `json:"rogue_aps"`
	EvilTwins       int64 `json:"evil_twins"`
}

// KnownDNSProviders contains information about trusted DNS providers
var KnownDNSProviders = map[string]*DNSProvider{
	"1.1.1.1": {
		Name:          "Cloudflare",
		PrimaryIP:     "1.1.1.1",
		SecondaryIP:   "1.0.0.1",
		DoHURL:        "https://cloudflare-dns.com/dns-query",
		DoTHost:       "one.one.one.one",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: false,
		BlocksAds:     false,
		PrivacyRating: "excellent",
		Country:       "US",
		IsTrusted:     true,
	},
	"1.1.1.2": {
		Name:          "Cloudflare Malware Blocking",
		PrimaryIP:     "1.1.1.2",
		SecondaryIP:   "1.0.0.2",
		DoHURL:        "https://security.cloudflare-dns.com/dns-query",
		DoTHost:       "security.cloudflare-dns.com",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: true,
		BlocksAds:     false,
		PrivacyRating: "excellent",
		Country:       "US",
		IsTrusted:     true,
	},
	"1.1.1.3": {
		Name:          "Cloudflare Family",
		PrimaryIP:     "1.1.1.3",
		SecondaryIP:   "1.0.0.3",
		DoHURL:        "https://family.cloudflare-dns.com/dns-query",
		DoTHost:       "family.cloudflare-dns.com",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: true,
		BlocksAds:     false,
		PrivacyRating: "excellent",
		Country:       "US",
		IsTrusted:     true,
	},
	"8.8.8.8": {
		Name:          "Google Public DNS",
		PrimaryIP:     "8.8.8.8",
		SecondaryIP:   "8.8.4.4",
		DoHURL:        "https://dns.google/dns-query",
		DoTHost:       "dns.google",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: false,
		BlocksAds:     false,
		PrivacyRating: "fair",
		Country:       "US",
		IsTrusted:     true,
	},
	"9.9.9.9": {
		Name:          "Quad9",
		PrimaryIP:     "9.9.9.9",
		SecondaryIP:   "149.112.112.112",
		DoHURL:        "https://dns.quad9.net/dns-query",
		DoTHost:       "dns.quad9.net",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: true,
		BlocksAds:     false,
		PrivacyRating: "excellent",
		Country:       "CH",
		IsTrusted:     true,
	},
	"94.140.14.14": {
		Name:          "AdGuard DNS",
		PrimaryIP:     "94.140.14.14",
		SecondaryIP:   "94.140.15.15",
		DoHURL:        "https://dns.adguard-dns.com/dns-query",
		DoTHost:       "dns.adguard-dns.com",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: true,
		BlocksAds:     true,
		PrivacyRating: "good",
		Country:       "CY",
		IsTrusted:     true,
	},
	"208.67.222.222": {
		Name:          "OpenDNS",
		PrimaryIP:     "208.67.222.222",
		SecondaryIP:   "208.67.220.220",
		DoHURL:        "https://doh.opendns.com/dns-query",
		DoTHost:       "",
		SupportsDoH:   true,
		SupportsDoT:   false,
		BlocksMalware: true,
		BlocksAds:     false,
		PrivacyRating: "fair",
		Country:       "US",
		IsTrusted:     true,
	},
	"185.228.168.9": {
		Name:          "CleanBrowsing Security",
		PrimaryIP:     "185.228.168.9",
		SecondaryIP:   "185.228.169.9",
		DoHURL:        "https://doh.cleanbrowsing.org/doh/security-filter/",
		DoTHost:       "security-filter-dns.cleanbrowsing.org",
		SupportsDoH:   true,
		SupportsDoT:   true,
		BlocksMalware: true,
		BlocksAds:     false,
		PrivacyRating: "good",
		Country:       "US",
		IsTrusted:     true,
	},
}

// WiFiSecurityRisks maps security types to risk information
var WiFiSecurityRisks = map[WiFiSecurityType]struct {
	RiskLevel   NetworkRiskLevel
	Description string
}{
	WiFiSecurityOpen: {
		RiskLevel:   NetworkRiskLevelCritical,
		Description: "Open network with no encryption - all traffic is visible to attackers",
	},
	WiFiSecurityWEP: {
		RiskLevel:   NetworkRiskLevelCritical,
		Description: "WEP encryption is broken and can be cracked in minutes",
	},
	WiFiSecurityWPA: {
		RiskLevel:   NetworkRiskLevelHigh,
		Description: "WPA has known vulnerabilities - WPA2 or WPA3 recommended",
	},
	WiFiSecurityWPA2: {
		RiskLevel:   NetworkRiskLevelLow,
		Description: "WPA2 is secure for most use cases, but WPA3 is preferred",
	},
	WiFiSecurityWPA3: {
		RiskLevel:   NetworkRiskLevelSafe,
		Description: "WPA3 provides the strongest Wi-Fi security currently available",
	},
}

// NetworkAttackDescriptions provides descriptions for attack types
var NetworkAttackDescriptions = map[NetworkAttackType]struct {
	Title       string
	Description string
	Severity    NetworkRiskLevel
	Mitigation  string
}{
	NetworkAttackARPSpoofing: {
		Title:       "ARP Spoofing Attack",
		Description: "An attacker is sending fake ARP messages to intercept network traffic",
		Severity:    NetworkRiskLevelCritical,
		Mitigation:  "Use VPN to encrypt all traffic, avoid sensitive activities on this network",
	},
	NetworkAttackDNSSpoofing: {
		Title:       "DNS Spoofing Attack",
		Description: "DNS responses are being manipulated to redirect you to malicious sites",
		Severity:    NetworkRiskLevelCritical,
		Mitigation:  "Switch to encrypted DNS (DoH/DoT) from a trusted provider",
	},
	NetworkAttackSSLStripping: {
		Title:       "SSL Stripping Attack",
		Description: "An attacker is downgrading secure HTTPS connections to unencrypted HTTP",
		Severity:    NetworkRiskLevelCritical,
		Mitigation:  "Only visit sites with HTTPS, use VPN, enable HSTS in browser",
	},
	NetworkAttackMITM: {
		Title:       "Man-in-the-Middle Attack",
		Description: "An attacker is intercepting communications between you and the server",
		Severity:    NetworkRiskLevelCritical,
		Mitigation:  "Use VPN immediately, disconnect from this network if possible",
	},
	NetworkAttackEvilTwin: {
		Title:       "Evil Twin Attack",
		Description: "A fake Wi-Fi network is impersonating a legitimate one to steal data",
		Severity:    NetworkRiskLevelCritical,
		Mitigation:  "Verify network authenticity, use VPN, avoid sensitive activities",
	},
	NetworkAttackRogueAP: {
		Title:       "Rogue Access Point",
		Description: "An unauthorized access point is present that could intercept traffic",
		Severity:    NetworkRiskLevelHigh,
		Mitigation:  "Do not connect to unknown networks, use VPN on public Wi-Fi",
	},
	NetworkAttackDNSHijacking: {
		Title:       "DNS Hijacking",
		Description: "Your DNS queries are being redirected to malicious DNS servers",
		Severity:    NetworkRiskLevelCritical,
		Mitigation:  "Configure secure DNS (1.1.1.1 or 9.9.9.9), use VPN",
	},
	NetworkAttackCaptivePortal: {
		Title:       "Suspicious Captive Portal",
		Description: "The network login page may be attempting to steal credentials",
		Severity:    NetworkRiskLevelMedium,
		Mitigation:  "Do not enter sensitive credentials, use VPN after connecting",
	},
	NetworkAttackDeauth: {
		Title:       "Deauthentication Attack",
		Description: "An attacker is forcing devices off the network (possible prelude to evil twin)",
		Severity:    NetworkRiskLevelHigh,
		Mitigation:  "If disconnections persist, this may indicate an active attack",
	},
}
