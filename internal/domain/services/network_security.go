package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// NetworkSecurityService handles network security analysis
type NetworkSecurityService struct {
	repos           *repository.Repositories
	cache           *cache.RedisCache
	logger          *logger.Logger
	knownGateways   map[string]string // IP -> MAC mapping for known gateways
	gatewaysMu      sync.RWMutex
	trustedNetworks map[string]bool   // SSID -> trusted
	trustedMu       sync.RWMutex
}

// NewNetworkSecurityService creates a new network security service
func NewNetworkSecurityService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *NetworkSecurityService {
	return &NetworkSecurityService{
		repos:           repos,
		cache:           cache,
		logger:          log.WithComponent("network-security"),
		knownGateways:   make(map[string]string),
		trustedNetworks: make(map[string]bool),
	}
}

// AuditWiFi performs a comprehensive Wi-Fi security audit
func (s *NetworkSecurityService) AuditWiFi(ctx context.Context, req *models.WiFiAuditRequest) (*models.WiFiAuditResult, error) {
	result := &models.WiFiAuditResult{
		ID:              uuid.New(),
		Network:         req.CurrentNetwork,
		SecurityIssues:  make([]models.WiFiSecurityIssue, 0),
		RogueAPDetected: make([]models.RogueAPAlert, 0),
		EvilTwinDetected: make([]models.EvilTwinAlert, 0),
		Recommendations: make([]models.NetworkRecommendation, 0),
		AuditedAt:       time.Now(),
	}

	// Check current network security
	if req.CurrentNetwork != nil {
		s.auditNetworkSecurity(result, req.CurrentNetwork)
	}

	// Check for rogue APs
	if len(req.NearbyNetworks) > 0 {
		s.detectRogueAPs(result, req.NearbyNetworks)
	}

	// Check for evil twin attacks
	if req.CurrentNetwork != nil && len(req.NearbyNetworks) > 0 {
		s.detectEvilTwin(result, req.CurrentNetwork, req.NearbyNetworks)
	}

	// Calculate overall risk
	result.RiskScore, result.RiskLevel = s.calculateWiFiRisk(result)

	// Generate recommendations
	s.generateWiFiRecommendations(result)

	s.logger.Info().
		Str("ssid", s.getSSID(req.CurrentNetwork)).
		Str("risk_level", string(result.RiskLevel)).
		Float64("risk_score", result.RiskScore).
		Int("issues", len(result.SecurityIssues)).
		Msg("Wi-Fi audit completed")

	return result, nil
}

func (s *NetworkSecurityService) getSSID(network *models.WiFiNetwork) string {
	if network == nil {
		return "unknown"
	}
	return network.SSID
}

func (s *NetworkSecurityService) auditNetworkSecurity(result *models.WiFiAuditResult, network *models.WiFiNetwork) {
	// Check security type
	if secRisk, ok := models.WiFiSecurityRisks[network.SecurityType]; ok {
		if secRisk.RiskLevel == models.NetworkRiskLevelCritical || secRisk.RiskLevel == models.NetworkRiskLevelHigh {
			result.SecurityIssues = append(result.SecurityIssues, models.WiFiSecurityIssue{
				Type:        "weak_encryption",
				Severity:    secRisk.RiskLevel,
				Title:       fmt.Sprintf("Weak Wi-Fi Security: %s", network.SecurityType),
				Description: secRisk.Description,
				Mitigation:  s.getSecurityMitigation(network.SecurityType),
			})
		}
	}

	// Check for hidden SSID (can indicate rogue AP)
	if network.IsHidden {
		result.SecurityIssues = append(result.SecurityIssues, models.WiFiSecurityIssue{
			Type:        "hidden_ssid",
			Severity:    models.NetworkRiskLevelLow,
			Title:       "Hidden Network SSID",
			Description: "This network hides its SSID. While sometimes used for security, this can also indicate a rogue access point.",
			Mitigation:  "Verify this is a known trusted network before using",
		})
	}

	// Check for common vulnerable SSID names
	vulnerableSSIDs := []string{"Free WiFi", "FREE_WIFI", "Public WiFi", "Guest", "Airport", "Hotel", "Starbucks"}
	ssidUpper := strings.ToUpper(network.SSID)
	for _, vulnSSID := range vulnerableSSIDs {
		if strings.Contains(ssidUpper, strings.ToUpper(vulnSSID)) {
			result.SecurityIssues = append(result.SecurityIssues, models.WiFiSecurityIssue{
				Type:        "public_network",
				Severity:    models.NetworkRiskLevelMedium,
				Title:       "Public Wi-Fi Network",
				Description: "This appears to be a public Wi-Fi network. Public networks are common targets for attackers.",
				Mitigation:  "Use VPN when connected to public Wi-Fi, avoid sensitive transactions",
			})
			break
		}
	}
}

func (s *NetworkSecurityService) getSecurityMitigation(secType models.WiFiSecurityType) string {
	switch secType {
	case models.WiFiSecurityOpen:
		return "Use VPN immediately. Do not transmit sensitive data. Consider using mobile data instead."
	case models.WiFiSecurityWEP:
		return "Upgrade to WPA2 or WPA3 if this is your network. Use VPN if connecting."
	case models.WiFiSecurityWPA:
		return "Upgrade to WPA2 or WPA3 for better security."
	default:
		return "Keep your device and router firmware updated."
	}
}

func (s *NetworkSecurityService) detectRogueAPs(result *models.WiFiAuditResult, networks []models.WiFiNetwork) {
	// Group networks by SSID
	ssidGroups := make(map[string][]models.WiFiNetwork)
	for _, network := range networks {
		ssidGroups[network.SSID] = append(ssidGroups[network.SSID], network)
	}

	// Check for suspicious patterns
	for ssid, nets := range ssidGroups {
		if len(nets) > 1 {
			// Multiple APs with same SSID - check for inconsistencies
			for i := 1; i < len(nets); i++ {
				if nets[i].SecurityType != nets[0].SecurityType {
					// Different security types for same SSID - suspicious
					result.RogueAPDetected = append(result.RogueAPDetected, models.RogueAPAlert{
						SSID:              ssid,
						BSSID:             nets[i].BSSID,
						SignalStrength:    nets[i].SignalLevel,
						SecurityType:      nets[i].SecurityType,
						RiskLevel:         models.NetworkRiskLevelHigh,
						Reason:            fmt.Sprintf("Same SSID '%s' but different security type than other APs", ssid),
						LegitimateNetwork: &nets[0],
						DetectedAt:        time.Now(),
					})
				}
			}
		}

		// Check for SSIDs that impersonate known networks
		s.checkSSIDImpersonation(result, ssid, nets)
	}
}

func (s *NetworkSecurityService) checkSSIDImpersonation(result *models.WiFiAuditResult, ssid string, networks []models.WiFiNetwork) {
	// Known legitimate SSIDs that are commonly impersonated
	knownSSIDs := map[string]bool{
		"attwifi":        true,
		"xfinitywifi":    true,
		"Starbucks WiFi": true,
		"Google Starbucks": true,
		"McDonald's Free WiFi": true,
	}

	// Check for typosquatting
	ssidLower := strings.ToLower(ssid)
	for known := range knownSSIDs {
		knownLower := strings.ToLower(known)
		if ssidLower != knownLower && s.isSimilar(ssidLower, knownLower) {
			for _, network := range networks {
				result.RogueAPDetected = append(result.RogueAPDetected, models.RogueAPAlert{
					SSID:           ssid,
					BSSID:          network.BSSID,
					SignalStrength: network.SignalLevel,
					SecurityType:   network.SecurityType,
					RiskLevel:      models.NetworkRiskLevelHigh,
					Reason:         fmt.Sprintf("SSID '%s' appears to impersonate legitimate network '%s'", ssid, known),
					DetectedAt:     time.Now(),
				})
			}
		}
	}
}

func (s *NetworkSecurityService) isSimilar(a, b string) bool {
	// Simple similarity check - could be improved with Levenshtein distance
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	// Check for common substitutions
	substitutions := map[string]string{
		"1": "l", "l": "1",
		"0": "o", "o": "0",
		"_": "-", "-": "_",
		" ": "", "": " ",
	}

	normalizedA := a
	normalizedB := b
	for old, new := range substitutions {
		normalizedA = strings.ReplaceAll(normalizedA, old, new)
		normalizedB = strings.ReplaceAll(normalizedB, old, new)
	}

	// Check if one contains the other (after normalization)
	if strings.Contains(normalizedA, normalizedB) || strings.Contains(normalizedB, normalizedA) {
		return len(a) != len(b) // Only similar if lengths differ
	}

	return false
}

func (s *NetworkSecurityService) detectEvilTwin(result *models.WiFiAuditResult, current *models.WiFiNetwork, nearby []models.WiFiNetwork) {
	for _, network := range nearby {
		// Same SSID but different BSSID
		if network.SSID == current.SSID && network.BSSID != current.BSSID {
			confidence := 0.5

			// Higher confidence if security types differ
			if network.SecurityType != current.SecurityType {
				confidence += 0.3
			}

			// Higher confidence if the other AP has weaker security
			if s.isWeakerSecurity(network.SecurityType, current.SecurityType) {
				confidence += 0.2
			}

			// Higher confidence if signal strength is unusually high
			if network.SignalLevel > current.SignalLevel+10 {
				confidence += 0.1
			}

			if confidence >= 0.6 {
				result.EvilTwinDetected = append(result.EvilTwinDetected, models.EvilTwinAlert{
					SSID:           current.SSID,
					LegitBSSID:     current.BSSID,
					EvilBSSID:      network.BSSID,
					SignalDiff:     network.SignalLevel - current.SignalLevel,
					SecurityDiff:   network.SecurityType != current.SecurityType,
					RiskLevel:      models.NetworkRiskLevelCritical,
					Confidence:     confidence,
					Description:    fmt.Sprintf("Potential evil twin detected for '%s'", current.SSID),
					Recommendation: "Do not connect to this network. If already connected, use VPN immediately.",
					DetectedAt:     time.Now(),
				})
			}
		}
	}
}

func (s *NetworkSecurityService) isWeakerSecurity(a, b models.WiFiSecurityType) bool {
	securityOrder := map[models.WiFiSecurityType]int{
		models.WiFiSecurityOpen:    0,
		models.WiFiSecurityWEP:     1,
		models.WiFiSecurityWPA:     2,
		models.WiFiSecurityWPA2:    3,
		models.WiFiSecurityWPA3:    4,
		models.WiFiSecurityUnknown: 0,
	}
	return securityOrder[a] < securityOrder[b]
}

func (s *NetworkSecurityService) calculateWiFiRisk(result *models.WiFiAuditResult) (float64, models.NetworkRiskLevel) {
	score := 0.0

	// Base score from security issues
	for _, issue := range result.SecurityIssues {
		switch issue.Severity {
		case models.NetworkRiskLevelCritical:
			score += 0.4
		case models.NetworkRiskLevelHigh:
			score += 0.25
		case models.NetworkRiskLevelMedium:
			score += 0.15
		case models.NetworkRiskLevelLow:
			score += 0.05
		}
	}

	// Add score for detected attacks
	score += float64(len(result.RogueAPDetected)) * 0.2
	score += float64(len(result.EvilTwinDetected)) * 0.3

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	// Determine risk level
	var level models.NetworkRiskLevel
	switch {
	case score >= 0.8:
		level = models.NetworkRiskLevelCritical
	case score >= 0.6:
		level = models.NetworkRiskLevelHigh
	case score >= 0.4:
		level = models.NetworkRiskLevelMedium
	case score >= 0.2:
		level = models.NetworkRiskLevelLow
	default:
		level = models.NetworkRiskLevelSafe
	}

	return score, level
}

func (s *NetworkSecurityService) generateWiFiRecommendations(result *models.WiFiAuditResult) {
	// Critical: Evil twin detected
	if len(result.EvilTwinDetected) > 0 {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "critical",
			Title:       "Evil Twin Attack Detected",
			Description: "A malicious access point is impersonating this network. Do not transmit sensitive data.",
			Action:      "enable_vpn",
		})
	}

	// Critical: Rogue AP detected
	if len(result.RogueAPDetected) > 0 {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "critical",
			Title:       "Rogue Access Point Detected",
			Description: "Unauthorized access points detected. Verify you're connected to the legitimate network.",
			Action:      "verify_network",
		})
	}

	// High: Weak encryption
	for _, issue := range result.SecurityIssues {
		if issue.Type == "weak_encryption" && (issue.Severity == models.NetworkRiskLevelCritical || issue.Severity == models.NetworkRiskLevelHigh) {
			result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
				Priority:    "high",
				Title:       "Enable VPN Protection",
				Description: "This network uses weak encryption. Enable VPN to protect your data.",
				Action:      "enable_vpn",
			})
			break
		}
	}

	// Medium: Public network
	for _, issue := range result.SecurityIssues {
		if issue.Type == "public_network" {
			result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
				Priority:    "medium",
				Title:       "Public Wi-Fi Detected",
				Description: "Use VPN when on public Wi-Fi and avoid sensitive transactions.",
				Action:      "enable_vpn",
			})
			break
		}
	}

	// Low: Consider WPA3
	if result.Network != nil && result.Network.SecurityType == models.WiFiSecurityWPA2 {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "low",
			Title:       "Consider WPA3 Upgrade",
			Description: "WPA3 provides stronger security than WPA2 if your router supports it.",
			Action:      "upgrade_security",
		})
	}
}

// CheckDNS performs a DNS security check
func (s *NetworkSecurityService) CheckDNS(ctx context.Context, req *models.DNSCheckRequest) (*models.DNSCheckResult, error) {
	result := &models.DNSCheckResult{
		ID:              uuid.New(),
		CurrentDNS:      req.CurrentDNS,
		SecurityIssues:  make([]models.DNSSecurityIssue, 0),
		Recommendations: make([]models.NetworkRecommendation, 0),
		CheckedAt:       time.Now(),
	}

	// Check if DNS is from a known provider
	if provider, ok := models.KnownDNSProviders[req.CurrentDNS]; ok {
		result.Provider = provider
		result.IsSecure = provider.IsTrusted
		result.IsEncrypted = provider.SupportsDoH || provider.SupportsDoT
		if provider.SupportsDoH {
			result.EncryptionType = "doh"
		} else if provider.SupportsDoT {
			result.EncryptionType = "dot"
		}
	} else {
		// Unknown DNS - could be ISP or potentially malicious
		result.IsSecure = false
		result.SecurityIssues = append(result.SecurityIssues, models.DNSSecurityIssue{
			Type:        "unknown_dns",
			Severity:    models.NetworkRiskLevelMedium,
			Title:       "Unknown DNS Server",
			Description: fmt.Sprintf("DNS server %s is not a recognized trusted provider", req.CurrentDNS),
			Mitigation:  "Consider switching to a trusted DNS provider like Cloudflare (1.1.1.1) or Quad9 (9.9.9.9)",
		})
	}

	// Check for DNS hijacking if requested
	if req.CheckHijack {
		s.checkDNSHijacking(ctx, result)
	}

	// Check for DNS leaks if requested
	if req.CheckLeaks {
		s.checkDNSLeaks(ctx, result)
	}

	// Generate recommendations
	s.generateDNSRecommendations(result)

	s.logger.Info().
		Str("dns", req.CurrentDNS).
		Bool("is_secure", result.IsSecure).
		Bool("is_hijacked", result.IsHijacked).
		Msg("DNS check completed")

	return result, nil
}

func (s *NetworkSecurityService) checkDNSHijacking(ctx context.Context, result *models.DNSCheckResult) {
	// Test domains that should resolve to known IPs
	testCases := []struct {
		domain     string
		expectedIP string // simplified - in reality would check against known good IPs
	}{
		{"www.google.com", ""},
		{"www.cloudflare.com", ""},
	}

	for _, tc := range testCases {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", tc.domain)
		if err != nil {
			continue
		}

		// Check if resolved IP looks suspicious
		for _, ip := range ips {
			if s.isSuspiciousIP(ip) {
				result.IsHijacked = true
				result.HijackDetails = &models.DNSHijackDetails{
					ExpectedIP:  tc.expectedIP,
					ResolvedIP:  ip.String(),
					TestDomain:  tc.domain,
					Confidence:  0.8,
					Description: fmt.Sprintf("DNS resolution for %s returned suspicious IP %s", tc.domain, ip.String()),
					DetectedAt:  time.Now(),
				}
				result.SecurityIssues = append(result.SecurityIssues, models.DNSSecurityIssue{
					Type:        "dns_hijacking",
					Severity:    models.NetworkRiskLevelCritical,
					Title:       "DNS Hijacking Detected",
					Description: "Your DNS queries are being redirected to potentially malicious servers",
					Mitigation:  "Switch to encrypted DNS (DoH) immediately. Consider using VPN.",
				})
				return
			}
		}
	}
}

func (s *NetworkSecurityService) isSuspiciousIP(ip net.IP) bool {
	// Check for private IPs (shouldn't resolve for public domains)
	if ip.IsPrivate() || ip.IsLoopback() {
		return true
	}

	// Check for known malicious IP ranges (simplified)
	// In production, this would check against threat intelligence
	return false
}

func (s *NetworkSecurityService) checkDNSLeaks(ctx context.Context, result *models.DNSCheckResult) {
	// In production, this would:
	// 1. Make requests to a DNS leak test service
	// 2. Check which DNS servers actually handled the request
	// 3. Report if queries went to unexpected servers

	// For now, we'll just check if using encrypted DNS
	if !result.IsEncrypted {
		result.LeakDetected = true
		result.LeakDetails = &models.DNSLeakDetails{
			LeakedToISP: true,
			Description: "DNS queries are not encrypted and may be visible to your ISP",
			DetectedAt:  time.Now(),
		}
		result.SecurityIssues = append(result.SecurityIssues, models.DNSSecurityIssue{
			Type:        "dns_leak",
			Severity:    models.NetworkRiskLevelMedium,
			Title:       "Potential DNS Leak",
			Description: "Your DNS queries are not encrypted and could be monitored",
			Mitigation:  "Enable DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)",
		})
	}
}

func (s *NetworkSecurityService) generateDNSRecommendations(result *models.DNSCheckResult) {
	// Critical: DNS hijacking
	if result.IsHijacked {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "critical",
			Title:       "Switch DNS Immediately",
			Description: "Your DNS is being hijacked. Switch to encrypted DNS (1.1.1.1 or 9.9.9.9) now.",
			Action:      "change_dns",
		})
	}

	// High: Not using encrypted DNS
	if !result.IsEncrypted {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "high",
			Title:       "Enable Encrypted DNS",
			Description: "Use DNS-over-HTTPS (DoH) for privacy. Recommended: Cloudflare (1.1.1.1) or Quad9 (9.9.9.9).",
			Action:      "enable_doh",
		})
	}

	// Medium: Not using malware-blocking DNS
	if result.Provider != nil && !result.Provider.BlocksMalware {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "medium",
			Title:       "Consider Malware-Blocking DNS",
			Description: "Use DNS that blocks malicious domains (Quad9, Cloudflare 1.1.1.2, or AdGuard).",
			Action:      "change_dns",
		})
	}

	// Low: Unknown provider
	if result.Provider == nil {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "medium",
			Title:       "Switch to Trusted DNS",
			Description: "Your current DNS provider is unknown. Consider switching to a trusted provider.",
			Action:      "change_dns",
		})
	}
}

// CheckARPSpoofing checks for ARP spoofing attacks
func (s *NetworkSecurityService) CheckARPSpoofing(ctx context.Context, req *models.ARPSpoofCheckRequest) (*models.ARPSpoofCheckResult, error) {
	result := &models.ARPSpoofCheckResult{
		ID:              uuid.New(),
		Alerts:          make([]models.NetworkAttackAlert, 0),
		SuspiciousMACs:  make([]string, 0),
		DuplicateIPs:    make([]string, 0),
		Recommendations: make([]models.NetworkRecommendation, 0),
		CheckedAt:       time.Now(),
	}

	// Check for multiple IPs with same MAC (normal for routers, suspicious otherwise)
	macToIPs := make(map[string][]string)
	for _, entry := range req.ARPTable {
		macToIPs[entry.MACAddress] = append(macToIPs[entry.MACAddress], entry.IPAddress)
	}

	for mac, ips := range macToIPs {
		if len(ips) > 1 {
			// Check if this is the gateway (multiple IPs normal)
			isGateway := false
			for _, ip := range ips {
				if ip == req.GatewayIP {
					isGateway = true
					break
				}
			}

			if !isGateway {
				result.SuspiciousMACs = append(result.SuspiciousMACs, mac)
				result.DuplicateIPs = append(result.DuplicateIPs, ips...)
			}
		}
	}

	// Check for multiple MACs claiming same IP (definitely suspicious)
	ipToMACs := make(map[string][]string)
	for _, entry := range req.ARPTable {
		ipToMACs[entry.IPAddress] = append(ipToMACs[entry.IPAddress], entry.MACAddress)
	}

	for ip, macs := range ipToMACs {
		if len(macs) > 1 {
			result.IsSpoofDetected = true
			attackInfo := models.NetworkAttackDescriptions[models.NetworkAttackARPSpoofing]
			result.Alerts = append(result.Alerts, models.NetworkAttackAlert{
				ID:          uuid.New(),
				Type:        models.NetworkAttackARPSpoofing,
				Severity:    attackInfo.Severity,
				Title:       attackInfo.Title,
				Description: fmt.Sprintf("Multiple MAC addresses claiming IP %s: %v", ip, macs),
				Evidence:    []string{fmt.Sprintf("IP %s has MACs: %v", ip, macs)},
				Mitigation:  attackInfo.Mitigation,
				DetectedAt:  time.Now(),
			})
		}
	}

	// Check if gateway MAC has changed (if we have history)
	if req.GatewayIP != "" && req.GatewayMAC != "" {
		s.gatewaysMu.RLock()
		knownMAC, exists := s.knownGateways[req.GatewayIP]
		s.gatewaysMu.RUnlock()

		if exists && knownMAC != req.GatewayMAC {
			result.IsSpoofDetected = true
			attackInfo := models.NetworkAttackDescriptions[models.NetworkAttackARPSpoofing]
			result.Alerts = append(result.Alerts, models.NetworkAttackAlert{
				ID:          uuid.New(),
				Type:        models.NetworkAttackARPSpoofing,
				Severity:    models.NetworkRiskLevelCritical,
				Title:       "Gateway MAC Address Changed",
				Description: fmt.Sprintf("Gateway %s MAC changed from %s to %s", req.GatewayIP, knownMAC, req.GatewayMAC),
				Evidence:    []string{fmt.Sprintf("Previous: %s, Current: %s", knownMAC, req.GatewayMAC)},
				Mitigation:  attackInfo.Mitigation,
				DetectedAt:  time.Now(),
			})
		} else if !exists {
			// Store for future comparison
			s.gatewaysMu.Lock()
			s.knownGateways[req.GatewayIP] = req.GatewayMAC
			s.gatewaysMu.Unlock()
		}
	}

	// Generate recommendations
	if result.IsSpoofDetected {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "critical",
			Title:       "ARP Spoofing Detected - Enable VPN",
			Description: "An attacker may be intercepting your traffic. Enable VPN immediately.",
			Action:      "enable_vpn",
		})
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "high",
			Title:       "Avoid Sensitive Activities",
			Description: "Do not perform banking or enter passwords on this network.",
			Action:      "avoid_sensitive",
		})
	}

	s.logger.Info().
		Bool("spoof_detected", result.IsSpoofDetected).
		Int("alerts", len(result.Alerts)).
		Msg("ARP spoof check completed")

	return result, nil
}

// CheckSSL checks SSL/TLS security for a host
func (s *NetworkSecurityService) CheckSSL(ctx context.Context, req *models.SSLCheckRequest) (*models.SSLCheckResult, error) {
	port := req.Port
	if port == 0 {
		port = 443
	}

	result := &models.SSLCheckResult{
		ID:              uuid.New(),
		Host:            req.Host,
		Port:            port,
		SecurityIssues:  make([]models.SSLSecurityIssue, 0),
		Recommendations: make([]models.NetworkRecommendation, 0),
		CheckedAt:       time.Now(),
	}

	// Connect with TLS
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", req.Host, port),
		&tls.Config{
			InsecureSkipVerify: true, // We want to inspect even invalid certs
		},
	)
	if err != nil {
		result.IsSecure = false
		result.SecurityIssues = append(result.SecurityIssues, models.SSLSecurityIssue{
			Type:        "connection_failed",
			Severity:    models.NetworkRiskLevelHigh,
			Title:       "TLS Connection Failed",
			Description: fmt.Sprintf("Could not establish TLS connection: %v", err),
			Mitigation:  "The server may not support HTTPS or may be down",
		})
		return result, nil
	}
	defer conn.Close()

	// Get connection state
	state := conn.ConnectionState()

	// Check TLS version
	result.TLSVersion = s.tlsVersionString(state.Version)
	if state.Version < tls.VersionTLS12 {
		result.SecurityIssues = append(result.SecurityIssues, models.SSLSecurityIssue{
			Type:        "old_tls",
			Severity:    models.NetworkRiskLevelHigh,
			Title:       "Outdated TLS Version",
			Description: fmt.Sprintf("Server uses %s which has known vulnerabilities", result.TLSVersion),
			Mitigation:  "Server should be upgraded to TLS 1.2 or higher",
		})
	}

	// Check cipher suite
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Check certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = &models.SSLCertificate{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			IsExpired:    time.Now().After(cert.NotAfter),
			IsSelfSigned: cert.Subject.String() == cert.Issuer.String(),
			IsValid:      !time.Now().After(cert.NotAfter) && !time.Now().Before(cert.NotBefore),
			PublicKeyAlg: cert.PublicKeyAlgorithm.String(),
		}

		// Check for issues
		if result.Certificate.IsExpired {
			result.SecurityIssues = append(result.SecurityIssues, models.SSLSecurityIssue{
				Type:        "expired_cert",
				Severity:    models.NetworkRiskLevelCritical,
				Title:       "Expired Certificate",
				Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
				Mitigation:  "Do not proceed - this could indicate a MITM attack",
			})
		}

		if result.Certificate.IsSelfSigned {
			result.SecurityIssues = append(result.SecurityIssues, models.SSLSecurityIssue{
				Type:        "self_signed",
				Severity:    models.NetworkRiskLevelHigh,
				Title:       "Self-Signed Certificate",
				Description: "Certificate is not signed by a trusted authority",
				Mitigation:  "Only proceed if you trust this server explicitly",
			})
		}

		// Verify certificate chain
		result.IsValidChain = len(state.VerifiedChains) > 0
	}

	// Determine overall security
	result.IsSecure = len(result.SecurityIssues) == 0

	// Generate recommendations
	if !result.IsSecure {
		result.Recommendations = append(result.Recommendations, models.NetworkRecommendation{
			Priority:    "high",
			Title:       "Proceed with Caution",
			Description: "This connection has security issues. Verify you're connecting to the correct server.",
			Action:      "verify_connection",
		})
	}

	s.logger.Info().
		Str("host", req.Host).
		Bool("is_secure", result.IsSecure).
		Str("tls_version", result.TLSVersion).
		Msg("SSL check completed")

	return result, nil
}

func (s *NetworkSecurityService) tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// GetVPNRecommendation returns VPN usage recommendation based on network conditions
func (s *NetworkSecurityService) GetVPNRecommendation(ctx context.Context, wifiAudit *models.WiFiAuditResult, dnsCheck *models.DNSCheckResult) *models.VPNRecommendation {
	rec := &models.VPNRecommendation{
		ShouldConnect: false,
		Priority:      "optional",
		NetworkRisk:   models.NetworkRiskLevelSafe,
	}

	// Check Wi-Fi audit results
	if wifiAudit != nil {
		rec.NetworkRisk = wifiAudit.RiskLevel

		if len(wifiAudit.EvilTwinDetected) > 0 {
			rec.ShouldConnect = true
			rec.Priority = "required"
			rec.Reason = "Evil twin attack detected - VPN required for protection"
			return rec
		}

		if len(wifiAudit.RogueAPDetected) > 0 {
			rec.ShouldConnect = true
			rec.Priority = "required"
			rec.Reason = "Rogue access point detected - VPN strongly recommended"
			return rec
		}

		if wifiAudit.RiskLevel == models.NetworkRiskLevelCritical || wifiAudit.RiskLevel == models.NetworkRiskLevelHigh {
			rec.ShouldConnect = true
			rec.Priority = "recommended"
			rec.Reason = "Network has significant security risks - VPN recommended"
			return rec
		}

		// Check for weak encryption
		for _, issue := range wifiAudit.SecurityIssues {
			if issue.Type == "weak_encryption" && issue.Severity == models.NetworkRiskLevelCritical {
				rec.ShouldConnect = true
				rec.Priority = "required"
				rec.Reason = "Network uses weak/no encryption - VPN required"
				return rec
			}
		}

		// Check for public network
		for _, issue := range wifiAudit.SecurityIssues {
			if issue.Type == "public_network" {
				rec.ShouldConnect = true
				rec.Priority = "recommended"
				rec.Reason = "Public Wi-Fi detected - VPN recommended for privacy"
				return rec
			}
		}
	}

	// Check DNS results
	if dnsCheck != nil {
		if dnsCheck.IsHijacked {
			rec.ShouldConnect = true
			rec.Priority = "required"
			rec.Reason = "DNS hijacking detected - VPN required"
			return rec
		}

		if !dnsCheck.IsSecure {
			rec.ShouldConnect = true
			rec.Priority = "recommended"
			rec.Reason = "DNS is not secure - VPN recommended"
			return rec
		}
	}

	rec.Reason = "Network appears safe - VPN optional"
	return rec
}

// GetStats returns network security statistics
func (s *NetworkSecurityService) GetStats(ctx context.Context) (*models.NetworkSecurityStats, error) {
	stats := &models.NetworkSecurityStats{
		AttacksByType: make(map[string]int64),
	}

	// In production, these would come from database
	// For now, return placeholder data
	if s.cache != nil {
		// Try to get cached stats
		// Implementation would use cache.Get()
	}

	return stats, nil
}
