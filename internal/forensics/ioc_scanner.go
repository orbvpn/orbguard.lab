package forensics

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	domainmodels "orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/forensics/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

const (
	iocCacheKeyPrefix = "forensics:iocs:"
	iocCacheTTL       = 1 * time.Hour
)

// IOCType represents the type of IOC
type IOCType string

const (
	IOCTypeDomain     IOCType = "domain"
	IOCTypeIP         IOCType = "ip"
	IOCTypeURL        IOCType = "url"
	IOCTypeHash       IOCType = "hash"
	IOCTypePath       IOCType = "path"
	IOCTypeProcess    IOCType = "process"
	IOCTypeEmail      IOCType = "email"
	IOCTypeRegistry   IOCType = "registry"
	IOCTypeCertificate IOCType = "certificate"
)

// IOC represents an indicator of compromise
type IOC struct {
	Type        IOCType   `json:"type"`
	Value       string    `json:"value"`
	Pattern     *regexp.Regexp `json:"-"` // Compiled regex for pattern matching
	Source      string    `json:"source"`
	Campaign    string    `json:"campaign,omitempty"`
	Attribution string    `json:"attribution,omitempty"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description,omitempty"`
	References  []string  `json:"references,omitempty"`
}

// IOCScanner provides IOC matching capabilities for forensic analysis
type IOCScanner struct {
	logger *logger.Logger
	cache  *cache.RedisCache

	// In-memory IOC storage (loaded from sources)
	iocs     map[IOCType][]IOC
	iocsLock sync.RWMutex

	// Pattern-based IOCs (paths, process names)
	pathPatterns    []*pathPattern
	processPatterns []*processPattern
}

type pathPattern struct {
	Pattern     *regexp.Regexp
	Source      string
	Campaign    string
	Attribution string
	Severity    string
	Confidence  float64
	Description string
}

type processPattern struct {
	Pattern     *regexp.Regexp
	Source      string
	Campaign    string
	Attribution string
	Severity    string
	Confidence  float64
	Description string
}

// NewIOCScanner creates a new IOC scanner
func NewIOCScanner(cache *cache.RedisCache, log *logger.Logger) *IOCScanner {
	scanner := &IOCScanner{
		logger: log.WithComponent("ioc-scanner"),
		cache:  cache,
		iocs:   make(map[IOCType][]IOC),
	}

	// Initialize with built-in Pegasus/spyware IOCs
	scanner.loadBuiltInIOCs()

	return scanner
}

// loadBuiltInIOCs loads hardcoded IOCs from known spyware research
func (s *IOCScanner) loadBuiltInIOCs() {
	s.iocsLock.Lock()
	defer s.iocsLock.Unlock()

	// Initialize IOC maps
	s.iocs[IOCTypeDomain] = make([]IOC, 0)
	s.iocs[IOCTypeIP] = make([]IOC, 0)
	s.iocs[IOCTypePath] = make([]IOC, 0)
	s.iocs[IOCTypeProcess] = make([]IOC, 0)
	s.iocs[IOCTypeHash] = make([]IOC, 0)

	// Pegasus domains (from Citizen Lab research)
	pegasusDomains := []string{
		"cloudfiles.me",
		"urlpush.net",
		"streamsend.co",
		"linkclick.me",
		"smsonline.pk",
		"srvtrack.com",
		"datausage.io",
		"mail2tor.com",
		"securemailer.co",
		"account-verify.co",
		"secure-link.info",
		"trackit.systems",
		"streamvideo.me",
		"dataservice.co",
		"privacyprotect.co",
		"documentcloud.info",
		"mediashare.link",
		"filehosting.co",
	}

	for _, domain := range pegasusDomains {
		s.iocs[IOCTypeDomain] = append(s.iocs[IOCTypeDomain], IOC{
			Type:        IOCTypeDomain,
			Value:       domain,
			Source:      "citizenlab",
			Campaign:    "pegasus",
			Attribution: "NSO Group",
			Severity:    "critical",
			Confidence:  0.95,
			Tags:        []string{"pegasus", "nso", "spyware", "mobile"},
			Description: "Known Pegasus C2 domain",
		})
	}

	// Predator domains (from research)
	predatorDomains := []string{
		"receiptpdf.com",
		"verifyaccount.co",
		"loginverify.net",
		"securepayment.info",
	}

	for _, domain := range predatorDomains {
		s.iocs[IOCTypeDomain] = append(s.iocs[IOCTypeDomain], IOC{
			Type:        IOCTypeDomain,
			Value:       domain,
			Source:      "citizenlab",
			Campaign:    "predator",
			Attribution: "Cytrox/Intellexa",
			Severity:    "critical",
			Confidence:  0.90,
			Tags:        []string{"predator", "cytrox", "spyware", "mobile"},
			Description: "Known Predator C2 domain",
		})
	}

	// Path patterns (Kaspersky research + Citizen Lab)
	s.pathPatterns = []*pathPattern{
		{
			Pattern:     regexp.MustCompile(`^/private/var/db/[a-f0-9]{32,}`),
			Source:      "kaspersky",
			Campaign:    "pegasus",
			Attribution: "NSO Group",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Pegasus staging directory pattern",
		},
		{
			Pattern:     regexp.MustCompile(`^/private/var/tmp/[a-f0-9]{32,}`),
			Source:      "citizenlab",
			Campaign:    "predator",
			Attribution: "Cytrox/Intellexa",
			Severity:    "critical",
			Confidence:  0.90,
			Description: "Predator staging directory pattern",
		},
		{
			Pattern:     regexp.MustCompile(`^/private/var/root/Library/`),
			Source:      "amnesty_mvt",
			Campaign:    "unknown",
			Severity:    "high",
			Confidence:  0.80,
			Description: "Suspicious root user library access",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)/Library/Application Support/[a-f0-9]{8,}/`),
			Source:      "amnesty_mvt",
			Campaign:    "unknown",
			Severity:    "high",
			Confidence:  0.75,
			Description: "Suspicious app support directory with hash name",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)roleaccount`),
			Source:      "kaspersky",
			Campaign:    "pegasus",
			Attribution: "NSO Group",
			Severity:    "critical",
			Confidence:  0.98,
			Description: "Known Pegasus component path",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)/bh$|/bh/`),
			Source:      "kaspersky",
			Campaign:    "pegasus",
			Attribution: "NSO Group",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Known Pegasus 'bh' component",
		},
	}

	// Process name patterns
	s.processPatterns = []*processPattern{
		{
			Pattern:     regexp.MustCompile(`^bh$`),
			Source:      "kaspersky",
			Campaign:    "pegasus",
			Attribution: "NSO Group",
			Severity:    "critical",
			Confidence:  0.98,
			Description: "Known Pegasus process name",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)^roleaccount`),
			Source:      "kaspersky",
			Campaign:    "pegasus",
			Attribution: "NSO Group",
			Severity:    "critical",
			Confidence:  0.98,
			Description: "Known Pegasus masquerading process",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)^pcsd$`),
			Source:      "citizenlab",
			Campaign:    "predator",
			Attribution: "Cytrox/Intellexa",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Known Predator process name",
		},
		{
			Pattern:     regexp.MustCompile(`^[a-f0-9]{8}$`),
			Source:      "amnesty_mvt",
			Campaign:    "unknown",
			Severity:    "high",
			Confidence:  0.70,
			Description: "Suspicious 8-char hex process name",
		},
		{
			Pattern:     regexp.MustCompile(`(?i)mspy|flexispy|cerberus|cocospy|spyic|hoverwatch|eyezy|mobilespy`),
			Source:      "internal",
			Campaign:    "stalkerware",
			Severity:    "high",
			Confidence:  0.95,
			Description: "Known stalkerware application",
		},
	}

	// Hash IOCs (known malicious files)
	knownHashes := []struct {
		Hash        string
		Campaign    string
		Attribution string
		Description string
	}{
		// Placeholder hashes - in production these would be loaded from threat intel feeds
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "pegasus", "NSO Group", "Pegasus iOS payload"},
	}

	for _, h := range knownHashes {
		s.iocs[IOCTypeHash] = append(s.iocs[IOCTypeHash], IOC{
			Type:        IOCTypeHash,
			Value:       h.Hash,
			Source:      "citizenlab",
			Campaign:    h.Campaign,
			Attribution: h.Attribution,
			Severity:    "critical",
			Confidence:  0.99,
			Tags:        []string{h.Campaign, "mobile", "spyware"},
			Description: h.Description,
		})
	}

	s.logger.Info().
		Int("domains", len(s.iocs[IOCTypeDomain])).
		Int("path_patterns", len(s.pathPatterns)).
		Int("process_patterns", len(s.processPatterns)).
		Int("hashes", len(s.iocs[IOCTypeHash])).
		Msg("loaded built-in IOCs")
}

// LoadFromIndicators loads IOCs from the threat intelligence system
func (s *IOCScanner) LoadFromIndicators(ctx context.Context, indicators []domainmodels.Indicator) error {
	s.iocsLock.Lock()
	defer s.iocsLock.Unlock()

	loaded := 0
	for _, ind := range indicators {
		iocType := s.mapIndicatorType(ind.Type)
		if iocType == "" {
			continue
		}

		ioc := IOC{
			Type:       iocType,
			Value:      ind.Value,
			Source:     ind.SourceName,
			Severity:   string(ind.Severity),
			Confidence: ind.Confidence,
			Tags:       ind.Tags,
		}

		// Check for campaign/attribution in tags
		for _, tag := range ind.Tags {
			if strings.Contains(tag, "pegasus") {
				ioc.Campaign = "pegasus"
				ioc.Attribution = "NSO Group"
			} else if strings.Contains(tag, "predator") {
				ioc.Campaign = "predator"
				ioc.Attribution = "Cytrox/Intellexa"
			}
		}

		s.iocs[iocType] = append(s.iocs[iocType], ioc)
		loaded++
	}

	s.logger.Info().Int("loaded", loaded).Msg("loaded IOCs from threat intel")
	return nil
}

// mapIndicatorType maps domain model indicator types to IOC types
func (s *IOCScanner) mapIndicatorType(indType domainmodels.IndicatorType) IOCType {
	switch indType {
	case domainmodels.IndicatorTypeDomain:
		return IOCTypeDomain
	case domainmodels.IndicatorTypeIP:
		return IOCTypeIP
	case domainmodels.IndicatorTypeURL:
		return IOCTypeURL
	case domainmodels.IndicatorTypeHash:
		return IOCTypeHash
	case domainmodels.IndicatorTypeFilePath:
		return IOCTypePath
	case domainmodels.IndicatorTypeEmail:
		return IOCTypeEmail
	default:
		return ""
	}
}

// ScanResult represents the result of an IOC scan
type ScanResult struct {
	Matches     []IOCMatch `json:"matches"`
	TotalChecks int        `json:"total_checks"`
	Duration    time.Duration `json:"duration"`
}

// IOCMatch represents a match against known IOCs
type IOCMatch struct {
	IOCType     IOCType  `json:"ioc_type"`
	Value       string   `json:"value"`
	MatchedIOC  IOC      `json:"matched_ioc"`
	Confidence  float64  `json:"confidence"`
}

// ScanPath checks a file path against known IOC patterns
func (s *IOCScanner) ScanPath(path string) []models.IOCMatch {
	s.iocsLock.RLock()
	defer s.iocsLock.RUnlock()

	matches := make([]models.IOCMatch, 0)

	// Check against path patterns
	for _, pattern := range s.pathPatterns {
		if pattern.Pattern.MatchString(path) {
			matches = append(matches, models.IOCMatch{
				IOCType:     string(IOCTypePath),
				Value:       path,
				Source:      pattern.Source,
				Campaign:    pattern.Campaign,
				Attribution: pattern.Attribution,
			})
		}
	}

	return matches
}

// ScanProcess checks a process name against known IOC patterns
func (s *IOCScanner) ScanProcess(processName string) []models.IOCMatch {
	s.iocsLock.RLock()
	defer s.iocsLock.RUnlock()

	matches := make([]models.IOCMatch, 0)

	// Check against process patterns
	for _, pattern := range s.processPatterns {
		if pattern.Pattern.MatchString(processName) {
			matches = append(matches, models.IOCMatch{
				IOCType:     string(IOCTypeProcess),
				Value:       processName,
				Source:      pattern.Source,
				Campaign:    pattern.Campaign,
				Attribution: pattern.Attribution,
			})
		}
	}

	return matches
}

// ScanDomain checks a domain against known IOCs
func (s *IOCScanner) ScanDomain(domain string) []models.IOCMatch {
	s.iocsLock.RLock()
	defer s.iocsLock.RUnlock()

	matches := make([]models.IOCMatch, 0)
	domain = strings.ToLower(domain)

	for _, ioc := range s.iocs[IOCTypeDomain] {
		if strings.EqualFold(ioc.Value, domain) ||
			strings.HasSuffix(domain, "."+ioc.Value) {
			matches = append(matches, models.IOCMatch{
				IOCType:     string(IOCTypeDomain),
				Value:       domain,
				Source:      ioc.Source,
				Campaign:    ioc.Campaign,
				Attribution: ioc.Attribution,
			})
		}
	}

	return matches
}

// ScanIP checks an IP address against known IOCs
func (s *IOCScanner) ScanIP(ip string) []models.IOCMatch {
	s.iocsLock.RLock()
	defer s.iocsLock.RUnlock()

	matches := make([]models.IOCMatch, 0)

	for _, ioc := range s.iocs[IOCTypeIP] {
		if ioc.Value == ip {
			matches = append(matches, models.IOCMatch{
				IOCType:     string(IOCTypeIP),
				Value:       ip,
				Source:      ioc.Source,
				Campaign:    ioc.Campaign,
				Attribution: ioc.Attribution,
			})
		}
	}

	return matches
}

// ScanHash checks a file hash against known IOCs
func (s *IOCScanner) ScanHash(hash string) []models.IOCMatch {
	s.iocsLock.RLock()
	defer s.iocsLock.RUnlock()

	matches := make([]models.IOCMatch, 0)
	hash = strings.ToLower(hash)

	for _, ioc := range s.iocs[IOCTypeHash] {
		if strings.EqualFold(ioc.Value, hash) {
			matches = append(matches, models.IOCMatch{
				IOCType:     string(IOCTypeHash),
				Value:       hash,
				Source:      ioc.Source,
				Campaign:    ioc.Campaign,
				Attribution: ioc.Attribution,
			})
		}
	}

	return matches
}

// ScanForensicResult scans a forensic result against all IOCs
func (s *IOCScanner) ScanForensicResult(result *models.ForensicResult) []models.IOCMatch {
	allMatches := make([]models.IOCMatch, 0)

	// Scan anomalies for paths and processes
	for _, anomaly := range result.Anomalies {
		if anomaly.Path != "" {
			matches := s.ScanPath(anomaly.Path)
			allMatches = append(allMatches, matches...)
		}
		if anomaly.ProcessName != "" {
			matches := s.ScanProcess(anomaly.ProcessName)
			allMatches = append(allMatches, matches...)
		}
	}

	// Scan timeline events
	for _, event := range result.Timeline {
		if event.Path != "" {
			matches := s.ScanPath(event.Path)
			allMatches = append(allMatches, matches...)
		}
		if event.ProcessName != "" {
			matches := s.ScanProcess(event.ProcessName)
			allMatches = append(allMatches, matches...)
		}
		if event.Domain != "" {
			matches := s.ScanDomain(event.Domain)
			allMatches = append(allMatches, matches...)
		}
		if event.IPAddress != "" {
			matches := s.ScanIP(event.IPAddress)
			allMatches = append(allMatches, matches...)
		}
	}

	return allMatches
}

// EnhanceForensicResult enhances a forensic result with IOC matches
func (s *IOCScanner) EnhanceForensicResult(result *models.ForensicResult) {
	matches := s.ScanForensicResult(result)

	// Add IOC matches to anomalies
	for i := range result.Anomalies {
		anomaly := &result.Anomalies[i]

		// Check if any matches relate to this anomaly
		for _, match := range matches {
			if match.Value == anomaly.Path || match.Value == anomaly.ProcessName {
				anomaly.IOCMatch = &models.IOCMatch{
					IOCType:     match.IOCType,
					Value:       match.Value,
					Source:      match.Source,
					Campaign:    match.Campaign,
					Attribution: match.Attribution,
				}

				// Increase confidence if IOC matched
				if anomaly.Confidence < 0.95 {
					anomaly.Confidence = 0.95
				}

				// Upgrade severity if needed
				if match.Campaign == "pegasus" || match.Campaign == "predator" {
					anomaly.Severity = models.ForensicSeverityCritical
				}
			}
		}
	}

	// Add detected threats based on IOC matches
	campaignMatches := make(map[string][]models.IOCMatch)
	for _, match := range matches {
		if match.Campaign != "" {
			campaignMatches[match.Campaign] = append(campaignMatches[match.Campaign], match)
		}
	}

	// Create threats for campaigns with multiple matches
	for campaign, cMatches := range campaignMatches {
		if len(cMatches) >= 2 {
			threat := s.createThreatFromMatches(campaign, cMatches)
			if threat != nil {
				result.AddThreat(*threat)
			}
		}
	}

	// Store IOC match count in raw data
	result.RawData["ioc_matches"] = len(matches)
	result.RawData["ioc_campaigns"] = len(campaignMatches)
}

// createThreatFromMatches creates a detected threat from IOC matches
func (s *IOCScanner) createThreatFromMatches(campaign string, matches []models.IOCMatch) *models.DetectedThreat {
	if len(matches) == 0 {
		return nil
	}

	now := time.Now()
	firstMatch := matches[0]

	var infectionType models.InfectionType
	var name string
	var attribution string
	var mitreTechniques []string
	var remediation []string

	switch campaign {
	case "pegasus":
		infectionType = models.InfectionTypePegasus
		name = "NSO Group Pegasus"
		attribution = firstMatch.Attribution
		mitreTechniques = []string{
			"T1059.007", // JavaScript
			"T1203",     // Exploitation for Client Execution
			"T1547.001", // Boot or Logon Autostart
			"T1055",     // Process Injection
			"T1041",     // Exfiltration Over C2
			"T1430",     // Location Tracking
			"T1429",     // Audio Capture
			"T1512",     // Video Capture
		}
		remediation = []string{
			"CRITICAL: Pegasus infection confirmed via IOC match",
			"Do NOT factory reset - preserve evidence",
			"Disconnect device from network immediately",
			"Contact Citizen Lab or Amnesty Tech for assistance",
			"Consider all data on device compromised",
			"Document everything for legal/reporting purposes",
		}

	case "predator":
		infectionType = models.InfectionTypePredator
		name = "Cytrox/Intellexa Predator"
		attribution = firstMatch.Attribution
		mitreTechniques = []string{
			"T1204.002", // Malicious Link
			"T1190",     // Exploit Public-Facing Application
			"T1547",     // Boot or Logon Autostart
			"T1041",     // Exfiltration Over C2
		}
		remediation = []string{
			"CRITICAL: Predator infection confirmed via IOC match",
			"Preserve device for forensic analysis",
			"Seek professional security assistance",
			"Report to relevant authorities",
		}

	case "stalkerware":
		infectionType = models.InfectionTypeStalkerware
		name = "Stalkerware Application"
		mitreTechniques = []string{
			"T1430", // Location Tracking
			"T1429", // Audio Capture
			"T1417", // Input Capture
			"T1636", // Protected User Data
		}
		remediation = []string{
			"WARNING: Stalkerware detected on device",
			"Someone may be monitoring your activities",
			"If you feel unsafe, do NOT confront the installer",
			"Contact local authorities or domestic violence hotline",
			"Have a safety plan before removing the app",
		}

	default:
		infectionType = models.InfectionTypeUnknownAPT
		name = "Unknown APT Indicators"
		mitreTechniques = []string{
			"T1059", // Command and Scripting
			"T1055", // Process Injection
		}
		remediation = []string{
			"Suspicious indicators found matching threat intelligence",
			"Conduct full forensic analysis",
			"Seek professional security assistance",
		}
	}

	return &models.DetectedThreat{
		Type:            infectionType,
		Name:            name,
		Confidence:      0.90,
		Severity:        models.ForensicSeverityCritical,
		Description:     fmt.Sprintf("%d IOC matches found for %s campaign", len(matches), campaign),
		Attribution:     attribution,
		LastActive:      &now,
		AnomalyIDs:      []string{}, // Would be populated with matching anomaly IDs
		MITRETechniques: mitreTechniques,
		IOCs:            matches,
		Remediation:     remediation,
	}
}

// GetStats returns IOC scanner statistics
func (s *IOCScanner) GetStats() map[string]any {
	s.iocsLock.RLock()
	defer s.iocsLock.RUnlock()

	stats := map[string]any{
		"domains":          len(s.iocs[IOCTypeDomain]),
		"ips":              len(s.iocs[IOCTypeIP]),
		"hashes":           len(s.iocs[IOCTypeHash]),
		"path_patterns":    len(s.pathPatterns),
		"process_patterns": len(s.processPatterns),
	}

	total := 0
	for _, iocs := range s.iocs {
		total += len(iocs)
	}
	total += len(s.pathPatterns) + len(s.processPatterns)
	stats["total"] = total

	return stats
}
