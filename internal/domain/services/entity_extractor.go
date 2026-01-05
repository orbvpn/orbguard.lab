package services

import (
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// EntityExtractor extracts IOCs and entities from text using NLP/regex patterns
type EntityExtractor struct {
	patterns        map[models.EntityType]*regexp.Regexp
	malwareKeywords map[string]float64
	actorKeywords   map[string]float64
	campaignKeywords map[string]float64
	logger          *logger.Logger
}

// NewEntityExtractor creates a new entity extractor
func NewEntityExtractor(log *logger.Logger) *EntityExtractor {
	ee := &EntityExtractor{
		patterns:         make(map[models.EntityType]*regexp.Regexp),
		malwareKeywords:  make(map[string]float64),
		actorKeywords:    make(map[string]float64),
		campaignKeywords: make(map[string]float64),
		logger:           log.WithComponent("entity-extractor"),
	}

	ee.compilePatterns()
	ee.loadKeywords()

	return ee
}

// compilePatterns compiles regex patterns for entity extraction
func (ee *EntityExtractor) compilePatterns() {
	// IPv4 address
	ee.patterns[models.EntityTypeIP] = regexp.MustCompile(
		`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
	)

	// Domain name
	ee.patterns[models.EntityTypeDomain] = regexp.MustCompile(
		`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b`,
	)

	// URL
	ee.patterns[models.EntityTypeURL] = regexp.MustCompile(
		`(?i)\b(?:https?://|hxxps?://|ftp://|www\.)[^\s<>"'\)]+`,
	)

	// Email address
	ee.patterns[models.EntityTypeEmail] = regexp.MustCompile(
		`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
	)

	// MD5 hash
	hashMD5 := regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	// SHA1 hash
	hashSHA1 := regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	// SHA256 hash
	hashSHA256 := regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	// Combined hash pattern
	ee.patterns[models.EntityTypeHash] = regexp.MustCompile(
		`\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b`,
	)
	// Store individual patterns for type detection
	_ = hashMD5
	_ = hashSHA1
	_ = hashSHA256

	// CVE identifier
	ee.patterns[models.EntityTypeCVE] = regexp.MustCompile(
		`\bCVE-\d{4}-\d{4,7}\b`,
	)

	// MITRE ATT&CK technique
	ee.patterns[models.EntityTypeMITRE] = regexp.MustCompile(
		`\bT\d{4}(?:\.\d{3})?\b`,
	)

	// Bitcoin address
	ee.patterns[models.EntityTypeBitcoin] = regexp.MustCompile(
		`\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b`,
	)

	// Windows registry key
	ee.patterns[models.EntityTypeRegistry] = regexp.MustCompile(
		`\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s]+`,
	)

	// File path (Windows and Unix)
	ee.patterns[models.EntityTypeFilePath] = regexp.MustCompile(
		`(?:[A-Za-z]:\\[^\s<>"|?*]+)|(?:/(?:usr|var|etc|tmp|home|root|opt|bin|sbin|lib)[^\s<>"|?*]*)`,
	)

	// Date patterns
	ee.patterns[models.EntityTypeDate] = regexp.MustCompile(
		`\b(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4})\b`,
	)
}

// loadKeywords loads known malware, actor, and campaign keywords
func (ee *EntityExtractor) loadKeywords() {
	// Known malware families (confidence scores)
	ee.malwareKeywords = map[string]float64{
		"pegasus":     1.0,
		"predator":    1.0,
		"nso":         0.9,
		"candiru":     1.0,
		"hermit":      1.0,
		"chrysaor":    1.0,
		"phantom":     0.8,
		"finspy":      1.0,
		"finfisher":   1.0,
		"cytrox":      1.0,
		"emotet":      1.0,
		"trickbot":    1.0,
		"ryuk":        1.0,
		"conti":       1.0,
		"lockbit":     1.0,
		"revil":       1.0,
		"sodinokibi":  1.0,
		"darkside":    1.0,
		"cobalt":      0.8,
		"mimikatz":    0.9,
		"metasploit":  0.8,
		"empire":      0.7,
		"covenant":    0.8,
		"sliver":      0.8,
		"qakbot":      1.0,
		"dridex":      1.0,
		"gootkit":     1.0,
		"icedid":      1.0,
		"bazarloader": 1.0,
		"stalkerware": 0.9,
		"spyware":     0.8,
		"trojan":      0.8,
		"ransomware":  0.9,
		"rootkit":     0.9,
		"keylogger":   0.9,
		"rat":         0.7,
		"backdoor":    0.8,
		"dropper":     0.8,
		"loader":      0.7,
		"stealer":     0.8,
		"infostealer": 0.9,
		"botnet":      0.8,
		"worm":        0.8,
		"adware":      0.7,
		"cryptominer": 0.8,
		"miner":       0.7,
	}

	// Known threat actors
	ee.actorKeywords = map[string]float64{
		"apt28":        1.0,
		"apt29":        1.0,
		"apt32":        1.0,
		"apt33":        1.0,
		"apt34":        1.0,
		"apt35":        1.0,
		"apt38":        1.0,
		"apt41":        1.0,
		"lazarus":      1.0,
		"kimsuky":      1.0,
		"sandworm":     1.0,
		"cozy bear":    1.0,
		"fancy bear":   1.0,
		"turla":        1.0,
		"gamaredon":    1.0,
		"hafnium":      1.0,
		"nobelium":     1.0,
		"darkhotel":    1.0,
		"charming kitten": 1.0,
		"scarab":       0.8,
		"winnti":       1.0,
		"tick":         0.8,
		"mustang panda": 1.0,
		"naikon":       1.0,
		"sidewinder":   1.0,
		"patchwork":    1.0,
		"oceanlotus":   1.0,
		"fin7":         1.0,
		"fin8":         1.0,
		"carbanak":     1.0,
		"wizard spider": 1.0,
		"evil corp":    1.0,
		"ta505":        1.0,
		"ta551":        1.0,
		"molerats":     1.0,
		"moonlight":    0.8,
		"darkhydrus":   1.0,
		"oilrig":       1.0,
		"helix kitten": 1.0,
		"muddy water":  1.0,
		"magic hound":  1.0,
		"equation group": 1.0,
	}

	// Known campaigns
	ee.campaignKeywords = map[string]float64{
		"solarwinds":     1.0,
		"sunburst":       1.0,
		"kaseya":         1.0,
		"log4j":          1.0,
		"log4shell":      1.0,
		"exchange":       0.6,
		"proxylogon":     1.0,
		"proxyshell":     1.0,
		"printnightmare": 1.0,
		"eternal blue":   1.0,
		"eternalblue":    1.0,
		"wannacry":       1.0,
		"notpetya":       1.0,
		"petya":          0.9,
		"colonial":       0.8,
		"operation":      0.4,
		"campaign":       0.3,
	}
}

// ExtractEntities extracts all entities from text
func (ee *EntityExtractor) ExtractEntities(text string) *models.EntityExtractionResult {
	startTime := time.Now()

	result := &models.EntityExtractionResult{
		SourceText:   text,
		Entities:     make([]models.ExtractedEntity, 0),
		EntityCounts: make(map[models.EntityType]int),
		Indicators:   make([]models.ExtractedIndicator, 0),
	}

	// Track extracted values to avoid duplicates
	seen := make(map[string]bool)

	// Extract pattern-based entities
	for entityType, pattern := range ee.patterns {
		matches := pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			value := text[match[0]:match[1]]

			// Skip if already seen
			key := string(entityType) + ":" + strings.ToLower(value)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Validate and normalize
			normalized, confidence := ee.validateEntity(value, entityType)
			if confidence > 0 {
				entity := models.ExtractedEntity{
					Text:       value,
					Type:       entityType,
					StartPos:   match[0],
					EndPos:     match[1],
					Confidence: confidence,
					Normalized: normalized,
				}

				result.Entities = append(result.Entities, entity)
				result.EntityCounts[entityType]++

				// Convert to indicator if applicable
				indicator := ee.entityToIndicator(entity)
				if indicator != nil {
					result.Indicators = append(result.Indicators, *indicator)
				}
			}
		}
	}

	// Extract keyword-based entities
	ee.extractKeywordEntities(text, result, seen)

	// Extract contextual entities
	ee.extractContextualEntities(text, result, seen)

	result.ProcessingTime = time.Since(startTime)

	return result
}

// ExtractIndicators extracts only IOCs from text
func (ee *EntityExtractor) ExtractIndicators(text string) []models.ExtractedIndicator {
	result := ee.ExtractEntities(text)
	return result.Indicators
}

// validateEntity validates and normalizes an entity
func (ee *EntityExtractor) validateEntity(value string, entityType models.EntityType) (string, float64) {
	switch entityType {
	case models.EntityTypeIP:
		return ee.validateIP(value)
	case models.EntityTypeDomain:
		return ee.validateDomain(value)
	case models.EntityTypeURL:
		return ee.validateURL(value)
	case models.EntityTypeEmail:
		return ee.validateEmail(value)
	case models.EntityTypeHash:
		return ee.validateHash(value)
	case models.EntityTypeCVE:
		return strings.ToUpper(value), 1.0
	case models.EntityTypeMITRE:
		return strings.ToUpper(value), 1.0
	case models.EntityTypeBitcoin:
		return value, 0.9
	case models.EntityTypeRegistry:
		return value, 0.8
	case models.EntityTypeFilePath:
		return value, 0.7
	default:
		return value, 0.5
	}
}

// validateIP validates an IP address
func (ee *EntityExtractor) validateIP(value string) (string, float64) {
	ip := net.ParseIP(value)
	if ip == nil {
		return "", 0
	}

	// Lower confidence for private IPs
	if ip.IsPrivate() || ip.IsLoopback() {
		return value, 0.3
	}

	return value, 0.95
}

// validateDomain validates a domain name
func (ee *EntityExtractor) validateDomain(value string) (string, float64) {
	value = strings.ToLower(value)

	// Skip common false positives
	skipPatterns := []string{
		"example.com", "test.com", "localhost",
		".exe", ".dll", ".txt", ".pdf", ".doc",
	}
	for _, skip := range skipPatterns {
		if strings.Contains(value, skip) {
			return "", 0
		}
	}

	// Skip if it looks like a version number
	if regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(value) {
		return "", 0
	}

	// Validate TLD
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", 0
	}

	// Check for valid TLD (at least 2 chars)
	tld := parts[len(parts)-1]
	if len(tld) < 2 || len(tld) > 10 {
		return "", 0
	}

	return value, 0.85
}

// validateURL validates a URL
func (ee *EntityExtractor) validateURL(value string) (string, float64) {
	// Defang common obfuscation
	value = strings.ReplaceAll(value, "hxxp", "http")
	value = strings.ReplaceAll(value, "[.]", ".")
	value = strings.ReplaceAll(value, "[:]", ":")

	parsed, err := url.Parse(value)
	if err != nil {
		return "", 0
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "ftp" {
		return "", 0
	}

	if parsed.Host == "" {
		return "", 0
	}

	return value, 0.9
}

// validateEmail validates an email address
func (ee *EntityExtractor) validateEmail(value string) (string, float64) {
	_, err := mail.ParseAddress(value)
	if err != nil {
		return "", 0
	}

	return strings.ToLower(value), 0.85
}

// validateHash validates a hash
func (ee *EntityExtractor) validateHash(value string) (string, float64) {
	value = strings.ToLower(value)
	length := len(value)

	// Check valid hex characters
	for _, c := range value {
		if !unicode.IsDigit(c) && (c < 'a' || c > 'f') {
			return "", 0
		}
	}

	switch length {
	case 32: // MD5
		return value, 0.9
	case 40: // SHA1
		return value, 0.92
	case 64: // SHA256
		return value, 0.95
	default:
		return "", 0
	}
}

// extractKeywordEntities extracts entities based on keywords
func (ee *EntityExtractor) extractKeywordEntities(text string, result *models.EntityExtractionResult, seen map[string]bool) {
	lowerText := strings.ToLower(text)

	// Extract malware mentions
	for keyword, confidence := range ee.malwareKeywords {
		if idx := strings.Index(lowerText, keyword); idx != -1 {
			key := "malware:" + keyword
			if !seen[key] {
				seen[key] = true
				result.Entities = append(result.Entities, models.ExtractedEntity{
					Text:       keyword,
					Type:       models.EntityTypeMalware,
					StartPos:   idx,
					EndPos:     idx + len(keyword),
					Confidence: confidence,
					Normalized: keyword,
				})
				result.EntityCounts[models.EntityTypeMalware]++
			}
		}
	}

	// Extract threat actor mentions
	for keyword, confidence := range ee.actorKeywords {
		if idx := strings.Index(lowerText, keyword); idx != -1 {
			key := "actor:" + keyword
			if !seen[key] {
				seen[key] = true
				result.Entities = append(result.Entities, models.ExtractedEntity{
					Text:       keyword,
					Type:       models.EntityTypeThreatActor,
					StartPos:   idx,
					EndPos:     idx + len(keyword),
					Confidence: confidence,
					Normalized: keyword,
				})
				result.EntityCounts[models.EntityTypeThreatActor]++
			}
		}
	}

	// Extract campaign mentions
	for keyword, confidence := range ee.campaignKeywords {
		if idx := strings.Index(lowerText, keyword); idx != -1 {
			key := "campaign:" + keyword
			if !seen[key] {
				seen[key] = true
				result.Entities = append(result.Entities, models.ExtractedEntity{
					Text:       keyword,
					Type:       models.EntityTypeCampaign,
					StartPos:   idx,
					EndPos:     idx + len(keyword),
					Confidence: confidence,
					Normalized: keyword,
				})
				result.EntityCounts[models.EntityTypeCampaign]++
			}
		}
	}
}

// extractContextualEntities extracts entities based on context patterns
func (ee *EntityExtractor) extractContextualEntities(text string, result *models.EntityExtractionResult, seen map[string]bool) {
	// Pattern: "attributed to X" or "associated with X"
	attributionPattern := regexp.MustCompile(`(?i)(?:attributed to|associated with|linked to|operated by)\s+([A-Z][A-Za-z0-9\s]+?)(?:\.|,|;|\s+(?:and|or|who))`)
	matches := attributionPattern.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) > 1 {
			actor := strings.TrimSpace(match[1])
			key := "actor:" + strings.ToLower(actor)
			if !seen[key] && len(actor) > 2 && len(actor) < 50 {
				seen[key] = true
				idx := strings.Index(text, actor)
				result.Entities = append(result.Entities, models.ExtractedEntity{
					Text:       actor,
					Type:       models.EntityTypeThreatActor,
					StartPos:   idx,
					EndPos:     idx + len(actor),
					Confidence: 0.6,
					Normalized: strings.ToLower(actor),
				})
				result.EntityCounts[models.EntityTypeThreatActor]++
			}
		}
	}

	// Pattern: "targeting X" for organizations
	targetPattern := regexp.MustCompile(`(?i)targeting\s+(?:the\s+)?([A-Z][A-Za-z\s]+?)(?:\s+sector|\s+industry|'s|\.|,)`)
	matches = targetPattern.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) > 1 {
			org := strings.TrimSpace(match[1])
			key := "org:" + strings.ToLower(org)
			if !seen[key] && len(org) > 2 && len(org) < 50 {
				seen[key] = true
				idx := strings.Index(text, org)
				result.Entities = append(result.Entities, models.ExtractedEntity{
					Text:       org,
					Type:       models.EntityTypeOrganization,
					StartPos:   idx,
					EndPos:     idx + len(org),
					Confidence: 0.5,
					Normalized: org,
				})
				result.EntityCounts[models.EntityTypeOrganization]++
			}
		}
	}
}

// entityToIndicator converts an entity to an indicator if applicable
func (ee *EntityExtractor) entityToIndicator(entity models.ExtractedEntity) *models.ExtractedIndicator {
	var indicatorType models.IndicatorType

	switch entity.Type {
	case models.EntityTypeIP:
		indicatorType = models.IndicatorTypeIP
	case models.EntityTypeDomain:
		indicatorType = models.IndicatorTypeDomain
	case models.EntityTypeURL:
		indicatorType = models.IndicatorTypeURL
	case models.EntityTypeEmail:
		indicatorType = models.IndicatorTypeEmail
	case models.EntityTypeHash:
		indicatorType = models.IndicatorTypeHash
	case models.EntityTypeFilePath:
		indicatorType = models.IndicatorTypeFilePath
	case models.EntityTypeRegistry:
		indicatorType = models.IndicatorTypeRegistry
	default:
		return nil
	}

	// Extract context (surrounding text)
	context := ""
	if len(entity.Text) < 50 {
		context = entity.Text
	}

	return &models.ExtractedIndicator{
		Value:      entity.Normalized,
		Type:       indicatorType,
		Confidence: entity.Confidence,
		Context:    context,
	}
}

// GetSupportedEntities returns list of supported entity types
func (ee *EntityExtractor) GetSupportedEntities() []models.EntityType {
	return []models.EntityType{
		models.EntityTypeIP,
		models.EntityTypeDomain,
		models.EntityTypeURL,
		models.EntityTypeEmail,
		models.EntityTypeHash,
		models.EntityTypeCVE,
		models.EntityTypeMITRE,
		models.EntityTypeBitcoin,
		models.EntityTypeRegistry,
		models.EntityTypeFilePath,
		models.EntityTypeMalware,
		models.EntityTypeThreatActor,
		models.EntityTypeCampaign,
		models.EntityTypeOrganization,
		models.EntityTypeDate,
	}
}
