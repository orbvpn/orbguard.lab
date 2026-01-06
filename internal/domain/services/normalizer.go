package services

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// Normalizer normalizes and validates raw indicators
type Normalizer struct {
	logger *logger.Logger
}

// NewNormalizer creates a new Normalizer
func NewNormalizer(log *logger.Logger) *Normalizer {
	return &Normalizer{
		logger: log.WithComponent("normalizer"),
	}
}

// Normalize normalizes a raw indicator into a standard format
func (n *Normalizer) Normalize(raw models.RawIndicator) (*models.Indicator, error) {
	// Normalize the value based on type
	normalizedValue := n.normalizeValue(raw.Value, raw.Type)
	if normalizedValue == "" {
		return nil, ErrInvalidIndicator
	}

	// Generate hash for deduplication
	valueHash := n.generateHash(normalizedValue)

	// Determine severity
	severity := raw.Severity
	if severity == "" {
		severity = n.inferSeverity(raw)
	}

	// Determine confidence
	confidence := 0.5
	if raw.Confidence != nil {
		confidence = *raw.Confidence
	}

	// Determine timestamps
	now := time.Now()
	firstSeen := now
	if raw.FirstSeen != nil {
		firstSeen = *raw.FirstSeen
	}
	lastSeen := now
	if raw.LastSeen != nil {
		lastSeen = *raw.LastSeen
	}

	// Normalize tags
	tags := n.normalizeTags(raw.Tags)

	// Detect platforms from tags and type
	platforms := n.detectPlatforms(raw)

	indicator := &models.Indicator{
		ID:          uuid.New(),
		Value:       normalizedValue,
		ValueHash:   valueHash,
		Type:        raw.Type,
		Severity:    severity,
		Confidence:  confidence,
		Description: raw.Description,
		Tags:        tags,
		Platforms:   platforms,
		SourceID:    raw.SourceID,
		SourceName:  raw.SourceName,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		ReportCount: 0,
		SourceCount: 1,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	return indicator, nil
}

// NormalizeBatch normalizes multiple raw indicators
func (n *Normalizer) NormalizeBatch(raws []models.RawIndicator) ([]*models.Indicator, []error) {
	indicators := make([]*models.Indicator, 0, len(raws))
	errors := make([]error, 0)

	for _, raw := range raws {
		indicator, err := n.Normalize(raw)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		indicators = append(indicators, indicator)
	}

	return indicators, errors
}

// normalizeValue normalizes the indicator value based on its type
func (n *Normalizer) normalizeValue(value string, iocType models.IndicatorType) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	switch iocType {
	case models.IndicatorTypeDomain:
		return n.normalizeDomain(value)
	case models.IndicatorTypeIP, models.IndicatorTypeIPv6:
		return n.normalizeIP(value)
	case models.IndicatorTypeURL:
		return n.normalizeURL(value)
	case models.IndicatorTypeHash:
		return n.normalizeHash(value)
	case models.IndicatorTypeEmail:
		return n.normalizeEmail(value)
	default:
		return value
	}
}

// normalizeDomain normalizes a domain name
func (n *Normalizer) normalizeDomain(domain string) string {
	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove path if present
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Lowercase
	domain = strings.ToLower(domain)

	// Validate domain format
	if !isValidDomain(domain) {
		return ""
	}

	return domain
}

// normalizeIP normalizes an IP address
func (n *Normalizer) normalizeIP(ip string) string {
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		// Check if it's IPv6 with port
		if strings.Contains(ip[:idx], ":") {
			// IPv6 with port like [::1]:8080
			ip = strings.TrimPrefix(ip, "[")
			ip = strings.Split(ip, "]")[0]
		} else {
			// IPv4 with port
			ip = ip[:idx]
		}
	}

	// Parse and validate
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	return parsed.String()
}

// normalizeURL normalizes a URL
func (n *Normalizer) normalizeURL(rawURL string) string {
	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	// Parse URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Lowercase host
	parsed.Host = strings.ToLower(parsed.Host)

	return parsed.String()
}

// normalizeHash normalizes a file hash (MD5, SHA1, SHA256)
func (n *Normalizer) normalizeHash(hash string) string {
	// Remove any spaces or dashes
	hash = strings.ReplaceAll(hash, " ", "")
	hash = strings.ReplaceAll(hash, "-", "")

	// Lowercase
	hash = strings.ToLower(hash)

	// Validate hash length (MD5=32, SHA1=40, SHA256=64)
	if len(hash) != 32 && len(hash) != 40 && len(hash) != 64 {
		return ""
	}

	// Validate hex characters
	if !isHexString(hash) {
		return ""
	}

	return hash
}

// normalizeEmail normalizes an email address
func (n *Normalizer) normalizeEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))

	// Basic email validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return ""
	}

	return email
}

// generateHash generates a SHA256 hash of the value for deduplication
func (n *Normalizer) generateHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// normalizeTags normalizes and deduplicates tags
func (n *Normalizer) normalizeTags(tags []string) []string {
	seen := make(map[string]bool)
	normalized := make([]string, 0, len(tags))

	for _, tag := range tags {
		// Lowercase and trim
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}

		// Remove special characters
		tag = regexp.MustCompile(`[^a-z0-9-_]`).ReplaceAllString(tag, "")

		// Deduplicate
		if !seen[tag] {
			seen[tag] = true
			normalized = append(normalized, tag)
		}
	}

	return normalized
}

// detectPlatforms detects target platforms from tags and type
func (n *Normalizer) detectPlatforms(raw models.RawIndicator) []models.Platform {
	platforms := make([]models.Platform, 0)
	platformSet := make(map[models.Platform]bool)

	// Check tags for platform hints
	for _, tag := range raw.Tags {
		tag = strings.ToLower(tag)
		switch {
		case strings.Contains(tag, "android"):
			platformSet[models.PlatformAndroid] = true
		case strings.Contains(tag, "ios") || strings.Contains(tag, "iphone") || strings.Contains(tag, "ipad"):
			platformSet[models.PlatformIOS] = true
		case strings.Contains(tag, "windows"):
			platformSet[models.PlatformWindows] = true
		case strings.Contains(tag, "macos") || strings.Contains(tag, "osx"):
			platformSet[models.PlatformMacOS] = true
		case strings.Contains(tag, "linux"):
			platformSet[models.PlatformLinux] = true
		}
	}

	// Package names are typically Android
	if raw.Type == models.IndicatorTypePackage {
		platformSet[models.PlatformAndroid] = true
	}

	// Convert set to slice
	for p := range platformSet {
		platforms = append(platforms, p)
	}

	return platforms
}

// inferSeverity infers severity based on indicator characteristics
func (n *Normalizer) inferSeverity(raw models.RawIndicator) models.Severity {
	// Check for known high-severity keywords
	value := strings.ToLower(raw.Value + " " + raw.Description)
	tags := strings.ToLower(strings.Join(raw.Tags, " "))

	// Critical indicators
	if strings.Contains(tags, "pegasus") ||
		strings.Contains(tags, "nso-group") ||
		strings.Contains(tags, "predator") ||
		strings.Contains(tags, "apt") ||
		strings.Contains(value, "c2") ||
		strings.Contains(value, "command-and-control") {
		return models.SeverityCritical
	}

	// High severity
	if strings.Contains(tags, "spyware") ||
		strings.Contains(tags, "ransomware") ||
		strings.Contains(tags, "trojan") ||
		strings.Contains(tags, "botnet") {
		return models.SeverityHigh
	}

	// Medium severity
	if strings.Contains(tags, "phishing") ||
		strings.Contains(tags, "malware") {
		return models.SeverityMedium
	}

	// Default to medium
	return models.SeverityMedium
}

// isValidDomain checks if a domain is valid
func isValidDomain(domain string) bool {
	// Basic validation
	if len(domain) < 3 || len(domain) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// No double dots
	if strings.Contains(domain, "..") {
		return false
	}

	// Valid characters
	validDomain := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	return validDomain.MatchString(domain)
}

// isHexString checks if a string contains only hex characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Common errors
var (
	ErrInvalidIndicator = &NormalizerError{Message: "invalid indicator"}
)

// NormalizerError represents a normalization error
type NormalizerError struct {
	Message string
}

func (e *NormalizerError) Error() string {
	return e.Message
}
