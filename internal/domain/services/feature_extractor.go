package services

import (
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// FeatureExtractor extracts numerical features from indicators for ML processing
type FeatureExtractor struct {
	logger *logger.Logger
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor(log *logger.Logger) *FeatureExtractor {
	return &FeatureExtractor{
		logger: log.WithComponent("feature-extractor"),
	}
}

// ExtractFeatures extracts all features from an indicator
func (fe *FeatureExtractor) ExtractFeatures(indicator *models.Indicator) *models.IndicatorFeatures {
	features := &models.IndicatorFeatures{}

	// Extract structural features (common to all types)
	fe.extractStructuralFeatures(indicator.Value, features)

	// Extract type-specific features
	switch indicator.Type {
	case models.IndicatorTypeDomain:
		fe.extractDomainFeatures(indicator.Value, features)
	case models.IndicatorTypeURL:
		fe.extractURLFeatures(indicator.Value, features)
	case models.IndicatorTypeIP, models.IndicatorTypeIPv6:
		fe.extractIPFeatures(indicator.Value, features)
	case models.IndicatorTypeHash:
		fe.extractHashFeatures(indicator.Value, indicator.Type, features)
	}

	// Extract behavioral/reputation features
	fe.extractBehavioralFeatures(indicator, features)

	return features
}

// ExtractBatchFeatures extracts features from multiple indicators
func (fe *FeatureExtractor) ExtractBatchFeatures(indicators []*models.Indicator) []*models.FeatureVector {
	vectors := make([]*models.FeatureVector, 0, len(indicators))

	for _, ind := range indicators {
		features := fe.ExtractFeatures(ind)
		vector := fe.FeaturesToVector(ind.ID, ind.Type, features)
		vectors = append(vectors, vector)
	}

	return vectors
}

// FeaturesToVector converts features to a normalized vector
func (fe *FeatureExtractor) FeaturesToVector(id interface{}, indType models.IndicatorType, features *models.IndicatorFeatures) *models.FeatureVector {
	featureMap := map[string]float64{
		"length":            float64(features.Length),
		"entropy":           features.Entropy,
		"numeric_ratio":     features.NumericRatio,
		"special_char_ratio": features.SpecialCharRatio,
		"uppercase_ratio":   features.UppercaseRatio,
		"subdomain_count":   float64(features.SubdomainCount),
		"path_depth":        float64(features.PathDepth),
		"query_param_count": float64(features.QueryParamCount),
		"has_ip":            boolToFloat(features.HasIP),
		"has_port":          boolToFloat(features.HasPort),
		"tld_risk":          features.TLDRisk,
		"domain_age":        float64(features.DomainAge),
		"is_private":        boolToFloat(features.IsPrivate),
		"is_reserved":       boolToFloat(features.IsReserved),
		"asn_risk":          features.ASNRisk,
		"geo_risk":          features.GeoRisk,
		"first_seen_days":   float64(features.FirstSeenDaysAgo),
		"last_seen_days":    float64(features.LastSeenDaysAgo),
		"source_count":      float64(features.SourceCount),
		"campaign_count":    float64(features.CampaignCount),
		"related_count":     float64(features.RelatedCount),
		"severity":          features.CurrentSeverity,
		"confidence":        features.CurrentConfidence,
		"report_count":      float64(features.ReportCount),
	}

	// Create normalized vector
	normalized := fe.normalizeFeatures(featureMap)

	vector := &models.FeatureVector{
		IndicatorType: indType,
		Features:      featureMap,
		Normalized:    normalized,
		CreatedAt:     time.Now(),
	}

	// Handle ID type
	switch v := id.(type) {
	case [16]byte:
		copy(vector.IndicatorID[:], v[:])
	}

	return vector
}

// extractStructuralFeatures extracts features based on string structure
func (fe *FeatureExtractor) extractStructuralFeatures(value string, features *models.IndicatorFeatures) {
	features.Length = len(value)
	features.Entropy = fe.calculateEntropy(value)
	features.NumericRatio = fe.calculateCharRatio(value, unicode.IsDigit)
	features.SpecialCharRatio = fe.calculateSpecialCharRatio(value)
	features.UppercaseRatio = fe.calculateCharRatio(value, unicode.IsUpper)
}

// extractDomainFeatures extracts domain-specific features
func (fe *FeatureExtractor) extractDomainFeatures(domain string, features *models.IndicatorFeatures) {
	// Count subdomains
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		features.SubdomainCount = len(parts) - 2
	}

	// Check TLD risk
	if len(parts) > 0 {
		tld := strings.ToLower(parts[len(parts)-1])
		features.TLDRisk = models.RiskyTLDs[tld]
	}

	// Check if domain contains IP
	features.HasIP = fe.containsIP(domain)

	// Check for suspicious patterns
	features.SpecialCharRatio = fe.calculateDomainSpecialCharRatio(domain)
}

// extractURLFeatures extracts URL-specific features
func (fe *FeatureExtractor) extractURLFeatures(rawURL string, features *models.IndicatorFeatures) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	// Extract domain features from host
	if parsed.Host != "" {
		host := parsed.Host
		// Remove port if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			features.HasPort = true
			host = host[:idx]
		}
		fe.extractDomainFeatures(host, features)
	}

	// Path depth
	if parsed.Path != "" {
		features.PathDepth = strings.Count(parsed.Path, "/")
	}

	// Query parameters
	features.QueryParamCount = len(parsed.Query())

	// Check for IP in URL
	features.HasIP = fe.containsIP(rawURL)
}

// extractIPFeatures extracts IP-specific features
func (fe *FeatureExtractor) extractIPFeatures(ipStr string, features *models.IndicatorFeatures) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	// Check if private
	features.IsPrivate = ip.IsPrivate()
	features.IsReserved = ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast()

	// Note: ASN and Geo lookups would require external services
	// These are placeholders for when that data is available
	features.ASNRisk = 0.0
	features.GeoRisk = 0.0
}

// extractHashFeatures extracts hash-specific features
func (fe *FeatureExtractor) extractHashFeatures(hash string, hashType models.IndicatorType, features *models.IndicatorFeatures) {
	features.HashType = string(hashType)

	// Hash entropy should be very high (close to 4.0 for hex)
	// Low entropy might indicate a weak/fake hash
	features.Entropy = fe.calculateEntropy(hash)
}

// extractBehavioralFeatures extracts behavioral/reputation features
func (fe *FeatureExtractor) extractBehavioralFeatures(indicator *models.Indicator, features *models.IndicatorFeatures) {
	now := time.Now()

	// Time-based features
	if !indicator.FirstSeen.IsZero() {
		features.FirstSeenDaysAgo = int(now.Sub(indicator.FirstSeen).Hours() / 24)
	}
	if !indicator.LastSeen.IsZero() {
		features.LastSeenDaysAgo = int(now.Sub(indicator.LastSeen).Hours() / 24)
	}

	// Reputation features
	features.CurrentSeverity = severityToFloat(indicator.Severity)
	features.CurrentConfidence = indicator.Confidence

	// Source diversity
	features.SourceCount = indicator.SourceCount

	// Campaign associations (1 if associated with a campaign, 0 otherwise)
	if indicator.CampaignID != nil {
		features.CampaignCount = 1
	}

	// Related indicators count (based on MITRE techniques)
	features.RelatedCount = len(indicator.MitreTechniques)

	// Report count
	features.ReportCount = indicator.ReportCount
}

// severityToFloat converts severity string to numeric value
func severityToFloat(severity models.Severity) float64 {
	switch severity {
	case models.SeverityCritical:
		return 5.0
	case models.SeverityHigh:
		return 4.0
	case models.SeverityMedium:
		return 3.0
	case models.SeverityLow:
		return 2.0
	case models.SeverityInfo:
		return 1.0
	default:
		return 0.0
	}
}

// calculateEntropy calculates Shannon entropy of a string
func (fe *FeatureExtractor) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// calculateCharRatio calculates the ratio of characters matching a predicate
func (fe *FeatureExtractor) calculateCharRatio(s string, pred func(rune) bool) float64 {
	if len(s) == 0 {
		return 0.0
	}

	count := 0
	total := 0
	for _, c := range s {
		total++
		if pred(c) {
			count++
		}
	}

	return float64(count) / float64(total)
}

// calculateSpecialCharRatio calculates ratio of special characters
func (fe *FeatureExtractor) calculateSpecialCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	count := 0
	for _, c := range s {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			count++
		}
	}

	return float64(count) / float64(len(s))
}

// calculateDomainSpecialCharRatio calculates special char ratio excluding dots
func (fe *FeatureExtractor) calculateDomainSpecialCharRatio(domain string) float64 {
	if len(domain) == 0 {
		return 0.0
	}

	count := 0
	for _, c := range domain {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '.' {
			count++
		}
	}

	return float64(count) / float64(len(domain))
}

// containsIP checks if a string contains an IP address
func (fe *FeatureExtractor) containsIP(s string) bool {
	ipv4Pattern := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	return ipv4Pattern.MatchString(s)
}

// normalizeFeatures normalizes features to 0-1 range
func (fe *FeatureExtractor) normalizeFeatures(features map[string]float64) []float64 {
	// Define normalization parameters for each feature
	normalizers := map[string]struct{ min, max float64 }{
		"length":            {0, 2000},
		"entropy":           {0, 5},
		"numeric_ratio":     {0, 1},
		"special_char_ratio": {0, 1},
		"uppercase_ratio":   {0, 1},
		"subdomain_count":   {0, 10},
		"path_depth":        {0, 20},
		"query_param_count": {0, 50},
		"has_ip":            {0, 1},
		"has_port":          {0, 1},
		"tld_risk":          {0, 1},
		"domain_age":        {0, 3650}, // 10 years
		"is_private":        {0, 1},
		"is_reserved":       {0, 1},
		"asn_risk":          {0, 1},
		"geo_risk":          {0, 1},
		"first_seen_days":   {0, 365},
		"last_seen_days":    {0, 365},
		"source_count":      {0, 20},
		"campaign_count":    {0, 10},
		"related_count":     {0, 100},
		"severity":          {0, 5},
		"confidence":        {0, 1},
		"report_count":      {0, 1000},
	}

	// Order of features in vector
	featureOrder := []string{
		"length", "entropy", "numeric_ratio", "special_char_ratio", "uppercase_ratio",
		"subdomain_count", "path_depth", "query_param_count", "has_ip", "has_port",
		"tld_risk", "domain_age", "is_private", "is_reserved", "asn_risk", "geo_risk",
		"first_seen_days", "last_seen_days", "source_count", "campaign_count",
		"related_count", "severity", "confidence", "report_count",
	}

	normalized := make([]float64, len(featureOrder))
	for i, name := range featureOrder {
		value := features[name]
		params := normalizers[name]

		// Min-max normalization
		if params.max > params.min {
			normalized[i] = (value - params.min) / (params.max - params.min)
			// Clamp to [0, 1]
			if normalized[i] < 0 {
				normalized[i] = 0
			} else if normalized[i] > 1 {
				normalized[i] = 1
			}
		}
	}

	return normalized
}

// boolToFloat converts boolean to float64
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// GetFeatureNames returns the ordered list of feature names
func (fe *FeatureExtractor) GetFeatureNames() []string {
	return []string{
		"length", "entropy", "numeric_ratio", "special_char_ratio", "uppercase_ratio",
		"subdomain_count", "path_depth", "query_param_count", "has_ip", "has_port",
		"tld_risk", "domain_age", "is_private", "is_reserved", "asn_risk", "geo_risk",
		"first_seen_days", "last_seen_days", "source_count", "campaign_count",
		"related_count", "severity", "confidence", "report_count",
	}
}
