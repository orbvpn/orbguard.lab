package services

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/detection/yara"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// YARAService provides YARA scanning capabilities
type YARAService struct {
	engine     *yara.Engine
	loader     *yara.Loader
	cache      *cache.RedisCache
	logger     *logger.Logger
	rulesDir   string

	// Statistics
	statsMu     sync.RWMutex
	totalScans  int64
	totalMatches int64
	scanTimes   []time.Duration
}

// NewYARAService creates a new YARA service
func NewYARAService(rulesDir string, c *cache.RedisCache, log *logger.Logger) *YARAService {
	svc := &YARAService{
		engine:   yara.NewEngine(),
		loader:   yara.NewLoader(log),
		cache:    c,
		logger:   log.WithComponent("yara-service"),
		rulesDir: rulesDir,
		scanTimes: make([]time.Duration, 0, 100),
	}

	// Load rules on initialization
	if err := svc.LoadRules(); err != nil {
		log.Warn().Err(err).Msg("failed to load YARA rules on startup")
	}

	return svc
}

// LoadRules loads all YARA rules from the rules directory and built-in rules
func (s *YARAService) LoadRules() error {
	s.logger.Info().Msg("loading YARA rules")

	// Load built-in rules first
	builtinRules, err := s.loader.LoadBuiltinRules()
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to load built-in rules")
	}

	for _, rule := range builtinRules {
		if err := s.engine.AddRule(rule); err != nil {
			s.logger.Warn().Err(err).Str("rule", rule.Name).Msg("failed to add built-in rule")
		}
	}

	// Load rules from directory if specified
	if s.rulesDir != "" {
		if _, err := os.Stat(s.rulesDir); err == nil {
			dirRules, err := s.loader.LoadDirectory(s.rulesDir)
			if err != nil {
				s.logger.Warn().Err(err).Str("dir", s.rulesDir).Msg("failed to load rules from directory")
			} else {
				for _, rule := range dirRules {
					if err := s.engine.AddRule(rule); err != nil {
						s.logger.Warn().Err(err).Str("rule", rule.Name).Msg("failed to add directory rule")
					}
				}
			}
		}
	}

	s.logger.Info().Int("total_rules", s.engine.RuleCount()).Msg("YARA rules loaded")
	return nil
}

// Scan performs a YARA scan on the provided data
func (s *YARAService) Scan(ctx context.Context, req *models.YARAScanRequest) (*models.YARAScanResult, error) {
	startTime := time.Now()

	// Get the data to scan
	data, err := s.extractData(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract data: %w", err)
	}

	// Get rules to use
	rules := s.getRulesToUse(req)

	// Perform the scan
	matches := s.engine.MatchWithRules(data, rules)

	// Build result
	result := &models.YARAScanResult{
		ID:          uuid.New(),
		ScanTime:    time.Since(startTime),
		Matches:     matches,
		RulesUsed:   len(rules),
		DataSize:    int64(len(data)),
		IsMalicious: len(matches) > 0,
		ScannedAt:   time.Now(),
		FileName:    req.FileName,
		FileType:    req.FileType,
		PackageName: req.PackageName,
	}

	// Calculate max severity and risk score
	if len(matches) > 0 {
		result.MaxSeverity = s.calculateMaxSeverity(matches)
		result.RiskScore = s.calculateRiskScore(matches)
	}

	// Update statistics
	s.updateStats(result)

	// Cache result if caching is available
	if s.cache != nil && req.FileName != "" {
		s.cacheResult(ctx, req.FileName, result)
	}

	return result, nil
}

// extractData extracts the data to scan from the request
func (s *YARAService) extractData(req *models.YARAScanRequest) ([]byte, error) {
	if len(req.Data) > 0 {
		return req.Data, nil
	}

	if req.Base64Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Base64Data)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 data: %w", err)
		}
		return decoded, nil
	}

	if req.HexData != "" {
		decoded, err := hex.DecodeString(req.HexData)
		if err != nil {
			return nil, fmt.Errorf("invalid hex data: %w", err)
		}
		return decoded, nil
	}

	if req.FilePath != "" {
		data, err := os.ReadFile(req.FilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("no data provided for scanning")
}

// getRulesToUse returns the rules to use for scanning based on the request
func (s *YARAService) getRulesToUse(req *models.YARAScanRequest) []*yara.CompiledRule {
	allRules := s.engine.GetRules()

	// If specific rule IDs are requested
	if len(req.RuleIDs) > 0 {
		ruleIDSet := make(map[string]bool)
		for _, id := range req.RuleIDs {
			ruleIDSet[id.String()] = true
		}

		var filtered []*yara.CompiledRule
		for _, rule := range allRules {
			if ruleIDSet[rule.Rule.ID.String()] {
				filtered = append(filtered, rule)
			}
		}
		return filtered
	}

	// Filter by categories
	if len(req.Categories) > 0 {
		categorySet := make(map[models.YARARuleCategory]bool)
		for _, cat := range req.Categories {
			categorySet[cat] = true
		}

		var filtered []*yara.CompiledRule
		for _, rule := range allRules {
			if categorySet[rule.Rule.Category] {
				filtered = append(filtered, rule)
			}
		}
		if len(filtered) > 0 {
			allRules = filtered
		}
	}

	// Filter by minimum severity
	if req.MinSeverity != nil {
		minWeight := severityWeight(*req.MinSeverity)
		var filtered []*yara.CompiledRule
		for _, rule := range allRules {
			if severityWeight(rule.Rule.Severity) >= minWeight {
				filtered = append(filtered, rule)
			}
		}
		if len(filtered) > 0 {
			allRules = filtered
		}
	}

	// Filter by platform
	if req.Platform != "" {
		var filtered []*yara.CompiledRule
		for _, rule := range allRules {
			if len(rule.Rule.Platforms) == 0 {
				// Rule applies to all platforms
				filtered = append(filtered, rule)
			} else {
				for _, p := range rule.Rule.Platforms {
					if p == req.Platform || p == "all" {
						filtered = append(filtered, rule)
						break
					}
				}
			}
		}
		if len(filtered) > 0 {
			allRules = filtered
		}
	}

	return allRules
}

// calculateMaxSeverity finds the highest severity among matches
func (s *YARAService) calculateMaxSeverity(matches []models.YARAMatch) models.Severity {
	maxSeverity := models.SeverityInfo
	maxWeight := 0

	for _, m := range matches {
		weight := severityWeight(m.Severity)
		if weight > maxWeight {
			maxWeight = weight
			maxSeverity = m.Severity
		}
	}

	return maxSeverity
}

// calculateRiskScore calculates an overall risk score
func (s *YARAService) calculateRiskScore(matches []models.YARAMatch) float64 {
	if len(matches) == 0 {
		return 0
	}

	totalScore := 0.0
	for _, m := range matches {
		switch m.Severity {
		case models.SeverityCritical:
			totalScore += 10.0
		case models.SeverityHigh:
			totalScore += 7.5
		case models.SeverityMedium:
			totalScore += 5.0
		case models.SeverityLow:
			totalScore += 2.5
		case models.SeverityInfo:
			totalScore += 1.0
		}
	}

	// Cap at 10
	if totalScore > 10.0 {
		totalScore = 10.0
	}

	return totalScore
}

// updateStats updates scanning statistics
func (s *YARAService) updateStats(result *models.YARAScanResult) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	s.totalScans++
	if result.IsMalicious {
		s.totalMatches++
	}

	// Keep last 100 scan times
	s.scanTimes = append(s.scanTimes, result.ScanTime)
	if len(s.scanTimes) > 100 {
		s.scanTimes = s.scanTimes[1:]
	}
}

// cacheResult caches a scan result
func (s *YARAService) cacheResult(ctx context.Context, key string, result *models.YARAScanResult) {
	cacheKey := fmt.Sprintf("yara:scan:%s", key)
	data, err := json.Marshal(result)
	if err == nil {
		s.cache.Set(ctx, cacheKey, string(data), 10*time.Minute)
	}
}

// GetCachedResult retrieves a cached scan result
func (s *YARAService) GetCachedResult(ctx context.Context, key string) (*models.YARAScanResult, bool) {
	if s.cache == nil {
		return nil, false
	}

	cacheKey := fmt.Sprintf("yara:scan:%s", key)
	data, err := s.cache.Get(ctx, cacheKey)
	if err != nil || data == "" {
		return nil, false
	}

	var result models.YARAScanResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, false
	}

	return &result, true
}

// AddRule adds a new rule to the engine
func (s *YARAService) AddRule(rule *models.YARARule) error {
	// Validate the rule
	if err := s.loader.ValidateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}

	// Add to engine
	if err := s.engine.AddRule(rule); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	s.logger.Info().Str("rule", rule.Name).Msg("added YARA rule")
	return nil
}

// RemoveRule removes a rule from the engine
func (s *YARAService) RemoveRule(ruleID uuid.UUID) error {
	s.engine.RemoveRule(ruleID.String())
	s.logger.Info().Str("rule_id", ruleID.String()).Msg("removed YARA rule")
	return nil
}

// GetRules returns all loaded rules
func (s *YARAService) GetRules(filter *models.YARARuleFilter) []*models.YARARule {
	compiledRules := s.engine.GetRules()
	rules := make([]*models.YARARule, 0, len(compiledRules))

	for _, compiled := range compiledRules {
		rule := compiled.Rule

		// Apply filters
		if filter != nil {
			// Filter by category
			if len(filter.Categories) > 0 {
				found := false
				for _, cat := range filter.Categories {
					if rule.Category == cat {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			// Filter by severity
			if len(filter.Severities) > 0 {
				found := false
				for _, sev := range filter.Severities {
					if rule.Severity == sev {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			// Filter by status
			if filter.Status != nil && rule.Status != *filter.Status {
				continue
			}

			// Filter by platform
			if len(filter.Platforms) > 0 {
				found := false
				for _, p := range filter.Platforms {
					for _, rp := range rule.Platforms {
						if p == rp {
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found && len(rule.Platforms) > 0 {
					continue
				}
			}
		}

		rules = append(rules, rule)
	}

	// Apply pagination
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(rules) {
			rules = rules[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(rules) {
			rules = rules[:filter.Limit]
		}
	}

	return rules
}

// GetRule returns a specific rule by ID
func (s *YARAService) GetRule(ruleID uuid.UUID) *models.YARARule {
	compiled := s.engine.GetRule(ruleID.String())
	if compiled == nil {
		return nil
	}
	return compiled.Rule
}

// GetStats returns scanning statistics
func (s *YARAService) GetStats() *models.YARAScanStats {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	stats := &models.YARAScanStats{
		TotalScans:        s.totalScans,
		TotalMatches:      s.totalMatches,
		MaliciousDetected: s.totalMatches,
		ByCategory:        make(map[string]int64),
		BySeverity:        make(map[string]int64),
	}

	// Calculate average scan time
	if len(s.scanTimes) > 0 {
		var total time.Duration
		for _, t := range s.scanTimes {
			total += t
		}
		stats.AverageScanTime = total / time.Duration(len(s.scanTimes))
	}

	// Count rules by category and severity
	for _, compiled := range s.engine.GetRules() {
		stats.ByCategory[string(compiled.Rule.Category)]++
		stats.BySeverity[string(compiled.Rule.Severity)]++
	}

	return stats
}

// ReloadRules reloads all rules
func (s *YARAService) ReloadRules() error {
	s.engine.Clear()
	return s.LoadRules()
}

// ScanFile scans a file by path
func (s *YARAService) ScanFile(ctx context.Context, filePath string) (*models.YARAScanResult, error) {
	return s.Scan(ctx, &models.YARAScanRequest{
		FilePath: filePath,
		FileName: filePath,
	})
}

// ScanBytes scans raw bytes
func (s *YARAService) ScanBytes(ctx context.Context, data []byte, fileName string) (*models.YARAScanResult, error) {
	return s.Scan(ctx, &models.YARAScanRequest{
		Data:     data,
		FileName: fileName,
	})
}

// ScanAPK scans an Android APK file
func (s *YARAService) ScanAPK(ctx context.Context, apkData []byte, packageName string) (*models.YARAScanResult, error) {
	return s.Scan(ctx, &models.YARAScanRequest{
		Data:        apkData,
		PackageName: packageName,
		Platform:    "android",
		FileType:    "apk",
		Categories:  []models.YARARuleCategory{models.YARACategoryPegasus, models.YARACategoryStalkerware, models.YARACategorySpyware},
	})
}

// ScanIPA scans an iOS IPA file
func (s *YARAService) ScanIPA(ctx context.Context, ipaData []byte, bundleID string) (*models.YARAScanResult, error) {
	return s.Scan(ctx, &models.YARAScanRequest{
		Data:        ipaData,
		PackageName: bundleID,
		Platform:    "ios",
		FileType:    "ipa",
		Categories:  []models.YARARuleCategory{models.YARACategoryPegasus, models.YARACategoryStalkerware, models.YARACategorySpyware},
	})
}

// Helper function for severity weight
func severityWeight(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	case models.SeverityInfo:
		return 1
	default:
		return 0
	}
}
