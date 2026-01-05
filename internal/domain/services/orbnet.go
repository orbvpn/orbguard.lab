package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// OrbNetService handles OrbNet VPN integration
type OrbNetService struct {
	repos  *repository.Repositories
	cache  *cache.RedisCache
	logger *logger.Logger
	config models.OrbNetConfig

	// In-memory stores
	servers     map[uuid.UUID]*models.OrbNetServer
	clients     map[uuid.UUID]*models.OrbNetClient
	blockRules  map[uuid.UUID]*models.DNSBlockRule
	filterConfigs map[uuid.UUID]*models.DNSFilterConfig

	// Domain lookup cache
	domainCache map[string]*models.DNSBlockResponse

	mu sync.RWMutex

	// Push channel for real-time updates
	pushChan chan *models.ThreatPushEvent

	// Stats
	queriesTotal   int64
	queriesBlocked int64
	statsMu        sync.RWMutex
}

// NewOrbNetService creates a new OrbNet integration service
func NewOrbNetService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *OrbNetService {
	svc := &OrbNetService{
		repos:         repos,
		cache:         cache,
		logger:        log.WithComponent("orbnet"),
		config:        models.DefaultOrbNetConfig,
		servers:       make(map[uuid.UUID]*models.OrbNetServer),
		clients:       make(map[uuid.UUID]*models.OrbNetClient),
		blockRules:    make(map[uuid.UUID]*models.DNSBlockRule),
		filterConfigs: make(map[uuid.UUID]*models.DNSFilterConfig),
		domainCache:   make(map[string]*models.DNSBlockResponse),
		pushChan:      make(chan *models.ThreatPushEvent, 1000),
	}

	// Load threat intelligence into block rules
	svc.loadThreatIntelRules()

	return svc
}

// loadThreatIntelRules loads indicators from database into block rules
func (s *OrbNetService) loadThreatIntelRules() {
	ctx := context.Background()

	if s.repos == nil || s.repos.Indicators == nil {
		s.logger.Warn().Msg("no repository available, using default rules only")
		s.loadDefaultRules()
		return
	}

	// Load domain indicators
	filter := repository.IndicatorFilter{
		Types: []models.IndicatorType{models.IndicatorTypeDomain},
		Limit: 50000,
	}

	indicators, _, err := s.repos.Indicators.List(ctx, filter)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to load domain indicators")
		s.loadDefaultRules()
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ind := range indicators {
		rule := s.indicatorToBlockRule(ind)
		s.blockRules[rule.ID] = rule
	}

	// Also load URL indicators and extract domains
	filter.Types = []models.IndicatorType{models.IndicatorTypeURL}
	urlIndicators, _, err := s.repos.Indicators.List(ctx, filter)
	if err == nil {
		for _, ind := range urlIndicators {
			domain := extractDomainFromURL(ind.Value)
			if domain != "" {
				rule := &models.DNSBlockRule{
					ID:          uuid.New(),
					Domain:      domain,
					RuleType:    models.DNSRuleTypeExact,
					Category:    s.mapSeverityToCategory(ind.Severity),
					Severity:    ind.Severity,
					Source:      "threat_intel",
					Description: ind.Description,
					Tags:        ind.Tags,
					Enabled:     true,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				s.blockRules[rule.ID] = rule
			}
		}
	}

	s.loadDefaultRules()

	s.logger.Info().
		Int("total_rules", len(s.blockRules)).
		Int("from_indicators", len(indicators)+len(urlIndicators)).
		Msg("loaded threat intelligence into DNS block rules")
}

// loadDefaultRules loads built-in blocking rules
func (s *OrbNetService) loadDefaultRules() {
	defaultDomains := map[string]string{
		// Known malware domains
		"malware.com":           models.DNSCategoryMalware,
		"virus-download.net":    models.DNSCategoryMalware,
		"trojan-source.org":     models.DNSCategoryMalware,

		// Known phishing domains
		"secure-login-verify.com":  models.DNSCategoryPhishing,
		"account-verify-now.net":   models.DNSCategoryPhishing,
		"update-your-info.com":     models.DNSCategoryPhishing,

		// Known tracking domains
		"tracking.example.com":     models.DNSCategoryTracking,
		"analytics-collector.net":  models.DNSCategoryTracking,
		"pixel-tracker.com":        models.DNSCategoryTracking,

		// Ad networks (examples)
		"ads.example.com":          models.DNSCategoryAds,
		"doubleclick.net":          models.DNSCategoryAds,
		"adservice.google.com":     models.DNSCategoryAds,
	}

	for domain, category := range defaultDomains {
		rule := &models.DNSBlockRule{
			ID:          uuid.New(),
			Domain:      domain,
			RuleType:    models.DNSRuleTypeExact,
			Category:    category,
			Severity:    s.categoryToSeverity(category),
			Source:      "default",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		s.blockRules[rule.ID] = rule
	}
}

// ShouldBlockDomain checks if a domain should be blocked
func (s *OrbNetService) ShouldBlockDomain(ctx context.Context, domain string) *models.DNSBlockResponse {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check cache first
	cacheKey := fmt.Sprintf("dns:block:%s", domain)
	if s.cache != nil {
		if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
			if cached == "allow" {
				return &models.DNSBlockResponse{Domain: domain, Blocked: false}
			}
		}
	}

	// Check in-memory domain cache
	s.mu.RLock()
	if resp, ok := s.domainCache[domain]; ok {
		s.mu.RUnlock()
		return resp
	}
	s.mu.RUnlock()

	// Check against rules
	response := s.checkDomainAgainstRules(domain)

	// Update stats
	s.statsMu.Lock()
	s.queriesTotal++
	if response.Blocked {
		s.queriesBlocked++
	}
	s.statsMu.Unlock()

	// Cache the result
	s.mu.Lock()
	s.domainCache[domain] = response
	s.mu.Unlock()

	if s.cache != nil {
		ttl := 5 * time.Minute
		if response.Blocked {
			s.cache.Set(ctx, cacheKey, "block", ttl)
		} else {
			s.cache.Set(ctx, cacheKey, "allow", ttl)
		}
	}

	return response
}

// checkDomainAgainstRules checks domain against all blocking rules
func (s *OrbNetService) checkDomainAgainstRules(domain string) *models.DNSBlockResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.blockRules {
		if !rule.Enabled {
			continue
		}

		matched := false
		switch rule.RuleType {
		case models.DNSRuleTypeExact:
			matched = domain == rule.Domain
		case models.DNSRuleTypeWildcard:
			matched = matchWildcard(domain, rule.Domain)
		case models.DNSRuleTypeRegex:
			if re, err := regexp.Compile(rule.Domain); err == nil {
				matched = re.MatchString(domain)
			}
		}

		if matched {
			// Update hit count
			rule.HitCount++
			now := time.Now()
			rule.LastHitAt = &now

			return &models.DNSBlockResponse{
				Domain:   domain,
				Blocked:  true,
				Reason:   fmt.Sprintf("Matched %s rule: %s", rule.Category, rule.Domain),
				Category: rule.Category,
				Severity: rule.Severity,
				RuleID:   &rule.ID,
				Threat: &models.ThreatInfo{
					Type:        rule.Category,
					Description: rule.Description,
					Confidence:  0.9,
				},
			}
		}
	}

	// Check database for real-time lookup if not in rules
	if s.repos != nil && s.repos.Indicators != nil {
		ctx := context.Background()
		ind, err := s.repos.Indicators.GetByValue(ctx, domain, models.IndicatorTypeDomain)
		if err == nil && ind != nil {
			return &models.DNSBlockResponse{
				Domain:   domain,
				Blocked:  true,
				Reason:   "Domain found in threat intelligence",
				Category: s.mapSeverityToCategory(ind.Severity),
				Severity: ind.Severity,
				Threat: &models.ThreatInfo{
					Type:        string(ind.Type),
					Description: ind.Description,
					Confidence:  ind.Confidence,
					FirstSeen:   &ind.FirstSeen,
					LastSeen:    &ind.LastSeen,
				},
			}
		}
	}

	return &models.DNSBlockResponse{
		Domain:  domain,
		Blocked: false,
	}
}

// matchWildcard matches a domain against a wildcard pattern
func matchWildcard(domain, pattern string) bool {
	// Convert wildcard to regex
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = "^" + pattern + "$"

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(domain)
}

// RegisterServer registers a VPN server
func (s *OrbNetService) RegisterServer(server *models.OrbNetServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if server.ID == uuid.Nil {
		server.ID = uuid.New()
	}
	server.RegisteredAt = time.Now()
	server.Status = "online"

	s.servers[server.ID] = server

	s.logger.Info().
		Str("id", server.ID.String()).
		Str("hostname", server.Hostname).
		Str("location", server.Location).
		Msg("VPN server registered")

	return nil
}

// GetServer retrieves a server by ID
func (s *OrbNetService) GetServer(id uuid.UUID) (*models.OrbNetServer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	server, ok := s.servers[id]
	if !ok {
		return nil, fmt.Errorf("server not found: %s", id)
	}
	return server, nil
}

// ListServers lists all registered servers
func (s *OrbNetService) ListServers() []*models.OrbNetServer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.OrbNetServer, 0, len(s.servers))
	for _, server := range s.servers {
		result = append(result, server)
	}
	return result
}

// UpdateServerStatus updates server status
func (s *OrbNetService) UpdateServerStatus(id uuid.UUID, status string, load float64, connections int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[id]
	if !ok {
		return fmt.Errorf("server not found: %s", id)
	}

	server.Status = status
	server.Load = load
	server.Connections = connections
	now := time.Now()
	server.LastSeenAt = &now

	return nil
}

// SyncThreatData syncs threat data to a server
func (s *OrbNetService) SyncThreatData(ctx context.Context, req *models.ThreatSyncRequest) (*models.ThreatSyncResponse, error) {
	s.mu.RLock()
	server, ok := s.servers[req.ServerID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("server not found: %s", req.ServerID)
	}

	// Collect rules
	rules := make([]models.DNSBlockRule, 0)
	categories := make(map[string]int)

	s.mu.RLock()
	for _, rule := range s.blockRules {
		if !rule.Enabled {
			continue
		}

		// Filter by categories if specified
		if len(req.Categories) > 0 {
			found := false
			for _, cat := range req.Categories {
				if rule.Category == cat {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check if rule was created/updated after last sync
		isDelta := req.LastSyncAt != nil && rule.UpdatedAt.After(*req.LastSyncAt)
		if req.LastSyncAt != nil && !isDelta {
			continue
		}

		rules = append(rules, *rule)
		categories[rule.Category]++

		if req.MaxRules > 0 && len(rules) >= req.MaxRules {
			break
		}
	}
	s.mu.RUnlock()

	// Update server sync status
	s.mu.Lock()
	now := time.Now()
	server.LastThreatSync = &now
	server.ThreatRulesCount = len(rules)
	s.mu.Unlock()

	response := &models.ThreatSyncResponse{
		SyncID:     generateSyncID(),
		Timestamp:  now,
		ServerID:   req.ServerID,
		BlockRules: rules,
		TotalRules: len(rules),
		Categories: categories,
		IsDelta:    req.LastSyncAt != nil,
		AddedRules: len(rules),
		NextSyncAt: now.Add(s.config.SyncInterval),
	}

	s.logger.Info().
		Str("server_id", req.ServerID.String()).
		Int("rules_synced", len(rules)).
		Bool("delta", response.IsDelta).
		Msg("threat data synced to server")

	return response, nil
}

// PushThreatUpdate pushes a real-time threat update to all servers
func (s *OrbNetService) PushThreatUpdate(ctx context.Context, event *models.ThreatPushEvent) error {
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	event.Timestamp = time.Now()

	// Send to push channel
	select {
	case s.pushChan <- event:
		s.logger.Info().
			Str("event_id", event.EventID).
			Str("type", event.Type).
			Str("priority", event.Priority).
			Msg("threat update pushed")
		return nil
	default:
		return fmt.Errorf("push channel full")
	}
}

// GetPushChannel returns the push event channel for consumers
func (s *OrbNetService) GetPushChannel() <-chan *models.ThreatPushEvent {
	return s.pushChan
}

// AddBlockRule adds a new DNS block rule
func (s *OrbNetService) AddBlockRule(rule *models.DNSBlockRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.Enabled = true

	s.blockRules[rule.ID] = rule

	// Clear domain cache for this domain
	delete(s.domainCache, rule.Domain)

	// Push update to servers
	go s.PushThreatUpdate(context.Background(), &models.ThreatPushEvent{
		Type:     "add_rule",
		Priority: "normal",
		Rule:     rule,
	})

	return nil
}

// RemoveBlockRule removes a DNS block rule
func (s *OrbNetService) RemoveBlockRule(id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule, ok := s.blockRules[id]
	if !ok {
		return fmt.Errorf("rule not found: %s", id)
	}

	// Clear domain cache
	delete(s.domainCache, rule.Domain)
	delete(s.blockRules, id)

	// Push update to servers
	go s.PushThreatUpdate(context.Background(), &models.ThreatPushEvent{
		Type:     "remove_rule",
		Priority: "normal",
		RuleIDs:  []uuid.UUID{id},
	})

	return nil
}

// GetBlockRule retrieves a block rule
func (s *OrbNetService) GetBlockRule(id uuid.UUID) (*models.DNSBlockRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rule, ok := s.blockRules[id]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	return rule, nil
}

// ListBlockRules lists all block rules
func (s *OrbNetService) ListBlockRules(category string) []*models.DNSBlockRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.DNSBlockRule, 0)
	for _, rule := range s.blockRules {
		if category == "" || rule.Category == category {
			result = append(result, rule)
		}
	}
	return result
}

// EmergencyBlock blocks domains immediately across all servers
func (s *OrbNetService) EmergencyBlock(ctx context.Context, domains []string, reason string, duration time.Duration) error {
	s.mu.Lock()

	var expiresAt *time.Time
	if duration > 0 {
		t := time.Now().Add(duration)
		expiresAt = &t
	}

	for _, domain := range domains {
		rule := &models.DNSBlockRule{
			ID:          uuid.New(),
			Domain:      domain,
			RuleType:    models.DNSRuleTypeExact,
			Category:    models.DNSCategoryMalware,
			Severity:    models.SeverityCritical,
			Source:      "emergency",
			Description: reason,
			Enabled:     true,
			ExpiresAt:   expiresAt,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		s.blockRules[rule.ID] = rule
		delete(s.domainCache, domain)
	}
	s.mu.Unlock()

	// Push emergency update
	return s.PushThreatUpdate(ctx, &models.ThreatPushEvent{
		Type:     "emergency_block",
		Priority: "critical",
		Domains:  domains,
		Reason:   reason,
		Duration: duration,
	})
}

// GetDashboardStats returns dashboard statistics
func (s *OrbNetService) GetDashboardStats() *models.OrbNetDashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &models.OrbNetDashboardStats{
		Timestamp: time.Now(),
	}

	// Server stats
	for _, server := range s.servers {
		stats.TotalServers++
		if server.Status == "online" {
			stats.OnlineServers++
		}
		stats.TotalCapacity += server.Capacity
		stats.TotalConnections += server.Connections
		stats.AverageLoad += server.Load
	}
	if stats.TotalServers > 0 {
		stats.AverageLoad /= float64(stats.TotalServers)
	}

	// Client stats
	for _, client := range s.clients {
		stats.ActiveClients++
		if client.ThreatProtectionEnabled {
			stats.ProtectedClients++
		}
	}

	// Rule stats
	stats.RulesByCategory = make(map[string]int)
	for _, rule := range s.blockRules {
		if rule.Enabled {
			stats.TotalRules++
			stats.RulesByCategory[rule.Category]++
		}
	}

	// Query stats
	s.statsMu.RLock()
	stats.TotalQueries24h = s.queriesTotal
	stats.BlockedQueries24h = s.queriesBlocked
	if s.queriesTotal > 0 {
		stats.BlockRate = float64(s.queriesBlocked) / float64(s.queriesTotal) * 100
	}
	stats.ThreatsBlocked24h = s.queriesBlocked
	s.statsMu.RUnlock()

	// Sync status
	stats.SyncStatus = models.SyncStatusSynced
	for _, server := range s.servers {
		if server.LastThreatSync != nil {
			if stats.LastThreatSync == nil || server.LastThreatSync.After(*stats.LastThreatSync) {
				stats.LastThreatSync = server.LastThreatSync
			}
		}
	}

	return stats
}

// GetCategories returns available DNS block categories
func (s *OrbNetService) GetCategories() []map[string]interface{} {
	return []map[string]interface{}{
		{"id": models.DNSCategoryMalware, "name": "Malware", "description": "Malware distribution and C2 domains"},
		{"id": models.DNSCategoryPhishing, "name": "Phishing", "description": "Phishing and credential harvesting"},
		{"id": models.DNSCategoryAds, "name": "Ads", "description": "Advertising networks"},
		{"id": models.DNSCategoryTracking, "name": "Tracking", "description": "User tracking and analytics"},
		{"id": models.DNSCategoryAdult, "name": "Adult", "description": "Adult content"},
		{"id": models.DNSCategoryGambling, "name": "Gambling", "description": "Gambling sites"},
		{"id": models.DNSCategorySocialMedia, "name": "Social Media", "description": "Social media platforms"},
		{"id": models.DNSCategoryCrypto, "name": "Crypto", "description": "Cryptocurrency and mining"},
	}
}

// Helper functions

func (s *OrbNetService) indicatorToBlockRule(ind *models.Indicator) *models.DNSBlockRule {
	return &models.DNSBlockRule{
		ID:          uuid.New(),
		Domain:      ind.Value,
		RuleType:    models.DNSRuleTypeExact,
		Category:    s.mapSeverityToCategory(ind.Severity),
		Severity:    ind.Severity,
		Source:      "threat_intel",
		Description: ind.Description,
		Tags:        ind.Tags,
		Enabled:     true,
		CreatedAt:   ind.CreatedAt,
		UpdatedAt:   ind.UpdatedAt,
	}
}

func (s *OrbNetService) mapSeverityToCategory(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return models.DNSCategoryMalware
	case models.SeverityMedium:
		return models.DNSCategoryPhishing
	default:
		return models.DNSCategoryTracking
	}
}

func (s *OrbNetService) categoryToSeverity(category string) models.Severity {
	switch category {
	case models.DNSCategoryMalware:
		return models.SeverityCritical
	case models.DNSCategoryPhishing:
		return models.SeverityHigh
	case models.DNSCategoryTracking, models.DNSCategoryAds:
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func extractDomainFromURL(urlStr string) string {
	// Simple domain extraction
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		// Remove port if present
		hostParts := strings.Split(parts[0], ":")
		return strings.ToLower(hostParts[0])
	}
	return ""
}

func generateSyncID() string {
	data := fmt.Sprintf("%d-%s", time.Now().UnixNano(), uuid.New().String())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}
