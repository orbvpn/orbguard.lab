package services

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	repository "orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// CorrelationEngine provides advanced threat correlation capabilities
type CorrelationEngine struct {
	repos      *repository.Repositories
	cache      *cache.RedisCache
	logger     *logger.Logger
	config     *models.CorrelationConfig

	// Statistics
	statsMu         sync.RWMutex
	totalCorrelations int64
	byType          map[string]int64
	byStrength      map[string]int64
	processingTimes []time.Duration
	lastProcessed   time.Time
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine(repos *repository.Repositories, c *cache.RedisCache, log *logger.Logger) *CorrelationEngine {
	return &CorrelationEngine{
		repos:           repos,
		cache:           c,
		logger:          log.WithComponent("correlation-engine"),
		config:          models.DefaultCorrelationConfig(),
		byType:          make(map[string]int64),
		byStrength:      make(map[string]int64),
		processingTimes: make([]time.Duration, 0, 100),
	}
}

// SetConfig updates the correlation configuration
func (e *CorrelationEngine) SetConfig(config *models.CorrelationConfig) {
	e.config = config
}

// Correlate performs correlation analysis on the given request
func (e *CorrelationEngine) Correlate(ctx context.Context, req *models.CorrelationRequest) (*models.CorrelationResponse, error) {
	startTime := time.Now()
	requestID := uuid.New()

	e.logger.Info().
		Str("request_id", requestID.String()).
		Int("indicator_count", len(req.IndicatorIDs)+len(req.IndicatorValues)).
		Msg("starting correlation analysis")

	// Fetch indicators
	indicators, err := e.fetchIndicators(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch indicators: %w", err)
	}

	if len(indicators) == 0 {
		return &models.CorrelationResponse{
			RequestID:      requestID,
			Statistics:     models.CorrelationStats{},
			ProcessingTime: time.Since(startTime),
			GeneratedAt:    time.Now(),
		}, nil
	}

	response := &models.CorrelationResponse{
		RequestID:   requestID,
		GeneratedAt: time.Now(),
	}

	// Determine which correlation types to run
	types := req.Types
	if len(types) == 0 {
		types = []models.CorrelationType{
			models.CorrelationTemporal,
			models.CorrelationInfrastructure,
			models.CorrelationCampaign,
		}
	}

	var correlations []models.CorrelationEvent
	var clusters []models.IndicatorCluster

	for _, corrType := range types {
		switch corrType {
		case models.CorrelationTemporal:
			corrs := e.temporalCorrelation(ctx, indicators)
			correlations = append(correlations, corrs...)

		case models.CorrelationInfrastructure:
			corrs, clus := e.infrastructureCorrelation(ctx, indicators)
			correlations = append(correlations, corrs...)
			clusters = append(clusters, clus...)

		case models.CorrelationTTP:
			corrs := e.ttpCorrelation(ctx, indicators)
			correlations = append(correlations, corrs...)

		case models.CorrelationCampaign:
			matches := e.campaignMatching(ctx, indicators)
			response.CampaignMatches = append(response.CampaignMatches, matches...)

		case models.CorrelationNetwork:
			corrs := e.networkCorrelation(ctx, indicators)
			correlations = append(correlations, corrs...)
		}
	}

	// Filter by minimum confidence
	if req.MinConfidence > 0 {
		correlations = e.filterByConfidence(correlations, req.MinConfidence)
	}

	// Limit results
	if req.MaxResults > 0 && len(correlations) > req.MaxResults {
		correlations = correlations[:req.MaxResults]
	}

	// Actor matching
	response.ActorMatches = e.actorMatching(ctx, indicators, correlations)

	response.Correlations = correlations
	response.Clusters = clusters
	response.ProcessingTime = time.Since(startTime)
	response.Statistics = e.calculateStats(indicators, correlations, clusters, response.CampaignMatches, response.ActorMatches)

	// Update engine statistics
	e.updateStats(response)

	e.logger.Info().
		Str("request_id", requestID.String()).
		Int("correlations_found", len(correlations)).
		Int("clusters_formed", len(clusters)).
		Dur("processing_time", response.ProcessingTime).
		Msg("correlation analysis complete")

	return response, nil
}

// fetchIndicators retrieves indicators from the database
func (e *CorrelationEngine) fetchIndicators(ctx context.Context, req *models.CorrelationRequest) ([]*models.Indicator, error) {
	var indicators []*models.Indicator

	// Fetch by IDs
	for _, id := range req.IndicatorIDs {
		ind, err := e.repos.Indicators.GetByID(ctx, id)
		if err != nil {
			e.logger.Warn().Err(err).Str("id", id.String()).Msg("failed to fetch indicator by ID")
			continue
		}
		if ind != nil {
			indicators = append(indicators, ind)
		}
	}

	// Fetch by values - try each indicator type
	indicatorTypes := []models.IndicatorType{
		models.IndicatorTypeIP,
		models.IndicatorTypeDomain,
		models.IndicatorTypeURL,
		models.IndicatorTypeHash,
		models.IndicatorTypeEmail,
	}
	for _, value := range req.IndicatorValues {
		var found bool
		for _, iocType := range indicatorTypes {
			ind, err := e.repos.Indicators.GetByValue(ctx, value, iocType)
			if err != nil {
				continue
			}
			if ind != nil {
				indicators = append(indicators, ind)
				found = true
				break
			}
		}
		if !found {
			e.logger.Warn().Str("value", value).Msg("indicator not found by value")
		}
	}

	return indicators, nil
}

// temporalCorrelation finds indicators that appeared around the same time
func (e *CorrelationEngine) temporalCorrelation(ctx context.Context, indicators []*models.Indicator) []models.CorrelationEvent {
	var correlations []models.CorrelationEvent

	// Group indicators by time windows
	windows := []struct {
		duration time.Duration
		name     string
		strength models.CorrelationStrength
	}{
		{e.config.TemporalWindowShort, "1_hour", models.CorrelationStrengthVeryStrong},
		{e.config.TemporalWindowMedium, "24_hours", models.CorrelationStrengthStrong},
		{e.config.TemporalWindowLong, "7_days", models.CorrelationStrengthModerate},
	}

	for _, window := range windows {
		groups := e.groupByTimeWindow(indicators, window.duration)

		for timestamp, group := range groups {
			if len(group) < e.config.MinTemporalOverlap {
				continue
			}

			ids := make([]uuid.UUID, len(group))
			indicators := make([]string, len(group))
			for i, ind := range group {
				ids[i] = ind.ID
				indicators[i] = ind.Value
			}

			confidence := e.calculateTemporalConfidence(len(group), window.duration)

			corr := models.CorrelationEvent{
				ID:          uuid.New(),
				Type:        models.CorrelationTemporal,
				Strength:    window.strength,
				Confidence:  confidence,
				Description: fmt.Sprintf("%d indicators appeared within %s window around %s", len(group), window.name, timestamp.Format(time.RFC3339)),
				Indicators:  ids,
				Evidence: models.CorrelationEvidence{
					TemporalLinks: []models.TemporalLinkEvidence{{
						WindowStart: timestamp,
						WindowEnd:   timestamp.Add(window.duration),
						Count:       len(group),
						Indicators:  indicators,
					}},
				},
				CreatedAt: time.Now(),
			}

			correlations = append(correlations, corr)
		}
	}

	return correlations
}

// groupByTimeWindow groups indicators by time window
func (e *CorrelationEngine) groupByTimeWindow(indicators []*models.Indicator, window time.Duration) map[time.Time][]*models.Indicator {
	groups := make(map[time.Time][]*models.Indicator)

	for _, ind := range indicators {
		// Truncate to window boundary
		windowStart := ind.FirstSeen.Truncate(window)
		groups[windowStart] = append(groups[windowStart], ind)
	}

	return groups
}

// calculateTemporalConfidence calculates confidence for temporal correlation
func (e *CorrelationEngine) calculateTemporalConfidence(count int, window time.Duration) float64 {
	// More indicators in shorter windows = higher confidence
	baseConfidence := float64(count) / 10.0 // max at 10 indicators
	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}

	// Adjust by window size (shorter = higher confidence)
	windowFactor := 1.0
	switch {
	case window <= time.Hour:
		windowFactor = 1.0
	case window <= 24*time.Hour:
		windowFactor = 0.8
	default:
		windowFactor = 0.6
	}

	return baseConfidence * windowFactor
}

// infrastructureCorrelation finds indicators sharing infrastructure
func (e *CorrelationEngine) infrastructureCorrelation(ctx context.Context, indicators []*models.Indicator) ([]models.CorrelationEvent, []models.IndicatorCluster) {
	var correlations []models.CorrelationEvent
	var clusters []models.IndicatorCluster

	// Group by IP subnet
	ipGroups := e.groupByIPSubnet(indicators)
	for cidr, group := range ipGroups {
		if len(group) < e.config.MinSharedInfra {
			continue
		}

		ids := make([]uuid.UUID, len(group))
		ips := make([]string, len(group))
		for i, ind := range group {
			ids[i] = ind.ID
			ips[i] = ind.Value
		}

		confidence := float64(len(group)) / 10.0
		if confidence > 1.0 {
			confidence = 1.0
		}

		corr := models.CorrelationEvent{
			ID:          uuid.New(),
			Type:        models.CorrelationInfrastructure,
			Strength:    e.calculateStrength(confidence),
			Confidence:  confidence,
			Description: fmt.Sprintf("%d IPs share subnet %s", len(group), cidr),
			Indicators:  ids,
			Evidence: models.CorrelationEvidence{
				NetworkPatterns: []models.NetworkPatternEvidence{{
					Type:    "same_subnet",
					Pattern: cidr,
					IPs:     ips,
					Count:   len(group),
				}},
			},
			CreatedAt: time.Now(),
		}

		correlations = append(correlations, corr)

		// Create cluster
		cluster := e.createCluster(group, models.CorrelationInfrastructure, []string{fmt.Sprintf("shared subnet: %s", cidr)}, confidence)
		clusters = append(clusters, cluster)
	}

	// Group by domain patterns
	domainGroups := e.groupByDomainPattern(indicators)
	for pattern, group := range domainGroups {
		if len(group) < e.config.MinSharedInfra {
			continue
		}

		ids := make([]uuid.UUID, len(group))
		domains := make([]string, len(group))
		for i, ind := range group {
			ids[i] = ind.ID
			domains[i] = ind.Value
		}

		confidence := float64(len(group)) / 10.0
		if confidence > 1.0 {
			confidence = 1.0
		}

		corr := models.CorrelationEvent{
			ID:          uuid.New(),
			Type:        models.CorrelationInfrastructure,
			Strength:    e.calculateStrength(confidence),
			Confidence:  confidence,
			Description: fmt.Sprintf("%d domains match pattern: %s", len(group), pattern),
			Indicators:  ids,
			Evidence: models.CorrelationEvidence{
				DomainPatterns: []models.DomainPatternEvidence{{
					Pattern:    pattern,
					Domains:    domains,
					Similarity: 0.8,
				}},
			},
			CreatedAt: time.Now(),
		}

		correlations = append(correlations, corr)

		// Create cluster
		cluster := e.createCluster(group, models.CorrelationInfrastructure, []string{fmt.Sprintf("domain pattern: %s", pattern)}, confidence)
		clusters = append(clusters, cluster)
	}

	return correlations, clusters
}

// groupByIPSubnet groups IP indicators by /24 subnet
func (e *CorrelationEngine) groupByIPSubnet(indicators []*models.Indicator) map[string][]*models.Indicator {
	groups := make(map[string][]*models.Indicator)

	for _, ind := range indicators {
		if ind.Type != models.IndicatorTypeIP {
			continue
		}

		ip := net.ParseIP(ind.Value)
		if ip == nil {
			continue
		}

		// Convert to /24 subnet
		ip4 := ip.To4()
		if ip4 == nil {
			continue // Skip IPv6 for now
		}

		subnet := fmt.Sprintf("%d.%d.%d.0/%d", ip4[0], ip4[1], ip4[2], e.config.IPSubnetMask)
		groups[subnet] = append(groups[subnet], ind)
	}

	return groups
}

// groupByDomainPattern groups domain indicators by naming patterns
func (e *CorrelationEngine) groupByDomainPattern(indicators []*models.Indicator) map[string][]*models.Indicator {
	groups := make(map[string][]*models.Indicator)

	// Common malicious domain patterns
	patterns := []struct {
		name   string
		regex  *regexp.Regexp
	}{
		{"random-string", regexp.MustCompile(`^[a-z0-9]{12,}\.[a-z]{2,6}$`)},
		{"dga-like", regexp.MustCompile(`^[a-z]{5,20}\.[a-z]{2,4}$`)},
		{"number-prefix", regexp.MustCompile(`^\d+[a-z]+\.[a-z]{2,6}$`)},
		{"dash-heavy", regexp.MustCompile(`^[a-z]+-[a-z]+-[a-z]+\.[a-z]{2,6}$`)},
		{"typosquat-common", regexp.MustCompile(`(google|facebook|microsoft|apple|amazon|paypal|bank)[a-z0-9-]*\.[a-z]{2,6}`)},
	}

	for _, ind := range indicators {
		if ind.Type != models.IndicatorTypeDomain {
			continue
		}

		for _, p := range patterns {
			if p.regex.MatchString(strings.ToLower(ind.Value)) {
				groups[p.name] = append(groups[p.name], ind)
				break
			}
		}

		// Also group by TLD
		parts := strings.Split(ind.Value, ".")
		if len(parts) >= 2 {
			tld := parts[len(parts)-1]
			// Flag suspicious TLDs
			suspiciousTLDs := map[string]bool{
				"xyz": true, "tk": true, "ml": true, "ga": true, "cf": true,
				"gq": true, "top": true, "work": true, "click": true, "link": true,
			}
			if suspiciousTLDs[tld] {
				groups["suspicious-tld-"+tld] = append(groups["suspicious-tld-"+tld], ind)
			}
		}
	}

	return groups
}

// ttpCorrelation finds indicators with similar TTPs
func (e *CorrelationEngine) ttpCorrelation(ctx context.Context, indicators []*models.Indicator) []models.CorrelationEvent {
	var correlations []models.CorrelationEvent

	// Group indicators by MITRE technique tags
	techniqueGroups := make(map[string][]*models.Indicator)

	for _, ind := range indicators {
		for _, tag := range ind.Tags {
			if strings.HasPrefix(tag, "mitre:") || strings.HasPrefix(tag, "T") {
				techniqueGroups[tag] = append(techniqueGroups[tag], ind)
			}
		}
	}

	// Find indicators sharing techniques
	for technique, group := range techniqueGroups {
		if len(group) < e.config.MinTTPOverlap {
			continue
		}

		ids := make([]uuid.UUID, len(group))
		for i, ind := range group {
			ids[i] = ind.ID
		}

		confidence := float64(len(group)) / 10.0
		if confidence > 1.0 {
			confidence = 1.0
		}

		corr := models.CorrelationEvent{
			ID:          uuid.New(),
			Type:        models.CorrelationTTP,
			Strength:    e.calculateStrength(confidence),
			Confidence:  confidence,
			Description: fmt.Sprintf("%d indicators share MITRE technique %s", len(group), technique),
			Indicators:  ids,
			Evidence: models.CorrelationEvidence{
				TTPMatches: []models.TTPMatchEvidence{{
					TechniqueID:   technique,
					TechniqueName: technique, // Would need MITRE data to get name
				}},
			},
			CreatedAt: time.Now(),
		}

		correlations = append(correlations, corr)
	}

	return correlations
}

// networkCorrelation finds network-based correlations
func (e *CorrelationEngine) networkCorrelation(ctx context.Context, indicators []*models.Indicator) []models.CorrelationEvent {
	var correlations []models.CorrelationEvent

	// Group URLs by base domain
	domainGroups := make(map[string][]*models.Indicator)
	for _, ind := range indicators {
		if ind.Type == models.IndicatorTypeURL {
			domain := extractDomain(ind.Value)
			if domain != "" {
				domainGroups[domain] = append(domainGroups[domain], ind)
			}
		}
	}

	for domain, group := range domainGroups {
		if len(group) < 2 {
			continue
		}

		ids := make([]uuid.UUID, len(group))
		urls := make([]string, len(group))
		for i, ind := range group {
			ids[i] = ind.ID
			urls[i] = ind.Value
		}

		confidence := float64(len(group)) / 10.0
		if confidence > 1.0 {
			confidence = 1.0
		}

		corr := models.CorrelationEvent{
			ID:          uuid.New(),
			Type:        models.CorrelationNetwork,
			Strength:    e.calculateStrength(confidence),
			Confidence:  confidence,
			Description: fmt.Sprintf("%d URLs share domain %s", len(group), domain),
			Indicators:  ids,
			Evidence: models.CorrelationEvidence{
				SharedInfra: []models.SharedInfraEvidence{{
					Type:       "domain",
					Value:      domain,
					Indicators: urls,
					Count:      len(group),
				}},
			},
			CreatedAt: time.Now(),
		}

		correlations = append(correlations, corr)
	}

	return correlations
}

// campaignMatching matches indicators to existing campaigns
func (e *CorrelationEngine) campaignMatching(ctx context.Context, indicators []*models.Indicator) []models.CampaignMatch {
	var matches []models.CampaignMatch

	// Get all campaigns
	campaigns, _, err := e.repos.Campaigns.List(ctx, false, 100, 0)
	if err != nil {
		e.logger.Warn().Err(err).Msg("failed to fetch campaigns for matching")
		return matches
	}

	for _, campaign := range campaigns {
		// Get campaign indicators
		campaignInds, _, err := e.repos.Indicators.ListByCampaign(ctx, campaign.ID, 1000, 0)
		if err != nil {
			continue
		}

		// Check for overlaps
		matchingCount := 0
		var sharedPatterns []string
		campaignValues := make(map[string]bool)
		for _, ci := range campaignInds {
			campaignValues[ci.Value] = true
		}

		for _, ind := range indicators {
			if campaignValues[ind.Value] {
				matchingCount++
			}
		}

		if matchingCount > 0 {
			confidence := float64(matchingCount) / float64(len(indicators))
			if confidence > 0.1 { // At least 10% match
				matches = append(matches, models.CampaignMatch{
					CampaignID:         campaign.ID,
					CampaignName:       campaign.Name,
					Confidence:         confidence,
					MatchingIndicators: matchingCount,
					SharedPatterns:     sharedPatterns,
				})
			}
		}
	}

	// Sort by confidence
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})

	return matches
}

// actorMatching matches correlations to known threat actors
func (e *CorrelationEngine) actorMatching(ctx context.Context, indicators []*models.Indicator, correlations []models.CorrelationEvent) []models.ActorMatch {
	var matches []models.ActorMatch

	// Get all actors
	actors, _, err := e.repos.Actors.List(ctx, false, 100, 0)
	if err != nil {
		e.logger.Warn().Err(err).Msg("failed to fetch actors for matching")
		return matches
	}

	for _, actor := range actors {
		matchedTTPs := []string{}
		matchedInfra := []string{}

		// Check indicator tags for actor patterns
		for _, ind := range indicators {
			for _, tag := range ind.Tags {
				// Check for actor name in tags
				if strings.Contains(strings.ToLower(tag), strings.ToLower(actor.Name)) {
					matchedInfra = append(matchedInfra, ind.Value)
				}
				// Check for TTP matches from actor's known techniques
				for _, technique := range actor.CommonTechniques {
					if strings.Contains(tag, technique) {
						matchedTTPs = append(matchedTTPs, technique)
					}
				}
			}
		}

		if len(matchedTTPs) > 0 || len(matchedInfra) > 0 {
			confidence := (float64(len(matchedTTPs)) + float64(len(matchedInfra))) / float64(len(indicators))
			if confidence > 1.0 {
				confidence = 1.0
			}

			if confidence > 0.1 {
				matches = append(matches, models.ActorMatch{
					ActorID:      actor.ID,
					ActorName:    actor.Name,
					Confidence:   confidence,
					MatchedTTPs:  unique(matchedTTPs),
					MatchedInfra: unique(matchedInfra),
				})
			}
		}
	}

	// Sort by confidence
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})

	return matches
}

// createCluster creates an indicator cluster
func (e *CorrelationEngine) createCluster(indicators []*models.Indicator, clusterType models.CorrelationType, traits []string, confidence float64) models.IndicatorCluster {
	summaries := make([]models.IndicatorSummary, len(indicators))
	for i, ind := range indicators {
		summaries[i] = models.IndicatorSummary{
			ID:        ind.ID,
			Type:      ind.Type,
			Value:     ind.Value,
			Severity:  ind.Severity,
			FirstSeen: ind.FirstSeen,
		}
	}

	var suggestion *models.CampaignSuggestion
	if len(indicators) >= e.config.MinCampaignIndicators && confidence >= e.config.CampaignConfidenceMin {
		suggestion = &models.CampaignSuggestion{
			Name:           fmt.Sprintf("Potential Campaign %s", uuid.New().String()[:8]),
			Description:    fmt.Sprintf("Auto-detected cluster of %d related indicators", len(indicators)),
			Confidence:     confidence,
			IndicatorCount: len(indicators),
			TimeRange: models.TimeRange{
				Start: indicators[0].FirstSeen,
				End:   indicators[len(indicators)-1].FirstSeen,
			},
			CommonPatterns: traits,
		}
	}

	return models.IndicatorCluster{
		ID:                uuid.New(),
		Name:              fmt.Sprintf("%s Cluster", clusterType),
		Indicators:        summaries,
		ClusterType:       clusterType,
		Confidence:        confidence,
		CommonTraits:      traits,
		SuggestedCampaign: suggestion,
		CreatedAt:         time.Now(),
	}
}

// calculateStrength determines correlation strength from confidence
func (e *CorrelationEngine) calculateStrength(confidence float64) models.CorrelationStrength {
	switch {
	case confidence >= 0.9:
		return models.CorrelationStrengthVeryStrong
	case confidence >= 0.7:
		return models.CorrelationStrengthStrong
	case confidence >= 0.5:
		return models.CorrelationStrengthModerate
	default:
		return models.CorrelationStrengthWeak
	}
}

// filterByConfidence filters correlations by minimum confidence
func (e *CorrelationEngine) filterByConfidence(correlations []models.CorrelationEvent, minConfidence float64) []models.CorrelationEvent {
	filtered := make([]models.CorrelationEvent, 0, len(correlations))
	for _, corr := range correlations {
		if corr.Confidence >= minConfidence {
			filtered = append(filtered, corr)
		}
	}
	return filtered
}

// calculateStats calculates correlation statistics
func (e *CorrelationEngine) calculateStats(indicators []*models.Indicator, correlations []models.CorrelationEvent, clusters []models.IndicatorCluster, campaigns []models.CampaignMatch, actors []models.ActorMatch) models.CorrelationStats {
	stats := models.CorrelationStats{
		TotalIndicators:   len(indicators),
		CorrelationsFound: len(correlations),
		ClustersFormed:    len(clusters),
		CampaignsMatched:  len(campaigns),
		ActorsMatched:     len(actors),
	}

	if len(correlations) > 0 {
		totalConfidence := 0.0
		maxConfidence := 0.0
		for _, corr := range correlations {
			totalConfidence += corr.Confidence
			if corr.Confidence > maxConfidence {
				maxConfidence = corr.Confidence
			}
		}
		stats.AverageConfidence = totalConfidence / float64(len(correlations))
		stats.StrongestCorrelation = maxConfidence
	}

	return stats
}

// updateStats updates engine statistics
func (e *CorrelationEngine) updateStats(response *models.CorrelationResponse) {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()

	e.totalCorrelations += int64(len(response.Correlations))
	e.lastProcessed = time.Now()

	for _, corr := range response.Correlations {
		e.byType[string(corr.Type)]++
		e.byStrength[string(corr.Strength)]++
	}

	e.processingTimes = append(e.processingTimes, response.ProcessingTime)
	if len(e.processingTimes) > 100 {
		e.processingTimes = e.processingTimes[1:]
	}
}

// GetStats returns correlation engine statistics
func (e *CorrelationEngine) GetStats() *models.CorrelationEngineStats {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()

	stats := &models.CorrelationEngineStats{
		TotalCorrelations:      e.totalCorrelations,
		CorrelationsByType:     make(map[string]int64),
		CorrelationsByStrength: make(map[string]int64),
		LastProcessedAt:        e.lastProcessed,
	}

	for k, v := range e.byType {
		stats.CorrelationsByType[k] = v
	}
	for k, v := range e.byStrength {
		stats.CorrelationsByStrength[k] = v
	}

	if len(e.processingTimes) > 0 {
		var total time.Duration
		for _, t := range e.processingTimes {
			total += t
		}
		stats.AverageProcessingTime = total / time.Duration(len(e.processingTimes))
	}

	return stats
}

// CorrelateIndicator correlates a single indicator
func (e *CorrelationEngine) CorrelateIndicator(ctx context.Context, indicatorID uuid.UUID) (*models.CorrelationResponse, error) {
	return e.Correlate(ctx, &models.CorrelationRequest{
		IndicatorIDs:    []uuid.UUID{indicatorID},
		IncludeEvidence: true,
	})
}

// CorrelateBatch correlates a batch of indicators
func (e *CorrelationEngine) CorrelateBatch(ctx context.Context, indicatorIDs []uuid.UUID) (*models.CorrelationResponse, error) {
	return e.Correlate(ctx, &models.CorrelationRequest{
		IndicatorIDs:    indicatorIDs,
		IncludeEvidence: true,
	})
}

// DetectCampaigns auto-detects potential campaigns from uncategorized indicators
func (e *CorrelationEngine) DetectCampaigns(ctx context.Context, limit int) ([]models.CampaignSuggestion, error) {
	// Fetch recent uncategorized indicators
	filter := repository.IndicatorFilter{
		Limit: 500,
	}

	indicators, _, err := e.repos.Indicators.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch indicators: %w", err)
	}

	// Filter to only uncampaigned indicators
	var uncampaigned []*models.Indicator
	for _, ind := range indicators {
		if ind.CampaignID == nil {
			uncampaigned = append(uncampaigned, ind)
		}
	}

	// Run correlation
	response, err := e.Correlate(ctx, &models.CorrelationRequest{
		IndicatorIDs: extractIDs(uncampaigned),
		Types: []models.CorrelationType{
			models.CorrelationInfrastructure,
			models.CorrelationTemporal,
		},
		IncludeEvidence: true,
	})
	if err != nil {
		return nil, err
	}

	// Extract campaign suggestions
	var suggestions []models.CampaignSuggestion
	for _, cluster := range response.Clusters {
		if cluster.SuggestedCampaign != nil {
			suggestions = append(suggestions, *cluster.SuggestedCampaign)
		}
	}

	if limit > 0 && len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}

	return suggestions, nil
}

// Helper functions

func extractDomain(urlStr string) string {
	// Simple domain extraction from URL
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		hostParts := strings.Split(parts[0], ":")
		return hostParts[0]
	}
	return ""
}

func extractIDs(indicators []*models.Indicator) []uuid.UUID {
	ids := make([]uuid.UUID, len(indicators))
	for i, ind := range indicators {
		ids[i] = ind.ID
	}
	return ids
}

func unique(strs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(strs))
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
