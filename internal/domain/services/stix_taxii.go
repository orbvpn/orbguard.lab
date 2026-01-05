package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// STIXTAXIIService handles STIX conversion and TAXII server operations
type STIXTAXIIService struct {
	repos       *repository.Repositories
	cache       *cache.RedisCache
	logger      *logger.Logger
	config      models.TAXIIServerConfig
	collections map[string]*models.TAXIICollectionConfig
	identity    *models.STIXIdentity

	mu sync.RWMutex
	// Status tracking for async operations
	statusMap map[string]*models.TAXIIStatus
}

// NewSTIXTAXIIService creates a new STIX/TAXII service
func NewSTIXTAXIIService(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *STIXTAXIIService {
	svc := &STIXTAXIIService{
		repos:       repos,
		cache:       cache,
		logger:      log.WithComponent("stix-taxii"),
		config:      models.DefaultTAXIIServerConfig,
		collections: make(map[string]*models.TAXIICollectionConfig),
		statusMap:   make(map[string]*models.TAXIIStatus),
	}

	// Initialize default collections
	for _, col := range models.DefaultTAXIICollections {
		colCopy := col
		colCopy.CreatedAt = time.Now()
		colCopy.UpdatedAt = time.Now()
		svc.collections[col.ID] = &colCopy
		// Also index by alias
		if col.Alias != "" {
			svc.collections[col.Alias] = &colCopy
		}
	}

	// Create OrbGuard identity
	svc.identity = &models.STIXIdentity{
		STIXCommonProperties: models.STIXCommonProperties{
			Type:        models.STIXTypeIdentity,
			SpecVersion: "2.1",
			ID:          "identity--" + uuid.New().String(),
			Created:     time.Now(),
			Modified:    time.Now(),
		},
		Name:          "OrbGuard Threat Intelligence",
		Description:   "Mobile security threat intelligence from OrbGuard",
		IdentityClass: "organization",
		Sectors:       []string{"technology"},
	}

	return svc
}

// GetDiscovery returns TAXII discovery information
func (s *STIXTAXIIService) GetDiscovery(baseURL string) *models.TAXIIDiscovery {
	return &models.TAXIIDiscovery{
		Title:       s.config.Title,
		Description: s.config.Description,
		Contact:     s.config.Contact,
		Default:     baseURL + "/taxii2/",
		APIRoots:    []string{baseURL + "/taxii2/"},
	}
}

// GetAPIRoot returns API root information
func (s *STIXTAXIIService) GetAPIRoot() *models.TAXIIAPIRoot {
	return &models.TAXIIAPIRoot{
		Title:            s.config.Title,
		Description:      s.config.Description,
		Versions:         []string{"application/taxii+json;version=2.1"},
		MaxContentLength: s.config.MaxContentLength,
	}
}

// GetCollections returns all collections
func (s *STIXTAXIIService) GetCollections() *models.TAXIICollections {
	s.mu.RLock()
	defer s.mu.RUnlock()

	collections := make([]models.TAXIICollection, 0)
	seen := make(map[string]bool)

	for _, col := range s.collections {
		if seen[col.ID] {
			continue
		}
		seen[col.ID] = true
		collections = append(collections, models.TAXIICollection{
			ID:          col.ID,
			Title:       col.Title,
			Description: col.Description,
			Alias:       col.Alias,
			CanRead:     col.CanRead,
			CanWrite:    col.CanWrite,
			MediaTypes:  col.MediaTypes,
		})
	}

	return &models.TAXIICollections{Collections: collections}
}

// GetCollection returns a specific collection
func (s *STIXTAXIIService) GetCollection(collectionID string) (*models.TAXIICollection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	col, ok := s.collections[collectionID]
	if !ok {
		return nil, fmt.Errorf("collection not found: %s", collectionID)
	}

	return &models.TAXIICollection{
		ID:          col.ID,
		Title:       col.Title,
		Description: col.Description,
		Alias:       col.Alias,
		CanRead:     col.CanRead,
		CanWrite:    col.CanWrite,
		MediaTypes:  col.MediaTypes,
	}, nil
}

// GetObjects returns STIX objects from a collection
func (s *STIXTAXIIService) GetObjects(ctx context.Context, collectionID string, filters *models.TAXIIObjectFilters) (*models.TAXIIEnvelope, error) {
	s.mu.RLock()
	col, ok := s.collections[collectionID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("collection not found: %s", collectionID)
	}

	if !col.CanRead {
		return nil, fmt.Errorf("collection is not readable")
	}

	// Get indicators from repository
	indicators, err := s.getIndicatorsForCollection(ctx, col.Alias, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to get indicators: %w", err)
	}

	// Convert to STIX objects
	objects := make([]interface{}, 0, len(indicators))
	for _, ind := range indicators {
		stixObj := s.IndicatorToSTIX(ind)
		objects = append(objects, stixObj)
	}

	// Determine if there are more results
	limit := 100
	if filters != nil && filters.Limit > 0 {
		limit = filters.Limit
	}
	hasMore := len(objects) >= limit

	envelope := &models.TAXIIEnvelope{
		More:    hasMore,
		Objects: objects,
	}

	if hasMore && len(objects) > 0 {
		// Set next cursor (using last object ID)
		if stixInd, ok := objects[len(objects)-1].(*models.STIXIndicator); ok {
			envelope.Next = stixInd.ID
		}
	}

	return envelope, nil
}

// getIndicatorsForCollection gets indicators for a specific collection
func (s *STIXTAXIIService) getIndicatorsForCollection(ctx context.Context, alias string, filters *models.TAXIIObjectFilters) ([]*models.Indicator, error) {
	if s.repos == nil || s.repos.Indicators == nil {
		return []*models.Indicator{}, nil
	}

	// Build filter based on collection alias
	repoFilters := repository.IndicatorFilter{
		Limit: 100,
	}

	if filters != nil {
		if filters.Limit > 0 && filters.Limit < 1000 {
			repoFilters.Limit = filters.Limit
		}
		if filters.AddedAfter != nil {
			repoFilters.FirstSeenAfter = filters.AddedAfter
		}
	}

	// Filter by collection type
	switch alias {
	case "mobile-threats":
		repoFilters.Tags = []string{"mobile", "android", "ios"}
	case "pegasus":
		repoFilters.Tags = []string{"pegasus", "nso-group", "spyware"}
	case "phishing":
		repoFilters.Tags = []string{"phishing", "smishing"}
	case "malware":
		repoFilters.Tags = []string{"malware", "trojan", "ransomware"}
	case "community":
		repoFilters.Tags = []string{"community"}
	}

	indicators, _, err := s.repos.Indicators.List(ctx, repoFilters)
	return indicators, err
}

// AddObjects adds STIX objects to a collection
func (s *STIXTAXIIService) AddObjects(ctx context.Context, collectionID string, envelope *models.TAXIIEnvelope) (*models.TAXIIStatus, error) {
	s.mu.RLock()
	col, ok := s.collections[collectionID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("collection not found: %s", collectionID)
	}

	if !col.CanWrite {
		return nil, fmt.Errorf("collection is not writable")
	}

	// Create status for tracking
	now := time.Now()
	status := &models.TAXIIStatus{
		ID:               "status--" + uuid.New().String(),
		Status:           "complete",
		RequestTimestamp: &now,
		TotalCount:       len(envelope.Objects),
		Successes:        make([]models.TAXIIStatusDetail, 0),
		Failures:         make([]models.TAXIIStatusDetail, 0),
	}

	// Process each object
	for _, obj := range envelope.Objects {
		objMap, ok := obj.(map[string]interface{})
		if !ok {
			status.FailureCount++
			status.Failures = append(status.Failures, models.TAXIIStatusDetail{
				Message: "Invalid object format",
			})
			continue
		}

		objType, _ := objMap["type"].(string)
		objID, _ := objMap["id"].(string)

		// Only accept indicators for now
		if objType != "indicator" {
			status.FailureCount++
			status.Failures = append(status.Failures, models.TAXIIStatusDetail{
				ID:      objID,
				Message: fmt.Sprintf("Unsupported object type: %s", objType),
			})
			continue
		}

		// Convert STIX indicator to our model and store
		indicator, err := s.STIXToIndicator(objMap)
		if err != nil {
			status.FailureCount++
			status.Failures = append(status.Failures, models.TAXIIStatusDetail{
				ID:      objID,
				Message: err.Error(),
			})
			continue
		}

		// Add community tag
		indicator.Tags = append(indicator.Tags, "community", "taxii-submitted")

		// Store indicator
		if s.repos != nil && s.repos.Indicators != nil {
			if _, err := s.repos.Indicators.Create(ctx, indicator); err != nil {
				status.FailureCount++
				status.Failures = append(status.Failures, models.TAXIIStatusDetail{
					ID:      objID,
					Message: err.Error(),
				})
				continue
			}
		}

		status.SuccessCount++
		status.Successes = append(status.Successes, models.TAXIIStatusDetail{
			ID:      objID,
			Version: "2.1",
		})
	}

	// Store status for later retrieval
	s.mu.Lock()
	s.statusMap[status.ID] = status
	s.mu.Unlock()

	return status, nil
}

// GetStatus returns the status of an add objects request
func (s *STIXTAXIIService) GetStatus(statusID string) (*models.TAXIIStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status, ok := s.statusMap[statusID]
	if !ok {
		return nil, fmt.Errorf("status not found: %s", statusID)
	}

	return status, nil
}

// GetManifest returns the manifest for a collection
func (s *STIXTAXIIService) GetManifest(ctx context.Context, collectionID string, filters *models.TAXIIObjectFilters) (*models.TAXIIManifest, error) {
	s.mu.RLock()
	col, ok := s.collections[collectionID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("collection not found: %s", collectionID)
	}

	if !col.CanRead {
		return nil, fmt.Errorf("collection is not readable")
	}

	// Get indicators
	indicators, err := s.getIndicatorsForCollection(ctx, col.Alias, filters)
	if err != nil {
		return nil, err
	}

	// Build manifest entries
	entries := make([]models.TAXIIManifestEntry, 0, len(indicators))
	for _, ind := range indicators {
		entries = append(entries, models.TAXIIManifestEntry{
			ID:         s.indicatorToSTIXID(ind),
			DateAdded:  ind.CreatedAt,
			Version:    ind.UpdatedAt.Format(time.RFC3339),
			MediaTypes: []string{models.STIXMediaType},
		})
	}

	return &models.TAXIIManifest{
		Objects: entries,
	}, nil
}

// IndicatorToSTIX converts an OrbGuard indicator to a STIX indicator
func (s *STIXTAXIIService) IndicatorToSTIX(ind *models.Indicator) *models.STIXIndicator {
	stixID := s.indicatorToSTIXID(ind)

	// Build STIX pattern
	pattern := s.buildSTIXPattern(ind)

	// Determine indicator types
	indicatorTypes := s.determineIndicatorTypes(ind)

	// Build external references from tags
	externalRefs := make([]models.ExternalReference, 0)
	for _, tag := range ind.Tags {
		if strings.HasPrefix(tag, "source:") {
			externalRefs = append(externalRefs, models.ExternalReference{
				SourceName: strings.TrimPrefix(tag, "source:"),
			})
		}
	}

	// Build kill chain phases if we have MITRE techniques
	killChainPhases := make([]models.KillChainPhase, 0)
	for _, technique := range ind.MitreTechniques {
		killChainPhases = append(killChainPhases, models.KillChainPhase{
			KillChainName: "mitre-attack",
			PhaseName:     technique,
		})
	}

	// Default TLP marking (white for public intel)
	markingRefs := []string{models.TLPWhite.ID}

	// Convert confidence from 0-1 to 0-100
	confidence := int(ind.Confidence * 100)
	if confidence > 100 {
		confidence = 100
	}

	stixIndicator := &models.STIXIndicator{
		STIXCommonProperties: models.STIXCommonProperties{
			Type:               models.STIXTypeIndicator,
			SpecVersion:        "2.1",
			ID:                 stixID,
			Created:            ind.CreatedAt,
			Modified:           ind.UpdatedAt,
			CreatedByRef:       s.identity.ID,
			Labels:             ind.Tags,
			Confidence:         confidence,
			ExternalReferences: externalRefs,
			ObjectMarkingRefs:  markingRefs,
		},
		Name:            ind.Value,
		Description:     ind.Description,
		IndicatorTypes:  indicatorTypes,
		Pattern:         pattern,
		PatternType:     models.PatternTypeSTIX,
		PatternVersion:  "2.1",
		ValidFrom:       ind.FirstSeen,
		KillChainPhases: killChainPhases,
	}

	if !ind.LastSeen.IsZero() {
		stixIndicator.ValidUntil = &ind.LastSeen
	}

	return stixIndicator
}

// indicatorToSTIXID generates a deterministic STIX ID for an indicator
func (s *STIXTAXIIService) indicatorToSTIXID(ind *models.Indicator) string {
	// Use indicator UUID if available, otherwise generate from value
	if ind.ID != uuid.Nil {
		return fmt.Sprintf("indicator--%s", ind.ID.String())
	}
	// Generate deterministic UUID from value
	namespace := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	id := uuid.NewSHA1(namespace, []byte(ind.Value))
	return fmt.Sprintf("indicator--%s", id.String())
}

// buildSTIXPattern builds a STIX pattern from an indicator
func (s *STIXTAXIIService) buildSTIXPattern(ind *models.Indicator) string {
	switch ind.Type {
	case models.IndicatorTypeDomain:
		return fmt.Sprintf("[domain-name:value = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeIP:
		if strings.Contains(ind.Value, ":") {
			return fmt.Sprintf("[ipv6-addr:value = '%s']", escapeSTIXPattern(ind.Value))
		}
		return fmt.Sprintf("[ipv4-addr:value = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeIPv6:
		return fmt.Sprintf("[ipv6-addr:value = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeURL:
		return fmt.Sprintf("[url:value = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeHash:
		// Determine hash type
		hashType := "SHA-256"
		switch len(ind.Value) {
		case 32:
			hashType = "MD5"
		case 40:
			hashType = "SHA-1"
		case 64:
			hashType = "SHA-256"
		case 128:
			hashType = "SHA-512"
		}
		return fmt.Sprintf("[file:hashes.'%s' = '%s']", hashType, escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeEmail:
		return fmt.Sprintf("[email-addr:value = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypePackage:
		return fmt.Sprintf("[software:name = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeCertificate:
		return fmt.Sprintf("[x509-certificate:serial_number = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeProcess:
		return fmt.Sprintf("[process:name = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeFilePath:
		return fmt.Sprintf("[file:name = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeRegistry:
		return fmt.Sprintf("[windows-registry-key:key = '%s']", escapeSTIXPattern(ind.Value))
	case models.IndicatorTypeYARA:
		return fmt.Sprintf("[x-orbguard-yara:rule = '%s']", escapeSTIXPattern(ind.Value))
	default:
		// Generic pattern
		return fmt.Sprintf("[x-orbguard-indicator:value = '%s' AND x-orbguard-indicator:type = '%s']",
			escapeSTIXPattern(ind.Value), string(ind.Type))
	}
}

// escapeSTIXPattern escapes special characters in STIX patterns
func escapeSTIXPattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}

// determineIndicatorTypes determines STIX indicator types from tags
func (s *STIXTAXIIService) determineIndicatorTypes(ind *models.Indicator) []string {
	types := make([]string, 0)

	for _, tag := range ind.Tags {
		tag = strings.ToLower(tag)
		switch {
		case strings.Contains(tag, "malware") || strings.Contains(tag, "trojan"):
			types = append(types, "malicious-activity")
		case strings.Contains(tag, "phishing") || strings.Contains(tag, "smishing"):
			types = append(types, "malicious-activity")
		case strings.Contains(tag, "c2") || strings.Contains(tag, "command-and-control"):
			types = append(types, "malicious-activity")
		case strings.Contains(tag, "spyware") || strings.Contains(tag, "stalkerware"):
			types = append(types, "malicious-activity")
		case strings.Contains(tag, "suspicious"):
			types = append(types, "anomalous-activity")
		case strings.Contains(tag, "compromised"):
			types = append(types, "compromised")
		}
	}

	// Default if no types determined
	if len(types) == 0 {
		if ind.Severity == models.SeverityCritical || ind.Severity == models.SeverityHigh {
			types = append(types, "malicious-activity")
		} else {
			types = append(types, "unknown")
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, t := range types {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}

	return result
}

// STIXToIndicator converts a STIX indicator to an OrbGuard indicator
func (s *STIXTAXIIService) STIXToIndicator(obj map[string]interface{}) (*models.Indicator, error) {
	pattern, _ := obj["pattern"].(string)
	if pattern == "" {
		return nil, fmt.Errorf("missing pattern")
	}

	// Parse pattern to extract value and type
	value, indType, err := parseSTIXPattern(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pattern: %w", err)
	}

	indicator := &models.Indicator{
		ID:          uuid.New(),
		Value:       value,
		Type:        indType,
		Description: getStringField(obj, "description"),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		FirstSeen:   time.Now(),
		Severity:    models.SeverityMedium,
		Confidence:  0.5, // 50% confidence by default
	}

	// Parse name
	if name := getStringField(obj, "name"); name != "" {
		indicator.Description = name
	}

	// Parse labels as tags
	if labels, ok := obj["labels"].([]interface{}); ok {
		for _, label := range labels {
			if labelStr, ok := label.(string); ok {
				indicator.Tags = append(indicator.Tags, labelStr)
			}
		}
	}

	// Parse confidence (STIX uses 0-100, we use 0-1)
	if conf, ok := obj["confidence"].(float64); ok {
		indicator.Confidence = conf / 100.0
	}

	// Parse valid_from
	if validFrom := getStringField(obj, "valid_from"); validFrom != "" {
		if t, err := time.Parse(time.RFC3339, validFrom); err == nil {
			indicator.FirstSeen = t
		}
	}

	return indicator, nil
}

// parseSTIXPattern parses a STIX pattern to extract value and type
func parseSTIXPattern(pattern string) (string, models.IndicatorType, error) {
	// Simple pattern parsing - handles basic patterns
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimPrefix(pattern, "[")
	pattern = strings.TrimSuffix(pattern, "]")

	// Parse object:property = 'value'
	parts := strings.SplitN(pattern, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid pattern format")
	}

	objProp := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, "'\"")

	// Determine type from object
	var indType models.IndicatorType
	switch {
	case strings.HasPrefix(objProp, "domain-name"):
		indType = models.IndicatorTypeDomain
	case strings.HasPrefix(objProp, "ipv4-addr"):
		indType = models.IndicatorTypeIP
	case strings.HasPrefix(objProp, "ipv6-addr"):
		indType = models.IndicatorTypeIPv6
	case strings.HasPrefix(objProp, "url"):
		indType = models.IndicatorTypeURL
	case strings.HasPrefix(objProp, "file:hashes"):
		indType = models.IndicatorTypeHash
	case strings.HasPrefix(objProp, "email-addr"):
		indType = models.IndicatorTypeEmail
	case strings.HasPrefix(objProp, "software"):
		indType = models.IndicatorTypePackage
	case strings.HasPrefix(objProp, "process"):
		indType = models.IndicatorTypeProcess
	case strings.HasPrefix(objProp, "x509-certificate"):
		indType = models.IndicatorTypeCertificate
	case strings.HasPrefix(objProp, "windows-registry-key"):
		indType = models.IndicatorTypeRegistry
	case strings.HasPrefix(objProp, "file"):
		indType = models.IndicatorTypeFilePath
	default:
		indType = models.IndicatorTypeDomain // default to domain
	}

	return value, indType, nil
}

// getStringField safely gets a string field from a map
func getStringField(obj map[string]interface{}, key string) string {
	if val, ok := obj[key].(string); ok {
		return val
	}
	return ""
}

// CampaignToSTIX converts an OrbGuard campaign to a STIX campaign
func (s *STIXTAXIIService) CampaignToSTIX(campaign *models.Campaign) *models.STIXCampaign {
	stixID := fmt.Sprintf("campaign--%s", campaign.ID.String())

	// Build labels from target sectors
	labels := make([]string, 0)
	labels = append(labels, campaign.TargetSectors...)

	stixCampaign := &models.STIXCampaign{
		STIXCommonProperties: models.STIXCommonProperties{
			Type:         models.STIXTypeCampaign,
			SpecVersion:  "2.1",
			ID:           stixID,
			Created:      campaign.CreatedAt,
			Modified:     campaign.UpdatedAt,
			CreatedByRef: s.identity.ID,
			Labels:       labels,
		},
		Name:        campaign.Name,
		Description: campaign.Description,
	}

	if !campaign.FirstSeen.IsZero() {
		stixCampaign.FirstSeen = &campaign.FirstSeen
	}
	if !campaign.LastSeen.IsZero() {
		stixCampaign.LastSeen = &campaign.LastSeen
	}

	return stixCampaign
}

// ThreatActorToSTIX converts an OrbGuard threat actor to a STIX threat actor
func (s *STIXTAXIIService) ThreatActorToSTIX(actor *models.ThreatActor) *models.STIXThreatActor {
	stixID := fmt.Sprintf("threat-actor--%s", actor.ID.String())

	stixActor := &models.STIXThreatActor{
		STIXCommonProperties: models.STIXCommonProperties{
			Type:         models.STIXTypeThreatActor,
			SpecVersion:  "2.1",
			ID:           stixID,
			Created:      actor.CreatedAt,
			Modified:     actor.UpdatedAt,
			CreatedByRef: s.identity.ID,
		},
		Name:              actor.Name,
		Description:       actor.Description,
		ThreatActorTypes:  []string{string(actor.Type)},
		Aliases:           actor.Aliases,
		PrimaryMotivation: string(actor.Motivation),
	}

	return stixActor
}

// CreateBundle creates a STIX bundle from multiple objects
func (s *STIXTAXIIService) CreateBundle(objects []interface{}) *models.STIXBundle {
	// Always include identity and TLP markings
	allObjects := []interface{}{
		s.identity,
		models.TLPWhite,
		models.TLPGreen,
		models.TLPAmber,
		models.TLPRed,
	}
	allObjects = append(allObjects, objects...)

	return models.NewSTIXBundle(allObjects)
}

// GetStats returns service statistics
func (s *STIXTAXIIService) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	collectionStats := make([]map[string]interface{}, 0)
	seen := make(map[string]bool)

	for _, col := range s.collections {
		if seen[col.ID] {
			continue
		}
		seen[col.ID] = true
		collectionStats = append(collectionStats, map[string]interface{}{
			"id":           col.ID,
			"title":        col.Title,
			"object_count": col.ObjectCount,
			"can_read":     col.CanRead,
			"can_write":    col.CanWrite,
		})
	}

	return map[string]interface{}{
		"title":           s.config.Title,
		"collections":     collectionStats,
		"total_collections": len(collectionStats),
		"status_count":    len(s.statusMap),
	}
}
