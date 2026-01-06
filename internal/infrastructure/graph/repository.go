package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// GraphRepository handles graph database operations
type GraphRepository struct {
	client *Neo4jClient
	logger *logger.Logger
}

// NewGraphRepository creates a new graph repository
func NewGraphRepository(client *Neo4jClient, log *logger.Logger) *GraphRepository {
	return &GraphRepository{
		client: client,
		logger: log.WithComponent("graph-repo"),
	}
}

// CreateIndicator creates or updates an indicator node
func (r *GraphRepository) CreateIndicator(ctx context.Context, indicator *models.IndicatorNode) error {
	params := map[string]interface{}{
		"id":         indicator.ID.String(),
		"type":       string(indicator.Type),
		"value":      indicator.Value,
		"severity":   string(indicator.Severity),
		"confidence": indicator.Confidence,
		"first_seen": indicator.FirstSeen.Unix(),
		"last_seen":  indicator.LastSeen.Unix(),
		"tags":       indicator.Tags,
		"source":     indicator.Source,
	}

	_, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, models.CypherCreateIndicator, params)
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to create indicator node: %w", err)
	}

	return nil
}

// CreateIndicatorsBatch creates multiple indicator nodes in a single transaction
func (r *GraphRepository) CreateIndicatorsBatch(ctx context.Context, indicators []*models.IndicatorNode) (int, error) {
	if len(indicators) == 0 {
		return 0, nil
	}

	// Build batch parameters
	batch := make([]map[string]interface{}, 0, len(indicators))
	for _, ind := range indicators {
		batch = append(batch, map[string]interface{}{
			"id":         ind.ID.String(),
			"type":       string(ind.Type),
			"value":      ind.Value,
			"severity":   string(ind.Severity),
			"confidence": ind.Confidence,
			"first_seen": ind.FirstSeen.Unix(),
			"last_seen":  ind.LastSeen.Unix(),
			"tags":       ind.Tags,
			"source":     ind.Source,
		})
	}

	cypher := `
		UNWIND $batch AS ind
		MERGE (i:Indicator {id: ind.id})
		SET i.type = ind.type,
			i.value = ind.value,
			i.severity = ind.severity,
			i.confidence = ind.confidence,
			i.first_seen = ind.first_seen,
			i.last_seen = ind.last_seen,
			i.tags = ind.tags,
			i.source = ind.source,
			i.updated_at = timestamp()
		RETURN count(i) as created`

	result, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		res, err := tx.Run(ctx, cypher, map[string]interface{}{"batch": batch})
		if err != nil {
			return 0, err
		}
		if res.Next(ctx) {
			if count, ok := res.Record().Get("created"); ok {
				if c, ok := count.(int64); ok {
					return int(c), nil
				}
			}
		}
		return len(batch), nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to batch create indicators: %w", err)
	}

	return result.(int), nil
}

// CreateCampaign creates or updates a campaign node
func (r *GraphRepository) CreateCampaign(ctx context.Context, campaign *models.CampaignNode) error {
	params := map[string]interface{}{
		"id":             campaign.ID.String(),
		"slug":           campaign.Slug,
		"name":           campaign.Name,
		"description":    campaign.Description,
		"malware_family": campaign.MalwareFamily,
		"first_seen":     campaign.FirstSeen.Unix(),
		"last_seen":      campaign.LastSeen.Unix(),
		"is_active":      campaign.IsActive,
	}

	_, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, models.CypherCreateCampaign, params)
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to create campaign node: %w", err)
	}

	return nil
}

// CreateThreatActor creates or updates a threat actor node
func (r *GraphRepository) CreateThreatActor(ctx context.Context, actor *models.ThreatActorNode) error {
	params := map[string]interface{}{
		"id":          actor.ID.String(),
		"name":        actor.Name,
		"aliases":     actor.Aliases,
		"description": actor.Description,
		"motivation":  actor.Motivation,
		"country":     actor.Country,
		"first_seen":  actor.FirstSeen.Unix(),
		"last_seen":   actor.LastSeen.Unix(),
		"is_active":   actor.IsActive,
	}

	_, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, models.CypherCreateActor, params)
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to create threat actor node: %w", err)
	}

	return nil
}

// LinkIndicatorToCampaign creates a relationship between an indicator and campaign
func (r *GraphRepository) LinkIndicatorToCampaign(ctx context.Context, indicatorID, campaignID uuid.UUID, confidence float64) error {
	params := map[string]interface{}{
		"indicator_id": indicatorID.String(),
		"campaign_id":  campaignID.String(),
		"confidence":   confidence,
		"first_seen":   time.Now().Unix(),
		"last_seen":    time.Now().Unix(),
	}

	_, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, models.CypherLinkIndicatorCampaign, params)
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to link indicator to campaign: %w", err)
	}

	return nil
}

// LinkIndicatorToActor creates a relationship between an indicator and threat actor
func (r *GraphRepository) LinkIndicatorToActor(ctx context.Context, indicatorID, actorID uuid.UUID, confidence float64) error {
	params := map[string]interface{}{
		"indicator_id": indicatorID.String(),
		"actor_id":     actorID.String(),
		"confidence":   confidence,
		"first_seen":   time.Now().Unix(),
	}

	_, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, models.CypherLinkIndicatorActor, params)
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to link indicator to actor: %w", err)
	}

	return nil
}

// LinkIndicators creates a relationship between two indicators
func (r *GraphRepository) LinkIndicators(ctx context.Context, source, target uuid.UUID, relType models.GraphRelationType, confidence float64) error {
	cypher := fmt.Sprintf(`
		MATCH (i1:Indicator {id: $source_id})
		MATCH (i2:Indicator {id: $target_id})
		MERGE (i1)-[r:%s]->(i2)
		SET r.confidence = $confidence,
			r.created_at = $created_at
		RETURN r`, relType)

	params := map[string]interface{}{
		"source_id":  source.String(),
		"target_id":  target.String(),
		"confidence": confidence,
		"created_at": time.Now().Unix(),
	}

	_, err := r.client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, cypher, params)
		return nil, err
	})

	return err
}

// FindRelatedIndicators finds indicators related to a given indicator
func (r *GraphRepository) FindRelatedIndicators(ctx context.Context, indicatorID uuid.UUID, maxDepth, limit int) ([]models.RelatedIndicator, error) {
	if maxDepth < 1 {
		maxDepth = 2
	}
	if limit < 1 {
		limit = 50
	}

	cypher := fmt.Sprintf(models.CypherFindRelated, maxDepth)
	params := map[string]interface{}{
		"id":    indicatorID.String(),
		"limit": limit,
	}

	result, err := r.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		records, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		var related []models.RelatedIndicator
		for records.Next(ctx) {
			record := records.Record()
			nodeVal, _ := record.Get("related")
			distVal, _ := record.Get("distance")

			if node, ok := nodeVal.(neo4j.Node); ok {
				indicator := nodeToIndicator(node)
				distance := 1
				if d, ok := distVal.(int64); ok {
					distance = int(d)
				}

				related = append(related, models.RelatedIndicator{
					Indicator:        indicator,
					RelationType:     models.RelRelatedTo,
					RelationStrength: 1.0 / float64(distance),
					PathLength:       distance,
				})
			}
		}

		return related, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to find related indicators: %w", err)
	}

	return result.([]models.RelatedIndicator), nil
}

// GetCorrelation returns full correlation data for an indicator
func (r *GraphRepository) GetCorrelation(ctx context.Context, indicatorID uuid.UUID) (*models.CorrelationResult, error) {
	params := map[string]interface{}{
		"id": indicatorID.String(),
	}

	result, err := r.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		records, err := tx.Run(ctx, models.CypherGetCorrelation, params)
		if err != nil {
			return nil, err
		}

		correlation := &models.CorrelationResult{
			ID:          uuid.New(),
			GeneratedAt: time.Now(),
		}

		if records.Next(ctx) {
			record := records.Record()

			// Extract primary indicator
			if iVal, _ := record.Get("i"); iVal != nil {
				if node, ok := iVal.(neo4j.Node); ok {
					indicator := nodeToIndicator(node)
					correlation.PrimaryIndicator = &indicator
				}
			}

			// Extract campaigns
			if cVal, _ := record.Get("campaigns"); cVal != nil {
				if campaigns, ok := cVal.([]interface{}); ok {
					for _, c := range campaigns {
						if node, ok := c.(neo4j.Node); ok {
							correlation.Campaigns = append(correlation.Campaigns, nodeToCampaign(node))
						}
					}
				}
			}

			// Extract threat actors
			if aVal, _ := record.Get("actors"); aVal != nil {
				if actors, ok := aVal.([]interface{}); ok {
					for _, a := range actors {
						if node, ok := a.(neo4j.Node); ok {
							correlation.ThreatActors = append(correlation.ThreatActors, nodeToActor(node))
						}
					}
				}
			}

			// Extract related indicators
			if rVal, _ := record.Get("related"); rVal != nil {
				if related, ok := rVal.([]interface{}); ok {
					for _, r := range related {
						if m, ok := r.(map[string]interface{}); ok {
							if indNode, ok := m["indicator"].(neo4j.Node); ok {
								relType := models.RelRelatedTo
								if rt, ok := m["type"].(string); ok {
									relType = models.GraphRelationType(rt)
								}
								correlation.RelatedIndicators = append(correlation.RelatedIndicators, models.RelatedIndicator{
									Indicator:    nodeToIndicator(indNode),
									RelationType: relType,
								})
							}
						}
					}
				}
			}
		}

		correlation.TotalRelations = len(correlation.RelatedIndicators) + len(correlation.Campaigns) + len(correlation.ThreatActors)
		correlation.CorrelationScore = calculateCorrelationScore(correlation)
		correlation.RiskScore = calculateRiskScore(correlation)

		return correlation, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get correlation: %w", err)
	}

	return result.(*models.CorrelationResult), nil
}

// FindSharedInfrastructure finds indicators sharing infrastructure
func (r *GraphRepository) FindSharedInfrastructure(ctx context.Context, limit int) (*models.InfrastructureOverlapResult, error) {
	if limit < 1 {
		limit = 100
	}

	result, err := r.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		records, err := tx.Run(ctx, models.CypherFindSharedInfra, map[string]interface{}{
			"limit": limit,
		})
		if err != nil {
			return nil, err
		}

		overlap := &models.InfrastructureOverlapResult{}
		asnMap := make(map[string]*models.ASNOverlap)

		for records.Next(ctx) {
			record := records.Record()
			infraVal, _ := record.Get("infra")

			if infraNode, ok := infraVal.(neo4j.Node); ok {
				props := infraNode.Props
				if asn, ok := props["asn"].(string); ok && asn != "" {
					if _, exists := asnMap[asn]; !exists {
						asnMap[asn] = &models.ASNOverlap{
							ASN:        asn,
							Indicators: make([]models.IndicatorNode, 0),
						}
					}
					// Add indicators...
				}
			}
		}

		for _, asnOverlap := range asnMap {
			asnOverlap.Count = len(asnOverlap.Indicators)
			overlap.SharedASN = append(overlap.SharedASN, *asnOverlap)
		}

		return overlap, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to find shared infrastructure: %w", err)
	}

	return result.(*models.InfrastructureOverlapResult), nil
}

// DetectCampaigns tries to detect new campaigns from indicator patterns
func (r *GraphRepository) DetectCampaigns(ctx context.Context, minSharedInfra, limit int) ([]models.CampaignDetection, error) {
	if minSharedInfra < 2 {
		minSharedInfra = 2
	}
	if limit < 1 {
		limit = 20
	}

	params := map[string]interface{}{
		"min_shared": minSharedInfra,
		"limit":      limit,
	}

	result, err := r.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		records, err := tx.Run(ctx, models.CypherDetectCampaigns, params)
		if err != nil {
			return nil, err
		}

		var detections []models.CampaignDetection
		for records.Next(ctx) {
			record := records.Record()

			detection := models.CampaignDetection{
				ProposedName: fmt.Sprintf("AutoDetected-%s", time.Now().Format("20060102-150405")),
				Indicators:   make([]models.IndicatorNode, 0),
				SharedInfra:  make([]string, 0),
				Confidence:   0.5, // Base confidence
			}

			// Extract indicators
			if i1Val, _ := record.Get("i1"); i1Val != nil {
				if node, ok := i1Val.(neo4j.Node); ok {
					detection.Indicators = append(detection.Indicators, nodeToIndicator(node))
				}
			}
			if i2Val, _ := record.Get("i2"); i2Val != nil {
				if node, ok := i2Val.(neo4j.Node); ok {
					detection.Indicators = append(detection.Indicators, nodeToIndicator(node))
				}
			}

			// Extract shared infrastructure
			if infraVal, _ := record.Get("shared_infra"); infraVal != nil {
				if infras, ok := infraVal.([]interface{}); ok {
					for _, inf := range infras {
						if node, ok := inf.(neo4j.Node); ok {
							if val, ok := node.Props["value"].(string); ok {
								detection.SharedInfra = append(detection.SharedInfra, val)
							}
						}
					}
				}
			}

			// Increase confidence based on shared infrastructure
			detection.Confidence += float64(len(detection.SharedInfra)) * 0.1
			if detection.Confidence > 1.0 {
				detection.Confidence = 1.0
			}

			detections = append(detections, detection)
		}

		return detections, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to detect campaigns: %w", err)
	}

	return result.([]models.CampaignDetection), nil
}

// GetStats returns graph statistics
func (r *GraphRepository) GetStats(ctx context.Context) (*models.GraphStats, error) {
	stats, err := r.client.Stats(ctx)
	if err != nil {
		return nil, err
	}

	return &models.GraphStats{
		TotalNodes:         stats["Indicator"] + stats["Campaign"] + stats["ThreatActor"] + stats["Infrastructure"],
		TotalRelationships: stats["relationships"],
		NodesByType: map[string]int64{
			"Indicator":      stats["Indicator"],
			"Campaign":       stats["Campaign"],
			"ThreatActor":    stats["ThreatActor"],
			"Infrastructure": stats["Infrastructure"],
			"MITREAttack":    stats["MITREAttack"],
		},
		LastUpdated: time.Now(),
	}, nil
}

// Traverse performs a graph traversal from a starting node
func (r *GraphRepository) Traverse(ctx context.Context, req *models.GraphTraversalRequest) (*models.GraphQueryResult, error) {
	if req.MaxDepth < 1 {
		req.MaxDepth = 3
	}
	if req.Limit < 1 {
		req.Limit = 100
	}

	direction := "-"
	if req.Direction == "outgoing" {
		direction = "->"
	} else if req.Direction == "incoming" {
		direction = "<-"
	}

	relFilter := ""
	if len(req.RelTypes) > 0 {
		relFilter = ":" + string(req.RelTypes[0])
		for i := 1; i < len(req.RelTypes); i++ {
			relFilter += "|" + string(req.RelTypes[i])
		}
	}

	// Build proper Cypher path pattern
	var cypher string
	if direction == "->" {
		cypher = fmt.Sprintf(`
		MATCH (start {id: $start_id})
		MATCH path = (start)-[r%s*1..%d]->(end)
		RETURN nodes(path) as nodes, relationships(path) as rels
		LIMIT $limit`, relFilter, req.MaxDepth)
	} else if direction == "<-" {
		cypher = fmt.Sprintf(`
		MATCH (start {id: $start_id})
		MATCH path = (start)<-[r%s*1..%d]-(end)
		RETURN nodes(path) as nodes, relationships(path) as rels
		LIMIT $limit`, relFilter, req.MaxDepth)
	} else {
		cypher = fmt.Sprintf(`
		MATCH (start {id: $start_id})
		MATCH path = (start)-[r%s*1..%d]-(end)
		RETURN nodes(path) as nodes, relationships(path) as rels
		LIMIT $limit`, relFilter, req.MaxDepth)
	}

	params := map[string]interface{}{
		"start_id": req.StartNodeID,
		"limit":    req.Limit,
	}

	startTime := time.Now()

	result, err := r.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		records, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		queryResult := &models.GraphQueryResult{
			Nodes:         make([]models.GraphNode, 0),
			Relationships: make([]models.GraphRelationship, 0),
		}

		nodesSeen := make(map[string]bool)
		relsSeen := make(map[string]bool)

		for records.Next(ctx) {
			record := records.Record()

			// Extract nodes
			if nodesVal, _ := record.Get("nodes"); nodesVal != nil {
				if nodes, ok := nodesVal.([]interface{}); ok {
					for _, n := range nodes {
						if node, ok := n.(neo4j.Node); ok {
							if !nodesSeen[node.ElementId] {
								nodesSeen[node.ElementId] = true
								queryResult.Nodes = append(queryResult.Nodes, neo4jNodeToGraphNode(node))
							}
						}
					}
				}
			}

			// Extract relationships
			if relsVal, _ := record.Get("rels"); relsVal != nil {
				if rels, ok := relsVal.([]interface{}); ok {
					for _, r := range rels {
						if rel, ok := r.(neo4j.Relationship); ok {
							if !relsSeen[rel.ElementId] {
								relsSeen[rel.ElementId] = true
								queryResult.Relationships = append(queryResult.Relationships, neo4jRelToGraphRel(rel))
							}
						}
					}
				}
			}
		}

		queryResult.TotalNodes = len(queryResult.Nodes)
		queryResult.TotalRelations = len(queryResult.Relationships)

		return queryResult, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to traverse graph: %w", err)
	}

	queryResult := result.(*models.GraphQueryResult)
	queryResult.QueryTime = time.Since(startTime)

	return queryResult, nil
}

// Helper functions

func nodeToIndicator(node neo4j.Node) models.IndicatorNode {
	props := node.Props
	indicator := models.IndicatorNode{}

	if id, ok := props["id"].(string); ok {
		indicator.ID, _ = uuid.Parse(id)
	}
	if t, ok := props["type"].(string); ok {
		indicator.Type = models.IndicatorType(t)
	}
	if v, ok := props["value"].(string); ok {
		indicator.Value = v
	}
	if s, ok := props["severity"].(string); ok {
		indicator.Severity = models.Severity(s)
	}
	if c, ok := props["confidence"].(float64); ok {
		indicator.Confidence = c
	}
	if fs, ok := props["first_seen"].(int64); ok {
		indicator.FirstSeen = time.Unix(fs, 0)
	}
	if ls, ok := props["last_seen"].(int64); ok {
		indicator.LastSeen = time.Unix(ls, 0)
	}
	if tags, ok := props["tags"].([]interface{}); ok {
		for _, t := range tags {
			if tag, ok := t.(string); ok {
				indicator.Tags = append(indicator.Tags, tag)
			}
		}
	}
	if src, ok := props["source"].(string); ok {
		indicator.Source = src
	}

	return indicator
}

func nodeToCampaign(node neo4j.Node) models.CampaignNode {
	props := node.Props
	campaign := models.CampaignNode{}

	if id, ok := props["id"].(string); ok {
		campaign.ID, _ = uuid.Parse(id)
	}
	if slug, ok := props["slug"].(string); ok {
		campaign.Slug = slug
	}
	if name, ok := props["name"].(string); ok {
		campaign.Name = name
	}
	if desc, ok := props["description"].(string); ok {
		campaign.Description = desc
	}
	if mf, ok := props["malware_family"].(string); ok {
		campaign.MalwareFamily = mf
	}
	if fs, ok := props["first_seen"].(int64); ok {
		campaign.FirstSeen = time.Unix(fs, 0)
	}
	if ls, ok := props["last_seen"].(int64); ok {
		campaign.LastSeen = time.Unix(ls, 0)
	}
	if active, ok := props["is_active"].(bool); ok {
		campaign.IsActive = active
	}

	return campaign
}

func nodeToActor(node neo4j.Node) models.ThreatActorNode {
	props := node.Props
	actor := models.ThreatActorNode{}

	if id, ok := props["id"].(string); ok {
		actor.ID, _ = uuid.Parse(id)
	}
	if name, ok := props["name"].(string); ok {
		actor.Name = name
	}
	if desc, ok := props["description"].(string); ok {
		actor.Description = desc
	}
	if motivation, ok := props["motivation"].(string); ok {
		actor.Motivation = motivation
	}
	if country, ok := props["country"].(string); ok {
		actor.Country = country
	}
	if aliases, ok := props["aliases"].([]interface{}); ok {
		for _, a := range aliases {
			if alias, ok := a.(string); ok {
				actor.Aliases = append(actor.Aliases, alias)
			}
		}
	}
	if fs, ok := props["first_seen"].(int64); ok {
		actor.FirstSeen = time.Unix(fs, 0)
	}
	if ls, ok := props["last_seen"].(int64); ok {
		actor.LastSeen = time.Unix(ls, 0)
	}
	if active, ok := props["is_active"].(bool); ok {
		actor.IsActive = active
	}

	return actor
}

func neo4jNodeToGraphNode(node neo4j.Node) models.GraphNode {
	props := make(map[string]interface{})
	for k, v := range node.Props {
		props[k] = v
	}

	return models.GraphNode{
		ID:         node.ElementId,
		Labels:     node.Labels,
		Properties: props,
	}
}

func neo4jRelToGraphRel(rel neo4j.Relationship) models.GraphRelationship {
	props := make(map[string]interface{})
	for k, v := range rel.Props {
		props[k] = v
	}

	confidence := 1.0
	if c, ok := props["confidence"].(float64); ok {
		confidence = c
	}

	return models.GraphRelationship{
		ID:         rel.ElementId,
		Type:       models.GraphRelationType(rel.Type),
		SourceID:   rel.StartElementId,
		TargetID:   rel.EndElementId,
		Properties: props,
		Confidence: confidence,
	}
}

func calculateCorrelationScore(correlation *models.CorrelationResult) float64 {
	score := 0.0

	// More campaigns = higher correlation
	score += float64(len(correlation.Campaigns)) * 0.2

	// More actors = higher correlation
	score += float64(len(correlation.ThreatActors)) * 0.3

	// More related indicators = higher correlation
	score += float64(len(correlation.RelatedIndicators)) * 0.05

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func calculateRiskScore(correlation *models.CorrelationResult) float64 {
	score := 0.0

	if correlation.PrimaryIndicator != nil {
		// Base score from indicator severity
		switch correlation.PrimaryIndicator.Severity {
		case models.SeverityCritical:
			score = 0.9
		case models.SeverityHigh:
			score = 0.7
		case models.SeverityMedium:
			score = 0.5
		case models.SeverityLow:
			score = 0.3
		default:
			score = 0.1
		}

		// Increase if linked to known actors
		if len(correlation.ThreatActors) > 0 {
			score += 0.1
		}

		// Increase if part of active campaign
		for _, c := range correlation.Campaigns {
			if c.IsActive {
				score += 0.05
			}
		}
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}
