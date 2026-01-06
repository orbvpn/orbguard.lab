package models

import (
	"time"

	"github.com/google/uuid"
)

// GraphNodeType represents types of nodes in the threat graph
type GraphNodeType string

const (
	GraphNodeIndicator   GraphNodeType = "Indicator"
	GraphNodeCampaign    GraphNodeType = "Campaign"
	GraphNodeThreatActor GraphNodeType = "ThreatActor"
	GraphNodeMalware     GraphNodeType = "Malware"
	GraphNodeTool        GraphNodeType = "Tool"
	GraphNodeVulnerability GraphNodeType = "Vulnerability"
	GraphNodeTactic      GraphNodeType = "Tactic"
	GraphNodeTechnique   GraphNodeType = "Technique"
	GraphNodeInfrastructure GraphNodeType = "Infrastructure"
	GraphNodeVictim      GraphNodeType = "Victim"
	GraphNodeLocation    GraphNodeType = "Location"
	GraphNodeASN         GraphNodeType = "ASN"
	GraphNodeRegistrar   GraphNodeType = "Registrar"
)

// GraphRelationType represents types of relationships in the threat graph
type GraphRelationType string

const (
	// Indicator relationships
	RelIndicatesTarget    GraphRelationType = "INDICATES"
	RelAttributedTo       GraphRelationType = "ATTRIBUTED_TO"
	RelPartOf             GraphRelationType = "PART_OF"
	RelUsedBy             GraphRelationType = "USED_BY"
	RelDelivers           GraphRelationType = "DELIVERS"
	RelCommunicatesWith   GraphRelationType = "COMMUNICATES_WITH"
	RelResolves           GraphRelationType = "RESOLVES"
	RelHostedOn           GraphRelationType = "HOSTED_ON"
	RelRegisteredWith     GraphRelationType = "REGISTERED_WITH"
	RelLocatedIn          GraphRelationType = "LOCATED_IN"
	RelSimilarTo          GraphRelationType = "SIMILAR_TO"
	RelRelatedTo          GraphRelationType = "RELATED_TO"
	RelMitigates          GraphRelationType = "MITIGATES"
	RelTargets            GraphRelationType = "TARGETS"
	RelExploits           GraphRelationType = "EXPLOITS"
	RelUsesTechnique      GraphRelationType = "USES_TECHNIQUE"
	RelSubTechniqueOf     GraphRelationType = "SUB_TECHNIQUE_OF"
	RelBelongsToTactic    GraphRelationType = "BELONGS_TO_TACTIC"
	RelSharedInfra        GraphRelationType = "SHARES_INFRASTRUCTURE"
	RelCoOccurs           GraphRelationType = "CO_OCCURS"
)

// GraphNode represents a node in the threat graph
type GraphNode struct {
	ID         string                 `json:"id"`
	Type       GraphNodeType          `json:"type"`
	Labels     []string               `json:"labels"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// GraphRelationship represents a relationship between nodes
type GraphRelationship struct {
	ID         string                 `json:"id"`
	Type       GraphRelationType      `json:"type"`
	SourceID   string                 `json:"source_id"`
	TargetID   string                 `json:"target_id"`
	Properties map[string]interface{} `json:"properties"`
	Confidence float64                `json:"confidence"`
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
}

// IndicatorNode represents an indicator in the graph
type IndicatorNode struct {
	ID        uuid.UUID     `json:"id"`
	Type      IndicatorType `json:"type"`
	Value     string        `json:"value"`
	Severity  Severity      `json:"severity"`
	Confidence float64      `json:"confidence"`
	FirstSeen time.Time     `json:"first_seen"`
	LastSeen  time.Time     `json:"last_seen"`
	Tags      []string      `json:"tags"`
	Source    string        `json:"source"`
}

// CampaignNode represents a campaign in the graph
type CampaignNode struct {
	ID            uuid.UUID `json:"id"`
	Slug          string    `json:"slug"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	MalwareFamily string    `json:"malware_family,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	IsActive      bool      `json:"is_active"`
}

// ThreatActorNode represents a threat actor in the graph
type ThreatActorNode struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Aliases     []string           `json:"aliases,omitempty"`
	Description string             `json:"description,omitempty"`
	Motivation  string             `json:"motivation,omitempty"`
	Sophistication string          `json:"sophistication,omitempty"`
	Country     string             `json:"country,omitempty"`
	FirstSeen   time.Time          `json:"first_seen"`
	LastSeen    time.Time          `json:"last_seen"`
	IsActive    bool               `json:"is_active"`
}

// InfrastructureNode represents infrastructure in the graph (IP, domain hosting)
type InfrastructureNode struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // ip, domain, url
	Value     string    `json:"value"`
	ASN       string    `json:"asn,omitempty"`
	Country   string    `json:"country,omitempty"`
	Registrar string    `json:"registrar,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// MITREAttackNode represents a MITRE ATT&CK technique/tactic
type MITREAttackNode struct {
	ID          string   `json:"id"`          // e.g., T1566
	Name        string   `json:"name"`        // e.g., Phishing
	Type        string   `json:"type"`        // tactic, technique, sub-technique
	Description string   `json:"description,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	ParentID    string   `json:"parent_id,omitempty"` // For sub-techniques
	TacticIDs   []string `json:"tactic_ids,omitempty"`
}

// GraphPath represents a path through the graph
type GraphPath struct {
	Nodes         []GraphNode         `json:"nodes"`
	Relationships []GraphRelationship `json:"relationships"`
	Length        int                 `json:"length"`
}

// GraphQueryResult represents the result of a graph query
type GraphQueryResult struct {
	Nodes         []GraphNode         `json:"nodes"`
	Relationships []GraphRelationship `json:"relationships"`
	TotalNodes    int                 `json:"total_nodes"`
	TotalRelations int                `json:"total_relations"`
	QueryTime     time.Duration       `json:"query_time"`
}

// CorrelationResult represents correlated threat data
type CorrelationResult struct {
	ID                uuid.UUID                 `json:"id"`
	PrimaryIndicator  *IndicatorNode            `json:"primary_indicator"`
	RelatedIndicators []RelatedIndicator        `json:"related_indicators"`
	Campaigns         []CampaignNode            `json:"campaigns"`
	ThreatActors      []ThreatActorNode         `json:"threat_actors"`
	Infrastructure    []InfrastructureNode      `json:"infrastructure"`
	MITRETechniques   []MITREAttackNode         `json:"mitre_techniques,omitempty"`
	TotalRelations    int                       `json:"total_relations"`
	RiskScore         float64                   `json:"risk_score"`
	CorrelationScore  float64                   `json:"correlation_score"`
	GeneratedAt       time.Time                 `json:"generated_at"`
}

// RelatedIndicator represents a related indicator with relationship info
type RelatedIndicator struct {
	Indicator        IndicatorNode     `json:"indicator"`
	RelationType     GraphRelationType `json:"relation_type"`
	RelationStrength float64           `json:"relation_strength"`
	PathLength       int               `json:"path_length"`
}

// InfrastructureOverlapResult represents shared infrastructure detection
type InfrastructureOverlapResult struct {
	SharedASN       []ASNOverlap       `json:"shared_asn,omitempty"`
	SharedRegistrar []RegistrarOverlap `json:"shared_registrar,omitempty"`
	SharedIPRange   []IPRangeOverlap   `json:"shared_ip_range,omitempty"`
	SimilarDomains  []DomainSimilarity `json:"similar_domains,omitempty"`
}

// ASNOverlap represents shared ASN between indicators
type ASNOverlap struct {
	ASN        string          `json:"asn"`
	ASNName    string          `json:"asn_name,omitempty"`
	Indicators []IndicatorNode `json:"indicators"`
	Campaigns  []string        `json:"campaigns,omitempty"`
	Count      int             `json:"count"`
}

// RegistrarOverlap represents shared registrar between domains
type RegistrarOverlap struct {
	Registrar  string          `json:"registrar"`
	Indicators []IndicatorNode `json:"indicators"`
	Count      int             `json:"count"`
}

// IPRangeOverlap represents shared IP range
type IPRangeOverlap struct {
	CIDR       string          `json:"cidr"`
	Indicators []IndicatorNode `json:"indicators"`
	Count      int             `json:"count"`
}

// DomainSimilarity represents similar domain patterns
type DomainSimilarity struct {
	Pattern    string          `json:"pattern"`
	Domains    []string        `json:"domains"`
	Similarity float64         `json:"similarity"`
	Campaign   string          `json:"campaign,omitempty"`
}

// TemporalCorrelation represents time-based correlation
type TemporalCorrelation struct {
	TimeWindow  time.Duration   `json:"time_window"`
	Indicators  []IndicatorNode `json:"indicators"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	ActivitySpikes []ActivitySpike `json:"activity_spikes,omitempty"`
}

// ActivitySpike represents a spike in activity
type ActivitySpike struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
	Severity  Severity  `json:"severity"`
}

// TTPSimilarity represents TTP (Tactics, Techniques, Procedures) similarity
type TTPSimilarity struct {
	Actor1        string   `json:"actor1"`
	Actor2        string   `json:"actor2"`
	SharedTactics []string `json:"shared_tactics"`
	SharedTechniques []string `json:"shared_techniques"`
	Similarity    float64  `json:"similarity"`
}

// CampaignDetection represents auto-detected campaign grouping
type CampaignDetection struct {
	ProposedName    string            `json:"proposed_name"`
	Indicators      []IndicatorNode   `json:"indicators"`
	CommonPatterns  []string          `json:"common_patterns"`
	SharedInfra     []string          `json:"shared_infrastructure"`
	TimeRange       TimeRange         `json:"time_range"`
	Confidence      float64           `json:"confidence"`
	SuggestedActor  string            `json:"suggested_actor,omitempty"`
}

// RelationshipBuildResult represents the result of auto-building relationships
type RelationshipBuildResult struct {
	TotalCreated         int           `json:"total_created"`
	TagRelationships     int           `json:"tag_relationships"`
	SourceRelationships  int           `json:"source_relationships"`
	TemporalRelationships int          `json:"temporal_relationships"`
	StartedAt            time.Time     `json:"started_at"`
	CompletedAt          time.Time     `json:"completed_at"`
	Duration             time.Duration `json:"duration"`
	Errors               []string      `json:"errors,omitempty"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// GraphStats represents graph statistics
type GraphStats struct {
	TotalNodes        int64            `json:"total_nodes"`
	TotalRelationships int64           `json:"total_relationships"`
	NodesByType       map[string]int64 `json:"nodes_by_type"`
	RelationsByType   map[string]int64 `json:"relations_by_type"`
	AverageConnections float64         `json:"average_connections"`
	MostConnectedNodes []NodeConnection `json:"most_connected_nodes"`
	LastUpdated       time.Time        `json:"last_updated"`
}

// NodeConnection represents a node's connection count
type NodeConnection struct {
	NodeID      string        `json:"node_id"`
	NodeType    GraphNodeType `json:"node_type"`
	Label       string        `json:"label"`
	Connections int           `json:"connections"`
}

// GraphSearchRequest represents a graph search request
type GraphSearchRequest struct {
	Query       string            `json:"query,omitempty"`
	NodeTypes   []GraphNodeType   `json:"node_types,omitempty"`
	RelTypes    []GraphRelationType `json:"relation_types,omitempty"`
	Severity    *Severity         `json:"severity,omitempty"`
	TimeRange   *TimeRange        `json:"time_range,omitempty"`
	Limit       int               `json:"limit,omitempty"`
	MaxDepth    int               `json:"max_depth,omitempty"`
}

// GraphTraversalRequest represents a graph traversal request
type GraphTraversalRequest struct {
	StartNodeID   string              `json:"start_node_id"`
	Direction     string              `json:"direction"` // outgoing, incoming, both
	RelTypes      []GraphRelationType `json:"relation_types,omitempty"`
	MaxDepth      int                 `json:"max_depth,omitempty"`
	Limit         int                 `json:"limit,omitempty"`
	IncludeNodes  []GraphNodeType     `json:"include_nodes,omitempty"`
	ExcludeNodes  []GraphNodeType     `json:"exclude_nodes,omitempty"`
}

// Neo4j Cypher query templates
const (
	// Create indicator node
	CypherCreateIndicator = `
		MERGE (i:Indicator {id: $id})
		SET i.type = $type,
			i.value = $value,
			i.severity = $severity,
			i.confidence = $confidence,
			i.first_seen = $first_seen,
			i.last_seen = $last_seen,
			i.tags = $tags,
			i.source = $source
		RETURN i`

	// Create campaign node
	CypherCreateCampaign = `
		MERGE (c:Campaign {id: $id})
		SET c.slug = $slug,
			c.name = $name,
			c.description = $description,
			c.malware_family = $malware_family,
			c.first_seen = $first_seen,
			c.last_seen = $last_seen,
			c.is_active = $is_active
		RETURN c`

	// Create threat actor node
	CypherCreateActor = `
		MERGE (a:ThreatActor {id: $id})
		SET a.name = $name,
			a.aliases = $aliases,
			a.description = $description,
			a.motivation = $motivation,
			a.country = $country,
			a.first_seen = $first_seen,
			a.last_seen = $last_seen,
			a.is_active = $is_active
		RETURN a`

	// Link indicator to campaign
	CypherLinkIndicatorCampaign = `
		MATCH (i:Indicator {id: $indicator_id})
		MATCH (c:Campaign {id: $campaign_id})
		MERGE (i)-[r:PART_OF]->(c)
		SET r.confidence = $confidence,
			r.first_seen = $first_seen,
			r.last_seen = $last_seen
		RETURN r`

	// Link indicator to threat actor
	CypherLinkIndicatorActor = `
		MATCH (i:Indicator {id: $indicator_id})
		MATCH (a:ThreatActor {id: $actor_id})
		MERGE (i)-[r:ATTRIBUTED_TO]->(a)
		SET r.confidence = $confidence,
			r.first_seen = $first_seen
		RETURN r`

	// Find related indicators
	CypherFindRelated = `
		MATCH path = (i:Indicator {id: $id})-[*1..%d]-(related:Indicator)
		WHERE i <> related
		RETURN DISTINCT related, length(path) as distance
		ORDER BY distance
		LIMIT $limit`

	// Find shared infrastructure
	CypherFindSharedInfra = `
		MATCH (i1:Indicator)-[:HOSTED_ON|RESOLVES]->(infra)<-[:HOSTED_ON|RESOLVES]-(i2:Indicator)
		WHERE i1 <> i2
		RETURN i1, infra, i2, count(*) as overlap
		ORDER BY overlap DESC
		LIMIT $limit`

	// Get correlation for indicator
	CypherGetCorrelation = `
		MATCH (i:Indicator {id: $id})
		OPTIONAL MATCH (i)-[:PART_OF]->(c:Campaign)
		OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(a:ThreatActor)
		OPTIONAL MATCH (i)-[r]-(related:Indicator)
		RETURN i, collect(DISTINCT c) as campaigns,
			   collect(DISTINCT a) as actors,
			   collect(DISTINCT {indicator: related, type: type(r)}) as related`

	// Detect potential campaigns
	CypherDetectCampaigns = `
		MATCH (i1:Indicator)-[:HOSTED_ON|RESOLVES]->(infra)<-[:HOSTED_ON|RESOLVES]-(i2:Indicator)
		WHERE i1 <> i2 AND NOT (i1)-[:PART_OF]->(:Campaign)
		WITH i1, i2, collect(infra) as shared_infra
		WHERE size(shared_infra) >= $min_shared
		RETURN i1, i2, shared_infra
		LIMIT $limit`
)
