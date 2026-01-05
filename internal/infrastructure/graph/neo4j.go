package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"orbguard-lab/internal/config"
	"orbguard-lab/pkg/logger"
)

// Neo4jClient wraps the Neo4j driver
type Neo4jClient struct {
	driver  neo4j.DriverWithContext
	config  config.Neo4jConfig
	logger  *logger.Logger
}

// NewNeo4jClient creates a new Neo4j client
func NewNeo4jClient(ctx context.Context, cfg config.Neo4jConfig, log *logger.Logger) (*Neo4jClient, error) {
	auth := neo4j.BasicAuth(cfg.Username, cfg.Password, "")

	driver, err := neo4j.NewDriverWithContext(cfg.URI, auth, func(c *neo4j.Config) {
		c.MaxConnectionPoolSize = cfg.MaxConnections
		c.MaxConnectionLifetime = time.Duration(cfg.MaxLifetimeMinutes) * time.Minute
		c.ConnectionAcquisitionTimeout = 30 * time.Second
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	// Verify connectivity
	if err := driver.VerifyConnectivity(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	client := &Neo4jClient{
		driver: driver,
		config: cfg,
		logger: log.WithComponent("neo4j"),
	}

	// Initialize schema/indexes
	if err := client.initializeSchema(ctx); err != nil {
		log.Warn().Err(err).Msg("failed to initialize Neo4j schema")
	}

	log.Info().
		Str("uri", cfg.URI).
		Msg("connected to Neo4j")

	return client, nil
}

// Close closes the Neo4j driver
func (c *Neo4jClient) Close(ctx context.Context) error {
	return c.driver.Close(ctx)
}

// Session creates a new session
func (c *Neo4jClient) Session(ctx context.Context, mode neo4j.SessionConfig) neo4j.SessionWithContext {
	return c.driver.NewSession(ctx, mode)
}

// ReadSession creates a read-only session
func (c *Neo4jClient) ReadSession(ctx context.Context) neo4j.SessionWithContext {
	return c.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeRead,
		DatabaseName: c.config.Database,
	})
}

// WriteSession creates a read-write session
func (c *Neo4jClient) WriteSession(ctx context.Context) neo4j.SessionWithContext {
	return c.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeWrite,
		DatabaseName: c.config.Database,
	})
}

// ExecuteWrite executes a write transaction
func (c *Neo4jClient) ExecuteWrite(ctx context.Context, work func(tx neo4j.ManagedTransaction) (interface{}, error)) (interface{}, error) {
	session := c.WriteSession(ctx)
	defer session.Close(ctx)

	return session.ExecuteWrite(ctx, work)
}

// ExecuteRead executes a read transaction
func (c *Neo4jClient) ExecuteRead(ctx context.Context, work func(tx neo4j.ManagedTransaction) (interface{}, error)) (interface{}, error) {
	session := c.ReadSession(ctx)
	defer session.Close(ctx)

	return session.ExecuteRead(ctx, work)
}

// Run executes a Cypher query (auto-commit transaction)
func (c *Neo4jClient) Run(ctx context.Context, cypher string, params map[string]interface{}) (neo4j.ResultWithContext, error) {
	session := c.WriteSession(ctx)
	defer session.Close(ctx)

	return session.Run(ctx, cypher, params)
}

// RunRead executes a read-only Cypher query
func (c *Neo4jClient) RunRead(ctx context.Context, cypher string, params map[string]interface{}) (neo4j.ResultWithContext, error) {
	session := c.ReadSession(ctx)
	defer session.Close(ctx)

	return session.Run(ctx, cypher, params)
}

// initializeSchema creates indexes and constraints
func (c *Neo4jClient) initializeSchema(ctx context.Context) error {
	session := c.WriteSession(ctx)
	defer session.Close(ctx)

	// Create indexes for faster lookups
	indexes := []string{
		// Indicator indexes
		"CREATE INDEX indicator_id IF NOT EXISTS FOR (i:Indicator) ON (i.id)",
		"CREATE INDEX indicator_value IF NOT EXISTS FOR (i:Indicator) ON (i.value)",
		"CREATE INDEX indicator_type IF NOT EXISTS FOR (i:Indicator) ON (i.type)",
		"CREATE INDEX indicator_severity IF NOT EXISTS FOR (i:Indicator) ON (i.severity)",

		// Campaign indexes
		"CREATE INDEX campaign_id IF NOT EXISTS FOR (c:Campaign) ON (c.id)",
		"CREATE INDEX campaign_slug IF NOT EXISTS FOR (c:Campaign) ON (c.slug)",
		"CREATE INDEX campaign_name IF NOT EXISTS FOR (c:Campaign) ON (c.name)",

		// ThreatActor indexes
		"CREATE INDEX actor_id IF NOT EXISTS FOR (a:ThreatActor) ON (a.id)",
		"CREATE INDEX actor_name IF NOT EXISTS FOR (a:ThreatActor) ON (a.name)",

		// Infrastructure indexes
		"CREATE INDEX infra_id IF NOT EXISTS FOR (inf:Infrastructure) ON (inf.id)",
		"CREATE INDEX infra_value IF NOT EXISTS FOR (inf:Infrastructure) ON (inf.value)",
		"CREATE INDEX infra_asn IF NOT EXISTS FOR (inf:Infrastructure) ON (inf.asn)",

		// MITRE ATT&CK indexes
		"CREATE INDEX mitre_id IF NOT EXISTS FOR (m:MITREAttack) ON (m.id)",

		// Full-text search indexes
		"CREATE FULLTEXT INDEX indicator_search IF NOT EXISTS FOR (i:Indicator) ON EACH [i.value, i.tags]",
		"CREATE FULLTEXT INDEX campaign_search IF NOT EXISTS FOR (c:Campaign) ON EACH [c.name, c.description]",
		"CREATE FULLTEXT INDEX actor_search IF NOT EXISTS FOR (a:ThreatActor) ON EACH [a.name, a.aliases, a.description]",
	}

	for _, idx := range indexes {
		_, err := session.Run(ctx, idx, nil)
		if err != nil {
			c.logger.Warn().Err(err).Str("index", idx).Msg("failed to create index")
		}
	}

	c.logger.Info().Msg("Neo4j schema initialized")
	return nil
}

// Health checks Neo4j connectivity
func (c *Neo4jClient) Health(ctx context.Context) error {
	return c.driver.VerifyConnectivity(ctx)
}

// Stats returns basic database statistics
func (c *Neo4jClient) Stats(ctx context.Context) (map[string]int64, error) {
	stats := make(map[string]int64)

	session := c.ReadSession(ctx)
	defer session.Close(ctx)

	// Count nodes by label
	nodeLabels := []string{"Indicator", "Campaign", "ThreatActor", "Infrastructure", "MITREAttack"}
	for _, label := range nodeLabels {
		result, err := session.Run(ctx, fmt.Sprintf("MATCH (n:%s) RETURN count(n) as count", label), nil)
		if err != nil {
			continue
		}
		if result.Next(ctx) {
			count, _ := result.Record().Get("count")
			if c, ok := count.(int64); ok {
				stats[label] = c
			}
		}
	}

	// Count relationships
	result, err := session.Run(ctx, "MATCH ()-[r]->() RETURN count(r) as count", nil)
	if err == nil && result.Next(ctx) {
		count, _ := result.Record().Get("count")
		if c, ok := count.(int64); ok {
			stats["relationships"] = c
		}
	}

	return stats, nil
}

// ClearDatabase clears all data (use with caution!)
func (c *Neo4jClient) ClearDatabase(ctx context.Context) error {
	session := c.WriteSession(ctx)
	defer session.Close(ctx)

	_, err := session.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
	if err != nil {
		return fmt.Errorf("failed to clear database: %w", err)
	}

	c.logger.Warn().Msg("Neo4j database cleared")
	return nil
}

// BatchCreate creates multiple nodes in a batch
func (c *Neo4jClient) BatchCreate(ctx context.Context, cypher string, batchParams []map[string]interface{}) error {
	session := c.WriteSession(ctx)
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		for _, params := range batchParams {
			_, err := tx.Run(ctx, cypher, params)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})

	return err
}

// RecordToMap converts a Neo4j record to a map
func RecordToMap(record *neo4j.Record) map[string]interface{} {
	result := make(map[string]interface{})
	for _, key := range record.Keys {
		val, _ := record.Get(key)
		result[key] = val
	}
	return result
}

// NodeToMap converts a Neo4j node to a map
func NodeToMap(node neo4j.Node) map[string]interface{} {
	result := make(map[string]interface{})
	result["id"] = node.ElementId
	result["labels"] = node.Labels
	for k, v := range node.Props {
		result[k] = v
	}
	return result
}

// RelationshipToMap converts a Neo4j relationship to a map
func RelationshipToMap(rel neo4j.Relationship) map[string]interface{} {
	result := make(map[string]interface{})
	result["id"] = rel.ElementId
	result["type"] = rel.Type
	result["start"] = rel.StartElementId
	result["end"] = rel.EndElementId
	for k, v := range rel.Props {
		result[k] = v
	}
	return result
}
