package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"orbguard-lab/internal/domain/models"
)

// CampaignRepository handles campaign persistence
type CampaignRepository struct {
	pool *pgxpool.Pool
}

// NewCampaignRepository creates a new campaign repository
func NewCampaignRepository(pool *pgxpool.Pool) *CampaignRepository {
	return &CampaignRepository{pool: pool}
}

// Create inserts a new campaign
func (r *CampaignRepository) Create(ctx context.Context, c *models.Campaign) (*models.Campaign, error) {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now

	// Determine status from IsActive flag
	status := c.Status
	if status == "" {
		if c.IsActive {
			status = "active"
		} else {
			status = "inactive"
		}
	}

	query := `
		INSERT INTO campaigns (
			id, slug, name, description, status, threat_actor_id,
			target_sectors, target_regions, target_platforms,
			mitre_tactics, mitre_techniques, first_seen, last_seen,
			indicator_count, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		) RETURNING id, created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		c.ID, c.Slug, c.Name, c.Description, status, c.ThreatActorID,
		c.TargetSectors, c.TargetRegions, platformsToStrings(c.TargetPlatforms),
		c.MitreTactics, c.MitreTechniques, c.FirstSeen, c.LastSeen,
		c.IndicatorCount, c.CreatedAt, c.UpdatedAt,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create campaign: %w", err)
	}

	return c, nil
}

// GetByID retrieves a campaign by ID
func (r *CampaignRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Campaign, error) {
	query := `
		SELECT c.id, c.slug, c.name, c.description, c.status, c.threat_actor_id,
			   c.target_sectors, c.target_regions, c.target_platforms::text[],
			   c.mitre_tactics, c.mitre_techniques, c.first_seen, c.last_seen,
			   c.indicator_count, c.status = 'active' as is_active, c.created_at, c.updated_at,
			   ta.name as threat_actor_name
		FROM campaigns c
		LEFT JOIN threat_actors ta ON c.threat_actor_id = ta.id
		WHERE c.id = $1`

	return r.scanCampaign(r.pool.QueryRow(ctx, query, id))
}

// GetBySlug retrieves a campaign by its slug
func (r *CampaignRepository) GetBySlug(ctx context.Context, slug string) (*models.Campaign, error) {
	query := `
		SELECT c.id, c.slug, c.name, c.description, c.status, c.threat_actor_id,
			   c.target_sectors, c.target_regions, c.target_platforms::text[],
			   c.mitre_tactics, c.mitre_techniques, c.first_seen, c.last_seen,
			   c.indicator_count, c.status = 'active' as is_active, c.created_at, c.updated_at,
			   ta.name as threat_actor_name
		FROM campaigns c
		LEFT JOIN threat_actors ta ON c.threat_actor_id = ta.id
		WHERE c.slug = $1`

	return r.scanCampaign(r.pool.QueryRow(ctx, query, slug))
}

// List retrieves all campaigns with optional filtering
func (r *CampaignRepository) List(ctx context.Context, activeOnly bool, limit, offset int) ([]*models.Campaign, int64, error) {
	// Count query
	countQuery := "SELECT COUNT(*) FROM campaigns"
	if activeOnly {
		countQuery += " WHERE status = 'active'"
	}

	var total int64
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count campaigns: %w", err)
	}

	// List query
	query := `
		SELECT c.id, c.slug, c.name, c.description, c.status, c.threat_actor_id,
			   c.target_sectors, c.target_regions, c.target_platforms::text[],
			   c.mitre_tactics, c.mitre_techniques, c.first_seen, c.last_seen,
			   c.indicator_count, c.status = 'active' as is_active, c.created_at, c.updated_at,
			   ta.name as threat_actor_name
		FROM campaigns c
		LEFT JOIN threat_actors ta ON c.threat_actor_id = ta.id`

	if activeOnly {
		query += " WHERE c.status = 'active'"
	}
	query += " ORDER BY c.last_seen DESC NULLS LAST, c.name"

	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list campaigns: %w", err)
	}
	defer rows.Close()

	var campaigns []*models.Campaign
	for rows.Next() {
		c, err := r.scanCampaignFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		campaigns = append(campaigns, c)
	}

	return campaigns, total, nil
}

// ListByThreatActor retrieves campaigns for a specific threat actor
func (r *CampaignRepository) ListByThreatActor(ctx context.Context, actorID uuid.UUID) ([]*models.Campaign, error) {
	query := `
		SELECT c.id, c.slug, c.name, c.description, c.status, c.threat_actor_id,
			   c.target_sectors, c.target_regions, c.target_platforms::text[],
			   c.mitre_tactics, c.mitre_techniques, c.first_seen, c.last_seen,
			   c.indicator_count, c.status = 'active' as is_active, c.created_at, c.updated_at,
			   ta.name as threat_actor_name
		FROM campaigns c
		LEFT JOIN threat_actors ta ON c.threat_actor_id = ta.id
		WHERE c.threat_actor_id = $1
		ORDER BY c.last_seen DESC NULLS LAST`

	rows, err := r.pool.Query(ctx, query, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to list campaigns by actor: %w", err)
	}
	defer rows.Close()

	var campaigns []*models.Campaign
	for rows.Next() {
		c, err := r.scanCampaignFromRows(rows)
		if err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}

	return campaigns, nil
}

// Update updates a campaign
func (r *CampaignRepository) Update(ctx context.Context, c *models.Campaign) error {
	c.UpdatedAt = time.Now()

	// Derive status from IsActive if not set
	status := c.Status
	if status == "" {
		if c.IsActive {
			status = "active"
		} else {
			status = "inactive"
		}
	}

	query := `
		UPDATE campaigns SET
			name = $2, description = $3, status = $4, threat_actor_id = $5,
			target_sectors = $6, target_regions = $7, target_platforms = $8,
			mitre_tactics = $9, mitre_techniques = $10, first_seen = $11, last_seen = $12,
			indicator_count = $13, updated_at = $14
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query,
		c.ID, c.Name, c.Description, status, c.ThreatActorID,
		c.TargetSectors, c.TargetRegions, platformsToStrings(c.TargetPlatforms),
		c.MitreTactics, c.MitreTechniques, c.FirstSeen, c.LastSeen,
		c.IndicatorCount, c.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update campaign: %w", err)
	}

	return nil
}

// IncrementIndicatorCount increments the indicator count for a campaign
func (r *CampaignRepository) IncrementIndicatorCount(ctx context.Context, id uuid.UUID, delta int) error {
	query := `
		UPDATE campaigns SET
			indicator_count = indicator_count + $2,
			last_seen = NOW(),
			updated_at = NOW()
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id, delta)
	return err
}

// SetActive sets the active status of a campaign
func (r *CampaignRepository) SetActive(ctx context.Context, id uuid.UUID, active bool) error {
	status := "inactive"
	if active {
		status = "active"
	}
	query := `UPDATE campaigns SET status = $2, updated_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id, status)
	return err
}

// GetStats returns campaign statistics
func (r *CampaignRepository) GetStats(ctx context.Context) (*CampaignStats, error) {
	stats := &CampaignStats{}

	err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'active')
		FROM campaigns
	`).Scan(&stats.TotalCount, &stats.ActiveCount)

	if err != nil {
		return nil, fmt.Errorf("failed to get campaign stats: %w", err)
	}

	return stats, nil
}

// Helper functions

func (r *CampaignRepository) scanCampaign(row pgx.Row) (*models.Campaign, error) {
	c := &models.Campaign{}
	var platforms []string
	var actorName *string

	err := row.Scan(
		&c.ID, &c.Slug, &c.Name, &c.Description, &c.Status, &c.ThreatActorID,
		&c.TargetSectors, &c.TargetRegions, &platforms,
		&c.MitreTactics, &c.MitreTechniques, &c.FirstSeen, &c.LastSeen,
		&c.IndicatorCount, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		&actorName,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan campaign: %w", err)
	}

	c.TargetPlatforms = stringsToPlatforms(platforms)
	if actorName != nil {
		c.ThreatActorName = *actorName
	}

	return c, nil
}

func (r *CampaignRepository) scanCampaignFromRows(rows pgx.Rows) (*models.Campaign, error) {
	c := &models.Campaign{}
	var platforms []string
	var actorName *string

	err := rows.Scan(
		&c.ID, &c.Slug, &c.Name, &c.Description, &c.Status, &c.ThreatActorID,
		&c.TargetSectors, &c.TargetRegions, &platforms,
		&c.MitreTactics, &c.MitreTechniques, &c.FirstSeen, &c.LastSeen,
		&c.IndicatorCount, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		&actorName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan campaign row: %w", err)
	}

	c.TargetPlatforms = stringsToPlatforms(platforms)
	if actorName != nil {
		c.ThreatActorName = *actorName
	}

	return c, nil
}

// CampaignStats holds aggregate campaign statistics
type CampaignStats struct {
	TotalCount  int64 `json:"total_count"`
	ActiveCount int64 `json:"active_count"`
}
