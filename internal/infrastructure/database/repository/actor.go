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

// ThreatActorRepository handles threat actor persistence
type ThreatActorRepository struct {
	pool *pgxpool.Pool
}

// NewThreatActorRepository creates a new threat actor repository
func NewThreatActorRepository(pool *pgxpool.Pool) *ThreatActorRepository {
	return &ThreatActorRepository{pool: pool}
}

// Create inserts a new threat actor
func (r *ThreatActorRepository) Create(ctx context.Context, a *models.ThreatActor) (*models.ThreatActor, error) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	now := time.Now()
	a.CreatedAt = now
	a.UpdatedAt = now

	query := `
		INSERT INTO threat_actors (
			id, name, aliases, description, type, motivation, country, active,
			target_sectors, target_regions, common_techniques,
			campaign_count, indicator_count, "references", created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		) RETURNING id, created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		a.ID, a.Name, a.Aliases, a.Description, a.Type, a.Motivation, a.Country, a.Active,
		a.TargetSectors, a.TargetRegions, a.CommonTechniques,
		a.CampaignCount, a.IndicatorCount, a.References, a.CreatedAt, a.UpdatedAt,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create threat actor: %w", err)
	}

	return a, nil
}

// GetByID retrieves a threat actor by ID
func (r *ThreatActorRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ThreatActor, error) {
	query := `
		SELECT id, name, aliases, description, type, motivation, country, active,
			   target_sectors, target_regions, common_techniques,
			   campaign_count, indicator_count, "references", created_at, updated_at
		FROM threat_actors
		WHERE id = $1`

	return r.scanActor(r.pool.QueryRow(ctx, query, id))
}

// GetByName retrieves a threat actor by name
func (r *ThreatActorRepository) GetByName(ctx context.Context, name string) (*models.ThreatActor, error) {
	query := `
		SELECT id, name, aliases, description, type, motivation, country, active,
			   target_sectors, target_regions, common_techniques,
			   campaign_count, indicator_count, "references", created_at, updated_at
		FROM threat_actors
		WHERE name = $1 OR $1 = ANY(aliases)`

	return r.scanActor(r.pool.QueryRow(ctx, query, name))
}

// List retrieves all threat actors
func (r *ThreatActorRepository) List(ctx context.Context, activeOnly bool, limit, offset int) ([]*models.ThreatActor, int64, error) {
	// Count query
	countQuery := "SELECT COUNT(*) FROM threat_actors"
	if activeOnly {
		countQuery += " WHERE active = true"
	}

	var total int64
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count threat actors: %w", err)
	}

	// List query
	query := `
		SELECT id, name, aliases, description, type, motivation, country, active,
			   target_sectors, target_regions, common_techniques,
			   campaign_count, indicator_count, "references", created_at, updated_at
		FROM threat_actors`

	if activeOnly {
		query += " WHERE active = true"
	}
	query += " ORDER BY name"

	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list threat actors: %w", err)
	}
	defer rows.Close()

	var actors []*models.ThreatActor
	for rows.Next() {
		a, err := r.scanActorFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		actors = append(actors, a)
	}

	return actors, total, nil
}

// Update updates a threat actor
func (r *ThreatActorRepository) Update(ctx context.Context, a *models.ThreatActor) error {
	a.UpdatedAt = time.Now()

	query := `
		UPDATE threat_actors SET
			name = $2, aliases = $3, description = $4, type = $5, motivation = $6,
			country = $7, active = $8, target_sectors = $9, target_regions = $10,
			common_techniques = $11, campaign_count = $12, indicator_count = $13,
			"references" = $14, updated_at = $15
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query,
		a.ID, a.Name, a.Aliases, a.Description, a.Type, a.Motivation,
		a.Country, a.Active, a.TargetSectors, a.TargetRegions,
		a.CommonTechniques, a.CampaignCount, a.IndicatorCount,
		a.References, a.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update threat actor: %w", err)
	}

	return nil
}

// IncrementCounts increments campaign and/or indicator counts
func (r *ThreatActorRepository) IncrementCounts(ctx context.Context, id uuid.UUID, campaigns, indicators int) error {
	query := `
		UPDATE threat_actors SET
			campaign_count = campaign_count + $2,
			indicator_count = indicator_count + $3,
			updated_at = NOW()
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id, campaigns, indicators)
	return err
}

// SetActive sets the active status of a threat actor
func (r *ThreatActorRepository) SetActive(ctx context.Context, id uuid.UUID, active bool) error {
	query := `UPDATE threat_actors SET active = $2, updated_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id, active)
	return err
}

// Helper functions

func (r *ThreatActorRepository) scanActor(row pgx.Row) (*models.ThreatActor, error) {
	a := &models.ThreatActor{}

	err := row.Scan(
		&a.ID, &a.Name, &a.Aliases, &a.Description, &a.Type, &a.Motivation,
		&a.Country, &a.Active, &a.TargetSectors, &a.TargetRegions,
		&a.CommonTechniques, &a.CampaignCount, &a.IndicatorCount,
		&a.References, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan threat actor: %w", err)
	}

	return a, nil
}

func (r *ThreatActorRepository) scanActorFromRows(rows pgx.Rows) (*models.ThreatActor, error) {
	a := &models.ThreatActor{}

	err := rows.Scan(
		&a.ID, &a.Name, &a.Aliases, &a.Description, &a.Type, &a.Motivation,
		&a.Country, &a.Active, &a.TargetSectors, &a.TargetRegions,
		&a.CommonTechniques, &a.CampaignCount, &a.IndicatorCount,
		&a.References, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan threat actor row: %w", err)
	}

	return a, nil
}
