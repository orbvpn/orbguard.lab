package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"orbguard-lab/internal/domain/models"
)

// SourceRepository handles source persistence
type SourceRepository struct {
	pool *pgxpool.Pool
}

// NewSourceRepository creates a new source repository
func NewSourceRepository(pool *pgxpool.Pool) *SourceRepository {
	return &SourceRepository{pool: pool}
}

// Create inserts a new source
func (r *SourceRepository) Create(ctx context.Context, s *models.Source) (*models.Source, error) {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now()
	s.CreatedAt = now
	s.UpdatedAt = now

	query := `
		INSERT INTO sources (
			id, slug, name, description, category, type, status,
			api_url, feed_url, github_urls, requires_api_key,
			reliability, weight, update_interval,
			last_fetched, next_fetch, last_error, error_count,
			indicator_count, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		) RETURNING id, created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		s.ID, s.Slug, s.Name, s.Description, s.Category, s.Type, s.Status,
		s.APIURL, s.FeedURL, s.GithubURLs, s.RequiresAPIKey,
		s.Reliability, s.Weight, s.UpdateInterval,
		s.LastFetched, s.NextFetch, s.LastError, s.ErrorCount,
		s.IndicatorCount, s.CreatedAt, s.UpdatedAt,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create source: %w", err)
	}

	return s, nil
}

// GetByID retrieves a source by ID
func (r *SourceRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Source, error) {
	query := `
		SELECT id, slug, name, description, category, type, status,
			   api_url, feed_url, github_urls, requires_api_key,
			   reliability, weight, update_interval,
			   last_fetched, next_fetch, last_error, error_count,
			   indicator_count, created_at, updated_at
		FROM sources
		WHERE id = $1`

	return r.scanSource(r.pool.QueryRow(ctx, query, id))
}

// GetBySlug retrieves a source by its slug
func (r *SourceRepository) GetBySlug(ctx context.Context, slug string) (*models.Source, error) {
	query := `
		SELECT id, slug, name, description, category, type, status,
			   api_url, feed_url, github_urls, requires_api_key,
			   reliability, weight, update_interval,
			   last_fetched, next_fetch, last_error, error_count,
			   indicator_count, created_at, updated_at
		FROM sources
		WHERE slug = $1`

	return r.scanSource(r.pool.QueryRow(ctx, query, slug))
}

// List retrieves all sources
func (r *SourceRepository) List(ctx context.Context) ([]*models.Source, error) {
	query := `
		SELECT id, slug, name, description, category, type, status,
			   api_url, feed_url, github_urls, requires_api_key,
			   reliability, weight, update_interval,
			   last_fetched, next_fetch, last_error, error_count,
			   indicator_count, created_at, updated_at
		FROM sources
		ORDER BY name`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources: %w", err)
	}
	defer rows.Close()

	var sources []*models.Source
	for rows.Next() {
		s, err := r.scanSourceFromRows(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}

	return sources, nil
}

// ListActive retrieves all active sources
func (r *SourceRepository) ListActive(ctx context.Context) ([]*models.Source, error) {
	query := `
		SELECT id, slug, name, description, category, type, status,
			   api_url, feed_url, github_urls, requires_api_key,
			   reliability, weight, update_interval,
			   last_fetched, next_fetch, last_error, error_count,
			   indicator_count, created_at, updated_at
		FROM sources
		WHERE status = 'active'
		ORDER BY weight DESC, name`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active sources: %w", err)
	}
	defer rows.Close()

	var sources []*models.Source
	for rows.Next() {
		s, err := r.scanSourceFromRows(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}

	return sources, nil
}

// ListDue retrieves sources that are due for update
func (r *SourceRepository) ListDue(ctx context.Context) ([]*models.Source, error) {
	query := `
		SELECT id, slug, name, description, category, type, status,
			   api_url, feed_url, github_urls, requires_api_key,
			   reliability, weight, update_interval,
			   last_fetched, next_fetch, last_error, error_count,
			   indicator_count, created_at, updated_at
		FROM sources
		WHERE status = 'active' AND (next_fetch IS NULL OR next_fetch <= NOW())
		ORDER BY weight DESC, name`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list due sources: %w", err)
	}
	defer rows.Close()

	var sources []*models.Source
	for rows.Next() {
		s, err := r.scanSourceFromRows(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}

	return sources, nil
}

// UpdateAfterFetch updates source metadata after a successful fetch
func (r *SourceRepository) UpdateAfterFetch(ctx context.Context, id uuid.UUID, indicatorCount int) error {
	query := `
		UPDATE sources SET
			last_fetched = NOW(),
			next_fetch = NOW() + update_interval,
			last_error = NULL,
			error_count = 0,
			indicator_count = indicator_count + $2,
			status = 'active',
			updated_at = NOW()
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id, indicatorCount)
	if err != nil {
		return fmt.Errorf("failed to update source after fetch: %w", err)
	}

	return nil
}

// UpdateAfterError updates source metadata after a failed fetch
func (r *SourceRepository) UpdateAfterError(ctx context.Context, id uuid.UUID, errMsg string) error {
	query := `
		UPDATE sources SET
			last_fetched = NOW(),
			next_fetch = NOW() + (update_interval * LEAST(error_count + 1, 4)),
			last_error = $2,
			error_count = error_count + 1,
			status = CASE WHEN error_count >= 3 THEN 'error' ELSE status END,
			updated_at = NOW()
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id, errMsg)
	if err != nil {
		return fmt.Errorf("failed to update source after error: %w", err)
	}

	return nil
}

// SetStatus sets the status of a source
func (r *SourceRepository) SetStatus(ctx context.Context, id uuid.UUID, status models.SourceStatus) error {
	query := `UPDATE sources SET status = $2, updated_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id, status)
	return err
}

// GetStats returns source statistics
func (r *SourceRepository) GetStats(ctx context.Context) (*SourceStats, error) {
	stats := &SourceStats{}

	// Total and active counts
	err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'active')
		FROM sources
	`).Scan(&stats.TotalCount, &stats.ActiveCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get source counts: %w", err)
	}

	// By category
	rows, err := r.pool.Query(ctx, `
		SELECT category, COUNT(*)
		FROM sources
		WHERE status = 'active'
		GROUP BY category
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get category counts: %w", err)
	}
	stats.ByCategory = make(map[string]int64)
	for rows.Next() {
		var cat string
		var count int64
		if err := rows.Scan(&cat, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.ByCategory[cat] = count
	}
	rows.Close()

	// Error count
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sources WHERE error_count > 0
	`).Scan(&stats.ErrorCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get error count: %w", err)
	}

	return stats, nil
}

// Helper functions

func (r *SourceRepository) scanSource(row pgx.Row) (*models.Source, error) {
	s := &models.Source{}
	var apiURL, feedURL, description pgtype.Text

	err := row.Scan(
		&s.ID, &s.Slug, &s.Name, &description, &s.Category, &s.Type, &s.Status,
		&apiURL, &feedURL, &s.GithubURLs, &s.RequiresAPIKey,
		&s.Reliability, &s.Weight, &s.UpdateInterval,
		&s.LastFetched, &s.NextFetch, &s.LastError, &s.ErrorCount,
		&s.IndicatorCount, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan source: %w", err)
	}

	if description.Valid {
		s.Description = description.String
	}
	if apiURL.Valid {
		s.APIURL = apiURL.String
	}
	if feedURL.Valid {
		s.FeedURL = feedURL.String
	}

	return s, nil
}

func (r *SourceRepository) scanSourceFromRows(rows pgx.Rows) (*models.Source, error) {
	s := &models.Source{}
	var apiURL, feedURL, description pgtype.Text

	err := rows.Scan(
		&s.ID, &s.Slug, &s.Name, &description, &s.Category, &s.Type, &s.Status,
		&apiURL, &feedURL, &s.GithubURLs, &s.RequiresAPIKey,
		&s.Reliability, &s.Weight, &s.UpdateInterval,
		&s.LastFetched, &s.NextFetch, &s.LastError, &s.ErrorCount,
		&s.IndicatorCount, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan source row: %w", err)
	}

	if description.Valid {
		s.Description = description.String
	}
	if apiURL.Valid {
		s.APIURL = apiURL.String
	}
	if feedURL.Valid {
		s.FeedURL = feedURL.String
	}

	return s, nil
}

// SourceStats holds aggregate source statistics
type SourceStats struct {
	TotalCount  int64            `json:"total_count"`
	ActiveCount int64            `json:"active_count"`
	ByCategory  map[string]int64 `json:"by_category"`
	ErrorCount  int64            `json:"error_count"`
}
