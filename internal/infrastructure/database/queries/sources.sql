-- name: GetSourceByID :one
SELECT * FROM sources WHERE id = $1;

-- name: GetSourceBySlug :one
SELECT * FROM sources WHERE slug = $1;

-- name: ListSources :many
SELECT * FROM sources
ORDER BY name ASC;

-- name: ListActiveSources :many
SELECT * FROM sources
WHERE status = 'active'
ORDER BY name ASC;

-- name: ListSourcesByCategory :many
SELECT * FROM sources
WHERE category = $1
ORDER BY name ASC;

-- name: ListSourcesDueForUpdate :many
SELECT * FROM sources
WHERE status = 'active'
  AND (next_fetch IS NULL OR next_fetch <= NOW())
ORDER BY next_fetch ASC NULLS FIRST
LIMIT $1;

-- name: CountSources :one
SELECT COUNT(*) FROM sources;

-- name: CountActiveSources :one
SELECT COUNT(*) FROM sources WHERE status = 'active';

-- name: CreateSource :one
INSERT INTO sources (
    name, slug, description, category, type, status,
    api_url, feed_url, github_urls, requires_api_key,
    reliability, weight, update_interval
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13
)
RETURNING *;

-- name: UpdateSourceStatus :exec
UPDATE sources
SET status = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateSourceAfterFetch :exec
UPDATE sources
SET
    last_fetched = NOW(),
    next_fetch = NOW() + update_interval,
    last_error = NULL,
    error_count = 0,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateSourceError :exec
UPDATE sources
SET
    last_error = $2,
    error_count = error_count + 1,
    next_fetch = NOW() + update_interval,
    status = CASE WHEN error_count >= 5 THEN 'error'::source_status ELSE status END,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateSourceIndicatorCount :exec
UPDATE sources
SET
    indicator_count = $2,
    last_indicator_at = NOW(),
    updated_at = NOW()
WHERE id = $1;

-- name: IncrementSourceIndicatorCount :exec
UPDATE sources
SET
    indicator_count = indicator_count + $2,
    last_indicator_at = NOW(),
    updated_at = NOW()
WHERE id = $1;

-- name: ResetSourceErrors :exec
UPDATE sources
SET
    last_error = NULL,
    error_count = 0,
    status = 'active',
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteSource :exec
DELETE FROM sources WHERE id = $1;
