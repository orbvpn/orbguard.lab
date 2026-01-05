-- name: GetReportByID :one
SELECT * FROM community_reports WHERE id = $1;

-- name: ListReports :many
SELECT * FROM community_reports
ORDER BY reported_at DESC
LIMIT $1 OFFSET $2;

-- name: ListReportsByStatus :many
SELECT * FROM community_reports
WHERE status = $1
ORDER BY reported_at DESC
LIMIT $2 OFFSET $3;

-- name: ListPendingReports :many
SELECT * FROM community_reports
WHERE status = 'pending'
ORDER BY reported_at ASC
LIMIT $1;

-- name: CountReports :one
SELECT COUNT(*) FROM community_reports;

-- name: CountReportsByStatus :one
SELECT COUNT(*) FROM community_reports WHERE status = $1;

-- name: CountPendingReports :one
SELECT COUNT(*) FROM community_reports WHERE status = 'pending';

-- name: CreateReport :one
INSERT INTO community_reports (
    status, indicator_value, indicator_type, severity, description, tags,
    reporter_hash, reporter_country,
    device_type, device_model, os_version, app_version,
    evidence_data, reported_at
) VALUES (
    'pending', $1, $2, $3, $4, $5,
    $6, $7,
    $8, $9, $10, $11,
    $12, NOW()
)
RETURNING *;

-- name: UpdateReportStatus :exec
UPDATE community_reports
SET
    status = $2,
    reviewed_by = $3,
    reviewed_at = NOW(),
    review_notes = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: ApproveReport :exec
UPDATE community_reports
SET
    status = 'approved',
    reviewed_by = $2,
    reviewed_at = NOW(),
    review_notes = $3,
    indicator_id = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: RejectReport :exec
UPDATE community_reports
SET
    status = 'rejected',
    reviewed_by = $2,
    reviewed_at = NOW(),
    review_notes = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: MarkReportAsDuplicate :exec
UPDATE community_reports
SET
    status = 'duplicate',
    reviewed_by = $2,
    reviewed_at = NOW(),
    review_notes = $3,
    indicator_id = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteReport :exec
DELETE FROM community_reports WHERE id = $1;

-- Update History

-- name: CreateUpdateHistory :one
INSERT INTO update_history (
    source_id, source_slug,
    started_at, completed_at, duration,
    success, error,
    total_fetched, new_indicators, updated_indicators, skipped_indicators,
    metadata
) VALUES (
    $1, $2,
    $3, $4, $5,
    $6, $7,
    $8, $9, $10, $11,
    $12
)
RETURNING *;

-- name: ListUpdateHistory :many
SELECT * FROM update_history
ORDER BY started_at DESC
LIMIT $1 OFFSET $2;

-- name: ListUpdateHistoryBySource :many
SELECT * FROM update_history
WHERE source_id = $1
ORDER BY started_at DESC
LIMIT $2 OFFSET $3;

-- name: GetLatestUpdateBySource :one
SELECT * FROM update_history
WHERE source_id = $1
ORDER BY started_at DESC
LIMIT 1;

-- name: CountUpdateHistory :one
SELECT COUNT(*) FROM update_history;

-- name: CountFailedUpdates :one
SELECT COUNT(*) FROM update_history
WHERE success = FALSE
  AND started_at >= NOW() - INTERVAL '24 hours';

-- name: DeleteOldUpdateHistory :execrows
DELETE FROM update_history
WHERE created_at < NOW() - INTERVAL '30 days';
