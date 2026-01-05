-- name: GetIndicatorByID :one
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators WHERE id = $1;

-- name: GetIndicatorByHash :one
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators WHERE value_hash = $1;

-- name: GetIndicatorByValue :one
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators WHERE value = $1 AND type = $2;

-- name: ListIndicators :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
ORDER BY last_seen DESC
LIMIT $1 OFFSET $2;

-- name: ListIndicatorsByType :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE type = $1
ORDER BY last_seen DESC
LIMIT $2 OFFSET $3;

-- name: ListIndicatorsBySeverity :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE severity = $1
ORDER BY last_seen DESC
LIMIT $2 OFFSET $3;

-- name: ListIndicatorsByCampaign :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE campaign_id = $1
ORDER BY last_seen DESC
LIMIT $2 OFFSET $3;

-- name: ListPegasusIndicators :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE 'pegasus' = ANY(tags) OR 'nso-group' = ANY(tags)
ORDER BY severity DESC, confidence DESC
LIMIT $1 OFFSET $2;

-- name: ListMobileIndicators :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE 'android' = ANY(platforms) OR 'ios' = ANY(platforms)
ORDER BY severity DESC, confidence DESC
LIMIT $1 OFFSET $2;

-- name: ListActiveIndicators :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE (expires_at IS NULL OR expires_at > NOW())
ORDER BY last_seen DESC
LIMIT $1 OFFSET $2;

-- name: ListCriticalIndicators :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE severity = 'critical'
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY confidence DESC, last_seen DESC
LIMIT $1 OFFSET $2;

-- name: SearchIndicators :many
SELECT
    id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at
FROM indicators
WHERE value ILIKE '%' || $1 || '%'
   OR $1 = ANY(tags)
ORDER BY severity DESC, confidence DESC
LIMIT $2 OFFSET $3;

-- name: CountIndicators :one
SELECT COUNT(*) FROM indicators;

-- name: CountIndicatorsByType :one
SELECT COUNT(*) FROM indicators WHERE type = $1;

-- name: CountIndicatorsBySeverity :one
SELECT COUNT(*) FROM indicators WHERE severity = $1;

-- name: CountPegasusIndicators :one
SELECT COUNT(*) FROM indicators
WHERE 'pegasus' = ANY(tags) OR 'nso-group' = ANY(tags);

-- name: CountMobileIndicators :one
SELECT COUNT(*) FROM indicators
WHERE 'android' = ANY(platforms) OR 'ios' = ANY(platforms);

-- name: CreateIndicator :one
INSERT INTO indicators (
    value, value_hash, type, severity, confidence, description,
    tags, platforms, first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14,
    $15, $16, $17, $18, $19, $20
)
RETURNING id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at;

-- name: UpsertIndicator :one
INSERT INTO indicators (
    value, value_hash, type, severity, confidence, description,
    tags, platforms, first_seen, last_seen,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13,
    $14, $15, $16
)
ON CONFLICT (value_hash) DO UPDATE SET
    last_seen = EXCLUDED.last_seen,
    confidence = GREATEST(indicators.confidence, EXCLUDED.confidence),
    source_count = indicators.source_count + 1,
    updated_at = NOW()
RETURNING id, value, value_hash, type::text, severity::text, confidence, description,
    tags, platforms::text[], first_seen, last_seen, expires_at,
    campaign_id, threat_actor_id, malware_family_id,
    mitre_techniques, mitre_tactics, cve_ids, report_count, source_count, metadata,
    graph_node_id, created_at, updated_at;

-- name: UpdateIndicatorConfidence :exec
UPDATE indicators
SET confidence = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateIndicatorLastSeen :exec
UPDATE indicators
SET last_seen = NOW(), updated_at = NOW()
WHERE id = $1;

-- name: IncrementIndicatorSourceCount :exec
UPDATE indicators
SET source_count = source_count + 1, updated_at = NOW()
WHERE id = $1;

-- name: IncrementIndicatorReportCount :exec
UPDATE indicators
SET report_count = report_count + 1, updated_at = NOW()
WHERE id = $1;

-- name: DeleteIndicator :exec
DELETE FROM indicators WHERE id = $1;

-- name: DeleteExpiredIndicators :execrows
DELETE FROM indicators
WHERE expires_at IS NOT NULL AND expires_at < NOW();

-- name: GetIndicatorSources :many
SELECT
    isrc.indicator_id,
    isrc.source_id,
    s.name as source_name,
    isrc.source_confidence,
    isrc.fetched_at,
    isrc.created_at
FROM indicator_sources isrc
JOIN sources s ON s.id = isrc.source_id
WHERE isrc.indicator_id = $1
ORDER BY isrc.fetched_at DESC;

-- name: AddIndicatorSource :exec
INSERT INTO indicator_sources (indicator_id, source_id, source_confidence, raw_data, fetched_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (indicator_id, source_id) DO UPDATE SET
    source_confidence = EXCLUDED.source_confidence,
    fetched_at = NOW();

-- name: GetIndicatorStats :one
SELECT
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE type = 'domain') as domains,
    COUNT(*) FILTER (WHERE type = 'ip') as ips,
    COUNT(*) FILTER (WHERE type = 'hash') as hashes,
    COUNT(*) FILTER (WHERE type = 'url') as urls,
    COUNT(*) FILTER (WHERE type = 'process') as processes,
    COUNT(*) FILTER (WHERE type = 'package') as packages,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
    COUNT(*) FILTER (WHERE severity = 'high') as high,
    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
    COUNT(*) FILTER (WHERE severity = 'low') as low,
    COUNT(*) FILTER (WHERE 'pegasus' = ANY(tags)) as pegasus,
    COUNT(*) FILTER (WHERE 'android' = ANY(platforms) OR 'ios' = ANY(platforms)) as mobile,
    COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '1 day') as today_new,
    COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '7 days') as week_new,
    COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '30 days') as month_new
FROM indicators;
