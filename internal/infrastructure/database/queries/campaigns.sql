-- name: GetCampaignByID :one
SELECT * FROM campaigns WHERE id = $1;

-- name: GetCampaignBySlug :one
SELECT * FROM campaigns WHERE slug = $1;

-- name: ListCampaigns :many
SELECT * FROM campaigns
ORDER BY last_seen DESC;

-- name: ListActiveCampaigns :many
SELECT * FROM campaigns
WHERE status = 'active'
ORDER BY last_seen DESC;

-- name: CountCampaigns :one
SELECT COUNT(*) FROM campaigns;

-- name: CountActiveCampaigns :one
SELECT COUNT(*) FROM campaigns WHERE status = 'active';

-- name: CreateCampaign :one
INSERT INTO campaigns (
    name, slug, description, status,
    threat_actor_id, target_sectors, target_regions, target_platforms,
    mitre_techniques, mitre_tactics,
    first_seen, last_seen, start_date, end_date,
    "references", metadata
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, $8,
    $9, $10,
    $11, $12, $13, $14,
    $15, $16
)
RETURNING *;

-- name: UpdateCampaignIndicatorCount :exec
UPDATE campaigns
SET indicator_count = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateCampaignLastSeen :exec
UPDATE campaigns
SET last_seen = NOW(), updated_at = NOW()
WHERE id = $1;

-- name: DeleteCampaign :exec
DELETE FROM campaigns WHERE id = $1;

-- Threat Actors

-- name: GetThreatActorByID :one
SELECT * FROM threat_actors WHERE id = $1;

-- name: GetThreatActorByName :one
SELECT * FROM threat_actors WHERE name = $1;

-- name: ListThreatActors :many
SELECT * FROM threat_actors
ORDER BY name ASC;

-- name: ListActiveThreatActors :many
SELECT * FROM threat_actors
WHERE active = TRUE
ORDER BY name ASC;

-- name: CountThreatActors :one
SELECT COUNT(*) FROM threat_actors;

-- name: CreateThreatActor :one
INSERT INTO threat_actors (
    name, aliases, description, type, motivation, country, active,
    target_sectors, target_regions, common_techniques,
    "references", metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10,
    $11, $12
)
RETURNING *;

-- name: UpdateThreatActorIndicatorCount :exec
UPDATE threat_actors
SET indicator_count = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateThreatActorCampaignCount :exec
UPDATE threat_actors
SET campaign_count = $2, updated_at = NOW()
WHERE id = $1;

-- Malware Families

-- name: GetMalwareFamilyByID :one
SELECT * FROM malware_families WHERE id = $1;

-- name: GetMalwareFamilyByName :one
SELECT * FROM malware_families WHERE name = $1;

-- name: ListMalwareFamilies :many
SELECT * FROM malware_families
ORDER BY name ASC;

-- name: CountMalwareFamilies :one
SELECT COUNT(*) FROM malware_families;

-- name: CreateMalwareFamily :one
INSERT INTO malware_families (
    name, aliases, description, type, platforms,
    threat_actor_id, techniques, capabilities,
    first_seen, last_seen, "references", metadata
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    $9, $10, $11, $12
)
RETURNING *;

-- name: UpdateMalwareFamilyIndicatorCount :exec
UPDATE malware_families
SET indicator_count = $2, updated_at = NOW()
WHERE id = $1;
