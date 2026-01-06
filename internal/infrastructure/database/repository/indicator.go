package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/database/db"
)

// IndicatorFilter defines filtering options for listing indicators
type IndicatorFilter struct {
	Types          []models.IndicatorType
	Severities     []models.Severity
	Platforms      []models.Platform
	Tags           []string
	CampaignID     *uuid.UUID
	ThreatActorID  *uuid.UUID
	MinConfidence  float64
	FirstSeenAfter *time.Time
	LastSeenAfter  *time.Time
	PegasusOnly    bool
	MobileOnly     bool
	CriticalOnly   bool
	Value          string
	Limit          int
	Offset         int
}

// IndicatorStats holds aggregate statistics
type IndicatorStats struct {
	TotalCount    int64            `json:"total_count"`
	ByType        map[string]int64 `json:"by_type"`
	BySeverity    map[string]int64 `json:"by_severity"`
	PegasusCount  int64            `json:"pegasus_count"`
	MobileCount   int64            `json:"mobile_count"`
	CriticalCount int64            `json:"critical_count"`
	TodayNew      int64            `json:"today_new"`
	WeeklyNew     int64            `json:"weekly_new"`
	MonthlyNew    int64            `json:"monthly_new"`
}

// IndicatorRepository handles indicator persistence using sqlc
type IndicatorRepository struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewIndicatorRepository creates a new indicator repository
func NewIndicatorRepository(pool *pgxpool.Pool) *IndicatorRepository {
	return &IndicatorRepository{
		pool:    pool,
		queries: db.New(pool),
	}
}

// Create inserts a new indicator
func (r *IndicatorRepository) Create(ctx context.Context, i *models.Indicator) (*models.Indicator, error) {
	// Ensure value hash
	if i.ValueHash == "" {
		i.ValueHash = hashValue(i.Value)
	}

	now := time.Now()
	if i.FirstSeen.IsZero() {
		i.FirstSeen = now
	}
	if i.LastSeen.IsZero() {
		i.LastSeen = now
	}

	params := &db.CreateIndicatorParams{
		Value:           i.Value,
		ValueHash:       i.ValueHash,
		Type:            i.Type,
		Severity:        i.Severity,
		Confidence:      floatToNumeric(i.Confidence),
		Description:     textOrNull(i.Description),
		Tags:            i.Tags,
		Platforms:       platformsToStrings(i.Platforms),
		FirstSeen:       timeToTimestamptz(i.FirstSeen),
		LastSeen:        timeToTimestamptz(i.LastSeen),
		ExpiresAt:       timeToTimestamptzPtr(i.ExpiresAt),
		CampaignID:      uuidToNullUUID(i.CampaignID),
		ThreatActorID:   uuidToNullUUID(i.ThreatActorID),
		MalwareFamilyID: uuidToNullUUID(i.MalwareFamilyID),
		MitreTechniques: i.MitreTechniques,
		MitreTactics:    i.MitreTactics,
		CveIds:          i.CVEIDs,
		ReportCount:     int32(i.ReportCount),
		SourceCount:     int32(i.SourceCount),
		Metadata:        i.Metadata,
	}

	result, err := r.queries.CreateIndicator(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create indicator: %w", err)
	}

	return createIndicatorRowToModel(result), nil
}

// Upsert creates or updates an indicator based on value_hash
func (r *IndicatorRepository) Upsert(ctx context.Context, i *models.Indicator) (*models.Indicator, error) {
	// Ensure value hash
	if i.ValueHash == "" {
		i.ValueHash = hashValue(i.Value)
	}

	now := time.Now()
	if i.FirstSeen.IsZero() {
		i.FirstSeen = now
	}
	if i.LastSeen.IsZero() {
		i.LastSeen = now
	}

	// Ensure source_id and source_name have defaults if not set
	sourceID := i.SourceID
	if sourceID == "" {
		sourceID = "unknown"
	}
	sourceName := i.SourceName
	if sourceName == "" {
		sourceName = "Unknown Source"
	}

	params := &db.UpsertIndicatorParams{
		Value:           i.Value,
		ValueHash:       i.ValueHash,
		Type:            i.Type,
		Severity:        i.Severity,
		Confidence:      floatToNumeric(i.Confidence),
		Description:     textOrNull(i.Description),
		Tags:            i.Tags,
		Platforms:       platformsToStrings(i.Platforms),
		FirstSeen:       timeToTimestamptz(i.FirstSeen),
		LastSeen:        timeToTimestamptz(i.LastSeen),
		SourceID:        sourceID,
		SourceName:      sourceName,
		CampaignID:      uuidToNullUUID(i.CampaignID),
		ThreatActorID:   uuidToNullUUID(i.ThreatActorID),
		MalwareFamilyID: uuidToNullUUID(i.MalwareFamilyID),
		MitreTechniques: i.MitreTechniques,
		MitreTactics:    i.MitreTactics,
		CveIds:          i.CVEIDs,
	}

	result, err := r.queries.UpsertIndicator(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert indicator: %w", err)
	}

	return upsertIndicatorRowToModel(result), nil
}

// GetByID retrieves an indicator by ID
func (r *IndicatorRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Indicator, error) {
	result, err := r.queries.GetIndicatorByID(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get indicator by ID: %w", err)
	}
	return getIndicatorByIDRowToModel(result), nil
}

// GetByHash retrieves an indicator by its value hash
func (r *IndicatorRepository) GetByHash(ctx context.Context, hash string) (*models.Indicator, error) {
	result, err := r.queries.GetIndicatorByHash(ctx, hash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get indicator by hash: %w", err)
	}
	return getIndicatorByHashRowToModel(result), nil
}

// GetByValue retrieves an indicator by its value and type
func (r *IndicatorRepository) GetByValue(ctx context.Context, value string, iocType models.IndicatorType) (*models.Indicator, error) {
	result, err := r.queries.GetIndicatorByValue(ctx, &db.GetIndicatorByValueParams{
		Value: value,
		Type:  iocType,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get indicator by value: %w", err)
	}
	return getIndicatorByValueRowToModel(result), nil
}

// List retrieves indicators with filtering and pagination
func (r *IndicatorRepository) List(ctx context.Context, filter IndicatorFilter) ([]*models.Indicator, int64, error) {
	// Use specialized methods for common filters
	if filter.PegasusOnly && len(filter.Types) == 0 && len(filter.Severities) == 0 {
		return r.listPegasusWithCount(ctx, filter.Limit, filter.Offset)
	}
	if filter.MobileOnly && len(filter.Types) == 0 && len(filter.Severities) == 0 {
		return r.listMobileWithCount(ctx, filter.Limit, filter.Offset)
	}
	if filter.CriticalOnly && len(filter.Types) == 0 && len(filter.Severities) == 0 {
		return r.listCriticalWithCount(ctx, filter.Limit, filter.Offset)
	}
	if filter.CampaignID != nil && len(filter.Types) == 0 && len(filter.Severities) == 0 {
		return r.listByCampaignWithCount(ctx, *filter.CampaignID, filter.Limit, filter.Offset)
	}

	// For complex filters, use dynamic SQL
	return r.listWithComplexFilter(ctx, filter)
}

func (r *IndicatorRepository) listPegasusWithCount(ctx context.Context, limit, offset int) ([]*models.Indicator, int64, error) {
	if limit <= 0 {
		limit = 100
	}

	count, err := r.queries.CountPegasusIndicators(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count pegasus indicators: %w", err)
	}

	results, err := r.queries.ListPegasusIndicators(ctx, &db.ListPegasusIndicatorsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list pegasus indicators: %w", err)
	}

	indicators := make([]*models.Indicator, len(results))
	for i, row := range results {
		indicators[i] = listPegasusIndicatorsRowToModel(row)
	}

	return indicators, count, nil
}

func (r *IndicatorRepository) listMobileWithCount(ctx context.Context, limit, offset int) ([]*models.Indicator, int64, error) {
	if limit <= 0 {
		limit = 100
	}

	count, err := r.queries.CountMobileIndicators(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count mobile indicators: %w", err)
	}

	results, err := r.queries.ListMobileIndicators(ctx, &db.ListMobileIndicatorsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list mobile indicators: %w", err)
	}

	indicators := make([]*models.Indicator, len(results))
	for i, row := range results {
		indicators[i] = listMobileIndicatorsRowToModel(row)
	}

	return indicators, count, nil
}

func (r *IndicatorRepository) listCriticalWithCount(ctx context.Context, limit, offset int) ([]*models.Indicator, int64, error) {
	if limit <= 0 {
		limit = 100
	}

	count, err := r.queries.CountIndicatorsBySeverity(ctx, models.SeverityCritical)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count critical indicators: %w", err)
	}

	results, err := r.queries.ListCriticalIndicators(ctx, &db.ListCriticalIndicatorsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list critical indicators: %w", err)
	}

	indicators := make([]*models.Indicator, len(results))
	for i, row := range results {
		indicators[i] = listCriticalIndicatorsRowToModel(row)
	}

	return indicators, count, nil
}

func (r *IndicatorRepository) listByCampaignWithCount(ctx context.Context, campaignID uuid.UUID, limit, offset int) ([]*models.Indicator, int64, error) {
	if limit <= 0 {
		limit = 100
	}

	// Count query
	var count int64
	err := r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM indicators WHERE campaign_id = $1", campaignID).Scan(&count)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count campaign indicators: %w", err)
	}

	results, err := r.queries.ListIndicatorsByCampaign(ctx, &db.ListIndicatorsByCampaignParams{
		CampaignID: pgtype.UUID{Bytes: campaignID, Valid: true},
		Limit:      int32(limit),
		Offset:     int32(offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list campaign indicators: %w", err)
	}

	indicators := make([]*models.Indicator, len(results))
	for i, row := range results {
		indicators[i] = listIndicatorsByCampaignRowToModel(row)
	}

	return indicators, count, nil
}

func (r *IndicatorRepository) listWithComplexFilter(ctx context.Context, filter IndicatorFilter) ([]*models.Indicator, int64, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	// Build conditions
	if len(filter.Types) > 0 {
		types := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			types[i] = string(t)
		}
		conditions = append(conditions, fmt.Sprintf("type = ANY($%d::indicator_type[])", argNum))
		args = append(args, types)
		argNum++
	}

	if len(filter.Severities) > 0 {
		sevs := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			sevs[i] = string(s)
		}
		conditions = append(conditions, fmt.Sprintf("severity = ANY($%d::severity_level[])", argNum))
		args = append(args, sevs)
		argNum++
	}

	if len(filter.Platforms) > 0 {
		plats := make([]string, len(filter.Platforms))
		for i, p := range filter.Platforms {
			plats[i] = string(p)
		}
		conditions = append(conditions, fmt.Sprintf("platforms && $%d::platform_type[]", argNum))
		args = append(args, plats)
		argNum++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argNum))
		args = append(args, filter.Tags)
		argNum++
	}

	if filter.CampaignID != nil {
		conditions = append(conditions, fmt.Sprintf("campaign_id = $%d", argNum))
		args = append(args, *filter.CampaignID)
		argNum++
	}

	if filter.ThreatActorID != nil {
		conditions = append(conditions, fmt.Sprintf("threat_actor_id = $%d", argNum))
		args = append(args, *filter.ThreatActorID)
		argNum++
	}

	if filter.MinConfidence > 0 {
		conditions = append(conditions, fmt.Sprintf("confidence >= $%d", argNum))
		args = append(args, filter.MinConfidence)
		argNum++
	}

	if filter.FirstSeenAfter != nil {
		conditions = append(conditions, fmt.Sprintf("first_seen >= $%d", argNum))
		args = append(args, *filter.FirstSeenAfter)
		argNum++
	}

	if filter.LastSeenAfter != nil {
		conditions = append(conditions, fmt.Sprintf("last_seen >= $%d", argNum))
		args = append(args, *filter.LastSeenAfter)
		argNum++
	}

	if filter.PegasusOnly {
		conditions = append(conditions, "('pegasus' = ANY(tags) OR 'nso-group' = ANY(tags))")
	}

	if filter.MobileOnly {
		conditions = append(conditions, "('android' = ANY(platforms) OR 'ios' = ANY(platforms))")
	}

	if filter.CriticalOnly {
		conditions = append(conditions, "severity = 'critical'")
	}

	if filter.Value != "" {
		conditions = append(conditions, fmt.Sprintf("value ILIKE $%d", argNum))
		args = append(args, "%"+filter.Value+"%")
		argNum++
	}

	whereClause := "1=1"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM indicators WHERE %s", whereClause)
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count indicators: %w", err)
	}

	// Apply pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	query := fmt.Sprintf(`
		SELECT id, value, value_hash, type::text, severity::text, confidence, description,
			   tags, platforms::text[], first_seen, last_seen, expires_at,
			   campaign_id, threat_actor_id, malware_family_id,
			   mitre_techniques, mitre_tactics, cve_ids,
			   report_count, source_count, metadata, graph_node_id,
			   created_at, updated_at
		FROM indicators
		WHERE %s
		ORDER BY last_seen DESC, confidence DESC
		LIMIT $%d OFFSET $%d`, whereClause, argNum, argNum+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list indicators: %w", err)
	}
	defer rows.Close()

	var indicators []*models.Indicator
	for rows.Next() {
		ind, err := scanIndicatorRow(rows)
		if err != nil {
			return nil, 0, err
		}
		indicators = append(indicators, ind)
	}

	return indicators, total, nil
}

// ListPegasus returns all Pegasus-related indicators
func (r *IndicatorRepository) ListPegasus(ctx context.Context, limit, offset int) ([]*models.Indicator, int64, error) {
	return r.listPegasusWithCount(ctx, limit, offset)
}

// ListMobile returns all mobile platform indicators
func (r *IndicatorRepository) ListMobile(ctx context.Context, limit, offset int) ([]*models.Indicator, int64, error) {
	return r.listMobileWithCount(ctx, limit, offset)
}

// ListByCampaign returns indicators for a specific campaign
func (r *IndicatorRepository) ListByCampaign(ctx context.Context, campaignID uuid.UUID, limit, offset int) ([]*models.Indicator, int64, error) {
	return r.listByCampaignWithCount(ctx, campaignID, limit, offset)
}

// Search searches indicators by value or tags
func (r *IndicatorRepository) Search(ctx context.Context, query string, limit, offset int) ([]*models.Indicator, error) {
	if limit <= 0 {
		limit = 100
	}

	results, err := r.queries.SearchIndicators(ctx, &db.SearchIndicatorsParams{
		Column1: textOrNull(query),
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search indicators: %w", err)
	}

	indicators := make([]*models.Indicator, len(results))
	for i, row := range results {
		indicators[i] = searchIndicatorsRowToModel(row)
	}

	return indicators, nil
}

// CheckBatch checks multiple indicator values and returns matches
func (r *IndicatorRepository) CheckBatch(ctx context.Context, values []string) ([]*models.Indicator, error) {
	if len(values) == 0 {
		return nil, nil
	}

	query := `
		SELECT id, value, value_hash, type::text, severity::text, confidence, description,
			   tags, platforms::text[], first_seen, last_seen, expires_at,
			   campaign_id, threat_actor_id, malware_family_id,
			   mitre_techniques, mitre_tactics, cve_ids,
			   report_count, source_count, metadata, graph_node_id,
			   created_at, updated_at
		FROM indicators
		WHERE value = ANY($1)`

	rows, err := r.pool.Query(ctx, query, values)
	if err != nil {
		return nil, fmt.Errorf("failed to check batch: %w", err)
	}
	defer rows.Close()

	var indicators []*models.Indicator
	for rows.Next() {
		ind, err := scanIndicatorRow(rows)
		if err != nil {
			return nil, err
		}
		indicators = append(indicators, ind)
	}

	return indicators, nil
}

// Delete removes an indicator
func (r *IndicatorRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteIndicator(ctx, id)
}

// DeleteExpired removes expired indicators
func (r *IndicatorRepository) DeleteExpired(ctx context.Context) (int64, error) {
	return r.queries.DeleteExpiredIndicators(ctx)
}

// AddIndicatorSource links an indicator to a source
func (r *IndicatorRepository) AddIndicatorSource(ctx context.Context, indicatorID, sourceID uuid.UUID, confidence float64, rawData string) error {
	return r.queries.AddIndicatorSource(ctx, &db.AddIndicatorSourceParams{
		IndicatorID:      indicatorID,
		SourceID:         sourceID,
		SourceConfidence: floatToNumeric(confidence),
		RawData:          textOrNull(rawData),
	})
}

// GetIndicatorSources returns all sources for an indicator
func (r *IndicatorRepository) GetIndicatorSources(ctx context.Context, indicatorID uuid.UUID) ([]*models.IndicatorSource, error) {
	results, err := r.queries.GetIndicatorSources(ctx, indicatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to get indicator sources: %w", err)
	}

	sources := make([]*models.IndicatorSource, len(results))
	for i, r := range results {
		sources[i] = &models.IndicatorSource{
			IndicatorID:      r.IndicatorID,
			SourceID:         r.SourceID,
			SourceName:       r.SourceName,
			SourceConfidence: numericToFloat(r.SourceConfidence),
			FetchedAt:        timestamptzToTime(r.FetchedAt),
			CreatedAt:        timestamptzToTime(r.CreatedAt),
		}
	}

	return sources, nil
}

// GetStats returns indicator statistics
func (r *IndicatorRepository) GetStats(ctx context.Context) (*IndicatorStats, error) {
	result, err := r.queries.GetIndicatorStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get indicator stats: %w", err)
	}

	return &IndicatorStats{
		TotalCount:    result.Total,
		PegasusCount:  result.Pegasus,
		MobileCount:   result.Mobile,
		CriticalCount: result.Critical,
		TodayNew:      result.TodayNew,
		WeeklyNew:     result.WeekNew,
		MonthlyNew:    result.MonthNew,
		ByType: map[string]int64{
			"domain":  result.Domains,
			"ip":      result.Ips,
			"hash":    result.Hashes,
			"url":     result.Urls,
			"process": result.Processes,
			"package": result.Packages,
		},
		BySeverity: map[string]int64{
			"critical": result.Critical,
			"high":     result.High,
			"medium":   result.Medium,
			"low":      result.Low,
		},
	}, nil
}

// UpdateConfidence updates an indicator's confidence score
func (r *IndicatorRepository) UpdateConfidence(ctx context.Context, id uuid.UUID, confidence float64) error {
	return r.queries.UpdateIndicatorConfidence(ctx, &db.UpdateIndicatorConfidenceParams{
		ID:         id,
		Confidence: floatToNumeric(confidence),
	})
}

// UpdateLastSeen updates an indicator's last seen timestamp
func (r *IndicatorRepository) UpdateLastSeen(ctx context.Context, id uuid.UUID) error {
	return r.queries.UpdateIndicatorLastSeen(ctx, id)
}

// IncrementSourceCount increments the source count
func (r *IndicatorRepository) IncrementSourceCount(ctx context.Context, id uuid.UUID) error {
	return r.queries.IncrementIndicatorSourceCount(ctx, id)
}

// IncrementReportCount increments the report count
func (r *IndicatorRepository) IncrementReportCount(ctx context.Context, id uuid.UUID) error {
	return r.queries.IncrementIndicatorReportCount(ctx, id)
}

// WithTx returns a repository that uses the given transaction
func (r *IndicatorRepository) WithTx(tx pgx.Tx) *IndicatorRepository {
	return &IndicatorRepository{
		pool:    r.pool,
		queries: r.queries.WithTx(tx),
	}
}

// Helper functions

func hashValue(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func dbIndicatorToModel(i *db.Indicator) *models.Indicator {
	if i == nil {
		return nil
	}

	return &models.Indicator{
		ID:              i.ID,
		Value:           i.Value,
		ValueHash:       i.ValueHash,
		Type:            i.Type,
		Severity:        i.Severity,
		Confidence:      numericToFloat(i.Confidence),
		Description:     nullTextToString(i.Description),
		Tags:            i.Tags,
		Platforms:       stringsToPlatforms(i.Platforms),
		FirstSeen:       timestamptzToTime(i.FirstSeen),
		LastSeen:        timestamptzToTime(i.LastSeen),
		ExpiresAt:       timestamptzToTimePtr(i.ExpiresAt),
		CampaignID:      nullUUIDToPtr(i.CampaignID),
		ThreatActorID:   nullUUIDToPtr(i.ThreatActorID),
		MalwareFamilyID: nullUUIDToPtr(i.MalwareFamilyID),
		MitreTechniques: i.MitreTechniques,
		MitreTactics:    i.MitreTactics,
		CVEIDs:          i.CveIds,
		ReportCount:     int(i.ReportCount),
		SourceCount:     int(i.SourceCount),
		Metadata:        i.Metadata,
		GraphNodeID:     nullTextToString(i.GraphNodeID),
		CreatedAt:       timestamptzToTime(i.CreatedAt),
		UpdatedAt:       timestamptzToTime(i.UpdatedAt),
	}
}

// indicatorRow is an interface for the various Row types generated by sqlc
// that have string-based type/severity/platforms fields
type indicatorRow interface {
	GetID() uuid.UUID
	GetValue() string
	GetValueHash() string
	GetType() string
	GetSeverity() string
	GetConfidence() pgtype.Numeric
	GetDescription() pgtype.Text
	GetTags() []string
	GetPlatforms() []string
	GetFirstSeen() pgtype.Timestamptz
	GetLastSeen() pgtype.Timestamptz
	GetExpiresAt() pgtype.Timestamptz
	GetCampaignID() pgtype.UUID
	GetThreatActorID() pgtype.UUID
	GetMalwareFamilyID() pgtype.UUID
	GetMitreTechniques() []string
	GetMitreTactics() []string
	GetCveIds() []string
	GetReportCount() int32
	GetSourceCount() int32
	GetMetadata() []byte
	GetGraphNodeID() pgtype.Text
	GetCreatedAt() pgtype.Timestamptz
	GetUpdatedAt() pgtype.Timestamptz
}

// convertIndicatorRow converts a sqlc-generated row with string types to a model
func convertIndicatorRow(
	id uuid.UUID,
	value, valueHash, typeStr, severityStr string,
	confidence pgtype.Numeric,
	description pgtype.Text,
	tags, platforms []string,
	firstSeen, lastSeen, expiresAt pgtype.Timestamptz,
	campaignID, threatActorID, malwareFamilyID pgtype.UUID,
	mitreTechniques, mitreTactics, cveIDs []string,
	reportCount, sourceCount int32,
	metadata []byte,
	graphNodeID pgtype.Text,
	createdAt, updatedAt pgtype.Timestamptz,
) *models.Indicator {
	return &models.Indicator{
		ID:              id,
		Value:           value,
		ValueHash:       valueHash,
		Type:            models.IndicatorType(typeStr),
		Severity:        models.Severity(severityStr),
		Confidence:      numericToFloat(confidence),
		Description:     nullTextToString(description),
		Tags:            tags,
		Platforms:       stringsToPlatforms(platforms),
		FirstSeen:       timestamptzToTime(firstSeen),
		LastSeen:        timestamptzToTime(lastSeen),
		ExpiresAt:       timestamptzToTimePtr(expiresAt),
		CampaignID:      nullUUIDToPtr(campaignID),
		ThreatActorID:   nullUUIDToPtr(threatActorID),
		MalwareFamilyID: nullUUIDToPtr(malwareFamilyID),
		MitreTechniques: mitreTechniques,
		MitreTactics:    mitreTactics,
		CVEIDs:          cveIDs,
		ReportCount:     int(reportCount),
		SourceCount:     int(sourceCount),
		Metadata:        metadata,
		GraphNodeID:     nullTextToString(graphNodeID),
		CreatedAt:       timestamptzToTime(createdAt),
		UpdatedAt:       timestamptzToTime(updatedAt),
	}
}

// listIndicatorsRowToModel converts a ListIndicatorsRow to a model
func listIndicatorsRowToModel(r *db.ListIndicatorsRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// listPegasusIndicatorsRowToModel converts a ListPegasusIndicatorsRow to a model
func listPegasusIndicatorsRowToModel(r *db.ListPegasusIndicatorsRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// listMobileIndicatorsRowToModel converts a ListMobileIndicatorsRow to a model
func listMobileIndicatorsRowToModel(r *db.ListMobileIndicatorsRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// listCriticalIndicatorsRowToModel converts a ListCriticalIndicatorsRow to a model
func listCriticalIndicatorsRowToModel(r *db.ListCriticalIndicatorsRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// listIndicatorsByCampaignRowToModel converts a ListIndicatorsByCampaignRow to a model
func listIndicatorsByCampaignRowToModel(r *db.ListIndicatorsByCampaignRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// getIndicatorByIDRowToModel converts a GetIndicatorByIDRow to a model
func getIndicatorByIDRowToModel(r *db.GetIndicatorByIDRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// getIndicatorByHashRowToModel converts a GetIndicatorByHashRow to a model
func getIndicatorByHashRowToModel(r *db.GetIndicatorByHashRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// getIndicatorByValueRowToModel converts a GetIndicatorByValueRow to a model
func getIndicatorByValueRowToModel(r *db.GetIndicatorByValueRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// createIndicatorRowToModel converts a CreateIndicatorRow to a model
func createIndicatorRowToModel(r *db.CreateIndicatorRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// upsertIndicatorRowToModel converts a UpsertIndicatorRow to a model
func upsertIndicatorRowToModel(r *db.UpsertIndicatorRow) *models.Indicator {
	ind := convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
	// Set source fields from the row
	ind.SourceID = r.SourceID
	ind.SourceName = r.SourceName
	return ind
}

// searchIndicatorsRowToModel converts a SearchIndicatorsRow to a model
func searchIndicatorsRowToModel(r *db.SearchIndicatorsRow) *models.Indicator {
	return convertIndicatorRow(
		r.ID, r.Value, r.ValueHash, r.Type, r.Severity,
		r.Confidence, r.Description, r.Tags, r.Platforms,
		r.FirstSeen, r.LastSeen, r.ExpiresAt,
		r.CampaignID, r.ThreatActorID, r.MalwareFamilyID,
		r.MitreTechniques, r.MitreTactics, r.CveIds,
		r.ReportCount, r.SourceCount, r.Metadata, r.GraphNodeID,
		r.CreatedAt, r.UpdatedAt,
	)
}

// scanIndicatorRow scans a row from a query with casted string types
func scanIndicatorRow(rows pgx.Rows) (*models.Indicator, error) {
	var (
		id              uuid.UUID
		value           string
		valueHash       string
		typeStr         string
		severityStr     string
		confidence      pgtype.Numeric
		description     pgtype.Text
		tags            []string
		platforms       []string
		firstSeen       pgtype.Timestamptz
		lastSeen        pgtype.Timestamptz
		expiresAt       pgtype.Timestamptz
		campaignID      pgtype.UUID
		threatActorID   pgtype.UUID
		malwareFamilyID pgtype.UUID
		mitreTechniques []string
		mitreTactics    []string
		cveIDs          []string
		reportCount     int32
		sourceCount     int32
		metadata        []byte
		graphNodeID     pgtype.Text
		createdAt       pgtype.Timestamptz
		updatedAt       pgtype.Timestamptz
	)

	err := rows.Scan(
		&id, &value, &valueHash, &typeStr, &severityStr, &confidence, &description,
		&tags, &platforms, &firstSeen, &lastSeen, &expiresAt,
		&campaignID, &threatActorID, &malwareFamilyID,
		&mitreTechniques, &mitreTactics, &cveIDs,
		&reportCount, &sourceCount, &metadata, &graphNodeID,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan indicator: %w", err)
	}

	return convertIndicatorRow(
		id, value, valueHash, typeStr, severityStr,
		confidence, description, tags, platforms,
		firstSeen, lastSeen, expiresAt,
		campaignID, threatActorID, malwareFamilyID,
		mitreTechniques, mitreTactics, cveIDs,
		reportCount, sourceCount, metadata, graphNodeID,
		createdAt, updatedAt,
	), nil
}
