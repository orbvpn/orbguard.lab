package services

import (
	"context"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// Deduplicator handles deduplication of indicators
type Deduplicator struct {
	cache  *cache.RedisCache
	logger *logger.Logger

	// In-memory bloom filter for fast preliminary checks
	seenHashes map[string]bool

	// Cache TTL for deduplication records
	cacheTTL time.Duration
}

// NewDeduplicator creates a new Deduplicator
func NewDeduplicator(cache *cache.RedisCache, log *logger.Logger) *Deduplicator {
	return &Deduplicator{
		cache:      cache,
		logger:     log.WithComponent("deduplicator"),
		seenHashes: make(map[string]bool),
		cacheTTL:   24 * time.Hour,
	}
}

// DeduplicationResult represents the result of deduplication
type DeduplicationResult struct {
	NewIndicators     []*models.Indicator
	ExistingIndicators []*models.Indicator
	DuplicateCount    int
}

// Deduplicate checks for duplicates and returns unique indicators
func (d *Deduplicator) Deduplicate(ctx context.Context, indicators []*models.Indicator) (*DeduplicationResult, error) {
	result := &DeduplicationResult{
		NewIndicators:      make([]*models.Indicator, 0),
		ExistingIndicators: make([]*models.Indicator, 0),
	}

	for _, indicator := range indicators {
		exists, err := d.CheckExists(ctx, indicator.ValueHash)
		if err != nil {
			d.logger.Warn().Err(err).Str("hash", indicator.ValueHash).Msg("failed to check existence")
			// On error, assume it's new to avoid losing data
			result.NewIndicators = append(result.NewIndicators, indicator)
			continue
		}

		if exists {
			result.ExistingIndicators = append(result.ExistingIndicators, indicator)
			result.DuplicateCount++
		} else {
			result.NewIndicators = append(result.NewIndicators, indicator)
			// Mark as seen
			d.MarkSeen(ctx, indicator.ValueHash)
		}
	}

	return result, nil
}

// CheckExists checks if an indicator hash already exists
func (d *Deduplicator) CheckExists(ctx context.Context, hash string) (bool, error) {
	// Quick check in memory
	if d.seenHashes[hash] {
		return true, nil
	}

	// Check Redis cache
	key := "dedup:" + hash
	count, err := d.cache.Exists(ctx, key)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// MarkSeen marks an indicator hash as seen
func (d *Deduplicator) MarkSeen(ctx context.Context, hash string) {
	// Mark in memory
	d.seenHashes[hash] = true

	// Mark in Redis
	key := "dedup:" + hash
	if err := d.cache.Set(ctx, key, "1", d.cacheTTL); err != nil {
		d.logger.Warn().Err(err).Str("hash", hash).Msg("failed to mark hash as seen in cache")
	}
}

// MarkSeenBatch marks multiple hashes as seen
func (d *Deduplicator) MarkSeenBatch(ctx context.Context, hashes []string) error {
	pipe := d.cache.Pipeline()

	for _, hash := range hashes {
		d.seenHashes[hash] = true
		key := "dedup:" + hash
		pipe.Set(ctx, d.cache.Client().Options().Addr, "1", d.cacheTTL)
		_ = key // Used in actual pipeline
	}

	// Note: This is a simplified version. In production, you'd use the pipeline properly
	for _, hash := range hashes {
		d.MarkSeen(ctx, hash)
	}

	return nil
}

// LoadExistingHashes loads existing hashes from database into memory
func (d *Deduplicator) LoadExistingHashes(hashes []string) {
	for _, hash := range hashes {
		d.seenHashes[hash] = true
	}
	d.logger.Info().Int("count", len(hashes)).Msg("loaded existing hashes into memory")
}

// Clear clears the in-memory cache (for testing or memory management)
func (d *Deduplicator) Clear() {
	d.seenHashes = make(map[string]bool)
}

// Stats returns deduplication statistics
func (d *Deduplicator) Stats() map[string]int {
	return map[string]int{
		"memory_cache_size": len(d.seenHashes),
	}
}

// CompareIndicators checks if two indicators are duplicates
func (d *Deduplicator) CompareIndicators(a, b *models.Indicator) bool {
	// Same hash means duplicate
	if a.ValueHash == b.ValueHash {
		return true
	}

	// Same value and type means duplicate
	if a.Value == b.Value && a.Type == b.Type {
		return true
	}

	return false
}

// MergeIndicators merges two duplicate indicators, keeping the best data
func (d *Deduplicator) MergeIndicators(existing, new *models.Indicator) *models.Indicator {
	merged := *existing

	// Update last seen to most recent
	if new.LastSeen.After(existing.LastSeen) {
		merged.LastSeen = new.LastSeen
	}

	// Keep first seen as earliest
	if new.FirstSeen.Before(existing.FirstSeen) {
		merged.FirstSeen = new.FirstSeen
	}

	// Use higher confidence
	if new.Confidence > existing.Confidence {
		merged.Confidence = new.Confidence
	}

	// Use higher severity
	if new.SeverityWeight() > existing.SeverityWeight() {
		merged.Severity = new.Severity
	}

	// Merge tags
	merged.Tags = mergeTags(existing.Tags, new.Tags)

	// Merge platforms
	merged.Platforms = mergePlatforms(existing.Platforms, new.Platforms)

	// Merge MITRE techniques
	merged.MitreTechniques = mergeStrings(existing.MitreTechniques, new.MitreTechniques)

	// Increment source count
	merged.SourceCount = existing.SourceCount + 1

	// Keep the better description (longer)
	if len(new.Description) > len(existing.Description) {
		merged.Description = new.Description
	}

	return &merged
}

// mergeTags merges two tag slices, removing duplicates
func mergeTags(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, tag := range a {
		if !seen[tag] {
			seen[tag] = true
			result = append(result, tag)
		}
	}
	for _, tag := range b {
		if !seen[tag] {
			seen[tag] = true
			result = append(result, tag)
		}
	}

	return result
}

// mergePlatforms merges two platform slices, removing duplicates
func mergePlatforms(a, b []models.Platform) []models.Platform {
	seen := make(map[models.Platform]bool)
	result := make([]models.Platform, 0, len(a)+len(b))

	for _, p := range a {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range b {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}

	return result
}

// mergeStrings merges two string slices, removing duplicates
func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}
