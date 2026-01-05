package services

import (
	"math"
	"strings"
	"time"

	"orbguard-lab/internal/config"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// Scorer calculates confidence scores for indicators
type Scorer struct {
	config config.ScoringConfig
	logger *logger.Logger
}

// NewScorer creates a new Scorer
func NewScorer(cfg config.ScoringConfig, log *logger.Logger) *Scorer {
	return &Scorer{
		config: cfg,
		logger: log.WithComponent("scorer"),
	}
}

// ScoreIndicator calculates a confidence score for an indicator
func (s *Scorer) ScoreIndicator(indicator *models.Indicator, sources []models.IndicatorSource) float64 {
	var score float64

	// 1. Source reliability score (weighted average of source reliabilities)
	sourceScore := s.calculateSourceScore(sources)
	score += sourceScore * s.config.Weights.SourceReliability

	// 2. Source count score (more sources = higher confidence)
	countScore := s.calculateSourceCountScore(len(sources))
	score += countScore * s.config.Weights.SourceCount

	// 3. Recency score (more recent = higher confidence)
	recencyScore := s.calculateRecencyScore(indicator.LastSeen)
	score += recencyScore * s.config.Weights.Recency

	// 4. Report count score (more reports = higher confidence)
	reportScore := s.calculateReportCountScore(indicator.ReportCount)
	score += reportScore * s.config.Weights.ReportCount

	// 5. Source confidence score (average of source-provided confidences)
	srcConfScore := s.calculateSourceConfidenceScore(sources)
	score += srcConfScore * s.config.Weights.SourceConfidence

	// Apply bonuses
	score = s.applyBonuses(score, indicator)

	// Clamp to [0, 1]
	return clamp(score, 0, 1)
}

// calculateSourceScore calculates the weighted average of source reliabilities
func (s *Scorer) calculateSourceScore(sources []models.IndicatorSource) float64 {
	if len(sources) == 0 {
		return 0.5 // Default reliability
	}

	var totalWeight float64
	var weightedSum float64

	for _, src := range sources {
		reliability, ok := s.config.SourceReliability[src.SourceName]
		if !ok {
			reliability = 0.5 // Default reliability for unknown sources
		}

		// Weight by source confidence
		weight := src.SourceConfidence
		if weight == 0 {
			weight = 1.0
		}

		weightedSum += reliability * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0.5
	}

	return weightedSum / totalWeight
}

// calculateSourceCountScore calculates score based on number of sources
func (s *Scorer) calculateSourceCountScore(count int) float64 {
	// Logarithmic scale: 1 source = 0.5, 2 = 0.7, 3+ = 0.8+
	if count == 0 {
		return 0.3
	}
	if count == 1 {
		return 0.5
	}

	// log2(count) / log2(10) gives diminishing returns
	return clamp(0.5+0.3*math.Log2(float64(count))/3.32, 0, 1)
}

// calculateRecencyScore calculates score based on how recent the indicator is
func (s *Scorer) calculateRecencyScore(lastSeen time.Time) float64 {
	age := time.Since(lastSeen)

	switch {
	case age < 24*time.Hour:
		return 1.0 // Very fresh
	case age < 7*24*time.Hour:
		return 0.9 // Within a week
	case age < 30*24*time.Hour:
		return 0.7 // Within a month
	case age < 90*24*time.Hour:
		return 0.5 // Within 3 months
	case age < 365*24*time.Hour:
		return 0.3 // Within a year
	default:
		return 0.1 // Old
	}
}

// calculateReportCountScore calculates score based on number of reports
func (s *Scorer) calculateReportCountScore(count int) float64 {
	if count == 0 {
		return 0.5
	}

	// Logarithmic scale with diminishing returns
	return clamp(0.5+0.3*math.Log10(float64(count+1)), 0, 1)
}

// calculateSourceConfidenceScore calculates the average of source-provided confidences
func (s *Scorer) calculateSourceConfidenceScore(sources []models.IndicatorSource) float64 {
	if len(sources) == 0 {
		return 0.5
	}

	var total float64
	for _, src := range sources {
		if src.SourceConfidence > 0 {
			total += src.SourceConfidence
		} else {
			total += 0.5 // Default if not provided
		}
	}

	return total / float64(len(sources))
}

// applyBonuses applies bonus multipliers for special indicators
func (s *Scorer) applyBonuses(score float64, indicator *models.Indicator) float64 {
	// Pegasus bonus
	if indicator.IsPegasus() {
		score *= s.config.Bonuses.Pegasus
	}

	// CVE-linked bonus
	if len(indicator.CVEIDs) > 0 {
		score *= s.config.Bonuses.CVELinked
	}

	// Known malware family bonus
	if indicator.MalwareFamilyID != nil {
		score *= s.config.Bonuses.KnownFamily
	}

	return score
}

// InferSeverity infers the severity level based on score and other factors
func (s *Scorer) InferSeverity(score float64, indicator *models.Indicator) models.Severity {
	// Check for critical indicators first
	if indicator.IsPegasus() || s.hasCriticalTag(indicator) {
		return models.SeverityCritical
	}

	// Score-based severity
	switch {
	case score >= 0.9:
		return models.SeverityCritical
	case score >= 0.7:
		return models.SeverityHigh
	case score >= 0.5:
		return models.SeverityMedium
	case score >= 0.3:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// hasCriticalTag checks if the indicator has any critical tags
func (s *Scorer) hasCriticalTag(indicator *models.Indicator) bool {
	criticalTags := []string{
		"pegasus", "predator", "hermit", "nso-group",
		"apt", "ransomware", "zero-day", "exploit",
		"c2", "command-and-control",
	}

	for _, tag := range indicator.Tags {
		tagLower := strings.ToLower(tag)
		for _, critical := range criticalTags {
			if tagLower == critical {
				return true
			}
		}
	}

	return false
}

// ScoreResult represents the result of scoring an indicator
type ScoreResult struct {
	FinalScore        float64 `json:"final_score"`
	SourceScore       float64 `json:"source_score"`
	SourceCountScore  float64 `json:"source_count_score"`
	RecencyScore      float64 `json:"recency_score"`
	ReportCountScore  float64 `json:"report_count_score"`
	SourceConfScore   float64 `json:"source_conf_score"`
	BonusMultiplier   float64 `json:"bonus_multiplier"`
	InferredSeverity  models.Severity `json:"inferred_severity"`
}

// ScoreIndicatorDetailed returns a detailed breakdown of the scoring
func (s *Scorer) ScoreIndicatorDetailed(indicator *models.Indicator, sources []models.IndicatorSource) ScoreResult {
	sourceScore := s.calculateSourceScore(sources)
	countScore := s.calculateSourceCountScore(len(sources))
	recencyScore := s.calculateRecencyScore(indicator.LastSeen)
	reportScore := s.calculateReportCountScore(indicator.ReportCount)
	srcConfScore := s.calculateSourceConfidenceScore(sources)

	baseScore := sourceScore*s.config.Weights.SourceReliability +
		countScore*s.config.Weights.SourceCount +
		recencyScore*s.config.Weights.Recency +
		reportScore*s.config.Weights.ReportCount +
		srcConfScore*s.config.Weights.SourceConfidence

	// Calculate bonus multiplier
	bonusMultiplier := 1.0
	if indicator.IsPegasus() {
		bonusMultiplier *= s.config.Bonuses.Pegasus
	}
	if len(indicator.CVEIDs) > 0 {
		bonusMultiplier *= s.config.Bonuses.CVELinked
	}
	if indicator.MalwareFamilyID != nil {
		bonusMultiplier *= s.config.Bonuses.KnownFamily
	}

	finalScore := clamp(baseScore*bonusMultiplier, 0, 1)

	return ScoreResult{
		FinalScore:       finalScore,
		SourceScore:      sourceScore,
		SourceCountScore: countScore,
		RecencyScore:     recencyScore,
		ReportCountScore: reportScore,
		SourceConfScore:  srcConfScore,
		BonusMultiplier:  bonusMultiplier,
		InferredSeverity: s.InferSeverity(finalScore, indicator),
	}
}

// clamp clamps a value between min and max
func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
