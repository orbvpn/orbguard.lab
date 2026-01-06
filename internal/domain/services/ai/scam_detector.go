package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// ScamDetector is the main AI-powered scam detection service
type ScamDetector struct {
	logger           *logger.Logger
	llmClient        *LLMClient
	visionAnalyzer   *VisionAnalyzer
	speechAnalyzer   *SpeechAnalyzer
	intentClassifier *IntentClassifier
	entityExtractor  *EntityExtractor
	patternDB        *ScamPatternDB
	phoneReputation  *PhoneReputationService
	languageDetector *LanguageDetector
	config           ScamDetectorConfig

	// Statistics
	stats ScamDetectorStats
	statsMu sync.RWMutex
}

// ScamDetectorConfig contains configuration for the scam detector
type ScamDetectorConfig struct {
	// LLM settings
	ClaudeAPIKey     string
	OpenAIAPIKey     string
	LLMProvider      string // "claude" or "openai"

	// Feature flags
	EnableVision     bool
	EnableSpeech     bool
	EnablePhoneRep   bool
	EnablePatternDB  bool
	EnableLLM        bool

	// Thresholds
	ScamThreshold    float64 // Score above this is considered scam
	SuspiciousThresh float64 // Score above this is suspicious

	// Multi-language
	SupportedLanguages []string

	// Cache
	EnableCache      bool
	CacheTTL         time.Duration
}

// ScamDetectorStats contains statistics about scam detection
type ScamDetectorStats struct {
	TotalAnalyzed    int64
	ScamsDetected    int64
	SuspiciousFound  int64
	ByType           map[models.ScamType]int64
	BySeverity       map[models.ScamSeverity]int64
	AvgConfidence    float64
	AvgProcessingMs  float64
}

// NewScamDetector creates a new scam detector
func NewScamDetector(log *logger.Logger, config ScamDetectorConfig) *ScamDetector {
	detector := &ScamDetector{
		logger: log.WithComponent("scam-detector"),
		config: config,
		stats: ScamDetectorStats{
			ByType:     make(map[models.ScamType]int64),
			BySeverity: make(map[models.ScamSeverity]int64),
		},
	}

	// Set default thresholds
	if config.ScamThreshold == 0 {
		config.ScamThreshold = 0.7
	}
	if config.SuspiciousThresh == 0 {
		config.SuspiciousThresh = 0.4
	}

	// Initialize components
	if config.EnableLLM {
		llmConfig := LLMConfig{
			ClaudeAPIKey: config.ClaudeAPIKey,
			OpenAIAPIKey: config.OpenAIAPIKey,
			Provider:     config.LLMProvider,
		}
		detector.llmClient = NewLLMClient(llmConfig, log)
	}

	if config.EnablePatternDB {
		detector.patternDB = NewScamPatternDB(log)
	}

	if config.EnableVision && detector.llmClient != nil {
		visionConfig := VisionConfig{
			ClaudeAPIKey: config.ClaudeAPIKey,
			OpenAIAPIKey: config.OpenAIAPIKey,
			Provider:     config.LLMProvider,
		}
		detector.visionAnalyzer = NewVisionAnalyzer(log, detector.llmClient, visionConfig)
	}

	if config.EnableSpeech && detector.llmClient != nil {
		speechConfig := SpeechAnalyzerConfig{
			OpenAIAPIKey:     config.OpenAIAPIKey,
			Provider:         "openai",
			EnableTranscript: true,
		}
		detector.speechAnalyzer = NewSpeechAnalyzer(log, detector.llmClient, speechConfig)
	}

	detector.intentClassifier = NewIntentClassifier(log, detector.llmClient, detector.patternDB)
	detector.entityExtractor = NewEntityExtractor(log, detector.llmClient)

	if config.EnablePhoneRep {
		phoneConfig := PhoneReputationConfig{
			EnableLocalDB: true,
			CacheTTL:      24 * time.Hour,
		}
		detector.phoneReputation = NewPhoneReputationService(log, phoneConfig)
	}

	// Initialize language detector
	detector.languageDetector = NewLanguageDetector(log)

	return detector
}

// Analyze performs comprehensive scam analysis on content
func (d *ScamDetector) Analyze(ctx context.Context, req *models.ScamAnalysisRequest) (*models.ScamAnalysisResult, error) {
	startTime := time.Now()

	result := &models.ScamAnalysisResult{
		RequestID:   req.ID,
		ContentType: req.ContentType,
		Timestamp:   time.Now(),
		Severity:    models.ScamSeverityNone,
	}

	// Detect language
	if d.languageDetector != nil && req.Content != "" {
		lang := d.languageDetector.Detect(req.Content)
		result.Language = lang
		req.Language = lang
	}

	// Route to appropriate analyzer based on content type
	var err error
	switch req.ContentType {
	case models.ContentTypeText, models.ContentTypeSMS, models.ContentTypeEmail:
		err = d.analyzeText(ctx, req, result)
	case models.ContentTypeURL:
		err = d.analyzeURL(ctx, req, result)
	case models.ContentTypeImage:
		err = d.analyzeImage(ctx, req, result)
	case models.ContentTypeVoice:
		err = d.analyzeVoice(ctx, req, result)
	case models.ContentTypePhone:
		err = d.analyzePhone(ctx, req, result)
	default:
		// Try text analysis as fallback
		err = d.analyzeText(ctx, req, result)
	}

	if err != nil {
		d.logger.Error().Err(err).Str("content_type", string(req.ContentType)).Msg("Analysis failed")
		return nil, err
	}

	// Finalize result
	d.finalizeResult(result, startTime)

	// Update statistics
	d.updateStats(result)

	return result, nil
}

// analyzeText analyzes text content for scams
func (d *ScamDetector) analyzeText(ctx context.Context, req *models.ScamAnalysisRequest, result *models.ScamAnalysisResult) error {
	content := req.Content

	// Pattern matching
	if d.patternDB != nil {
		matches := d.patternDB.MatchWithLanguage(content, req.Language)
		if len(matches) > 0 {
			result.RiskScore = d.patternDB.CalculateScamScore(matches)
			result.ScamType = d.patternDB.GetMostLikelyScamType(matches)
			result.Severity = d.patternDB.GetHighestSeverity(matches)

			for _, m := range matches {
				result.Indicators = append(result.Indicators, models.ScamIndicator{
					Type:        string(m.Category),
					Description: m.PatternName,
					Confidence:  m.Weight,
					Evidence:    strings.Join(m.Matches, ", "),
				})
			}
		}
	}

	// Intent classification
	if d.intentClassifier != nil {
		intent, err := d.intentClassifier.ClassifyIntent(ctx, content, req.ContentType)
		if err == nil {
			result.Intent = &models.IntentAnalysis{
				PrimaryIntent: string(intent.PrimaryIntent),
				Confidence:    intent.Confidence,
				IsScam:        intent.IsScam,
				RiskScore:     intent.RiskScore,
			}

			if intent.IsScam && intent.Confidence > result.RiskScore {
				result.RiskScore = intent.RiskScore
				result.IsScam = true
			}

			if intent.Manipulation != nil && intent.Manipulation.IsManipulative {
				result.Manipulation = &models.ManipulationAnalysis{
					IsManipulative: true,
					Severity:       intent.Manipulation.OverallSeverity,
				}
				for _, tech := range intent.Manipulation.Techniques {
					result.Manipulation.Techniques = append(result.Manipulation.Techniques, models.ManipulationTechnique{
						Name:        tech.Name,
						Description: tech.Description,
						Severity:    tech.Severity,
					})
				}
			}

			// Add urgency info
			if intent.UrgencyLevel != UrgencyNone {
				result.UrgencyLevel = string(intent.UrgencyLevel)
			}
		}
	}

	// Entity extraction
	if d.entityExtractor != nil {
		entities, err := d.entityExtractor.ExtractFromRequest(ctx, req)
		if err == nil && entities != nil {
			result.Entities = entities

			// Check phone numbers for reputation
			if d.phoneReputation != nil {
				for i, phone := range entities.PhoneNumbers {
					rep, err := d.phoneReputation.Lookup(ctx, phone.Number)
					if err == nil && rep != nil {
						entities.PhoneNumbers[i].IsSuspicious = rep.IsScam || rep.IsSpam
						if rep.IsScam {
							result.Indicators = append(result.Indicators, models.ScamIndicator{
								Type:        "known_scam_phone",
								Description: fmt.Sprintf("Phone number %s is a known scam number", phone.Number),
								Confidence:  0.95,
								Evidence:    phone.Number,
							})
							result.RiskScore = maxFloat(result.RiskScore, 0.9)
						}
					}
				}
			}

			// Check for suspicious URLs
			for _, url := range entities.URLs {
				if url.IsSuspicious {
					result.Indicators = append(result.Indicators, models.ScamIndicator{
						Type:        "suspicious_url",
						Description: fmt.Sprintf("Suspicious URL detected: %s", url.Reason),
						Confidence:  0.8,
						Evidence:    url.URL,
					})
				}
			}

			// Check for crypto addresses (suspicious in unsolicited messages)
			if len(entities.CryptoAddresses) > 0 {
				result.Indicators = append(result.Indicators, models.ScamIndicator{
					Type:        "crypto_address",
					Description: "Cryptocurrency address found in message",
					Confidence:  0.7,
					Evidence:    entities.CryptoAddresses[0].Address,
				})
			}
		}
	}

	// LLM analysis for complex cases
	if d.llmClient != nil && result.RiskScore >= d.config.SuspiciousThresh {
		llmAnalysis, err := d.llmClient.AnalyzeForScam(ctx, req)
		if err == nil {
			// Merge LLM analysis
			if llmAnalysis.IsScam && llmAnalysis.Confidence > result.RiskScore {
				result.RiskScore = llmAnalysis.Confidence
				result.IsScam = true
				result.ScamType = llmAnalysis.ScamType
			}

			if llmAnalysis.Explanation != "" {
				result.Explanation = llmAnalysis.Explanation
			}

			result.Indicators = append(result.Indicators, llmAnalysis.Indicators...)
		}
	}

	return nil
}

// analyzeURL analyzes a URL for scams
func (d *ScamDetector) analyzeURL(ctx context.Context, req *models.ScamAnalysisRequest, result *models.ScamAnalysisResult) error {
	// Extract and analyze the URL
	entities, err := d.entityExtractor.Extract(ctx, req.Content)
	if err != nil {
		return err
	}

	if len(entities.URLs) == 0 {
		result.Explanation = "No valid URL found in content"
		return nil
	}

	url := entities.URLs[0]

	// Check URL characteristics
	if url.IsSuspicious {
		result.RiskScore = 0.7
		for _, reason := range url.SuspiciousReasons {
			result.Indicators = append(result.Indicators, models.ScamIndicator{
				Type:        "url_" + reason,
				Description: fmt.Sprintf("URL flagged for: %s", reason),
				Confidence:  0.8,
				Evidence:    url.Raw,
			})
		}
	}

	// Check for brand impersonation
	if url.LooksLike != "" {
		result.RiskScore = maxFloat(result.RiskScore, 0.9)
		result.ScamType = models.ScamTypePhishing
		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "brand_impersonation",
			Description: fmt.Sprintf("URL appears to impersonate %s", url.LooksLike),
			Confidence:  0.85,
			Evidence:    url.Raw,
		})
	}

	// Additional URL analysis could include:
	// - Domain age check
	// - SSL certificate validation
	// - Page content analysis (if vision enabled)

	// Convert to model entities
	result.Entities = &models.ExtractedEntities{
		URLs: []models.URLEntity{{
			URL:          url.Raw,
			Domain:       url.Domain,
			IsSuspicious: url.IsSuspicious,
			Reason:       strings.Join(url.SuspiciousReasons, ", "),
		}},
	}

	return nil
}

// analyzeImage analyzes an image for scams
func (d *ScamDetector) analyzeImage(ctx context.Context, req *models.ScamAnalysisRequest, result *models.ScamAnalysisResult) error {
	if d.visionAnalyzer == nil {
		return fmt.Errorf("vision analysis not enabled")
	}

	if len(req.ImageData) == 0 {
		return fmt.Errorf("no image data provided")
	}

	visionResult, err := d.visionAnalyzer.AnalyzeImage(ctx, req.ImageData, req.MimeType)
	if err != nil {
		return err
	}

	// Map vision result to scam result
	result.IsScam = visionResult.IsScam
	result.RiskScore = visionResult.Confidence
	result.ScamType = visionResult.ScamType
	result.Severity = visionResult.Severity
	result.Explanation = visionResult.Explanation

	// Convert red flags to indicators
	for _, flag := range visionResult.RedFlags {
		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "visual_red_flag",
			Description: flag,
			Confidence:  visionResult.Confidence,
		})
	}

	// Add visual indicators
	for _, vi := range visionResult.VisualIndicators {
		if vi.IsRedFlag {
			result.Indicators = append(result.Indicators, models.ScamIndicator{
				Type:        vi.Type,
				Description: vi.Description,
				Confidence:  vi.Confidence,
			})
		}
	}

	// Add brand imitation info
	if visionResult.BrandImitation != nil && visionResult.BrandImitation.Detected {
		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "brand_imitation",
			Description: fmt.Sprintf("Imitating %s", visionResult.BrandImitation.ImitatedBrand),
			Confidence:  visionResult.BrandImitation.Confidence,
			Evidence:    strings.Join(visionResult.BrandImitation.Discrepancies, ", "),
		})
	}

	// Extract entities from OCR text
	if visionResult.ExtractedText != "" {
		entities, _ := d.entityExtractor.Extract(ctx, visionResult.ExtractedText)
		if entities != nil {
			result.Entities = &models.ExtractedEntities{}
			for _, url := range entities.URLs {
				result.Entities.URLs = append(result.Entities.URLs, models.URLEntity{
					URL:          url.Raw,
					Domain:       url.Domain,
					IsSuspicious: url.IsSuspicious,
				})
			}
		}
	}

	return nil
}

// analyzeVoice analyzes voice content for scams
func (d *ScamDetector) analyzeVoice(ctx context.Context, req *models.ScamAnalysisRequest, result *models.ScamAnalysisResult) error {
	if d.speechAnalyzer == nil {
		return fmt.Errorf("speech analysis not enabled")
	}

	if len(req.AudioData) == 0 {
		return fmt.Errorf("no audio data provided")
	}

	speechResult, err := d.speechAnalyzer.AnalyzeAudio(ctx, req.AudioData, req.MimeType)
	if err != nil {
		return err
	}

	// Map speech result to scam result
	result.IsScam = speechResult.IsScam
	result.RiskScore = speechResult.ScamConfidence
	result.ScamType = speechResult.ScamType
	result.Severity = speechResult.Severity
	result.Explanation = speechResult.Explanation

	// Add transcript
	result.Transcript = speechResult.Transcript
	result.Language = speechResult.TranscriptLang

	// Convert red flags to indicators
	for _, flag := range speechResult.RedFlags {
		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "audio_red_flag",
			Description: flag,
			Confidence:  speechResult.ScamConfidence,
		})
	}

	// Add content analysis
	if speechResult.ContentAnalysis != nil {
		for _, threat := range speechResult.ContentAnalysis.Threats {
			result.Indicators = append(result.Indicators, models.ScamIndicator{
				Type:        "threat",
				Description: threat,
				Confidence:  0.9,
			})
		}
	}

	// Map entities
	if speechResult.ExtractedEntities != nil {
		result.Entities = &models.ExtractedEntities{}
		for _, phone := range speechResult.ExtractedEntities.PhoneNumbers {
			result.Entities.PhoneNumbers = append(result.Entities.PhoneNumbers, models.PhoneEntity{
				Number:       phone.Raw,
				CountryCode:  phone.CountryCode,
				IsSuspicious: phone.IsSuspicious,
			})
		}
	}

	return nil
}

// analyzePhone analyzes a phone number for scams
func (d *ScamDetector) analyzePhone(ctx context.Context, req *models.ScamAnalysisRequest, result *models.ScamAnalysisResult) error {
	if d.phoneReputation == nil {
		return fmt.Errorf("phone reputation service not enabled")
	}

	rep, err := d.phoneReputation.Lookup(ctx, req.Content)
	if err != nil {
		return err
	}

	result.Entities = &models.ExtractedEntities{
		PhoneNumbers: []models.PhoneEntity{{
			Number:       rep.Number,
			CountryCode:  rep.CountryCode,
			IsSuspicious: rep.IsScam || rep.IsSpam,
		}},
	}

	// Map reputation to result
	if rep.IsScam {
		result.IsScam = true
		result.RiskScore = 0.95
		result.Severity = models.ScamSeverityCritical

		if rep.ScamInfo != nil {
			result.ScamType = models.ScamType(rep.ScamInfo.ScamType)
			result.Explanation = rep.ScamInfo.Description
		}

		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "known_scam_number",
			Description: "This phone number is in our scam database",
			Confidence:  rep.Confidence,
			Evidence:    rep.Number,
		})
	} else if rep.IsSpam {
		result.RiskScore = 0.7
		result.Severity = models.ScamSeverityMedium
		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "spam_number",
			Description: "This phone number has been reported for spam",
			Confidence:  0.8,
		})
	} else if rep.IsPremiumRate {
		result.RiskScore = 0.6
		result.Severity = models.ScamSeverityMedium
		result.Indicators = append(result.Indicators, models.ScamIndicator{
			Type:        "premium_rate",
			Description: "This is a premium rate number - calling may incur charges",
			Confidence:  0.9,
		})
	} else {
		result.RiskScore = 1 - (rep.ReputationScore / 100)
	}

	// Add phone metadata to explanation
	info := []string{}
	if rep.CountryName != "" {
		info = append(info, fmt.Sprintf("Country: %s", rep.CountryName))
	}
	if rep.Carrier != "" {
		info = append(info, fmt.Sprintf("Carrier: %s", rep.Carrier))
	}
	if rep.LineType != "" {
		info = append(info, fmt.Sprintf("Type: %s", rep.LineType))
	}
	if len(info) > 0 {
		result.Explanation = strings.Join(info, ", ")
	}

	return nil
}

// finalizeResult finalizes the analysis result
func (d *ScamDetector) finalizeResult(result *models.ScamAnalysisResult, startTime time.Time) {
	// Determine if it's a scam based on threshold
	if result.RiskScore >= d.config.ScamThreshold {
		result.IsScam = true
	}

	// Determine severity if not already set
	if result.Severity == models.ScamSeverityNone && result.RiskScore > 0 {
		if result.RiskScore >= 0.9 {
			result.Severity = models.ScamSeverityCritical
		} else if result.RiskScore >= 0.7 {
			result.Severity = models.ScamSeverityHigh
		} else if result.RiskScore >= 0.5 {
			result.Severity = models.ScamSeverityMedium
		} else if result.RiskScore >= 0.3 {
			result.Severity = models.ScamSeverityLow
		}
	}

	// Generate recommendation
	result.Recommendation = d.generateRecommendation(result)

	// Calculate processing time
	result.ProcessingTime = time.Since(startTime)
}

// generateRecommendation generates a recommendation based on the analysis
func (d *ScamDetector) generateRecommendation(result *models.ScamAnalysisResult) string {
	if !result.IsScam && result.RiskScore < d.config.SuspiciousThresh {
		return "This content appears to be safe. However, always exercise caution with unsolicited messages."
	}

	recommendations := []string{}

	if result.IsScam {
		recommendations = append(recommendations, "⚠️ HIGH ALERT: This appears to be a scam.")

		switch result.ScamType {
		case models.ScamTypePhishing:
			recommendations = append(recommendations, "Do NOT click any links or provide personal information.")
			recommendations = append(recommendations, "Verify the sender through official channels.")
		case models.ScamTypeTechSupport:
			recommendations = append(recommendations, "Do NOT call any phone numbers provided.")
			recommendations = append(recommendations, "Legitimate companies don't call about virus infections.")
		case models.ScamTypeInvestment, models.ScamTypeCrypto:
			recommendations = append(recommendations, "Do NOT send any money or cryptocurrency.")
			recommendations = append(recommendations, "Guaranteed returns are always a scam.")
		case models.ScamTypeRomance:
			recommendations = append(recommendations, "Be extremely cautious with online relationships.")
			recommendations = append(recommendations, "Never send money to someone you haven't met in person.")
		case models.ScamTypeAdvanceFee, models.ScamTypeLottery:
			recommendations = append(recommendations, "You cannot win a lottery you didn't enter.")
			recommendations = append(recommendations, "Never pay fees to receive prizes or inheritances.")
		case models.ScamTypeImpersonation:
			recommendations = append(recommendations, "Verify the sender's identity through official channels.")
			recommendations = append(recommendations, "Government agencies don't threaten arrest via phone/email.")
		default:
			recommendations = append(recommendations, "Do not engage with this content.")
		}

		recommendations = append(recommendations, "Report this to the relevant authorities.")

	} else if result.RiskScore >= d.config.SuspiciousThresh {
		recommendations = append(recommendations, "⚠️ This content has suspicious characteristics.")
		recommendations = append(recommendations, "Proceed with caution and verify through official channels.")
	}

	return strings.Join(recommendations, "\n")
}

// updateStats updates detection statistics
func (d *ScamDetector) updateStats(result *models.ScamAnalysisResult) {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()

	d.stats.TotalAnalyzed++

	if result.IsScam {
		d.stats.ScamsDetected++
		d.stats.ByType[result.ScamType]++
	} else if result.RiskScore >= d.config.SuspiciousThresh {
		d.stats.SuspiciousFound++
	}

	d.stats.BySeverity[result.Severity]++

	// Update average confidence
	d.stats.AvgConfidence = (d.stats.AvgConfidence*float64(d.stats.TotalAnalyzed-1) + result.RiskScore) / float64(d.stats.TotalAnalyzed)

	// Update average processing time
	d.stats.AvgProcessingMs = (d.stats.AvgProcessingMs*float64(d.stats.TotalAnalyzed-1) + float64(result.ProcessingTime.Milliseconds())) / float64(d.stats.TotalAnalyzed)
}

// GetStats returns current detection statistics
func (d *ScamDetector) GetStats() ScamDetectorStats {
	d.statsMu.RLock()
	defer d.statsMu.RUnlock()

	// Return a copy
	stats := ScamDetectorStats{
		TotalAnalyzed:   d.stats.TotalAnalyzed,
		ScamsDetected:   d.stats.ScamsDetected,
		SuspiciousFound: d.stats.SuspiciousFound,
		AvgConfidence:   d.stats.AvgConfidence,
		AvgProcessingMs: d.stats.AvgProcessingMs,
		ByType:          make(map[models.ScamType]int64),
		BySeverity:      make(map[models.ScamSeverity]int64),
	}

	for k, v := range d.stats.ByType {
		stats.ByType[k] = v
	}
	for k, v := range d.stats.BySeverity {
		stats.BySeverity[k] = v
	}

	return stats
}

// ReportScam reports a scam for improving detection
func (d *ScamDetector) ReportScam(ctx context.Context, report *models.ScamReport) error {
	// Add to pattern database if it's a new pattern
	if d.patternDB != nil && report.NewPattern != "" {
		d.patternDB.AddPattern(ScamPattern{
			ID:              fmt.Sprintf("user-%d", time.Now().Unix()),
			Name:            "User reported pattern",
			Description:     report.Description,
			Category:        report.ScamType,
			Severity:        models.ScamSeverityHigh,
			Keywords:        []string{report.NewPattern},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
		})
	}

	// Add phone number to scam database
	if d.phoneReputation != nil && report.PhoneNumber != "" {
		d.phoneReputation.ReportNumber(report.PhoneNumber, "scam", report.Description, string(report.ScamType))
	}

	d.logger.Info().
		Str("type", string(report.ScamType)).
		Str("phone", report.PhoneNumber).
		Str("description", report.Description).
		Msg("Scam reported")

	return nil
}

// AnalyzeBatch analyzes multiple items in batch
func (d *ScamDetector) AnalyzeBatch(ctx context.Context, requests []*models.ScamAnalysisRequest) ([]*models.ScamAnalysisResult, error) {
	results := make([]*models.ScamAnalysisResult, len(requests))

	// Process in parallel with limited concurrency
	const maxConcurrency = 5
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, req := range requests {
		wg.Add(1)
		go func(idx int, r *models.ScamAnalysisRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := d.Analyze(ctx, r)
			if err != nil {
				d.logger.Warn().Err(err).Int("index", idx).Msg("Batch analysis failed")
				results[idx] = &models.ScamAnalysisResult{
					RequestID: r.ID,
					Severity:  models.ScamSeverityNone,
					Explanation: fmt.Sprintf("Analysis failed: %v", err),
				}
			} else {
				results[idx] = result
			}
		}(i, req)
	}

	wg.Wait()
	return results, nil
}
