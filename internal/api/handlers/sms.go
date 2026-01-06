package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// SMSHandler handles SMS analysis endpoints
type SMSHandler struct {
	analyzer *services.SMSAnalyzer
	cache    *cache.RedisCache
	logger   *logger.Logger
}

// NewSMSHandler creates a new SMS handler
func NewSMSHandler(repos *repository.Repositories, cache *cache.RedisCache, log *logger.Logger) *SMSHandler {
	return &SMSHandler{
		analyzer: services.NewSMSAnalyzer(repos, cache, log),
		cache:    cache,
		logger:   log.WithComponent("sms-handler"),
	}
}

// AnalyzeRequest is the request body for SMS analysis
type AnalyzeRequest struct {
	Sender    string    `json:"sender"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
}

// AnalyzeBatchRequest is the request body for batch SMS analysis
type AnalyzeBatchRequest struct {
	Messages []AnalyzeRequest `json:"messages"`
	DeviceID string           `json:"device_id,omitempty"`
}

// Analyze handles POST /api/v1/sms/analyze - analyzes a single SMS message
func (h *SMSHandler) Analyze(w http.ResponseWriter, r *http.Request) {
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug().Err(err).Msg("invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Body == "" {
		http.Error(w, "Message body is required", http.StatusBadRequest)
		return
	}

	// Create SMS message
	msg := &models.SMSMessage{
		ID:        uuid.New(),
		Sender:    req.Sender,
		Body:      req.Body,
		Timestamp: req.Timestamp,
		DeviceID:  req.DeviceID,
	}

	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}

	// Analyze
	result, err := h.analyzer.Analyze(r.Context(), msg)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to analyze SMS")
		http.Error(w, "Analysis failed", http.StatusInternalServerError)
		return
	}

	h.logger.Info().
		Bool("is_threat", result.IsThreat).
		Str("threat_level", string(result.ThreatLevel)).
		Str("threat_type", string(result.ThreatType)).
		Msg("SMS analyzed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// AnalyzeBatch handles POST /api/v1/sms/analyze/batch - analyzes multiple SMS messages
func (h *SMSHandler) AnalyzeBatch(w http.ResponseWriter, r *http.Request) {
	var req AnalyzeBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug().Err(err).Msg("invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Messages) == 0 {
		http.Error(w, "At least one message is required", http.StatusBadRequest)
		return
	}

	if len(req.Messages) > 100 {
		http.Error(w, "Maximum 100 messages per batch", http.StatusBadRequest)
		return
	}

	// Convert to models
	messages := make([]models.SMSMessage, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = models.SMSMessage{
			ID:        uuid.New(),
			Sender:    m.Sender,
			Body:      m.Body,
			Timestamp: m.Timestamp,
			DeviceID:  req.DeviceID,
		}
		if messages[i].Timestamp.IsZero() {
			messages[i].Timestamp = time.Now()
		}
	}

	// Analyze batch
	batchReq := &models.SMSBatchAnalysisRequest{
		Messages: messages,
		DeviceID: req.DeviceID,
	}

	result, err := h.analyzer.AnalyzeBatch(r.Context(), batchReq)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to analyze SMS batch")
		http.Error(w, "Analysis failed", http.StatusInternalServerError)
		return
	}

	h.logger.Info().
		Int("total", result.TotalCount).
		Int("threats", result.ThreatCount).
		Msg("SMS batch analyzed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// CheckURL handles POST /api/v1/sms/check-url - checks if a URL is malicious
func (h *SMSHandler) CheckURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Create a minimal message with just the URL
	msg := &models.SMSMessage{
		ID:   uuid.New(),
		Body: req.URL,
	}

	// Analyze - the analyzer will extract and check the URL
	result, err := h.analyzer.Analyze(r.Context(), msg)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to check URL")
		http.Error(w, "Check failed", http.StatusInternalServerError)
		return
	}

	// Return just the URL analysis part
	response := struct {
		URL         string                  `json:"url"`
		IsMalicious bool                    `json:"is_malicious"`
		Category    models.URLCategory      `json:"category"`
		ThreatLevel models.ThreatLevel      `json:"threat_level"`
		Confidence  float64                 `json:"confidence"`
		Details     string                  `json:"details,omitempty"`
		URLs        []models.SMSExtractedURL `json:"urls,omitempty"`
	}{
		URL:         req.URL,
		IsMalicious: result.IsThreat,
		ThreatLevel: result.ThreatLevel,
		Confidence:  result.Confidence,
		URLs:        result.URLs,
	}

	if len(result.URLs) > 0 {
		response.Category = result.URLs[0].Category
		response.Details = result.URLs[0].ThreatDetails
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetPatterns handles GET /api/v1/sms/patterns - returns detection patterns for mobile
func (h *SMSHandler) GetPatterns(w http.ResponseWriter, r *http.Request) {
	// Return pattern info for mobile app to use for local detection
	patterns := struct {
		Version        string   `json:"version"`
		LastUpdated    string   `json:"last_updated"`
		UrgencyWords   []string `json:"urgency_words"`
		FearWords      []string `json:"fear_words"`
		RewardWords    []string `json:"reward_words"`
		PersonalWords  []string `json:"personal_words"`
		FinancialWords []string `json:"financial_words"`
		URLShorteners  []string `json:"url_shorteners"`
		SuspiciousTLDs []string `json:"suspicious_tlds"`
	}{
		Version:     "1.0.0",
		LastUpdated: time.Now().Format(time.RFC3339),
		UrgencyWords: []string{
			"urgent", "immediately", "now", "asap", "expire", "today only",
			"limited time", "act now", "don't wait", "hurry",
		},
		FearWords: []string{
			"suspended", "blocked", "limit", "unusual", "unauthorized",
			"fraud", "stolen", "hacked", "compromised", "alert", "warning",
			"verify your", "confirm your",
		},
		RewardWords: []string{
			"won", "winner", "prize", "gift", "free", "reward",
			"cash", "money", "bonus", "lucky",
		},
		PersonalWords: []string{
			"ssn", "social security", "password", "pin", "dob",
			"date of birth", "mother's maiden", "address",
		},
		FinancialWords: []string{
			"credit card", "debit card", "bank account", "routing number",
			"cvv", "expir", "billing",
		},
		URLShorteners: []string{
			"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
			"is.gd", "buff.ly", "j.mp", "rb.gy", "cutt.ly",
		},
		SuspiciousTLDs: []string{
			".xyz", ".top", ".club", ".work", ".click", ".link",
			".gq", ".ml", ".cf", ".tk", ".ga",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(patterns)
}

// GetStats handles GET /api/v1/sms/stats - returns SMS threat statistics
func (h *SMSHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, these would come from database
	stats := struct {
		TotalAnalyzed    int64            `json:"total_analyzed"`
		ThreatsDetected  int64            `json:"threats_detected"`
		ThreatsByType    map[string]int64 `json:"threats_by_type"`
		ThreatsByLevel   map[string]int64 `json:"threats_by_level"`
		TopScamCategories []struct {
			Category string `json:"category"`
			Count    int64  `json:"count"`
		} `json:"top_scam_categories"`
		Last24Hours struct {
			Analyzed int64 `json:"analyzed"`
			Threats  int64 `json:"threats"`
		} `json:"last_24_hours"`
	}{
		TotalAnalyzed:   0,
		ThreatsDetected: 0,
		ThreatsByType: map[string]int64{
			"phishing":      0,
			"smishing":      0,
			"scam":          0,
			"bank_fraud":    0,
			"delivery_scam": 0,
		},
		ThreatsByLevel: map[string]int64{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
