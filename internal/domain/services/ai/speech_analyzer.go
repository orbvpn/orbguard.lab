package ai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// SpeechAnalyzer analyzes voice messages and audio for scam indicators
type SpeechAnalyzer struct {
	httpClient *http.Client
	logger     *logger.Logger
	llmClient  *LLMClient
	config     SpeechAnalyzerConfig
}

// SpeechAnalyzerConfig contains configuration for speech analysis
type SpeechAnalyzerConfig struct {
	// Speech-to-text services
	OpenAIAPIKey      string
	WhisperEndpoint   string // For self-hosted Whisper
	GoogleSpeechKey   string

	// Provider preference
	Provider          string // "openai", "whisper", "google"

	// Analysis settings
	MaxAudioDuration  time.Duration
	MaxAudioSize      int64
	EnableTranscript  bool
	EnableVoiceprint  bool
	EnableEmotionDetection bool
}

// SpeechAnalysisResult contains the result of voice message analysis
type SpeechAnalysisResult struct {
	// Transcript
	Transcript        string              `json:"transcript"`
	TranscriptLang    string              `json:"transcript_language"`
	TranscriptConf    float64             `json:"transcript_confidence"`

	// Scam analysis
	IsScam            bool                `json:"is_scam"`
	ScamConfidence    float64             `json:"scam_confidence"`
	ScamType          models.ScamType     `json:"scam_type,omitempty"`
	Severity          models.ScamSeverity `json:"severity"`

	// Voice characteristics
	VoiceAnalysis     *VoiceCharacteristics `json:"voice_analysis,omitempty"`

	// Content analysis
	ContentAnalysis   *AudioContentAnalysis `json:"content_analysis,omitempty"`

	// Extracted entities
	ExtractedEntities *ExtractedEntities  `json:"extracted_entities,omitempty"`

	// Pattern matches
	PatternMatches    []PatternMatch      `json:"pattern_matches,omitempty"`

	// Red flags
	RedFlags          []string            `json:"red_flags,omitempty"`

	// Explanation
	Explanation       string              `json:"explanation"`

	// Metadata
	AudioDuration     time.Duration       `json:"audio_duration"`
	ProcessingTime    time.Duration       `json:"processing_time"`
}

// VoiceCharacteristics contains voice analysis results
type VoiceCharacteristics struct {
	// Speaker analysis
	SpeakerCount      int                 `json:"speaker_count"`
	IsSynthetic       bool                `json:"is_synthetic"` // AI-generated voice
	SyntheticConf     float64             `json:"synthetic_confidence"`

	// Emotional indicators
	Emotion           string              `json:"emotion,omitempty"` // urgent, threatening, friendly, etc.
	EmotionConf       float64             `json:"emotion_confidence"`
	Urgency           float64             `json:"urgency"` // 0-1 scale
	Aggression        float64             `json:"aggression"` // 0-1 scale

	// Voice quality
	AudioQuality      string              `json:"audio_quality"` // good, poor, synthetic
	BackgroundNoise   string              `json:"background_noise,omitempty"`
	CallCenterLikely  bool                `json:"call_center_likely"`

	// Accent/region (for context)
	AccentRegion      string              `json:"accent_region,omitempty"`
}

// AudioContentAnalysis contains analysis of the spoken content
type AudioContentAnalysis struct {
	// Topics discussed
	Topics            []string            `json:"topics,omitempty"`

	// Key phrases
	KeyPhrases        []string            `json:"key_phrases,omitempty"`

	// Request analysis
	Requests          []AudioRequest      `json:"requests,omitempty"`

	// Manipulation tactics
	ManipulationScore float64             `json:"manipulation_score"`
	Tactics           []string            `json:"tactics,omitempty"`

	// Authority claims
	AuthorityClaims   []string            `json:"authority_claims,omitempty"`

	// Threats
	Threats           []string            `json:"threats,omitempty"`
}

// AudioRequest represents a request made in the audio
type AudioRequest struct {
	Type        string `json:"type"` // money, information, action
	Description string `json:"description"`
	IsRisky     bool   `json:"is_risky"`
	Urgency     string `json:"urgency"`
}

// NewSpeechAnalyzer creates a new speech analyzer
func NewSpeechAnalyzer(log *logger.Logger, llmClient *LLMClient, config SpeechAnalyzerConfig) *SpeechAnalyzer {
	if config.MaxAudioDuration == 0 {
		config.MaxAudioDuration = 5 * time.Minute
	}
	if config.MaxAudioSize == 0 {
		config.MaxAudioSize = 25 * 1024 * 1024 // 25MB
	}

	return &SpeechAnalyzer{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger:    log.WithComponent("speech-analyzer"),
		llmClient: llmClient,
		config:    config,
	}
}

// AnalyzeAudio analyzes audio data for scam indicators
func (s *SpeechAnalyzer) AnalyzeAudio(ctx context.Context, audioData []byte, mimeType string) (*SpeechAnalysisResult, error) {
	startTime := time.Now()

	result := &SpeechAnalysisResult{
		Severity: models.ScamSeverityNone,
	}

	// Validate audio
	if len(audioData) == 0 {
		return nil, fmt.Errorf("empty audio data")
	}
	if int64(len(audioData)) > s.config.MaxAudioSize {
		return nil, fmt.Errorf("audio too large: %d bytes (max: %d)", len(audioData), s.config.MaxAudioSize)
	}

	// Transcribe audio
	transcript, lang, confidence, err := s.transcribeAudio(ctx, audioData, mimeType)
	if err != nil {
		return nil, fmt.Errorf("transcription failed: %w", err)
	}

	result.Transcript = transcript
	result.TranscriptLang = lang
	result.TranscriptConf = confidence

	// Analyze transcript for scams
	if transcript != "" {
		s.analyzeTranscript(ctx, transcript, result)
	}

	// Voice analysis (if enabled)
	if s.config.EnableVoiceprint {
		result.VoiceAnalysis = s.analyzeVoiceCharacteristics(audioData)
	}

	// Calculate severity
	s.calculateSeverity(result)

	result.ProcessingTime = time.Since(startTime)

	return result, nil
}

// AnalyzeAudioFile analyzes an audio file
func (s *SpeechAnalyzer) AnalyzeAudioFile(ctx context.Context, filePath string) (*SpeechAnalysisResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read audio file: %w", err)
	}

	mimeType := detectAudioMimeType(filePath, data)
	return s.AnalyzeAudio(ctx, data, mimeType)
}

// transcribeAudio transcribes audio to text
func (s *SpeechAnalyzer) transcribeAudio(ctx context.Context, audioData []byte, mimeType string) (transcript, language string, confidence float64, err error) {
	switch s.config.Provider {
	case "openai":
		return s.transcribeWithOpenAI(ctx, audioData, mimeType)
	case "whisper":
		return s.transcribeWithWhisper(ctx, audioData, mimeType)
	default:
		// Default to OpenAI if key is available
		if s.config.OpenAIAPIKey != "" {
			return s.transcribeWithOpenAI(ctx, audioData, mimeType)
		}
		return "", "", 0, fmt.Errorf("no speech-to-text provider configured")
	}
}

// transcribeWithOpenAI uses OpenAI Whisper API
func (s *SpeechAnalyzer) transcribeWithOpenAI(ctx context.Context, audioData []byte, mimeType string) (string, string, float64, error) {
	// Create multipart form
	var buf bytes.Buffer
	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"

	// Write file part
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"audio.mp3\"\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n\r\n", mimeType))
	buf.Write(audioData)
	buf.WriteString("\r\n")

	// Write model part
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Disposition: form-data; name=\"model\"\r\n\r\n")
	buf.WriteString("whisper-1\r\n")

	// Write response_format part
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Disposition: form-data; name=\"response_format\"\r\n\r\n")
	buf.WriteString("verbose_json\r\n")

	buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/audio/transcriptions", &buf)
	if err != nil {
		return "", "", 0, err
	}

	req.Header.Set("Authorization", "Bearer "+s.config.OpenAIAPIKey)
	req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", 0, fmt.Errorf("OpenAI API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Text     string  `json:"text"`
		Language string  `json:"language"`
		Duration float64 `json:"duration"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, err
	}

	// OpenAI Whisper doesn't provide per-segment confidence, assume high
	return result.Text, result.Language, 0.9, nil
}

// transcribeWithWhisper uses self-hosted Whisper
func (s *SpeechAnalyzer) transcribeWithWhisper(ctx context.Context, audioData []byte, mimeType string) (string, string, float64, error) {
	endpoint := s.config.WhisperEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:9000/asr"
	}

	// Encode audio as base64
	encoded := base64.StdEncoding.EncodeToString(audioData)

	reqBody := map[string]interface{}{
		"audio":    encoded,
		"encoding": "base64",
		"task":     "transcribe",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return "", "", 0, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Text       string  `json:"text"`
		Language   string  `json:"language"`
		Confidence float64 `json:"confidence"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, err
	}

	return result.Text, result.Language, result.Confidence, nil
}

// analyzeTranscript analyzes the transcript for scam indicators
func (s *SpeechAnalyzer) analyzeTranscript(ctx context.Context, transcript string, result *SpeechAnalysisResult) {
	// Use LLM for deep analysis
	if s.llmClient != nil {
		llmAnalysis, err := s.analyzeWithLLM(ctx, transcript)
		if err != nil {
			s.logger.Warn().Err(err).Msg("LLM analysis failed")
		} else {
			s.mergeLLMAnalysis(result, llmAnalysis)
		}
	}

	// Pattern matching
	patternDB := NewScamPatternDB(s.logger)
	matches := patternDB.Match(transcript)
	result.PatternMatches = matches

	// Extract entities
	extractor := NewEntityExtractor(s.logger, nil) // Without LLM for speed
	entities, _ := extractor.Extract(ctx, transcript)
	result.ExtractedEntities = entities

	// Check for specific audio scam indicators
	s.checkAudioScamIndicators(transcript, result)
}

// analyzeWithLLM uses LLM for comprehensive transcript analysis
func (s *SpeechAnalyzer) analyzeWithLLM(ctx context.Context, transcript string) (*SpeechAnalysisResult, error) {
	systemPrompt := `You are an expert in detecting phone scams, voice phishing (vishing), and fraudulent voice messages.

Analyze the following voice message transcript and identify any scam indicators.

Provide your analysis in JSON format:
{
  "is_scam": boolean,
  "scam_confidence": 0.0-1.0,
  "scam_type": "tech_support|irs|bank|romance|investment|other",
  "content_analysis": {
    "topics": ["list of topics discussed"],
    "key_phrases": ["important phrases"],
    "requests": [{"type": "money|information|action", "description": "desc", "is_risky": boolean, "urgency": "low|medium|high"}],
    "manipulation_score": 0.0-1.0,
    "tactics": ["pressure tactics used"],
    "authority_claims": ["claims to authority"],
    "threats": ["any threats made"]
  },
  "red_flags": ["list of red flags"],
  "explanation": "detailed explanation"
}`

	prompt := fmt.Sprintf("Analyze this voice message transcript for scam indicators:\n\n%s", transcript)

	response, err := s.llmClient.Chat(ctx, []Message{NewTextMessage("user", prompt)}, systemPrompt)
	if err != nil {
		return nil, err
	}

	return s.parseLLMAnalysis(response)
}

// parseLLMAnalysis parses the LLM analysis response
func (s *SpeechAnalyzer) parseLLMAnalysis(response string) (*SpeechAnalysisResult, error) {
	result := &SpeechAnalysisResult{}

	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return nil, fmt.Errorf("no JSON in response")
	}

	var parsed struct {
		IsScam         bool    `json:"is_scam"`
		ScamConfidence float64 `json:"scam_confidence"`
		ScamType       string  `json:"scam_type"`
		ContentAnalysis struct {
			Topics            []string `json:"topics"`
			KeyPhrases        []string `json:"key_phrases"`
			Requests          []struct {
				Type        string `json:"type"`
				Description string `json:"description"`
				IsRisky     bool   `json:"is_risky"`
				Urgency     string `json:"urgency"`
			} `json:"requests"`
			ManipulationScore float64  `json:"manipulation_score"`
			Tactics           []string `json:"tactics"`
			AuthorityClaims   []string `json:"authority_claims"`
			Threats           []string `json:"threats"`
		} `json:"content_analysis"`
		RedFlags    []string `json:"red_flags"`
		Explanation string   `json:"explanation"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, err
	}

	result.IsScam = parsed.IsScam
	result.ScamConfidence = parsed.ScamConfidence
	result.ScamType = models.ScamType(parsed.ScamType)
	result.RedFlags = parsed.RedFlags
	result.Explanation = parsed.Explanation

	result.ContentAnalysis = &AudioContentAnalysis{
		Topics:            parsed.ContentAnalysis.Topics,
		KeyPhrases:        parsed.ContentAnalysis.KeyPhrases,
		ManipulationScore: parsed.ContentAnalysis.ManipulationScore,
		Tactics:           parsed.ContentAnalysis.Tactics,
		AuthorityClaims:   parsed.ContentAnalysis.AuthorityClaims,
		Threats:           parsed.ContentAnalysis.Threats,
	}

	for _, req := range parsed.ContentAnalysis.Requests {
		result.ContentAnalysis.Requests = append(result.ContentAnalysis.Requests, AudioRequest{
			Type:        req.Type,
			Description: req.Description,
			IsRisky:     req.IsRisky,
			Urgency:     req.Urgency,
		})
	}

	return result, nil
}

// mergeLLMAnalysis merges LLM analysis results
func (s *SpeechAnalyzer) mergeLLMAnalysis(result *SpeechAnalysisResult, llmResult *SpeechAnalysisResult) {
	if llmResult == nil {
		return
	}

	result.IsScam = llmResult.IsScam
	result.ScamConfidence = llmResult.ScamConfidence
	result.ScamType = llmResult.ScamType
	result.ContentAnalysis = llmResult.ContentAnalysis
	result.RedFlags = llmResult.RedFlags
	result.Explanation = llmResult.Explanation
}

// checkAudioScamIndicators checks for specific voice scam indicators
func (s *SpeechAnalyzer) checkAudioScamIndicators(transcript string, result *SpeechAnalysisResult) {
	lower := strings.ToLower(transcript)

	// IRS/Tax scam indicators
	irsIndicators := []string{
		"irs", "internal revenue", "tax fraud", "arrest warrant",
		"police will be sent", "legal action", "tax debt",
	}

	// Tech support scam indicators
	techSupportIndicators := []string{
		"microsoft", "apple support", "your computer",
		"virus detected", "security breach", "remote access",
		"give me access", "let me connect",
	}

	// Bank scam indicators
	bankIndicators := []string{
		"your bank account", "suspicious activity", "verify your account",
		"card has been blocked", "fraud department", "transfer your funds",
	}

	// General scam indicators
	generalIndicators := []string{
		"press 1", "call back immediately", "this is urgent",
		"your social security", "warrant for your arrest",
		"gift card", "bitcoin", "wire transfer",
	}

	checkIndicators := func(indicators []string, scamType models.ScamType) {
		for _, indicator := range indicators {
			if strings.Contains(lower, indicator) {
				result.RedFlags = append(result.RedFlags, fmt.Sprintf("Contains '%s'", indicator))
				if !result.IsScam {
					result.IsScam = true
					result.ScamType = scamType
					result.ScamConfidence = 0.7
				}
			}
		}
	}

	checkIndicators(irsIndicators, models.ScamTypeImpersonation)
	checkIndicators(techSupportIndicators, models.ScamTypeTechSupport)
	checkIndicators(bankIndicators, models.ScamTypePhishing)
	checkIndicators(generalIndicators, models.ScamType("general"))
}

// analyzeVoiceCharacteristics analyzes voice characteristics
func (s *SpeechAnalyzer) analyzeVoiceCharacteristics(audioData []byte) *VoiceCharacteristics {
	// This is a placeholder - real implementation would use audio analysis libraries
	// or call specialized APIs for voice analysis

	return &VoiceCharacteristics{
		SpeakerCount:     1,
		IsSynthetic:      false,
		SyntheticConf:    0.1,
		AudioQuality:     "unknown",
		CallCenterLikely: false,
	}
}

// calculateSeverity calculates the severity based on analysis
func (s *SpeechAnalyzer) calculateSeverity(result *SpeechAnalysisResult) {
	if !result.IsScam {
		result.Severity = models.ScamSeverityNone
		return
	}

	// Base severity on confidence and red flags
	if result.ScamConfidence >= 0.9 {
		result.Severity = models.ScamSeverityCritical
	} else if result.ScamConfidence >= 0.7 {
		result.Severity = models.ScamSeverityHigh
	} else if result.ScamConfidence >= 0.5 {
		result.Severity = models.ScamSeverityMedium
	} else {
		result.Severity = models.ScamSeverityLow
	}

	// Increase severity for certain scam types
	criticalTypes := []models.ScamType{
		models.ScamTypeImpersonation,
		models.ScamTypeExtortion,
	}
	for _, t := range criticalTypes {
		if result.ScamType == t && result.Severity == models.ScamSeverityHigh {
			result.Severity = models.ScamSeverityCritical
		}
	}

	// Increase severity if threats detected
	if result.ContentAnalysis != nil && len(result.ContentAnalysis.Threats) > 0 {
		if result.Severity == models.ScamSeverityMedium {
			result.Severity = models.ScamSeverityHigh
		} else if result.Severity == models.ScamSeverityHigh {
			result.Severity = models.ScamSeverityCritical
		}
	}
}

// Helper functions

func detectAudioMimeType(filePath string, data []byte) string {
	// Check file extension first
	lower := strings.ToLower(filePath)
	switch {
	case strings.HasSuffix(lower, ".mp3"):
		return "audio/mpeg"
	case strings.HasSuffix(lower, ".wav"):
		return "audio/wav"
	case strings.HasSuffix(lower, ".m4a"):
		return "audio/m4a"
	case strings.HasSuffix(lower, ".ogg"):
		return "audio/ogg"
	case strings.HasSuffix(lower, ".webm"):
		return "audio/webm"
	case strings.HasSuffix(lower, ".flac"):
		return "audio/flac"
	}

	// Check magic bytes
	if len(data) < 12 {
		return "audio/mpeg"
	}

	// MP3
	if data[0] == 0xFF && (data[1]&0xE0) == 0xE0 {
		return "audio/mpeg"
	}
	if string(data[:3]) == "ID3" {
		return "audio/mpeg"
	}

	// WAV
	if string(data[:4]) == "RIFF" && string(data[8:12]) == "WAVE" {
		return "audio/wav"
	}

	// OGG
	if string(data[:4]) == "OggS" {
		return "audio/ogg"
	}

	// FLAC
	if string(data[:4]) == "fLaC" {
		return "audio/flac"
	}

	return "audio/mpeg" // Default to MP3
}
