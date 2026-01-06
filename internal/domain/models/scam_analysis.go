package models

import (
	"time"

	"github.com/google/uuid"
)

// ScamType represents the type of scam detected
type ScamType string

const (
	ScamTypePhishing       ScamType = "phishing"
	ScamTypeAdvanceFee     ScamType = "advance_fee"       // Nigerian prince, lottery
	ScamTypeRomance        ScamType = "romance"           // Romance/dating scams
	ScamTypeTechSupport    ScamType = "tech_support"      // Fake tech support
	ScamTypeInvestment     ScamType = "investment"        // Crypto, forex, ponzi
	ScamTypeImpersonation  ScamType = "impersonation"     // CEO fraud, authority
	ScamTypeJobOffer       ScamType = "job_offer"         // Fake job offers
	ScamTypeJobScam        ScamType = "job_scam"          // Fake job scams
	ScamTypeShipping       ScamType = "shipping"          // Fake delivery notices
	ScamTypeTaxRefund      ScamType = "tax_refund"        // IRS/tax scams
	ScamTypePrizeWinning   ScamType = "prize_winning"     // Fake prizes/lottery
	ScamTypeLottery        ScamType = "lottery"           // Lottery scams
	ScamTypeSocialMedia    ScamType = "social_media"      // Account takeover
	ScamTypeSubscription   ScamType = "subscription"      // Fake subscription renewal
	ScamTypeBanking        ScamType = "banking"           // Bank impersonation
	ScamTypeCrypto         ScamType = "crypto"            // Crypto giveaway scams
	ScamTypeSextortion     ScamType = "sextortion"        // Blackmail scams
	ScamTypeExtortion      ScamType = "extortion"         // Extortion/blackmail
	ScamTypeCharityFraud   ScamType = "charity_fraud"     // Fake charities
	ScamTypeRentalScam     ScamType = "rental_scam"       // Fake property listings
	ScamTypeSMSPremium     ScamType = "sms_premium"       // Premium SMS traps
	ScamTypeOther          ScamType = "other"
	ScamTypeNone           ScamType = "none"              // Not a scam
)

// ScamSeverity represents the severity level of a scam
type ScamSeverity string

const (
	ScamSeverityCritical ScamSeverity = "critical"  // Immediate financial risk
	ScamSeverityHigh     ScamSeverity = "high"      // High probability of scam
	ScamSeverityMedium   ScamSeverity = "medium"    // Suspicious, needs review
	ScamSeverityLow      ScamSeverity = "low"       // Minor concerns
	ScamSeverityNone     ScamSeverity = "none"      // Safe/legitimate
)

// ContentType represents the type of content being analyzed
type ContentType string

const (
	ContentTypeText       ContentType = "text"       // Plain text message
	ContentTypeURL        ContentType = "url"        // URL/link
	ContentTypeImage      ContentType = "image"      // Screenshot/image
	ContentTypeVoice      ContentType = "voice"      // Voice message
	ContentTypeEmail      ContentType = "email"      // Email content
	ContentTypeSMS        ContentType = "sms"        // SMS message
	ContentTypePhone      ContentType = "phone"      // Phone number
	ContentTypeSocialPost ContentType = "social"     // Social media post
)

// ScamAnalysisRequest represents a request to analyze content for scams
type ScamAnalysisRequest struct {
	ID          string      `json:"id"`
	ContentType ContentType `json:"content_type"`
	Content     string      `json:"content"`              // Text content or base64 for images
	URL         string      `json:"url,omitempty"`        // URL if applicable
	PhoneNumber string      `json:"phone_number,omitempty"`
	Email       string      `json:"email,omitempty"`
	Language    string      `json:"language,omitempty"`   // Detected or specified language
	Context     string      `json:"context,omitempty"`    // Additional context
	Source      string      `json:"source,omitempty"`     // Where content came from (SMS, email, etc.)
	MimeType    string      `json:"mime_type,omitempty"`  // MIME type for image/audio
	SenderInfo  *SenderInfo `json:"sender_info,omitempty"`
	ImageData   []byte      `json:"-"`                    // Raw image data (not serialized)
	AudioData   []byte      `json:"-"`                    // Raw audio data (not serialized)
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	UserID      uuid.UUID   `json:"user_id,omitempty"`
	DeviceID    string      `json:"device_id,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// SenderInfo contains information about the message sender
type SenderInfo struct {
	PhoneNumber    string  `json:"phone_number,omitempty"`
	Email          string  `json:"email,omitempty"`
	DisplayName    string  `json:"display_name,omitempty"`
	IsContact      bool    `json:"is_contact"`
	ReputationScore float64 `json:"reputation_score,omitempty"`
	Country        string  `json:"country,omitempty"`
	Carrier        string  `json:"carrier,omitempty"`
}

// ScamAnalysisResult represents the result of scam analysis
type ScamAnalysisResult struct {
	ID              uuid.UUID       `json:"id"`
	RequestID       string          `json:"request_id"`
	ContentType     ContentType     `json:"content_type"`
	IsScam          bool            `json:"is_scam"`
	ScamType        ScamType        `json:"scam_type"`
	Severity        ScamSeverity    `json:"severity"`
	Confidence      float64         `json:"confidence"`        // 0.0 - 1.0
	RiskScore       float64         `json:"risk_score"`        // 0-1.0

	// Detailed analysis
	Intent          *IntentAnalysis       `json:"intent,omitempty"`
	Manipulation    *ManipulationAnalysis `json:"manipulation,omitempty"`
	Entities        *ExtractedEntities    `json:"entities,omitempty"`
	Indicators      []ScamIndicator       `json:"indicators,omitempty"`
	PatternMatches  []PatternMatch        `json:"pattern_matches,omitempty"`
	LanguageAnalysis *LanguageAnalysis    `json:"language_analysis,omitempty"`
	URLAnalysis     *URLScamAnalysis      `json:"url_analysis,omitempty"`
	PhoneAnalysis   *PhoneAnalysis        `json:"phone_analysis,omitempty"`
	ImageAnalysis   *ImageAnalysis        `json:"image_analysis,omitempty"`
	VoiceAnalysis   *VoiceAnalysis        `json:"voice_analysis,omitempty"`

	// AI explanation
	Explanation     string          `json:"explanation"`
	DetailedReason  string          `json:"detailed_reason,omitempty"`
	RedFlags        []RedFlag       `json:"red_flags,omitempty"`
	UrgencyLevel    string          `json:"urgency_level,omitempty"`

	// Recommendations
	Recommendation  string          `json:"recommendation"`
	RecommendedAction string        `json:"recommended_action,omitempty"`
	SafetyTips      []string        `json:"safety_tips,omitempty"`

	// Transcript (for voice/speech)
	Transcript      string          `json:"transcript,omitempty"`
	Language        string          `json:"language,omitempty"`

	// Reference data
	SimilarScams    []SimilarScam   `json:"similar_scams,omitempty"`
	ReportCount     int             `json:"report_count,omitempty"` // How many times reported

	// Metadata
	Timestamp       time.Time       `json:"timestamp"`
	AnalyzedAt      time.Time       `json:"analyzed_at"`
	ProcessingTime  time.Duration   `json:"processing_time"`
	ModelUsed       string          `json:"model_used,omitempty"`
	AnalysisMethod  string          `json:"analysis_method,omitempty"` // llm, pattern, hybrid, on_device
}

// IntentAnalysis contains the intent classification results
type IntentAnalysis struct {
	PrimaryIntent   string             `json:"primary_intent"`
	Confidence      float64            `json:"confidence"`
	IsScam          bool               `json:"is_scam"`
	RiskScore       float64            `json:"risk_score"`
	Intents         map[string]float64 `json:"intents,omitempty"` // Intent -> confidence
	Urgency         string             `json:"urgency,omitempty"` // high, medium, low
	EmotionalTone   string             `json:"emotional_tone,omitempty"` // fear, greed, urgency
	ManipulationTactics []string       `json:"manipulation_tactics,omitempty"`
}

// ManipulationAnalysis contains manipulation analysis results
type ManipulationAnalysis struct {
	IsManipulative    bool                     `json:"is_manipulative"`
	Severity          string                   `json:"severity"`
	Techniques        []ManipulationTechnique  `json:"techniques,omitempty"`
	EmotionalTriggers []string                 `json:"emotional_triggers,omitempty"`
}

// ManipulationTechnique represents a manipulation technique
type ManipulationTechnique struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// ScamIndicator represents a scam indicator found in content
type ScamIndicator struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Evidence    string  `json:"evidence,omitempty"`
}

// ExtractedEntities contains entities extracted from the content
type ExtractedEntities struct {
	URLs            []URLEntity       `json:"urls,omitempty"`
	PhoneNumbers    []PhoneEntity     `json:"phone_numbers,omitempty"`
	Emails          []EmailEntity     `json:"emails,omitempty"`
	CryptoAddresses []CryptoEntity    `json:"crypto_addresses,omitempty"`
	BankAccounts    []string          `json:"bank_accounts,omitempty"`
	Names           []string          `json:"names,omitempty"`
	Dates           []string          `json:"dates,omitempty"`
	MoneyAmounts    []MoneyAmount     `json:"money_amounts,omitempty"`
	Organizations   []string          `json:"organizations,omitempty"`
	Locations       []string          `json:"locations,omitempty"`
	TrackingNumbers []string          `json:"tracking_numbers,omitempty"`
}

// URLEntity represents an extracted URL entity
type URLEntity struct {
	URL          string `json:"url"`
	Domain       string `json:"domain"`
	IsSuspicious bool   `json:"is_suspicious"`
	Reason       string `json:"reason,omitempty"`
}

// PhoneEntity represents an extracted phone entity
type PhoneEntity struct {
	Number       string `json:"number"`
	CountryCode  string `json:"country_code,omitempty"`
	IsSuspicious bool   `json:"is_suspicious"`
	Reason       string `json:"reason,omitempty"`
}

// EmailEntity represents an extracted email entity
type EmailEntity struct {
	Email        string `json:"email"`
	Domain       string `json:"domain"`
	IsSuspicious bool   `json:"is_suspicious"`
	Reason       string `json:"reason,omitempty"`
}

// CryptoEntity represents an extracted crypto address entity
type CryptoEntity struct {
	Address      string `json:"address"`
	Currency     string `json:"currency"`
	IsSuspicious bool   `json:"is_suspicious"`
	Reason       string `json:"reason,omitempty"`
}

// ExtractedURL contains analysis of an extracted URL
type ExtractedURL struct {
	URL           string  `json:"url"`
	Domain        string  `json:"domain"`
	IsShortened   bool    `json:"is_shortened"`
	ExpandedURL   string  `json:"expanded_url,omitempty"`
	IsMalicious   bool    `json:"is_malicious"`
	IsPhishing    bool    `json:"is_phishing"`
	RiskScore     float64 `json:"risk_score"`
	Category      string  `json:"category,omitempty"`
}

// CryptoAddress contains a cryptocurrency address
type CryptoAddress struct {
	Address  string `json:"address"`
	Currency string `json:"currency"` // BTC, ETH, etc.
	IsValid  bool   `json:"is_valid"`
	Label    string `json:"label,omitempty"` // Known scam wallet
}

// MoneyAmount contains a detected money amount
type MoneyAmount struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	Context  string  `json:"context,omitempty"`
}

// PatternMatch represents a matched scam pattern
type PatternMatch struct {
	PatternID    string   `json:"pattern_id"`
	PatternName  string   `json:"pattern_name"`
	Category     ScamType `json:"category"`
	Confidence   float64  `json:"confidence"`
	MatchedText  string   `json:"matched_text,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// LanguageAnalysis contains language-related analysis
type LanguageAnalysis struct {
	DetectedLanguage string             `json:"detected_language"`
	LanguageCode     string             `json:"language_code"`
	Confidence       float64            `json:"confidence"`
	TranslatedText   string             `json:"translated_text,omitempty"`
	GrammarScore     float64            `json:"grammar_score,omitempty"` // Poor grammar indicator
	SuspiciousPhrases []SuspiciousPhrase `json:"suspicious_phrases,omitempty"`
}

// SuspiciousPhrase represents a suspicious phrase found in text
type SuspiciousPhrase struct {
	Phrase      string  `json:"phrase"`
	Reason      string  `json:"reason"`
	Confidence  float64 `json:"confidence"`
}

// URLScamAnalysis contains URL-specific analysis
type URLScamAnalysis struct {
	URL             string   `json:"url"`
	Domain          string   `json:"domain"`
	RegisteredDate  string   `json:"registered_date,omitempty"`
	DomainAge       int      `json:"domain_age_days,omitempty"`
	IsSuspicious    bool     `json:"is_suspicious"`
	IsPhishing      bool     `json:"is_phishing"`
	IsMalware       bool     `json:"is_malware"`
	SSLValid        bool     `json:"ssl_valid"`
	SSLIssuer       string   `json:"ssl_issuer,omitempty"`
	RedirectChain   []string `json:"redirect_chain,omitempty"`
	FinalURL        string   `json:"final_url,omitempty"`
	TargetBrand     string   `json:"target_brand,omitempty"` // Brand being impersonated
	RiskFactors     []string `json:"risk_factors,omitempty"`
	VTDetections    int      `json:"vt_detections,omitempty"`
	Screenshot      string   `json:"screenshot,omitempty"` // Base64 encoded
}

// PhoneAnalysis contains phone number analysis
type PhoneAnalysis struct {
	Number          string  `json:"number"`
	FormattedNumber string  `json:"formatted_number"`
	CountryCode     string  `json:"country_code"`
	Country         string  `json:"country"`
	Carrier         string  `json:"carrier,omitempty"`
	LineType        string  `json:"line_type,omitempty"` // mobile, landline, voip
	IsValid         bool    `json:"is_valid"`
	IsSpam          bool    `json:"is_spam"`
	IsScam          bool    `json:"is_scam"`
	ReportCount     int     `json:"report_count"`
	ReputationScore float64 `json:"reputation_score"`
	Categories      []string `json:"categories,omitempty"` // telemarketer, scam, etc.
}

// ImageAnalysis contains image/screenshot analysis results
type ImageAnalysis struct {
	HasText         bool              `json:"has_text"`
	ExtractedText   string            `json:"extracted_text,omitempty"`
	DetectedLogos   []DetectedLogo    `json:"detected_logos,omitempty"`
	DetectedBrands  []string          `json:"detected_brands,omitempty"`
	IsFakeBranding  bool              `json:"is_fake_branding"`
	SuspiciousElements []string       `json:"suspicious_elements,omitempty"`
	QRCodeContent   string            `json:"qr_code_content,omitempty"`
	ImageType       string            `json:"image_type,omitempty"` // screenshot, photo, etc.
}

// DetectedLogo represents a detected logo in an image
type DetectedLogo struct {
	Brand      string  `json:"brand"`
	Confidence float64 `json:"confidence"`
	IsOfficial bool    `json:"is_official"`
}

// VoiceAnalysis contains voice message analysis results
type VoiceAnalysis struct {
	Duration        float64 `json:"duration_seconds"`
	TranscribedText string  `json:"transcribed_text"`
	Language        string  `json:"language"`
	Confidence      float64 `json:"transcription_confidence"`
	IsRobocall      bool    `json:"is_robocall"`
	VoiceCloning    float64 `json:"voice_cloning_probability,omitempty"` // AI-generated voice
	BackgroundNoise string  `json:"background_noise,omitempty"` // call_center, outdoor, etc.
	SpeakerCount    int     `json:"speaker_count,omitempty"`
}

// RedFlag represents a detected red flag in the content
type RedFlag struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Evidence    string  `json:"evidence,omitempty"`
}

// SimilarScam represents a similar scam from the database
type SimilarScam struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	ScamType    ScamType `json:"scam_type"`
	Similarity  float64  `json:"similarity"`
	ReportCount int      `json:"report_count"`
	FirstSeen   string   `json:"first_seen"`
}

// ScamPattern represents a scam detection pattern
type ScamPattern struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Category    ScamType  `json:"category"`
	Description string    `json:"description"`

	// Pattern matching
	Keywords      []string `json:"keywords,omitempty"`
	Phrases       []string `json:"phrases,omitempty"`
	RegexPatterns []string `json:"regex_patterns,omitempty"`
	URLPatterns   []string `json:"url_patterns,omitempty"`

	// Scoring
	BaseScore     float64  `json:"base_score"`
	Severity      ScamSeverity `json:"severity"`

	// Metadata
	Language      string    `json:"language,omitempty"` // empty = all languages
	Region        string    `json:"region,omitempty"`   // Specific to region
	IsActive      bool      `json:"is_active"`
	ReportCount   int       `json:"report_count"`
	FalsePositive float64   `json:"false_positive_rate"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ScamReport represents a user-submitted scam report
type ScamReport struct {
	ID          uuid.UUID   `json:"id"`
	UserID      uuid.UUID   `json:"user_id,omitempty"`
	DeviceID    string      `json:"device_id,omitempty"`
	ContentType ContentType `json:"content_type"`
	Content     string      `json:"content"`
	URL         string      `json:"url,omitempty"`
	PhoneNumber string      `json:"phone_number,omitempty"`
	SenderInfo  *SenderInfo `json:"sender_info,omitempty"`
	ScamType    ScamType    `json:"scam_type"`
	Description string      `json:"description,omitempty"`
	NewPattern  string      `json:"new_pattern,omitempty"` // User-suggested pattern
	Country     string      `json:"country,omitempty"`
	Verified    bool        `json:"verified"`
	ReportedAt  time.Time   `json:"reported_at"`
}

// BulkScanRequest represents a request to scan multiple messages
type BulkScanRequest struct {
	Messages []ScamAnalysisRequest `json:"messages"`
	Options  BulkScanOptions       `json:"options,omitempty"`
}

// BulkScanOptions contains options for bulk scanning
type BulkScanOptions struct {
	QuickScan     bool   `json:"quick_scan"`      // Fast scan, lower accuracy
	IncludeURLs   bool   `json:"include_urls"`    // Deep URL analysis
	Language      string `json:"language,omitempty"` // Force language
}

// BulkScanResult represents results of bulk scanning
type BulkScanResult struct {
	TotalScanned   int                  `json:"total_scanned"`
	ScamsDetected  int                  `json:"scams_detected"`
	HighRisk       int                  `json:"high_risk"`
	Results        []ScamAnalysisResult `json:"results"`
	ProcessingTime string               `json:"processing_time"`
}

// ChatMessage represents a message in the scam guard chat
type ChatMessage struct {
	ID        uuid.UUID `json:"id"`
	Role      string    `json:"role"` // user, assistant, system
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Analysis  *ScamAnalysisResult `json:"analysis,omitempty"`
}

// ScamGuardSession represents a scam guard chat session
type ScamGuardSession struct {
	ID        uuid.UUID     `json:"id"`
	UserID    uuid.UUID     `json:"user_id,omitempty"`
	DeviceID  string        `json:"device_id,omitempty"`
	Messages  []ChatMessage `json:"messages"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// AIModelConfig represents configuration for AI models
type AIModelConfig struct {
	Provider         string  `json:"provider"`          // claude, openai, local
	Model            string  `json:"model"`             // claude-3-sonnet, gpt-4, etc.
	Temperature      float64 `json:"temperature"`
	MaxTokens        int     `json:"max_tokens"`
	SystemPrompt     string  `json:"system_prompt"`
	VisionEnabled    bool    `json:"vision_enabled"`
	StreamingEnabled bool    `json:"streaming_enabled"`
}
