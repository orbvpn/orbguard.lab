package models

import (
	"time"

	"github.com/google/uuid"
)

// SMSMessage represents an SMS message to be analyzed
type SMSMessage struct {
	ID        uuid.UUID `json:"id"`
	Sender    string    `json:"sender"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
	DeviceID  string    `json:"device_id,omitempty"`
}

// SMSAnalysisResult contains the complete analysis of an SMS
type SMSAnalysisResult struct {
	ID              uuid.UUID            `json:"id"`
	MessageID       uuid.UUID            `json:"message_id"`
	IsThreat        bool                 `json:"is_threat"`
	ThreatLevel     ThreatLevel          `json:"threat_level"`
	ThreatType      SMSThreatType        `json:"threat_type,omitempty"`
	Confidence      float64              `json:"confidence"`
	Description     string               `json:"description"`
	Recommendations []string             `json:"recommendations,omitempty"`

	// Extracted data
	URLs            []SMSExtractedURL    `json:"urls,omitempty"`
	PhoneNumbers    []string             `json:"phone_numbers,omitempty"`
	Emails          []string             `json:"emails,omitempty"`

	// Detection details
	PatternMatches  []SMSPatternMatch    `json:"pattern_matches,omitempty"`
	SenderAnalysis  *SenderAnalysis      `json:"sender_analysis,omitempty"`
	IntentAnalysis  *SMSIntentAnalysis   `json:"intent_analysis,omitempty"`

	AnalyzedAt      time.Time            `json:"analyzed_at"`
}

// ThreatLevel represents the severity of an SMS threat
type ThreatLevel string

const (
	ThreatLevelSafe     ThreatLevel = "safe"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// SMSThreatType categorizes the type of SMS threat
type SMSThreatType string

const (
	SMSThreatTypeNone                SMSThreatType = ""
	SMSThreatTypePhishing            SMSThreatType = "phishing"
	SMSThreatTypeSmishing            SMSThreatType = "smishing"
	SMSThreatTypeMalware             SMSThreatType = "malware"
	SMSThreatTypeScam                SMSThreatType = "scam"
	SMSThreatTypeSpam                SMSThreatType = "spam"
	SMSThreatTypeImpersonation       SMSThreatType = "impersonation"
	SMSThreatTypeExecutiveImpersonation SMSThreatType = "executive_impersonation"
	SMSThreatTypeBankFraud           SMSThreatType = "bank_fraud"
	SMSThreatTypeDeliveryScam        SMSThreatType = "delivery_scam"
	SMSThreatTypeTechSupport         SMSThreatType = "tech_support_scam"
	SMSThreatTypePremiumRate         SMSThreatType = "premium_rate"
	SMSThreatTypeSuspiciousLink      SMSThreatType = "suspicious_link"
)

// SMSExtractedURL contains analysis of a URL found in the SMS
type SMSExtractedURL struct {
	URL           string      `json:"url"`
	Domain        string      `json:"domain"`
	IsMalicious   bool        `json:"is_malicious"`
	IsShortened   bool        `json:"is_shortened"`
	ExpandedURL   string      `json:"expanded_url,omitempty"`
	Category      URLCategory `json:"category,omitempty"`
	ThreatDetails string      `json:"threat_details,omitempty"`
	Confidence    float64     `json:"confidence"`
	// Indicator match from threat intelligence
	IndicatorID   string      `json:"indicator_id,omitempty"`
	CampaignID    string      `json:"campaign_id,omitempty"`
}

// SMSPatternMatch represents a matched suspicious pattern in SMS
type SMSPatternMatch struct {
	PatternName  string  `json:"pattern_name"`
	PatternType  string  `json:"pattern_type"`
	MatchedText  string  `json:"matched_text"`
	Confidence   float64 `json:"confidence"`
	Description  string  `json:"description"`
}

// SenderAnalysis contains analysis of the SMS sender
type SenderAnalysis struct {
	IsShortCode    bool    `json:"is_short_code"`
	IsAlphanumeric bool    `json:"is_alphanumeric"`
	IsSpoofed      bool    `json:"is_spoofed"`
	SpoofTarget    string  `json:"spoof_target,omitempty"`
	IsKnownBrand   bool    `json:"is_known_brand"`
	BrandName      string  `json:"brand_name,omitempty"`
	RiskScore      float64 `json:"risk_score"`
	Notes          string  `json:"notes,omitempty"`
}

// SMSIntentAnalysis contains NLP analysis of SMS message intent
type SMSIntentAnalysis struct {
	PrimaryIntent   string   `json:"primary_intent"`
	Urgency         float64  `json:"urgency"`         // 0-1 how urgent the message appears
	FearFactor      float64  `json:"fear_factor"`     // 0-1 uses fear/threat tactics
	RewardPromise   float64  `json:"reward_promise"`  // 0-1 promises rewards/prizes
	ActionRequired  bool     `json:"action_required"` // Demands immediate action
	PersonalData    bool     `json:"personal_data"`   // Requests personal info
	FinancialData   bool     `json:"financial_data"`  // Requests financial info
	Entities        []Entity `json:"entities,omitempty"`
	SuspiciousFlags []string `json:"suspicious_flags,omitempty"`
}

// Entity represents an extracted entity from the message
type Entity struct {
	Type  string `json:"type"`  // PERSON, ORG, MONEY, DATE, etc.
	Value string `json:"value"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// SMSBatchAnalysisRequest represents a batch analysis request
type SMSBatchAnalysisRequest struct {
	Messages []SMSMessage `json:"messages"`
	DeviceID string       `json:"device_id"`
}

// SMSBatchAnalysisResult contains results for batch analysis
type SMSBatchAnalysisResult struct {
	Results     []SMSAnalysisResult `json:"results"`
	TotalCount  int                 `json:"total_count"`
	ThreatCount int                 `json:"threat_count"`
	AnalyzedAt  time.Time           `json:"analyzed_at"`
}
