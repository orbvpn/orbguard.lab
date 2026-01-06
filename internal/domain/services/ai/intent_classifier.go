package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// IntentClassifier classifies message intent for scam detection
type IntentClassifier struct {
	logger    *logger.Logger
	llmClient *LLMClient
	patterns  *ScamPatternDB
}

// MessageIntent represents the classified intent of a message
type MessageIntent struct {
	// Primary classification
	PrimaryIntent    Intent           `json:"primary_intent"`
	Confidence       float64          `json:"confidence"`

	// Secondary intents (a message can have multiple intents)
	SecondaryIntents []IntentScore    `json:"secondary_intents,omitempty"`

	// Scam-specific analysis
	IsScam           bool             `json:"is_scam"`
	ScamType         models.ScamType  `json:"scam_type,omitempty"`
	ScamIndicators   []string         `json:"scam_indicators,omitempty"`

	// Psychological manipulation detection
	Manipulation     *ManipulationAnalysis `json:"manipulation,omitempty"`

	// Risk assessment
	RiskScore        float64          `json:"risk_score"`
	RiskFactors      []RiskFactor     `json:"risk_factors,omitempty"`

	// Urgency and pressure tactics
	UrgencyLevel     UrgencyLevel     `json:"urgency_level"`
	PressureTactics  []string         `json:"pressure_tactics,omitempty"`

	// Request analysis
	Requests         []RequestAnalysis `json:"requests,omitempty"`

	// Explanation
	Explanation      string           `json:"explanation"`
}

// Intent represents a message intent category
type Intent string

const (
	// Legitimate intents
	IntentInformational    Intent = "informational"
	IntentTransactional    Intent = "transactional"
	IntentSupport          Intent = "support"
	IntentMarketing        Intent = "marketing"
	IntentSocial           Intent = "social"
	IntentVerification     Intent = "verification"

	// Suspicious/scam intents
	IntentPhishing         Intent = "phishing"
	IntentFinancialScam    Intent = "financial_scam"
	IntentRomanceScam      Intent = "romance_scam"
	IntentTechSupport      Intent = "tech_support_scam"
	IntentImpersonation    Intent = "impersonation"
	IntentExtortion        Intent = "extortion"
	IntentAdvanceFee       Intent = "advance_fee_scam"
	IntentInvestmentScam   Intent = "investment_scam"
	IntentCryptoScam       Intent = "crypto_scam"
	IntentJobScam          Intent = "job_scam"
	IntentLotteryScam      Intent = "lottery_scam"
	IntentCharityScam      Intent = "charity_scam"
	IntentMalwareDelivery  Intent = "malware_delivery"

	// Unknown
	IntentUnknown          Intent = "unknown"
)

// IntentScore represents an intent with its confidence score
type IntentScore struct {
	Intent     Intent  `json:"intent"`
	Confidence float64 `json:"confidence"`
}

// UrgencyLevel represents the level of urgency in a message
type UrgencyLevel string

const (
	UrgencyNone     UrgencyLevel = "none"
	UrgencyLow      UrgencyLevel = "low"
	UrgencyMedium   UrgencyLevel = "medium"
	UrgencyHigh     UrgencyLevel = "high"
	UrgencyExtreme  UrgencyLevel = "extreme"
)

// ManipulationAnalysis contains psychological manipulation analysis
type ManipulationAnalysis struct {
	IsManipulative      bool                `json:"is_manipulative"`
	Techniques          []ManipulationTechnique `json:"techniques,omitempty"`
	EmotionalTriggers   []string            `json:"emotional_triggers,omitempty"`
	TargetedEmotions    []string            `json:"targeted_emotions,omitempty"`
	OverallSeverity     string              `json:"overall_severity"`
}

// ManipulationTechnique represents a manipulation technique
type ManipulationTechnique struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Examples    []string `json:"examples,omitempty"`
	Severity    string   `json:"severity"`
}

// RiskFactor represents a risk factor in the message
type RiskFactor struct {
	Factor      string  `json:"factor"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	Evidence    string  `json:"evidence,omitempty"`
}

// RequestAnalysis analyzes what the message is requesting
type RequestAnalysis struct {
	RequestType  string   `json:"request_type"`
	Description  string   `json:"description"`
	IsRisky      bool     `json:"is_risky"`
	RiskReason   string   `json:"risk_reason,omitempty"`
	TargetAction string   `json:"target_action,omitempty"`
}

// NewIntentClassifier creates a new intent classifier
func NewIntentClassifier(log *logger.Logger, llmClient *LLMClient, patterns *ScamPatternDB) *IntentClassifier {
	return &IntentClassifier{
		logger:    log.WithComponent("intent-classifier"),
		llmClient: llmClient,
		patterns:  patterns,
	}
}

// ClassifyIntent classifies the intent of a message
func (c *IntentClassifier) ClassifyIntent(ctx context.Context, content string, contentType models.ContentType) (*MessageIntent, error) {
	result := &MessageIntent{
		PrimaryIntent: IntentUnknown,
		UrgencyLevel:  UrgencyNone,
	}

	// First, apply rule-based classification
	c.applyRuleBasedClassification(content, result)

	// Then use LLM for more nuanced analysis
	if c.llmClient != nil {
		llmResult, err := c.classifyWithLLM(ctx, content, contentType)
		if err != nil {
			c.logger.Warn().Err(err).Msg("LLM classification failed, using rule-based only")
		} else {
			c.mergeLLMResult(result, llmResult)
		}
	}

	// Calculate overall risk score
	c.calculateRiskScore(result)

	return result, nil
}

// applyRuleBasedClassification applies rule-based intent classification
func (c *IntentClassifier) applyRuleBasedClassification(content string, result *MessageIntent) {
	contentLower := strings.ToLower(content)

	// Check for urgency indicators
	result.UrgencyLevel = c.detectUrgencyLevel(contentLower)

	// Check for pressure tactics
	result.PressureTactics = c.detectPressureTactics(contentLower)

	// Check for manipulation techniques
	result.Manipulation = c.detectManipulation(contentLower)

	// Check for scam patterns
	c.checkScamPatterns(content, result)

	// Analyze requests in the message
	result.Requests = c.analyzeRequests(contentLower)

	// Determine primary intent from patterns
	c.determineIntentFromPatterns(result)
}

// detectUrgencyLevel detects the urgency level in content
func (c *IntentClassifier) detectUrgencyLevel(content string) UrgencyLevel {
	extremePatterns := []string{
		"act now or", "last chance", "expires in minutes",
		"immediate action required", "your account will be closed",
		"respond within 24 hours or", "urgent: your account has been",
		"final warning", "immediate suspension",
	}

	highPatterns := []string{
		"urgent", "immediately", "asap", "right now",
		"don't delay", "time sensitive", "expires today",
		"limited time", "act fast", "hurry",
	}

	mediumPatterns := []string{
		"soon", "quickly", "deadline", "expiring",
		"don't miss", "limited offer", "ending soon",
	}

	lowPatterns := []string{
		"when you can", "at your convenience", "reminder",
	}

	for _, pattern := range extremePatterns {
		if strings.Contains(content, pattern) {
			return UrgencyExtreme
		}
	}

	for _, pattern := range highPatterns {
		if strings.Contains(content, pattern) {
			return UrgencyHigh
		}
	}

	for _, pattern := range mediumPatterns {
		if strings.Contains(content, pattern) {
			return UrgencyMedium
		}
	}

	for _, pattern := range lowPatterns {
		if strings.Contains(content, pattern) {
			return UrgencyLow
		}
	}

	return UrgencyNone
}

// detectPressureTactics detects pressure tactics in content
func (c *IntentClassifier) detectPressureTactics(content string) []string {
	var tactics []string

	tacticPatterns := map[string][]string{
		"artificial_scarcity": {
			"only \\d+ left", "limited spots", "exclusive offer",
			"while supplies last", "first come first served",
		},
		"fear_of_loss": {
			"you will lose", "don't miss out", "before it's too late",
			"your account will be", "suspended", "terminated",
		},
		"social_proof": {
			"everyone is", "thousands have", "people like you",
			"others are already", "join millions",
		},
		"authority_appeal": {
			"official notice", "government", "law enforcement",
			"legal action", "court order", "compliance required",
		},
		"reciprocity": {
			"we've already", "as a thank you", "because you're valued",
			"special for you", "exclusive access",
		},
		"commitment_consistency": {
			"you agreed to", "as discussed", "following up on",
			"you previously", "continuing our conversation",
		},
	}

	for tactic, patterns := range tacticPatterns {
		for _, pattern := range patterns {
			matched, _ := regexp.MatchString(pattern, content)
			if matched || strings.Contains(content, pattern) {
				tactics = append(tactics, tactic)
				break
			}
		}
	}

	return tactics
}

// detectManipulation detects psychological manipulation
func (c *IntentClassifier) detectManipulation(content string) *ManipulationAnalysis {
	analysis := &ManipulationAnalysis{
		IsManipulative: false,
	}

	techniques := []ManipulationTechnique{
		{
			Name:        "Fear Induction",
			Description: "Creating fear to prompt action",
			Severity:    "high",
		},
		{
			Name:        "Greed Exploitation",
			Description: "Appealing to desire for money/rewards",
			Severity:    "medium",
		},
		{
			Name:        "Trust Exploitation",
			Description: "Impersonating trusted entities",
			Severity:    "high",
		},
		{
			Name:        "Sympathy Appeal",
			Description: "Exploiting compassion",
			Severity:    "medium",
		},
		{
			Name:        "Authority Impersonation",
			Description: "Pretending to be authority figures",
			Severity:    "high",
		},
	}

	// Fear patterns
	fearPatterns := []string{
		"your account has been compromised", "security alert",
		"unusual activity", "unauthorized access", "suspended",
		"legal action", "arrest warrant", "tax fraud",
	}

	// Greed patterns
	greedPatterns := []string{
		"won", "winner", "prize", "lottery", "inheritance",
		"million", "billion", "guaranteed returns", "investment opportunity",
		"double your money", "free money",
	}

	// Trust patterns
	trustPatterns := []string{
		"your bank", "official", "verified", "trusted",
		"secure message from", "important notice from",
	}

	// Sympathy patterns
	sympathyPatterns := []string{
		"help me", "dying", "sick child", "medical emergency",
		"stranded", "need your help", "please help",
	}

	// Authority patterns
	authorityPatterns := []string{
		"irs", "fbi", "police", "government", "microsoft support",
		"apple support", "tech support", "court", "judge",
	}

	if containsAny(content, fearPatterns) {
		techniques[0].Examples = findMatches(content, fearPatterns)
		analysis.Techniques = append(analysis.Techniques, techniques[0])
		analysis.EmotionalTriggers = append(analysis.EmotionalTriggers, "fear")
		analysis.TargetedEmotions = append(analysis.TargetedEmotions, "anxiety", "panic")
	}

	if containsAny(content, greedPatterns) {
		techniques[1].Examples = findMatches(content, greedPatterns)
		analysis.Techniques = append(analysis.Techniques, techniques[1])
		analysis.EmotionalTriggers = append(analysis.EmotionalTriggers, "greed")
		analysis.TargetedEmotions = append(analysis.TargetedEmotions, "excitement", "hope")
	}

	if containsAny(content, trustPatterns) {
		techniques[2].Examples = findMatches(content, trustPatterns)
		analysis.Techniques = append(analysis.Techniques, techniques[2])
		analysis.EmotionalTriggers = append(analysis.EmotionalTriggers, "trust")
	}

	if containsAny(content, sympathyPatterns) {
		techniques[3].Examples = findMatches(content, sympathyPatterns)
		analysis.Techniques = append(analysis.Techniques, techniques[3])
		analysis.EmotionalTriggers = append(analysis.EmotionalTriggers, "sympathy")
		analysis.TargetedEmotions = append(analysis.TargetedEmotions, "compassion", "guilt")
	}

	if containsAny(content, authorityPatterns) {
		techniques[4].Examples = findMatches(content, authorityPatterns)
		analysis.Techniques = append(analysis.Techniques, techniques[4])
		analysis.EmotionalTriggers = append(analysis.EmotionalTriggers, "authority")
		analysis.TargetedEmotions = append(analysis.TargetedEmotions, "compliance", "fear")
	}

	if len(analysis.Techniques) > 0 {
		analysis.IsManipulative = true
		if len(analysis.Techniques) >= 3 {
			analysis.OverallSeverity = "critical"
		} else if len(analysis.Techniques) >= 2 {
			analysis.OverallSeverity = "high"
		} else {
			analysis.OverallSeverity = "medium"
		}
	} else {
		analysis.OverallSeverity = "none"
	}

	return analysis
}

// checkScamPatterns checks for known scam patterns
func (c *IntentClassifier) checkScamPatterns(content string, result *MessageIntent) {
	contentLower := strings.ToLower(content)

	// Phishing patterns
	phishingPatterns := []string{
		"verify your account", "confirm your identity",
		"update your payment", "click here to login",
		"your password expires", "unusual sign-in activity",
		"reset your password", "verify your information",
	}

	// Advance fee patterns
	advanceFeePatterns := []string{
		"processing fee", "transfer fee", "tax payment required",
		"pay a small fee", "advance payment", "release the funds",
		"clearance fee", "insurance fee",
	}

	// Romance scam patterns
	romancePatterns := []string{
		"i love you", "my dear", "my darling", "deployed overseas",
		"send me money", "need money for flight", "stuck abroad",
		"can't access my bank", "wire transfer",
	}

	// Tech support patterns
	techSupportPatterns := []string{
		"your computer has virus", "detected malware",
		"call this number immediately", "microsoft detected",
		"your ip has been", "hacked", "download this tool",
	}

	// Investment scam patterns
	investmentPatterns := []string{
		"guaranteed returns", "risk-free investment",
		"double your money", "exclusive opportunity",
		"get rich quick", "secret trading", "insider information",
	}

	// Crypto scam patterns
	cryptoPatterns := []string{
		"send bitcoin", "send crypto", "wallet address",
		"airdrop", "giveaway", "double your crypto",
		"eth giveaway", "btc giveaway", "send 0.1 btc",
	}

	if containsAny(contentLower, phishingPatterns) {
		result.ScamIndicators = append(result.ScamIndicators, "phishing_language")
		result.IsScam = true
		result.ScamType = models.ScamTypePhishing
	}

	if containsAny(contentLower, advanceFeePatterns) {
		result.ScamIndicators = append(result.ScamIndicators, "advance_fee_request")
		result.IsScam = true
		result.ScamType = models.ScamTypeAdvanceFee
	}

	if containsAny(contentLower, romancePatterns) {
		result.ScamIndicators = append(result.ScamIndicators, "romance_scam_language")
		result.IsScam = true
		result.ScamType = models.ScamTypeRomance
	}

	if containsAny(contentLower, techSupportPatterns) {
		result.ScamIndicators = append(result.ScamIndicators, "tech_support_scam")
		result.IsScam = true
		result.ScamType = models.ScamTypeTechSupport
	}

	if containsAny(contentLower, investmentPatterns) {
		result.ScamIndicators = append(result.ScamIndicators, "investment_scam")
		result.IsScam = true
		result.ScamType = models.ScamTypeInvestment
	}

	if containsAny(contentLower, cryptoPatterns) {
		result.ScamIndicators = append(result.ScamIndicators, "crypto_scam")
		result.IsScam = true
		result.ScamType = models.ScamTypeCrypto
	}
}

// analyzeRequests analyzes what the message is requesting
func (c *IntentClassifier) analyzeRequests(content string) []RequestAnalysis {
	var requests []RequestAnalysis

	// Money requests
	moneyPatterns := []string{
		"send money", "wire transfer", "bank transfer",
		"pay", "payment", "fee", "deposit",
	}

	// Personal info requests
	personalInfoPatterns := []string{
		"social security", "ssn", "date of birth", "dob",
		"mother's maiden name", "password", "pin", "cvv",
		"credit card", "bank account", "routing number",
	}

	// Action requests
	actionPatterns := []string{
		"click here", "download", "install", "call this number",
		"reply with", "send your", "provide your",
	}

	// Access requests
	accessPatterns := []string{
		"remote access", "teamviewer", "anydesk", "screen share",
		"give access", "let me access",
	}

	if containsAny(content, moneyPatterns) {
		requests = append(requests, RequestAnalysis{
			RequestType:  "financial",
			Description:  "Request for money or payment",
			IsRisky:      true,
			RiskReason:   "Financial requests are common in scams",
			TargetAction: "Send money",
		})
	}

	if containsAny(content, personalInfoPatterns) {
		requests = append(requests, RequestAnalysis{
			RequestType:  "personal_information",
			Description:  "Request for sensitive personal information",
			IsRisky:      true,
			RiskReason:   "Legitimate organizations don't ask for sensitive info via message",
			TargetAction: "Provide personal data",
		})
	}

	if containsAny(content, actionPatterns) {
		requests = append(requests, RequestAnalysis{
			RequestType:  "action",
			Description:  "Request to perform an action",
			IsRisky:      true,
			RiskReason:   "Could lead to malware installation or credential theft",
			TargetAction: "Click/Download/Install",
		})
	}

	if containsAny(content, accessPatterns) {
		requests = append(requests, RequestAnalysis{
			RequestType:  "remote_access",
			Description:  "Request for remote computer access",
			IsRisky:      true,
			RiskReason:   "Remote access can lead to full system compromise",
			TargetAction: "Grant remote access",
		})
	}

	return requests
}

// determineIntentFromPatterns determines the primary intent from detected patterns
func (c *IntentClassifier) determineIntentFromPatterns(result *MessageIntent) {
	if result.IsScam {
		switch result.ScamType {
		case models.ScamTypePhishing:
			result.PrimaryIntent = IntentPhishing
		case models.ScamTypeAdvanceFee:
			result.PrimaryIntent = IntentAdvanceFee
		case models.ScamTypeRomance:
			result.PrimaryIntent = IntentRomanceScam
		case models.ScamTypeTechSupport:
			result.PrimaryIntent = IntentTechSupport
		case models.ScamTypeInvestment:
			result.PrimaryIntent = IntentInvestmentScam
		case models.ScamTypeCrypto:
			result.PrimaryIntent = IntentCryptoScam
		default:
			result.PrimaryIntent = IntentFinancialScam
		}
		result.Confidence = 0.7 // Rule-based confidence
	}
}

// classifyWithLLM uses LLM for intent classification
func (c *IntentClassifier) classifyWithLLM(ctx context.Context, content string, contentType models.ContentType) (*MessageIntent, error) {
	systemPrompt := `You are an expert scam detection analyst. Analyze the following message and classify its intent.

Provide your analysis in JSON format with the following structure:
{
  "primary_intent": "intent_type",
  "confidence": 0.0-1.0,
  "secondary_intents": [{"intent": "type", "confidence": 0.0-1.0}],
  "is_scam": boolean,
  "scam_type": "type_if_scam",
  "scam_indicators": ["list of indicators"],
  "risk_score": 0.0-1.0,
  "risk_factors": [{"factor": "name", "description": "desc", "weight": 0.0-1.0}],
  "urgency_level": "none|low|medium|high|extreme",
  "pressure_tactics": ["list"],
  "explanation": "detailed explanation"
}

Intent types:
- informational: General information sharing
- transactional: Legitimate business transaction
- support: Customer support
- marketing: Marketing/promotional
- social: Social communication
- verification: Legitimate verification
- phishing: Credential/data theft attempt
- financial_scam: Money theft attempt
- romance_scam: Romance/relationship scam
- tech_support_scam: Fake tech support
- impersonation: Impersonating known entity
- extortion: Blackmail/extortion
- advance_fee_scam: Advance fee fraud
- investment_scam: Fake investment
- crypto_scam: Cryptocurrency scam
- job_scam: Fake job offer
- lottery_scam: Fake lottery/prize
- charity_scam: Fake charity
- malware_delivery: Malware distribution`

	userPrompt := fmt.Sprintf("Analyze this %s message for scam indicators and classify its intent:\n\n%s", contentType, content)

	response, err := c.llmClient.Chat(ctx, []Message{NewTextMessage("user", userPrompt)}, systemPrompt)
	if err != nil {
		return nil, err
	}

	return c.parseLLMIntentResponse(response)
}

// parseLLMIntentResponse parses LLM response into MessageIntent
func (c *IntentClassifier) parseLLMIntentResponse(response string) (*MessageIntent, error) {
	result := &MessageIntent{}

	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return nil, fmt.Errorf("no JSON found in response")
	}

	var parsed struct {
		PrimaryIntent    string  `json:"primary_intent"`
		Confidence       float64 `json:"confidence"`
		SecondaryIntents []struct {
			Intent     string  `json:"intent"`
			Confidence float64 `json:"confidence"`
		} `json:"secondary_intents"`
		IsScam          bool     `json:"is_scam"`
		ScamType        string   `json:"scam_type"`
		ScamIndicators  []string `json:"scam_indicators"`
		RiskScore       float64  `json:"risk_score"`
		RiskFactors     []struct {
			Factor      string  `json:"factor"`
			Description string  `json:"description"`
			Weight      float64 `json:"weight"`
		} `json:"risk_factors"`
		UrgencyLevel    string   `json:"urgency_level"`
		PressureTactics []string `json:"pressure_tactics"`
		Explanation     string   `json:"explanation"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	result.PrimaryIntent = Intent(parsed.PrimaryIntent)
	result.Confidence = parsed.Confidence
	result.IsScam = parsed.IsScam
	result.ScamType = models.ScamType(parsed.ScamType)
	result.ScamIndicators = parsed.ScamIndicators
	result.RiskScore = parsed.RiskScore
	result.UrgencyLevel = UrgencyLevel(parsed.UrgencyLevel)
	result.PressureTactics = parsed.PressureTactics
	result.Explanation = parsed.Explanation

	for _, si := range parsed.SecondaryIntents {
		result.SecondaryIntents = append(result.SecondaryIntents, IntentScore{
			Intent:     Intent(si.Intent),
			Confidence: si.Confidence,
		})
	}

	for _, rf := range parsed.RiskFactors {
		result.RiskFactors = append(result.RiskFactors, RiskFactor{
			Factor:      rf.Factor,
			Description: rf.Description,
			Weight:      rf.Weight,
		})
	}

	return result, nil
}

// mergeLLMResult merges LLM result with rule-based result
func (c *IntentClassifier) mergeLLMResult(result *MessageIntent, llmResult *MessageIntent) {
	if llmResult == nil {
		return
	}

	// Use LLM's primary intent if confidence is higher
	if llmResult.Confidence > result.Confidence {
		result.PrimaryIntent = llmResult.PrimaryIntent
		result.Confidence = llmResult.Confidence
	}

	// Merge scam detection
	if llmResult.IsScam && !result.IsScam {
		result.IsScam = true
		result.ScamType = llmResult.ScamType
	}

	// Merge indicators (deduplicate)
	for _, indicator := range llmResult.ScamIndicators {
		if !containsString(result.ScamIndicators, indicator) {
			result.ScamIndicators = append(result.ScamIndicators, indicator)
		}
	}

	// Merge risk factors
	result.RiskFactors = append(result.RiskFactors, llmResult.RiskFactors...)

	// Use higher urgency
	if urgencyToInt(llmResult.UrgencyLevel) > urgencyToInt(result.UrgencyLevel) {
		result.UrgencyLevel = llmResult.UrgencyLevel
	}

	// Merge pressure tactics
	for _, tactic := range llmResult.PressureTactics {
		if !containsString(result.PressureTactics, tactic) {
			result.PressureTactics = append(result.PressureTactics, tactic)
		}
	}

	// Use LLM explanation if available
	if llmResult.Explanation != "" {
		result.Explanation = llmResult.Explanation
	}

	// Merge secondary intents
	result.SecondaryIntents = llmResult.SecondaryIntents
}

// calculateRiskScore calculates the overall risk score
func (c *IntentClassifier) calculateRiskScore(result *MessageIntent) {
	var score float64

	// Base score from scam detection
	if result.IsScam {
		score += 0.5
	}

	// Add manipulation score
	if result.Manipulation != nil && result.Manipulation.IsManipulative {
		switch result.Manipulation.OverallSeverity {
		case "critical":
			score += 0.3
		case "high":
			score += 0.2
		case "medium":
			score += 0.1
		}
	}

	// Add urgency score
	switch result.UrgencyLevel {
	case UrgencyExtreme:
		score += 0.15
	case UrgencyHigh:
		score += 0.1
	case UrgencyMedium:
		score += 0.05
	}

	// Add pressure tactics score
	score += float64(len(result.PressureTactics)) * 0.05

	// Add risky requests score
	for _, req := range result.Requests {
		if req.IsRisky {
			score += 0.1
		}
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	result.RiskScore = score
}

// Helper functions

func containsAny(content string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

func findMatches(content string, patterns []string) []string {
	var matches []string
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			matches = append(matches, pattern)
		}
	}
	return matches
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func urgencyToInt(level UrgencyLevel) int {
	switch level {
	case UrgencyExtreme:
		return 4
	case UrgencyHigh:
		return 3
	case UrgencyMedium:
		return 2
	case UrgencyLow:
		return 1
	default:
		return 0
	}
}
