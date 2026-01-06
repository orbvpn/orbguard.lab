package services

import (
	"regexp"
	"strings"

	"orbguard-lab/internal/domain/models"
)

// ExecutiveImpersonationDetector detects CEO/executive impersonation attacks (BEC)
type ExecutiveImpersonationDetector struct {
	// User's organization context (would be configured per-user/org)
	executives     []ExecutiveProfile
	companyDomains []string
}

// ExecutiveProfile represents a known executive
type ExecutiveProfile struct {
	Name     string
	Title    string
	Email    string
	Phone    string
	Aliases  []string
}

// NewExecutiveImpersonationDetector creates a new detector
func NewExecutiveImpersonationDetector() *ExecutiveImpersonationDetector {
	return &ExecutiveImpersonationDetector{
		executives:     []ExecutiveProfile{},
		companyDomains: []string{},
	}
}

// SetExecutives configures known executives for the organization
func (d *ExecutiveImpersonationDetector) SetExecutives(executives []ExecutiveProfile) {
	d.executives = executives
}

// SetCompanyDomains configures the company's email domains
func (d *ExecutiveImpersonationDetector) SetCompanyDomains(domains []string) {
	d.companyDomains = domains
}

// ImpersonationResult contains the detection result
type ImpersonationResult struct {
	IsImpersonation  bool     `json:"is_impersonation"`
	Confidence       float64  `json:"confidence"`
	ImpersonatedName string   `json:"impersonated_name,omitempty"`
	ImpersonatedRole string   `json:"impersonated_role,omitempty"`
	TacticUsed       string   `json:"tactic_used,omitempty"`
	Indicators       []string `json:"indicators,omitempty"`
}

// Detect analyzes a message for executive impersonation
func (d *ExecutiveImpersonationDetector) Detect(sender string, body string) *ImpersonationResult {
	result := &ImpersonationResult{
		IsImpersonation: false,
		Confidence:      0,
		Indicators:      []string{},
	}

	bodyLower := strings.ToLower(body)
	senderLower := strings.ToLower(sender)

	// Check for CEO/executive title mentions
	executiveTitles := []string{
		"ceo", "chief executive", "president", "cfo", "chief financial",
		"coo", "chief operating", "cto", "chief technology", "ciso",
		"vp", "vice president", "director", "managing director", "founder",
		"chairman", "board member", "executive director",
	}

	for _, title := range executiveTitles {
		if strings.Contains(bodyLower, title) || strings.Contains(senderLower, title) {
			result.ImpersonatedRole = title
			result.Confidence += 0.2
			result.Indicators = append(result.Indicators, "executive_title_mentioned")
			break
		}
	}

	// Check for specific impersonation patterns
	patterns := d.getImpersonationPatterns()
	for _, p := range patterns {
		if p.Pattern.MatchString(body) {
			result.Confidence += p.Weight
			result.Indicators = append(result.Indicators, p.Name)
			if result.TacticUsed == "" {
				result.TacticUsed = p.Tactic
			}
		}
	}

	// Check for urgent wire transfer requests
	if d.detectWireTransferRequest(bodyLower) {
		result.Confidence += 0.3
		result.Indicators = append(result.Indicators, "wire_transfer_request")
		result.TacticUsed = "wire_transfer_fraud"
	}

	// Check for gift card requests
	if d.detectGiftCardRequest(bodyLower) {
		result.Confidence += 0.35
		result.Indicators = append(result.Indicators, "gift_card_request")
		result.TacticUsed = "gift_card_fraud"
	}

	// Check for secrecy/urgency combination
	if d.hasSecrecyIndicator(bodyLower) && d.hasUrgencyIndicator(bodyLower) {
		result.Confidence += 0.2
		result.Indicators = append(result.Indicators, "secrecy_urgency_combo")
	}

	// Check if sender is impersonating known executive
	for _, exec := range d.executives {
		if d.matchesExecutive(senderLower, bodyLower, exec) {
			result.ImpersonatedName = exec.Name
			result.ImpersonatedRole = exec.Title
			result.Confidence += 0.3
			result.Indicators = append(result.Indicators, "matches_known_executive")
			break
		}
	}

	// Determine if this is impersonation
	if result.Confidence >= 0.5 {
		result.IsImpersonation = true
	}

	// Cap confidence at 1.0
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	return result
}

// ImpersonationPattern represents a detection pattern
type ImpersonationPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Weight  float64
	Tactic  string
}

// getImpersonationPatterns returns patterns for detecting BEC attacks
func (d *ExecutiveImpersonationDetector) getImpersonationPatterns() []ImpersonationPattern {
	return []ImpersonationPattern{
		// Authority establishment
		{
			Name:    "authority_claim",
			Pattern: regexp.MustCompile(`(?i)(this is|i am|it's)\s+(the\s+)?(ceo|president|founder|boss|your boss|[a-z]+\s+from\s+(executive|management))`),
			Weight:  0.25,
			Tactic:  "authority_impersonation",
		},
		// Meeting excuse (can't talk)
		{
			Name:    "meeting_excuse",
			Pattern: regexp.MustCompile(`(?i)(in a meeting|can't (talk|call)|stuck in|busy with|conference)`),
			Weight:  0.15,
			Tactic:  "unavailability_excuse",
		},
		// Urgent favor request
		{
			Name:    "urgent_favor",
			Pattern: regexp.MustCompile(`(?i)(need (you|your|a) (to|help)|favor|urgent (task|matter|request)|quick favor)`),
			Weight:  0.2,
			Tactic:  "urgent_request",
		},
		// Keep it confidential
		{
			Name:    "confidential_request",
			Pattern: regexp.MustCompile(`(?i)(keep (this|it) (quiet|between us|confidential)|don't (mention|tell|share)|discreet|private matter)`),
			Weight:  0.25,
			Tactic:  "secrecy_demand",
		},
		// Immediate action required
		{
			Name:    "immediate_action",
			Pattern: regexp.MustCompile(`(?i)(right (now|away)|immediately|asap|urgent|time.?sensitive|before.*(day|end|close))`),
			Weight:  0.15,
			Tactic:  "urgency_pressure",
		},
		// Will explain later
		{
			Name:    "explain_later",
			Pattern: regexp.MustCompile(`(?i)(explain|tell you|discuss).*(later|when i'm back|after|tomorrow)`),
			Weight:  0.15,
			Tactic:  "deferred_explanation",
		},
		// Invoice payment
		{
			Name:    "invoice_payment",
			Pattern: regexp.MustCompile(`(?i)(pay|process|send).*(invoice|payment|vendor|supplier)`),
			Weight:  0.2,
			Tactic:  "invoice_fraud",
		},
		// Change bank details
		{
			Name:    "bank_details_change",
			Pattern: regexp.MustCompile(`(?i)(change|update|new).*(bank|account|routing|wire|payment).*(details|info|number)`),
			Weight:  0.35,
			Tactic:  "bank_details_fraud",
		},
		// Personal phone/email request
		{
			Name:    "personal_contact",
			Pattern: regexp.MustCompile(`(?i)(using|from) (my|a) (personal|private) (phone|email|number)`),
			Weight:  0.2,
			Tactic:  "personal_device_excuse",
		},
	}
}

// detectWireTransferRequest checks for wire transfer patterns
func (d *ExecutiveImpersonationDetector) detectWireTransferRequest(body string) bool {
	patterns := []string{
		"wire transfer",
		"bank transfer",
		"transfer funds",
		"send money",
		"process payment",
		"wire the money",
		"transfer immediately",
		"urgent payment",
		"send to this account",
	}

	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// detectGiftCardRequest checks for gift card purchase patterns
func (d *ExecutiveImpersonationDetector) detectGiftCardRequest(body string) bool {
	patterns := []string{
		"gift card",
		"giftcard",
		"amazon card",
		"itunes card",
		"google play card",
		"buy some cards",
		"purchase cards",
		"scratch off",
		"send the codes",
		"send me the numbers",
	}

	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// hasSecrecyIndicator checks for secrecy language
func (d *ExecutiveImpersonationDetector) hasSecrecyIndicator(body string) bool {
	patterns := []string{
		"keep this",
		"don't tell",
		"don't mention",
		"between us",
		"confidential",
		"private",
		"secret",
		"discreet",
	}

	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// hasUrgencyIndicator checks for urgency language
func (d *ExecutiveImpersonationDetector) hasUrgencyIndicator(body string) bool {
	patterns := []string{
		"urgent",
		"asap",
		"right now",
		"immediately",
		"time sensitive",
		"don't delay",
		"before close",
		"end of day",
	}

	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// matchesExecutive checks if message might be impersonating a known executive
func (d *ExecutiveImpersonationDetector) matchesExecutive(sender, body string, exec ExecutiveProfile) bool {
	nameLower := strings.ToLower(exec.Name)
	nameParts := strings.Fields(nameLower)

	// Check if sender contains executive name
	for _, part := range nameParts {
		if len(part) > 2 && strings.Contains(sender, part) {
			return true
		}
	}

	// Check if body mentions executive name
	for _, part := range nameParts {
		if len(part) > 2 && strings.Contains(body, part) {
			// Check if paired with authority language
			if strings.Contains(body, "this is") || strings.Contains(body, "i am") {
				return true
			}
		}
	}

	// Check aliases
	for _, alias := range exec.Aliases {
		if strings.Contains(sender, strings.ToLower(alias)) {
			return true
		}
	}

	return false
}

// AnalyzeSMSForImpersonation integrates with SMS analysis
func (d *ExecutiveImpersonationDetector) AnalyzeSMSForImpersonation(result *models.SMSAnalysisResult, sender, body string) {
	impersonation := d.Detect(sender, body)

	if impersonation.IsImpersonation {
		result.IsThreat = true
		result.ThreatType = models.SMSThreatTypeExecutiveImpersonation
		result.Confidence = impersonation.Confidence

		// Add to pattern matches
		for _, indicator := range impersonation.Indicators {
			result.PatternMatches = append(result.PatternMatches, models.SMSPatternMatch{
				PatternName: indicator,
				PatternType: "executive_impersonation",
				Confidence:  impersonation.Confidence,
				Description: "Executive impersonation indicator: " + indicator,
			})
		}

		// Update recommendations
		result.Recommendations = append(result.Recommendations,
			"This message may be an executive impersonation scam (BEC attack)",
			"Do NOT send money, gift cards, or sensitive information",
			"Verify the sender's identity through a known phone number or in-person",
			"Contact your IT security team immediately",
		)

		if impersonation.TacticUsed == "gift_card_fraud" {
			result.Recommendations = append(result.Recommendations,
				"ALERT: Legitimate executives never ask employees to buy gift cards via SMS",
			)
		}

		if impersonation.TacticUsed == "wire_transfer_fraud" {
			result.Recommendations = append(result.Recommendations,
				"ALERT: Always verify wire transfer requests through established procedures",
			)
		}

		// Update threat level
		if impersonation.Confidence >= 0.8 {
			result.ThreatLevel = models.ThreatLevelCritical
			result.Description = "CRITICAL: High-confidence executive impersonation attack detected"
		} else if impersonation.Confidence >= 0.6 {
			result.ThreatLevel = models.ThreatLevelHigh
			result.Description = "HIGH: Likely executive impersonation attempt"
		}
	}
}
