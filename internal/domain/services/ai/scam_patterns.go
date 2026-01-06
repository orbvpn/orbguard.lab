package ai

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// ScamPatternDB contains a database of known scam patterns
type ScamPatternDB struct {
	mu       sync.RWMutex
	logger   *logger.Logger
	patterns []ScamPattern
	regexCache map[string]*regexp.Regexp
}

// ScamPattern represents a scam detection pattern
type ScamPattern struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Category        models.ScamType     `json:"category"`
	Severity        models.ScamSeverity `json:"severity"`
	Patterns        []string            `json:"patterns"`         // Regex patterns
	Keywords        []string            `json:"keywords"`         // Simple keyword matches
	RequiredMatches int                 `json:"required_matches"` // Min patterns/keywords to match
	Weight          float64             `json:"weight"`           // 0-1 weight for scoring
	Enabled         bool                `json:"enabled"`
	Language        string              `json:"language,omitempty"` // "" for all languages
	Region          string              `json:"region,omitempty"`   // "" for all regions
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

// PatternMatch represents a matched pattern
type PatternMatch struct {
	PatternID   string              `json:"pattern_id"`
	PatternName string              `json:"pattern_name"`
	Category    models.ScamType     `json:"category"`
	Severity    models.ScamSeverity `json:"severity"`
	Matches     []string            `json:"matches"`
	Weight      float64             `json:"weight"`
	Context     string              `json:"context,omitempty"`
}

// NewScamPatternDB creates a new scam pattern database
func NewScamPatternDB(log *logger.Logger) *ScamPatternDB {
	db := &ScamPatternDB{
		logger:     log.WithComponent("scam-pattern-db"),
		regexCache: make(map[string]*regexp.Regexp),
	}
	db.loadDefaultPatterns()
	return db
}

// loadDefaultPatterns loads the default scam patterns
func (db *ScamPatternDB) loadDefaultPatterns() {
	db.patterns = []ScamPattern{
		// Phishing patterns
		{
			ID:          "phish-001",
			Name:        "Account Verification Request",
			Description: "Requests to verify account credentials",
			Category:    models.ScamTypePhishing,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"verify your account", "confirm your identity", "verify your information",
				"account verification required", "validate your account",
				"update your account information", "verify your credentials",
			},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
		},
		{
			ID:          "phish-002",
			Name:        "Password Expiry",
			Description: "Claims password is expiring or needs reset",
			Category:    models.ScamTypePhishing,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"password expires", "password expiring", "password will expire",
				"reset your password", "change your password immediately",
				"password has been compromised",
			},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
		},
		{
			ID:          "phish-003",
			Name:        "Suspicious Login Activity",
			Description: "Claims of unusual or suspicious login activity",
			Category:    models.ScamTypePhishing,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"unusual sign-in", "suspicious login", "unauthorized access",
				"unusual activity", "someone tried to sign in", "login from new device",
				"access from unknown location",
			},
			RequiredMatches: 1,
			Weight:          0.75,
			Enabled:         true,
		},
		{
			ID:          "phish-004",
			Name:        "Click Link Urgency",
			Description: "Urgently requesting to click a link",
			Category:    models.ScamTypePhishing,
			Severity:    models.ScamSeverityMedium,
			Patterns: []string{
				`click\s+(here|below|this\s+link)\s+(immediately|now|asap)`,
				`(urgent|important).*click\s+(here|below)`,
			},
			Keywords: []string{
				"click here immediately", "click this link now",
				"click below to verify", "click to confirm",
			},
			RequiredMatches: 1,
			Weight:          0.7,
			Enabled:         true,
		},

		// Advance Fee Fraud
		{
			ID:          "advfee-001",
			Name:        "Inheritance Scam",
			Description: "Claims of inheritance from unknown relative",
			Category:    models.ScamTypeAdvanceFee,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"inheritance", "deceased relative", "next of kin",
				"unclaimed funds", "estate of", "beneficiary",
				"late mr", "late mrs", "late dr",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
		},
		{
			ID:          "advfee-002",
			Name:        "Lottery/Prize Scam",
			Description: "Claims of winning a lottery or prize",
			Category:    models.ScamTypeLottery,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"you have won", "congratulations winner", "lottery winner",
				"prize winner", "claim your prize", "winning ticket",
				"lucky winner", "you've been selected", "award notification",
			},
			RequiredMatches: 1,
			Weight:          0.9,
			Enabled:         true,
		},
		{
			ID:          "advfee-003",
			Name:        "Processing Fee Request",
			Description: "Requests for fees to release funds",
			Category:    models.ScamTypeAdvanceFee,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"processing fee", "transfer fee", "clearance fee",
				"release fee", "handling fee", "administrative fee",
				"pay to receive", "small fee to release",
			},
			RequiredMatches: 1,
			Weight:          0.85,
			Enabled:         true,
		},

		// Tech Support Scams
		{
			ID:          "tech-001",
			Name:        "Virus/Malware Alert",
			Description: "Fake virus or malware warnings",
			Category:    models.ScamTypeTechSupport,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"virus detected", "malware found", "your computer is infected",
				"security threat detected", "your device has been compromised",
				"critical security warning", "trojan detected",
			},
			RequiredMatches: 1,
			Weight:          0.85,
			Enabled:         true,
		},
		{
			ID:          "tech-002",
			Name:        "Tech Support Call Request",
			Description: "Requests to call fake tech support",
			Category:    models.ScamTypeTechSupport,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"call microsoft", "call apple support", "call tech support",
				"call immediately", "toll-free number", "call this number",
				"speak to technician", "our technicians",
			},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
		},
		{
			ID:          "tech-003",
			Name:        "Remote Access Request",
			Description: "Requests for remote computer access",
			Category:    models.ScamTypeTechSupport,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"remote access", "teamviewer", "anydesk", "logmein",
				"remote desktop", "screen share", "take control",
				"connect to your computer",
			},
			RequiredMatches: 1,
			Weight:          0.9,
			Enabled:         true,
		},

		// Romance Scams
		{
			ID:          "romance-001",
			Name:        "Love Bombing",
			Description: "Excessive declarations of love early on",
			Category:    models.ScamTypeRomance,
			Severity:    models.ScamSeverityMedium,
			Keywords: []string{
				"i love you", "i'm in love with you", "my love for you",
				"you are my soulmate", "we are meant to be", "true love",
				"my heart belongs to you", "love at first sight",
			},
			RequiredMatches: 2,
			Weight:          0.6,
			Enabled:         true,
		},
		{
			ID:          "romance-002",
			Name:        "Military/Overseas Deployment",
			Description: "Claims of being deployed overseas",
			Category:    models.ScamTypeRomance,
			Severity:    models.ScamSeverityMedium,
			Keywords: []string{
				"deployed overseas", "military deployment", "serving abroad",
				"stationed in", "peacekeeping mission", "oil rig",
				"ship captain", "working offshore",
			},
			RequiredMatches: 1,
			Weight:          0.7,
			Enabled:         true,
		},
		{
			ID:          "romance-003",
			Name:        "Emergency Money Request",
			Description: "Urgent requests for money from romantic interest",
			Category:    models.ScamTypeRomance,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"send me money", "need money urgently", "wire transfer",
				"western union", "moneygram", "gift cards",
				"emergency", "stuck", "stranded", "can't access my bank",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
		},

		// Investment Scams
		{
			ID:          "invest-001",
			Name:        "Guaranteed Returns",
			Description: "Promises of guaranteed investment returns",
			Category:    models.ScamTypeInvestment,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"guaranteed returns", "guaranteed profit", "risk-free investment",
				"guaranteed income", "100% safe", "zero risk",
				"no risk", "sure profit", "certain returns",
			},
			RequiredMatches: 1,
			Weight:          0.85,
			Enabled:         true,
		},
		{
			ID:          "invest-002",
			Name:        "Get Rich Quick",
			Description: "Promises of quick wealth",
			Category:    models.ScamTypeInvestment,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"get rich quick", "double your money", "multiply your investment",
				"10x returns", "100x returns", "make millions",
				"financial freedom", "quit your job", "retire early",
			},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
		},
		{
			ID:          "invest-003",
			Name:        "Insider/Secret Information",
			Description: "Claims of insider or secret investment information",
			Category:    models.ScamTypeInvestment,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"insider information", "secret strategy", "hidden opportunity",
				"exclusive tip", "they don't want you to know",
				"wall street secret", "millionaire's secret",
			},
			RequiredMatches: 1,
			Weight:          0.9,
			Enabled:         true,
		},

		// Cryptocurrency Scams
		{
			ID:          "crypto-001",
			Name:        "Crypto Giveaway",
			Description: "Fake cryptocurrency giveaway",
			Category:    models.ScamTypeCrypto,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"crypto giveaway", "bitcoin giveaway", "eth giveaway",
				"airdrop", "free crypto", "free bitcoin",
				"send to receive", "double your crypto",
			},
			RequiredMatches: 1,
			Weight:          0.95,
			Enabled:         true,
		},
		{
			ID:          "crypto-002",
			Name:        "Send to Receive Scam",
			Description: "Requests to send crypto to receive more",
			Category:    models.ScamTypeCrypto,
			Severity:    models.ScamSeverityCritical,
			Patterns: []string{
				`send\s+[\d.]+\s*(btc|eth|crypto).*receive`,
				`send.*to.*wallet.*get.*back`,
			},
			Keywords: []string{
				"send 0.1 btc", "send 1 eth", "send crypto to receive",
				"send to this wallet", "double your bitcoin",
			},
			RequiredMatches: 1,
			Weight:          0.95,
			Enabled:         true,
		},
		{
			ID:          "crypto-003",
			Name:        "Fake Exchange/Wallet",
			Description: "Promoting fake crypto exchange or wallet",
			Category:    models.ScamTypeCrypto,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"new exchange", "revolutionary platform", "next coinbase",
				"better than binance", "exclusive trading", "new wallet",
			},
			RequiredMatches: 2,
			Weight:          0.8,
			Enabled:         true,
		},

		// Impersonation Scams
		{
			ID:          "imperson-001",
			Name:        "CEO/Executive Impersonation",
			Description: "Impersonating company executives",
			Category:    models.ScamTypeImpersonation,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"i am the ceo", "this is the ceo", "from the ceo",
				"urgent from management", "confidential request",
				"wire transfer urgent", "keep this confidential",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
		},
		{
			ID:          "imperson-002",
			Name:        "Government Agency Impersonation",
			Description: "Impersonating government agencies",
			Category:    models.ScamTypeImpersonation,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"irs", "social security", "immigration", "fbi",
				"tax authority", "police department", "customs",
				"arrest warrant", "legal action", "court summons",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
		},
		{
			ID:          "imperson-003",
			Name:        "Bank Impersonation",
			Description: "Impersonating banks or financial institutions",
			Category:    models.ScamTypeImpersonation,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"your bank", "account suspended", "card blocked",
				"fraudulent activity", "security department",
				"verify your card", "confirm transaction",
			},
			RequiredMatches: 2,
			Weight:          0.85,
			Enabled:         true,
		},

		// Extortion Scams
		{
			ID:          "extort-001",
			Name:        "Sextortion",
			Description: "Threats to release compromising content",
			Category:    models.ScamTypeExtortion,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"compromising photos", "embarrassing video", "your webcam",
				"recorded you", "send to contacts", "expose you",
				"unless you pay", "bitcoin ransom",
			},
			RequiredMatches: 2,
			Weight:          0.95,
			Enabled:         true,
		},
		{
			ID:          "extort-002",
			Name:        "Ransomware Threat",
			Description: "Threats about encrypted files or data",
			Category:    models.ScamTypeExtortion,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"encrypted your files", "ransomware", "pay to decrypt",
				"your data has been encrypted", "decryption key",
				"bitcoin payment", "time is running out",
			},
			RequiredMatches: 2,
			Weight:          0.95,
			Enabled:         true,
		},

		// Job Scams
		{
			ID:          "job-001",
			Name:        "Work From Home Scam",
			Description: "Fake work from home opportunities",
			Category:    models.ScamTypeJobScam,
			Severity:    models.ScamSeverityMedium,
			Keywords: []string{
				"work from home", "make money online", "easy money",
				"no experience needed", "start immediately",
				"be your own boss", "unlimited income",
			},
			RequiredMatches: 3,
			Weight:          0.7,
			Enabled:         true,
		},
		{
			ID:          "job-002",
			Name:        "Upfront Payment Job Scam",
			Description: "Job offers requiring upfront payment",
			Category:    models.ScamTypeJobScam,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"training fee", "registration fee", "equipment fee",
				"pay to start", "materials fee", "background check fee",
			},
			RequiredMatches: 1,
			Weight:          0.85,
			Enabled:         true,
		},

		// Urgency/Pressure Patterns
		{
			ID:          "urgency-001",
			Name:        "Extreme Urgency",
			Description: "Messages with extreme urgency pressure",
			Category:    models.ScamType("pressure"),
			Severity:    models.ScamSeverityMedium,
			Keywords: []string{
				"act now", "immediate action required", "expires in 24 hours",
				"last chance", "final warning", "don't delay",
				"time sensitive", "urgent response needed",
			},
			RequiredMatches: 1,
			Weight:          0.6,
			Enabled:         true,
		},
		{
			ID:          "urgency-002",
			Name:        "Account Suspension Threat",
			Description: "Threats to suspend or close accounts",
			Category:    models.ScamType("pressure"),
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"account will be suspended", "account will be closed",
				"service termination", "access will be revoked",
				"permanent closure", "account deactivation",
			},
			RequiredMatches: 1,
			Weight:          0.75,
			Enabled:         true,
		},

		// Multi-language patterns (Arabic)
		{
			ID:          "ar-001",
			Name:        "Arabic Phishing",
			Description: "Arabic language phishing patterns",
			Category:    models.ScamTypePhishing,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"تحقق من حسابك", "تأكيد الهوية", "تحديث المعلومات",
				"حسابك معلق", "نشاط مشبوه", "اضغط هنا",
			},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
			Language:        "ar",
		},
		{
			ID:          "ar-002",
			Name:        "Arabic Prize Scam",
			Description: "Arabic language prize/lottery scams",
			Category:    models.ScamTypeLottery,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"مبروك لقد ربحت", "جائزة", "فائز", "سحب",
				"مليون", "دولار", "درهم",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
			Language:        "ar",
		},

		// Multi-language patterns (Persian/Farsi)
		{
			ID:          "fa-001",
			Name:        "Persian Phishing",
			Description: "Persian language phishing patterns",
			Category:    models.ScamTypePhishing,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"تایید حساب", "رمز عبور", "ورود به سیستم",
				"حساب شما", "کلیک کنید", "فوری",
			},
			RequiredMatches: 1,
			Weight:          0.8,
			Enabled:         true,
			Language:        "fa",
		},

		// Multi-language patterns (Hindi)
		{
			ID:          "hi-001",
			Name:        "Hindi Prize Scam",
			Description: "Hindi language prize scams",
			Category:    models.ScamTypeLottery,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"बधाई हो आपने जीता", "पुरस्कार", "लॉटरी",
				"करोड़", "लाख", "रुपये",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
			Language:        "hi",
		},

		// UAE/Gulf specific patterns
		{
			ID:          "uae-001",
			Name:        "UAE Bank Scam",
			Description: "UAE-specific bank impersonation",
			Category:    models.ScamTypeImpersonation,
			Severity:    models.ScamSeverityHigh,
			Keywords: []string{
				"emirates nbd", "adcb", "fab", "mashreq",
				"dubai islamic bank", "rak bank", "enbd",
				"uae central bank", "dirham", "aed",
			},
			RequiredMatches: 2,
			Weight:          0.85,
			Enabled:         true,
			Region:          "UAE",
		},
		{
			ID:          "uae-002",
			Name:        "UAE Government Scam",
			Description: "UAE government impersonation",
			Category:    models.ScamTypeImpersonation,
			Severity:    models.ScamSeverityCritical,
			Keywords: []string{
				"emirates id", "visa renewal", "residence permit",
				"ministry of", "dubai police", "abu dhabi police",
				"immigration fine", "traffic fine",
			},
			RequiredMatches: 2,
			Weight:          0.9,
			Enabled:         true,
			Region:          "UAE",
		},
	}

	// Compile regex patterns
	for _, pattern := range db.patterns {
		for _, p := range pattern.Patterns {
			if _, exists := db.regexCache[p]; !exists {
				if compiled, err := regexp.Compile("(?i)" + p); err == nil {
					db.regexCache[p] = compiled
				}
			}
		}
	}
}

// Match matches content against all patterns
func (db *ScamPatternDB) Match(content string) []PatternMatch {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var matches []PatternMatch
	contentLower := strings.ToLower(content)

	for _, pattern := range db.patterns {
		if !pattern.Enabled {
			continue
		}

		matchCount := 0
		var matchedStrings []string

		// Check keywords
		for _, keyword := range pattern.Keywords {
			if strings.Contains(contentLower, strings.ToLower(keyword)) {
				matchCount++
				matchedStrings = append(matchedStrings, keyword)
			}
		}

		// Check regex patterns
		for _, p := range pattern.Patterns {
			if regex, exists := db.regexCache[p]; exists {
				if found := regex.FindAllString(content, -1); len(found) > 0 {
					matchCount++
					matchedStrings = append(matchedStrings, found...)
				}
			}
		}

		// Check if we have enough matches
		if matchCount >= pattern.RequiredMatches {
			matches = append(matches, PatternMatch{
				PatternID:   pattern.ID,
				PatternName: pattern.Name,
				Category:    pattern.Category,
				Severity:    pattern.Severity,
				Matches:     matchedStrings,
				Weight:      pattern.Weight,
			})
		}
	}

	return matches
}

// MatchWithLanguage matches content with language-specific patterns
func (db *ScamPatternDB) MatchWithLanguage(content string, language string) []PatternMatch {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var matches []PatternMatch
	contentLower := strings.ToLower(content)

	for _, pattern := range db.patterns {
		if !pattern.Enabled {
			continue
		}

		// Skip if pattern is language-specific and doesn't match
		if pattern.Language != "" && pattern.Language != language {
			continue
		}

		matchCount := 0
		var matchedStrings []string

		// Check keywords
		for _, keyword := range pattern.Keywords {
			if strings.Contains(contentLower, strings.ToLower(keyword)) {
				matchCount++
				matchedStrings = append(matchedStrings, keyword)
			}
		}

		// Check regex patterns
		for _, p := range pattern.Patterns {
			if regex, exists := db.regexCache[p]; exists {
				if found := regex.FindAllString(content, -1); len(found) > 0 {
					matchCount++
					matchedStrings = append(matchedStrings, found...)
				}
			}
		}

		if matchCount >= pattern.RequiredMatches {
			matches = append(matches, PatternMatch{
				PatternID:   pattern.ID,
				PatternName: pattern.Name,
				Category:    pattern.Category,
				Severity:    pattern.Severity,
				Matches:     matchedStrings,
				Weight:      pattern.Weight,
			})
		}
	}

	return matches
}

// MatchByCategory matches content against patterns of a specific category
func (db *ScamPatternDB) MatchByCategory(content string, category models.ScamType) []PatternMatch {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var matches []PatternMatch
	contentLower := strings.ToLower(content)

	for _, pattern := range db.patterns {
		if !pattern.Enabled || pattern.Category != category {
			continue
		}

		matchCount := 0
		var matchedStrings []string

		for _, keyword := range pattern.Keywords {
			if strings.Contains(contentLower, strings.ToLower(keyword)) {
				matchCount++
				matchedStrings = append(matchedStrings, keyword)
			}
		}

		for _, p := range pattern.Patterns {
			if regex, exists := db.regexCache[p]; exists {
				if found := regex.FindAllString(content, -1); len(found) > 0 {
					matchCount++
					matchedStrings = append(matchedStrings, found...)
				}
			}
		}

		if matchCount >= pattern.RequiredMatches {
			matches = append(matches, PatternMatch{
				PatternID:   pattern.ID,
				PatternName: pattern.Name,
				Category:    pattern.Category,
				Severity:    pattern.Severity,
				Matches:     matchedStrings,
				Weight:      pattern.Weight,
			})
		}
	}

	return matches
}

// AddPattern adds a new pattern to the database
func (db *ScamPatternDB) AddPattern(pattern ScamPattern) {
	db.mu.Lock()
	defer db.mu.Unlock()

	pattern.CreatedAt = time.Now()
	pattern.UpdatedAt = time.Now()
	pattern.Enabled = true

	// Compile regex patterns
	for _, p := range pattern.Patterns {
		if _, exists := db.regexCache[p]; !exists {
			if compiled, err := regexp.Compile("(?i)" + p); err == nil {
				db.regexCache[p] = compiled
			}
		}
	}

	db.patterns = append(db.patterns, pattern)
}

// GetPattern retrieves a pattern by ID
func (db *ScamPatternDB) GetPattern(id string) *ScamPattern {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for i := range db.patterns {
		if db.patterns[i].ID == id {
			return &db.patterns[i]
		}
	}
	return nil
}

// UpdatePattern updates an existing pattern
func (db *ScamPatternDB) UpdatePattern(id string, update ScamPattern) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i := range db.patterns {
		if db.patterns[i].ID == id {
			update.ID = id
			update.CreatedAt = db.patterns[i].CreatedAt
			update.UpdatedAt = time.Now()
			db.patterns[i] = update

			// Update regex cache
			for _, p := range update.Patterns {
				if _, exists := db.regexCache[p]; !exists {
					if compiled, err := regexp.Compile("(?i)" + p); err == nil {
						db.regexCache[p] = compiled
					}
				}
			}
			return true
		}
	}
	return false
}

// DeletePattern removes a pattern
func (db *ScamPatternDB) DeletePattern(id string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i := range db.patterns {
		if db.patterns[i].ID == id {
			db.patterns = append(db.patterns[:i], db.patterns[i+1:]...)
			return true
		}
	}
	return false
}

// EnablePattern enables a pattern
func (db *ScamPatternDB) EnablePattern(id string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i := range db.patterns {
		if db.patterns[i].ID == id {
			db.patterns[i].Enabled = true
			db.patterns[i].UpdatedAt = time.Now()
			return true
		}
	}
	return false
}

// DisablePattern disables a pattern
func (db *ScamPatternDB) DisablePattern(id string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i := range db.patterns {
		if db.patterns[i].ID == id {
			db.patterns[i].Enabled = false
			db.patterns[i].UpdatedAt = time.Now()
			return true
		}
	}
	return false
}

// GetAllPatterns returns all patterns
func (db *ScamPatternDB) GetAllPatterns() []ScamPattern {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]ScamPattern, len(db.patterns))
	copy(result, db.patterns)
	return result
}

// GetPatternsByCategory returns patterns by category
func (db *ScamPatternDB) GetPatternsByCategory(category models.ScamType) []ScamPattern {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []ScamPattern
	for _, p := range db.patterns {
		if p.Category == category {
			result = append(result, p)
		}
	}
	return result
}

// CalculateScamScore calculates overall scam score from matches
func (db *ScamPatternDB) CalculateScamScore(matches []PatternMatch) float64 {
	if len(matches) == 0 {
		return 0
	}

	var totalWeight float64
	var weightedSum float64

	for _, match := range matches {
		weightedSum += match.Weight
		totalWeight += 1.0
	}

	// Normalize to 0-1 range
	score := weightedSum / totalWeight

	// Apply diminishing returns for multiple matches
	if len(matches) > 1 {
		multiplier := 1.0 + (float64(len(matches)-1) * 0.1)
		if multiplier > 1.5 {
			multiplier = 1.5
		}
		score *= multiplier
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

// GetHighestSeverity returns the highest severity from matches
func (db *ScamPatternDB) GetHighestSeverity(matches []PatternMatch) models.ScamSeverity {
	if len(matches) == 0 {
		return models.ScamSeverityNone
	}

	severityOrder := map[models.ScamSeverity]int{
		models.ScamSeverityNone:     0,
		models.ScamSeverityLow:      1,
		models.ScamSeverityMedium:   2,
		models.ScamSeverityHigh:     3,
		models.ScamSeverityCritical: 4,
	}

	highest := models.ScamSeverityNone
	for _, match := range matches {
		if severityOrder[match.Severity] > severityOrder[highest] {
			highest = match.Severity
		}
	}

	return highest
}

// GetMostLikelyScamType determines the most likely scam type from matches
func (db *ScamPatternDB) GetMostLikelyScamType(matches []PatternMatch) models.ScamType {
	if len(matches) == 0 {
		return ""
	}

	categoryWeights := make(map[models.ScamType]float64)
	for _, match := range matches {
		categoryWeights[match.Category] += match.Weight
	}

	var bestCategory models.ScamType
	var bestWeight float64

	for category, weight := range categoryWeights {
		if weight > bestWeight {
			bestWeight = weight
			bestCategory = category
		}
	}

	return bestCategory
}
