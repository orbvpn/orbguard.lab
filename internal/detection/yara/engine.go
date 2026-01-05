package yara

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"orbguard-lab/internal/domain/models"
)

// Engine is a pure Go YARA rule engine
type Engine struct {
	rules    map[string]*CompiledRule
	rulesMu  sync.RWMutex
}

// CompiledRule represents a compiled YARA rule ready for matching
type CompiledRule struct {
	Rule     *models.YARARule
	Patterns []*CompiledPattern
}

// CompiledPattern represents a compiled string pattern
type CompiledPattern struct {
	ID        string
	Type      models.YARAStringType
	Regex     *regexp.Regexp // For text and regex patterns
	Bytes     []byte         // For hex patterns
	Modifiers []string
	NoCase    bool
	Wide      bool
	ASCII     bool
	FullWord  bool
}

// NewEngine creates a new YARA engine
func NewEngine() *Engine {
	return &Engine{
		rules: make(map[string]*CompiledRule),
	}
}

// CompileRule compiles a YARA rule for matching
func (e *Engine) CompileRule(rule *models.YARARule) (*CompiledRule, error) {
	compiled := &CompiledRule{
		Rule:     rule,
		Patterns: make([]*CompiledPattern, 0, len(rule.Strings)),
	}

	for _, str := range rule.Strings {
		pattern, err := e.compilePattern(&str)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern %s: %w", str.ID, err)
		}
		compiled.Patterns = append(compiled.Patterns, pattern)
	}

	return compiled, nil
}

// compilePattern compiles a single string pattern
func (e *Engine) compilePattern(str *models.YARAString) (*CompiledPattern, error) {
	pattern := &CompiledPattern{
		ID:        str.ID,
		Type:      str.Type,
		Modifiers: str.Modifiers,
	}

	// Parse modifiers
	for _, mod := range str.Modifiers {
		switch strings.ToLower(mod) {
		case "nocase":
			pattern.NoCase = true
		case "wide":
			pattern.Wide = true
		case "ascii":
			pattern.ASCII = true
		case "fullword":
			pattern.FullWord = true
		}
	}

	switch str.Type {
	case models.YARAStringTypeText:
		return e.compileTextPattern(pattern, str.Value)
	case models.YARAStringTypeHex:
		return e.compileHexPattern(pattern, str.Value)
	case models.YARAStringTypeRegex:
		return e.compileRegexPattern(pattern, str.Value)
	default:
		return nil, fmt.Errorf("unknown pattern type: %s", str.Type)
	}
}

// compileTextPattern compiles a text string pattern
func (e *Engine) compileTextPattern(pattern *CompiledPattern, value string) (*CompiledPattern, error) {
	// Escape regex special characters for literal matching
	escaped := regexp.QuoteMeta(value)

	// Add word boundaries if fullword
	if pattern.FullWord {
		escaped = `\b` + escaped + `\b`
	}

	// Build regex flags
	flags := ""
	if pattern.NoCase {
		flags = "(?i)"
	}

	regex, err := regexp.Compile(flags + escaped)
	if err != nil {
		return nil, fmt.Errorf("failed to compile text pattern: %w", err)
	}

	pattern.Regex = regex
	return pattern, nil
}

// compileHexPattern compiles a hex string pattern
func (e *Engine) compileHexPattern(pattern *CompiledPattern, value string) (*CompiledPattern, error) {
	// Remove spaces and curly braces from hex string
	cleaned := strings.ReplaceAll(value, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "{", "")
	cleaned = strings.ReplaceAll(cleaned, "}", "")

	// Check for wildcards (?) - convert to regex if present
	if strings.Contains(cleaned, "?") {
		// Convert hex with wildcards to regex
		regexStr := ""
		for i := 0; i < len(cleaned); i += 2 {
			if i+1 < len(cleaned) {
				pair := cleaned[i : i+2]
				if pair == "??" {
					regexStr += "."
				} else if strings.Contains(pair, "?") {
					// Single nibble wildcard
					regexStr += "."
				} else {
					b, err := hex.DecodeString(pair)
					if err != nil {
						return nil, fmt.Errorf("invalid hex pair: %s", pair)
					}
					regexStr += regexp.QuoteMeta(string(b))
				}
			}
		}
		regex, err := regexp.Compile(regexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to compile hex pattern: %w", err)
		}
		pattern.Regex = regex
	} else {
		// Pure hex without wildcards
		decoded, err := hex.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid hex string: %w", err)
		}
		pattern.Bytes = decoded
	}

	return pattern, nil
}

// compileRegexPattern compiles a regex pattern
func (e *Engine) compileRegexPattern(pattern *CompiledPattern, value string) (*CompiledPattern, error) {
	flags := ""
	if pattern.NoCase {
		flags = "(?i)"
	}

	regex, err := regexp.Compile(flags + value)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	pattern.Regex = regex
	return pattern, nil
}

// AddRule adds a compiled rule to the engine
func (e *Engine) AddRule(rule *models.YARARule) error {
	compiled, err := e.CompileRule(rule)
	if err != nil {
		return err
	}

	e.rulesMu.Lock()
	e.rules[rule.ID.String()] = compiled
	e.rulesMu.Unlock()

	return nil
}

// RemoveRule removes a rule from the engine
func (e *Engine) RemoveRule(ruleID string) {
	e.rulesMu.Lock()
	delete(e.rules, ruleID)
	e.rulesMu.Unlock()
}

// Match scans data against all loaded rules
func (e *Engine) Match(data []byte) []models.YARAMatch {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	var matches []models.YARAMatch

	for _, compiled := range e.rules {
		if match := e.matchRule(compiled, data); match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// MatchWithRules scans data against specific rules
func (e *Engine) MatchWithRules(data []byte, rules []*CompiledRule) []models.YARAMatch {
	var matches []models.YARAMatch

	for _, compiled := range rules {
		if match := e.matchRule(compiled, data); match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// matchRule checks if a single rule matches the data
func (e *Engine) matchRule(compiled *CompiledRule, data []byte) *models.YARAMatch {
	stringMatches := make([]models.YARAStringMatch, 0)

	for _, pattern := range compiled.Patterns {
		patternMatches := e.matchPattern(pattern, data)
		stringMatches = append(stringMatches, patternMatches...)
	}

	// Evaluate condition
	if !e.evaluateCondition(compiled, stringMatches) {
		return nil
	}

	// Build match result
	return &models.YARAMatch{
		RuleID:        compiled.Rule.ID,
		RuleName:      compiled.Rule.Name,
		Category:      compiled.Rule.Category,
		Severity:      compiled.Rule.Severity,
		Description:   compiled.Rule.Description,
		Tags:          compiled.Rule.Tags,
		MitreTTPs:     compiled.Rule.MitreTTPs,
		StringMatches: stringMatches,
		MatchCount:    len(stringMatches),
	}
}

// matchPattern finds all matches of a pattern in data
func (e *Engine) matchPattern(pattern *CompiledPattern, data []byte) []models.YARAStringMatch {
	var matches []models.YARAStringMatch

	if pattern.Regex != nil {
		// Regex-based matching
		allMatches := pattern.Regex.FindAllIndex(data, -1)
		for _, loc := range allMatches {
			matchData := data[loc[0]:loc[1]]
			displayData := string(matchData)
			if len(displayData) > 64 {
				displayData = displayData[:64] + "..."
			}

			matches = append(matches, models.YARAStringMatch{
				StringID: pattern.ID,
				Offset:   int64(loc[0]),
				Length:   loc[1] - loc[0],
				Data:     displayData,
			})
		}
	} else if pattern.Bytes != nil {
		// Byte sequence matching
		offset := 0
		for {
			idx := bytes.Index(data[offset:], pattern.Bytes)
			if idx == -1 {
				break
			}
			actualOffset := offset + idx
			displayData := hex.EncodeToString(pattern.Bytes)
			if len(displayData) > 64 {
				displayData = displayData[:64] + "..."
			}

			matches = append(matches, models.YARAStringMatch{
				StringID: pattern.ID,
				Offset:   int64(actualOffset),
				Length:   len(pattern.Bytes),
				Data:     displayData,
			})
			offset = actualOffset + 1
		}
	}

	return matches
}

// evaluateCondition evaluates the rule's condition
func (e *Engine) evaluateCondition(compiled *CompiledRule, matches []models.YARAStringMatch) bool {
	if len(compiled.Rule.Conditions) == 0 {
		// Default: any string must match
		return len(matches) > 0
	}

	// Build a map of which strings matched
	matchedStrings := make(map[string]int)
	for _, m := range matches {
		matchedStrings[m.StringID]++
	}

	// Evaluate each condition (currently supports simple conditions)
	for _, cond := range compiled.Rule.Conditions {
		if !e.evaluateSingleCondition(cond.Expression, matchedStrings, len(compiled.Patterns)) {
			return false
		}
	}

	return true
}

// evaluateSingleCondition evaluates a single condition expression
func (e *Engine) evaluateSingleCondition(expr string, matched map[string]int, totalStrings int) bool {
	expr = strings.TrimSpace(strings.ToLower(expr))

	switch {
	case expr == "any of them":
		return len(matched) > 0

	case expr == "all of them":
		return len(matched) == totalStrings

	case expr == "none of them":
		return len(matched) == 0

	case strings.HasPrefix(expr, "any of"):
		// "any of ($a, $b)" or "any of ($str*)"
		return len(matched) > 0

	case strings.HasPrefix(expr, "all of"):
		// "all of ($a, $b)" or "all of ($str*)"
		return len(matched) == totalStrings

	case strings.Contains(expr, " of "):
		// "2 of them", "3 of ($a, $b, $c)"
		return e.evaluateCountCondition(expr, matched, totalStrings)

	case strings.HasPrefix(expr, "$"):
		// Simple string reference: $a, $str1
		_, exists := matched[expr]
		return exists

	case strings.Contains(expr, " and "):
		// $a and $b
		parts := strings.Split(expr, " and ")
		for _, part := range parts {
			if !e.evaluateSingleCondition(strings.TrimSpace(part), matched, totalStrings) {
				return false
			}
		}
		return true

	case strings.Contains(expr, " or "):
		// $a or $b
		parts := strings.Split(expr, " or ")
		for _, part := range parts {
			if e.evaluateSingleCondition(strings.TrimSpace(part), matched, totalStrings) {
				return true
			}
		}
		return false

	default:
		// Unknown condition, default to true if any match
		return len(matched) > 0
	}
}

// evaluateCountCondition evaluates conditions like "2 of them"
func (e *Engine) evaluateCountCondition(expr string, matched map[string]int, totalStrings int) bool {
	// Parse "N of them" or "N of ($a, $b)"
	parts := strings.Split(expr, " of ")
	if len(parts) != 2 {
		return false
	}

	// Parse count
	var count int
	_, err := fmt.Sscanf(parts[0], "%d", &count)
	if err != nil {
		return false
	}

	target := strings.TrimSpace(parts[1])
	if target == "them" || target == "($*)" {
		return len(matched) >= count
	}

	// Count specific strings
	// Parse ($a, $b, $c) format
	if strings.HasPrefix(target, "(") && strings.HasSuffix(target, ")") {
		target = strings.TrimPrefix(target, "(")
		target = strings.TrimSuffix(target, ")")
		stringIDs := strings.Split(target, ",")
		matchedCount := 0
		for _, id := range stringIDs {
			id = strings.TrimSpace(id)
			if _, exists := matched[id]; exists {
				matchedCount++
			}
		}
		return matchedCount >= count
	}

	return len(matched) >= count
}

// GetRules returns all loaded rules
func (e *Engine) GetRules() []*CompiledRule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	rules := make([]*CompiledRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	return rules
}

// GetRule returns a specific rule by ID
func (e *Engine) GetRule(ruleID string) *CompiledRule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()
	return e.rules[ruleID]
}

// RuleCount returns the number of loaded rules
func (e *Engine) RuleCount() int {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()
	return len(e.rules)
}

// Clear removes all rules from the engine
func (e *Engine) Clear() {
	e.rulesMu.Lock()
	e.rules = make(map[string]*CompiledRule)
	e.rulesMu.Unlock()
}
