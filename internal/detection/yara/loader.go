package yara

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// Loader loads YARA rules from files
type Loader struct {
	logger *logger.Logger
}

// NewLoader creates a new rule loader
func NewLoader(log *logger.Logger) *Loader {
	return &Loader{
		logger: log.WithComponent("yara-loader"),
	}
}

// LoadDirectory loads all .yar and .yara files from a directory
func (l *Loader) LoadDirectory(dirPath string) ([]*models.YARARule, error) {
	var rules []*models.YARARule

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		fileRules, err := l.LoadFile(path)
		if err != nil {
			l.logger.Warn().Err(err).Str("file", path).Msg("failed to load rule file")
			return nil // Continue loading other files
		}

		rules = append(rules, fileRules...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	l.logger.Info().Int("count", len(rules)).Str("dir", dirPath).Msg("loaded YARA rules from directory")
	return rules, nil
}

// LoadFile loads rules from a single YARA file
func (l *Loader) LoadFile(filePath string) ([]*models.YARARule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return l.ParseRules(string(content))
}

// ParseRules parses YARA rules from a string
func (l *Loader) ParseRules(content string) ([]*models.YARARule, error) {
	var rules []*models.YARARule

	// Regex to match rule blocks
	// rule <name> [: <tags>] { ... }
	rulePattern := regexp.MustCompile(`(?s)rule\s+(\w+)\s*(?::\s*([^\{]+))?\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}`)

	matches := rulePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		ruleName := strings.TrimSpace(match[1])
		ruleTags := strings.TrimSpace(match[2])
		ruleBody := strings.TrimSpace(match[3])

		rule, err := l.parseRuleBody(ruleName, ruleTags, ruleBody)
		if err != nil {
			l.logger.Warn().Err(err).Str("rule", ruleName).Msg("failed to parse rule")
			continue
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRuleBody parses the body of a YARA rule
func (l *Loader) parseRuleBody(name, tags, body string) (*models.YARARule, error) {
	rule := &models.YARARule{
		ID:        uuid.New(),
		Name:      name,
		Status:    models.YARARuleStatusActive,
		Severity:  models.SeverityMedium,
		Category:  models.YARACategoryGeneric,
		Tags:      parseTags(tags),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Parse meta section
	metaPattern := regexp.MustCompile(`(?s)meta\s*:\s*(.*?)(?:strings\s*:|condition\s*:|$)`)
	if metaMatch := metaPattern.FindStringSubmatch(body); len(metaMatch) > 1 {
		l.parseMetaSection(rule, metaMatch[1])
	}

	// Parse strings section
	stringsPattern := regexp.MustCompile(`(?s)strings\s*:\s*(.*?)(?:condition\s*:|$)`)
	if stringsMatch := stringsPattern.FindStringSubmatch(body); len(stringsMatch) > 1 {
		rule.Strings = l.parseStringsSection(stringsMatch[1])
	}

	// Parse condition section
	conditionPattern := regexp.MustCompile(`(?s)condition\s*:\s*(.*)$`)
	if condMatch := conditionPattern.FindStringSubmatch(body); len(condMatch) > 1 {
		rule.Conditions = l.parseConditionSection(condMatch[1])
	}

	// Store raw rule
	rule.RawRule = fmt.Sprintf("rule %s : %s {\n%s\n}", name, tags, body)

	return rule, nil
}

// parseMetaSection parses the meta section of a rule
func (l *Loader) parseMetaSection(rule *models.YARARule, meta string) {
	lines := strings.Split(meta, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse key = "value" or key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

		switch strings.ToLower(key) {
		case "description", "desc":
			rule.Description = value
		case "author":
			rule.Author = value
		case "reference", "ref":
			rule.Reference = value
		case "severity":
			rule.Severity = parseSeverity(value)
		case "category":
			rule.Category = parseCategory(value)
		case "mitre", "mitre_attack", "attack":
			rule.MitreTTPs = append(rule.MitreTTPs, strings.Split(value, ",")...)
		case "platform", "platforms":
			rule.Platforms = append(rule.Platforms, strings.Split(value, ",")...)
		}
	}
}

// parseStringsSection parses the strings section of a rule
func (l *Loader) parseStringsSection(stringsSection string) []models.YARAString {
	var strings_ []models.YARAString

	lines := strings.Split(stringsSection, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Parse $id = "value" [modifiers] or $id = { hex } or $id = /regex/
		str := l.parseStringLine(line)
		if str != nil {
			strings_ = append(strings_, *str)
		}
	}

	return strings_
}

// parseStringLine parses a single string definition
func (l *Loader) parseStringLine(line string) *models.YARAString {
	// Match $id = ...
	pattern := regexp.MustCompile(`(\$\w+)\s*=\s*(.+)`)
	match := pattern.FindStringSubmatch(line)
	if len(match) < 3 {
		return nil
	}

	str := &models.YARAString{
		ID: match[1],
	}

	value := strings.TrimSpace(match[2])

	// Determine type and parse
	if strings.HasPrefix(value, "{") {
		// Hex string
		str.Type = models.YARAStringTypeHex
		endIdx := strings.Index(value, "}")
		if endIdx == -1 {
			return nil
		}
		str.Value = strings.TrimSpace(value[1:endIdx])
		// Parse modifiers after }
		if endIdx < len(value)-1 {
			str.Modifiers = parseModifiers(value[endIdx+1:])
		}
	} else if strings.HasPrefix(value, "/") {
		// Regex
		str.Type = models.YARAStringTypeRegex
		// Find closing /
		endIdx := strings.LastIndex(value, "/")
		if endIdx <= 0 {
			return nil
		}
		str.Value = value[1:endIdx]
		// Parse modifiers after /
		if endIdx < len(value)-1 {
			str.Modifiers = parseModifiers(value[endIdx+1:])
		}
	} else if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`) {
		// Text string
		str.Type = models.YARAStringTypeText
		quote := value[0:1]
		endIdx := strings.LastIndex(value, quote)
		if endIdx <= 0 {
			return nil
		}
		str.Value = value[1:endIdx]
		// Parse modifiers after quote
		if endIdx < len(value)-1 {
			str.Modifiers = parseModifiers(value[endIdx+1:])
		}
	} else {
		return nil
	}

	return str
}

// parseConditionSection parses the condition section
func (l *Loader) parseConditionSection(condition string) []models.YARACondition {
	condition = strings.TrimSpace(condition)
	// Remove trailing comments
	if idx := strings.Index(condition, "//"); idx != -1 {
		condition = strings.TrimSpace(condition[:idx])
	}

	return []models.YARACondition{
		{Expression: condition},
	}
}

// Helper functions

func parseTags(tagStr string) []string {
	if tagStr == "" {
		return nil
	}
	var tags []string
	for _, tag := range strings.Fields(tagStr) {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func parseModifiers(modStr string) []string {
	var mods []string
	for _, mod := range strings.Fields(modStr) {
		mod = strings.TrimSpace(strings.ToLower(mod))
		switch mod {
		case "nocase", "wide", "ascii", "fullword", "xor", "base64":
			mods = append(mods, mod)
		}
	}
	return mods
}

func parseSeverity(value string) models.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	case "info":
		return models.SeverityInfo
	default:
		return models.SeverityMedium
	}
}

func parseCategory(value string) models.YARARuleCategory {
	switch strings.ToLower(value) {
	case "pegasus":
		return models.YARACategoryPegasus
	case "stalkerware":
		return models.YARACategoryStalkerware
	case "spyware":
		return models.YARACategorySpyware
	case "trojan":
		return models.YARACategoryTrojan
	case "ransomware":
		return models.YARACategoryRansomware
	case "adware":
		return models.YARACategoryAdware
	case "rootkit":
		return models.YARACategoryRootkit
	case "exploit":
		return models.YARACategoryExploit
	default:
		return models.YARACategoryGeneric
	}
}

// LoadBuiltinRules loads built-in rules embedded in the binary
func (l *Loader) LoadBuiltinRules() ([]*models.YARARule, error) {
	var rules []*models.YARARule

	// Load Pegasus rules
	pegasusRules := l.getPegasusRules()
	rules = append(rules, pegasusRules...)

	// Load stalkerware rules
	stalkerwareRules := l.getStalkerwareRules()
	rules = append(rules, stalkerwareRules...)

	// Load generic spyware rules
	spywareRules := l.getSpywareRules()
	rules = append(rules, spywareRules...)

	l.logger.Info().Int("count", len(rules)).Msg("loaded built-in YARA rules")
	return rules, nil
}

// getPegasusRules returns Pegasus-specific detection rules
func (l *Loader) getPegasusRules() []*models.YARARule {
	return []*models.YARARule{
		{
			ID:          uuid.New(),
			Name:        "Pegasus_iOS_Process",
			Description: "Detects Pegasus spyware iOS process names",
			Category:    models.YARACategoryPegasus,
			Severity:    models.SeverityCritical,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"pegasus", "nso-group", "ios", "spyware"},
			MitreTTPs:   []string{"T1417", "T1429", "T1512"},
			Platforms:   []string{"ios"},
			Strings: []models.YARAString{
				{ID: "$proc1", Value: "setframed", Type: models.YARAStringTypeText},
				{ID: "$proc2", Value: "bridged", Type: models.YARAStringTypeText},
				{ID: "$proc3", Value: "CommsCentre", Type: models.YARAStringTypeText},
				{ID: "$proc4", Value: "aggregated", Type: models.YARAStringTypeText},
				{ID: "$proc5", Value: "liaborage", Type: models.YARAStringTypeText},
				{ID: "$proc6", Value: "pclodd", Type: models.YARAStringTypeText},
			},
			Conditions: []models.YARACondition{{Expression: "any of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Pegasus_Domain_Indicators",
			Description: "Detects known Pegasus C2 domain patterns",
			Category:    models.YARACategoryPegasus,
			Severity:    models.SeverityCritical,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"pegasus", "nso-group", "c2", "domain"},
			MitreTTPs:   []string{"T1071"},
			Platforms:   []string{"android", "ios"},
			Strings: []models.YARAString{
				{ID: "$d1", Value: "lsgatag.com", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$d2", Value: "lxwo.org", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$d3", Value: "iosmac.org", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$d4", Value: "cloudatlasinc.com", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$d5", Value: "mynetsec.net", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$d6", Value: "updates-icloud-content.com", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
			},
			Conditions: []models.YARACondition{{Expression: "any of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Pegasus_Android_Package",
			Description: "Detects Pegasus-style Android package names",
			Category:    models.YARACategoryPegasus,
			Severity:    models.SeverityHigh,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"pegasus", "android", "package"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$pkg1", Value: "com.network.android", Type: models.YARAStringTypeText},
				{ID: "$pkg2", Value: "com.system.framework", Type: models.YARAStringTypeText},
				{ID: "$pkg3", Value: "com.google.android.update", Type: models.YARAStringTypeText},
				{ID: "$pkg4", Value: "com.sec.android.app", Type: models.YARAStringTypeText},
			},
			Conditions: []models.YARACondition{{Expression: "any of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}
}

// getStalkerwareRules returns stalkerware detection rules
func (l *Loader) getStalkerwareRules() []*models.YARARule {
	return []*models.YARARule{
		{
			ID:          uuid.New(),
			Name:        "Stalkerware_Common_Packages",
			Description: "Detects known stalkerware application packages",
			Category:    models.YARACategoryStalkerware,
			Severity:    models.SeverityHigh,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"stalkerware", "android", "spyware"},
			MitreTTPs:   []string{"T1417", "T1430"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$pkg1", Value: "com.flexispy", Type: models.YARAStringTypeText},
				{ID: "$pkg2", Value: "com.mspy", Type: models.YARAStringTypeText},
				{ID: "$pkg3", Value: "com.spyzie", Type: models.YARAStringTypeText},
				{ID: "$pkg4", Value: "com.cocospy", Type: models.YARAStringTypeText},
				{ID: "$pkg5", Value: "com.hoverwatch", Type: models.YARAStringTypeText},
				{ID: "$pkg6", Value: "com.spyera", Type: models.YARAStringTypeText},
				{ID: "$pkg7", Value: "com.phonesheriff", Type: models.YARAStringTypeText},
				{ID: "$pkg8", Value: "com.cerberusapp", Type: models.YARAStringTypeText},
				{ID: "$pkg9", Value: "com.thetruthspy", Type: models.YARAStringTypeText},
				{ID: "$pkg10", Value: "com.xnspy", Type: models.YARAStringTypeText},
			},
			Conditions: []models.YARACondition{{Expression: "any of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Stalkerware_Behavior_Strings",
			Description: "Detects stalkerware behavior indicators in code",
			Category:    models.YARACategoryStalkerware,
			Severity:    models.SeverityMedium,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"stalkerware", "behavior"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$s1", Value: "getLastKnownLocation", Type: models.YARAStringTypeText},
				{ID: "$s2", Value: "getCallLog", Type: models.YARAStringTypeText},
				{ID: "$s3", Value: "getSmsInbox", Type: models.YARAStringTypeText},
				{ID: "$s4", Value: "takeScreenshot", Type: models.YARAStringTypeText},
				{ID: "$s5", Value: "recordAudio", Type: models.YARAStringTypeText},
				{ID: "$s6", Value: "capturePhoto", Type: models.YARAStringTypeText},
				{ID: "$s7", Value: "keylogger", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$s8", Value: "stealth_mode", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$s9", Value: "hide_icon", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
			},
			Conditions: []models.YARACondition{{Expression: "3 of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}
}

// getSpywareRules returns generic spyware detection rules
func (l *Loader) getSpywareRules() []*models.YARARule {
	return []*models.YARARule{
		{
			ID:          uuid.New(),
			Name:        "Spyware_Suspicious_Permissions",
			Description: "Detects apps with suspicious permission combinations",
			Category:    models.YARACategorySpyware,
			Severity:    models.SeverityMedium,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"spyware", "permissions", "android"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$p1", Value: "android.permission.READ_SMS", Type: models.YARAStringTypeText},
				{ID: "$p2", Value: "android.permission.READ_CALL_LOG", Type: models.YARAStringTypeText},
				{ID: "$p3", Value: "android.permission.ACCESS_FINE_LOCATION", Type: models.YARAStringTypeText},
				{ID: "$p4", Value: "android.permission.RECORD_AUDIO", Type: models.YARAStringTypeText},
				{ID: "$p5", Value: "android.permission.CAMERA", Type: models.YARAStringTypeText},
				{ID: "$p6", Value: "android.permission.READ_CONTACTS", Type: models.YARAStringTypeText},
				{ID: "$p7", Value: "android.permission.RECEIVE_BOOT_COMPLETED", Type: models.YARAStringTypeText},
				{ID: "$p8", Value: "android.permission.INTERNET", Type: models.YARAStringTypeText},
			},
			Conditions: []models.YARACondition{{Expression: "5 of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Spyware_Data_Exfiltration",
			Description: "Detects data exfiltration patterns",
			Category:    models.YARACategorySpyware,
			Severity:    models.SeverityHigh,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"spyware", "exfiltration"},
			Platforms:   []string{"android", "ios"},
			Strings: []models.YARAString{
				{ID: "$e1", Value: "uploadToServer", Type: models.YARAStringTypeText},
				{ID: "$e2", Value: "sendToC2", Type: models.YARAStringTypeText},
				{ID: "$e3", Value: "exfiltrate", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$e4", Value: "base64encode", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
				{ID: "$e5", Value: "/upload/data", Type: models.YARAStringTypeText},
				{ID: "$e6", Value: "stolen_data", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
			},
			Conditions: []models.YARACondition{{Expression: "2 of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Spyware_Hidden_App",
			Description: "Detects apps attempting to hide themselves",
			Category:    models.YARACategorySpyware,
			Severity:    models.SeverityHigh,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"spyware", "stealth", "hidden"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$h1", Value: "setComponentEnabledSetting", Type: models.YARAStringTypeText},
				{ID: "$h2", Value: "COMPONENT_ENABLED_STATE_DISABLED", Type: models.YARAStringTypeText},
				{ID: "$h3", Value: "PackageManager.DONT_KILL_APP", Type: models.YARAStringTypeText},
				{ID: "$h4", Value: "hideFromLauncher", Type: models.YARAStringTypeText},
				{ID: "$h5", Value: "removeFromRecents", Type: models.YARAStringTypeText},
			},
			Conditions: []models.YARACondition{{Expression: "2 of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Spyware_Accessibility_Abuse",
			Description: "Detects accessibility service abuse for data theft",
			Category:    models.YARACategorySpyware,
			Severity:    models.SeverityCritical,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"spyware", "accessibility", "keylogger"},
			MitreTTPs:   []string{"T1417"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$a1", Value: "AccessibilityService", Type: models.YARAStringTypeText},
				{ID: "$a2", Value: "onAccessibilityEvent", Type: models.YARAStringTypeText},
				{ID: "$a3", Value: "TYPE_VIEW_TEXT_CHANGED", Type: models.YARAStringTypeText},
				{ID: "$a4", Value: "TYPE_VIEW_CLICKED", Type: models.YARAStringTypeText},
				{ID: "$a5", Value: "getEventText", Type: models.YARAStringTypeText},
				{ID: "$a6", Value: "captureKeystrokes", Type: models.YARAStringTypeText, Modifiers: []string{"nocase"}},
			},
			Conditions: []models.YARACondition{{Expression: "$a1 and $a2 and 2 of ($a3, $a4, $a5, $a6)"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Spyware_Root_Detection_Bypass",
			Description: "Detects attempts to bypass root detection",
			Category:    models.YARACategorySpyware,
			Severity:    models.SeverityMedium,
			Status:      models.YARARuleStatusActive,
			Author:      "OrbGuard",
			Tags:        []string{"spyware", "root", "bypass"},
			Platforms:   []string{"android"},
			Strings: []models.YARAString{
				{ID: "$r1", Value: "RootBeer", Type: models.YARAStringTypeText},
				{ID: "$r2", Value: "SafetyNet", Type: models.YARAStringTypeText},
				{ID: "$r3", Value: "isRooted", Type: models.YARAStringTypeText},
				{ID: "$r4", Value: "checkSu", Type: models.YARAStringTypeText},
				{ID: "$r5", Value: "/system/bin/su", Type: models.YARAStringTypeText},
				{ID: "$r6", Value: "Magisk", Type: models.YARAStringTypeText},
			},
			Conditions: []models.YARACondition{{Expression: "3 of them"}},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}
}

// ValidateRule validates a YARA rule
func (l *Loader) ValidateRule(rule *models.YARARule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if len(rule.Strings) == 0 {
		return fmt.Errorf("rule must have at least one string pattern")
	}
	if len(rule.Conditions) == 0 {
		return fmt.Errorf("rule must have at least one condition")
	}

	// Try to compile the rule
	engine := NewEngine()
	_, err := engine.CompileRule(rule)
	if err != nil {
		return fmt.Errorf("failed to compile rule: %w", err)
	}

	return nil
}

// ParseFromYARAFile reads a standard .yara file and returns parsed content
func (l *Loader) ParseFromYARAFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var content strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		content.WriteString(scanner.Text())
		content.WriteString("\n")
	}

	return content.String(), scanner.Err()
}
