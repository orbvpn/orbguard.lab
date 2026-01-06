package ai

import (
	"regexp"
	"strings"
	"unicode"

	"orbguard-lab/pkg/logger"
)

// LanguageDetector detects the language of text content
type LanguageDetector struct {
	logger *logger.Logger
}

// SupportedLanguage represents a supported language
type SupportedLanguage struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	NativeName  string `json:"native_name"`
	Direction   string `json:"direction"` // ltr or rtl
	ScriptRange []rune `json:"-"`         // Unicode range
}

// Supported languages
var (
	LanguageEnglish = SupportedLanguage{
		Code:       "en",
		Name:       "English",
		NativeName: "English",
		Direction:  "ltr",
	}
	LanguageArabic = SupportedLanguage{
		Code:       "ar",
		Name:       "Arabic",
		NativeName: "العربية",
		Direction:  "rtl",
		ScriptRange: []rune{0x0600, 0x06FF}, // Arabic block
	}
	LanguagePersian = SupportedLanguage{
		Code:       "fa",
		Name:       "Persian",
		NativeName: "فارسی",
		Direction:  "rtl",
		ScriptRange: []rune{0x0600, 0x06FF}, // Uses Arabic block + extensions
	}
	LanguageHindi = SupportedLanguage{
		Code:       "hi",
		Name:       "Hindi",
		NativeName: "हिन्दी",
		Direction:  "ltr",
		ScriptRange: []rune{0x0900, 0x097F}, // Devanagari block
	}
	LanguageUrdu = SupportedLanguage{
		Code:       "ur",
		Name:       "Urdu",
		NativeName: "اردو",
		Direction:  "rtl",
		ScriptRange: []rune{0x0600, 0x06FF}, // Uses Arabic block
	}
	LanguageChinese = SupportedLanguage{
		Code:       "zh",
		Name:       "Chinese",
		NativeName: "中文",
		Direction:  "ltr",
		ScriptRange: []rune{0x4E00, 0x9FFF}, // CJK Unified Ideographs
	}
	LanguageRussian = SupportedLanguage{
		Code:       "ru",
		Name:       "Russian",
		NativeName: "Русский",
		Direction:  "ltr",
		ScriptRange: []rune{0x0400, 0x04FF}, // Cyrillic block
	}
	LanguageSpanish = SupportedLanguage{
		Code:       "es",
		Name:       "Spanish",
		NativeName: "Español",
		Direction:  "ltr",
	}
	LanguageFrench = SupportedLanguage{
		Code:       "fr",
		Name:       "French",
		NativeName: "Français",
		Direction:  "ltr",
	}
	LanguageGerman = SupportedLanguage{
		Code:       "de",
		Name:       "German",
		NativeName: "Deutsch",
		Direction:  "ltr",
	}
)

// NewLanguageDetector creates a new language detector
func NewLanguageDetector(log *logger.Logger) *LanguageDetector {
	return &LanguageDetector{
		logger: log.WithComponent("language-detector"),
	}
}

// Detect detects the language of the given text
func (d *LanguageDetector) Detect(text string) string {
	if len(text) == 0 {
		return "en"
	}

	// Count characters by script
	scriptCounts := d.analyzeScript(text)

	// Determine primary script
	primaryScript := d.getPrimaryScript(scriptCounts)

	// Detect specific language within script
	return d.detectLanguageByScript(primaryScript, text)
}

// DetectWithConfidence detects language with confidence score
func (d *LanguageDetector) DetectWithConfidence(text string) (string, float64) {
	if len(text) == 0 {
		return "en", 0.5
	}

	scriptCounts := d.analyzeScript(text)
	totalChars := 0
	maxCount := 0
	var maxScript string

	for script, count := range scriptCounts {
		totalChars += count
		if count > maxCount {
			maxCount = count
			maxScript = script
		}
	}

	confidence := 0.5
	if totalChars > 0 {
		confidence = float64(maxCount) / float64(totalChars)
	}

	lang := d.detectLanguageByScript(maxScript, text)
	return lang, confidence
}

// analyzeScript counts characters by script type
func (d *LanguageDetector) analyzeScript(text string) map[string]int {
	counts := make(map[string]int)

	for _, r := range text {
		script := d.getScript(r)
		if script != "" {
			counts[script]++
		}
	}

	return counts
}

// getScript determines the script of a character
func (d *LanguageDetector) getScript(r rune) string {
	switch {
	case r >= 0x0600 && r <= 0x06FF:
		return "arabic"
	case r >= 0x0750 && r <= 0x077F:
		return "arabic_supplement"
	case r >= 0xFB50 && r <= 0xFDFF:
		return "arabic_presentation_a"
	case r >= 0xFE70 && r <= 0xFEFF:
		return "arabic_presentation_b"
	case r >= 0x0900 && r <= 0x097F:
		return "devanagari"
	case r >= 0x0980 && r <= 0x09FF:
		return "bengali"
	case r >= 0x0A00 && r <= 0x0A7F:
		return "gurmukhi"
	case r >= 0x0A80 && r <= 0x0AFF:
		return "gujarati"
	case r >= 0x4E00 && r <= 0x9FFF:
		return "cjk"
	case r >= 0x3040 && r <= 0x309F:
		return "hiragana"
	case r >= 0x30A0 && r <= 0x30FF:
		return "katakana"
	case r >= 0xAC00 && r <= 0xD7AF:
		return "hangul"
	case r >= 0x0400 && r <= 0x04FF:
		return "cyrillic"
	case r >= 0x0370 && r <= 0x03FF:
		return "greek"
	case r >= 0x0590 && r <= 0x05FF:
		return "hebrew"
	case r >= 0x0E00 && r <= 0x0E7F:
		return "thai"
	case unicode.IsLetter(r) && r < 0x0250:
		return "latin"
	default:
		return ""
	}
}

// getPrimaryScript determines the primary script from counts
func (d *LanguageDetector) getPrimaryScript(counts map[string]int) string {
	maxCount := 0
	primaryScript := "latin"

	for script, count := range counts {
		if count > maxCount {
			maxCount = count
			primaryScript = script
		}
	}

	return primaryScript
}

// detectLanguageByScript detects specific language within a script
func (d *LanguageDetector) detectLanguageByScript(script, text string) string {
	switch script {
	case "arabic", "arabic_supplement", "arabic_presentation_a", "arabic_presentation_b":
		return d.detectArabicVariant(text)
	case "devanagari":
		return "hi" // Hindi
	case "bengali":
		return "bn" // Bengali
	case "gurmukhi":
		return "pa" // Punjabi
	case "gujarati":
		return "gu" // Gujarati
	case "cjk":
		return d.detectCJKLanguage(text)
	case "hiragana", "katakana":
		return "ja" // Japanese
	case "hangul":
		return "ko" // Korean
	case "cyrillic":
		return d.detectCyrillicLanguage(text)
	case "greek":
		return "el" // Greek
	case "hebrew":
		return "he" // Hebrew
	case "thai":
		return "th" // Thai
	case "latin":
		return d.detectLatinLanguage(text)
	default:
		return "en"
	}
}

// detectArabicVariant detects Arabic vs Persian vs Urdu
func (d *LanguageDetector) detectArabicVariant(text string) string {
	// Persian-specific characters
	persianSpecific := []rune{'پ', 'چ', 'ژ', 'گ', 'ی'} // Pe, Che, Zhe, Gaf, Yeh

	// Urdu-specific characters
	urduSpecific := []rune{'ٹ', 'ڈ', 'ڑ', 'ں', 'ے', 'ہ'} // Tteh, Ddal, Rreh, Noon Ghunna, Yeh Barree, Heh Goal

	persianCount := 0
	urduCount := 0

	for _, r := range text {
		for _, p := range persianSpecific {
			if r == p {
				persianCount++
			}
		}
		for _, u := range urduSpecific {
			if r == u {
				urduCount++
			}
		}
	}

	// Persian-specific words
	persianWords := []string{"است", "این", "آن", "را", "می", "که"}
	for _, word := range persianWords {
		if strings.Contains(text, word) {
			persianCount += 2
		}
	}

	// Urdu-specific words
	urduWords := []string{"ہے", "کا", "کی", "نے", "سے", "میں"}
	for _, word := range urduWords {
		if strings.Contains(text, word) {
			urduCount += 2
		}
	}

	if persianCount > urduCount && persianCount > 0 {
		return "fa"
	} else if urduCount > persianCount && urduCount > 0 {
		return "ur"
	}

	return "ar"
}

// detectCJKLanguage attempts to distinguish Chinese variants
func (d *LanguageDetector) detectCJKLanguage(text string) string {
	// Check for Japanese specific characters (hiragana/katakana mixed in)
	hasHiragana := regexp.MustCompile(`[\x{3040}-\x{309F}]`).MatchString(text)
	hasKatakana := regexp.MustCompile(`[\x{30A0}-\x{30FF}]`).MatchString(text)

	if hasHiragana || hasKatakana {
		return "ja"
	}

	// Traditional vs Simplified Chinese detection would require
	// character frequency analysis - defaulting to simplified
	return "zh"
}

// detectCyrillicLanguage detects Russian vs Ukrainian vs Bulgarian
func (d *LanguageDetector) detectCyrillicLanguage(text string) string {
	// Ukrainian-specific characters
	ukrainianChars := []rune{'і', 'ї', 'є', 'ґ'}
	for _, r := range text {
		for _, u := range ukrainianChars {
			if r == u || unicode.ToLower(r) == u {
				return "uk"
			}
		}
	}

	// Bulgarian-specific characters
	bulgarianChars := []rune{'ъ', 'ь'}
	bulgarianCount := 0
	for _, r := range text {
		for _, b := range bulgarianChars {
			if r == b {
				bulgarianCount++
			}
		}
	}

	// Default to Russian
	return "ru"
}

// detectLatinLanguage detects specific Latin-script language
func (d *LanguageDetector) detectLatinLanguage(text string) string {
	textLower := strings.ToLower(text)

	// Spanish indicators
	spanishPatterns := []string{"el", "la", "de", "que", "los", "del", "las", "una", "por", "con", "está", "ñ"}
	spanishScore := 0
	for _, p := range spanishPatterns {
		if strings.Contains(textLower, " "+p+" ") || strings.Contains(textLower, p) {
			spanishScore++
		}
	}

	// French indicators
	frenchPatterns := []string{"le", "la", "de", "les", "des", "un", "une", "est", "dans", "pour", "avec", "ce", "ç", "é", "è", "ê", "à", "ù", "û"}
	frenchScore := 0
	for _, p := range frenchPatterns {
		if strings.Contains(textLower, p) {
			frenchScore++
		}
	}

	// German indicators
	germanPatterns := []string{"der", "die", "das", "und", "ist", "ein", "eine", "nicht", "mit", "auf", "ich", "ß", "ü", "ö", "ä"}
	germanScore := 0
	for _, p := range germanPatterns {
		if strings.Contains(textLower, p) {
			germanScore++
		}
	}

	// Portuguese indicators
	portuguesePatterns := []string{"o", "a", "de", "que", "em", "do", "da", "com", "não", "uma", "os", "as", "ã", "ç"}
	portugueseScore := 0
	for _, p := range portuguesePatterns {
		if strings.Contains(textLower, p) {
			portugueseScore++
		}
	}

	// Italian indicators
	italianPatterns := []string{"il", "di", "che", "è", "la", "un", "una", "per", "non", "sono", "con"}
	italianScore := 0
	for _, p := range italianPatterns {
		if strings.Contains(textLower, p) {
			italianScore++
		}
	}

	// Dutch indicators
	dutchPatterns := []string{"de", "het", "een", "van", "en", "is", "dat", "op", "te", "niet", "met", "ij"}
	dutchScore := 0
	for _, p := range dutchPatterns {
		if strings.Contains(textLower, p) {
			dutchScore++
		}
	}

	// English indicators (common words)
	englishPatterns := []string{"the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at"}
	englishScore := 0
	for _, p := range englishPatterns {
		if strings.Contains(textLower, " "+p+" ") {
			englishScore++
		}
	}

	// Find highest score
	maxScore := englishScore
	lang := "en"

	if spanishScore > maxScore {
		maxScore = spanishScore
		lang = "es"
	}
	if frenchScore > maxScore {
		maxScore = frenchScore
		lang = "fr"
	}
	if germanScore > maxScore {
		maxScore = germanScore
		lang = "de"
	}
	if portugueseScore > maxScore {
		maxScore = portugueseScore
		lang = "pt"
	}
	if italianScore > maxScore {
		maxScore = italianScore
		lang = "it"
	}
	if dutchScore > maxScore {
		lang = "nl"
	}

	return lang
}

// GetLanguageInfo returns information about a language code
func (d *LanguageDetector) GetLanguageInfo(code string) *SupportedLanguage {
	languages := map[string]SupportedLanguage{
		"en": LanguageEnglish,
		"ar": LanguageArabic,
		"fa": LanguagePersian,
		"hi": LanguageHindi,
		"ur": LanguageUrdu,
		"zh": LanguageChinese,
		"ru": LanguageRussian,
		"es": LanguageSpanish,
		"fr": LanguageFrench,
		"de": LanguageGerman,
	}

	if lang, exists := languages[code]; exists {
		return &lang
	}
	return nil
}

// IsRTL returns whether a language is right-to-left
func (d *LanguageDetector) IsRTL(code string) bool {
	rtlLanguages := map[string]bool{
		"ar": true,
		"fa": true,
		"ur": true,
		"he": true,
	}
	return rtlLanguages[code]
}

// GetSupportedLanguages returns all supported languages
func (d *LanguageDetector) GetSupportedLanguages() []SupportedLanguage {
	return []SupportedLanguage{
		LanguageEnglish,
		LanguageArabic,
		LanguagePersian,
		LanguageHindi,
		LanguageUrdu,
		LanguageChinese,
		LanguageRussian,
		LanguageSpanish,
		LanguageFrench,
		LanguageGerman,
	}
}

// NormalizeText normalizes text for a specific language
func (d *LanguageDetector) NormalizeText(text, langCode string) string {
	// Basic normalization
	text = strings.TrimSpace(text)

	switch langCode {
	case "ar", "fa", "ur":
		// Arabic/Persian/Urdu normalization
		text = d.normalizeArabicText(text)
	case "zh":
		// Chinese normalization (e.g., full-width to half-width)
		text = d.normalizeChineseText(text)
	}

	return text
}

// normalizeArabicText normalizes Arabic/Persian/Urdu text
func (d *LanguageDetector) normalizeArabicText(text string) string {
	// Normalize Arabic characters
	replacements := map[rune]rune{
		'أ': 'ا', // Alef with Hamza above -> Alef
		'إ': 'ا', // Alef with Hamza below -> Alef
		'آ': 'ا', // Alef with Madda -> Alef
		'ؤ': 'و', // Waw with Hamza -> Waw
		'ئ': 'ي', // Yeh with Hamza -> Yeh
		'ة': 'ه', // Teh Marbuta -> Heh
		'ى': 'ي', // Alef Maksura -> Yeh
	}

	var result strings.Builder
	for _, r := range text {
		if replacement, exists := replacements[r]; exists {
			result.WriteRune(replacement)
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// normalizeChineseText normalizes Chinese text
func (d *LanguageDetector) normalizeChineseText(text string) string {
	// Convert full-width characters to half-width
	var result strings.Builder
	for _, r := range text {
		// Full-width ASCII variants (FF01-FF5E) to ASCII (0021-007E)
		if r >= 0xFF01 && r <= 0xFF5E {
			result.WriteRune(r - 0xFEE0)
		} else if r == 0x3000 { // Full-width space
			result.WriteRune(' ')
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}
