package ai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// VisionAnalyzer analyzes images and screenshots for scam indicators
type VisionAnalyzer struct {
	httpClient *http.Client
	logger     *logger.Logger
	llmClient  *LLMClient
	config     VisionConfig
}

// VisionConfig contains configuration for vision analysis
type VisionConfig struct {
	// LLM settings
	ClaudeAPIKey string
	OpenAIAPIKey string
	Provider     string // "claude" or "openai"

	// OCR settings
	TesseractEnabled bool
	TesseractPath    string

	// Analysis settings
	MaxImageSize     int64 // Maximum image size in bytes
	EnableOCR        bool
	EnableLogoDetect bool
	EnableQRDecode   bool
}

// VisionAnalysisResult contains the result of vision analysis
type VisionAnalysisResult struct {
	// Overall assessment
	IsScam         bool               `json:"is_scam"`
	Confidence     float64            `json:"confidence"`
	ScamType       models.ScamType    `json:"scam_type,omitempty"`
	Severity       models.ScamSeverity `json:"severity"`

	// Extracted content
	ExtractedText    string            `json:"extracted_text,omitempty"`
	ExtractedURLs    []string          `json:"extracted_urls,omitempty"`
	ExtractedPhones  []string          `json:"extracted_phones,omitempty"`
	ExtractedEmails  []string          `json:"extracted_emails,omitempty"`
	ExtractedQRCodes []QRCodeResult    `json:"extracted_qr_codes,omitempty"`

	// Visual indicators
	VisualIndicators []VisualIndicator `json:"visual_indicators,omitempty"`
	BrandImitation   *BrandImitation   `json:"brand_imitation,omitempty"`

	// UI analysis
	UIAnalysis *UIAnalysis `json:"ui_analysis,omitempty"`

	// Detailed explanation
	Explanation string   `json:"explanation"`
	RedFlags    []string `json:"red_flags,omitempty"`

	// Raw LLM response
	RawAnalysis string `json:"raw_analysis,omitempty"`
}

// VisualIndicator represents a visual scam indicator
type VisualIndicator struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Location    string  `json:"location,omitempty"` // e.g., "top-left", "center"
	Confidence  float64 `json:"confidence"`
	IsRedFlag   bool    `json:"is_red_flag"`
}

// BrandImitation contains brand imitation detection results
type BrandImitation struct {
	Detected       bool     `json:"detected"`
	ImitatedBrand  string   `json:"imitated_brand,omitempty"`
	Confidence     float64  `json:"confidence"`
	Discrepancies  []string `json:"discrepancies,omitempty"`
	LegitimateURL  string   `json:"legitimate_url,omitempty"`
}

// QRCodeResult contains decoded QR code information
type QRCodeResult struct {
	Content     string `json:"content"`
	Type        string `json:"type"` // url, text, crypto_address, etc.
	IsSuspicious bool   `json:"is_suspicious"`
	Reason      string `json:"reason,omitempty"`
}

// UIAnalysis contains UI/UX analysis for fake app detection
type UIAnalysis struct {
	IsAppScreenshot  bool     `json:"is_app_screenshot"`
	AppType          string   `json:"app_type,omitempty"` // banking, messaging, wallet, etc.
	SuspiciousUI     []string `json:"suspicious_ui,omitempty"`
	MissingElements  []string `json:"missing_elements,omitempty"`
	FakeIndicators   []string `json:"fake_indicators,omitempty"`
	PlatformMismatch bool     `json:"platform_mismatch"`
}

// NewVisionAnalyzer creates a new vision analyzer
func NewVisionAnalyzer(log *logger.Logger, llmClient *LLMClient, config VisionConfig) *VisionAnalyzer {
	return &VisionAnalyzer{
		httpClient: &http.Client{},
		logger:     log.WithComponent("vision-analyzer"),
		llmClient:  llmClient,
		config:     config,
	}
}

// AnalyzeImage analyzes an image for scam indicators
func (v *VisionAnalyzer) AnalyzeImage(ctx context.Context, imageData []byte, mimeType string) (*VisionAnalysisResult, error) {
	result := &VisionAnalysisResult{
		Severity: models.ScamSeverityNone,
	}

	// Validate image
	if len(imageData) == 0 {
		return nil, fmt.Errorf("empty image data")
	}

	if v.config.MaxImageSize > 0 && int64(len(imageData)) > v.config.MaxImageSize {
		return nil, fmt.Errorf("image too large: %d bytes (max: %d)", len(imageData), v.config.MaxImageSize)
	}

	// Detect mime type if not provided
	if mimeType == "" {
		mimeType = detectImageMimeType(imageData)
	}

	// Analyze with LLM vision
	llmAnalysis, err := v.analyzeWithLLM(ctx, imageData, mimeType)
	if err != nil {
		v.logger.Warn().Err(err).Msg("LLM vision analysis failed")
		// Continue with other analysis methods
	} else {
		v.mergeAnalysis(result, llmAnalysis)
	}

	// Extract text patterns from extracted text
	if result.ExtractedText != "" {
		v.extractEntitiesFromText(result)
	}

	// Determine final severity
	v.determineSeverity(result)

	return result, nil
}

// AnalyzeImageFile analyzes an image file for scam indicators
func (v *VisionAnalyzer) AnalyzeImageFile(ctx context.Context, filePath string) (*VisionAnalysisResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read image file: %w", err)
	}

	mimeType := detectImageMimeType(data)
	return v.AnalyzeImage(ctx, data, mimeType)
}

// AnalyzeImageURL analyzes an image from URL
func (v *VisionAnalyzer) AnalyzeImageURL(ctx context.Context, imageURL string) (*VisionAnalysisResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", imageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch image: status %d", resp.StatusCode)
	}

	// Limit read size
	limitedReader := io.LimitReader(resp.Body, 20*1024*1024) // 20MB max
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read image: %w", err)
	}

	mimeType := resp.Header.Get("Content-Type")
	return v.AnalyzeImage(ctx, data, mimeType)
}

// analyzeWithLLM uses LLM vision capabilities for analysis
func (v *VisionAnalyzer) analyzeWithLLM(ctx context.Context, imageData []byte, mimeType string) (*VisionAnalysisResult, error) {
	if v.llmClient == nil {
		return nil, fmt.Errorf("LLM client not configured")
	}

	// Encode image to base64
	base64Image := base64.StdEncoding.EncodeToString(imageData)

	// Create vision analysis prompt
	prompt := v.buildVisionPrompt()

	// Create message with image
	messages := []Message{
		{
			Role: "user",
			Content: []ContentPart{
				{
					Type: "image",
					Source: &ImageSource{
						Type:      "base64",
						MediaType: mimeType,
						Data:      base64Image,
					},
				},
				{
					Type: "text",
					Text: prompt,
				},
			},
		},
	}

	systemPrompt := v.buildVisionSystemPrompt()

	// Call LLM with vision
	response, err := v.llmClient.Chat(ctx, messages, systemPrompt)
	if err != nil {
		return nil, fmt.Errorf("LLM vision analysis failed: %w", err)
	}

	// Parse response
	return v.parseVisionResponse(response)
}

// buildVisionSystemPrompt creates the system prompt for vision analysis
func (v *VisionAnalyzer) buildVisionSystemPrompt() string {
	return `You are an expert cybersecurity analyst specializing in visual scam detection.
Your task is to analyze images (screenshots, photos, documents) for potential scam indicators.

You must identify:
1. Phishing attempts (fake login pages, fake apps, brand imitation)
2. Scam messages (urgency tactics, suspicious requests)
3. Fake documents (forged certificates, fake invoices)
4. Cryptocurrency scams (fake wallet interfaces, pump-and-dump schemes)
5. Tech support scams (fake error messages, fake security warnings)
6. Romance/social engineering scams (manipulative messaging)
7. Investment scams (unrealistic promises, fake trading platforms)
8. QR codes leading to malicious URLs
9. Fake government/official communications

Provide your analysis in JSON format with the following structure:
{
  "is_scam": boolean,
  "confidence": 0.0-1.0,
  "scam_type": "phishing|tech_support|investment|romance|crypto|advance_fee|lottery|impersonation|other",
  "extracted_text": "all readable text from the image",
  "urls": ["extracted URLs"],
  "phones": ["extracted phone numbers"],
  "emails": ["extracted email addresses"],
  "visual_indicators": [
    {"type": "type", "description": "description", "is_red_flag": boolean}
  ],
  "brand_imitation": {
    "detected": boolean,
    "brand": "brand name",
    "discrepancies": ["list of visual discrepancies"]
  },
  "ui_analysis": {
    "is_app_screenshot": boolean,
    "app_type": "type",
    "suspicious_elements": ["list"],
    "fake_indicators": ["list"]
  },
  "explanation": "detailed explanation",
  "red_flags": ["list of red flags identified"]
}`
}

// buildVisionPrompt creates the user prompt for vision analysis
func (v *VisionAnalyzer) buildVisionPrompt() string {
	return `Analyze this image for potential scam indicators.

Examine carefully:
1. Any text visible in the image - extract ALL text you can read
2. URLs, phone numbers, email addresses visible
3. Brand logos and whether they look authentic
4. UI elements and whether they match legitimate apps
5. Signs of urgency, fear tactics, or too-good-to-be-true offers
6. QR codes and their potential destination
7. Document authenticity (letterheads, signatures, seals)
8. Language quality (grammar, spelling, formatting)

Pay special attention to:
- Mismatched branding (wrong colors, fonts, logos)
- Suspicious URLs (misspellings, unusual domains)
- Requests for personal information or money
- Threatening language or artificial urgency
- Unrealistic promises or prizes
- Poor image quality or editing artifacts

Provide your complete analysis in the specified JSON format.`
}

// parseVisionResponse parses the LLM response into VisionAnalysisResult
func (v *VisionAnalyzer) parseVisionResponse(response string) (*VisionAnalysisResult, error) {
	result := &VisionAnalysisResult{
		RawAnalysis: response,
	}

	// Try to extract JSON from response
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		// If no JSON found, try to parse the whole response
		jsonStr = response
	}

	var parsed struct {
		IsScam           bool     `json:"is_scam"`
		Confidence       float64  `json:"confidence"`
		ScamType         string   `json:"scam_type"`
		ExtractedText    string   `json:"extracted_text"`
		URLs             []string `json:"urls"`
		Phones           []string `json:"phones"`
		Emails           []string `json:"emails"`
		VisualIndicators []struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			IsRedFlag   bool   `json:"is_red_flag"`
		} `json:"visual_indicators"`
		BrandImitation struct {
			Detected      bool     `json:"detected"`
			Brand         string   `json:"brand"`
			Discrepancies []string `json:"discrepancies"`
		} `json:"brand_imitation"`
		UIAnalysis struct {
			IsAppScreenshot    bool     `json:"is_app_screenshot"`
			AppType            string   `json:"app_type"`
			SuspiciousElements []string `json:"suspicious_elements"`
			FakeIndicators     []string `json:"fake_indicators"`
		} `json:"ui_analysis"`
		Explanation string   `json:"explanation"`
		RedFlags    []string `json:"red_flags"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		// If JSON parsing fails, create a basic result from the text
		result.Explanation = response
		return result, nil
	}

	// Map parsed data to result
	result.IsScam = parsed.IsScam
	result.Confidence = parsed.Confidence
	result.ScamType = models.ScamType(parsed.ScamType)
	result.ExtractedText = parsed.ExtractedText
	result.ExtractedURLs = parsed.URLs
	result.ExtractedPhones = parsed.Phones
	result.ExtractedEmails = parsed.Emails
	result.Explanation = parsed.Explanation
	result.RedFlags = parsed.RedFlags

	// Map visual indicators
	for _, vi := range parsed.VisualIndicators {
		result.VisualIndicators = append(result.VisualIndicators, VisualIndicator{
			Type:        vi.Type,
			Description: vi.Description,
			IsRedFlag:   vi.IsRedFlag,
			Confidence:  1.0,
		})
	}

	// Map brand imitation
	if parsed.BrandImitation.Detected {
		result.BrandImitation = &BrandImitation{
			Detected:      true,
			ImitatedBrand: parsed.BrandImitation.Brand,
			Discrepancies: parsed.BrandImitation.Discrepancies,
			Confidence:    parsed.Confidence,
		}
	}

	// Map UI analysis
	if parsed.UIAnalysis.IsAppScreenshot {
		result.UIAnalysis = &UIAnalysis{
			IsAppScreenshot: true,
			AppType:         parsed.UIAnalysis.AppType,
			SuspiciousUI:    parsed.UIAnalysis.SuspiciousElements,
			FakeIndicators:  parsed.UIAnalysis.FakeIndicators,
		}
	}

	return result, nil
}

// mergeAnalysis merges LLM analysis into the result
func (v *VisionAnalyzer) mergeAnalysis(result *VisionAnalysisResult, llmResult *VisionAnalysisResult) {
	if llmResult == nil {
		return
	}

	result.IsScam = llmResult.IsScam
	result.Confidence = llmResult.Confidence
	result.ScamType = llmResult.ScamType
	result.ExtractedText = llmResult.ExtractedText
	result.ExtractedURLs = llmResult.ExtractedURLs
	result.ExtractedPhones = llmResult.ExtractedPhones
	result.ExtractedEmails = llmResult.ExtractedEmails
	result.VisualIndicators = llmResult.VisualIndicators
	result.BrandImitation = llmResult.BrandImitation
	result.UIAnalysis = llmResult.UIAnalysis
	result.Explanation = llmResult.Explanation
	result.RedFlags = llmResult.RedFlags
	result.RawAnalysis = llmResult.RawAnalysis
}

// extractEntitiesFromText extracts URLs, phones, emails from text
func (v *VisionAnalyzer) extractEntitiesFromText(result *VisionAnalysisResult) {
	text := result.ExtractedText

	// Extract URLs
	urlPattern := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	urls := urlPattern.FindAllString(text, -1)
	for _, url := range urls {
		if !contains(result.ExtractedURLs, url) {
			result.ExtractedURLs = append(result.ExtractedURLs, url)
		}
	}

	// Extract email addresses
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emails := emailPattern.FindAllString(text, -1)
	for _, email := range emails {
		if !contains(result.ExtractedEmails, email) {
			result.ExtractedEmails = append(result.ExtractedEmails, email)
		}
	}

	// Extract phone numbers (various formats)
	phonePatterns := []string{
		`\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,      // US format
		`\+?[0-9]{1,3}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{4}`, // International
		`\+971[-.\s]?[0-9]{2}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,             // UAE
		`\+44[-.\s]?[0-9]{4}[-.\s]?[0-9]{6}`,                              // UK
	}

	for _, pattern := range phonePatterns {
		phoneRegex := regexp.MustCompile(pattern)
		phones := phoneRegex.FindAllString(text, -1)
		for _, phone := range phones {
			cleanPhone := cleanPhoneNumber(phone)
			if len(cleanPhone) >= 10 && !contains(result.ExtractedPhones, cleanPhone) {
				result.ExtractedPhones = append(result.ExtractedPhones, cleanPhone)
			}
		}
	}
}

// determineSeverity determines the severity based on analysis results
func (v *VisionAnalyzer) determineSeverity(result *VisionAnalysisResult) {
	if !result.IsScam {
		result.Severity = models.ScamSeverityNone
		return
	}

	// Critical: High confidence phishing or brand imitation
	if result.Confidence >= 0.9 {
		if result.BrandImitation != nil && result.BrandImitation.Detected {
			result.Severity = models.ScamSeverityCritical
			return
		}
		if result.ScamType == models.ScamTypePhishing {
			result.Severity = models.ScamSeverityCritical
			return
		}
	}

	// High: Clear scam indicators
	if result.Confidence >= 0.7 {
		result.Severity = models.ScamSeverityHigh
		return
	}

	// Medium: Suspicious but not confirmed
	if result.Confidence >= 0.5 {
		result.Severity = models.ScamSeverityMedium
		return
	}

	// Low: Might be suspicious
	result.Severity = models.ScamSeverityLow
}

// AnalyzeScreenshot analyzes a screenshot with context
func (v *VisionAnalyzer) AnalyzeScreenshot(ctx context.Context, imageData []byte, mimeType string, context ScreenshotContext) (*VisionAnalysisResult, error) {
	// First do basic analysis
	result, err := v.AnalyzeImage(ctx, imageData, mimeType)
	if err != nil {
		return nil, err
	}

	// Add context-aware analysis
	v.applyContextualAnalysis(result, context)

	return result, nil
}

// ScreenshotContext provides context for screenshot analysis
type ScreenshotContext struct {
	Source      string   `json:"source"`       // "browser", "app", "message", etc.
	URL         string   `json:"url"`          // Current URL if browser
	AppName     string   `json:"app_name"`     // App name if app screenshot
	Platform    string   `json:"platform"`     // "ios", "android", "macos", "windows"
	UserLocale  string   `json:"user_locale"`  // User's locale
	PreviousURL string   `json:"previous_url"` // Previous URL for redirect detection
	Suspicious  []string `json:"suspicious"`   // User-reported suspicious elements
}

// applyContextualAnalysis applies context-aware analysis
func (v *VisionAnalyzer) applyContextualAnalysis(result *VisionAnalysisResult, context ScreenshotContext) {
	// Check URL mismatch
	if context.URL != "" && result.BrandImitation != nil {
		legitDomain := getBrandDomain(result.BrandImitation.ImitatedBrand)
		if legitDomain != "" && !strings.Contains(context.URL, legitDomain) {
			result.RedFlags = append(result.RedFlags,
				fmt.Sprintf("URL mismatch: showing %s but URL is %s", result.BrandImitation.ImitatedBrand, context.URL))
			result.Severity = models.ScamSeverityCritical
			result.Confidence = max(result.Confidence, 0.95)
		}
	}

	// Check platform mismatch
	if result.UIAnalysis != nil && context.Platform != "" {
		if detectPlatformMismatch(result.UIAnalysis, context.Platform) {
			result.UIAnalysis.PlatformMismatch = true
			result.RedFlags = append(result.RedFlags, "UI platform doesn't match device platform")
		}
	}

	// Check for redirect attacks
	if context.PreviousURL != "" && context.URL != "" {
		if isRedirectSuspicious(context.PreviousURL, context.URL) {
			result.RedFlags = append(result.RedFlags,
				fmt.Sprintf("Suspicious redirect from %s to %s", context.PreviousURL, context.URL))
		}
	}
}

// DetectFakeApp detects fake app screenshots
func (v *VisionAnalyzer) DetectFakeApp(ctx context.Context, imageData []byte, claimedApp string) (*FakeAppDetectionResult, error) {
	result := &FakeAppDetectionResult{
		ClaimedApp: claimedApp,
	}

	// Analyze with vision
	visionResult, err := v.AnalyzeImage(ctx, imageData, "")
	if err != nil {
		return nil, err
	}

	result.VisionAnalysis = visionResult

	// Check for known fake app indicators
	if visionResult.UIAnalysis != nil {
		result.IsFake = len(visionResult.UIAnalysis.FakeIndicators) > 0
		result.FakeIndicators = visionResult.UIAnalysis.FakeIndicators
	}

	// Check brand imitation
	if visionResult.BrandImitation != nil && visionResult.BrandImitation.Detected {
		result.IsFake = true
		result.ImitatedBrand = visionResult.BrandImitation.ImitatedBrand
		result.Discrepancies = visionResult.BrandImitation.Discrepancies
	}

	// Determine confidence
	result.Confidence = visionResult.Confidence
	if result.IsFake {
		result.Confidence = max(result.Confidence, 0.7)
	}

	return result, nil
}

// FakeAppDetectionResult contains fake app detection results
type FakeAppDetectionResult struct {
	IsFake         bool                `json:"is_fake"`
	Confidence     float64             `json:"confidence"`
	ClaimedApp     string              `json:"claimed_app"`
	ImitatedBrand  string              `json:"imitated_brand,omitempty"`
	FakeIndicators []string            `json:"fake_indicators,omitempty"`
	Discrepancies  []string            `json:"discrepancies,omitempty"`
	VisionAnalysis *VisionAnalysisResult `json:"vision_analysis,omitempty"`
}

// Helper functions

func detectImageMimeType(data []byte) string {
	// Check magic bytes
	if len(data) < 4 {
		return "application/octet-stream"
	}

	// PNG
	if bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
		return "image/png"
	}

	// JPEG
	if bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		return "image/jpeg"
	}

	// GIF
	if bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")) {
		return "image/gif"
	}

	// WebP
	if len(data) > 12 && bytes.Equal(data[0:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
		return "image/webp"
	}

	// BMP
	if bytes.HasPrefix(data, []byte("BM")) {
		return "image/bmp"
	}

	return "application/octet-stream"
}

func extractJSON(text string) string {
	// Try to find JSON object in text
	start := strings.Index(text, "{")
	if start == -1 {
		return ""
	}

	// Find matching closing brace
	braceCount := 0
	for i := start; i < len(text); i++ {
		if text[i] == '{' {
			braceCount++
		} else if text[i] == '}' {
			braceCount--
			if braceCount == 0 {
				return text[start : i+1]
			}
		}
	}

	return ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func cleanPhoneNumber(phone string) string {
	// Remove all non-digit characters except leading +
	result := ""
	for i, c := range phone {
		if c == '+' && i == 0 {
			result += string(c)
		} else if c >= '0' && c <= '9' {
			result += string(c)
		}
	}
	return result
}

func getBrandDomain(brand string) string {
	brandDomains := map[string]string{
		"Apple":       "apple.com",
		"Microsoft":   "microsoft.com",
		"Google":      "google.com",
		"Amazon":      "amazon.com",
		"PayPal":      "paypal.com",
		"Netflix":     "netflix.com",
		"Facebook":    "facebook.com",
		"Instagram":   "instagram.com",
		"WhatsApp":    "whatsapp.com",
		"Bank of America": "bankofamerica.com",
		"Chase":       "chase.com",
		"Wells Fargo": "wellsfargo.com",
		"Coinbase":    "coinbase.com",
		"Binance":     "binance.com",
		"Emirates NBD": "emiratesnbd.com",
		"ADCB":        "adcb.com",
		"FAB":         "bankfab.com",
	}

	// Case-insensitive lookup
	for b, domain := range brandDomains {
		if strings.EqualFold(brand, b) {
			return domain
		}
	}
	return ""
}

func detectPlatformMismatch(ui *UIAnalysis, platform string) bool {
	// iOS specific elements on Android or vice versa
	iosElements := []string{"San Francisco font", "iOS navigation bar", "Apple Pay", "Face ID prompt"}
	androidElements := []string{"Material Design", "Android navigation", "Google Pay prompt"}

	if platform == "android" {
		for _, elem := range iosElements {
			for _, suspicious := range ui.SuspiciousUI {
				if strings.Contains(strings.ToLower(suspicious), strings.ToLower(elem)) {
					return true
				}
			}
		}
	} else if platform == "ios" {
		for _, elem := range androidElements {
			for _, suspicious := range ui.SuspiciousUI {
				if strings.Contains(strings.ToLower(suspicious), strings.ToLower(elem)) {
					return true
				}
			}
		}
	}

	return false
}

func isRedirectSuspicious(fromURL, toURL string) bool {
	// Check for open redirect patterns
	suspiciousPatterns := []string{
		"redirect=",
		"url=",
		"next=",
		"return=",
		"goto=",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(fromURL, pattern) {
			// The redirect URL in parameter doesn't match actual destination
			return true
		}
	}

	// Check for homograph attacks or lookalike domains
	// This is simplified - real implementation would use more sophisticated detection
	return false
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// GetImageDimensions returns the dimensions of an image
func GetImageDimensions(data []byte) (width, height int, err error) {
	reader := bytes.NewReader(data)
	config, _, err := image.DecodeConfig(reader)
	if err != nil {
		return 0, 0, err
	}
	return config.Width, config.Height, nil
}
