package services

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// HIBPClient provides access to Have I Been Pwned API
type HIBPClient struct {
	apiKey     string
	httpClient *http.Client
	logger     *logger.Logger
	baseURL    string
}

// HIBPConfig holds configuration for HIBP client
type HIBPConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewHIBPClient creates a new HIBP API client
func NewHIBPClient(config HIBPConfig, log *logger.Logger) *HIBPClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &HIBPClient{
		apiKey:  config.APIKey,
		baseURL: "https://haveibeenpwned.com/api/v3",
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: log.WithComponent("hibp-client"),
	}
}

// CheckEmail checks if an email has been involved in any breaches
func (c *HIBPClient) CheckEmail(ctx context.Context, email string) (*models.BreachCheckResponse, error) {
	response := &models.BreachCheckResponse{
		Email:     email,
		IsBreached: false,
		CheckedAt: time.Now(),
	}

	// Check if API key is configured
	if c.apiKey == "" {
		c.logger.Warn().Str("email", email).Msg("HIBP API key not configured, returning simulated response")
		// Return simulated response for development/testing
		response.RiskLevel = models.BreachSeverityLow
		response.Recommendations = []string{
			"HIBP API key not configured - this is a simulated response.",
			"Configure ORBGUARD_SOURCES_HIBP_API_KEY for real breach checks.",
			"Get an API key at: https://haveibeenpwned.com/API/Key",
		}
		return response, nil
	}

	// Get breaches for this email
	breaches, err := c.getBreachedAccount(ctx, email)
	if err != nil {
		// 404 means not breached
		if strings.Contains(err.Error(), "404") {
			response.RiskLevel = models.BreachSeverityLow
			response.Recommendations = []string{"No breaches found. Continue using strong, unique passwords."}
			return response, nil
		}
		return nil, err
	}

	response.IsBreached = len(breaches) > 0
	response.BreachCount = len(breaches)
	response.Breaches = breaches

	// Calculate exposed data types and severity
	exposedTypesMap := make(map[string]bool)
	var firstBreach, latestBreach time.Time
	maxSeverity := models.BreachSeverityLow

	for _, breach := range breaches {
		for _, dataClass := range breach.DataClasses {
			exposedTypesMap[dataClass] = true
		}

		if firstBreach.IsZero() || breach.BreachDate.Before(firstBreach) {
			firstBreach = breach.BreachDate
		}
		if latestBreach.IsZero() || breach.BreachDate.After(latestBreach) {
			latestBreach = breach.BreachDate
		}

		if models.CompareSeverity(breach.Severity, maxSeverity) > 0 {
			maxSeverity = breach.Severity
		}
	}

	for dataType := range exposedTypesMap {
		response.ExposedDataTypes = append(response.ExposedDataTypes, dataType)
	}

	if !firstBreach.IsZero() {
		response.FirstBreach = &firstBreach
	}
	if !latestBreach.IsZero() {
		response.LatestBreach = &latestBreach
	}

	response.RiskLevel = maxSeverity
	response.Recommendations = c.generateRecommendations(breaches, exposedTypesMap)

	c.logger.Info().
		Str("email", maskEmail(email)).
		Int("breach_count", len(breaches)).
		Str("risk_level", string(maxSeverity)).
		Msg("email breach check completed")

	return response, nil
}

// CheckPassword checks if a password has been exposed in breaches using k-anonymity
func (c *HIBPClient) CheckPassword(ctx context.Context, password string) (*models.PasswordCheckResponse, error) {
	response := &models.PasswordCheckResponse{
		IsBreached:  false,
		BreachCount: 0,
		RiskLevel:   "safe",
		Message:     "This password has not been found in any known data breaches.",
		CheckedAt:   time.Now(),
	}

	// Hash password with SHA-1
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))

	// Get first 5 characters (prefix) and the rest (suffix)
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	// Query HIBP Passwords API with k-anonymity
	resp, err := c.queryPasswordRange(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to query password range: %w", err)
	}

	// Search for our suffix in the response
	lines := strings.Split(resp, "\r\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		if parts[0] == suffix {
			count, _ := strconv.Atoi(parts[1])
			response.IsBreached = true
			response.BreachCount = count
			response.RiskLevel = c.calculatePasswordRisk(count)
			response.Message = c.generatePasswordMessage(count)
			break
		}
	}

	c.logger.Debug().
		Bool("breached", response.IsBreached).
		Int("count", response.BreachCount).
		Str("risk", response.RiskLevel).
		Msg("password breach check completed")

	return response, nil
}

// GetBreachByName gets details of a specific breach by name
func (c *HIBPClient) GetBreachByName(ctx context.Context, name string) (*models.Breach, error) {
	reqURL := fmt.Sprintf("%s/breach/%s", c.baseURL, url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "OrbGuard-Security-App")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var hibpBreach hibpBreachResponse
	if err := json.NewDecoder(resp.Body).Decode(&hibpBreach); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.convertBreach(hibpBreach), nil
}

// GetAllBreaches gets all breaches in the HIBP database
func (c *HIBPClient) GetAllBreaches(ctx context.Context) ([]models.Breach, error) {
	reqURL := fmt.Sprintf("%s/breaches", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "OrbGuard-Security-App")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var hibpBreaches []hibpBreachResponse
	if err := json.NewDecoder(resp.Body).Decode(&hibpBreaches); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	breaches := make([]models.Breach, len(hibpBreaches))
	for i, hb := range hibpBreaches {
		breaches[i] = *c.convertBreach(hb)
	}

	return breaches, nil
}

// getBreachedAccount gets breaches for a specific email account
func (c *HIBPClient) getBreachedAccount(ctx context.Context, email string) ([]models.Breach, error) {
	reqURL := fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false",
		c.baseURL, url.PathEscape(email))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "OrbGuard-Security-App")
	req.Header.Set("hibp-api-key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404 not found")
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited - try again later")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid API key")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var hibpBreaches []hibpBreachResponse
	if err := json.NewDecoder(resp.Body).Decode(&hibpBreaches); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	breaches := make([]models.Breach, len(hibpBreaches))
	for i, hb := range hibpBreaches {
		breaches[i] = *c.convertBreach(hb)
	}

	return breaches, nil
}

// queryPasswordRange queries the password range API (k-anonymity)
func (c *HIBPClient) queryPasswordRange(ctx context.Context, prefix string) (string, error) {
	reqURL := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "OrbGuard-Security-App")
	req.Header.Set("Add-Padding", "true") // Privacy enhancement

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(body), nil
}

// convertBreach converts HIBP breach response to our model
func (c *HIBPClient) convertBreach(hb hibpBreachResponse) *models.Breach {
	breachDate, _ := time.Parse("2006-01-02", hb.BreachDate)
	addedDate, _ := time.Parse(time.RFC3339, hb.AddedDate)
	modifiedDate, _ := time.Parse(time.RFC3339, hb.ModifiedDate)

	return &models.Breach{
		Name:         hb.Name,
		Title:        hb.Title,
		Domain:       hb.Domain,
		BreachDate:   breachDate,
		AddedDate:    addedDate,
		ModifiedDate: modifiedDate,
		PwnCount:     hb.PwnCount,
		Description:  hb.Description,
		LogoPath:     hb.LogoPath,
		DataClasses:  hb.DataClasses,
		IsVerified:   hb.IsVerified,
		IsFabricated: hb.IsFabricated,
		IsSensitive:  hb.IsSensitive,
		IsRetired:    hb.IsRetired,
		IsSpamList:   hb.IsSpamList,
		IsMalware:    hb.IsMalware,
		Severity:     models.CalculateBreachSeverity(hb.DataClasses),
	}
}

// calculatePasswordRisk determines risk level based on breach count
func (c *HIBPClient) calculatePasswordRisk(count int) string {
	switch {
	case count == 0:
		return "safe"
	case count < 10:
		return "weak"
	case count < 100:
		return "compromised"
	case count < 1000:
		return "high_risk"
	default:
		return "critical"
	}
}

// generatePasswordMessage generates a message based on breach count
func (c *HIBPClient) generatePasswordMessage(count int) string {
	switch {
	case count < 10:
		return fmt.Sprintf("This password has appeared %d times in data breaches. Consider changing it.", count)
	case count < 100:
		return fmt.Sprintf("WARNING: This password has appeared %d times in data breaches. You should change it immediately.", count)
	case count < 1000:
		return fmt.Sprintf("DANGER: This password has appeared %d times in data breaches. Change it now!", count)
	default:
		return fmt.Sprintf("CRITICAL: This password has appeared %d times in data breaches. It is extremely compromised and must be changed immediately!", count)
	}
}

// generateRecommendations creates recommendations based on breaches
func (c *HIBPClient) generateRecommendations(breaches []models.Breach, exposedTypes map[string]bool) []string {
	recommendations := []string{}

	if exposedTypes["Passwords"] {
		recommendations = append(recommendations,
			"Change your password immediately on the affected services",
			"Use a unique password for each account",
			"Consider using a password manager")
	}

	if exposedTypes["Credit cards"] || exposedTypes["Bank account numbers"] || exposedTypes["Financial data"] {
		recommendations = append(recommendations,
			"Monitor your bank and credit card statements for unauthorized transactions",
			"Consider placing a fraud alert on your credit reports",
			"Contact your bank if you see any suspicious activity")
	}

	if exposedTypes["Social security numbers"] {
		recommendations = append(recommendations,
			"Place a credit freeze with the three major credit bureaus",
			"Monitor your credit report regularly",
			"Consider identity theft protection services")
	}

	if exposedTypes["Phone numbers"] {
		recommendations = append(recommendations,
			"Be cautious of phishing calls and smishing attempts",
			"Consider registering with the Do Not Call Registry")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations,
			"Enable two-factor authentication on all affected accounts",
			"Monitor your accounts for suspicious activity")
	}

	// Always add 2FA recommendation
	if !contains(recommendations, "Enable two-factor authentication") {
		recommendations = append(recommendations, "Enable two-factor authentication on all accounts where available")
	}

	return recommendations
}

// HIBP API response types
type hibpBreachResponse struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
	PwnCount     int64    `json:"PwnCount"`
	Description  string   `json:"Description"`
	LogoPath     string   `json:"LogoPath"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsFabricated bool     `json:"IsFabricated"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsRetired    bool     `json:"IsRetired"`
	IsSpamList   bool     `json:"IsSpamList"`
	IsMalware    bool     `json:"IsMalware"`
}

// Helper functions

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***"
	}

	local := parts[0]
	if len(local) <= 2 {
		return local[0:1] + "***@" + parts[1]
	}
	return local[0:1] + "***" + local[len(local)-1:] + "@" + parts[1]
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}
