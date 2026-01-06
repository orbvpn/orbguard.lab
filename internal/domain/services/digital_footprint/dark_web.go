package digital_footprint

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// DarkWebScanner scans for data exposure on the dark web and breaches
type DarkWebScanner struct {
	httpClient *http.Client
	cache      *cache.RedisCache
	logger     *logger.Logger

	// API keys (would be loaded from config)
	hibpAPIKey string
}

// NewDarkWebScanner creates a new dark web scanner
func NewDarkWebScanner(redisCache *cache.RedisCache, log *logger.Logger) *DarkWebScanner {
	return &DarkWebScanner{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:  redisCache,
		logger: log.WithComponent("dark-web-scanner"),
	}
}

// SetHIBPAPIKey sets the Have I Been Pwned API key
func (s *DarkWebScanner) SetHIBPAPIKey(key string) {
	s.hibpAPIKey = key
}

// Scan performs a dark web and breach scan
func (s *DarkWebScanner) Scan(ctx context.Context, email, phone string) ([]models.BreachFinding, []models.DataExposure, error) {
	var breaches []models.BreachFinding
	var exposures []models.DataExposure

	// Check HIBP for email breaches
	if email != "" {
		hibpBreaches, err := s.checkHIBP(ctx, email)
		if err != nil {
			s.logger.Warn().Err(err).Str("email", maskEmail(email)).Msg("HIBP check failed")
		} else {
			breaches = append(breaches, hibpBreaches...)

			// Convert breaches to exposures
			for _, b := range hibpBreaches {
				for _, dataType := range b.ExposedDataTypes {
					exposure := models.DataExposure{
						ID:           uuid.New(),
						Type:         dataType,
						Severity:     s.getSeverityForType(dataType),
						Source:       models.ExposureSourceBreach,
						SourceName:   b.BreachName,
						ExposedValue: models.RedactValue(email, models.ExposureTypeEmail),
						Context:      fmt.Sprintf("Found in %s breach (%s)", b.BreachName, b.BreachDate.Format("Jan 2006")),
						FirstSeen:    b.BreachDate,
						LastSeen:     b.DiscoveredAt,
						CanAutoRemove: false,
						CreatedAt:    time.Now(),
					}
					exposures = append(exposures, exposure)
				}
			}
		}
	}

	// Check for password exposure using k-anonymity
	if email != "" {
		pwned, count, err := s.checkPasswordPwned(ctx, email)
		if err != nil {
			s.logger.Warn().Err(err).Msg("password pwned check failed")
		} else if pwned {
			exposures = append(exposures, models.DataExposure{
				ID:           uuid.New(),
				Type:         models.ExposureTypePassword,
				Severity:     models.ExposureSeverityCritical,
				Source:       models.ExposureSourceBreach,
				SourceName:   "Password Breach Database",
				ExposedValue: "********",
				Context:      fmt.Sprintf("Password appeared in %d breaches", count),
				FirstSeen:    time.Now().AddDate(-1, 0, 0), // Approximate
				LastSeen:     time.Now(),
				CanAutoRemove: false,
				CreatedAt:    time.Now(),
			})
		}
	}

	// Check paste sites
	if email != "" {
		pasteExposures, err := s.checkPasteSites(ctx, email)
		if err != nil {
			s.logger.Warn().Err(err).Msg("paste site check failed")
		} else {
			exposures = append(exposures, pasteExposures...)
		}
	}

	return breaches, exposures, nil
}

// HIBPBreach represents a breach from Have I Been Pwned
type HIBPBreach struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
	PwnCount     int64    `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsFabricated bool     `json:"IsFabricated"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsRetired    bool     `json:"IsRetired"`
	IsSpamList   bool     `json:"IsSpamList"`
}

// checkHIBP checks Have I Been Pwned for breaches
func (s *DarkWebScanner) checkHIBP(ctx context.Context, email string) ([]models.BreachFinding, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("hibp:breaches:%s", hashEmail(email))
	if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		var breaches []models.BreachFinding
		if err := json.Unmarshal([]byte(cached), &breaches); err == nil {
			return breaches, nil
		}
	}

	// Make API request
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", email)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("hibp-api-key", s.hibpAPIKey)
	req.Header.Set("User-Agent", "OrbGuard-Security-Scanner")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 404 means no breaches found
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var hibpBreaches []HIBPBreach
	if err := json.Unmarshal(body, &hibpBreaches); err != nil {
		return nil, err
	}

	// Convert to our model
	var breaches []models.BreachFinding
	for _, hb := range hibpBreaches {
		breachDate, _ := time.Parse("2006-01-02", hb.BreachDate)
		addedDate, _ := time.Parse("2006-01-02T15:04:05", hb.AddedDate)

		breach := models.BreachFinding{
			BreachID:         hb.Name,
			BreachName:       hb.Title,
			BreachDate:       breachDate,
			Domain:           hb.Domain,
			ExposedDataTypes: s.mapDataClasses(hb.DataClasses),
			RecordCount:      hb.PwnCount,
			Description:      hb.Description,
			IsSensitive:      hb.IsSensitive,
			IsVerified:       hb.IsVerified,
			IsSpamList:       hb.IsSpamList,
			Source:           "HIBP",
			DiscoveredAt:     addedDate,
		}
		breaches = append(breaches, breach)
	}

	// Cache result
	if data, err := json.Marshal(breaches); err == nil {
		_ = s.cache.Set(ctx, cacheKey, string(data), 24*time.Hour)
	}

	return breaches, nil
}

// checkPasswordPwned checks if a password hash appears in breaches
func (s *DarkWebScanner) checkPasswordPwned(ctx context.Context, password string) (bool, int, error) {
	// Use k-anonymity model - only send first 5 chars of SHA1 hash
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, err
	}

	req.Header.Set("User-Agent", "OrbGuard-Security-Scanner")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("pwnedpasswords API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	// Search for our suffix in the response
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 2 && parts[0] == suffix {
			var count int
			fmt.Sscanf(parts[1], "%d", &count)
			return true, count, nil
		}
	}

	return false, 0, nil
}

// checkPasteSites checks paste sites for exposed data
func (s *DarkWebScanner) checkPasteSites(ctx context.Context, email string) ([]models.DataExposure, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("hibp:pastes:%s", hashEmail(email))
	if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		var exposures []models.DataExposure
		if err := json.Unmarshal([]byte(cached), &exposures); err == nil {
			return exposures, nil
		}
	}

	// Make API request to HIBP paste endpoint
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/pasteaccount/%s", email)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("hibp-api-key", s.hibpAPIKey)
	req.Header.Set("User-Agent", "OrbGuard-Security-Scanner")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 404 means no pastes found
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HIBP paste API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pastes []struct {
		Source     string `json:"Source"`
		ID         string `json:"Id"`
		Title      string `json:"Title"`
		Date       string `json:"Date"`
		EmailCount int    `json:"EmailCount"`
	}
	if err := json.Unmarshal(body, &pastes); err != nil {
		return nil, err
	}

	var exposures []models.DataExposure
	for _, paste := range pastes {
		pasteDate, _ := time.Parse("2006-01-02T15:04:05", paste.Date)
		exposure := models.DataExposure{
			ID:           uuid.New(),
			Type:         models.ExposureTypeEmail,
			Severity:     models.ExposureSeverityHigh,
			Source:       models.ExposureSourcePasteSite,
			SourceName:   paste.Source,
			ExposedValue: models.RedactValue(email, models.ExposureTypeEmail),
			Context:      fmt.Sprintf("Found in paste on %s", paste.Source),
			FirstSeen:    pasteDate,
			LastSeen:     pasteDate,
			CanAutoRemove: false,
			CreatedAt:    time.Now(),
		}
		exposures = append(exposures, exposure)
	}

	// Cache result
	if data, err := json.Marshal(exposures); err == nil {
		_ = s.cache.Set(ctx, cacheKey, string(data), 24*time.Hour)
	}

	return exposures, nil
}

// mapDataClasses maps HIBP data classes to our exposure types
func (s *DarkWebScanner) mapDataClasses(classes []string) []models.ExposureType {
	var types []models.ExposureType
	seen := make(map[models.ExposureType]bool)

	for _, class := range classes {
		var t models.ExposureType
		switch strings.ToLower(class) {
		case "email addresses", "emails":
			t = models.ExposureTypeEmail
		case "passwords", "password hints":
			t = models.ExposureTypePassword
		case "phone numbers":
			t = models.ExposureTypePhone
		case "physical addresses", "addresses":
			t = models.ExposureTypeAddress
		case "names":
			t = models.ExposureTypeName
		case "usernames":
			t = models.ExposureTypeUsername
		case "dates of birth", "dobs", "ages":
			t = models.ExposureTypeDateOfBirth
		case "social security numbers":
			t = models.ExposureTypeSSN
		case "credit cards", "partial credit card data":
			t = models.ExposureTypeCreditCard
		case "bank account numbers":
			t = models.ExposureTypeBankAccount
		case "ip addresses":
			t = models.ExposureTypeIPAddress
		case "employers", "job titles":
			t = models.ExposureTypeEmployment
		case "education levels":
			t = models.ExposureTypeEducation
		case "photos", "avatars":
			t = models.ExposureTypePhoto
		case "social media profiles":
			t = models.ExposureTypeSocialProfile
		default:
			continue
		}

		if !seen[t] {
			types = append(types, t)
			seen[t] = true
		}
	}

	return types
}

// getSeverityForType returns severity level for exposure type
func (s *DarkWebScanner) getSeverityForType(t models.ExposureType) models.ExposureSeverity {
	switch t {
	case models.ExposureTypeSSN, models.ExposureTypePassword, models.ExposureTypeCreditCard, models.ExposureTypeBankAccount:
		return models.ExposureSeverityCritical
	case models.ExposureTypeAddress, models.ExposureTypeDateOfBirth, models.ExposureTypePhone, models.ExposureTypeDriverLicense:
		return models.ExposureSeverityHigh
	case models.ExposureTypeEmail, models.ExposureTypeEmployment, models.ExposureTypeEducation:
		return models.ExposureSeverityMedium
	case models.ExposureTypeName, models.ExposureTypeUsername:
		return models.ExposureSeverityLow
	default:
		return models.ExposureSeverityInfo
	}
}

// Helper functions
func hashEmail(email string) string {
	hash := sha1.Sum([]byte(strings.ToLower(email)))
	return hex.EncodeToString(hash[:])
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***"
	}
	if len(parts[0]) <= 2 {
		return parts[0][:1] + "***@" + parts[1]
	}
	return parts[0][:2] + "***@" + parts[1]
}
