package digital_footprint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// SocialMediaScanner scans social media platforms for privacy exposures
type SocialMediaScanner struct {
	httpClient *http.Client
	cache      *cache.RedisCache
	logger     *logger.Logger
}

// SocialScanRequest contains social media scan parameters
type SocialScanRequest struct {
	Email    string
	FullName string
	Profiles []models.SocialProfileInfo
}

// SocialPlatform represents a social media platform configuration
type SocialPlatform struct {
	Name           string
	Domain         string
	SearchURL      string
	ProfilePattern string
	PrivacyURL     string
	OptOutURL      string
	PrivacyChecks  []PrivacyCheck
}

// PrivacyCheck represents a privacy setting to check
type PrivacyCheck struct {
	Name        string
	Description string
	Severity    string
	Pattern     string // Regex pattern to detect issue
	Remediation string
}

// NewSocialMediaScanner creates a new social media scanner
func NewSocialMediaScanner(redisCache *cache.RedisCache, log *logger.Logger) *SocialMediaScanner {
	return &SocialMediaScanner{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cache:  redisCache,
		logger: log.WithComponent("social-media-scanner"),
	}
}

// Scan checks social media platforms for privacy issues
func (s *SocialMediaScanner) Scan(ctx context.Context, req SocialScanRequest) ([]models.SocialMediaFinding, error) {
	var findings []models.SocialMediaFinding

	// Get platforms to check
	platforms := s.getPlatforms()

	// Check each provided profile
	for _, profile := range req.Profiles {
		for _, platform := range platforms {
			if strings.EqualFold(platform.Name, profile.Platform) {
				finding, err := s.checkPlatform(ctx, platform, profile, req)
				if err != nil {
					s.logger.Debug().
						Err(err).
						Str("platform", platform.Name).
						Msg("platform check failed")
					continue
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
	}

	// Also do discovery search if no profiles provided
	if len(req.Profiles) == 0 && req.Email != "" {
		discoveredFindings := s.discoverProfiles(ctx, req)
		findings = append(findings, discoveredFindings...)
	}

	return findings, nil
}

// getPlatforms returns social media platform configurations
func (s *SocialMediaScanner) getPlatforms() []SocialPlatform {
	return []SocialPlatform{
		{
			Name:           "facebook",
			Domain:         "facebook.com",
			SearchURL:      "https://www.facebook.com/search/people/?q=%s",
			ProfilePattern: `facebook\.com/([a-zA-Z0-9.]+)`,
			PrivacyURL:     "https://www.facebook.com/privacy/checkup",
			OptOutURL:      "https://www.facebook.com/help/delete_account",
			PrivacyChecks: []PrivacyCheck{
				{
					Name:        "public_profile",
					Description: "Profile is publicly visible",
					Severity:    "high",
					Pattern:     `"privacy":\s*"EVERYONE"`,
					Remediation: "Change profile visibility to 'Friends Only' in Privacy Settings",
				},
				{
					Name:        "public_friends_list",
					Description: "Friends list is publicly visible",
					Severity:    "medium",
					Pattern:     `friends.*public|public.*friends`,
					Remediation: "Hide friends list in Privacy Settings",
				},
				{
					Name:        "location_sharing",
					Description: "Location data is being shared",
					Severity:    "high",
					Pattern:     `"location":\s*"[^"]+"|check-in|checked in at`,
					Remediation: "Disable location history in Privacy Settings",
				},
				{
					Name:        "search_engine_indexed",
					Description: "Profile is indexed by search engines",
					Severity:    "medium",
					Pattern:     `search engines outside of Facebook`,
					Remediation: "Disable search engine indexing in Privacy Settings",
				},
			},
		},
		{
			Name:           "linkedin",
			Domain:         "linkedin.com",
			SearchURL:      "https://www.linkedin.com/search/results/people/?keywords=%s",
			ProfilePattern: `linkedin\.com/in/([a-zA-Z0-9-]+)`,
			PrivacyURL:     "https://www.linkedin.com/psettings/",
			OptOutURL:      "https://www.linkedin.com/help/linkedin/answer/63",
			PrivacyChecks: []PrivacyCheck{
				{
					Name:        "public_profile",
					Description: "Profile is publicly visible to non-LinkedIn members",
					Severity:    "medium",
					Pattern:     `public profile`,
					Remediation: "Adjust public profile settings in Privacy & Settings",
				},
				{
					Name:        "email_visible",
					Description: "Email address is visible on profile",
					Severity:    "high",
					Pattern:     `@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
					Remediation: "Hide email address in Contact Info settings",
				},
				{
					Name:        "connections_visible",
					Description: "Connections list is visible to others",
					Severity:    "low",
					Pattern:     `\d+\+?\s*connections`,
					Remediation: "Hide connection count in Privacy Settings",
				},
			},
		},
		{
			Name:           "twitter",
			Domain:         "twitter.com",
			SearchURL:      "https://twitter.com/search?q=%s&src=typed_query&f=user",
			ProfilePattern: `twitter\.com/([a-zA-Z0-9_]+)`,
			PrivacyURL:     "https://twitter.com/settings/privacy_and_safety",
			OptOutURL:      "https://help.twitter.com/en/managing-your-account/how-to-deactivate-twitter-account",
			PrivacyChecks: []PrivacyCheck{
				{
					Name:        "public_tweets",
					Description: "Tweets are publicly visible",
					Severity:    "medium",
					Pattern:     `"protected":\s*false`,
					Remediation: "Enable protected tweets in Privacy and Safety settings",
				},
				{
					Name:        "location_in_tweets",
					Description: "Location is included in tweets",
					Severity:    "high",
					Pattern:     `"geo":\s*{|"place":\s*{`,
					Remediation: "Disable location tagging in Privacy settings",
				},
				{
					Name:        "discoverable_by_email",
					Description: "Account discoverable by email address",
					Severity:    "medium",
					Pattern:     `discoverability`,
					Remediation: "Disable email/phone discoverability in Privacy settings",
				},
			},
		},
		{
			Name:           "instagram",
			Domain:         "instagram.com",
			SearchURL:      "https://www.instagram.com/web/search/topsearch/?query=%s",
			ProfilePattern: `instagram\.com/([a-zA-Z0-9._]+)`,
			PrivacyURL:     "https://www.instagram.com/accounts/privacy_and_security/",
			OptOutURL:      "https://help.instagram.com/370452623149242",
			PrivacyChecks: []PrivacyCheck{
				{
					Name:        "public_account",
					Description: "Account is publicly visible",
					Severity:    "medium",
					Pattern:     `"is_private":\s*false`,
					Remediation: "Switch to a private account in Privacy Settings",
				},
				{
					Name:        "tagged_photos_visible",
					Description: "Photos you're tagged in are visible",
					Severity:    "low",
					Pattern:     `tagged.*photos|photos.*tagged`,
					Remediation: "Manually approve tags before they appear on your profile",
				},
			},
		},
		{
			Name:           "tiktok",
			Domain:         "tiktok.com",
			SearchURL:      "https://www.tiktok.com/search?q=%s",
			ProfilePattern: `tiktok\.com/@([a-zA-Z0-9._]+)`,
			PrivacyURL:     "https://www.tiktok.com/privacy/",
			OptOutURL:      "https://support.tiktok.com/en/account-and-privacy/deleting-an-account",
			PrivacyChecks: []PrivacyCheck{
				{
					Name:        "public_account",
					Description: "Account and videos are publicly visible",
					Severity:    "medium",
					Pattern:     `"privateAccount":\s*false`,
					Remediation: "Switch to a private account in Privacy settings",
				},
			},
		},
	}
}

// checkPlatform checks a specific platform for privacy issues
func (s *SocialMediaScanner) checkPlatform(ctx context.Context, platform SocialPlatform, profile models.SocialProfileInfo, req SocialScanRequest) (*models.SocialMediaFinding, error) {
	// Check cache
	cacheKey := fmt.Sprintf("social:%s:%s", platform.Name, profile.Username)
	if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		var finding models.SocialMediaFinding
		if err := json.Unmarshal([]byte(cached), &finding); err == nil {
			return &finding, nil
		}
	}

	// Build profile URL
	profileURL := profile.URL
	if profileURL == "" && profile.Username != "" {
		profileURL = fmt.Sprintf("https://%s/%s", platform.Domain, profile.Username)
	}

	if profileURL == "" {
		return nil, fmt.Errorf("no profile URL or username provided")
	}

	// Fetch profile page
	httpReq, err := http.NewRequestWithContext(ctx, "GET", profileURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Profile doesn't exist
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB limit
	if err != nil {
		return nil, err
	}

	// Check for privacy issues
	var issues []models.SocialMediaPrivacyIssue
	for _, check := range platform.PrivacyChecks {
		if check.Pattern != "" {
			re, err := regexp.Compile("(?i)" + check.Pattern)
			if err != nil {
				continue
			}
			if re.Match(body) {
				issues = append(issues, models.SocialMediaPrivacyIssue{
					Type:        check.Name,
					Description: check.Description,
					Severity:    check.Severity,
					Remediation: check.Remediation,
				})
			}
		}
	}

	// Calculate risk score
	riskScore := s.calculateRiskScore(issues)
	riskLevel := s.getRiskLevel(riskScore)

	finding := &models.SocialMediaFinding{
		Platform:      platform.Name,
		ProfileURL:    profileURL,
		Username:      profile.Username,
		PrivacyIssues: issues,
		RiskScore:     riskScore,
		RiskLevel:     riskLevel,
		FoundAt:       time.Now(),
	}

	// Cache result
	if data, err := json.Marshal(finding); err == nil {
		_ = s.cache.Set(ctx, cacheKey, string(data), 24*time.Hour)
	}

	return finding, nil
}

// discoverProfiles tries to discover social media profiles
func (s *SocialMediaScanner) discoverProfiles(ctx context.Context, req SocialScanRequest) []models.SocialMediaFinding {
	var findings []models.SocialMediaFinding

	// Use email username as potential handle
	emailParts := strings.Split(req.Email, "@")
	if len(emailParts) != 2 {
		return findings
	}
	username := emailParts[0]

	platforms := s.getPlatforms()

	for _, platform := range platforms {
		// Try common profile URL patterns
		profileURLs := []string{
			fmt.Sprintf("https://%s/%s", platform.Domain, username),
			fmt.Sprintf("https://www.%s/%s", platform.Domain, username),
		}

		for _, profileURL := range profileURLs {
			httpReq, err := http.NewRequestWithContext(ctx, "HEAD", profileURL, nil)
			if err != nil {
				continue
			}

			httpReq.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.httpClient.Do(httpReq)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// If we get 200, profile likely exists
			if resp.StatusCode == http.StatusOK {
				finding, err := s.checkPlatform(ctx, platform, models.SocialProfileInfo{
					Platform: platform.Name,
					Username: username,
					URL:      profileURL,
				}, req)
				if err == nil && finding != nil {
					findings = append(findings, *finding)
				}
				break // Found on this platform, move to next
			}
		}
	}

	return findings
}

// calculateRiskScore calculates risk score from issues
func (s *SocialMediaScanner) calculateRiskScore(issues []models.SocialMediaPrivacyIssue) float64 {
	if len(issues) == 0 {
		return 0
	}

	var score float64
	for _, issue := range issues {
		switch issue.Severity {
		case "high":
			score += 30
		case "medium":
			score += 15
		case "low":
			score += 5
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

// getRiskLevel returns risk level from score
func (s *SocialMediaScanner) getRiskLevel(score float64) string {
	switch {
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// GetPlatformPrivacyGuide returns privacy guide for a platform
func (s *SocialMediaScanner) GetPlatformPrivacyGuide(platform string) *PlatformPrivacyGuide {
	platforms := s.getPlatforms()

	for _, p := range platforms {
		if strings.EqualFold(p.Name, platform) {
			var steps []PrivacyStep
			for _, check := range p.PrivacyChecks {
				steps = append(steps, PrivacyStep{
					Issue:       check.Description,
					Severity:    check.Severity,
					Remediation: check.Remediation,
				})
			}

			return &PlatformPrivacyGuide{
				Platform:     p.Name,
				PrivacyURL:   p.PrivacyURL,
				DeleteURL:    p.OptOutURL,
				PrivacySteps: steps,
			}
		}
	}

	return nil
}

// PlatformPrivacyGuide contains privacy guidance for a platform
type PlatformPrivacyGuide struct {
	Platform     string        `json:"platform"`
	PrivacyURL   string        `json:"privacy_url"`
	DeleteURL    string        `json:"delete_url"`
	PrivacySteps []PrivacyStep `json:"privacy_steps"`
}

// PrivacyStep represents a privacy improvement step
type PrivacyStep struct {
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// CheckUsernameAvailability checks if a username exists on platforms
func (s *SocialMediaScanner) CheckUsernameAvailability(ctx context.Context, username string) map[string]bool {
	results := make(map[string]bool)
	platforms := s.getPlatforms()

	for _, platform := range platforms {
		profileURL := fmt.Sprintf("https://%s/%s", platform.Domain, url.PathEscape(username))

		httpReq, err := http.NewRequestWithContext(ctx, "HEAD", profileURL, nil)
		if err != nil {
			results[platform.Name] = false
			continue
		}

		httpReq.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := s.httpClient.Do(httpReq)
		if err != nil {
			results[platform.Name] = false
			continue
		}
		resp.Body.Close()

		// 200 means username is taken (profile exists)
		results[platform.Name] = resp.StatusCode == http.StatusOK
	}

	return results
}
