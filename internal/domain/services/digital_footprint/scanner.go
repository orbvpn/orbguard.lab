package digital_footprint

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/brokers"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// Scanner orchestrates digital footprint scanning across multiple sources
type Scanner struct {
	brokerDB       *brokers.BrokerDatabase
	darkWebScanner *DarkWebScanner
	brokerScanner  *BrokerScanner
	socialScanner  *SocialMediaScanner
	removalService *RemovalService
	cache          *cache.RedisCache
	logger         *logger.Logger

	// Configuration
	config ScannerConfig

	// Rate limiting
	rateLimiter *rateLimiter
}

// ScannerConfig holds scanner configuration
type ScannerConfig struct {
	MaxConcurrentScans    int           `json:"max_concurrent_scans"`
	BrokerScanTimeout     time.Duration `json:"broker_scan_timeout"`
	DarkWebScanTimeout    time.Duration `json:"dark_web_scan_timeout"`
	SocialMediaTimeout    time.Duration `json:"social_media_timeout"`
	EnableDarkWebScan     bool          `json:"enable_dark_web_scan"`
	EnableBrokerScan      bool          `json:"enable_broker_scan"`
	EnableSocialMediaScan bool          `json:"enable_social_media_scan"`
	EnableBreachScan      bool          `json:"enable_breach_scan"`
	CacheTTL              time.Duration `json:"cache_ttl"`
}

// DefaultScannerConfig returns default configuration
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		MaxConcurrentScans:    10,
		BrokerScanTimeout:     30 * time.Second,
		DarkWebScanTimeout:    60 * time.Second,
		SocialMediaTimeout:    30 * time.Second,
		EnableDarkWebScan:     true,
		EnableBrokerScan:      true,
		EnableSocialMediaScan: true,
		EnableBreachScan:      true,
		CacheTTL:              24 * time.Hour,
	}
}

// NewScanner creates a new digital footprint scanner
func NewScanner(
	redisCache *cache.RedisCache,
	log *logger.Logger,
	config ScannerConfig,
) *Scanner {
	brokerDB := brokers.NewBrokerDatabase()

	s := &Scanner{
		brokerDB:    brokerDB,
		cache:       redisCache,
		logger:      log.WithComponent("digital-footprint-scanner"),
		config:      config,
		rateLimiter: newRateLimiter(config.MaxConcurrentScans),
	}

	// Initialize sub-scanners
	s.darkWebScanner = NewDarkWebScanner(redisCache, log)
	s.brokerScanner = NewBrokerScanner(brokerDB, redisCache, log)
	s.socialScanner = NewSocialMediaScanner(redisCache, log)
	s.removalService = NewRemovalService(brokerDB, log)

	return s
}

// ScanFootprint performs a comprehensive digital footprint scan
func (s *Scanner) ScanFootprint(ctx context.Context, req models.FootprintScanRequest) (*models.DigitalFootprint, error) {
	scanID := uuid.New()
	startTime := time.Now()

	s.logger.Info().
		Str("scan_id", scanID.String()).
		Str("user_id", req.UserID.String()).
		Str("scan_type", req.ScanType).
		Msg("starting digital footprint scan")

	// Create footprint result
	footprint := &models.DigitalFootprint{
		ID:          scanID,
		UserID:      req.UserID,
		ScanType:    req.ScanType,
		Status:      "running",
		StartedAt:   startTime,
		SearchEmail: req.Email,
		SearchPhone: req.Phone,
		SearchName:  req.FullName,
	}

	// Run scans concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	errCh := make(chan error, 4)

	// Dark web scan
	if s.config.EnableDarkWebScan && req.IncludeDarkWeb {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.rateLimiter.acquire()
			defer s.rateLimiter.release()

			scanCtx, cancel := context.WithTimeout(ctx, s.config.DarkWebScanTimeout)
			defer cancel()

			breaches, exposures, err := s.darkWebScanner.Scan(scanCtx, req.Email, req.Phone)
			if err != nil {
				s.logger.Error().Err(err).Msg("dark web scan failed")
				errCh <- err
				return
			}

			mu.Lock()
			footprint.BreachFindings = append(footprint.BreachFindings, breaches...)
			footprint.Exposures = append(footprint.Exposures, exposures...)
			footprint.BreachesFound = len(breaches)
			footprint.DarkWebExposures = len(exposures)
			mu.Unlock()
		}()
	}

	// Data broker scan
	if s.config.EnableBrokerScan && req.IncludeDataBrokers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.rateLimiter.acquire()
			defer s.rateLimiter.release()

			scanCtx, cancel := context.WithTimeout(ctx, s.config.BrokerScanTimeout*time.Duration(10)) // 10 brokers at a time
			defer cancel()

			findings, exposures, err := s.brokerScanner.Scan(scanCtx, BrokerScanRequest{
				Email:     req.Email,
				Phone:     req.Phone,
				FirstName: req.FirstName,
				LastName:  req.LastName,
				FullName:  req.FullName,
				Addresses: req.Addresses,
			})
			if err != nil {
				s.logger.Error().Err(err).Msg("broker scan failed")
				errCh <- err
				return
			}

			mu.Lock()
			footprint.BrokerFindings = append(footprint.BrokerFindings, findings...)
			footprint.Exposures = append(footprint.Exposures, exposures...)
			footprint.DataBrokersFound = len(findings)
			mu.Unlock()
		}()
	}

	// Social media scan
	if s.config.EnableSocialMediaScan && req.IncludeSocialMedia {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.rateLimiter.acquire()
			defer s.rateLimiter.release()

			scanCtx, cancel := context.WithTimeout(ctx, s.config.SocialMediaTimeout)
			defer cancel()

			findings, err := s.socialScanner.Scan(scanCtx, SocialScanRequest{
				Email:    req.Email,
				FullName: req.FullName,
				Profiles: req.SocialProfiles,
			})
			if err != nil {
				s.logger.Error().Err(err).Msg("social media scan failed")
				errCh <- err
				return
			}

			mu.Lock()
			footprint.SocialMediaFindings = append(footprint.SocialMediaFindings, findings...)
			footprint.SocialMediaRisks = len(findings)
			mu.Unlock()
		}()
	}

	// Wait for all scans to complete
	wg.Wait()
	close(errCh)

	// Process exposures and calculate severity counts
	s.processExposures(footprint)

	// Calculate risk score
	footprint.CalculateRiskScore()

	// Generate recommendations
	footprint.Recommendations = s.generateRecommendations(footprint)

	// Update status
	completedAt := time.Now()
	footprint.CompletedAt = &completedAt
	footprint.Status = "completed"

	s.logger.Info().
		Str("scan_id", scanID.String()).
		Int("total_exposures", footprint.TotalExposures).
		Int("brokers_found", footprint.DataBrokersFound).
		Float64("risk_score", footprint.RiskScore).
		Dur("duration", time.Since(startTime)).
		Msg("digital footprint scan completed")

	return footprint, nil
}

// processExposures categorizes exposures by severity
func (s *Scanner) processExposures(footprint *models.DigitalFootprint) {
	for _, exp := range footprint.Exposures {
		footprint.TotalExposures++
		switch exp.Severity {
		case models.ExposureSeverityCritical:
			footprint.CriticalExposures++
		case models.ExposureSeverityHigh:
			footprint.HighExposures++
		case models.ExposureSeverityMedium:
			footprint.MediumExposures++
		case models.ExposureSeverityLow:
			footprint.LowExposures++
		}
	}
}

// generateRecommendations generates actionable recommendations
func (s *Scanner) generateRecommendations(footprint *models.DigitalFootprint) []models.FootprintRecommendation {
	var recommendations []models.FootprintRecommendation
	priority := 1

	// Critical: Password/SSN exposures
	for _, exp := range footprint.Exposures {
		if exp.Type == models.ExposureTypePassword {
			recommendations = append(recommendations, models.FootprintRecommendation{
				Priority:    priority,
				Category:    "breach",
				Title:       "Password Exposed in Data Breach",
				Description: "Your password was found in a data breach. Change this password immediately on all sites where you use it.",
				Action:      "Change password on affected accounts",
				Impact:      "high",
				Effort:      "easy",
				CanAutomate: false,
			})
			priority++
			break // Only one recommendation per type
		}
	}

	for _, exp := range footprint.Exposures {
		if exp.Type == models.ExposureTypeSSN {
			recommendations = append(recommendations, models.FootprintRecommendation{
				Priority:    priority,
				Category:    "breach",
				Title:       "Social Security Number Exposed",
				Description: "Your SSN was found exposed. Consider placing a credit freeze with all three bureaus.",
				Action:      "Place credit freeze with Equifax, Experian, and TransUnion",
				Impact:      "high",
				Effort:      "medium",
				CanAutomate: false,
			})
			priority++
			break
		}
	}

	// High priority: Remove from data brokers
	if footprint.DataBrokersFound > 0 {
		autoRemovable := 0
		for _, bf := range footprint.BrokerFindings {
			if bf.CanAutoRemove {
				autoRemovable++
			}
		}

		recommendations = append(recommendations, models.FootprintRecommendation{
			Priority:    priority,
			Category:    "data_broker",
			Title:       "Remove Data from Brokers",
			Description: "Your personal information was found on " + string(rune(footprint.DataBrokersFound)) + " data broker sites.",
			Action:      "Request data removal from each broker",
			Impact:      "high",
			Effort:      "medium",
			CanAutomate: autoRemovable > 0,
		})
		priority++
	}

	// Medium priority: Social media privacy
	if footprint.SocialMediaRisks > 0 {
		recommendations = append(recommendations, models.FootprintRecommendation{
			Priority:    priority,
			Category:    "social_media",
			Title:       "Improve Social Media Privacy",
			Description: "Privacy issues were found on your social media profiles.",
			Action:      "Review and update privacy settings on each platform",
			Impact:      "medium",
			Effort:      "easy",
			CanAutomate: false,
		})
		priority++
	}

	// General recommendations based on risk level
	if footprint.RiskLevel == "critical" || footprint.RiskLevel == "high" {
		recommendations = append(recommendations, models.FootprintRecommendation{
			Priority:    priority,
			Category:    "general",
			Title:       "Enable Two-Factor Authentication",
			Description: "Protect your accounts with 2FA to prevent unauthorized access.",
			Action:      "Enable 2FA on all important accounts",
			Impact:      "high",
			Effort:      "easy",
			CanAutomate: false,
		})
		priority++

		recommendations = append(recommendations, models.FootprintRecommendation{
			Priority:    priority,
			Category:    "general",
			Title:       "Use a Password Manager",
			Description: "Generate and store unique passwords for each account.",
			Action:      "Set up a password manager like 1Password or Bitwarden",
			Impact:      "high",
			Effort:      "medium",
			CanAutomate: false,
		})
		priority++
	}

	// Dark web monitoring
	if footprint.DarkWebExposures > 0 {
		recommendations = append(recommendations, models.FootprintRecommendation{
			Priority:    priority,
			Category:    "breach",
			Title:       "Monitor for Future Breaches",
			Description: "Your data was found on the dark web. Set up breach monitoring.",
			Action:      "Enable OrbGuard breach alerts",
			Impact:      "medium",
			Effort:      "easy",
			CanAutomate: true,
		})
		priority++
	}

	return recommendations
}

// QuickScan performs a fast scan checking only cached/fast sources
func (s *Scanner) QuickScan(ctx context.Context, email string) (*models.DigitalFootprint, error) {
	return s.ScanFootprint(ctx, models.FootprintScanRequest{
		UserID:             uuid.New(),
		ScanType:           "quick",
		Email:              email,
		IncludeDarkWeb:     true,
		IncludeDataBrokers: false, // Skip slow broker checks
		IncludeSocialMedia: false,
		IncludeBreaches:    true,
	})
}

// GetBrokerCount returns total number of tracked brokers
func (s *Scanner) GetBrokerCount() int {
	return s.brokerDB.Count()
}

// GetAllBrokers returns all tracked brokers
func (s *Scanner) GetAllBrokers() []*models.DataBroker {
	return s.brokerDB.GetAllBrokers()
}

// GetBrokersByCategory returns brokers by category
func (s *Scanner) GetBrokersByCategory(category models.DataBrokerCategory) []*models.DataBroker {
	return s.brokerDB.GetBrokersByCategory(category)
}

// RequestRemoval initiates a data removal request
func (s *Scanner) RequestRemoval(ctx context.Context, userID, brokerID uuid.UUID, email string) (*models.RemovalRequest, error) {
	return s.removalService.CreateRequest(ctx, userID, brokerID, email)
}

// RequestBatchRemoval initiates removal from multiple brokers
func (s *Scanner) RequestBatchRemoval(ctx context.Context, userID uuid.UUID, brokerIDs []uuid.UUID, email string) (*models.BatchRemovalRequest, error) {
	return s.removalService.CreateBatchRequest(ctx, userID, brokerIDs, email)
}

// GetRemovalStatus gets the status of a removal request
func (s *Scanner) GetRemovalStatus(ctx context.Context, requestID uuid.UUID) (*models.RemovalRequest, error) {
	return s.removalService.GetStatus(ctx, requestID)
}

// GetStats returns scanner statistics
func (s *Scanner) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_brokers":       s.brokerDB.Count(),
		"automatable_brokers": len(s.brokerDB.GetAutomatable()),
		"categories": map[string]int{
			"people_search":   len(s.brokerDB.GetBrokersByCategory(models.BrokerPeopleSearch)),
			"marketing":       len(s.brokerDB.GetBrokersByCategory(models.BrokerMarketing)),
			"b2b_lead":        len(s.brokerDB.GetBrokersByCategory(models.BrokerB2BLead)),
			"background":      len(s.brokerDB.GetBrokersByCategory(models.BrokerBackground)),
			"financial":       len(s.brokerDB.GetBrokersByCategory(models.BrokerFinancial)),
			"location":        len(s.brokerDB.GetBrokersByCategory(models.BrokerLocation)),
			"social_media":    len(s.brokerDB.GetBrokersByCategory(models.BrokerSocialMedia)),
			"identity":        len(s.brokerDB.GetBrokersByCategory(models.BrokerIdentity)),
			"public_records":  len(s.brokerDB.GetBrokersByCategory(models.BrokerPublicRecords)),
		},
	}
}

// rateLimiter provides simple concurrency limiting
type rateLimiter struct {
	sem chan struct{}
}

func newRateLimiter(max int) *rateLimiter {
	return &rateLimiter{
		sem: make(chan struct{}, max),
	}
}

func (r *rateLimiter) acquire() {
	r.sem <- struct{}{}
}

func (r *rateLimiter) release() {
	<-r.sem
}
