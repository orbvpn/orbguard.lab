package digital_footprint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/brokers"
	"orbguard-lab/pkg/logger"
)

// RemovalService handles data removal requests
type RemovalService struct {
	brokerDB   *brokers.BrokerDatabase
	httpClient *http.Client
	logger     *logger.Logger

	// Templates for opt-out requests
	templates map[string]*template.Template
}

// NewRemovalService creates a new removal service
func NewRemovalService(brokerDB *brokers.BrokerDatabase, log *logger.Logger) *RemovalService {
	svc := &RemovalService{
		brokerDB: brokerDB,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger:    log.WithComponent("removal-service"),
		templates: make(map[string]*template.Template),
	}

	svc.loadTemplates()
	return svc
}

// CreateRequest creates a new removal request
func (s *RemovalService) CreateRequest(ctx context.Context, userID, brokerID uuid.UUID, email string) (*models.RemovalRequest, error) {
	broker := s.brokerDB.GetBroker(brokerID)
	if broker == nil {
		return nil, fmt.Errorf("broker not found: %s", brokerID)
	}

	// Determine removal method
	method := s.getRemovalMethod(broker)

	// Calculate expected completion date
	expectedDate := time.Now().AddDate(0, 0, broker.ProcessingDays)

	request := &models.RemovalRequest{
		ID:           uuid.New(),
		UserID:       userID,
		BrokerID:     brokerID,
		BrokerName:   broker.Name,
		BrokerDomain: broker.Domain,
		Status:       models.RemovalStatusPending,
		Method:       method,
		RequestType:  "opt_out",
		RequestEmail: email,
		ExpectedDate: &expectedDate,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	s.logger.Info().
		Str("request_id", request.ID.String()).
		Str("broker", broker.Name).
		Str("method", string(method)).
		Msg("created removal request")

	return request, nil
}

// CreateBatchRequest creates removal requests for multiple brokers
func (s *RemovalService) CreateBatchRequest(ctx context.Context, userID uuid.UUID, brokerIDs []uuid.UUID, email string) (*models.BatchRemovalRequest, error) {
	batch := &models.BatchRemovalRequest{
		ID:           uuid.New(),
		UserID:       userID,
		TotalBrokers: len(brokerIDs),
		Status:       models.RemovalStatusPending,
		Pending:      len(brokerIDs),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	for _, brokerID := range brokerIDs {
		request, err := s.CreateRequest(ctx, userID, brokerID, email)
		if err != nil {
			s.logger.Warn().Err(err).Str("broker_id", brokerID.String()).Msg("failed to create request")
			continue
		}
		batch.Requests = append(batch.Requests, *request)
	}

	return batch, nil
}

// ProcessRequest processes a removal request
func (s *RemovalService) ProcessRequest(ctx context.Context, request *models.RemovalRequest) error {
	broker := s.brokerDB.GetBroker(request.BrokerID)
	if broker == nil {
		return fmt.Errorf("broker not found: %s", request.BrokerID)
	}

	// Update status to in progress
	request.Status = models.RemovalStatusInProgress
	now := time.Now()
	request.SubmittedAt = &now
	request.UpdatedAt = now

	var err error

	switch request.Method {
	case models.RemovalMethodAutomated:
		err = s.processAutomatedRemoval(ctx, request, broker)
	case models.RemovalMethodCCPA:
		err = s.processCCPARequest(ctx, request, broker)
	case models.RemovalMethodGDPR:
		err = s.processGDPRRequest(ctx, request, broker)
	case models.RemovalMethodEmail:
		err = s.processEmailRemoval(ctx, request, broker)
	default:
		// Manual removal - just mark as submitted
		request.Notes = "Manual removal required. Please visit the opt-out URL."
	}

	if err != nil {
		request.Status = models.RemovalStatusFailed
		request.FailureReason = err.Error()
		request.RetryCount++
		request.LastRetryAt = &now
		s.logger.Error().Err(err).Str("broker", broker.Name).Msg("removal request failed")
	}

	request.UpdatedAt = time.Now()
	return err
}

// GetStatus returns the status of a removal request
func (s *RemovalService) GetStatus(ctx context.Context, requestID uuid.UUID) (*models.RemovalRequest, error) {
	// In a real implementation, this would fetch from database
	return nil, fmt.Errorf("not implemented - would fetch from database")
}

// getRemovalMethod determines the best removal method for a broker
func (s *RemovalService) getRemovalMethod(broker *models.DataBroker) models.RemovalMethod {
	if broker.CanAutomate {
		return models.RemovalMethodAutomated
	}

	if broker.CCPACompliant {
		return models.RemovalMethodCCPA
	}

	if broker.GDPRCompliant {
		return models.RemovalMethodGDPR
	}

	switch broker.OptOutMethod {
	case models.OptOutMethodWebForm:
		return models.RemovalMethodManualWeb
	case models.OptOutMethodEmail:
		return models.RemovalMethodEmail
	case models.OptOutMethodMail:
		return models.RemovalMethodMail
	default:
		return models.RemovalMethodManualWeb
	}
}

// processAutomatedRemoval handles automated opt-out submission
func (s *RemovalService) processAutomatedRemoval(ctx context.Context, request *models.RemovalRequest, broker *models.DataBroker) error {
	if broker.OptOutURL == "" {
		return fmt.Errorf("no opt-out URL available")
	}

	// Prepare form data based on broker
	formData := s.prepareFormData(request, broker)

	// Submit opt-out form
	resp, err := s.submitOptOutForm(ctx, broker.OptOutURL, formData)
	if err != nil {
		return fmt.Errorf("failed to submit opt-out form: %w", err)
	}

	// Check response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		request.Status = models.RemovalStatusInProgress
		request.ResponseMessage = "Opt-out request submitted successfully"

		// Set verification time
		verifyAt := time.Now().Add(time.Duration(broker.ProcessingDays) * 24 * time.Hour)
		request.RecheckAt = &verifyAt

		s.logger.Info().
			Str("broker", broker.Name).
			Int("status_code", resp.StatusCode).
			Msg("automated opt-out submitted")
	} else {
		return fmt.Errorf("opt-out submission returned status %d", resp.StatusCode)
	}

	return nil
}

// processCCPARequest generates and sends a CCPA deletion request
func (s *RemovalService) processCCPARequest(ctx context.Context, request *models.RemovalRequest, broker *models.DataBroker) error {
	// Generate CCPA request content
	content, err := s.generateCCPARequest(request, broker)
	if err != nil {
		return fmt.Errorf("failed to generate CCPA request: %w", err)
	}

	request.Notes = content
	request.RequestType = "ccpa"

	// If broker has email opt-out, we could send it automatically
	// For now, we'll just generate the content

	s.logger.Info().
		Str("broker", broker.Name).
		Msg("generated CCPA deletion request")

	return nil
}

// processGDPRRequest generates and sends a GDPR erasure request
func (s *RemovalService) processGDPRRequest(ctx context.Context, request *models.RemovalRequest, broker *models.DataBroker) error {
	// Generate GDPR request content
	content, err := s.generateGDPRRequest(request, broker)
	if err != nil {
		return fmt.Errorf("failed to generate GDPR request: %w", err)
	}

	request.Notes = content
	request.RequestType = "gdpr"

	s.logger.Info().
		Str("broker", broker.Name).
		Msg("generated GDPR erasure request")

	return nil
}

// processEmailRemoval generates an email opt-out request
func (s *RemovalService) processEmailRemoval(ctx context.Context, request *models.RemovalRequest, broker *models.DataBroker) error {
	// Generate email content
	content, err := s.generateEmailRequest(request, broker)
	if err != nil {
		return fmt.Errorf("failed to generate email request: %w", err)
	}

	request.Notes = content

	s.logger.Info().
		Str("broker", broker.Name).
		Msg("generated email opt-out request")

	return nil
}

// prepareFormData prepares form data for opt-out submission
func (s *RemovalService) prepareFormData(request *models.RemovalRequest, broker *models.DataBroker) url.Values {
	data := url.Values{}

	// Common fields
	data.Set("email", request.RequestEmail)
	if request.RequestName != "" {
		data.Set("name", request.RequestName)
		// Try to split name
		parts := strings.Fields(request.RequestName)
		if len(parts) >= 2 {
			data.Set("first_name", parts[0])
			data.Set("last_name", parts[len(parts)-1])
		}
	}

	// Broker-specific fields
	switch broker.Domain {
	case "spokeo.com":
		data.Set("url", request.ProfileURL)
		data.Set("reason", "personal")
	case "beenverified.com":
		data.Set("reason", "privacy")
	case "whitepages.com":
		data.Set("suppress", "true")
	default:
		data.Set("opt_out", "true")
		data.Set("remove", "true")
	}

	return data
}

// submitOptOutForm submits an opt-out form
func (s *RemovalService) submitOptOutForm(ctx context.Context, optOutURL string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", optOutURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	return s.httpClient.Do(req)
}

// loadTemplates loads email/request templates
func (s *RemovalService) loadTemplates() {
	// CCPA template
	ccpaTemplate := `Subject: California Consumer Privacy Act - Request to Delete Personal Information

Dear {{ .BrokerName }} Privacy Team,

I am writing to exercise my rights under the California Consumer Privacy Act (CCPA), Cal. Civ. Code § 1798.100 et seq.

I am a California resident and I am requesting that you delete all personal information you have collected about me.

My identifying information:
- Email: {{ .Email }}
{{ if .Name }}- Name: {{ .Name }}{{ end }}

Under the CCPA, you are required to:
1. Delete my personal information from your records
2. Direct any service providers to delete my personal information
3. Confirm deletion within 45 days

Please confirm receipt of this request and notify me when the deletion is complete.

Thank you for your prompt attention to this matter.

Sincerely,
{{ .Name }}
`

	// GDPR template
	gdprTemplate := `Subject: GDPR Article 17 - Right to Erasure Request

Dear {{ .BrokerName }} Data Protection Officer,

I am writing to exercise my rights under the General Data Protection Regulation (GDPR), specifically Article 17 (Right to Erasure / Right to be Forgotten).

I hereby request that you erase all personal data you hold about me.

My identifying information:
- Email: {{ .Email }}
{{ if .Name }}- Name: {{ .Name }}{{ end }}

Under GDPR Article 17, you are required to erase my personal data without undue delay where:
- The personal data is no longer necessary for the purpose it was collected
- I withdraw my consent for processing
- The data has been unlawfully processed

Please confirm:
1. Receipt of this request
2. The categories of data you hold about me
3. Completion of erasure within 30 days

Failure to comply may result in a complaint to the relevant supervisory authority.

Yours faithfully,
{{ .Name }}
`

	// Generic opt-out template
	optOutTemplate := `Subject: Data Removal / Opt-Out Request

Dear {{ .BrokerName }},

I am requesting that you remove my personal information from your database and stop sharing/selling my data.

My identifying information:
- Email: {{ .Email }}
{{ if .Name }}- Name: {{ .Name }}{{ end }}
{{ if .ProfileURL }}- Profile URL: {{ .ProfileURL }}{{ end }}

Please confirm when my information has been removed from your systems.

Thank you,
{{ .Name }}
`

	s.templates["ccpa"], _ = template.New("ccpa").Parse(ccpaTemplate)
	s.templates["gdpr"], _ = template.New("gdpr").Parse(gdprTemplate)
	s.templates["opt_out"], _ = template.New("opt_out").Parse(optOutTemplate)
}

// generateCCPARequest generates a CCPA deletion request
func (s *RemovalService) generateCCPARequest(request *models.RemovalRequest, broker *models.DataBroker) (string, error) {
	tmpl := s.templates["ccpa"]
	if tmpl == nil {
		return "", fmt.Errorf("CCPA template not found")
	}

	data := map[string]string{
		"BrokerName": broker.Name,
		"Email":      request.RequestEmail,
		"Name":       request.RequestName,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// generateGDPRRequest generates a GDPR erasure request
func (s *RemovalService) generateGDPRRequest(request *models.RemovalRequest, broker *models.DataBroker) (string, error) {
	tmpl := s.templates["gdpr"]
	if tmpl == nil {
		return "", fmt.Errorf("GDPR template not found")
	}

	data := map[string]string{
		"BrokerName": broker.Name,
		"Email":      request.RequestEmail,
		"Name":       request.RequestName,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// generateEmailRequest generates a generic opt-out email
func (s *RemovalService) generateEmailRequest(request *models.RemovalRequest, broker *models.DataBroker) (string, error) {
	tmpl := s.templates["opt_out"]
	if tmpl == nil {
		return "", fmt.Errorf("opt-out template not found")
	}

	data := map[string]string{
		"BrokerName": broker.Name,
		"Email":      request.RequestEmail,
		"Name":       request.RequestName,
		"ProfileURL": request.ProfileURL,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// VerifyRemoval verifies if data has been removed
func (s *RemovalService) VerifyRemoval(ctx context.Context, request *models.RemovalRequest) (bool, error) {
	broker := s.brokerDB.GetBroker(request.BrokerID)
	if broker == nil {
		return false, fmt.Errorf("broker not found")
	}

	// Attempt to search for the user's data again
	scanner := NewBrokerScanner(s.brokerDB, nil, s.logger)

	finding, _, err := scanner.ScanSingleBroker(ctx, request.BrokerID, BrokerScanRequest{
		Email: request.RequestEmail,
	})

	if err != nil {
		return false, err
	}

	// If no finding or not found, data has been removed
	removed := finding == nil || !finding.Found

	now := time.Now()
	request.VerifiedAt = &now
	request.RecheckCount++
	request.LastRecheckAt = &now

	if removed {
		request.Status = models.RemovalStatusCompleted
		request.VerificationResult = "Data successfully removed"
		completedAt := time.Now()
		request.CompletedAt = &completedAt
	} else {
		request.VerificationResult = "Data still present - recheck scheduled"
		// Schedule next recheck
		nextRecheck := time.Now().Add(7 * 24 * time.Hour)
		request.RecheckAt = &nextRecheck
	}

	return removed, nil
}

// GetRemovalStats returns removal statistics
func (s *RemovalService) GetRemovalStats(requests []models.RemovalRequest) models.RemovalStats {
	stats := models.RemovalStats{}

	var totalDays float64
	var completedCount int

	for _, r := range requests {
		stats.TotalRequests++

		switch r.Status {
		case models.RemovalStatusPending, models.RemovalStatusQueued:
			stats.PendingRequests++
		case models.RemovalStatusInProgress, models.RemovalStatusVerifying:
			stats.InProgressRequests++
		case models.RemovalStatusCompleted:
			stats.CompletedRequests++
			completedCount++
			if r.SubmittedAt != nil && r.CompletedAt != nil {
				totalDays += r.CompletedAt.Sub(*r.SubmittedAt).Hours() / 24
			}
		case models.RemovalStatusFailed, models.RemovalStatusRejected:
			stats.FailedRequests++
		}
	}

	if stats.TotalRequests > 0 {
		stats.SuccessRate = float64(stats.CompletedRequests) / float64(stats.TotalRequests) * 100
	}

	if completedCount > 0 {
		stats.AverageProcessDays = totalDays / float64(completedCount)
	}

	// Estimate time saved (average of 20 minutes per manual removal)
	stats.TimeSavedHours = float64(stats.CompletedRequests) * 20.0 / 60.0

	return stats
}

// GeneratePrivacyReport generates a privacy report
func (s *RemovalService) GeneratePrivacyReport(footprint *models.DigitalFootprint, requests []models.RemovalRequest) *PrivacyReport {
	report := &PrivacyReport{
		GeneratedAt:      time.Now(),
		FootprintSummary: s.generateFootprintSummary(footprint),
		RemovalStatus:    s.GetRemovalStats(requests),
		Recommendations:  footprint.Recommendations,
	}

	return report
}

// PrivacyReport represents a comprehensive privacy report
type PrivacyReport struct {
	GeneratedAt      time.Time                        `json:"generated_at"`
	FootprintSummary FootprintSummary                 `json:"footprint_summary"`
	RemovalStatus    models.RemovalStats              `json:"removal_status"`
	Recommendations  []models.FootprintRecommendation `json:"recommendations"`
}

// FootprintSummary summarizes the digital footprint
type FootprintSummary struct {
	RiskScore        float64 `json:"risk_score"`
	RiskLevel        string  `json:"risk_level"`
	TotalExposures   int     `json:"total_exposures"`
	DataBrokersFound int     `json:"data_brokers_found"`
	BreachesFound    int     `json:"breaches_found"`
	DarkWebExposures int     `json:"dark_web_exposures"`
	SocialMediaRisks int     `json:"social_media_risks"`
}

func (s *RemovalService) generateFootprintSummary(footprint *models.DigitalFootprint) FootprintSummary {
	return FootprintSummary{
		RiskScore:        footprint.RiskScore,
		RiskLevel:        footprint.RiskLevel,
		TotalExposures:   footprint.TotalExposures,
		DataBrokersFound: footprint.DataBrokersFound,
		BreachesFound:    footprint.BreachesFound,
		DarkWebExposures: footprint.DarkWebExposures,
		SocialMediaRisks: footprint.SocialMediaRisks,
	}
}

// ExportReport exports the privacy report as JSON
func (r *PrivacyReport) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
