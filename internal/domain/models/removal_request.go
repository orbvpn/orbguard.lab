package models

import (
	"time"

	"github.com/google/uuid"
)

// RemovalStatus represents the status of a data removal request
type RemovalStatus string

const (
	RemovalStatusPending     RemovalStatus = "pending"      // Not yet started
	RemovalStatusQueued      RemovalStatus = "queued"       // In queue to be processed
	RemovalStatusInProgress  RemovalStatus = "in_progress"  // Request submitted
	RemovalStatusVerifying   RemovalStatus = "verifying"    // Verifying removal
	RemovalStatusCompleted   RemovalStatus = "completed"    // Successfully removed
	RemovalStatusFailed      RemovalStatus = "failed"       // Request failed
	RemovalStatusRejected    RemovalStatus = "rejected"     // Broker rejected request
	RemovalStatusPartial     RemovalStatus = "partial"      // Partially removed
	RemovalStatusReappeared  RemovalStatus = "reappeared"   // Data reappeared after removal
)

// RemovalMethod represents how the removal was requested
type RemovalMethod string

const (
	RemovalMethodAutomated  RemovalMethod = "automated"   // Automated via API/scraping
	RemovalMethodManualWeb  RemovalMethod = "manual_web"  // Manual web form submission
	RemovalMethodEmail      RemovalMethod = "email"       // Email request
	RemovalMethodMail       RemovalMethod = "mail"        // Physical mail
	RemovalMethodCCPA       RemovalMethod = "ccpa"        // CCPA deletion request
	RemovalMethodGDPR       RemovalMethod = "gdpr"        // GDPR deletion request
	RemovalMethodPhone      RemovalMethod = "phone"       // Phone request
)

// RemovalRequest represents a request to remove data from a broker
type RemovalRequest struct {
	ID            uuid.UUID     `json:"id" db:"id"`
	UserID        uuid.UUID     `json:"user_id" db:"user_id"`
	FootprintID   *uuid.UUID    `json:"footprint_id,omitempty" db:"footprint_id"` // Associated scan
	BrokerID      uuid.UUID     `json:"broker_id" db:"broker_id"`
	ExposureID    *uuid.UUID    `json:"exposure_id,omitempty" db:"exposure_id"`

	// Broker info
	BrokerName    string        `json:"broker_name" db:"broker_name"`
	BrokerDomain  string        `json:"broker_domain" db:"broker_domain"`
	ProfileURL    string        `json:"profile_url,omitempty" db:"profile_url"`

	// Request details
	Status        RemovalStatus `json:"status" db:"status"`
	Method        RemovalMethod `json:"method" db:"method"`
	RequestType   string        `json:"request_type" db:"request_type"` // opt_out, deletion, ccpa, gdpr

	// User info used for request (encrypted)
	RequestEmail  string `json:"request_email" db:"request_email"`
	RequestName   string `json:"request_name,omitempty" db:"request_name"`

	// Tracking
	SubmittedAt   *time.Time `json:"submitted_at,omitempty" db:"submitted_at"`
	ConfirmedAt   *time.Time `json:"confirmed_at,omitempty" db:"confirmed_at"`  // Broker confirmed receipt
	CompletedAt   *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	ExpectedDate  *time.Time `json:"expected_date,omitempty" db:"expected_date"` // Expected completion

	// Response from broker
	ConfirmationID    string `json:"confirmation_id,omitempty" db:"confirmation_id"`
	ResponseMessage   string `json:"response_message,omitempty" db:"response_message"`

	// Verification
	VerifiedAt        *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	VerificationResult string    `json:"verification_result,omitempty" db:"verification_result"`

	// Re-check
	RecheckAt         *time.Time `json:"recheck_at,omitempty" db:"recheck_at"`
	RecheckCount      int        `json:"recheck_count" db:"recheck_count"`
	LastRecheckAt     *time.Time `json:"last_recheck_at,omitempty" db:"last_recheck_at"`

	// Retry handling
	RetryCount        int        `json:"retry_count" db:"retry_count"`
	LastRetryAt       *time.Time `json:"last_retry_at,omitempty" db:"last_retry_at"`
	FailureReason     string     `json:"failure_reason,omitempty" db:"failure_reason"`

	// Audit
	Notes             string     `json:"notes,omitempty" db:"notes"`
	Metadata          []byte     `json:"-" db:"metadata"` // Additional data as JSON

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// RemovalRequestEvent represents an event in the removal request lifecycle
type RemovalRequestEvent struct {
	ID            uuid.UUID `json:"id" db:"id"`
	RequestID     uuid.UUID `json:"request_id" db:"request_id"`
	EventType     string    `json:"event_type" db:"event_type"` // created, submitted, confirmed, etc.
	OldStatus     RemovalStatus `json:"old_status,omitempty" db:"old_status"`
	NewStatus     RemovalStatus `json:"new_status" db:"new_status"`
	Description   string    `json:"description,omitempty" db:"description"`
	Metadata      []byte    `json:"-" db:"metadata"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// BatchRemovalRequest represents a request to remove from multiple brokers
type BatchRemovalRequest struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	UserID        uuid.UUID       `json:"user_id" db:"user_id"`
	FootprintID   *uuid.UUID      `json:"footprint_id,omitempty" db:"footprint_id"`

	// Request info
	TotalBrokers    int           `json:"total_brokers" db:"total_brokers"`
	Status          RemovalStatus `json:"status" db:"status"`

	// Progress
	Pending         int           `json:"pending" db:"pending"`
	InProgress      int           `json:"in_progress" db:"in_progress"`
	Completed       int           `json:"completed" db:"completed"`
	Failed          int           `json:"failed" db:"failed"`

	// Individual requests
	Requests        []RemovalRequest `json:"requests,omitempty" db:"-"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// RemovalStats represents removal statistics for a user
type RemovalStats struct {
	TotalRequests      int     `json:"total_requests"`
	PendingRequests    int     `json:"pending_requests"`
	InProgressRequests int     `json:"in_progress_requests"`
	CompletedRequests  int     `json:"completed_requests"`
	FailedRequests     int     `json:"failed_requests"`
	SuccessRate        float64 `json:"success_rate"` // percentage
	AverageProcessDays float64 `json:"average_process_days"`
	DataPointsRemoved  int     `json:"data_points_removed"` // Estimated data points removed
	BrokersCleared     int     `json:"brokers_cleared"`     // Brokers fully cleared
	TimeSavedHours     float64 `json:"time_saved_hours"`    // Estimated manual time saved
}

// OptOutTemplate represents a template for opt-out requests
type OptOutTemplate struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	BrokerID    uuid.UUID     `json:"broker_id" db:"broker_id"`
	Method      RemovalMethod `json:"method" db:"method"`
	RequestType string        `json:"request_type" db:"request_type"` // ccpa, gdpr, opt_out

	// Template content
	Subject     string `json:"subject,omitempty" db:"subject"` // Email subject
	Body        string `json:"body" db:"body"`                  // Template body with placeholders
	Placeholders []string `json:"placeholders" db:"placeholders"` // {{name}}, {{email}}, etc.

	// Metadata
	Language    string    `json:"language" db:"language"` // en, es, de, etc.
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// CCPARequest represents a California Consumer Privacy Act request
type CCPARequest struct {
	RemovalRequest

	// CCPA specific
	RequestCategory   string `json:"request_category"` // delete, do_not_sell, know
	CaliforniaResident bool  `json:"california_resident"`
	VerificationMethod string `json:"verification_method"` // How identity was verified
}

// GDPRRequest represents a General Data Protection Regulation request
type GDPRRequest struct {
	RemovalRequest

	// GDPR specific
	RequestType     string `json:"gdpr_request_type"` // erasure, access, portability, rectification
	LegalBasis      string `json:"legal_basis"`       // Article being invoked
	EUResident      bool   `json:"eu_resident"`
	Country         string `json:"country"`
	ControllerName  string `json:"controller_name,omitempty"`
	SupervisoryAuth string `json:"supervisory_authority,omitempty"` // If escalating
}

// NewRemovalRequest creates a new removal request
func NewRemovalRequest(userID, brokerID uuid.UUID, brokerName, email string, method RemovalMethod) *RemovalRequest {
	now := time.Now()
	return &RemovalRequest{
		ID:           uuid.New(),
		UserID:       userID,
		BrokerID:     brokerID,
		BrokerName:   brokerName,
		Status:       RemovalStatusPending,
		Method:       method,
		RequestType:  "opt_out",
		RequestEmail: email,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsPending returns true if the request is in a pending state
func (r *RemovalRequest) IsPending() bool {
	return r.Status == RemovalStatusPending || r.Status == RemovalStatusQueued
}

// IsActive returns true if the request is actively being processed
func (r *RemovalRequest) IsActive() bool {
	return r.Status == RemovalStatusInProgress || r.Status == RemovalStatusVerifying
}

// IsComplete returns true if the request has finished (success or failure)
func (r *RemovalRequest) IsComplete() bool {
	return r.Status == RemovalStatusCompleted ||
	       r.Status == RemovalStatusFailed ||
	       r.Status == RemovalStatusRejected
}

// CanRetry returns true if the request can be retried
func (r *RemovalRequest) CanRetry() bool {
	return (r.Status == RemovalStatusFailed || r.Status == RemovalStatusRejected) &&
	       r.RetryCount < 3
}

// DaysUntilExpected returns days until expected completion
func (r *RemovalRequest) DaysUntilExpected() int {
	if r.ExpectedDate == nil {
		return -1
	}
	return int(time.Until(*r.ExpectedDate).Hours() / 24)
}

// UpdateProgress updates batch removal progress
func (b *BatchRemovalRequest) UpdateProgress() {
	b.Pending = 0
	b.InProgress = 0
	b.Completed = 0
	b.Failed = 0

	for _, r := range b.Requests {
		switch r.Status {
		case RemovalStatusPending, RemovalStatusQueued:
			b.Pending++
		case RemovalStatusInProgress, RemovalStatusVerifying:
			b.InProgress++
		case RemovalStatusCompleted:
			b.Completed++
		case RemovalStatusFailed, RemovalStatusRejected:
			b.Failed++
		}
	}

	// Update overall status
	if b.Pending == b.TotalBrokers {
		b.Status = RemovalStatusPending
	} else if b.Completed == b.TotalBrokers {
		b.Status = RemovalStatusCompleted
	} else if b.Failed == b.TotalBrokers {
		b.Status = RemovalStatusFailed
	} else if b.Completed > 0 && b.Failed > 0 && b.Pending == 0 && b.InProgress == 0 {
		b.Status = RemovalStatusPartial
	} else {
		b.Status = RemovalStatusInProgress
	}
}
