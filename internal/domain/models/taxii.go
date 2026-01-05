package models

import (
	"time"
)

// TAXII 2.1 Specification Implementation
// Reference: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html

// TAXIIMediaType constants
const (
	TAXIIMediaType     = "application/taxii+json;version=2.1"
	STIXMediaType      = "application/stix+json;version=2.1"
)

// TAXIIDiscovery represents the TAXII 2.1 Discovery response
type TAXIIDiscovery struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Contact     string   `json:"contact,omitempty"`
	Default     string   `json:"default,omitempty"`
	APIRoots    []string `json:"api_roots,omitempty"`
}

// TAXIIAPIRoot represents a TAXII 2.1 API Root
type TAXIIAPIRoot struct {
	Title              string   `json:"title"`
	Description        string   `json:"description,omitempty"`
	Versions           []string `json:"versions"`
	MaxContentLength   int64    `json:"max_content_length"`
}

// TAXIICollection represents a TAXII 2.1 Collection
type TAXIICollection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Alias       string   `json:"alias,omitempty"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	MediaTypes  []string `json:"media_types,omitempty"`
}

// TAXIICollections represents a list of TAXII collections
type TAXIICollections struct {
	Collections []TAXIICollection `json:"collections,omitempty"`
}

// TAXIIEnvelope represents the TAXII 2.1 envelope for STIX objects
type TAXIIEnvelope struct {
	More    bool          `json:"more,omitempty"`
	Next    string        `json:"next,omitempty"`
	Objects []interface{} `json:"objects,omitempty"`
}

// TAXIIManifest represents the TAXII 2.1 manifest
type TAXIIManifest struct {
	More    bool               `json:"more,omitempty"`
	Objects []TAXIIManifestEntry `json:"objects,omitempty"`
}

// TAXIIManifestEntry represents a single entry in the manifest
type TAXIIManifestEntry struct {
	ID           string    `json:"id"`
	DateAdded    time.Time `json:"date_added"`
	Version      string    `json:"version"`
	MediaTypes   []string  `json:"media_types,omitempty"`
}

// TAXIIStatus represents the status of an add objects request
type TAXIIStatus struct {
	ID               string              `json:"id"`
	Status           string              `json:"status"` // pending, complete
	RequestTimestamp *time.Time          `json:"request_timestamp,omitempty"`
	TotalCount       int                 `json:"total_count"`
	SuccessCount     int                 `json:"success_count"`
	FailureCount     int                 `json:"failure_count"`
	PendingCount     int                 `json:"pending_count"`
	Successes        []TAXIIStatusDetail `json:"successes,omitempty"`
	Failures         []TAXIIStatusDetail `json:"failures,omitempty"`
	Pendings         []TAXIIStatusDetail `json:"pendings,omitempty"`
}

// TAXIIStatusDetail represents details about a specific object's status
type TAXIIStatusDetail struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

// TAXIIError represents a TAXII 2.1 error response
type TAXIIError struct {
	Title           string            `json:"title"`
	Description     string            `json:"description,omitempty"`
	ErrorID         string            `json:"error_id,omitempty"`
	ErrorCode       string            `json:"error_code,omitempty"`
	HTTPStatus      int               `json:"http_status,omitempty"`
	ExternalDetails string            `json:"external_details,omitempty"`
	Details         map[string]string `json:"details,omitempty"`
}

// TAXIIVersions represents supported TAXII versions
type TAXIIVersions struct {
	Versions []string `json:"versions"`
}

// TAXIIObjectFilters represents filters for querying objects
type TAXIIObjectFilters struct {
	AddedAfter  *time.Time `json:"added_after,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Next        string     `json:"next,omitempty"`
	Match       map[string][]string `json:"match,omitempty"` // type, id, spec_version, version
}

// TAXIICollectionConfig represents configuration for a TAXII collection
type TAXIICollectionConfig struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Alias           string    `json:"alias"`
	CanRead         bool      `json:"can_read"`
	CanWrite        bool      `json:"can_write"`
	MediaTypes      []string  `json:"media_types"`
	// Internal fields
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ObjectCount     int64     `json:"object_count"`
	LastObjectAdded *time.Time `json:"last_object_added,omitempty"`
}

// TAXIIServerConfig represents configuration for the TAXII server
type TAXIIServerConfig struct {
	Title            string `json:"title"`
	Description      string `json:"description"`
	Contact          string `json:"contact"`
	MaxContentLength int64  `json:"max_content_length"`
	// Authentication
	RequireAuth      bool   `json:"require_auth"`
	// Rate limiting
	RateLimitPerMin  int    `json:"rate_limit_per_min"`
}

// Default TAXII server configuration
var DefaultTAXIIServerConfig = TAXIIServerConfig{
	Title:            "OrbGuard Threat Intelligence",
	Description:      "TAXII 2.1 server providing mobile threat intelligence",
	Contact:          "security@orbguard.io",
	MaxContentLength: 10485760, // 10MB
	RequireAuth:      true,
	RateLimitPerMin:  60,
}

// Default collections for OrbGuard
var DefaultTAXIICollections = []TAXIICollectionConfig{
	{
		ID:          "collection--mobile-threats",
		Title:       "Mobile Threats",
		Description: "Indicators related to mobile malware, spyware, and stalkerware",
		Alias:       "mobile-threats",
		CanRead:     true,
		CanWrite:    false,
		MediaTypes:  []string{STIXMediaType},
	},
	{
		ID:          "collection--pegasus",
		Title:       "Pegasus & State-Sponsored Spyware",
		Description: "Indicators related to Pegasus and other state-sponsored mobile spyware",
		Alias:       "pegasus",
		CanRead:     true,
		CanWrite:    false,
		MediaTypes:  []string{STIXMediaType},
	},
	{
		ID:          "collection--phishing",
		Title:       "Phishing & Smishing",
		Description: "Indicators related to phishing URLs, smishing campaigns, and social engineering",
		Alias:       "phishing",
		CanRead:     true,
		CanWrite:    false,
		MediaTypes:  []string{STIXMediaType},
	},
	{
		ID:          "collection--malware",
		Title:       "Mobile Malware",
		Description: "Indicators related to Android and iOS malware",
		Alias:       "malware",
		CanRead:     true,
		CanWrite:    false,
		MediaTypes:  []string{STIXMediaType},
	},
	{
		ID:          "collection--community",
		Title:       "Community Reported",
		Description: "Threat indicators reported by the OrbGuard community",
		Alias:       "community",
		CanRead:     true,
		CanWrite:    true,
		MediaTypes:  []string{STIXMediaType},
	},
}

// TAXII HTTP Headers
const (
	HeaderAccept       = "Accept"
	HeaderContentType  = "Content-Type"
	HeaderXTAXIIDateAdded = "X-TAXII-Date-Added-First"
	HeaderXTAXIIDateAddedLast = "X-TAXII-Date-Added-Last"
)

// TAXII Error Codes
const (
	TAXIIErrorBadRequest          = "bad-request"
	TAXIIErrorUnauthorized        = "unauthorized"
	TAXIIErrorForbidden           = "forbidden"
	TAXIIErrorNotFound            = "not-found"
	TAXIIErrorNotAcceptable       = "not-acceptable"
	TAXIIErrorUnsupportedMedia    = "unsupported-media-type"
	TAXIIErrorTooLarge            = "request-too-large"
	TAXIIErrorTooManyRequests     = "too-many-requests"
	TAXIIErrorInternalError       = "internal-error"
)

// NewTAXIIError creates a new TAXII error
func NewTAXIIError(title, description, errorCode string, httpStatus int) *TAXIIError {
	return &TAXIIError{
		Title:       title,
		Description: description,
		ErrorCode:   errorCode,
		HTTPStatus:  httpStatus,
	}
}

// Common TAXII errors
var (
	ErrTAXIIBadRequest = NewTAXIIError(
		"Bad Request",
		"The request was malformed or invalid",
		TAXIIErrorBadRequest,
		400,
	)
	ErrTAXIIUnauthorized = NewTAXIIError(
		"Unauthorized",
		"Authentication is required",
		TAXIIErrorUnauthorized,
		401,
	)
	ErrTAXIIForbidden = NewTAXIIError(
		"Forbidden",
		"You do not have permission to access this resource",
		TAXIIErrorForbidden,
		403,
	)
	ErrTAXIINotFound = NewTAXIIError(
		"Not Found",
		"The requested resource was not found",
		TAXIIErrorNotFound,
		404,
	)
	ErrTAXIINotAcceptable = NewTAXIIError(
		"Not Acceptable",
		"The requested media type is not supported",
		TAXIIErrorNotAcceptable,
		406,
	)
	ErrTAXIITooLarge = NewTAXIIError(
		"Request Too Large",
		"The request body exceeds the maximum allowed size",
		TAXIIErrorTooLarge,
		413,
	)
)
