package models

import (
	"time"

	"github.com/google/uuid"
)

// Playbook represents an automated response playbook
type Playbook struct {
	ID          uuid.UUID            `json:"id" db:"id"`
	Name        string               `json:"name" db:"name"`
	Description string               `json:"description" db:"description"`
	Enabled     bool                 `json:"enabled" db:"enabled"`
	Priority    int                  `json:"priority" db:"priority"` // Higher = runs first

	// Triggers define when the playbook runs
	Triggers    []PlaybookTrigger    `json:"triggers" db:"triggers"`

	// Conditions that must be met for the playbook to execute
	Conditions  []PlaybookCondition  `json:"conditions,omitempty" db:"conditions"`

	// Actions to execute when triggered
	Actions     []PlaybookAction     `json:"actions" db:"actions"`

	// Execution settings
	Settings    *PlaybookSettings    `json:"settings,omitempty" db:"settings"`

	// Statistics
	TotalExecutions   int64     `json:"total_executions" db:"total_executions"`
	SuccessExecutions int64     `json:"success_executions" db:"success_executions"`
	FailedExecutions  int64     `json:"failed_executions" db:"failed_executions"`
	LastExecutedAt    time.Time `json:"last_executed_at,omitempty" db:"last_executed_at"`
	LastError         string    `json:"last_error,omitempty" db:"last_error"`

	// Metadata
	Tags        []string             `json:"tags,omitempty" db:"tags"`
	CreatedBy   string               `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at" db:"updated_at"`
}

// PlaybookTrigger defines when a playbook should be triggered
type PlaybookTrigger struct {
	Type      TriggerType           `json:"type"`
	EventType string                `json:"event_type,omitempty"` // For event triggers
	Schedule  string                `json:"schedule,omitempty"`   // Cron expression for scheduled triggers
	Filters   *PlaybookTriggerFilters `json:"filters,omitempty"`
}

// TriggerType represents the type of trigger
type TriggerType string

const (
	TriggerTypeEvent     TriggerType = "event"      // Triggered by an event
	TriggerTypeScheduled TriggerType = "scheduled"  // Triggered on schedule
	TriggerTypeManual    TriggerType = "manual"     // Triggered manually
	TriggerTypeAPI       TriggerType = "api"        // Triggered via API call
	TriggerTypeWebhook   TriggerType = "webhook"    // Triggered by incoming webhook
)

// PlaybookTriggerFilters filters which events trigger the playbook
type PlaybookTriggerFilters struct {
	// Severity filters
	MinSeverity   string   `json:"min_severity,omitempty"`
	Severities    []string `json:"severities,omitempty"`

	// Type filters
	IndicatorTypes []string `json:"indicator_types,omitempty"`
	ThreatTypes    []string `json:"threat_types,omitempty"`

	// Platform filters
	Platforms     []string `json:"platforms,omitempty"`

	// Tag filters
	RequiredTags  []string `json:"required_tags,omitempty"`
	ExcludedTags  []string `json:"excluded_tags,omitempty"`

	// Source filters
	Sources       []string `json:"sources,omitempty"`

	// Campaign filters
	CampaignIDs   []string `json:"campaign_ids,omitempty"`

	// Confidence filter
	MinConfidence float64  `json:"min_confidence,omitempty"`

	// Custom filters
	CustomFilters map[string]interface{} `json:"custom_filters,omitempty"`
}

// PlaybookCondition defines a condition that must be met
type PlaybookCondition struct {
	Type     ConditionType          `json:"type"`
	Field    string                 `json:"field"`
	Operator ConditionOperator      `json:"operator"`
	Value    interface{}            `json:"value"`
	Negate   bool                   `json:"negate,omitempty"`
}

// ConditionType represents the type of condition
type ConditionType string

const (
	ConditionTypeField      ConditionType = "field"       // Compare a field value
	ConditionTypeTime       ConditionType = "time"        // Time-based condition
	ConditionTypeCount      ConditionType = "count"       // Count-based condition
	ConditionTypeExists     ConditionType = "exists"      // Check if value exists
	ConditionTypeExternal   ConditionType = "external"    // External service check
)

// ConditionOperator represents comparison operators
type ConditionOperator string

const (
	OperatorEquals         ConditionOperator = "eq"
	OperatorNotEquals      ConditionOperator = "neq"
	OperatorGreaterThan    ConditionOperator = "gt"
	OperatorGreaterOrEqual ConditionOperator = "gte"
	OperatorLessThan       ConditionOperator = "lt"
	OperatorLessOrEqual    ConditionOperator = "lte"
	OperatorContains       ConditionOperator = "contains"
	OperatorStartsWith     ConditionOperator = "starts_with"
	OperatorEndsWith       ConditionOperator = "ends_with"
	OperatorMatches        ConditionOperator = "matches"  // Regex
	OperatorIn             ConditionOperator = "in"       // In list
	OperatorNotIn          ConditionOperator = "not_in"
)

// PlaybookAction defines an action to take
type PlaybookAction struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        ActionType             `json:"type"`
	Config      map[string]interface{} `json:"config"`
	ContinueOnError bool               `json:"continue_on_error,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	RetryConfig *ActionRetryConfig     `json:"retry_config,omitempty"`
}

// ActionType represents the type of action
type ActionType string

const (
	// Notification actions
	ActionTypeSendWebhook      ActionType = "send_webhook"
	ActionTypeSendEmail        ActionType = "send_email"
	ActionTypeSendSlack        ActionType = "send_slack"
	ActionTypeSendTeams        ActionType = "send_teams"
	ActionTypeSendPagerDuty    ActionType = "send_pagerduty"
	ActionTypeSendSMS          ActionType = "send_sms"

	// Blocking actions
	ActionTypeBlockIP          ActionType = "block_ip"
	ActionTypeBlockDomain      ActionType = "block_domain"
	ActionTypeBlockHash        ActionType = "block_hash"
	ActionTypeBlockURL         ActionType = "block_url"
	ActionTypeQuarantineDevice ActionType = "quarantine_device"

	// Data actions
	ActionTypeEnrichIndicator  ActionType = "enrich_indicator"
	ActionTypeAddTag           ActionType = "add_tag"
	ActionTypeRemoveTag        ActionType = "remove_tag"
	ActionTypeUpdateSeverity   ActionType = "update_severity"
	ActionTypeCreateAlert      ActionType = "create_alert"
	ActionTypeCreateTicket     ActionType = "create_ticket"

	// Integration actions
	ActionTypeRunScript        ActionType = "run_script"
	ActionTypeCallAPI          ActionType = "call_api"
	ActionTypeTriggerPlaybook  ActionType = "trigger_playbook"

	// SIEM actions
	ActionTypeSendToSIEM       ActionType = "send_to_siem"
	ActionTypeSendToSOAR       ActionType = "send_to_soar"

	// Remediation actions
	ActionTypeIsolateEndpoint  ActionType = "isolate_endpoint"
	ActionTypeKillProcess      ActionType = "kill_process"
	ActionTypeDeleteFile       ActionType = "delete_file"
	ActionTypeResetPassword    ActionType = "reset_password"
	ActionTypeRevokeSession    ActionType = "revoke_session"
)

// ActionRetryConfig configures retry behavior for actions
type ActionRetryConfig struct {
	MaxRetries    int           `json:"max_retries"`
	RetryInterval time.Duration `json:"retry_interval"`
	BackoffFactor float64       `json:"backoff_factor"`
}

// PlaybookSettings contains execution settings
type PlaybookSettings struct {
	// Rate limiting
	MaxExecutionsPerHour  int  `json:"max_executions_per_hour,omitempty"`
	MaxExecutionsPerDay   int  `json:"max_executions_per_day,omitempty"`

	// Deduplication
	DeduplicationWindow   time.Duration `json:"deduplication_window,omitempty"`
	DeduplicationKey      string        `json:"deduplication_key,omitempty"`

	// Execution
	Parallel              bool          `json:"parallel,omitempty"`          // Run actions in parallel
	StopOnFirstFailure    bool          `json:"stop_on_first_failure,omitempty"`
	Timeout               time.Duration `json:"timeout,omitempty"`

	// Notifications
	NotifyOnSuccess       bool          `json:"notify_on_success,omitempty"`
	NotifyOnFailure       bool          `json:"notify_on_failure,omitempty"`
	NotificationChannel   string        `json:"notification_channel,omitempty"`
}

// PlaybookExecution represents a single execution of a playbook
type PlaybookExecution struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	PlaybookID    uuid.UUID              `json:"playbook_id" db:"playbook_id"`
	PlaybookName  string                 `json:"playbook_name" db:"playbook_name"`
	TriggerType   TriggerType            `json:"trigger_type" db:"trigger_type"`
	TriggerEvent  string                 `json:"trigger_event,omitempty" db:"trigger_event"`
	Status        ExecutionStatus        `json:"status" db:"status"`
	StartedAt     time.Time              `json:"started_at" db:"started_at"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
	Duration      time.Duration          `json:"duration,omitempty" db:"duration"`

	// Context data
	InputData     map[string]interface{} `json:"input_data,omitempty" db:"input_data"`
	OutputData    map[string]interface{} `json:"output_data,omitempty" db:"output_data"`

	// Action results
	ActionResults []ActionResult         `json:"action_results" db:"action_results"`

	// Error handling
	Error         string                 `json:"error,omitempty" db:"error"`
	ErrorAction   string                 `json:"error_action,omitempty" db:"error_action"`
}

// ExecutionStatus represents the status of a playbook execution
type ExecutionStatus string

const (
	ExecutionStatusPending    ExecutionStatus = "pending"
	ExecutionStatusRunning    ExecutionStatus = "running"
	ExecutionStatusSuccess    ExecutionStatus = "success"
	ExecutionStatusFailed     ExecutionStatus = "failed"
	ExecutionStatusCancelled  ExecutionStatus = "cancelled"
	ExecutionStatusSkipped    ExecutionStatus = "skipped"
	ExecutionStatusTimedOut   ExecutionStatus = "timed_out"
)

// ActionResult contains the result of a single action
type ActionResult struct {
	ActionID      string                 `json:"action_id"`
	ActionName    string                 `json:"action_name"`
	ActionType    ActionType             `json:"action_type"`
	Status        ExecutionStatus        `json:"status"`
	StartedAt     time.Time              `json:"started_at"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
	Duration      time.Duration          `json:"duration,omitempty"`
	Output        map[string]interface{} `json:"output,omitempty"`
	Error         string                 `json:"error,omitempty"`
	RetryCount    int                    `json:"retry_count,omitempty"`
}

// PlaybookStats contains playbook statistics
type PlaybookStats struct {
	TotalPlaybooks      int64              `json:"total_playbooks"`
	EnabledPlaybooks    int64              `json:"enabled_playbooks"`
	TotalExecutions     int64              `json:"total_executions"`
	SuccessRate         float64            `json:"success_rate"`
	AverageExecutionTime time.Duration     `json:"average_execution_time"`
	ExecutionsByStatus  map[string]int64   `json:"executions_by_status"`
	TopPlaybooks        []PlaybookSummary  `json:"top_playbooks"`
	Last24Hours         *PlaybookPeriodStats `json:"last_24_hours"`
}

// PlaybookSummary is a brief summary of a playbook
type PlaybookSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Executions  int64  `json:"executions"`
	SuccessRate float64 `json:"success_rate"`
}

// PlaybookPeriodStats contains stats for a specific period
type PlaybookPeriodStats struct {
	TotalExecutions   int64   `json:"total_executions"`
	SuccessExecutions int64   `json:"success_executions"`
	FailedExecutions  int64   `json:"failed_executions"`
	SuccessRate       float64 `json:"success_rate"`
}

// PlaybookTemplate represents a pre-built playbook template
type PlaybookTemplate struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Category    string               `json:"category"`
	Tags        []string             `json:"tags,omitempty"`
	Triggers    []PlaybookTrigger    `json:"triggers"`
	Conditions  []PlaybookCondition  `json:"conditions,omitempty"`
	Actions     []PlaybookAction     `json:"actions"`
	Settings    *PlaybookSettings    `json:"settings,omitempty"`
}

// DefaultPlaybookTemplates returns pre-built playbook templates
func DefaultPlaybookTemplates() []PlaybookTemplate {
	return []PlaybookTemplate{
		{
			ID:          "critical-threat-alert",
			Name:        "Critical Threat Alert",
			Description: "Send immediate alerts when critical threats are detected",
			Category:    "alerting",
			Tags:        []string{"critical", "alerting"},
			Triggers: []PlaybookTrigger{
				{
					Type:      TriggerTypeEvent,
					EventType: "threat.detected",
					Filters: &PlaybookTriggerFilters{
						MinSeverity: "critical",
					},
				},
			},
			Actions: []PlaybookAction{
				{
					ID:   "send-slack",
					Name: "Send Slack Alert",
					Type: ActionTypeSendSlack,
					Config: map[string]interface{}{
						"channel": "#security-alerts",
						"message": "🚨 Critical threat detected: {{.indicator_value}}",
					},
				},
				{
					ID:   "create-ticket",
					Name: "Create Incident Ticket",
					Type: ActionTypeCreateTicket,
					Config: map[string]interface{}{
						"priority": "critical",
						"assignee": "security-team",
					},
				},
			},
		},
		{
			ID:          "pegasus-detection",
			Name:        "Pegasus Detection Response",
			Description: "Automated response when Pegasus spyware indicators are detected",
			Category:    "response",
			Tags:        []string{"pegasus", "spyware", "mobile"},
			Triggers: []PlaybookTrigger{
				{
					Type:      TriggerTypeEvent,
					EventType: "threat.pegasus",
				},
			},
			Actions: []PlaybookAction{
				{
					ID:   "alert",
					Name: "Immediate Alert",
					Type: ActionTypeSendPagerDuty,
					Config: map[string]interface{}{
						"severity": "critical",
						"title":    "Pegasus Spyware Detected",
					},
				},
				{
					ID:   "quarantine",
					Name: "Quarantine Device",
					Type: ActionTypeQuarantineDevice,
					Config: map[string]interface{}{
						"isolate_network": true,
					},
				},
				{
					ID:   "enrich",
					Name: "Enrich Indicator",
					Type: ActionTypeEnrichIndicator,
					Config: map[string]interface{}{
						"sources": []string{"virustotal", "otx"},
					},
				},
			},
		},
		{
			ID:          "block-malicious-domain",
			Name:        "Block Malicious Domain",
			Description: "Automatically block domains marked as malicious",
			Category:    "blocking",
			Tags:        []string{"blocking", "domain"},
			Triggers: []PlaybookTrigger{
				{
					Type:      TriggerTypeEvent,
					EventType: "indicator.new",
					Filters: &PlaybookTriggerFilters{
						IndicatorTypes: []string{"domain"},
						MinConfidence:  0.9,
					},
				},
			},
			Actions: []PlaybookAction{
				{
					ID:   "block",
					Name: "Block Domain",
					Type: ActionTypeBlockDomain,
					Config: map[string]interface{}{
						"targets": []string{"firewall", "dns"},
					},
				},
				{
					ID:   "notify",
					Name: "Notify Team",
					Type: ActionTypeSendSlack,
					Config: map[string]interface{}{
						"channel": "#security-ops",
						"message": "Domain blocked: {{.indicator_value}}",
					},
				},
			},
		},
		{
			ID:          "phishing-response",
			Name:        "Phishing Campaign Response",
			Description: "Respond to detected phishing campaigns",
			Category:    "response",
			Tags:        []string{"phishing", "email"},
			Triggers: []PlaybookTrigger{
				{
					Type:      TriggerTypeEvent,
					EventType: "phishing.detected",
				},
			},
			Actions: []PlaybookAction{
				{
					ID:   "block-url",
					Name: "Block Phishing URL",
					Type: ActionTypeBlockURL,
					Config: map[string]interface{}{
						"targets": []string{"proxy", "firewall"},
					},
				},
				{
					ID:   "email-alert",
					Name: "Email Security Team",
					Type: ActionTypeSendEmail,
					Config: map[string]interface{}{
						"to":      "security@company.com",
						"subject": "Phishing Campaign Detected",
					},
				},
				{
					ID:   "tag",
					Name: "Add Phishing Tag",
					Type: ActionTypeAddTag,
					Config: map[string]interface{}{
						"tags": []string{"phishing", "active-campaign"},
					},
				},
			},
		},
		{
			ID:          "breach-notification",
			Name:        "Data Breach Notification",
			Description: "Notify when personal data is found in a breach",
			Category:    "alerting",
			Tags:        []string{"breach", "privacy"},
			Triggers: []PlaybookTrigger{
				{
					Type:      TriggerTypeEvent,
					EventType: "breach.detected",
				},
			},
			Actions: []PlaybookAction{
				{
					ID:   "notify-affected",
					Name: "Notify Affected User",
					Type: ActionTypeSendEmail,
					Config: map[string]interface{}{
						"template": "breach_notification",
					},
				},
				{
					ID:   "create-alert",
					Name: "Create Security Alert",
					Type: ActionTypeCreateAlert,
					Config: map[string]interface{}{
						"severity": "high",
						"category": "data_breach",
					},
				},
			},
		},
		{
			ID:          "enrich-new-indicators",
			Name:        "Enrich New Indicators",
			Description: "Automatically enrich new indicators with threat intelligence",
			Category:    "enrichment",
			Tags:        []string{"enrichment", "automation"},
			Triggers: []PlaybookTrigger{
				{
					Type:      TriggerTypeEvent,
					EventType: "indicator.new",
					Filters: &PlaybookTriggerFilters{
						MinConfidence: 0.5,
					},
				},
			},
			Actions: []PlaybookAction{
				{
					ID:   "enrich-vt",
					Name: "VirusTotal Enrichment",
					Type: ActionTypeEnrichIndicator,
					Config: map[string]interface{}{
						"source": "virustotal",
					},
					ContinueOnError: true,
				},
				{
					ID:   "enrich-otx",
					Name: "OTX Enrichment",
					Type: ActionTypeEnrichIndicator,
					Config: map[string]interface{}{
						"source": "alienvault_otx",
					},
					ContinueOnError: true,
				},
				{
					ID:   "update-severity",
					Name: "Update Severity Based on Results",
					Type: ActionTypeUpdateSeverity,
					Config: map[string]interface{}{
						"auto_calculate": true,
					},
				},
			},
		},
	}
}
