package models

import (
	"time"

	"github.com/google/uuid"
)

// IntegrationType represents the type of integration
type IntegrationType string

const (
	IntegrationTypeSlack     IntegrationType = "slack"
	IntegrationTypeTeams     IntegrationType = "teams"
	IntegrationTypePagerDuty IntegrationType = "pagerduty"
	IntegrationTypeEmail     IntegrationType = "email"
	IntegrationTypeJira      IntegrationType = "jira"
	IntegrationTypeSplunk    IntegrationType = "splunk"
)

// IntegrationStatus represents the status of an integration
type IntegrationStatus string

const (
	IntegrationStatusActive   IntegrationStatus = "active"
	IntegrationStatusInactive IntegrationStatus = "inactive"
	IntegrationStatusError    IntegrationStatus = "error"
	IntegrationStatusPending  IntegrationStatus = "pending"
)

// Integration represents an external integration configuration
type Integration struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Type        IntegrationType        `json:"type"`
	Status      IntegrationStatus      `json:"status"`
	Description string                 `json:"description,omitempty"`

	// Configuration (type-specific)
	Config      IntegrationConfig      `json:"config"`

	// Event filtering
	EventTypes  []string               `json:"event_types,omitempty"`
	Filters     *IntegrationFilters    `json:"filters,omitempty"`

	// Statistics
	MessagesSent   int64              `json:"messages_sent"`
	LastMessageAt  *time.Time         `json:"last_message_at,omitempty"`
	ErrorCount     int64              `json:"error_count"`
	LastError      string             `json:"last_error,omitempty"`
	LastErrorAt    *time.Time         `json:"last_error_at,omitempty"`

	// Metadata
	CreatedBy   string                 `json:"created_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// IntegrationConfig contains type-specific configuration
type IntegrationConfig struct {
	// Slack
	SlackWebhookURL   string `json:"slack_webhook_url,omitempty"`
	SlackChannel      string `json:"slack_channel,omitempty"`
	SlackUsername     string `json:"slack_username,omitempty"`
	SlackIconEmoji    string `json:"slack_icon_emoji,omitempty"`

	// Microsoft Teams
	TeamsWebhookURL   string `json:"teams_webhook_url,omitempty"`

	// PagerDuty
	PagerDutyAPIKey     string `json:"pagerduty_api_key,omitempty"`
	PagerDutyServiceID  string `json:"pagerduty_service_id,omitempty"`
	PagerDutyRoutingKey string `json:"pagerduty_routing_key,omitempty"`

	// Email
	EmailSMTPHost     string   `json:"email_smtp_host,omitempty"`
	EmailSMTPPort     int      `json:"email_smtp_port,omitempty"`
	EmailUsername     string   `json:"email_username,omitempty"`
	EmailPassword     string   `json:"email_password,omitempty"`
	EmailFrom         string   `json:"email_from,omitempty"`
	EmailTo           []string `json:"email_to,omitempty"`
	EmailUseTLS       bool     `json:"email_use_tls,omitempty"`

	// Jira
	JiraURL        string `json:"jira_url,omitempty"`
	JiraUsername   string `json:"jira_username,omitempty"`
	JiraAPIToken   string `json:"jira_api_token,omitempty"`
	JiraProject    string `json:"jira_project,omitempty"`
	JiraIssueType  string `json:"jira_issue_type,omitempty"`

	// Splunk
	SplunkHECURL   string `json:"splunk_hec_url,omitempty"`
	SplunkHECToken string `json:"splunk_hec_token,omitempty"`
	SplunkIndex    string `json:"splunk_index,omitempty"`
	SplunkSource   string `json:"splunk_source,omitempty"`
}

// IntegrationFilters defines filters for integration events
type IntegrationFilters struct {
	MinSeverity  string   `json:"min_severity,omitempty"`
	Campaigns    []string `json:"campaigns,omitempty"`
	ThreatTypes  []string `json:"threat_types,omitempty"`
	Platforms    []string `json:"platforms,omitempty"`
}

// IntegrationMessage represents a message to send via integration
type IntegrationMessage struct {
	ID           uuid.UUID              `json:"id"`
	Integration  *Integration           `json:"-"`
	EventType    string                 `json:"event_type"`
	Title        string                 `json:"title"`
	Summary      string                 `json:"summary"`
	Details      string                 `json:"details,omitempty"`
	Severity     string                 `json:"severity"`
	URL          string                 `json:"url,omitempty"`
	Fields       map[string]string      `json:"fields,omitempty"`
	Actions      []MessageAction        `json:"actions,omitempty"`
	Data         map[string]interface{} `json:"data,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// MessageAction represents an action button in a message
type MessageAction struct {
	Type  string `json:"type"` // button, link
	Text  string `json:"text"`
	URL   string `json:"url,omitempty"`
	Style string `json:"style,omitempty"` // primary, danger
}

// IntegrationDelivery represents a message delivery attempt
type IntegrationDelivery struct {
	ID            uuid.UUID        `json:"id"`
	IntegrationID uuid.UUID        `json:"integration_id"`
	MessageID     uuid.UUID        `json:"message_id"`
	Status        DeliveryStatus   `json:"status"`
	StatusCode    int              `json:"status_code,omitempty"`
	Response      string           `json:"response,omitempty"`
	Error         string           `json:"error,omitempty"`
	Attempts      int              `json:"attempts"`
	LastAttemptAt *time.Time       `json:"last_attempt_at,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
}

// SlackMessage represents a Slack message payload
type SlackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
	Blocks      []SlackBlock      `json:"blocks,omitempty"`
}

// SlackAttachment represents a Slack attachment
type SlackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Fallback   string       `json:"fallback,omitempty"`
	Title      string       `json:"title,omitempty"`
	TitleLink  string       `json:"title_link,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	Ts         int64        `json:"ts,omitempty"`
}

// SlackField represents a field in a Slack attachment
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SlackBlock represents a Slack block element
type SlackBlock struct {
	Type     string          `json:"type"`
	Text     *SlackBlockText `json:"text,omitempty"`
	Elements []interface{}   `json:"elements,omitempty"`
}

// SlackBlockText represents text in a Slack block
type SlackBlockText struct {
	Type  string `json:"type"` // plain_text, mrkdwn
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

// TeamsMessage represents a Microsoft Teams message payload
type TeamsMessage struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor,omitempty"`
	Summary    string         `json:"summary"`
	Title      string         `json:"title,omitempty"`
	Sections   []TeamsSection `json:"sections,omitempty"`
	Actions    []TeamsAction  `json:"potentialAction,omitempty"`
}

// TeamsSection represents a section in a Teams message
type TeamsSection struct {
	ActivityTitle    string       `json:"activityTitle,omitempty"`
	ActivitySubtitle string       `json:"activitySubtitle,omitempty"`
	ActivityImage    string       `json:"activityImage,omitempty"`
	Text             string       `json:"text,omitempty"`
	Facts            []TeamsFact  `json:"facts,omitempty"`
	Markdown         bool         `json:"markdown,omitempty"`
}

// TeamsFact represents a fact in a Teams section
type TeamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// TeamsAction represents an action in a Teams message
type TeamsAction struct {
	Type    string                 `json:"@type"`
	Name    string                 `json:"name"`
	Targets []TeamsActionTarget    `json:"targets,omitempty"`
	Actions []TeamsActionInput     `json:"actions,omitempty"`
	Inputs  []TeamsInput           `json:"inputs,omitempty"`
}

// TeamsActionTarget represents a target URL for a Teams action
type TeamsActionTarget struct {
	OS  string `json:"os,omitempty"`
	URI string `json:"uri"`
}

// TeamsActionInput represents an action input
type TeamsActionInput struct {
	Type   string `json:"@type"`
	Name   string `json:"name"`
	Target string `json:"target"`
}

// TeamsInput represents an input in a Teams action
type TeamsInput struct {
	Type        string `json:"@type"`
	ID          string `json:"id"`
	IsMultiline bool   `json:"isMultiline,omitempty"`
	Title       string `json:"title,omitempty"`
}

// PagerDutyEvent represents a PagerDuty event payload
type PagerDutyEvent struct {
	RoutingKey  string                 `json:"routing_key"`
	EventAction string                 `json:"event_action"` // trigger, acknowledge, resolve
	DedupKey    string                 `json:"dedup_key,omitempty"`
	Payload     PagerDutyPayload       `json:"payload"`
	Links       []PagerDutyLink        `json:"links,omitempty"`
	Images      []PagerDutyImage       `json:"images,omitempty"`
	Client      string                 `json:"client,omitempty"`
	ClientURL   string                 `json:"client_url,omitempty"`
}

// PagerDutyPayload represents the payload of a PagerDuty event
type PagerDutyPayload struct {
	Summary       string                 `json:"summary"`
	Source        string                 `json:"source"`
	Severity      string                 `json:"severity"` // critical, error, warning, info
	Timestamp     string                 `json:"timestamp,omitempty"`
	Component     string                 `json:"component,omitempty"`
	Group         string                 `json:"group,omitempty"`
	Class         string                 `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
}

// PagerDutyLink represents a link in a PagerDuty event
type PagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text,omitempty"`
}

// PagerDutyImage represents an image in a PagerDuty event
type PagerDutyImage struct {
	Src  string `json:"src"`
	Href string `json:"href,omitempty"`
	Alt  string `json:"alt,omitempty"`
}

// IntegrationTestResult represents the result of testing an integration
type IntegrationTestResult struct {
	Success     bool      `json:"success"`
	Message     string    `json:"message"`
	StatusCode  int       `json:"status_code,omitempty"`
	Response    string    `json:"response,omitempty"`
	LatencyMs   int64     `json:"latency_ms"`
	TestedAt    time.Time `json:"tested_at"`
}

// IntegrationStats contains statistics for an integration
type IntegrationStats struct {
	IntegrationID    uuid.UUID `json:"integration_id"`
	TotalMessages    int64     `json:"total_messages"`
	SuccessfulSends  int64     `json:"successful_sends"`
	FailedSends      int64     `json:"failed_sends"`
	AverageLatencyMs int64     `json:"average_latency_ms"`
	LastSuccess      time.Time `json:"last_success,omitempty"`
	LastFailure      time.Time `json:"last_failure,omitempty"`
}

// SeverityColor maps severity levels to colors for integrations
var SeverityColor = map[string]string{
	"critical": "#FF0000",
	"high":     "#FF8C00",
	"medium":   "#FFD700",
	"low":      "#00CED1",
	"info":     "#808080",
}

// GetSeverityColor returns the color for a severity level
func GetSeverityColor(severity string) string {
	if color, ok := SeverityColor[severity]; ok {
		return color
	}
	return "#808080"
}
