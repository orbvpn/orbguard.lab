package models

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// OrbNet VPN Integration
// ============================================================================

// OrbNetServer represents an OrbMesh VPN server
type OrbNetServer struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Hostname    string    `json:"hostname"`
	IPAddress   string    `json:"ip_address"`
	Port        int       `json:"port"`
	Location    string    `json:"location"` // e.g., "us-east-1", "eu-west-1"
	Country     string    `json:"country"`
	Region      string    `json:"region"`

	// Connection info
	Protocol    string    `json:"protocol"` // wireguard, openvpn
	PublicKey   string    `json:"public_key,omitempty"`

	// Status
	Status      string    `json:"status"` // online, offline, maintenance
	Load        float64   `json:"load"`   // 0.0 - 1.0
	Connections int       `json:"connections"`
	Capacity    int       `json:"capacity"`

	// Threat intel sync
	ThreatSyncEnabled bool       `json:"threat_sync_enabled"`
	LastThreatSync    *time.Time `json:"last_threat_sync,omitempty"`
	ThreatRulesCount  int        `json:"threat_rules_count"`

	// Timestamps
	RegisteredAt time.Time  `json:"registered_at"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
}

// OrbNetClient represents a connected VPN client
type OrbNetClient struct {
	ID           uuid.UUID `json:"id"`
	DeviceID     uuid.UUID `json:"device_id"`
	ServerID     uuid.UUID `json:"server_id"`
	UserID       string    `json:"user_id,omitempty"`

	// Connection
	ClientIP     string    `json:"client_ip"`
	AssignedIP   string    `json:"assigned_ip"`
	Protocol     string    `json:"protocol"`

	// Session
	ConnectedAt  time.Time `json:"connected_at"`
	LastActivity time.Time `json:"last_activity"`
	BytesSent    int64     `json:"bytes_sent"`
	BytesRecv    int64     `json:"bytes_recv"`

	// Threat protection status
	ThreatProtectionEnabled bool   `json:"threat_protection_enabled"`
	BlockedRequests         int64  `json:"blocked_requests"`
	ThreatAlertsToday       int    `json:"threat_alerts_today"`
}

// ============================================================================
// DNS Filtering
// ============================================================================

// DNSBlockRule represents a DNS blocking rule
type DNSBlockRule struct {
	ID          uuid.UUID `json:"id"`
	Domain      string    `json:"domain"`
	RuleType    string    `json:"rule_type"` // exact, wildcard, regex
	Category    string    `json:"category"`  // malware, phishing, ads, tracking, adult
	Severity    Severity  `json:"severity"`
	Source      string    `json:"source"`    // threat_intel, manual, community

	// Metadata
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`

	// Effectiveness
	HitCount    int64     `json:"hit_count"`
	LastHitAt   *time.Time `json:"last_hit_at,omitempty"`

	// Status
	Enabled     bool      `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DNSQuery represents a DNS query for analysis
type DNSQuery struct {
	ID          string    `json:"id"`
	ClientID    uuid.UUID `json:"client_id"`
	ServerID    uuid.UUID `json:"server_id"`

	// Query details
	Domain      string    `json:"domain"`
	QueryType   string    `json:"query_type"` // A, AAAA, CNAME, MX, TXT
	Timestamp   time.Time `json:"timestamp"`

	// Response
	Blocked     bool      `json:"blocked"`
	BlockReason string    `json:"block_reason,omitempty"`
	RuleID      *uuid.UUID `json:"rule_id,omitempty"`

	// Resolved
	Resolved    bool      `json:"resolved"`
	ResolvedIP  string    `json:"resolved_ip,omitempty"`
	ResponseTime int64    `json:"response_time_ms"`
}

// DNSFilterConfig represents DNS filtering configuration
type DNSFilterConfig struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`

	// Categories to block
	BlockMalware   bool `json:"block_malware"`
	BlockPhishing  bool `json:"block_phishing"`
	BlockAds       bool `json:"block_ads"`
	BlockTracking  bool `json:"block_tracking"`
	BlockAdult     bool `json:"block_adult"`
	BlockGambling  bool `json:"block_gambling"`
	BlockSocialMedia bool `json:"block_social_media"`

	// Custom rules
	CustomBlocklist []string `json:"custom_blocklist,omitempty"`
	CustomAllowlist []string `json:"custom_allowlist,omitempty"`

	// Settings
	LogQueries     bool `json:"log_queries"`
	SafeSearch     bool `json:"safe_search"`

	// Timestamps
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DNSBlockResponse represents a response for blocked domain check
type DNSBlockResponse struct {
	Domain      string    `json:"domain"`
	Blocked     bool      `json:"blocked"`
	Reason      string    `json:"reason,omitempty"`
	Category    string    `json:"category,omitempty"`
	Severity    Severity  `json:"severity,omitempty"`
	RuleID      *uuid.UUID `json:"rule_id,omitempty"`
	Threat      *ThreatInfo `json:"threat,omitempty"`
}

// ThreatInfo represents threat information for a blocked domain
type ThreatInfo struct {
	Type        string    `json:"type"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Campaign    string    `json:"campaign,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`
}

// ============================================================================
// Threat Intelligence Sync
// ============================================================================

// ThreatSyncRequest represents a request to sync threat data
type ThreatSyncRequest struct {
	ServerID    uuid.UUID `json:"server_id"`
	LastSyncAt  *time.Time `json:"last_sync_at,omitempty"`
	Categories  []string  `json:"categories,omitempty"` // malware, phishing, etc.
	MaxRules    int       `json:"max_rules,omitempty"`
	Format      string    `json:"format"` // json, binary, compressed
}

// ThreatSyncResponse represents threat data for VPN servers
type ThreatSyncResponse struct {
	SyncID      string       `json:"sync_id"`
	Timestamp   time.Time    `json:"timestamp"`
	ServerID    uuid.UUID    `json:"server_id"`

	// Rules
	BlockRules  []DNSBlockRule `json:"block_rules"`
	TotalRules  int            `json:"total_rules"`

	// Metadata
	Categories  map[string]int `json:"categories"` // count per category
	Sources     []string       `json:"sources"`

	// Delta sync
	IsDelta     bool          `json:"is_delta"`
	AddedRules  int           `json:"added_rules"`
	RemovedIDs  []uuid.UUID   `json:"removed_ids,omitempty"`

	// Next sync
	NextSyncAt  time.Time     `json:"next_sync_at"`
}

// ThreatPushEvent represents a real-time threat push to servers
type ThreatPushEvent struct {
	EventID     string       `json:"event_id"`
	Type        string       `json:"type"` // add_rule, remove_rule, update_rule, emergency_block
	Timestamp   time.Time    `json:"timestamp"`
	Priority    string       `json:"priority"` // normal, high, critical

	// Rule data
	Rule        *DNSBlockRule `json:"rule,omitempty"`
	RuleIDs     []uuid.UUID   `json:"rule_ids,omitempty"`

	// Emergency block
	Domains     []string      `json:"domains,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Duration    time.Duration `json:"duration,omitempty"`
}

// ============================================================================
// VPN Traffic Analysis
// ============================================================================

// TrafficAnalysis represents traffic analysis results
type TrafficAnalysis struct {
	ClientID    uuid.UUID `json:"client_id"`
	Period      string    `json:"period"` // hourly, daily, weekly
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`

	// Traffic stats
	TotalQueries    int64 `json:"total_queries"`
	BlockedQueries  int64 `json:"blocked_queries"`
	AllowedQueries  int64 `json:"allowed_queries"`

	// Category breakdown
	CategoryStats map[string]CategoryStats `json:"category_stats"`

	// Top domains
	TopBlocked  []DomainStat `json:"top_blocked"`
	TopAllowed  []DomainStat `json:"top_allowed"`

	// Threats detected
	ThreatsDetected int      `json:"threats_detected"`
	ThreatTypes     map[string]int `json:"threat_types"`

	// Risk score
	RiskScore   float64 `json:"risk_score"` // 0-100
	RiskLevel   string  `json:"risk_level"` // low, medium, high, critical
}

// CategoryStats represents stats for a category
type CategoryStats struct {
	Category    string `json:"category"`
	Queries     int64  `json:"queries"`
	Blocked     int64  `json:"blocked"`
	Percentage  float64 `json:"percentage"`
}

// DomainStat represents stats for a domain
type DomainStat struct {
	Domain      string `json:"domain"`
	Count       int64  `json:"count"`
	Category    string `json:"category,omitempty"`
	Blocked     bool   `json:"blocked"`
}

// ============================================================================
// Dashboard Stats
// ============================================================================

// OrbNetDashboardStats represents stats for admin dashboard
type OrbNetDashboardStats struct {
	// Servers
	TotalServers     int     `json:"total_servers"`
	OnlineServers    int     `json:"online_servers"`
	TotalCapacity    int     `json:"total_capacity"`
	TotalConnections int     `json:"total_connections"`
	AverageLoad      float64 `json:"average_load"`

	// Clients
	ActiveClients    int     `json:"active_clients"`
	ProtectedClients int     `json:"protected_clients"`

	// DNS Filtering
	TotalRules       int     `json:"total_rules"`
	RulesByCategory  map[string]int `json:"rules_by_category"`

	// Traffic (last 24h)
	TotalQueries24h  int64   `json:"total_queries_24h"`
	BlockedQueries24h int64  `json:"blocked_queries_24h"`
	BlockRate        float64 `json:"block_rate"` // percentage

	// Threats (last 24h)
	ThreatsBlocked24h int64  `json:"threats_blocked_24h"`
	TopThreatTypes   map[string]int64 `json:"top_threat_types"`
	TopBlockedDomains []DomainStat `json:"top_blocked_domains"`

	// Performance
	AvgResponseTime  float64 `json:"avg_response_time_ms"`
	P99ResponseTime  float64 `json:"p99_response_time_ms"`

	// Sync status
	LastThreatSync   *time.Time `json:"last_threat_sync,omitempty"`
	SyncStatus       string    `json:"sync_status"` // synced, pending, failed

	Timestamp        time.Time `json:"timestamp"`
}

// ============================================================================
// Configuration
// ============================================================================

// OrbNetConfig represents OrbNet integration configuration
type OrbNetConfig struct {
	// gRPC connection
	GRPCEndpoint    string        `json:"grpc_endpoint"`
	GRPCTimeout     time.Duration `json:"grpc_timeout"`
	UseTLS          bool          `json:"use_tls"`
	TLSCertPath     string        `json:"tls_cert_path,omitempty"`

	// Sync settings
	SyncInterval    time.Duration `json:"sync_interval"`
	MaxRulesPerSync int           `json:"max_rules_per_sync"`

	// Push settings
	PushEnabled     bool          `json:"push_enabled"`
	PushEndpoints   []string      `json:"push_endpoints,omitempty"`

	// Filtering defaults
	DefaultBlockMalware  bool `json:"default_block_malware"`
	DefaultBlockPhishing bool `json:"default_block_phishing"`
	DefaultBlockAds      bool `json:"default_block_ads"`
	DefaultBlockTracking bool `json:"default_block_tracking"`
}

// DefaultOrbNetConfig returns default OrbNet configuration
var DefaultOrbNetConfig = OrbNetConfig{
	GRPCEndpoint:         "localhost:50051",
	GRPCTimeout:          30 * time.Second,
	UseTLS:               false,
	SyncInterval:         5 * time.Minute,
	MaxRulesPerSync:      10000,
	PushEnabled:          true,
	DefaultBlockMalware:  true,
	DefaultBlockPhishing: true,
	DefaultBlockAds:      false,
	DefaultBlockTracking: false,
}

// DNS Block Categories
const (
	DNSCategoryMalware     = "malware"
	DNSCategoryPhishing    = "phishing"
	DNSCategoryAds         = "ads"
	DNSCategoryTracking    = "tracking"
	DNSCategoryAdult       = "adult"
	DNSCategoryGambling    = "gambling"
	DNSCategorySocialMedia = "social_media"
	DNSCategoryStreaming   = "streaming"
	DNSCategoryCrypto      = "crypto"
	DNSCategoryVPN         = "vpn"
)

// DNS Rule Types
const (
	DNSRuleTypeExact    = "exact"
	DNSRuleTypeWildcard = "wildcard"
	DNSRuleTypeRegex    = "regex"
)

// Sync Status
const (
	SyncStatusSynced   = "synced"
	SyncStatusPending  = "pending"
	SyncStatusFailed   = "failed"
	SyncStatusSyncing  = "syncing"
)
