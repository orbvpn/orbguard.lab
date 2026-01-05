package models

import (
	"time"

	"github.com/google/uuid"
)

// CorrelationType represents the type of correlation detected
type CorrelationType string

const (
	CorrelationTemporal       CorrelationType = "temporal"
	CorrelationInfrastructure CorrelationType = "infrastructure"
	CorrelationTTP            CorrelationType = "ttp"
	CorrelationBehavioral     CorrelationType = "behavioral"
	CorrelationNetwork        CorrelationType = "network"
	CorrelationCampaign       CorrelationType = "campaign"
)

// CorrelationStrength represents how strong a correlation is
type CorrelationStrength string

const (
	CorrelationStrengthWeak     CorrelationStrength = "weak"
	CorrelationStrengthModerate CorrelationStrength = "moderate"
	CorrelationStrengthStrong   CorrelationStrength = "strong"
	CorrelationStrengthVeryStrong CorrelationStrength = "very_strong"
)

// CorrelationConfig holds configuration for correlation analysis
type CorrelationConfig struct {
	// Temporal correlation settings
	TemporalWindowShort  time.Duration `json:"temporal_window_short"`  // 1 hour
	TemporalWindowMedium time.Duration `json:"temporal_window_medium"` // 24 hours
	TemporalWindowLong   time.Duration `json:"temporal_window_long"`   // 7 days
	MinTemporalOverlap   int           `json:"min_temporal_overlap"`   // minimum co-occurring indicators

	// Infrastructure overlap settings
	MinSharedInfra       int     `json:"min_shared_infra"`        // minimum shared infrastructure
	IPSubnetMask         int     `json:"ip_subnet_mask"`          // /24 by default
	DomainSimilarityMin  float64 `json:"domain_similarity_min"`   // 0.7 (70%)
	MinASNOverlap        int     `json:"min_asn_overlap"`         // minimum indicators per ASN

	// TTP matching settings
	MinTTPOverlap        int     `json:"min_ttp_overlap"`         // minimum shared techniques
	TTPSimilarityMin     float64 `json:"ttp_similarity_min"`      // 0.5 (50%)

	// Campaign detection settings
	MinCampaignIndicators int     `json:"min_campaign_indicators"` // minimum indicators for campaign
	CampaignConfidenceMin float64 `json:"campaign_confidence_min"` // 0.6 (60%)
}

// DefaultCorrelationConfig returns default correlation settings
func DefaultCorrelationConfig() *CorrelationConfig {
	return &CorrelationConfig{
		TemporalWindowShort:   1 * time.Hour,
		TemporalWindowMedium:  24 * time.Hour,
		TemporalWindowLong:    7 * 24 * time.Hour,
		MinTemporalOverlap:    3,
		MinSharedInfra:        2,
		IPSubnetMask:          24,
		DomainSimilarityMin:   0.7,
		MinASNOverlap:         3,
		MinTTPOverlap:         2,
		TTPSimilarityMin:      0.5,
		MinCampaignIndicators: 5,
		CampaignConfidenceMin: 0.6,
	}
}

// CorrelationEvent represents a correlation event from the engine
type CorrelationEvent struct {
	ID              uuid.UUID           `json:"id"`
	Type            CorrelationType     `json:"type"`
	Strength        CorrelationStrength `json:"strength"`
	Confidence      float64             `json:"confidence"`
	Description     string              `json:"description"`
	Indicators      []uuid.UUID         `json:"indicators"`
	CampaignID      *uuid.UUID          `json:"campaign_id,omitempty"`
	ThreatActorID   *uuid.UUID          `json:"threat_actor_id,omitempty"`
	Evidence        CorrelationEvidence `json:"evidence"`
	CreatedAt       time.Time           `json:"created_at"`
	ExpiresAt       *time.Time          `json:"expires_at,omitempty"`
}

// CorrelationEvidence holds evidence supporting a correlation
type CorrelationEvidence struct {
	SharedInfra     []SharedInfraEvidence   `json:"shared_infra,omitempty"`
	TemporalLinks   []TemporalLinkEvidence  `json:"temporal_links,omitempty"`
	TTPMatches      []TTPMatchEvidence      `json:"ttp_matches,omitempty"`
	DomainPatterns  []DomainPatternEvidence `json:"domain_patterns,omitempty"`
	NetworkPatterns []NetworkPatternEvidence `json:"network_patterns,omitempty"`
}

// SharedInfraEvidence represents evidence of shared infrastructure
type SharedInfraEvidence struct {
	Type       string   `json:"type"` // ip, asn, registrar, nameserver
	Value      string   `json:"value"`
	Indicators []string `json:"indicators"`
	Count      int      `json:"count"`
}

// TemporalLinkEvidence represents evidence of temporal correlation
type TemporalLinkEvidence struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Count       int       `json:"count"`
	Indicators  []string  `json:"indicators"`
}

// TTPMatchEvidence represents evidence of TTP matching
type TTPMatchEvidence struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	Actors        []string `json:"actors,omitempty"`
	Campaigns     []string `json:"campaigns,omitempty"`
}

// DomainPatternEvidence represents evidence of domain naming patterns
type DomainPatternEvidence struct {
	Pattern    string   `json:"pattern"`
	Domains    []string `json:"domains"`
	Similarity float64  `json:"similarity"`
}

// NetworkPatternEvidence represents evidence of network patterns
type NetworkPatternEvidence struct {
	Type    string   `json:"type"` // same_subnet, same_asn, same_hosting
	Pattern string   `json:"pattern"`
	IPs     []string `json:"ips"`
	Count   int      `json:"count"`
}

// IndicatorCluster represents a cluster of related indicators
type IndicatorCluster struct {
	ID              uuid.UUID           `json:"id"`
	Name            string              `json:"name"`
	Indicators      []IndicatorSummary  `json:"indicators"`
	ClusterType     CorrelationType     `json:"cluster_type"`
	Confidence      float64             `json:"confidence"`
	CommonTraits    []string            `json:"common_traits"`
	SuggestedCampaign *CampaignSuggestion `json:"suggested_campaign,omitempty"`
	CreatedAt       time.Time           `json:"created_at"`
}

// IndicatorSummary is a lightweight indicator representation for clustering
type IndicatorSummary struct {
	ID        uuid.UUID     `json:"id"`
	Type      IndicatorType `json:"type"`
	Value     string        `json:"value"`
	Severity  Severity      `json:"severity"`
	FirstSeen time.Time     `json:"first_seen"`
}

// CampaignSuggestion represents a suggested campaign grouping
type CampaignSuggestion struct {
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Confidence      float64   `json:"confidence"`
	IndicatorCount  int       `json:"indicator_count"`
	TimeRange       TimeRange `json:"time_range"`
	CommonPatterns  []string  `json:"common_patterns"`
	SuggestedActor  string    `json:"suggested_actor,omitempty"`
	MITRETechniques []string  `json:"mitre_techniques,omitempty"`
}

// InfrastructureProfile represents the infrastructure profile of an indicator/campaign
type InfrastructureProfile struct {
	ID              string                  `json:"id"`
	ASNs            []ASNInfo               `json:"asns"`
	IPRanges        []IPRangeInfo           `json:"ip_ranges"`
	Registrars      []RegistrarInfo         `json:"registrars"`
	Nameservers     []string                `json:"nameservers"`
	HostingProviders []HostingProviderInfo  `json:"hosting_providers"`
	Countries       []string                `json:"countries"`
	DomainPatterns  []string                `json:"domain_patterns"`
}

// ASNInfo represents ASN information
type ASNInfo struct {
	ASN         string `json:"asn"`
	Name        string `json:"name"`
	Country     string `json:"country"`
	Count       int    `json:"count"`
	Percentage  float64 `json:"percentage"`
}

// IPRangeInfo represents IP range information
type IPRangeInfo struct {
	CIDR       string `json:"cidr"`
	Count      int    `json:"count"`
	Country    string `json:"country,omitempty"`
	ASN        string `json:"asn,omitempty"`
}

// RegistrarInfo represents registrar information
type RegistrarInfo struct {
	Name       string `json:"name"`
	Count      int    `json:"count"`
	Percentage float64 `json:"percentage"`
}

// HostingProviderInfo represents hosting provider information
type HostingProviderInfo struct {
	Name       string `json:"name"`
	Count      int    `json:"count"`
	IPRanges   []string `json:"ip_ranges,omitempty"`
}

// CorrelationRequest represents a request to correlate indicators
type CorrelationRequest struct {
	IndicatorIDs    []uuid.UUID       `json:"indicator_ids,omitempty"`
	IndicatorValues []string          `json:"indicator_values,omitempty"`
	Types           []CorrelationType `json:"types,omitempty"`
	MinConfidence   float64           `json:"min_confidence,omitempty"`
	TimeRange       *TimeRange        `json:"time_range,omitempty"`
	IncludeEvidence bool              `json:"include_evidence"`
	MaxResults      int               `json:"max_results,omitempty"`
}

// CorrelationResponse represents the response from correlation analysis
type CorrelationResponse struct {
	RequestID       uuid.UUID           `json:"request_id"`
	Correlations    []CorrelationEvent  `json:"correlations"`
	Clusters        []IndicatorCluster  `json:"clusters,omitempty"`
	CampaignMatches []CampaignMatch     `json:"campaign_matches,omitempty"`
	ActorMatches    []ActorMatch        `json:"actor_matches,omitempty"`
	Statistics      CorrelationStats    `json:"statistics"`
	ProcessingTime  time.Duration       `json:"processing_time"`
	GeneratedAt     time.Time           `json:"generated_at"`
}

// CampaignMatch represents a match to an existing campaign
type CampaignMatch struct {
	CampaignID    uuid.UUID `json:"campaign_id"`
	CampaignName  string    `json:"campaign_name"`
	Confidence    float64   `json:"confidence"`
	MatchingIndicators int  `json:"matching_indicators"`
	SharedPatterns []string `json:"shared_patterns"`
}

// ActorMatch represents a match to a known threat actor
type ActorMatch struct {
	ActorID       uuid.UUID `json:"actor_id"`
	ActorName     string    `json:"actor_name"`
	Confidence    float64   `json:"confidence"`
	MatchedTTPs   []string  `json:"matched_ttps"`
	MatchedInfra  []string  `json:"matched_infra"`
}

// CorrelationStats provides statistics about correlation analysis
type CorrelationStats struct {
	TotalIndicators       int     `json:"total_indicators"`
	CorrelationsFound     int     `json:"correlations_found"`
	ClustersFormed        int     `json:"clusters_formed"`
	CampaignsMatched      int     `json:"campaigns_matched"`
	ActorsMatched         int     `json:"actors_matched"`
	AverageConfidence     float64 `json:"average_confidence"`
	StrongestCorrelation  float64 `json:"strongest_correlation"`
}

// EnrichmentData holds enrichment data for correlation
type EnrichmentData struct {
	IndicatorID uuid.UUID              `json:"indicator_id"`
	WHOIS       *WHOISData             `json:"whois,omitempty"`
	DNS         *DNSData               `json:"dns,omitempty"`
	GeoIP       *GeoIPData             `json:"geo_ip,omitempty"`
	ASN         *ASNData               `json:"asn,omitempty"`
	SSL         *SSLData               `json:"ssl,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	FetchedAt   time.Time              `json:"fetched_at"`
}

// WHOISData represents WHOIS lookup data
type WHOISData struct {
	Registrar       string    `json:"registrar"`
	RegistrarURL    string    `json:"registrar_url,omitempty"`
	CreatedDate     time.Time `json:"created_date,omitempty"`
	UpdatedDate     time.Time `json:"updated_date,omitempty"`
	ExpiresDate     time.Time `json:"expires_date,omitempty"`
	Nameservers     []string  `json:"nameservers"`
	Status          []string  `json:"status"`
	RegistrantOrg   string    `json:"registrant_org,omitempty"`
	RegistrantEmail string    `json:"registrant_email,omitempty"`
	Country         string    `json:"country,omitempty"`
}

// DNSData represents DNS lookup data
type DNSData struct {
	A       []string `json:"a,omitempty"`
	AAAA    []string `json:"aaaa,omitempty"`
	MX      []string `json:"mx,omitempty"`
	NS      []string `json:"ns,omitempty"`
	TXT     []string `json:"txt,omitempty"`
	CNAME   string   `json:"cname,omitempty"`
	SOA     string   `json:"soa,omitempty"`
}

// GeoIPData represents GeoIP lookup data
type GeoIPData struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
}

// ASNData represents ASN lookup data
type ASNData struct {
	ASN         string `json:"asn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Country     string `json:"country"`
	Registry    string `json:"registry,omitempty"`
	Allocated   string `json:"allocated,omitempty"`
}

// SSLData represents SSL certificate data
type SSLData struct {
	SerialNumber   string    `json:"serial_number"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidTo        time.Time `json:"valid_to"`
	SignatureAlg   string    `json:"signature_alg"`
	Fingerprint    string    `json:"fingerprint"`
	SAN            []string  `json:"san,omitempty"` // Subject Alternative Names
}

// CorrelationEngineStats represents correlation engine statistics
type CorrelationEngineStats struct {
	TotalCorrelations     int64             `json:"total_correlations"`
	CorrelationsByType    map[string]int64  `json:"correlations_by_type"`
	CorrelationsByStrength map[string]int64 `json:"correlations_by_strength"`
	CampaignsDetected     int64             `json:"campaigns_detected"`
	ClustersFormed        int64             `json:"clusters_formed"`
	AverageProcessingTime time.Duration     `json:"average_processing_time"`
	LastProcessedAt       time.Time         `json:"last_processed_at"`
}
