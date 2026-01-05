package models

import (
	"time"

	"github.com/google/uuid"
)

// FeatureVector represents extracted features from an indicator
type FeatureVector struct {
	IndicatorID   uuid.UUID         `json:"indicator_id"`
	IndicatorType IndicatorType     `json:"indicator_type"`
	Features      map[string]float64 `json:"features"`
	Normalized    []float64         `json:"normalized"`
	CreatedAt     time.Time         `json:"created_at"`
}

// IndicatorFeatures represents all features for ML processing
type IndicatorFeatures struct {
	// Structural features
	Length           int     `json:"length"`
	Entropy          float64 `json:"entropy"`
	NumericRatio     float64 `json:"numeric_ratio"`
	SpecialCharRatio float64 `json:"special_char_ratio"`
	UppercaseRatio   float64 `json:"uppercase_ratio"`

	// Domain-specific features (for domains/URLs)
	SubdomainCount   int     `json:"subdomain_count"`
	PathDepth        int     `json:"path_depth"`
	QueryParamCount  int     `json:"query_param_count"`
	HasIP            bool    `json:"has_ip"`
	HasPort          bool    `json:"has_port"`
	TLDRisk          float64 `json:"tld_risk"`
	DomainAge        int     `json:"domain_age_days"`

	// Network features (for IPs)
	IsPrivate        bool    `json:"is_private"`
	IsReserved       bool    `json:"is_reserved"`
	ASNRisk          float64 `json:"asn_risk"`
	GeoRisk          float64 `json:"geo_risk"`

	// Hash features
	HashType         string  `json:"hash_type,omitempty"`

	// Behavioral features
	FirstSeenDaysAgo int     `json:"first_seen_days_ago"`
	LastSeenDaysAgo  int     `json:"last_seen_days_ago"`
	SourceCount      int     `json:"source_count"`
	CampaignCount    int     `json:"campaign_count"`
	RelatedCount     int     `json:"related_count"`

	// Reputation features
	CurrentSeverity  float64 `json:"current_severity"`
	CurrentConfidence float64 `json:"current_confidence"`
	ReportCount      int     `json:"report_count"`
}

// AnomalyScore represents the result of anomaly detection
type AnomalyScore struct {
	IndicatorID   uuid.UUID `json:"indicator_id"`
	Score         float64   `json:"score"`          // 0.0 (normal) to 1.0 (anomalous)
	IsAnomaly     bool      `json:"is_anomaly"`
	Threshold     float64   `json:"threshold"`
	Confidence    float64   `json:"confidence"`
	Contributors  []string  `json:"contributors"`   // Features contributing most to anomaly
	Method        string    `json:"method"`         // isolation_forest, lof, etc.
	ComputedAt    time.Time `json:"computed_at"`
}

// AnomalyDetectionResult represents batch anomaly detection results
type AnomalyDetectionResult struct {
	TotalProcessed int             `json:"total_processed"`
	AnomalyCount   int             `json:"anomaly_count"`
	Scores         []AnomalyScore  `json:"scores"`
	Statistics     AnomalyStats    `json:"statistics"`
	ProcessingTime time.Duration   `json:"processing_time"`
}

// AnomalyStats represents statistics about anomaly detection
type AnomalyStats struct {
	MeanScore     float64 `json:"mean_score"`
	StdDevScore   float64 `json:"std_dev_score"`
	MedianScore   float64 `json:"median_score"`
	MinScore      float64 `json:"min_score"`
	MaxScore      float64 `json:"max_score"`
	Threshold     float64 `json:"threshold"`
	AnomalyRate   float64 `json:"anomaly_rate"`
}

// ClusterAssignment represents an indicator's cluster assignment
type ClusterAssignment struct {
	IndicatorID   uuid.UUID `json:"indicator_id"`
	ClusterID     int       `json:"cluster_id"`
	Distance      float64   `json:"distance"`       // Distance to cluster centroid
	Confidence    float64   `json:"confidence"`     // How confident the assignment is
	IsOutlier     bool      `json:"is_outlier"`
}

// Cluster represents a group of similar indicators
type Cluster struct {
	ID            int                  `json:"id"`
	Centroid      []float64            `json:"centroid"`
	Size          int                  `json:"size"`
	Density       float64              `json:"density"`
	Label         string               `json:"label,omitempty"`
	TopFeatures   []ClusterFeature     `json:"top_features"`
	Members       []uuid.UUID          `json:"members,omitempty"`
	SuggestedCampaign *CampaignSuggestion `json:"suggested_campaign,omitempty"`
}

// ClusterFeature represents a feature's importance in a cluster
type ClusterFeature struct {
	Name       string  `json:"name"`
	MeanValue  float64 `json:"mean_value"`
	Importance float64 `json:"importance"`
}

// ClusteringResult represents the result of clustering analysis
type ClusteringResult struct {
	K               int                  `json:"k"`
	Clusters        []Cluster            `json:"clusters"`
	Assignments     []ClusterAssignment  `json:"assignments"`
	Silhouette      float64              `json:"silhouette_score"`
	Inertia         float64              `json:"inertia"`
	OutlierCount    int                  `json:"outlier_count"`
	ProcessingTime  time.Duration        `json:"processing_time"`
}

// SeverityPrediction represents a predicted severity for an indicator
type SeverityPrediction struct {
	IndicatorID      uuid.UUID  `json:"indicator_id"`
	PredictedSeverity Severity  `json:"predicted_severity"`
	Confidence       float64    `json:"confidence"`
	Probabilities    map[Severity]float64 `json:"probabilities"`
	FeatureImportance map[string]float64  `json:"feature_importance"`
	Explanation      string     `json:"explanation"`
	ModelVersion     string     `json:"model_version"`
	PredictedAt      time.Time  `json:"predicted_at"`
}

// SeverityPredictionResult represents batch severity prediction results
type SeverityPredictionResult struct {
	TotalProcessed int                   `json:"total_processed"`
	Predictions    []SeverityPrediction  `json:"predictions"`
	Accuracy       float64               `json:"accuracy,omitempty"`
	ConfusionMatrix map[string]map[string]int `json:"confusion_matrix,omitempty"`
	ProcessingTime time.Duration         `json:"processing_time"`
}

// ExtractedEntity represents an entity extracted via NLP
type ExtractedEntity struct {
	Text       string       `json:"text"`
	Type       EntityType   `json:"type"`
	StartPos   int          `json:"start_pos"`
	EndPos     int          `json:"end_pos"`
	Confidence float64      `json:"confidence"`
	Normalized string       `json:"normalized,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// EntityType represents the type of extracted entity
type EntityType string

const (
	EntityTypeIP           EntityType = "ip_address"
	EntityTypeDomain       EntityType = "domain"
	EntityTypeURL          EntityType = "url"
	EntityTypeEmail        EntityType = "email"
	EntityTypeHash         EntityType = "hash"
	EntityTypeCVE          EntityType = "cve"
	EntityTypeMalware      EntityType = "malware"
	EntityTypeThreatActor  EntityType = "threat_actor"
	EntityTypeCampaign     EntityType = "campaign"
	EntityTypeOrganization EntityType = "organization"
	EntityTypePerson       EntityType = "person"
	EntityTypeLocation     EntityType = "location"
	EntityTypeDate         EntityType = "date"
	EntityTypeMITRE        EntityType = "mitre_technique"
	EntityTypeRegistry     EntityType = "registry_key"
	EntityTypeFilePath     EntityType = "file_path"
	EntityTypeBitcoin      EntityType = "bitcoin_address"
)

// EntityExtractionResult represents the result of NLP entity extraction
type EntityExtractionResult struct {
	SourceText     string            `json:"source_text,omitempty"`
	Entities       []ExtractedEntity `json:"entities"`
	EntityCounts   map[EntityType]int `json:"entity_counts"`
	Indicators     []ExtractedIndicator `json:"indicators"`
	ProcessingTime time.Duration     `json:"processing_time"`
}

// ExtractedIndicator represents an IOC extracted from text
type ExtractedIndicator struct {
	Value      string        `json:"value"`
	Type       IndicatorType `json:"type"`
	Confidence float64       `json:"confidence"`
	Context    string        `json:"context,omitempty"`
}

// MLEnrichmentResult represents the full ML enrichment of an indicator
type MLEnrichmentResult struct {
	IndicatorID       uuid.UUID              `json:"indicator_id"`
	Features          *IndicatorFeatures     `json:"features,omitempty"`
	AnomalyScore      *AnomalyScore          `json:"anomaly_score,omitempty"`
	ClusterAssignment *ClusterAssignment     `json:"cluster_assignment,omitempty"`
	SeverityPrediction *SeverityPrediction   `json:"severity_prediction,omitempty"`
	Entities          []ExtractedEntity      `json:"entities,omitempty"`
	EnrichedAt        time.Time              `json:"enriched_at"`
	ProcessingTime    time.Duration          `json:"processing_time"`
}

// MLModelInfo represents information about an ML model
type MLModelInfo struct {
	Name          string                 `json:"name"`
	Version       string                 `json:"version"`
	Type          string                 `json:"type"`
	TrainedAt     time.Time              `json:"trained_at"`
	TrainingSize  int                    `json:"training_size"`
	Accuracy      float64                `json:"accuracy,omitempty"`
	Parameters    map[string]interface{} `json:"parameters"`
	FeatureNames  []string               `json:"feature_names"`
	Status        string                 `json:"status"`
}

// MLServiceStats represents statistics about the ML service
type MLServiceStats struct {
	ModelsLoaded       int                    `json:"models_loaded"`
	Models             []MLModelInfo          `json:"models"`
	TotalPredictions   int64                  `json:"total_predictions"`
	TotalAnomalies     int64                  `json:"total_anomalies"`
	TotalClusters      int                    `json:"total_clusters"`
	TotalEntitiesExtracted int64              `json:"total_entities_extracted"`
	AverageLatencyMs   float64                `json:"average_latency_ms"`
	LastTrainedAt      time.Time              `json:"last_trained_at"`
	CacheHitRate       float64                `json:"cache_hit_rate"`
}

// MLTrainingRequest represents a request to train/retrain models
type MLTrainingRequest struct {
	ModelType     string                 `json:"model_type"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`
	TrainingData  []uuid.UUID            `json:"training_data,omitempty"`
	ValidateRatio float64                `json:"validate_ratio,omitempty"`
}

// MLTrainingResult represents the result of model training
type MLTrainingResult struct {
	ModelType      string                 `json:"model_type"`
	Version        string                 `json:"version"`
	TrainingSize   int                    `json:"training_size"`
	ValidationSize int                    `json:"validation_size"`
	Metrics        map[string]float64     `json:"metrics"`
	TrainingTime   time.Duration          `json:"training_time"`
	Success        bool                   `json:"success"`
	Error          string                 `json:"error,omitempty"`
}

// RiskyTLDs maps TLDs to risk scores (0.0 to 1.0)
var RiskyTLDs = map[string]float64{
	"tk":      0.9,
	"ml":      0.9,
	"ga":      0.9,
	"cf":      0.9,
	"gq":      0.9,
	"xyz":     0.7,
	"top":     0.7,
	"work":    0.7,
	"click":   0.7,
	"link":    0.7,
	"info":    0.5,
	"biz":     0.5,
	"online":  0.6,
	"site":    0.6,
	"club":    0.5,
	"live":    0.5,
	"stream":  0.6,
	"download":0.7,
	"zip":     0.8,
	"mov":     0.7,
	"review":  0.6,
	"country": 0.6,
	"kim":     0.6,
	"science": 0.5,
	"party":   0.6,
	"gdn":     0.7,
	"racing":  0.6,
	"win":     0.7,
	"accountant": 0.7,
	"date":    0.6,
	"faith":   0.6,
	"loan":    0.7,
	"men":     0.6,
	"porn":    0.8,
	"xxx":     0.8,
	"adult":   0.8,
	"sexy":    0.8,
	"sex":     0.8,
	"webcam":  0.7,
	"cam":     0.7,
}

// HighRiskASNs maps ASN numbers to risk scores
var HighRiskASNs = map[int]float64{
	// Known bulletproof hosting / high abuse ASNs
	// These are examples - would be populated from threat intelligence
	4134:  0.7,  // China Telecom
	4837:  0.7,  // China Unicom
	58461: 0.8,  // China Telecom backbone
	9009:  0.6,  // M247 (often abused)
	16509: 0.3,  // Amazon AWS (legitimate but commonly abused)
	14061: 0.3,  // DigitalOcean
	63949: 0.4,  // Linode
	20473: 0.5,  // AS-CHOOPA (Vultr)
	36352: 0.6,  // ColoCrossing (high abuse)
}

// HighRiskCountries maps country codes to risk scores
var HighRiskCountries = map[string]float64{
	"RU": 0.6, // Russia
	"CN": 0.6, // China
	"KP": 0.9, // North Korea
	"IR": 0.7, // Iran
	"NG": 0.5, // Nigeria
	"RO": 0.4, // Romania
	"UA": 0.4, // Ukraine
	"BY": 0.5, // Belarus
	"VN": 0.4, // Vietnam
	"ID": 0.3, // Indonesia
}
