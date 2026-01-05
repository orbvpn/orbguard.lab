package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	App         AppConfig         `mapstructure:"app"`
	Server      ServerConfig      `mapstructure:"server"`
	Database    DatabaseConfig    `mapstructure:"database"`
	Redis       RedisConfig       `mapstructure:"redis"`
	Neo4j       Neo4jConfig       `mapstructure:"neo4j"`
	NATS        NATSConfig        `mapstructure:"nats"`
	JWT         JWTConfig         `mapstructure:"jwt"`
	CORS        CORSConfig        `mapstructure:"cors"`
	RateLimit   RateLimitConfig   `mapstructure:"ratelimit"`
	Logger      LoggerConfig      `mapstructure:"logger"`
	Aggregation AggregationConfig `mapstructure:"aggregation"`
	Sources     SourcesConfig     `mapstructure:"sources"`
	Scoring     ScoringConfig     `mapstructure:"scoring"`
	Detection   DetectionConfig   `mapstructure:"detection"`
	MITRE       MITREConfig       `mapstructure:"mitre"`
	STIX        STIXConfig        `mapstructure:"stix"`
	ML          MLConfig          `mapstructure:"ml"`
	HIBP        HIBPConfig        `mapstructure:"hibp"`
}

// HIBPConfig holds Have I Been Pwned API configuration
type HIBPConfig struct {
	APIKey  string `mapstructure:"api_key"`
	Enabled bool   `mapstructure:"enabled"`
}

type AppConfig struct {
	Name        string `mapstructure:"name"`
	Environment string `mapstructure:"environment"`
	Version     string `mapstructure:"version"`
	Debug       bool   `mapstructure:"debug"`
}

type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	HTTPPort        int           `mapstructure:"http_port"`
	GRPCPort        int           `mapstructure:"grpc_port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	DBName          string        `mapstructure:"dbname"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	Schema          string        `mapstructure:"schema"`
}

func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&search_path=%s",
		c.User, c.Password, c.Host, c.Port, c.DBName, c.SSLMode, c.Schema,
	)
}

type RedisConfig struct {
	Host      string `mapstructure:"host"`
	Port      int    `mapstructure:"port"`
	Password  string `mapstructure:"password"`
	DB        int    `mapstructure:"db"`
	KeyPrefix string `mapstructure:"key_prefix"`
	TLS       bool   `mapstructure:"tls"`
}

func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

type Neo4jConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	URI                string `mapstructure:"uri"`
	Username           string `mapstructure:"username"`
	Password           string `mapstructure:"password"`
	Database           string `mapstructure:"database"`
	MaxConnections     int    `mapstructure:"max_connections"`
	MaxLifetimeMinutes int    `mapstructure:"max_lifetime_minutes"`
}

type NATSConfig struct {
	Enabled    bool               `mapstructure:"enabled"`
	URL        string             `mapstructure:"url"`
	StreamName string             `mapstructure:"stream_name"`
	Subjects   NATSSubjectsConfig `mapstructure:"subjects"`
}

type NATSSubjectsConfig struct {
	NewThreat        string `mapstructure:"new_threat"`
	UpdatedThreat    string `mapstructure:"updated_threat"`
	CampaignDetected string `mapstructure:"campaign_detected"`
}

type JWTConfig struct {
	Secret     string        `mapstructure:"secret"`
	Expiration time.Duration `mapstructure:"expiration"`
	Issuer     string        `mapstructure:"issuer"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

type RateLimitConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	RequestsPerMinute int  `mapstructure:"requests_per_minute"`
	RequestsPerHour   int  `mapstructure:"requests_per_hour"`
}

type LoggerConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	TimeFormat string `mapstructure:"time_format"`
}

type AggregationConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	InitialDelay   time.Duration `mapstructure:"initial_delay"`
	WorkerPoolSize int           `mapstructure:"worker_pool_size"`
}

type SourcesConfig struct {
	URLhaus           SourceConfig `mapstructure:"urlhaus"`
	ThreatFox         SourceConfig `mapstructure:"threatfox"`
	MalwareBazaar     SourceConfig `mapstructure:"malwarebazaar"`
	FeodoTracker      SourceConfig `mapstructure:"feodotracker"`
	SSLBlacklist      SourceConfig `mapstructure:"sslblacklist"`
	OpenPhish         SourceConfig `mapstructure:"openphish"`
	PhishTank         SourceConfig `mapstructure:"phishtank"`
	GoogleSafeBrowsing SourceConfig `mapstructure:"google_safebrowsing"`
	AbuseIPDB         SourceConfig `mapstructure:"abuseipdb"`
	GreyNoise         SourceConfig `mapstructure:"greynoise"`
	CitizenLab        SourceConfig `mapstructure:"citizenlab"`
	AmnestyMVT        SourceConfig `mapstructure:"amnesty_mvt"`
	Koodous           SourceConfig `mapstructure:"koodous"`
	AlienVaultOTX     SourceConfig `mapstructure:"alienvault_otx"`
	VirusTotal        SourceConfig `mapstructure:"virustotal"`
}

type SourceConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	UpdateInterval time.Duration `mapstructure:"update_interval"`
	APIURL         string        `mapstructure:"api_url"`
	FeedURL        string        `mapstructure:"feed_url"`
	APIKey         string        `mapstructure:"api_key"`
	GithubURLs     []string      `mapstructure:"github_urls"`
}

type ScoringConfig struct {
	Weights           ScoringWeights           `mapstructure:"weights"`
	Bonuses           ScoringBonuses           `mapstructure:"bonuses"`
	SourceReliability map[string]float64       `mapstructure:"source_reliability"`
}

type ScoringWeights struct {
	SourceReliability float64 `mapstructure:"source_reliability"`
	SourceCount       float64 `mapstructure:"source_count"`
	Recency           float64 `mapstructure:"recency"`
	ReportCount       float64 `mapstructure:"report_count"`
	SourceConfidence  float64 `mapstructure:"source_confidence"`
}

type ScoringBonuses struct {
	Pegasus     float64 `mapstructure:"pegasus"`
	CVELinked   float64 `mapstructure:"cve_linked"`
	KnownFamily float64 `mapstructure:"known_family"`
}

type DetectionConfig struct {
	YARA        YARAConfig        `mapstructure:"yara"`
	Behavioral  BehavioralConfig  `mapstructure:"behavioral"`
	SupplyChain SupplyChainConfig `mapstructure:"supply_chain"`
}

type YARAConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	RulesDir string `mapstructure:"rules_dir"`
}

type BehavioralConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	BaselineDuration time.Duration `mapstructure:"baseline_duration"`
}

type SupplyChainConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	OSVAPURL  string `mapstructure:"osv_api_url"`
}

type MITREConfig struct {
	DataDir              string `mapstructure:"data_dir"`
	MobileAttackFile     string `mapstructure:"mobile_attack_file"`
	EnterpriseAttackFile string `mapstructure:"enterprise_attack_file"`
}

type STIXConfig struct {
	Enabled     bool             `mapstructure:"enabled"`
	TAXIIServer TAXIIServerConfig `mapstructure:"taxii_server"`
}

type TAXIIServerConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port"`
}

type MLConfig struct {
	AnomalyDetection AnomalyDetectionConfig `mapstructure:"anomaly_detection"`
	Clustering       ClusteringConfig       `mapstructure:"clustering"`
}

type AnomalyDetectionConfig struct {
	Enabled    bool    `mapstructure:"enabled"`
	NumTrees   int     `mapstructure:"num_trees"`
	SampleSize int     `mapstructure:"sample_size"`
	Threshold  float64 `mapstructure:"threshold"`
}

type ClusteringConfig struct {
	Enabled    bool    `mapstructure:"enabled"`
	MinSamples int     `mapstructure:"min_samples"`
	Eps        float64 `mapstructure:"eps"`
}

// Load reads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/orbguard-lab")
	}

	// Environment variables
	v.SetEnvPrefix("ORBGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind nested env vars explicitly (viper doesn't auto-bind nested struct fields)
	v.BindEnv("redis.tls", "ORBGUARD_REDIS_TLS")
	v.BindEnv("redis.host", "ORBGUARD_REDIS_HOST")
	v.BindEnv("redis.port", "ORBGUARD_REDIS_PORT")
	v.BindEnv("redis.password", "ORBGUARD_REDIS_PASSWORD")
	v.BindEnv("database.host", "ORBGUARD_DATABASE_HOST")
	v.BindEnv("database.port", "ORBGUARD_DATABASE_PORT")
	v.BindEnv("database.user", "ORBGUARD_DATABASE_USER")
	v.BindEnv("database.password", "ORBGUARD_DATABASE_PASSWORD")
	v.BindEnv("database.dbname", "ORBGUARD_DATABASE_DBNAME")
	v.BindEnv("database.sslmode", "ORBGUARD_DATABASE_SSLMODE")
	v.BindEnv("neo4j.enabled", "ORBGUARD_NEO4J_ENABLED")
	v.BindEnv("nats.enabled", "ORBGUARD_NATS_ENABLED")
	v.BindEnv("app.environment", "ORBGUARD_APP_ENVIRONMENT")

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadDefault loads configuration with default path
func LoadDefault() (*Config, error) {
	return Load("")
}
