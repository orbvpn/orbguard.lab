-- +goose Up
-- +goose StatementBegin

-- Create schema
CREATE SCHEMA IF NOT EXISTS orbguard_lab;

-- Set search path for this session
SET search_path TO orbguard_lab, public;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For text search

-- Enum types
CREATE TYPE indicator_type AS ENUM (
    'domain',
    'ip',
    'ipv6',
    'hash',
    'url',
    'process',
    'certificate',
    'package',
    'email',
    'filepath',
    'registry',
    'yara'
);

CREATE TYPE severity_level AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'info'
);

CREATE TYPE platform_type AS ENUM (
    'android',
    'ios',
    'windows',
    'macos',
    'linux',
    'all'
);

CREATE TYPE source_category AS ENUM (
    'abuse_ch',
    'phishing',
    'ip_reputation',
    'mobile',
    'general',
    'government',
    'isac',
    'community',
    'premium'
);

CREATE TYPE source_type AS ENUM (
    'api',
    'feed',
    'github',
    'taxii',
    'manual',
    'community'
);

CREATE TYPE source_status AS ENUM (
    'active',
    'paused',
    'error',
    'disabled'
);

CREATE TYPE report_status AS ENUM (
    'pending',
    'reviewing',
    'approved',
    'rejected',
    'duplicate'
);

CREATE TYPE campaign_status AS ENUM (
    'active',
    'inactive',
    'historic'
);

CREATE TYPE threat_actor_type AS ENUM (
    'nation-state',
    'criminal',
    'hacktivist',
    'private-sector',
    'unknown'
);

CREATE TYPE threat_actor_motivation AS ENUM (
    'espionage',
    'financial',
    'sabotage',
    'surveillance',
    'hacktivism'
);

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Sources table
CREATE TABLE sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    category source_category NOT NULL,
    type source_type NOT NULL,
    status source_status NOT NULL DEFAULT 'active',

    -- Configuration
    api_url TEXT,
    feed_url TEXT,
    github_urls TEXT[],
    requires_api_key BOOLEAN NOT NULL DEFAULT FALSE,

    -- Scoring
    reliability DECIMAL(3,2) NOT NULL DEFAULT 0.50,
    weight DECIMAL(3,2) NOT NULL DEFAULT 1.00,

    -- Scheduling
    update_interval INTERVAL NOT NULL DEFAULT '1 hour',
    last_fetched TIMESTAMP WITH TIME ZONE,
    next_fetch TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    error_count INTEGER NOT NULL DEFAULT 0,

    -- Statistics
    indicator_count INTEGER NOT NULL DEFAULT 0,
    last_indicator_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Threat actors table
CREATE TABLE threat_actors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    aliases TEXT[],
    description TEXT,
    type threat_actor_type NOT NULL DEFAULT 'unknown',
    motivation threat_actor_motivation,
    country VARCHAR(100),
    active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Targets
    target_sectors TEXT[],
    target_regions TEXT[],

    -- MITRE ATT&CK
    common_techniques TEXT[],

    -- Statistics
    campaign_count INTEGER NOT NULL DEFAULT 0,
    indicator_count INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    "references" TEXT[],
    metadata JSONB,

    -- Neo4j
    graph_node_id VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Malware families table
CREATE TABLE malware_families (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    aliases TEXT[],
    description TEXT,
    type VARCHAR(100), -- spyware, ransomware, trojan, etc.
    platforms platform_type[],

    -- Attribution
    threat_actor_id UUID REFERENCES threat_actors(id),

    -- MITRE ATT&CK
    techniques TEXT[],

    -- Capabilities
    capabilities TEXT[],

    -- Statistics
    indicator_count INTEGER NOT NULL DEFAULT 0,
    campaign_count INTEGER NOT NULL DEFAULT 0,

    -- Temporal
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,

    -- Metadata
    "references" TEXT[],
    metadata JSONB,

    -- Neo4j
    graph_node_id VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Campaigns table
CREATE TABLE campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status campaign_status NOT NULL DEFAULT 'active',

    -- Attribution
    threat_actor_id UUID REFERENCES threat_actors(id),

    -- Targets
    target_sectors TEXT[],
    target_regions TEXT[],
    target_platforms platform_type[],

    -- MITRE ATT&CK
    mitre_techniques TEXT[],
    mitre_tactics TEXT[],

    -- Temporal
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,

    -- Statistics
    indicator_count INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    "references" TEXT[],
    metadata JSONB,

    -- Neo4j
    graph_node_id VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indicators table (main IOC storage)
CREATE TABLE indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    value TEXT NOT NULL,
    value_hash VARCHAR(64) NOT NULL, -- SHA256 for deduplication
    type indicator_type NOT NULL,
    severity severity_level NOT NULL DEFAULT 'medium',
    confidence DECIMAL(3,2) NOT NULL DEFAULT 0.50,
    description TEXT,
    tags TEXT[],
    platforms platform_type[],

    -- Source (required)
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,

    -- Temporal
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Attribution
    campaign_id UUID REFERENCES campaigns(id),
    threat_actor_id UUID REFERENCES threat_actors(id),
    malware_family_id UUID REFERENCES malware_families(id),

    -- MITRE ATT&CK
    mitre_techniques TEXT[],
    mitre_tactics TEXT[],

    -- Enrichment
    cve_ids TEXT[],
    report_count INTEGER NOT NULL DEFAULT 0,
    source_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB,

    -- Neo4j
    graph_node_id VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Unique constraint on hash for deduplication
    CONSTRAINT unique_indicator_hash UNIQUE (value_hash)
);

-- Indicator-Source relationship (many-to-many)
CREATE TABLE indicator_sources (
    indicator_id UUID NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    source_confidence DECIMAL(3,2) NOT NULL DEFAULT 0.50,
    raw_data TEXT,
    fetched_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    PRIMARY KEY (indicator_id, source_id)
);

-- Community reports table
CREATE TABLE community_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    status report_status NOT NULL DEFAULT 'pending',

    -- Indicator data
    indicator_value TEXT NOT NULL,
    indicator_type indicator_type NOT NULL,
    severity severity_level NOT NULL DEFAULT 'medium',
    description TEXT NOT NULL,
    tags TEXT[],

    -- Reporter info (anonymized)
    reporter_hash VARCHAR(64) NOT NULL, -- Hash of user/device ID
    reporter_country VARCHAR(100),

    -- Device info
    device_type VARCHAR(50),
    device_model VARCHAR(100),
    os_version VARCHAR(50),
    app_version VARCHAR(50),

    -- Evidence
    evidence_data JSONB,
    screenshot_url TEXT,

    -- Review
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,

    -- Link to created indicator
    indicator_id UUID REFERENCES indicators(id),

    -- Audit
    reported_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Update history table
CREATE TABLE update_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    source_slug VARCHAR(100) NOT NULL,

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    duration INTERVAL NOT NULL,

    -- Results
    success BOOLEAN NOT NULL,
    error TEXT,
    total_fetched INTEGER NOT NULL DEFAULT 0,
    new_indicators INTEGER NOT NULL DEFAULT 0,
    updated_indicators INTEGER NOT NULL DEFAULT 0,
    skipped_indicators INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    metadata JSONB,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Sources indexes
CREATE INDEX idx_sources_slug ON sources(slug);
CREATE INDEX idx_sources_status ON sources(status);
CREATE INDEX idx_sources_category ON sources(category);
CREATE INDEX idx_sources_next_fetch ON sources(next_fetch) WHERE status = 'active';

-- Threat actors indexes
CREATE INDEX idx_threat_actors_name ON threat_actors(name);
CREATE INDEX idx_threat_actors_type ON threat_actors(type);
CREATE INDEX idx_threat_actors_active ON threat_actors(active);

-- Malware families indexes
CREATE INDEX idx_malware_families_name ON malware_families(name);
CREATE INDEX idx_malware_families_type ON malware_families(type);

-- Campaigns indexes
CREATE INDEX idx_campaigns_slug ON campaigns(slug);
CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_threat_actor ON campaigns(threat_actor_id);

-- Indicators indexes
CREATE INDEX idx_indicators_value_hash ON indicators(value_hash);
CREATE INDEX idx_indicators_type ON indicators(type);
CREATE INDEX idx_indicators_severity ON indicators(severity);
CREATE INDEX idx_indicators_confidence ON indicators(confidence);
CREATE INDEX idx_indicators_first_seen ON indicators(first_seen);
CREATE INDEX idx_indicators_last_seen ON indicators(last_seen);
CREATE INDEX idx_indicators_expires_at ON indicators(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_indicators_campaign ON indicators(campaign_id) WHERE campaign_id IS NOT NULL;
CREATE INDEX idx_indicators_threat_actor ON indicators(threat_actor_id) WHERE threat_actor_id IS NOT NULL;
CREATE INDEX idx_indicators_malware_family ON indicators(malware_family_id) WHERE malware_family_id IS NOT NULL;

-- GIN indexes for array columns
CREATE INDEX idx_indicators_tags ON indicators USING GIN(tags);
CREATE INDEX idx_indicators_platforms ON indicators USING GIN(platforms);
CREATE INDEX idx_indicators_mitre_techniques ON indicators USING GIN(mitre_techniques);

-- Full-text search on indicator values
CREATE INDEX idx_indicators_value_trgm ON indicators USING GIN(value gin_trgm_ops);

-- Indicator sources indexes
CREATE INDEX idx_indicator_sources_source ON indicator_sources(source_id);
CREATE INDEX idx_indicator_sources_fetched ON indicator_sources(fetched_at);

-- Community reports indexes
CREATE INDEX idx_community_reports_status ON community_reports(status);
CREATE INDEX idx_community_reports_reported_at ON community_reports(reported_at);
CREATE INDEX idx_community_reports_indicator_type ON community_reports(indicator_type);

-- Update history indexes
CREATE INDEX idx_update_history_source ON update_history(source_id);
CREATE INDEX idx_update_history_started ON update_history(started_at);
CREATE INDEX idx_update_history_success ON update_history(success);

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Auto-update updated_at
CREATE TRIGGER update_sources_updated_at
    BEFORE UPDATE ON sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_actors_updated_at
    BEFORE UPDATE ON threat_actors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_malware_families_updated_at
    BEFORE UPDATE ON malware_families
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_campaigns_updated_at
    BEFORE UPDATE ON campaigns
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_indicators_updated_at
    BEFORE UPDATE ON indicators
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_community_reports_updated_at
    BEFORE UPDATE ON community_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

SET search_path TO orbguard_lab, public;

DROP TRIGGER IF EXISTS update_sources_updated_at ON sources;
DROP TRIGGER IF EXISTS update_threat_actors_updated_at ON threat_actors;
DROP TRIGGER IF EXISTS update_malware_families_updated_at ON malware_families;
DROP TRIGGER IF EXISTS update_campaigns_updated_at ON campaigns;
DROP TRIGGER IF EXISTS update_indicators_updated_at ON indicators;
DROP TRIGGER IF EXISTS update_community_reports_updated_at ON community_reports;

DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS update_history;
DROP TABLE IF EXISTS community_reports;
DROP TABLE IF EXISTS indicator_sources;
DROP TABLE IF EXISTS indicators;
DROP TABLE IF EXISTS campaigns;
DROP TABLE IF EXISTS malware_families;
DROP TABLE IF EXISTS threat_actors;
DROP TABLE IF EXISTS sources;

DROP TYPE IF EXISTS threat_actor_motivation;
DROP TYPE IF EXISTS threat_actor_type;
DROP TYPE IF EXISTS campaign_status;
DROP TYPE IF EXISTS report_status;
DROP TYPE IF EXISTS source_status;
DROP TYPE IF EXISTS source_type;
DROP TYPE IF EXISTS source_category;
DROP TYPE IF EXISTS platform_type;
DROP TYPE IF EXISTS severity_level;
DROP TYPE IF EXISTS indicator_type;

DROP SCHEMA IF EXISTS orbguard_lab;

-- +goose StatementEnd
