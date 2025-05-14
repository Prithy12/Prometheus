-- NetGuardian Intelligence Database Schema
-- Using PostgreSQL for structured threat intelligence storage

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "hstore";

-- Indicators of Compromise (IOCs)
CREATE TABLE IF NOT EXISTS iocs (
    ioc_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(50) NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'file_hash', 'email', 'user_agent')),
    value TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    severity INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 10),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expiration TIMESTAMP WITH TIME ZONE,
    tags TEXT[] DEFAULT '{}',
    source VARCHAR(100),
    description TEXT,
    context JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    CONSTRAINT unique_ioc_type_value UNIQUE (type, value)
);

CREATE INDEX idx_iocs_type ON iocs(type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_tags ON iocs USING GIN(tags);
CREATE INDEX idx_iocs_context ON iocs USING GIN(context);

-- Threat Actors
CREATE TABLE IF NOT EXISTS threat_actors (
    actor_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    aliases TEXT[] DEFAULT '{}',
    motivation VARCHAR(50)[] DEFAULT '{}' CHECK (motivation <@ ARRAY['financial', 'espionage', 'disruption', 'hacktivism', 'terrorism', 'warfare', 'unknown']),
    sophistication_level INTEGER CHECK (sophistication_level BETWEEN 1 AND 5),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    description TEXT,
    ttps TEXT[] DEFAULT '{}',
    country_of_origin VARCHAR(100),
    industries_targeted TEXT[] DEFAULT '{}',
    references TEXT[] DEFAULT '{}',
    context JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_threat_actors_name ON threat_actors(name);
CREATE INDEX idx_threat_actors_motivation ON threat_actors USING GIN(motivation);
CREATE INDEX idx_threat_actors_ttps ON threat_actors USING GIN(ttps);
CREATE INDEX idx_threat_actors_industries ON threat_actors USING GIN(industries_targeted);

-- Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    cvss_score DECIMAL(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_vector VARCHAR(100),
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    affected_products TEXT[] DEFAULT '{}',
    affected_versions TEXT[] DEFAULT '{}',
    remediation TEXT,
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_details TEXT,
    publish_date TIMESTAMP WITH TIME ZONE,
    patch_available BOOLEAN DEFAULT FALSE,
    references TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_affected_products ON vulnerabilities USING GIN(affected_products);

-- Campaigns (Attack Campaigns)
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(20) CHECK (status IN ('active', 'inactive', 'concluded')),
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,
    objectives TEXT,
    description TEXT,
    ttps TEXT[] DEFAULT '{}',
    industries_targeted TEXT[] DEFAULT '{}',
    regions_targeted TEXT[] DEFAULT '{}',
    attribution UUID REFERENCES threat_actors(actor_id),
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_attribution ON campaigns(attribution);
CREATE INDEX idx_campaigns_industries ON campaigns USING GIN(industries_targeted);
CREATE INDEX idx_campaigns_regions ON campaigns USING GIN(regions_targeted);

-- Campaign IOC Association
CREATE TABLE IF NOT EXISTS campaign_iocs (
    campaign_id UUID REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
    ioc_id UUID REFERENCES iocs(ioc_id) ON DELETE CASCADE,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (campaign_id, ioc_id)
);

-- Campaign Vulnerabilities Association
CREATE TABLE IF NOT EXISTS campaign_vulnerabilities (
    campaign_id UUID REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    exploitation_observed BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (campaign_id, vulnerability_id)
);

-- Campaign Timeline Events
CREATE TABLE IF NOT EXISTS campaign_timeline (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
    event_time TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    description TEXT,
    technical_details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_campaign_timeline_campaign ON campaign_timeline(campaign_id);
CREATE INDEX idx_campaign_timeline_event_time ON campaign_timeline(event_time);

-- Feed Sources
CREATE TABLE IF NOT EXISTS feed_sources (
    source_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    url TEXT,
    type VARCHAR(50),
    format VARCHAR(50),
    auth_method VARCHAR(50),
    auth_credentials TEXT ENCRYPTED WITH KEY FROM PGP,
    collection_frequency VARCHAR(50),
    last_collection TIMESTAMP WITH TIME ZONE,
    reliability_score INTEGER CHECK (reliability_score BETWEEN 0 AND 100),
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MITRE ATT&CK Tactics and Techniques
CREATE TABLE IF NOT EXISTS mitre_tactics (
    tactic_id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    url TEXT
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    url TEXT,
    tactics VARCHAR(20)[] DEFAULT '{}'
);

CREATE INDEX idx_mitre_techniques_tactics ON mitre_techniques USING GIN(tactics);

-- Intelligence Reports
CREATE TABLE IF NOT EXISTS intelligence_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    content TEXT,
    tlp VARCHAR(20) CHECK (tlp IN ('white', 'green', 'amber', 'red')),
    confidence_level INTEGER CHECK (confidence_level BETWEEN 0 AND 100),
    source VARCHAR(100),
    publication_date TIMESTAMP WITH TIME ZONE,
    related_campaigns UUID[] DEFAULT '{}',
    related_actors UUID[] DEFAULT '{}',
    related_iocs UUID[] DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100)
);

CREATE INDEX idx_intelligence_reports_tlp ON intelligence_reports(tlp);
CREATE INDEX idx_intelligence_reports_tags ON intelligence_reports USING GIN(tags);
CREATE INDEX idx_intelligence_reports_related_campaigns ON intelligence_reports USING GIN(related_campaigns);
CREATE INDEX idx_intelligence_reports_related_actors ON intelligence_reports USING GIN(related_actors);
CREATE INDEX idx_intelligence_reports_related_iocs ON intelligence_reports USING GIN(related_iocs);

-- Create view for fast lookup of IOCs with related campaigns
CREATE OR REPLACE VIEW iocs_with_campaigns AS
SELECT 
    i.ioc_id, 
    i.type, 
    i.value, 
    i.confidence, 
    i.severity, 
    i.first_seen, 
    i.last_seen,
    i.tags,
    array_agg(DISTINCT c.campaign_id) as campaign_ids,
    array_agg(DISTINCT c.name) as campaign_names
FROM 
    iocs i
LEFT JOIN 
    campaign_iocs ci ON i.ioc_id = ci.ioc_id
LEFT JOIN 
    campaigns c ON ci.campaign_id = c.campaign_id
GROUP BY 
    i.ioc_id;

-- Function to update 'updated_at' timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updating timestamps
CREATE TRIGGER update_iocs_updated_at
    BEFORE UPDATE ON iocs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_actors_updated_at
    BEFORE UPDATE ON threat_actors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vulnerabilities_updated_at
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_campaigns_updated_at
    BEFORE UPDATE ON campaigns
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_feed_sources_updated_at
    BEFORE UPDATE ON feed_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column(); 