-- NetGuardian Event Store Schema
-- Using ClickHouse for high-performance event storage

-- Security Events table
CREATE TABLE IF NOT EXISTS security_events
(
    event_id String,
    timestamp DateTime64(3),
    source_ip String,
    source_port UInt16,
    destination_ip String,
    destination_port UInt16,
    protocol String,
    event_type Enum('intrusion_attempt' = 1, 'malware_detection' = 2, 'reconnaissance' = 3, 'data_exfiltration' = 4, 'credential_access' = 5, 'lateral_movement' = 6, 'privilege_escalation' = 7, 'persistence' = 8, 'defense_evasion' = 9, 'command_and_control' = 10, 'impact' = 11, 'other' = 12),
    severity UInt8 COMMENT 'Range from 1 (lowest) to 10 (highest)',
    confidence UInt8 COMMENT 'Range from 1 (lowest) to 10 (highest)',
    description String,
    raw_data String COMMENT 'JSON formatted raw event data',
    processed_by String COMMENT 'ID of the processing component',
    network_segment String,
    asset_id String,
    ttl Date DEFAULT toDate(timestamp) + toIntervalDay(90) COMMENT 'Time to live - 90 days',
    INDEX severity_idx severity TYPE minmax GRANULARITY 1,
    INDEX event_type_idx event_type TYPE set(0) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event_type, source_ip, destination_ip)
TTL timestamp + INTERVAL 90 DAY;

-- Materialized View for alerts (high severity events)
CREATE MATERIALIZED VIEW IF NOT EXISTS security_alerts
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, event_type)
TTL timestamp + INTERVAL 90 DAY
AS SELECT
    event_id,
    timestamp,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    protocol,
    event_type,
    severity,
    confidence,
    description,
    network_segment,
    asset_id
FROM security_events
WHERE severity >= 7;

-- Aggregated Events Summary - Updated hourly
CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_event_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, event_type, network_segment)
TTL hour + INTERVAL 90 DAY
AS SELECT
    toStartOfHour(timestamp) AS hour,
    event_type,
    network_segment,
    count() AS event_count,
    min(severity) AS min_severity,
    max(severity) AS max_severity,
    avg(severity) AS avg_severity
FROM security_events
GROUP BY
    hour,
    event_type,
    network_segment;

-- Event blacklist - For suppressing false positives
CREATE TABLE IF NOT EXISTS event_blacklist
(
    rule_id String,
    source_ip_pattern String,
    destination_ip_pattern String,
    event_type Enum('intrusion_attempt' = 1, 'malware_detection' = 2, 'reconnaissance' = 3, 'data_exfiltration' = 4, 'credential_access' = 5, 'lateral_movement' = 6, 'privilege_escalation' = 7, 'persistence' = 8, 'defense_evasion' = 9, 'command_and_control' = 10, 'impact' = 11, 'other' = 12),
    reason String,
    created_at DateTime DEFAULT now(),
    created_by String,
    expires_at DateTime
) ENGINE = MergeTree()
ORDER BY (rule_id, event_type); 