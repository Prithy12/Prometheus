# NetGuardian Data Layer

The Data Layer is responsible for storing, retrieving, and managing all security-related data in the NetGuardian platform. It provides a unified API for other layers to interact with various data stores.

## Components

### Event Store

The Event Store is built on ClickHouse, a high-performance column-oriented DBMS, optimized for real-time analytics of security events. It provides:

- High-speed ingestion of security events
- Partitioning by month for optimal performance
- 90-day TTL for automatic data lifecycle management
- Materialized views for alerts and statistical aggregations
- Real-time querying capabilities across massive datasets

### Intelligence DB

The Intelligence DB is powered by PostgreSQL and provides structured storage for threat intelligence:

- Indicators of Compromise (IOCs) with confidence scoring and context
- Threat Actor profiles with TTPs and attribution details
- Vulnerability records with CVE information and CVSS scores
- Campaign tracking with timeline and attribution
- Intelligence reports with TLP classification

### Evidence Vault

The Evidence Vault provides secure, encrypted storage for forensic evidence using S3-compatible object storage:

- AES-256-GCM encryption for all stored evidence
- Digital signatures for evidence integrity verification
- Comprehensive chain-of-custody tracking
- Metadata searching and filtering
- Support for multiple evidence types (PCAP, logs, memory dumps, etc.)

### Schema Service

The Schema Service uses Protocol Buffers (protobuf) to provide strongly-typed schema definitions for:

- Security events and alerts
- Threat intelligence objects
- Response actions and playbooks

It supports versioning for backward compatibility and standardized message formats across the platform.

## Architecture

```
                   +-------------------+
                   |                   |
                   |  Data Layer API   |
                   |                   |
                   +-------------------+
                          |   |   |
             +------------+   |   +------------+
             |                |                |
+------------------------+    |    +------------------------+
|                        |    |    |                        |
|  Event Store           |    |    |  Intelligence DB       |
|  (ClickHouse)          |    |    |  (PostgreSQL)          |
|                        |    |    |                        |
+------------------------+    |    +------------------------+
                              |
              +---------------+---------------+
              |                               |
+------------------------+    +------------------------+
|                        |    |                        |
|  Evidence Vault        |    |  Schema Service        |
|  (S3 Compatible)       |    |  (Protocol Buffers)    |
|                        |    |                        |
+------------------------+    +------------------------+
```

## Usage

The Data Layer provides a unified API that can be accessed through the `DataLayerAPI` class:

```javascript
const DataLayerAPI = require('./data_layer/api');

// Initialize the API with configuration
const dataLayer = new DataLayerAPI({
  eventStore: {
    url: 'http://clickhouse:8123',
    user: 'netguardian',
    password: 'password'
  },
  intelligenceDB: {
    host: 'postgres',
    database: 'intelligence_db',
    user: 'netguardian',
    password: 'password'
  },
  evidenceVault: {
    endpoint: 'http://minio:9000',
    accessKeyId: 'minioadmin',
    secretAccessKey: 'minioadmin'
  }
});

// Store a security event
const eventId = await dataLayer.storeEvent({
  source_ip: '192.168.1.100',
  destination_ip: '10.0.0.1',
  event_type: 'intrusion_attempt',
  severity: 8,
  description: 'Potential SQL injection attempt'
});

// Retrieve threat intelligence
const iocs = await dataLayer.searchIOCs({ 
  type: 'ip', 
  minSeverity: 7 
});

// Store encrypted evidence with chain-of-custody
const evidence = await dataLayer.storeEvidence(
  pcapBuffer,
  {
    type: 'pcap',
    description: 'Network capture during incident',
    caseId: 'INC-2023-001'
  },
  'security-analyst'
);
```

## Configuration

Each component can be configured through environment variables or configuration objects:

### Event Store

- `CLICKHOUSE_URL`: ClickHouse server URL (default: `http://localhost:8123`)
- `CLICKHOUSE_USER`: Username (default: `netguardian`)
- `CLICKHOUSE_PASSWORD`: Password (default: `netguardian`)
- `CLICKHOUSE_DATABASE`: Database name (default: `default`)

### Intelligence DB

- `PG_HOST`: PostgreSQL host (default: `localhost`)
- `PG_PORT`: PostgreSQL port (default: `5432`)
- `PG_DATABASE`: Database name (default: `intelligence_db`)
- `PG_USER`: Username (default: `netguardian`)
- `PG_PASSWORD`: Password (default: `netguardian_secure_password`)
- `PG_MAX_CONNECTIONS`: Maximum connections (default: `20`)

### Evidence Vault

- `S3_ENDPOINT`: S3-compatible endpoint (default: `http://localhost:9000`)
- `S3_REGION`: S3 region (default: `us-east-1`)
- `S3_ACCESS_KEY`: Access key (default: `minioadmin`)
- `S3_SECRET_KEY`: Secret key (default: `minioadmin`)
- `S3_BUCKET`: Bucket name (default: `evidence-vault`)
- `ENCRYPTION_KEY`: AES-256 encryption key (32 bytes)

## Data Persistence

All components use Docker volumes for data persistence:

- Event Store: `/var/lib/clickhouse`
- Intelligence DB: `/var/lib/postgresql/data`
- Evidence Vault: S3 bucket storage
