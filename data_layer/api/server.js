const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const DataLayerAPI = require('../api');
const logger = require('../../utils/logger');

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Configure API security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Initialize Data Layer API
const dataLayer = new DataLayerAPI({
  eventStore: {
    host: process.env.CLICKHOUSE_HOST || 'event-store',
    port: process.env.CLICKHOUSE_PORT || 8123,
    user: process.env.CLICKHOUSE_USER || 'netguardian',
    password: process.env.CLICKHOUSE_PASSWORD || 'netguardian_secure_password',
    database: process.env.CLICKHOUSE_DB || 'security_events'
  },
  intelligenceDB: {
    host: process.env.POSTGRES_HOST || 'intelligence-db',
    port: process.env.POSTGRES_PORT || 5432,
    user: process.env.POSTGRES_USER || 'netguardian',
    password: process.env.POSTGRES_PASSWORD || 'netguardian_secure_password',
    database: process.env.POSTGRES_DB || 'intelligence_db',
    ssl: process.env.POSTGRES_SSL === 'true'
  },
  evidenceVault: {
    endpoint: process.env.S3_ENDPOINT || 'http://evidence-vault:9000',
    accessKeyId: process.env.S3_ACCESS_KEY || 'minioadmin',
    secretAccessKey: process.env.S3_SECRET_KEY || 'minioadmin',
    bucketName: process.env.S3_BUCKET || 'evidence-vault',
    region: process.env.S3_REGION || 'us-east-1',
    encryptionKey: process.env.ENCRYPTION_KEY
  }
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const status = await dataLayer.checkConnections();
    return res.status(200).json({
      status: 'ok',
      version: '1.0',
      services: status
    });
  } catch (error) {
    logger.error(`Health check failed: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Service health check failed',
      error: error.message
    });
  }
});

// ------------------
// Event Store Routes
// ------------------
app.post('/events', async (req, res) => {
  try {
    const eventId = await dataLayer.storeEvent(req.body);
    return res.status(201).json({ eventId });
  } catch (error) {
    logger.error(`Error storing event: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.post('/events/batch', async (req, res) => {
  try {
    const eventIds = await dataLayer.storeEvents(req.body);
    return res.status(201).json({ eventIds });
  } catch (error) {
    logger.error(`Error storing events: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/events', async (req, res) => {
  try {
    const { limit = 100, offset = 0, ...filters } = req.query;
    const events = await dataLayer.queryEvents(filters, parseInt(limit), parseInt(offset));
    return res.status(200).json(events);
  } catch (error) {
    logger.error(`Error querying events: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/alerts', async (req, res) => {
  try {
    const { limit = 100, offset = 0, ...filters } = req.query;
    const alerts = await dataLayer.getAlerts(filters, parseInt(limit), parseInt(offset));
    return res.status(200).json(alerts);
  } catch (error) {
    logger.error(`Error getting alerts: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/events/summary', async (req, res) => {
  try {
    const summary = await dataLayer.getEventSummary(req.query);
    return res.status(200).json(summary);
  } catch (error) {
    logger.error(`Error getting event summary: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

// -----------------------
// Intelligence DB Routes
// -----------------------
app.post('/intel/iocs', async (req, res) => {
  try {
    const ioc = await dataLayer.createIOC(req.body);
    return res.status(201).json(ioc);
  } catch (error) {
    logger.error(`Error creating IOC: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/intel/iocs/:iocId', async (req, res) => {
  try {
    const ioc = await dataLayer.getIOC(req.params.iocId);
    if (!ioc) {
      return res.status(404).json({ error: 'IOC not found' });
    }
    return res.status(200).json(ioc);
  } catch (error) {
    logger.error(`Error getting IOC: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/intel/iocs', async (req, res) => {
  try {
    const { limit = 100, offset = 0, ...filters } = req.query;
    const iocs = await dataLayer.searchIOCs(filters, parseInt(limit), parseInt(offset));
    return res.status(200).json(iocs);
  } catch (error) {
    logger.error(`Error searching IOCs: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

// ----------------------
// Evidence Vault Routes
// ----------------------
app.post('/evidence', async (req, res) => {
  try {
    if (!req.body.data || !req.body.metadata || !req.body.user) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const result = await dataLayer.storeEvidence(
      Buffer.from(req.body.data, 'base64'),
      req.body.metadata,
      req.body.user
    );
    
    return res.status(201).json(result);
  } catch (error) {
    logger.error(`Error storing evidence: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/evidence/:evidenceId', async (req, res) => {
  try {
    const metadata = await dataLayer.getEvidenceMetadata(req.params.evidenceId);
    return res.status(200).json(metadata);
  } catch (error) {
    logger.error(`Error getting evidence metadata: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/evidence/:evidenceId/download', async (req, res) => {
  try {
    const evidence = await dataLayer.retrieveEvidence(
      req.params.evidenceId,
      req.query.user || 'system'
    );
    
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename=${req.params.evidenceId}`);
    return res.status(200).send(evidence.data);
  } catch (error) {
    logger.error(`Error downloading evidence: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/evidence/:evidenceId/chain', async (req, res) => {
  try {
    const chain = await dataLayer.getChainOfCustody(req.params.evidenceId);
    return res.status(200).json(chain);
  } catch (error) {
    logger.error(`Error getting chain of custody: ${error.message}`);
    return res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(port, () => {
  logger.info(`Data Layer API Server running on port ${port}`);
}); 