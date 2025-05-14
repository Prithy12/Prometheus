/**
 * Configuration for NetGuardian Log Collector
 * 
 * Central configuration file that loads settings from environment variables
 * and default configuration files
 */
const path = require('path');
const fs = require('fs');
const { logger } = require('../utils/logger');

// Default API configuration
const defaultApiConfig = {
  baseUrl: process.env.API_GATEWAY_URL || 'http://localhost:5000',
  username: process.env.API_USERNAME || 'log-collector',
  password: process.env.API_PASSWORD || 'collector123',
  timeout: parseInt(process.env.API_TIMEOUT || '5000', 10)
};

// Default log sources
const defaultLogSources = [
  {
    name: 'System Authentication Logs',
    type: 'file',
    format: 'syslog',
    path: process.env.AUTH_LOG_PATH || '/var/log/auth.log',
    fromBeginning: process.env.PROCESS_EXISTING === 'true'
  },
  {
    name: 'Apache Access Logs',
    type: 'file',
    format: 'apache',
    path: process.env.APACHE_LOG_PATH || '/var/log/apache2/access.log',
    fromBeginning: process.env.PROCESS_EXISTING === 'true'
  },
  {
    name: 'Firewall Logs',
    type: 'file',
    format: 'firewall',
    path: process.env.FIREWALL_LOG_PATH || '/var/log/iptables.log',
    fromBeginning: process.env.PROCESS_EXISTING === 'true'
  },
  {
    name: 'Security Event Logs',
    type: 'directory',
    format: 'json',
    path: process.env.SECURITY_LOG_DIR || '/var/log/security',
    pattern: '*.json',
    processExisting: process.env.PROCESS_EXISTING === 'true'
  }
];

// Try to load custom configuration from file
let customConfig = {};
try {
  const configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'config.json');
  if (fs.existsSync(configPath)) {
    const configData = fs.readFileSync(configPath, 'utf8');
    customConfig = JSON.parse(configData);
    logger.info({ configPath }, 'Loaded custom configuration');
  }
} catch (error) {
  logger.warn({ error }, 'Failed to load custom configuration');
}

// Merge default and custom configurations
const config = {
  api: {
    ...defaultApiConfig,
    ...customConfig.api
  },
  logSources: customConfig.logSources || defaultLogSources,
  batchSize: parseInt(process.env.BATCH_SIZE || customConfig.batchSize || '100', 10),
  batchInterval: parseInt(process.env.BATCH_INTERVAL || customConfig.batchInterval || '30000', 10),
  eventRetentionTime: parseInt(process.env.EVENT_RETENTION_TIME || customConfig.eventRetentionTime || '86400000', 10), // 24 hours
  retryLimit: parseInt(process.env.RETRY_LIMIT || customConfig.retryLimit || '5', 10),
  retryDelay: parseInt(process.env.RETRY_DELAY || customConfig.retryDelay || '10000', 10) // 10 seconds
};

// Filter out log sources with invalid configurations
config.logSources = config.logSources.filter(source => {
  // Check required fields
  if (!source.type || !source.format || !source.path) {
    logger.warn({ source }, 'Skipping log source due to missing required fields');
    return false;
  }
  
  // Skip sources that don't exist in the filesystem
  try {
    if (!fs.existsSync(source.path)) {
      logger.warn({ path: source.path }, 'Log source path does not exist, skipping');
      return false;
    }
  } catch (error) {
    logger.error({ error, path: source.path }, 'Error checking log source path');
    return false;
  }
  
  return true;
});

// Log the configuration (redacting sensitive information)
logger.info({
  api: {
    baseUrl: config.api.baseUrl,
    username: config.api.username,
    timeout: config.api.timeout
  },
  logSourceCount: config.logSources.length,
  batchSize: config.batchSize,
  batchInterval: config.batchInterval
}, 'Log collector configuration');

module.exports = config; 