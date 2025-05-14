/**
 * NetGuardian Log Collector
 * 
 * This service monitors log files and directories, processes log entries,
 * and forwards security events to the Event Store via the API Gateway.
 */
require('dotenv').config();
const { logger } = require('./utils/logger');
const { initializeWatchers } = require('./utils/watcher');
const ApiClient = require('./utils/apiClient');
const config = require('./config');

// Global state
let isShuttingDown = false;
const apiClient = new ApiClient(config.api);

/**
 * Initialize the log collector service
 */
async function initialize() {
  logger.info('Starting NetGuardian Log Collector...');
  
  try {
    // Authenticate with API Gateway
    logger.info('Authenticating with API Gateway...');
    const authenticated = await apiClient.authenticate();
    if (!authenticated) {
      logger.error('Failed to authenticate with API Gateway. Check credentials and try again.');
      process.exit(1);
    }
    
    // Initialize file watchers for configured log sources
    logger.info(`Initializing watchers for ${config.logSources.length} log sources...`);
    initializeWatchers(config.logSources, processLogEntry);
    
    logger.info('NetGuardian Log Collector started successfully');
  } catch (error) {
    logger.error({ error }, 'Failed to initialize Log Collector');
    process.exit(1);
  }
}

/**
 * Process a log entry from any source
 * 
 * @param {Object} entry - The log entry
 * @param {string} entry.source - Source of the log (e.g., 'apache', 'syslog')
 * @param {string} entry.content - Raw log content
 * @param {Object} entry.metadata - Additional metadata about the log
 */
async function processLogEntry(entry) {
  if (isShuttingDown) return;
  
  try {
    logger.debug({ source: entry.source }, 'Processing log entry');
    
    // Get the appropriate parser for this log source
    const parser = require(`./parsers/${entry.source}`);
    
    // Parse the log entry
    const parsedEntry = await parser.parse(entry.content, entry.metadata);
    if (!parsedEntry) {
      logger.debug({ source: entry.source }, 'Log entry ignored - no match');
      return;
    }
    
    // Transform the parsed entry into a security event
    const transformer = require('./transformers/eventTransformer');
    const securityEvent = transformer.transform(parsedEntry, entry.source);
    
    // If a security event was generated, send it to the API Gateway
    if (securityEvent) {
      logger.info({ 
        source: entry.source, 
        eventType: securityEvent.event_type,
        severity: securityEvent.severity
      }, 'Security event generated');
      
      await apiClient.sendEvent(securityEvent);
    }
  } catch (error) {
    logger.error({ error, source: entry.source }, 'Error processing log entry');
  }
}

/**
 * Graceful shutdown
 */
function shutdown() {
  if (isShuttingDown) return;
  isShuttingDown = true;
  
  logger.info('Shutting down NetGuardian Log Collector...');
  
  // Perform cleanup operations
  
  // Exit process
  process.exit(0);
}

// Handle shutdown signals
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error({ error }, 'Uncaught exception');
  shutdown();
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error({ reason }, 'Unhandled promise rejection');
  shutdown();
});

// Start the application
initialize(); 