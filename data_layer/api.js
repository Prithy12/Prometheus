const EventStoreClient = require('./event_store/client');
const IntelligenceDBClient = require('./intelligence_db/client');
const EvidenceVaultClient = require('./evidence_vault/client');
const schemaService = require('./schema_service');
const logger = require('../utils/logger');

/**
 * NetGuardian Data Layer API
 * Provides a unified interface to all data components
 */
class DataLayerAPI {
  constructor(config = {}) {
    this.config = config;
    this.clients = {};
    
    this._initializeClients();
    
    logger.info('Data Layer API initialized');
  }

  /**
   * Initialize all data layer clients
   * @private
   */
  _initializeClients() {
    try {
      // Initialize Event Store client
      this.clients.eventStore = new EventStoreClient(this.config.eventStore);
      
      // Initialize Intelligence DB client
      this.clients.intelligenceDB = new IntelligenceDBClient(this.config.intelligenceDB);
      
      // Initialize Evidence Vault client
      this.clients.evidenceVault = new EvidenceVaultClient(this.config.evidenceVault);
      
      // Schema Service is already initialized as singleton
      this.clients.schemaService = schemaService;
    } catch (error) {
      logger.error(`Error initializing data layer clients: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Event Store Methods
   * ==============================
   */

  /**
   * Store a security event
   * @param {Object} event Security event to store
   * @returns {Promise<string>} Event ID
   */
  async storeEvent(event) {
    try {
      return await this.clients.eventStore.storeEvent(event);
    } catch (error) {
      logger.error(`Error in Data Layer API - storeEvent: ${error.message}`);
      throw error;
    }
  }

  /**
   * Store multiple security events
   * @param {Array<Object>} events Array of security events
   * @returns {Promise<Array<string>>} Array of event IDs
   */
  async storeEvents(events) {
    try {
      return await this.clients.eventStore.storeEvents(events);
    } catch (error) {
      logger.error(`Error in Data Layer API - storeEvents: ${error.message}`);
      throw error;
    }
  }

  /**
   * Query security events with filters
   * @param {Object} filters Query filters
   * @param {number} limit Maximum number of results
   * @param {number} offset Pagination offset
   * @returns {Promise<Array<Object>>} Security events matching the filters
   */
  async queryEvents(filters = {}, limit = 100, offset = 0) {
    try {
      return await this.clients.eventStore.queryEvents(filters, limit, offset);
    } catch (error) {
      logger.error(`Error in Data Layer API - queryEvents: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get alerts (high severity events)
   * @param {Object} filters Query filters
   * @param {number} limit Maximum number of results
   * @param {number} offset Pagination offset
   * @returns {Promise<Array<Object>>} Alerts matching the filters
   */
  async getAlerts(filters = {}, limit = 100, offset = 0) {
    try {
      return await this.clients.eventStore.getAlerts(filters, limit, offset);
    } catch (error) {
      logger.error(`Error in Data Layer API - getAlerts: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get event summary statistics
   * @param {Object} filters Query filters
   * @returns {Promise<Array<Object>>} Event summary statistics
   */
  async getEventSummary(filters = {}) {
    try {
      return await this.clients.eventStore.getEventSummary(filters);
    } catch (error) {
      logger.error(`Error in Data Layer API - getEventSummary: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Intelligence DB Methods
   * ==============================
   */

  /**
   * Create a new IOC
   * @param {Object} ioc IOC data
   * @returns {Promise<Object>} Created IOC
   */
  async createIOC(ioc) {
    try {
      return await this.clients.intelligenceDB.createIOC(ioc);
    } catch (error) {
      logger.error(`Error in Data Layer API - createIOC: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get IOC by ID
   * @param {string} iocId UUID of the IOC
   * @returns {Promise<Object>} IOC data
   */
  async getIOC(iocId) {
    try {
      return await this.clients.intelligenceDB.getIOC(iocId);
    } catch (error) {
      logger.error(`Error in Data Layer API - getIOC: ${error.message}`);
      throw error;
    }
  }

  /**
   * Update an IOC
   * @param {string} iocId UUID of the IOC
   * @param {Object} updateData Data to update
   * @returns {Promise<Object>} Updated IOC
   */
  async updateIOC(iocId, updateData) {
    try {
      return await this.clients.intelligenceDB.updateIOC(iocId, updateData);
    } catch (error) {
      logger.error(`Error in Data Layer API - updateIOC: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete an IOC
   * @param {string} iocId UUID of the IOC
   * @returns {Promise<boolean>} Success status
   */
  async deleteIOC(iocId) {
    try {
      return await this.clients.intelligenceDB.deleteIOC(iocId);
    } catch (error) {
      logger.error(`Error in Data Layer API - deleteIOC: ${error.message}`);
      throw error;
    }
  }

  /**
   * Search for IOCs with filtering options
   * @param {Object} filters Filtering criteria
   * @param {number} limit Maximum number of results
   * @param {number} offset Pagination offset
   * @returns {Promise<Array<Object>>} IOCs matching the filters
   */
  async searchIOCs(filters = {}, limit = 100, offset = 0) {
    try {
      return await this.clients.intelligenceDB.searchIOCs(filters, limit, offset);
    } catch (error) {
      logger.error(`Error in Data Layer API - searchIOCs: ${error.message}`);
      throw error;
    }
  }

  /**
   * Create a new threat actor
   * @param {Object} actor Threat actor data
   * @returns {Promise<Object>} Created threat actor
   */
  async createThreatActor(actor) {
    try {
      return await this.clients.intelligenceDB.createThreatActor(actor);
    } catch (error) {
      logger.error(`Error in Data Layer API - createThreatActor: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get threat actor by ID
   * @param {string} actorId UUID of the threat actor
   * @returns {Promise<Object>} Threat actor data
   */
  async getThreatActor(actorId) {
    try {
      return await this.clients.intelligenceDB.getThreatActor(actorId);
    } catch (error) {
      logger.error(`Error in Data Layer API - getThreatActor: ${error.message}`);
      throw error;
    }
  }

  /**
   * Create a new vulnerability
   * @param {Object} vulnerability Vulnerability data
   * @returns {Promise<Object>} Created vulnerability
   */
  async createVulnerability(vulnerability) {
    try {
      return await this.clients.intelligenceDB.createVulnerability(vulnerability);
    } catch (error) {
      logger.error(`Error in Data Layer API - createVulnerability: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get vulnerability by CVE ID
   * @param {string} cveId CVE ID of the vulnerability
   * @returns {Promise<Object>} Vulnerability data
   */
  async getVulnerabilityByCVE(cveId) {
    try {
      return await this.clients.intelligenceDB.getVulnerabilityByCVE(cveId);
    } catch (error) {
      logger.error(`Error in Data Layer API - getVulnerabilityByCVE: ${error.message}`);
      throw error;
    }
  }

  /**
   * Create a new campaign
   * @param {Object} campaign Campaign data
   * @returns {Promise<Object>} Created campaign
   */
  async createCampaign(campaign) {
    try {
      return await this.clients.intelligenceDB.createCampaign(campaign);
    } catch (error) {
      logger.error(`Error in Data Layer API - createCampaign: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get campaign by ID with related IOCs and timeline
   * @param {string} campaignId UUID of the campaign
   * @returns {Promise<Object>} Campaign data with related entities
   */
  async getCampaign(campaignId) {
    try {
      return await this.clients.intelligenceDB.getCampaign(campaignId);
    } catch (error) {
      logger.error(`Error in Data Layer API - getCampaign: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Evidence Vault Methods
   * ==============================
   */

  /**
   * Store evidence with encryption and chain-of-custody tracking
   * @param {Buffer|string} data Evidence data or file path
   * @param {Object} metadata Evidence metadata
   * @param {string} user User storing the evidence
   * @returns {Promise<Object>} Evidence ID and metadata
   */
  async storeEvidence(data, metadata, user) {
    try {
      return await this.clients.evidenceVault.storeEvidence(data, metadata, user);
    } catch (error) {
      logger.error(`Error in Data Layer API - storeEvidence: ${error.message}`);
      throw error;
    }
  }

  /**
   * Retrieve evidence with decryption and chain-of-custody tracking
   * @param {string} evidenceId Evidence ID
   * @param {string} user User retrieving the evidence
   * @param {string} outputPath Optional path to save the decrypted evidence
   * @returns {Promise<Object>} Evidence data and metadata
   */
  async retrieveEvidence(evidenceId, user, outputPath = null) {
    try {
      return await this.clients.evidenceVault.retrieveEvidence(evidenceId, user, outputPath);
    } catch (error) {
      logger.error(`Error in Data Layer API - retrieveEvidence: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get metadata for evidence without retrieving the actual data
   * @param {string} evidenceId Evidence ID
   * @returns {Promise<Object>} Evidence metadata
   */
  async getEvidenceMetadata(evidenceId) {
    try {
      return await this.clients.evidenceVault.getEvidenceMetadata(evidenceId);
    } catch (error) {
      logger.error(`Error in Data Layer API - getEvidenceMetadata: ${error.message}`);
      throw error;
    }
  }

  /**
   * Search for evidence by metadata
   * @param {Object} filters Search filters
   * @returns {Promise<Array<Object>>} Evidence items matching the filters
   */
  async searchEvidence(filters = {}) {
    try {
      return await this.clients.evidenceVault.searchEvidence(filters);
    } catch (error) {
      logger.error(`Error in Data Layer API - searchEvidence: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get the chain of custody for evidence
   * @param {string} evidenceId Evidence ID
   * @returns {Promise<Array<Object>>} Chain of custody entries
   */
  async getChainOfCustody(evidenceId) {
    try {
      return await this.clients.evidenceVault.getChainOfCustody(evidenceId);
    } catch (error) {
      logger.error(`Error in Data Layer API - getChainOfCustody: ${error.message}`);
      throw error;
    }
  }

  /**
   * Add a custody event to evidence
   * @param {string} evidenceId Evidence ID
   * @param {string} action Action performed
   * @param {string} user User performing the action
   * @param {string} description Description of the action
   * @returns {Promise<Object>} Updated metadata
   */
  async addCustodyEvent(evidenceId, action, user, description) {
    try {
      return await this.clients.evidenceVault.addCustodyEvent(evidenceId, action, user, description);
    } catch (error) {
      logger.error(`Error in Data Layer API - addCustodyEvent: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Schema Service Methods
   * ==============================
   */

  /**
   * Get a schema by name
   * @param {string} schemaName Name of the schema (without .proto extension)
   * @returns {Object} Schema definition
   */
  getSchema(schemaName) {
    try {
      return this.clients.schemaService.getSchema(schemaName);
    } catch (error) {
      logger.error(`Error in Data Layer API - getSchema: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get schema version information
   * @param {string} schemaName Name of the schema
   * @returns {Object} Version information
   */
  getSchemaVersion(schemaName) {
    try {
      return this.clients.schemaService.getSchemaVersion(schemaName);
    } catch (error) {
      logger.error(`Error in Data Layer API - getSchemaVersion: ${error.message}`);
      throw error;
    }
  }

  /**
   * Check if a message is compatible with current schema version
   * @param {string} schemaName Name of the schema
   * @param {Object} message Message containing schema_version field
   * @returns {boolean} Whether the message is compatible
   */
  isSchemaCompatible(schemaName, message) {
    try {
      return this.clients.schemaService.isCompatible(schemaName, message);
    } catch (error) {
      logger.error(`Error in Data Layer API - isSchemaCompatible: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get the current schema version object for a new message
   * @param {string} schemaName Name of the schema
   * @returns {Object} Schema version object
   */
  getCurrentSchemaVersion(schemaName) {
    try {
      return this.clients.schemaService.getCurrentVersionObject(schemaName);
    } catch (error) {
      logger.error(`Error in Data Layer API - getCurrentSchemaVersion: ${error.message}`);
      throw error;
    }
  }

  /**
   * Check connections to all data stores
   * @returns {Promise<Object>} Connection status for each data store
   */
  async checkConnections() {
    try {
      const results = {
        eventStore: false,
        intelligenceDB: false,
        evidenceVault: false // No direct way to check S3 connection, would need custom implementation
      };
      
      // Check EventStore
      try {
        results.eventStore = await this.clients.eventStore.checkConnection();
      } catch (error) {
        logger.error(`EventStore connection check failed: ${error.message}`);
      }
      
      // Check IntelligenceDB
      try {
        results.intelligenceDB = await this.clients.intelligenceDB.checkConnection();
      } catch (error) {
        logger.error(`IntelligenceDB connection check failed: ${error.message}`);
      }
      
      return results;
    } catch (error) {
      logger.error(`Error checking connections: ${error.message}`);
      throw error;
    }
  }

  /**
   * Close all client connections
   */
  async close() {
    try {
      // Close Intelligence DB connections
      if (this.clients.intelligenceDB) {
        await this.clients.intelligenceDB.close();
      }
      
      logger.info('All data layer connections closed');
    } catch (error) {
      logger.error(`Error closing connections: ${error.message}`);
      throw error;
    }
  }
}

module.exports = DataLayerAPI; 