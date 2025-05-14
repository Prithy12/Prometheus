/**
 * Data Layer API client
 * 
 * Provides methods to interact with the Data Layer API services
 */
const axios = require('axios');
const { logger } = require('./logger');

// Default configuration
const DEFAULT_CONFIG = {
  baseURL: process.env.DATA_LAYER_API_URL || 'http://data-layer-api:3000',
  timeout: parseInt(process.env.API_TIMEOUT || '5000', 10),
  headers: {
    'Content-Type': 'application/json',
  },
};

/**
 * Data Layer API client
 */
class DataLayerClient {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.client = axios.create(this.config);
    
    // Add request interceptor for logging
    this.client.interceptors.request.use((request) => {
      logger.debug({
        url: `${request.baseURL}${request.url}`,
        method: request.method,
        params: request.params,
      }, 'Outgoing request to Data Layer API');
      return request;
    });
    
    // Add response interceptor for logging and error handling
    this.client.interceptors.response.use(
      (response) => {
        logger.debug({
          url: response.config.url,
          status: response.status,
          statusText: response.statusText,
        }, 'Response from Data Layer API');
        return response.data;
      },
      (error) => {
        const status = error.response ? error.response.status : null;
        const data = error.response ? error.response.data : null;
        
        logger.error({
          url: error.config ? error.config.url : 'unknown',
          status,
          data,
          error: error.message,
        }, 'Error response from Data Layer API');
        
        // Format error for better handling
        const formattedError = new Error(
          data?.message || data?.error || error.message || 'Unknown error'
        );
        formattedError.status = status || 500;
        formattedError.data = data;
        formattedError.original = error;
        
        throw formattedError;
      }
    );
  }

  /*
   * Event Store Methods
   */
  
  /**
   * Store a security event
   * @param {Object} event - Security event data
   * @returns {Promise<Object>} Stored event with ID
   */
  async storeEvent(event) {
    return this.client.post('/events', event);
  }
  
  /**
   * Store multiple security events
   * @param {Array<Object>} events - Array of security event data
   * @returns {Promise<Object>} Result with IDs
   */
  async storeEvents(events) {
    return this.client.post('/events/batch', events);
  }
  
  /**
   * Get events with optional filtering
   * @param {Object} filters - Filter parameters
   * @param {number} limit - Max number of results
   * @param {number} offset - Pagination offset
   * @returns {Promise<Array<Object>>} Security events
   */
  async getEvents(filters = {}, limit = 100, offset = 0) {
    return this.client.get('/events', {
      params: { ...filters, limit, offset },
    });
  }
  
  /**
   * Get security alerts (high severity events)
   * @param {Object} filters - Filter parameters
   * @param {number} limit - Max number of results
   * @param {number} offset - Pagination offset
   * @returns {Promise<Array<Object>>} Security alerts
   */
  async getAlerts(filters = {}, limit = 100, offset = 0) {
    return this.client.get('/alerts', {
      params: { ...filters, limit, offset },
    });
  }
  
  /**
   * Get event summary statistics
   * @param {Object} filters - Filter parameters
   * @returns {Promise<Object>} Event summary statistics
   */
  async getEventSummary(filters = {}) {
    return this.client.get('/events/summary', {
      params: filters,
    });
  }
  
  /*
   * Intelligence DB Methods
   */
  
  /**
   * Create a new IOC
   * @param {Object} ioc - IOC data
   * @returns {Promise<Object>} Created IOC
   */
  async createIOC(ioc) {
    return this.client.post('/intel/iocs', ioc);
  }
  
  /**
   * Get an IOC by ID
   * @param {string} iocId - IOC ID
   * @returns {Promise<Object>} IOC data
   */
  async getIOC(iocId) {
    return this.client.get(`/intel/iocs/${iocId}`);
  }
  
  /**
   * Search for IOCs with filtering
   * @param {Object} filters - Filter parameters
   * @param {number} limit - Max number of results
   * @param {number} offset - Pagination offset
   * @returns {Promise<Array<Object>>} IOCs
   */
  async searchIOCs(filters = {}, limit = 100, offset = 0) {
    return this.client.get('/intel/iocs', {
      params: { ...filters, limit, offset },
    });
  }
  
  /*
   * Evidence Vault Methods
   */
  
  /**
   * Store evidence
   * @param {Buffer|string} data - Evidence data
   * @param {Object} metadata - Evidence metadata
   * @param {string} user - User storing the evidence
   * @returns {Promise<Object>} Stored evidence metadata
   */
  async storeEvidence(data, metadata, user) {
    // Convert data to base64 if it's a Buffer
    const base64Data = Buffer.isBuffer(data) 
      ? data.toString('base64')
      : Buffer.from(data).toString('base64');
    
    return this.client.post('/evidence', {
      data: base64Data,
      metadata,
      user,
    });
  }
  
  /**
   * Get evidence metadata
   * @param {string} evidenceId - Evidence ID
   * @returns {Promise<Object>} Evidence metadata
   */
  async getEvidenceMetadata(evidenceId) {
    return this.client.get(`/evidence/${evidenceId}`);
  }
  
  /**
   * Download evidence
   * @param {string} evidenceId - Evidence ID
   * @param {string} user - User downloading the evidence
   * @returns {Promise<Buffer>} Evidence data
   */
  async downloadEvidence(evidenceId, user) {
    return this.client.get(`/evidence/${evidenceId}/download`, {
      params: { user },
      responseType: 'arraybuffer',
    });
  }
  
  /**
   * Get evidence chain of custody
   * @param {string} evidenceId - Evidence ID
   * @returns {Promise<Array<Object>>} Chain of custody events
   */
  async getChainOfCustody(evidenceId) {
    return this.client.get(`/evidence/${evidenceId}/chain`);
  }
  
  /**
   * Check the health of the Data Layer API
   * @returns {Promise<Object>} Health status
   */
  async checkHealth() {
    return this.client.get('/health');
  }
}

// Create singleton instance
const dataLayerClient = new DataLayerClient();

module.exports = {
  dataLayerClient,
  DataLayerClient,
}; 