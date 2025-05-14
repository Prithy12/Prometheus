/**
 * API Client for NetGuardian Log Collector
 * 
 * Client for interacting with the NetGuardian API Gateway
 */
const axios = require('axios');
const { logger } = require('./logger');

class ApiClient {
  /**
   * Create a new API client
   * 
   * @param {Object} config - API configuration
   * @param {string} config.baseUrl - Base URL of the API Gateway
   * @param {string} config.username - Username for authentication
   * @param {string} config.password - Password for authentication
   * @param {number} config.timeout - Request timeout in milliseconds
   */
  constructor(config) {
    this.config = config;
    this.token = null;
    this.tokenExpiresAt = null;
    
    // Create axios instance
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 5000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'NetGuardian-LogCollector/1.0'
      }
    });
    
    // Add request interceptor for authentication
    this.client.interceptors.request.use(async (request) => {
      // If token is required and not available or expired, get a new one
      if (request.url !== '/api/auth/login' && (!this.token || this.isTokenExpired())) {
        await this.authenticate();
      }
      
      // Add token to request if available
      if (this.token && request.url !== '/api/auth/login') {
        request.headers.Authorization = `Bearer ${this.token}`;
      }
      
      return request;
    });
    
    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      response => response,
      error => {
        if (error.response) {
          // Log API error details
          logger.error({
            status: error.response.status,
            data: error.response.data,
            url: error.config.url
          }, 'API request failed');
          
          // Handle authentication errors
          if (error.response.status === 401 && this.token) {
            this.token = null;
            this.tokenExpiresAt = null;
          }
        } else if (error.request) {
          // Log network error
          logger.error('No response received from API');
        } else {
          // Log request configuration error
          logger.error({ error: error.message }, 'Error configuring API request');
        }
        
        return Promise.reject(error);
      }
    );
  }
  
  /**
   * Check if the authentication token is expired
   * 
   * @returns {boolean} True if the token is expired, false otherwise
   */
  isTokenExpired() {
    if (!this.tokenExpiresAt) return true;
    
    // Add a 5-minute buffer to token expiration
    const bufferTime = 5 * 60 * 1000;
    return Date.now() + bufferTime >= this.tokenExpiresAt;
  }
  
  /**
   * Authenticate with the API Gateway
   * 
   * @returns {Promise<boolean>} True if authentication was successful, false otherwise
   */
  async authenticate() {
    try {
      const response = await this.client.post('/api/auth/login', {
        username: this.config.username,
        password: this.config.password
      });
      
      if (response.data && response.data.data && response.data.data.token) {
        this.token = response.data.data.token;
        
        // Calculate token expiration time
        const expiresIn = response.data.data.expiresIn || 86400; // Default to 24 hours
        this.tokenExpiresAt = Date.now() + (expiresIn * 1000);
        
        logger.info('Successfully authenticated with API Gateway');
        return true;
      }
      
      logger.warn('Authentication response did not contain a token');
      return false;
    } catch (error) {
      logger.error({ error: error.message }, 'Authentication failed');
      return false;
    }
  }
  
  /**
   * Send a security event to the API Gateway
   * 
   * @param {Object} event - Security event data
   * @returns {Promise<Object>} API response
   */
  async sendEvent(event) {
    try {
      const response = await this.client.post('/api/events', event);
      
      logger.debug({
        eventId: response.data?.data?.event_id || 'unknown',
        status: response.status
      }, 'Event sent successfully');
      
      return response.data;
    } catch (error) {
      logger.error({ error: error.message }, 'Failed to send event');
      throw error;
    }
  }
  
  /**
   * Send multiple security events to the API Gateway in batch
   * 
   * @param {Array<Object>} events - Array of security event data
   * @returns {Promise<Object>} API response
   */
  async sendEvents(events) {
    if (!Array.isArray(events) || events.length === 0) {
      logger.warn('No events to send');
      return null;
    }
    
    try {
      const response = await this.client.post('/api/events/batch', events);
      
      logger.debug({
        eventCount: events.length,
        status: response.status
      }, 'Events sent successfully');
      
      return response.data;
    } catch (error) {
      logger.error({ error: error.message, eventCount: events.length }, 'Failed to send events');
      throw error;
    }
  }
}

module.exports = ApiClient; 