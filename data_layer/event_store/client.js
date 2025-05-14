const { ClickHouse } = require('clickhouse');
const { v4: uuidv4 } = require('uuid');
const logger = require('../../utils/logger');

/**
 * EventStore client for ClickHouse database
 * Handles storing and querying security events
 */
class EventStoreClient {
  constructor(config = {}) {
    this.config = {
      url: config.url || process.env.CLICKHOUSE_URL || 'http://localhost:8123',
      user: config.user || process.env.CLICKHOUSE_USER || 'netguardian',
      password: config.password || process.env.CLICKHOUSE_PASSWORD || 'netguardian',
      database: config.database || process.env.CLICKHOUSE_DATABASE || 'default',
      basicAuth: config.basicAuth || {
        username: config.user || process.env.CLICKHOUSE_USER || 'netguardian',
        password: config.password || process.env.CLICKHOUSE_PASSWORD || 'netguardian',
      },
      isUseGzip: true,
      format: 'json',
      raw: false,
      debug: process.env.NODE_ENV === 'development',
      ...config
    };

    this.clickhouse = new ClickHouse(this.config);
    this.tableName = 'security_events';
    this.alertsView = 'security_alerts';
    this.summaryView = 'hourly_event_summary';
    this.blacklistTable = 'event_blacklist';
    
    logger.info('EventStore client initialized');
  }

  /**
   * Store a security event in ClickHouse
   * @param {Object} event Security event to store
   * @returns {Promise<string>} Event ID
   */
  async storeEvent(event) {
    try {
      const eventId = event.event_id || uuidv4();
      const timestamp = event.timestamp || new Date().toISOString();

      const formattedEvent = {
        event_id: eventId,
        timestamp: timestamp,
        source_ip: event.source_ip || '',
        source_port: event.source_port || 0,
        destination_ip: event.destination_ip || '',
        destination_port: event.destination_port || 0,
        protocol: event.protocol || '',
        event_type: event.event_type || 'other',
        severity: event.severity || 1,
        confidence: event.confidence || 1,
        description: event.description || '',
        raw_data: event.raw_data ? JSON.stringify(event.raw_data) : '{}',
        processed_by: event.processed_by || '',
        network_segment: event.network_segment || '',
        asset_id: event.asset_id || ''
      };

      await this.clickhouse.insert(this.tableName, [formattedEvent]).toPromise();
      logger.info(`Event stored with ID: ${eventId}`);
      return eventId;
    } catch (error) {
      logger.error(`Error storing event: ${error.message}`);
      throw error;
    }
  }

  /**
   * Store multiple security events in ClickHouse
   * @param {Array<Object>} events Array of security events to store
   * @returns {Promise<Array<string>>} Array of event IDs
   */
  async storeEvents(events) {
    try {
      if (!Array.isArray(events) || events.length === 0) {
        throw new Error('Events must be a non-empty array');
      }

      const formattedEvents = events.map(event => {
        const eventId = event.event_id || uuidv4();
        const timestamp = event.timestamp || new Date().toISOString();

        return {
          event_id: eventId,
          timestamp: timestamp,
          source_ip: event.source_ip || '',
          source_port: event.source_port || 0,
          destination_ip: event.destination_ip || '',
          destination_port: event.destination_port || 0,
          protocol: event.protocol || '',
          event_type: event.event_type || 'other',
          severity: event.severity || 1,
          confidence: event.confidence || 1,
          description: event.description || '',
          raw_data: event.raw_data ? JSON.stringify(event.raw_data) : '{}',
          processed_by: event.processed_by || '',
          network_segment: event.network_segment || '',
          asset_id: event.asset_id || ''
        };
      });

      await this.clickhouse.insert(this.tableName, formattedEvents).toPromise();
      
      const eventIds = formattedEvents.map(event => event.event_id);
      logger.info(`Stored ${eventIds.length} events`);
      return eventIds;
    } catch (error) {
      logger.error(`Error storing multiple events: ${error.message}`);
      throw error;
    }
  }

  /**
   * Query security events with optional filters
   * @param {Object} filters Query filters
   * @param {number} limit Maximum number of results
   * @param {number} offset Pagination offset
   * @returns {Promise<Array<Object>>} Security events matching the filters
   */
  async queryEvents(filters = {}, limit = 100, offset = 0) {
    try {
      let query = `SELECT * FROM ${this.tableName} WHERE 1=1`;
      const params = {};

      if (filters.from) {
        query += ` AND timestamp >= {from:DateTime64(3)}`;
        params.from = filters.from;
      }

      if (filters.to) {
        query += ` AND timestamp <= {to:DateTime64(3)}`;
        params.to = filters.to;
      }

      if (filters.event_type) {
        query += ` AND event_type = {event_type:String}`;
        params.event_type = filters.event_type;
      }

      if (filters.min_severity) {
        query += ` AND severity >= {min_severity:UInt8}`;
        params.min_severity = filters.min_severity;
      }

      if (filters.source_ip) {
        query += ` AND source_ip = {source_ip:String}`;
        params.source_ip = filters.source_ip;
      }

      if (filters.destination_ip) {
        query += ` AND destination_ip = {destination_ip:String}`;
        params.destination_ip = filters.destination_ip;
      }

      if (filters.network_segment) {
        query += ` AND network_segment = {network_segment:String}`;
        params.network_segment = filters.network_segment;
      }

      if (filters.asset_id) {
        query += ` AND asset_id = {asset_id:String}`;
        params.asset_id = filters.asset_id;
      }

      query += ` ORDER BY timestamp DESC LIMIT ${limit} OFFSET ${offset}`;

      const result = await this.clickhouse.query(query, { params }).toPromise();
      logger.info(`Retrieved ${result.length} events`);
      return result;
    } catch (error) {
      logger.error(`Error querying events: ${error.message}`);
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
      let query = `SELECT * FROM ${this.alertsView} WHERE 1=1`;
      const params = {};

      if (filters.from) {
        query += ` AND timestamp >= {from:DateTime64(3)}`;
        params.from = filters.from;
      }

      if (filters.to) {
        query += ` AND timestamp <= {to:DateTime64(3)}`;
        params.to = filters.to;
      }

      if (filters.event_type) {
        query += ` AND event_type = {event_type:String}`;
        params.event_type = filters.event_type;
      }

      if (filters.min_severity) {
        query += ` AND severity >= {min_severity:UInt8}`;
        params.min_severity = filters.min_severity;
      }

      query += ` ORDER BY timestamp DESC LIMIT ${limit} OFFSET ${offset}`;

      const result = await this.clickhouse.query(query, { params }).toPromise();
      logger.info(`Retrieved ${result.length} alerts`);
      return result;
    } catch (error) {
      logger.error(`Error retrieving alerts: ${error.message}`);
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
      let query = `SELECT * FROM ${this.summaryView} WHERE 1=1`;
      const params = {};

      if (filters.from) {
        query += ` AND hour >= {from:DateTime}`;
        params.from = filters.from;
      }

      if (filters.to) {
        query += ` AND hour <= {to:DateTime}`;
        params.to = filters.to;
      }

      if (filters.event_type) {
        query += ` AND event_type = {event_type:String}`;
        params.event_type = filters.event_type;
      }

      if (filters.network_segment) {
        query += ` AND network_segment = {network_segment:String}`;
        params.network_segment = filters.network_segment;
      }

      query += ` ORDER BY hour DESC`;

      const result = await this.clickhouse.query(query, { params }).toPromise();
      logger.info(`Retrieved event summary with ${result.length} rows`);
      return result;
    } catch (error) {
      logger.error(`Error retrieving event summary: ${error.message}`);
      throw error;
    }
  }

  /**
   * Add event to blacklist
   * @param {Object} rule Blacklist rule
   * @returns {Promise<string>} Rule ID
   */
  async addToBlacklist(rule) {
    try {
      const ruleId = rule.rule_id || uuidv4();
      
      const formattedRule = {
        rule_id: ruleId,
        source_ip_pattern: rule.source_ip_pattern || '',
        destination_ip_pattern: rule.destination_ip_pattern || '',
        event_type: rule.event_type || 'other',
        reason: rule.reason || '',
        created_at: rule.created_at || new Date().toISOString(),
        created_by: rule.created_by || '',
        expires_at: rule.expires_at || ''
      };

      await this.clickhouse.insert(this.blacklistTable, [formattedRule]).toPromise();
      logger.info(`Added blacklist rule with ID: ${ruleId}`);
      return ruleId;
    } catch (error) {
      logger.error(`Error adding blacklist rule: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get blacklist rules
   * @returns {Promise<Array<Object>>} Blacklist rules
   */
  async getBlacklist() {
    try {
      const query = `SELECT * FROM ${this.blacklistTable} WHERE expires_at > now() OR expires_at = 0`;
      const result = await this.clickhouse.query(query).toPromise();
      logger.info(`Retrieved ${result.length} blacklist rules`);
      return result;
    } catch (error) {
      logger.error(`Error retrieving blacklist: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete from blacklist by rule ID
   * @param {string} ruleId Rule ID to delete
   * @returns {Promise<boolean>} Success status
   */
  async removeFromBlacklist(ruleId) {
    try {
      const query = `ALTER TABLE ${this.blacklistTable} DELETE WHERE rule_id = {rule_id:String}`;
      await this.clickhouse.query(query, { params: { rule_id: ruleId } }).toPromise();
      logger.info(`Removed blacklist rule with ID: ${ruleId}`);
      return true;
    } catch (error) {
      logger.error(`Error removing blacklist rule: ${error.message}`);
      throw error;
    }
  }

  /**
   * Check database connection
   * @returns {Promise<boolean>} Connection status
   */
  async checkConnection() {
    try {
      const result = await this.clickhouse.query('SELECT 1').toPromise();
      return result && result.length > 0;
    } catch (error) {
      logger.error(`Database connection check failed: ${error.message}`);
      return false;
    }
  }
}

module.exports = EventStoreClient; 