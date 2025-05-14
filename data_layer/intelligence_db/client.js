const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const logger = require('../../utils/logger');

/**
 * IntelligenceDB client for PostgreSQL
 * Handles CRUD operations for threat intelligence data
 */
class IntelligenceDBClient {
  constructor(config = {}) {
    this.config = {
      host: config.host || process.env.PG_HOST || 'localhost',
      port: config.port || process.env.PG_PORT || 5432,
      database: config.database || process.env.PG_DATABASE || 'intelligence_db',
      user: config.user || process.env.PG_USER || 'netguardian',
      password: config.password || process.env.PG_PASSWORD || 'netguardian_secure_password',
      max: config.maxConnections || process.env.PG_MAX_CONNECTIONS || 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
      ...config
    };

    this.pool = new Pool(this.config);
    
    // Setup error handler for the pool
    this.pool.on('error', (err, client) => {
      logger.error(`Unexpected error on idle PostgreSQL client: ${err.message}`);
    });
    
    logger.info('IntelligenceDB client initialized');
  }

  /**
   * Close all database connections
   */
  async close() {
    await this.pool.end();
    logger.info('IntelligenceDB client connections closed');
  }

  /**
   * Check database connection
   * @returns {Promise<boolean>} Connection status
   */
  async checkConnection() {
    const client = await this.pool.connect();
    try {
      await client.query('SELECT 1');
      return true;
    } catch (error) {
      logger.error(`Database connection check failed: ${error.message}`);
      return false;
    } finally {
      client.release();
    }
  }

  /**
   * Begin a transaction
   * @returns {Promise<Object>} PostgreSQL client with active transaction
   */
  async beginTransaction() {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      return client;
    } catch (error) {
      client.release();
      throw error;
    }
  }

  /**
   * Commit a transaction
   * @param {Object} client PostgreSQL client with active transaction
   */
  async commitTransaction(client) {
    try {
      await client.query('COMMIT');
    } finally {
      client.release();
    }
  }

  /**
   * Rollback a transaction
   * @param {Object} client PostgreSQL client with active transaction
   */
  async rollbackTransaction(client) {
    try {
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  }

  /**
   * ==============================
   * IOC (Indicators of Compromise) Methods
   * ==============================
   */

  /**
   * Create a new IOC
   * @param {Object} ioc IOC data
   * @returns {Promise<Object>} Created IOC
   */
  async createIOC(ioc) {
    const query = `
      INSERT INTO iocs (
        type, value, confidence, severity, 
        first_seen, last_seen, expiration, tags, 
        source, description, context, created_by
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
      ) RETURNING *
    `;

    const values = [
      ioc.type,
      ioc.value,
      ioc.confidence || 50,
      ioc.severity || 5,
      ioc.first_seen || new Date(),
      ioc.last_seen || new Date(),
      ioc.expiration,
      ioc.tags || [],
      ioc.source,
      ioc.description,
      ioc.context || {},
      ioc.created_by
    ];

    try {
      const result = await this.pool.query(query, values);
      logger.info(`Created IOC with ID: ${result.rows[0].ioc_id}`);
      return result.rows[0];
    } catch (error) {
      logger.error(`Error creating IOC: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get IOC by ID
   * @param {string} iocId UUID of the IOC
   * @returns {Promise<Object>} IOC data
   */
  async getIOC(iocId) {
    const query = 'SELECT * FROM iocs WHERE ioc_id = $1';
    
    try {
      const result = await this.pool.query(query, [iocId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
    } catch (error) {
      logger.error(`Error getting IOC by ID: ${error.message}`);
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
    // Create dynamic update query based on provided fields
    const allowedFields = [
      'confidence', 'severity', 'last_seen', 'expiration',
      'tags', 'source', 'description', 'context'
    ];
    
    const updates = [];
    const values = [iocId];
    let paramIndex = 2;
    
    // Build the SET clause dynamically
    Object.entries(updateData).forEach(([key, value]) => {
      if (allowedFields.includes(key) && value !== undefined) {
        updates.push(`${key} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
    });
    
    // If nothing to update, return the current IOC
    if (updates.length === 0) {
      return this.getIOC(iocId);
    }
    
    const query = `
      UPDATE iocs 
      SET ${updates.join(', ')} 
      WHERE ioc_id = $1 
      RETURNING *
    `;
    
    try {
      const result = await this.pool.query(query, values);
      
      if (result.rows.length === 0) {
        throw new Error(`IOC with ID ${iocId} not found`);
      }
      
      logger.info(`Updated IOC with ID: ${iocId}`);
      return result.rows[0];
    } catch (error) {
      logger.error(`Error updating IOC: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete an IOC
   * @param {string} iocId UUID of the IOC
   * @returns {Promise<boolean>} Success status
   */
  async deleteIOC(iocId) {
    const query = 'DELETE FROM iocs WHERE ioc_id = $1 RETURNING ioc_id';
    
    try {
      const result = await this.pool.query(query, [iocId]);
      
      if (result.rows.length === 0) {
        return false;
      }
      
      logger.info(`Deleted IOC with ID: ${iocId}`);
      return true;
    } catch (error) {
      logger.error(`Error deleting IOC: ${error.message}`);
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
    const conditions = ['1=1']; // Default condition that's always true
    const values = [];
    let paramIndex = 1;
    
    if (filters.type) {
      conditions.push(`type = $${paramIndex}`);
      values.push(filters.type);
      paramIndex++;
    }
    
    if (filters.value) {
      conditions.push(`value ILIKE $${paramIndex}`);
      values.push(`%${filters.value}%`);
      paramIndex++;
    }
    
    if (filters.minConfidence) {
      conditions.push(`confidence >= $${paramIndex}`);
      values.push(filters.minConfidence);
      paramIndex++;
    }
    
    if (filters.minSeverity) {
      conditions.push(`severity >= $${paramIndex}`);
      values.push(filters.minSeverity);
      paramIndex++;
    }
    
    if (filters.tags && Array.isArray(filters.tags) && filters.tags.length > 0) {
      conditions.push(`tags && $${paramIndex}`);
      values.push(filters.tags);
      paramIndex++;
    }
    
    if (filters.source) {
      conditions.push(`source = $${paramIndex}`);
      values.push(filters.source);
      paramIndex++;
    }
    
    values.push(limit);
    values.push(offset);
    
    const query = `
      SELECT * FROM iocs 
      WHERE ${conditions.join(' AND ')} 
      ORDER BY last_seen DESC 
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;
    
    try {
      const result = await this.pool.query(query, values);
      logger.info(`Found ${result.rows.length} IOCs matching the filters`);
      return result.rows;
    } catch (error) {
      logger.error(`Error searching IOCs: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Threat Actor Methods
   * ==============================
   */

  /**
   * Create a new threat actor
   * @param {Object} actor Threat actor data
   * @returns {Promise<Object>} Created threat actor
   */
  async createThreatActor(actor) {
    const query = `
      INSERT INTO threat_actors (
        name, aliases, motivation, sophistication_level,
        first_seen, last_seen, description, ttps,
        country_of_origin, industries_targeted, references, context
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
      ) RETURNING *
    `;

    const values = [
      actor.name,
      actor.aliases || [],
      actor.motivation || [],
      actor.sophistication_level || 1,
      actor.first_seen,
      actor.last_seen,
      actor.description,
      actor.ttps || [],
      actor.country_of_origin,
      actor.industries_targeted || [],
      actor.references || [],
      actor.context || {}
    ];

    try {
      const result = await this.pool.query(query, values);
      logger.info(`Created threat actor with ID: ${result.rows[0].actor_id}`);
      return result.rows[0];
    } catch (error) {
      logger.error(`Error creating threat actor: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get threat actor by ID
   * @param {string} actorId UUID of the threat actor
   * @returns {Promise<Object>} Threat actor data
   */
  async getThreatActor(actorId) {
    const query = 'SELECT * FROM threat_actors WHERE actor_id = $1';
    
    try {
      const result = await this.pool.query(query, [actorId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
    } catch (error) {
      logger.error(`Error getting threat actor by ID: ${error.message}`);
      throw error;
    }
  }

  /**
   * Update a threat actor
   * @param {string} actorId UUID of the threat actor
   * @param {Object} updateData Data to update
   * @returns {Promise<Object>} Updated threat actor
   */
  async updateThreatActor(actorId, updateData) {
    const allowedFields = [
      'name', 'aliases', 'motivation', 'sophistication_level',
      'last_seen', 'description', 'ttps', 'country_of_origin',
      'industries_targeted', 'references', 'context'
    ];
    
    const updates = [];
    const values = [actorId];
    let paramIndex = 2;
    
    Object.entries(updateData).forEach(([key, value]) => {
      if (allowedFields.includes(key) && value !== undefined) {
        updates.push(`${key} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
    });
    
    if (updates.length === 0) {
      return this.getThreatActor(actorId);
    }
    
    const query = `
      UPDATE threat_actors 
      SET ${updates.join(', ')} 
      WHERE actor_id = $1 
      RETURNING *
    `;
    
    try {
      const result = await this.pool.query(query, values);
      
      if (result.rows.length === 0) {
        throw new Error(`Threat actor with ID ${actorId} not found`);
      }
      
      logger.info(`Updated threat actor with ID: ${actorId}`);
      return result.rows[0];
    } catch (error) {
      logger.error(`Error updating threat actor: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete a threat actor
   * @param {string} actorId UUID of the threat actor
   * @returns {Promise<boolean>} Success status
   */
  async deleteThreatActor(actorId) {
    const query = 'DELETE FROM threat_actors WHERE actor_id = $1 RETURNING actor_id';
    
    try {
      const result = await this.pool.query(query, [actorId]);
      
      if (result.rows.length === 0) {
        return false;
      }
      
      logger.info(`Deleted threat actor with ID: ${actorId}`);
      return true;
    } catch (error) {
      logger.error(`Error deleting threat actor: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Vulnerability Methods
   * ==============================
   */

  /**
   * Create a new vulnerability
   * @param {Object} vulnerability Vulnerability data
   * @returns {Promise<Object>} Created vulnerability
   */
  async createVulnerability(vulnerability) {
    const query = `
      INSERT INTO vulnerabilities (
        cve_id, title, description, cvss_score,
        cvss_vector, severity, affected_products,
        affected_versions, remediation, exploit_available,
        exploit_details, publish_date, patch_available, references
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
      ) RETURNING *
    `;

    // Calculate severity based on CVSS score if not provided
    let severity = vulnerability.severity;
    if (!severity && vulnerability.cvss_score) {
      if (vulnerability.cvss_score >= 9.0) severity = 'critical';
      else if (vulnerability.cvss_score >= 7.0) severity = 'high';
      else if (vulnerability.cvss_score >= 4.0) severity = 'medium';
      else severity = 'low';
    }

    const values = [
      vulnerability.cve_id,
      vulnerability.title,
      vulnerability.description,
      vulnerability.cvss_score,
      vulnerability.cvss_vector,
      severity || 'low',
      vulnerability.affected_products || [],
      vulnerability.affected_versions || [],
      vulnerability.remediation,
      vulnerability.exploit_available || false,
      vulnerability.exploit_details,
      vulnerability.publish_date,
      vulnerability.patch_available || false,
      vulnerability.references || []
    ];

    try {
      const result = await this.pool.query(query, values);
      logger.info(`Created vulnerability with ID: ${result.rows[0].vulnerability_id}`);
      return result.rows[0];
    } catch (error) {
      logger.error(`Error creating vulnerability: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get vulnerability by ID
   * @param {string} vulnerabilityId UUID of the vulnerability
   * @returns {Promise<Object>} Vulnerability data
   */
  async getVulnerability(vulnerabilityId) {
    const query = 'SELECT * FROM vulnerabilities WHERE vulnerability_id = $1';
    
    try {
      const result = await this.pool.query(query, [vulnerabilityId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
    } catch (error) {
      logger.error(`Error getting vulnerability by ID: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get vulnerability by CVE ID
   * @param {string} cveId CVE ID of the vulnerability
   * @returns {Promise<Object>} Vulnerability data
   */
  async getVulnerabilityByCVE(cveId) {
    const query = 'SELECT * FROM vulnerabilities WHERE cve_id = $1';
    
    try {
      const result = await this.pool.query(query, [cveId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
    } catch (error) {
      logger.error(`Error getting vulnerability by CVE ID: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Campaign Methods
   * ==============================
   */

  /**
   * Create a new campaign
   * @param {Object} campaign Campaign data
   * @returns {Promise<Object>} Created campaign
   */
  async createCampaign(campaign) {
    const client = await this.beginTransaction();
    
    try {
      // Insert the campaign first
      const campaignQuery = `
        INSERT INTO campaigns (
          name, status, start_date, end_date,
          objectives, description, ttps,
          industries_targeted, regions_targeted,
          attribution, confidence_score
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
        ) RETURNING *
      `;

      const campaignValues = [
        campaign.name,
        campaign.status || 'active',
        campaign.start_date,
        campaign.end_date,
        campaign.objectives,
        campaign.description,
        campaign.ttps || [],
        campaign.industries_targeted || [],
        campaign.regions_targeted || [],
        campaign.attribution, // Threat actor ID reference
        campaign.confidence_score || 50
      ];

      const campaignResult = await client.query(campaignQuery, campaignValues);
      const createdCampaign = campaignResult.rows[0];
      
      // If IOCs are provided, associate them with the campaign
      if (campaign.iocs && Array.isArray(campaign.iocs) && campaign.iocs.length > 0) {
        const iocValuesString = campaign.iocs.map((ioc, index) => {
          return `($1, $${index + 2}, $${campaign.iocs.length + index + 2}, $${2 * campaign.iocs.length + index + 2}, $${3 * campaign.iocs.length + index + 2})`;
        }).join(', ');
        
        const iocParams = [createdCampaign.campaign_id];
        // Add all IOC IDs
        campaign.iocs.forEach(ioc => iocParams.push(ioc.ioc_id));
        // Add all first_seen values
        campaign.iocs.forEach(ioc => iocParams.push(ioc.first_seen || null));
        // Add all last_seen values
        campaign.iocs.forEach(ioc => iocParams.push(ioc.last_seen || null));
        // Add all notes values
        campaign.iocs.forEach(ioc => iocParams.push(ioc.notes || null));
        
        const iocQuery = `
          INSERT INTO campaign_iocs (
            campaign_id, ioc_id, first_seen, last_seen, notes
          ) VALUES ${iocValuesString}
        `;
        
        await client.query(iocQuery, iocParams);
      }
      
      // If timeline events are provided, add them to the campaign timeline
      if (campaign.timeline && Array.isArray(campaign.timeline) && campaign.timeline.length > 0) {
        const timelineValuesString = campaign.timeline.map((event, index) => {
          return `($1, $${index + 2}, $${campaign.timeline.length + index + 2}, $${2 * campaign.timeline.length + index + 2}, $${3 * campaign.timeline.length + index + 2})`;
        }).join(', ');
        
        const timelineParams = [createdCampaign.campaign_id];
        // Add all event times
        campaign.timeline.forEach(event => timelineParams.push(event.event_time));
        // Add all event types
        campaign.timeline.forEach(event => timelineParams.push(event.event_type));
        // Add all descriptions
        campaign.timeline.forEach(event => timelineParams.push(event.description || null));
        // Add all technical details
        campaign.timeline.forEach(event => timelineParams.push(event.technical_details || null));
        
        const timelineQuery = `
          INSERT INTO campaign_timeline (
            campaign_id, event_time, event_type, description, technical_details
          ) VALUES ${timelineValuesString}
        `;
        
        await client.query(timelineQuery, timelineParams);
      }
      
      await this.commitTransaction(client);
      logger.info(`Created campaign with ID: ${createdCampaign.campaign_id}`);
      return createdCampaign;
    } catch (error) {
      await this.rollbackTransaction(client);
      logger.error(`Error creating campaign: ${error.message}`);
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
      // Get the campaign
      const campaignQuery = 'SELECT * FROM campaigns WHERE campaign_id = $1';
      const campaignResult = await this.pool.query(campaignQuery, [campaignId]);
      
      if (campaignResult.rows.length === 0) {
        return null;
      }
      
      const campaign = campaignResult.rows[0];
      
      // Get associated IOCs
      const iocsQuery = `
        SELECT i.*, ci.first_seen as campaign_first_seen, ci.last_seen as campaign_last_seen, ci.notes
        FROM iocs i
        JOIN campaign_iocs ci ON i.ioc_id = ci.ioc_id
        WHERE ci.campaign_id = $1
      `;
      const iocsResult = await this.pool.query(iocsQuery, [campaignId]);
      campaign.iocs = iocsResult.rows;
      
      // Get campaign timeline
      const timelineQuery = 'SELECT * FROM campaign_timeline WHERE campaign_id = $1 ORDER BY event_time';
      const timelineResult = await this.pool.query(timelineQuery, [campaignId]);
      campaign.timeline = timelineResult.rows;
      
      // Get threat actor if attribution exists
      if (campaign.attribution) {
        const actorQuery = 'SELECT * FROM threat_actors WHERE actor_id = $1';
        const actorResult = await this.pool.query(actorQuery, [campaign.attribution]);
        if (actorResult.rows.length > 0) {
          campaign.attributed_to = actorResult.rows[0];
        }
      }
      
      return campaign;
    } catch (error) {
      logger.error(`Error getting campaign by ID: ${error.message}`);
      throw error;
    }
  }

  /**
   * ==============================
   * Intelligence Report Methods
   * ==============================
   */

  /**
   * Create a new intelligence report
   * @param {Object} report Intelligence report data
   * @returns {Promise<Object>} Created intelligence report
   */
  async createIntelligenceReport(report) {
    const query = `
      INSERT INTO intelligence_reports (
        title, summary, content, tlp,
        confidence_level, source, publication_date,
        related_campaigns, related_actors, related_iocs,
        tags, created_by
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
      ) RETURNING *
    `;

    const values = [
      report.title,
      report.summary,
      report.content,
      report.tlp || 'amber',
      report.confidence_level || 50,
      report.source,
      report.publication_date || new Date(),
      report.related_campaigns || [],
      report.related_actors || [],
      report.related_iocs || [],
      report.tags || [],
      report.created_by
    ];

    try {
      const result = await this.pool.query(query, values);
      logger.info(`Created intelligence report with ID: ${result.rows[0].report_id}`);
      return result.rows[0];
    } catch (error) {
      logger.error(`Error creating intelligence report: ${error.message}`);
      throw error;
    }
  }
}

module.exports = IntelligenceDBClient; 