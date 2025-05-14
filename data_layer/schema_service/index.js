const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const fs = require('fs');
const logger = require('../../utils/logger');

/**
 * Schema Service for Protocol Buffers
 * Compiles and exports Proto schemas with versioning support
 */
class SchemaService {
  constructor() {
    this.protosDir = path.join(__dirname, 'protos');
    this.schemas = {};
    this.services = {};
    this.schemaVersions = {
      security_event: { major: 1, minor: 0, patch: 0 },
      threat_intel: { major: 1, minor: 0, patch: 0 },
      response_action: { major: 1, minor: 0, patch: 0 }
    };
    
    this.protoLoadOptions = {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true
    };
    
    // Initialize schemas
    this._initializeSchemas();
    
    logger.info('Schema Service initialized');
  }

  /**
   * Initialize all schemas
   * @private
   */
  _initializeSchemas() {
    try {
      // Get all proto files
      const protoFiles = fs.readdirSync(this.protosDir)
        .filter(file => file.endsWith('.proto'));
      
      // Load each proto file
      protoFiles.forEach(protoFile => {
        const protoName = path.basename(protoFile, '.proto');
        const protoPath = path.join(this.protosDir, protoFile);
        
        try {
          // Load proto definition
          const packageDefinition = protoLoader.loadSync(
            protoPath,
            this.protoLoadOptions
          );
          
          // Load into gRPC
          const proto = grpc.loadPackageDefinition(packageDefinition);
          
          // Store in schemas map
          this.schemas[protoName] = proto.netguardian.schema;
          
          // Extract services
          Object.keys(proto.netguardian.schema).forEach(key => {
            if (typeof proto.netguardian.schema[key] === 'function' && 
                proto.netguardian.schema[key].service) {
              this.services[key] = proto.netguardian.schema[key];
            }
          });
          
          logger.info(`Loaded schema: ${protoName}`);
        } catch (error) {
          logger.error(`Error loading schema ${protoName}: ${error.message}`);
        }
      });
    } catch (error) {
      logger.error(`Error initializing schemas: ${error.message}`);
    }
  }

  /**
   * Get a schema by name
   * @param {string} schemaName Name of the schema (without .proto extension)
   * @returns {Object} Schema definition
   */
  getSchema(schemaName) {
    if (!this.schemas[schemaName]) {
      throw new Error(`Schema ${schemaName} not found`);
    }
    return this.schemas[schemaName];
  }

  /**
   * Get a service by name
   * @param {string} serviceName Name of the service
   * @returns {Object} Service definition
   */
  getService(serviceName) {
    if (!this.services[serviceName]) {
      throw new Error(`Service ${serviceName} not found`);
    }
    return this.services[serviceName];
  }

  /**
   * Get schema version information
   * @param {string} schemaName Name of the schema
   * @returns {Object} Version information
   */
  getSchemaVersion(schemaName) {
    if (!this.schemaVersions[schemaName]) {
      throw new Error(`Version info for schema ${schemaName} not found`);
    }
    return this.schemaVersions[schemaName];
  }

  /**
   * Check if a message is compatible with current schema version
   * @param {string} schemaName Name of the schema
   * @param {Object} message Message containing schema_version field
   * @returns {boolean} Whether the message is compatible
   */
  isCompatible(schemaName, message) {
    if (!message.schema_version) {
      // No version info in message, assume it's compatible
      return true;
    }
    
    const currentVersion = this.schemaVersions[schemaName];
    const messageVersion = message.schema_version;
    
    // Check if major version matches (backward compatibility only within same major version)
    if (messageVersion.major !== currentVersion.major) {
      return false;
    }
    
    // Message with lower minor version is compatible with higher minor version schema
    if (messageVersion.minor > currentVersion.minor) {
      return false;
    }
    
    return true;
  }

  /**
   * Set schema version information (for testing or updates)
   * @param {string} schemaName Name of the schema
   * @param {Object} version Version object with major, minor, patch
   */
  setSchemaVersion(schemaName, version) {
    if (!this.schemaVersions[schemaName]) {
      throw new Error(`Schema ${schemaName} not found for version update`);
    }
    
    this.schemaVersions[schemaName] = {
      major: version.major,
      minor: version.minor,
      patch: version.patch
    };
    
    logger.info(`Updated schema version for ${schemaName}: ${version.major}.${version.minor}.${version.patch}`);
  }
  
  /**
   * Get the current schema version object for a new message
   * @param {string} schemaName Name of the schema
   * @returns {Object} Schema version object
   */
  getCurrentVersionObject(schemaName) {
    const version = this.getSchemaVersion(schemaName);
    return {
      major: version.major,
      minor: version.minor,
      patch: version.patch
    };
  }
  
  /**
   * Create a new gRPC client for a service
   * @param {string} serviceName Name of the service
   * @param {string} address Server address (host:port)
   * @param {Object} credentials Optional credentials (defaults to insecure)
   * @returns {Object} gRPC client
   */
  createClient(serviceName, address, credentials = grpc.credentials.createInsecure()) {
    const Service = this.getService(serviceName);
    return new Service(address, credentials);
  }
}

// Export singleton instance
const schemaService = new SchemaService();
module.exports = schemaService; 