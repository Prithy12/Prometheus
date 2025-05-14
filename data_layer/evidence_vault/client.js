const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { createReadStream, createWriteStream } = require('fs');
const { pipeline } = require('stream/promises');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const logger = require('../../utils/logger');

/**
 * EvidenceVault client for S3-compatible storage
 * Handles encrypted evidence storage with chain-of-custody tracking
 */
class EvidenceVaultClient {
  constructor(config = {}) {
    this.config = {
      endpoint: config.endpoint || process.env.S3_ENDPOINT || 'http://localhost:9000',
      region: config.region || process.env.S3_REGION || 'us-east-1',
      credentials: {
        accessKeyId: config.accessKeyId || process.env.S3_ACCESS_KEY || 'minioadmin',
        secretAccessKey: config.secretAccessKey || process.env.S3_SECRET_KEY || 'minioadmin'
      },
      forcePathStyle: true, // Needed for MinIO and other S3-compatible servers
      ...config
    };
    
    this.s3Client = new S3Client(this.config);
    this.bucketName = config.bucketName || process.env.S3_BUCKET || 'evidence-vault';
    
    // Encryption keys
    this.encryptionKey = config.encryptionKey || process.env.ENCRYPTION_KEY || 
      Buffer.from('01234567890123456789012345678901', 'hex'); // 32 bytes (256 bits)
    
    this.evidenceTypes = {
      PCAP: 'pcap',
      LOG: 'log',
      MEMORY_DUMP: 'memory_dump',
      DISK_IMAGE: 'disk_image',
      NETWORK_FLOW: 'network_flow',
      SCREENSHOT: 'screenshot',
      TIMELINE: 'timeline',
      OTHER: 'other'
    };
    
    logger.info('EvidenceVault client initialized');
  }

  /**
   * Generate a chain of custody entry
   * @param {string} evidenceId Evidence ID
   * @param {string} action Action performed on the evidence
   * @param {string} user User who performed the action
   * @param {string} description Description of the action
   * @returns {Object} Chain of custody entry
   */
  _generateChainOfCustodyEntry(evidenceId, action, user, description = '') {
    const timestamp = new Date().toISOString();
    const entry = {
      timestamp,
      evidenceId,
      action,
      user,
      description,
    };

    // Sign the entry to prevent tampering
    const signature = this._signData(JSON.stringify(entry));
    
    return {
      ...entry,
      signature
    };
  }

  /**
   * Sign data using HMAC-SHA256
   * @param {string} data Data to sign
   * @returns {string} Signature
   */
  _signData(data) {
    const hmac = crypto.createHmac('sha256', this.encryptionKey);
    hmac.update(data);
    return hmac.digest('hex');
  }

  /**
   * Verify signature of data
   * @param {string} data Data to verify
   * @param {string} signature Signature to verify
   * @returns {boolean} Verification result
   */
  _verifySignature(data, signature) {
    const expectedSignature = this._signData(data);
    return crypto.timingSafeEqual(
      Buffer.from(expectedSignature, 'hex'),
      Buffer.from(signature, 'hex')
    );
  }

  /**
   * Encrypt data using AES-256-GCM
   * @param {Buffer} data Data to encrypt
   * @returns {Object} Encrypted data with IV and auth tag
   */
  _encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);

    const encryptedData = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);

    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      encryptedData,
      authTag: authTag.toString('hex')
    };
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param {Buffer} encryptedData Encrypted data
   * @param {string} ivHex Initialization vector in hex
   * @param {string} authTagHex Authentication tag in hex
   * @returns {Buffer} Decrypted data
   */
  _decryptData(encryptedData, ivHex, authTagHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
  }

  /**
   * Store evidence with encryption and chain-of-custody tracking
   * @param {Buffer|string} data Evidence data or file path
   * @param {Object} metadata Evidence metadata
   * @param {string} user User storing the evidence
   * @returns {Promise<Object>} Evidence ID and metadata
   */
  async storeEvidence(data, metadata, user) {
    try {
      // Generate a unique evidence ID
      const evidenceId = metadata.evidenceId || uuidv4();
      const timestamp = new Date().toISOString();
      
      // Ensure required metadata is present
      const evidenceMetadata = {
        evidenceId,
        timestamp,
        type: metadata.type || this.evidenceTypes.OTHER,
        caseId: metadata.caseId,
        source: metadata.source,
        description: metadata.description,
        tags: metadata.tags || [],
        customMetadata: metadata.customMetadata || {},
        ...metadata
      };
      
      // Process data (either Buffer or filepath)
      let dataBuffer;
      if (Buffer.isBuffer(data)) {
        dataBuffer = data;
      } else if (typeof data === 'string' && await this._fileExists(data)) {
        // Read file into buffer
        const fileStream = createReadStream(data);
        const chunks = [];
        for await (const chunk of fileStream) {
          chunks.push(chunk);
        }
        dataBuffer = Buffer.concat(chunks);
      } else {
        throw new Error('Invalid data: must be Buffer or valid file path');
      }
      
      // Encrypt the evidence data
      const encrypted = this._encryptData(dataBuffer);
      
      // Create chain of custody entry
      const custodyEntry = this._generateChainOfCustodyEntry(
        evidenceId,
        'STORE',
        user,
        `Initial storage of evidence ${metadata.description || ''}`
      );
      
      // Add chain of custody to metadata
      evidenceMetadata.chainOfCustody = [custodyEntry];
      evidenceMetadata.iv = encrypted.iv;
      evidenceMetadata.authTag = encrypted.authTag;
      evidenceMetadata.hash = {
        sha256: crypto.createHash('sha256').update(dataBuffer).digest('hex'),
        md5: crypto.createHash('md5').update(dataBuffer).digest('hex')
      };
      
      // Create S3 key based on evidence type and ID
      const s3Key = `${evidenceMetadata.type}/${evidenceId}`;
      
      // Upload to S3
      const upload = await this.s3Client.send(new PutObjectCommand({
        Bucket: this.bucketName,
        Key: s3Key,
        Body: encrypted.encryptedData,
        Metadata: {
          'evidence-metadata': JSON.stringify(evidenceMetadata)
        }
      }));
      
      logger.info(`Evidence stored with ID: ${evidenceId}`);
      
      return {
        evidenceId,
        metadata: evidenceMetadata
      };
    } catch (error) {
      logger.error(`Error storing evidence: ${error.message}`);
      throw error;
    }
  }

  /**
   * Check if a file exists
   * @param {string} filePath File path to check
   * @returns {Promise<boolean>} Whether the file exists
   */
  async _fileExists(filePath) {
    try {
      await fs.promises.access(filePath);
      return true;
    } catch {
      return false;
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
      // Find the evidence by ID across all types
      const objects = await this.s3Client.send(new ListObjectsV2Command({
        Bucket: this.bucketName,
        Prefix: '',
      }));
      
      const evidenceKeys = (objects.Contents || [])
        .filter(obj => obj.Key.endsWith(`/${evidenceId}`))
        .map(obj => obj.Key);
      
      if (evidenceKeys.length === 0) {
        throw new Error(`Evidence with ID ${evidenceId} not found`);
      }
      
      const s3Key = evidenceKeys[0];
      
      // Get the evidence data
      const response = await this.s3Client.send(new GetObjectCommand({
        Bucket: this.bucketName,
        Key: s3Key
      }));
      
      // Extract metadata
      const evidenceMetadata = JSON.parse(response.Metadata['evidence-metadata']);
      
      // Read encrypted data
      const chunks = [];
      for await (const chunk of response.Body) {
        chunks.push(chunk);
      }
      const encryptedData = Buffer.concat(chunks);
      
      // Decrypt the data
      const decryptedData = this._decryptData(
        encryptedData,
        evidenceMetadata.iv,
        evidenceMetadata.authTag
      );
      
      // Verify integrity with hash
      const calculatedHash = crypto.createHash('sha256').update(decryptedData).digest('hex');
      
      if (calculatedHash !== evidenceMetadata.hash.sha256) {
        throw new Error('Evidence integrity check failed: hash mismatch');
      }
      
      // Create chain of custody entry
      const custodyEntry = this._generateChainOfCustodyEntry(
        evidenceId,
        'RETRIEVE',
        user,
        `Evidence retrieved by ${user}`
      );
      
      // Add to chain of custody
      evidenceMetadata.chainOfCustody.push(custodyEntry);
      
      // Update metadata in S3
      await this.s3Client.send(new PutObjectCommand({
        Bucket: this.bucketName,
        Key: s3Key,
        Body: encryptedData,
        Metadata: {
          'evidence-metadata': JSON.stringify(evidenceMetadata)
        }
      }));
      
      // If an output path is provided, save the decrypted data
      if (outputPath) {
        const fileStream = createWriteStream(outputPath);
        await pipeline(
          Buffer.from(decryptedData),
          fileStream
        );
      }
      
      logger.info(`Evidence with ID ${evidenceId} retrieved by ${user}`);
      
      return {
        evidenceId,
        metadata: evidenceMetadata,
        data: decryptedData
      };
    } catch (error) {
      logger.error(`Error retrieving evidence: ${error.message}`);
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
      // Find the evidence by ID across all types
      const objects = await this.s3Client.send(new ListObjectsV2Command({
        Bucket: this.bucketName,
        Prefix: '',
      }));
      
      const evidenceKeys = (objects.Contents || [])
        .filter(obj => obj.Key.endsWith(`/${evidenceId}`))
        .map(obj => obj.Key);
      
      if (evidenceKeys.length === 0) {
        throw new Error(`Evidence with ID ${evidenceId} not found`);
      }
      
      const s3Key = evidenceKeys[0];
      
      // Get the head object to just retrieve metadata
      const response = await this.s3Client.send(new HeadObjectCommand({
        Bucket: this.bucketName,
        Key: s3Key
      }));
      
      // Extract metadata
      const evidenceMetadata = JSON.parse(response.Metadata['evidence-metadata']);
      
      logger.info(`Retrieved metadata for evidence ID: ${evidenceId}`);
      return evidenceMetadata;
    } catch (error) {
      logger.error(`Error retrieving evidence metadata: ${error.message}`);
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
      // List all objects in the bucket
      const objects = await this.s3Client.send(new ListObjectsV2Command({
        Bucket: this.bucketName
      }));
      
      if (!objects.Contents || objects.Contents.length === 0) {
        return [];
      }
      
      // Get metadata for each object and filter
      const results = [];
      
      for (const object of objects.Contents) {
        const response = await this.s3Client.send(new HeadObjectCommand({
          Bucket: this.bucketName,
          Key: object.Key
        }));
        
        // Skip objects without evidence metadata
        if (!response.Metadata || !response.Metadata['evidence-metadata']) {
          continue;
        }
        
        const metadata = JSON.parse(response.Metadata['evidence-metadata']);
        let match = true;
        
        // Apply filters
        if (filters.type && metadata.type !== filters.type) {
          match = false;
        }
        
        if (filters.caseId && metadata.caseId !== filters.caseId) {
          match = false;
        }
        
        if (filters.dateFrom && new Date(metadata.timestamp) < new Date(filters.dateFrom)) {
          match = false;
        }
        
        if (filters.dateTo && new Date(metadata.timestamp) > new Date(filters.dateTo)) {
          match = false;
        }
        
        if (filters.tags && Array.isArray(filters.tags) && filters.tags.length > 0) {
          // Check if the evidence has at least one of the specified tags
          const hasTag = filters.tags.some(tag => metadata.tags.includes(tag));
          if (!hasTag) {
            match = false;
          }
        }
        
        if (match) {
          results.push({
            evidenceId: metadata.evidenceId,
            metadata
          });
        }
      }
      
      logger.info(`Found ${results.length} evidence items matching filters`);
      return results;
    } catch (error) {
      logger.error(`Error searching evidence: ${error.message}`);
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
      const metadata = await this.getEvidenceMetadata(evidenceId);
      
      if (!metadata || !metadata.chainOfCustody) {
        throw new Error(`No chain of custody found for evidence ${evidenceId}`);
      }
      
      // Verify each entry in the chain of custody
      const validChain = metadata.chainOfCustody.every(entry => {
        const { signature, ...data } = entry;
        return this._verifySignature(JSON.stringify(data), signature);
      });
      
      if (!validChain) {
        throw new Error(`Chain of custody integrity check failed for evidence ${evidenceId}`);
      }
      
      logger.info(`Retrieved chain of custody for evidence ID: ${evidenceId}`);
      return metadata.chainOfCustody;
    } catch (error) {
      logger.error(`Error getting chain of custody: ${error.message}`);
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
      // Find the evidence by ID
      const objects = await this.s3Client.send(new ListObjectsV2Command({
        Bucket: this.bucketName,
        Prefix: '',
      }));
      
      const evidenceKeys = (objects.Contents || [])
        .filter(obj => obj.Key.endsWith(`/${evidenceId}`))
        .map(obj => obj.Key);
      
      if (evidenceKeys.length === 0) {
        throw new Error(`Evidence with ID ${evidenceId} not found`);
      }
      
      const s3Key = evidenceKeys[0];
      
      // Get the object
      const response = await this.s3Client.send(new GetObjectCommand({
        Bucket: this.bucketName,
        Key: s3Key
      }));
      
      // Extract metadata
      const evidenceMetadata = JSON.parse(response.Metadata['evidence-metadata']);
      
      // Read encrypted data for reupload
      const chunks = [];
      for await (const chunk of response.Body) {
        chunks.push(chunk);
      }
      const encryptedData = Buffer.concat(chunks);
      
      // Create and add chain of custody entry
      const custodyEntry = this._generateChainOfCustodyEntry(
        evidenceId,
        action,
        user,
        description
      );
      
      evidenceMetadata.chainOfCustody.push(custodyEntry);
      
      // Update metadata in S3
      await this.s3Client.send(new PutObjectCommand({
        Bucket: this.bucketName,
        Key: s3Key,
        Body: encryptedData,
        Metadata: {
          'evidence-metadata': JSON.stringify(evidenceMetadata)
        }
      }));
      
      logger.info(`Added custody event to evidence ID: ${evidenceId}`);
      return evidenceMetadata;
    } catch (error) {
      logger.error(`Error adding custody event: ${error.message}`);
      throw error;
    }
  }
}

module.exports = EvidenceVaultClient; 