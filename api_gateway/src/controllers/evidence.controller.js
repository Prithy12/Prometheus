/**
 * Evidence controller
 * 
 * Handles digital evidence operations
 */
const { v4: uuidv4 } = require('uuid');
const { dataLayerClient } = require('../utils/dataLayerClient');
const { ApiError } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');

/**
 * Upload evidence
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const uploadEvidence = async (req, res, next) => {
  try {
    const { metadata } = req.body;
    const data = req.body.data;
    
    if (!data) {
      throw new ApiError(400, 'Evidence data is required');
    }
    
    if (!metadata || !metadata.type || !metadata.description) {
      throw new ApiError(400, 'Evidence metadata is required (type and description at minimum)');
    }
    
    // Add evidenceId if not provided
    if (!metadata.evidenceId) {
      metadata.evidenceId = uuidv4();
    }
    
    // Add timestamp if not provided
    if (!metadata.timestamp) {
      metadata.timestamp = new Date().toISOString();
    }
    
    // Add user from request
    const user = req.user ? req.user.username : 'system';
    
    logger.debug({ 
      evidenceId: metadata.evidenceId,
      type: metadata.type,
      dataSize: data.length
    }, 'Uploading evidence');
    
    // Store evidence in data layer
    const result = await dataLayerClient.storeEvidence(data, metadata, user);
    
    res.status(201).json({
      status: 'success',
      message: 'Evidence uploaded successfully',
      data: result
    });
  } catch (error) {
    logger.error({ error }, 'Error uploading evidence');
    next(error);
  }
};

/**
 * Get evidence metadata
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getEvidenceMetadata = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    logger.debug({ evidenceId: id }, 'Getting evidence metadata');
    
    // Get evidence metadata from data layer
    const metadata = await dataLayerClient.getEvidenceMetadata(id);
    
    if (!metadata) {
      throw new ApiError(404, `Evidence with ID ${id} not found`);
    }
    
    res.status(200).json({
      status: 'success',
      data: { metadata }
    });
  } catch (error) {
    logger.error({ error, evidenceId: req.params.id }, 'Error getting evidence metadata');
    next(error);
  }
};

/**
 * Download evidence
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const downloadEvidence = async (req, res, next) => {
  try {
    const { id } = req.params;
    const user = req.user ? req.user.username : 'system';
    
    logger.debug({ evidenceId: id, user }, 'Downloading evidence');
    
    // First get metadata to check if evidence exists
    const metadata = await dataLayerClient.getEvidenceMetadata(id);
    
    if (!metadata) {
      throw new ApiError(404, `Evidence with ID ${id} not found`);
    }
    
    // Download evidence
    const data = await dataLayerClient.downloadEvidence(id, user);
    
    // Set response headers
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename=${id}`);
    
    // Send file data
    res.status(200).send(data);
  } catch (error) {
    logger.error({ error, evidenceId: req.params.id }, 'Error downloading evidence');
    next(error);
  }
};

/**
 * Get chain of custody for evidence
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getChainOfCustody = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    logger.debug({ evidenceId: id }, 'Getting chain of custody');
    
    // Get chain of custody from data layer
    const chain = await dataLayerClient.getChainOfCustody(id);
    
    if (!chain) {
      throw new ApiError(404, `Chain of custody for evidence ID ${id} not found`);
    }
    
    res.status(200).json({
      status: 'success',
      data: { chain }
    });
  } catch (error) {
    logger.error({ error, evidenceId: req.params.id }, 'Error getting chain of custody');
    next(error);
  }
};

/**
 * Search for evidence
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const searchEvidence = async (req, res, next) => {
  try {
    const filters = req.query;
    
    logger.debug({ filters }, 'Searching for evidence');
    
    // Search for evidence in data layer
    const evidence = await dataLayerClient.searchEvidence(filters);
    
    res.status(200).json({
      status: 'success',
      count: evidence.length,
      data: { evidence }
    });
  } catch (error) {
    logger.error({ error }, 'Error searching for evidence');
    next(error);
  }
};

module.exports = {
  uploadEvidence,
  getEvidenceMetadata,
  downloadEvidence,
  getChainOfCustody,
  searchEvidence
}; 