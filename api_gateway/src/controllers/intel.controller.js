/**
 * Intelligence controller
 * 
 * Handles threat intelligence operations (IOCs, threat actors, etc.)
 */
const { v4: uuidv4 } = require('uuid');
const { dataLayerClient } = require('../utils/dataLayerClient');
const { ApiError } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');

/**
 * Get all IOCs with optional filtering
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getIOCs = async (req, res, next) => {
  try {
    const { limit = 100, offset = 0, ...filters } = req.query;
    
    logger.debug({ filters, limit, offset }, 'Getting IOCs');
    
    // Get IOCs from data layer
    const iocs = await dataLayerClient.searchIOCs(
      filters,
      parseInt(limit, 10),
      parseInt(offset, 10)
    );
    
    res.status(200).json({
      status: 'success',
      count: iocs.length,
      data: { iocs }
    });
  } catch (error) {
    logger.error({ error }, 'Error getting IOCs');
    next(error);
  }
};

/**
 * Get a single IOC by ID
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getIOCById = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    logger.debug({ iocId: id }, 'Getting IOC by ID');
    
    // Get IOC from data layer
    const ioc = await dataLayerClient.getIOC(id);
    
    if (!ioc) {
      throw new ApiError(404, `IOC with ID ${id} not found`);
    }
    
    res.status(200).json({
      status: 'success',
      data: { ioc }
    });
  } catch (error) {
    logger.error({ error, iocId: req.params.id }, 'Error getting IOC by ID');
    next(error);
  }
};

/**
 * Create a new IOC
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const createIOC = async (req, res, next) => {
  try {
    const iocData = req.body;
    
    // Add ioc_id if not provided
    if (!iocData.ioc_id) {
      iocData.ioc_id = uuidv4();
    }
    
    // Add timestamps if not provided
    if (!iocData.first_seen) {
      iocData.first_seen = new Date().toISOString();
    }
    
    if (!iocData.last_seen) {
      iocData.last_seen = new Date().toISOString();
    }
    
    // Add created_by field
    iocData.created_by = req.user ? req.user.username : 'system';
    
    logger.debug({ iocData }, 'Creating new IOC');
    
    // Store IOC in data layer
    const result = await dataLayerClient.createIOC(iocData);
    
    res.status(201).json({
      status: 'success',
      message: 'IOC created successfully',
      data: { ioc: result }
    });
  } catch (error) {
    logger.error({ error }, 'Error creating IOC');
    next(error);
  }
};

/**
 * Check if an entity is an IOC
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const checkIOC = async (req, res, next) => {
  try {
    const { type, value } = req.query;
    
    if (!type || !value) {
      throw new ApiError(400, 'Both type and value parameters are required');
    }
    
    logger.debug({ type, value }, 'Checking if entity is an IOC');
    
    // Search for IOCs with matching type and value
    const iocs = await dataLayerClient.searchIOCs({ type, value });
    
    const isIOC = iocs.length > 0;
    
    res.status(200).json({
      status: 'success',
      data: {
        isIOC,
        matches: iocs
      }
    });
  } catch (error) {
    logger.error({ error }, 'Error checking IOC');
    next(error);
  }
};

module.exports = {
  getIOCs,
  getIOCById,
  createIOC,
  checkIOC
}; 