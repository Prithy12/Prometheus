/**
 * Events controller
 * 
 * Handles security event operations
 */
const { v4: uuidv4 } = require('uuid');
const { dataLayerClient } = require('../utils/dataLayerClient');
const { ApiError } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');

/**
 * Get all events with optional filtering
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getEvents = async (req, res, next) => {
  try {
    const { limit = 100, offset = 0, ...filters } = req.query;
    
    logger.debug({ filters, limit, offset }, 'Getting events');
    
    // Get events from data layer
    const events = await dataLayerClient.getEvents(
      filters,
      parseInt(limit, 10),
      parseInt(offset, 10)
    );
    
    res.status(200).json({
      status: 'success',
      count: events.length,
      data: { events }
    });
  } catch (error) {
    logger.error({ error }, 'Error getting events');
    next(error);
  }
};

/**
 * Get a single event by ID
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getEventById = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    logger.debug({ eventId: id }, 'Getting event by ID');
    
    // Get event from data layer
    const event = await dataLayerClient.getEvents({ event_id: id });
    
    if (!event || event.length === 0) {
      throw new ApiError(404, `Event with ID ${id} not found`);
    }
    
    res.status(200).json({
      status: 'success',
      data: { event: event[0] }
    });
  } catch (error) {
    logger.error({ error, eventId: req.params.id }, 'Error getting event by ID');
    next(error);
  }
};

/**
 * Create a new security event
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const createEvent = async (req, res, next) => {
  try {
    const eventData = req.body;
    
    // Add event_id if not provided
    if (!eventData.event_id) {
      eventData.event_id = uuidv4();
    }
    
    // Add timestamp if not provided
    if (!eventData.timestamp) {
      eventData.timestamp = new Date().toISOString();
    }
    
    // Add processed_by field
    eventData.processed_by = `api_gateway:${req.user ? req.user.username : 'system'}`;
    
    logger.debug({ eventData }, 'Creating new event');
    
    // Store event in data layer
    const result = await dataLayerClient.storeEvent(eventData);
    
    res.status(201).json({
      status: 'success',
      message: 'Event created successfully',
      data: { event_id: result.eventId || eventData.event_id }
    });
  } catch (error) {
    logger.error({ error }, 'Error creating event');
    next(error);
  }
};

/**
 * Create multiple security events in batch
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const createEvents = async (req, res, next) => {
  try {
    const events = req.body;
    
    if (!Array.isArray(events)) {
      throw new ApiError(400, 'Request body must be an array of events');
    }
    
    // Prepare events (add IDs, timestamps, etc.)
    const preparedEvents = events.map(event => ({
      ...event,
      event_id: event.event_id || uuidv4(),
      timestamp: event.timestamp || new Date().toISOString(),
      processed_by: `api_gateway:${req.user ? req.user.username : 'system'}`
    }));
    
    logger.debug({ eventCount: preparedEvents.length }, 'Creating events in batch');
    
    // Store events in data layer
    const result = await dataLayerClient.storeEvents(preparedEvents);
    
    res.status(201).json({
      status: 'success',
      message: 'Events created successfully',
      data: { 
        count: preparedEvents.length,
        event_ids: result.eventIds || preparedEvents.map(e => e.event_id)
      }
    });
  } catch (error) {
    logger.error({ error }, 'Error creating events in batch');
    next(error);
  }
};

/**
 * Get security alerts (high severity events)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getAlerts = async (req, res, next) => {
  try {
    const { limit = 100, offset = 0, ...filters } = req.query;
    
    logger.debug({ filters, limit, offset }, 'Getting alerts');
    
    // Get alerts from data layer
    const alerts = await dataLayerClient.getAlerts(
      filters,
      parseInt(limit, 10),
      parseInt(offset, 10)
    );
    
    res.status(200).json({
      status: 'success',
      count: alerts.length,
      data: { alerts }
    });
  } catch (error) {
    logger.error({ error }, 'Error getting alerts');
    next(error);
  }
};

/**
 * Get event summary statistics
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getEventSummary = async (req, res, next) => {
  try {
    const filters = req.query;
    
    logger.debug({ filters }, 'Getting event summary');
    
    // Get event summary from data layer
    const summary = await dataLayerClient.getEventSummary(filters);
    
    res.status(200).json({
      status: 'success',
      data: { summary }
    });
  } catch (error) {
    logger.error({ error }, 'Error getting event summary');
    next(error);
  }
};

module.exports = {
  getEvents,
  getEventById,
  createEvent,
  createEvents,
  getAlerts,
  getEventSummary
}; 