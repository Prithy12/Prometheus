/**
 * Error handling middleware for the API Gateway
 * 
 * Provides standardized error handling for the application
 */
const { logger } = require('../utils/logger');

/**
 * Custom error class for API errors
 */
class ApiError extends Error {
  constructor(statusCode, message, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Middleware for handling 404 errors
 */
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Resource not found: ${req.originalUrl}`);
  next(error);
};

/**
 * Middleware for handling all other errors
 */
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  
  // Log the error
  if (statusCode >= 500) {
    logger.error({
      err,
      req: {
        method: req.method,
        url: req.originalUrl,
        body: req.body,
        ip: req.ip
      }
    }, `Error: ${message}`);
  } else {
    logger.warn({
      err,
      req: {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip
      }
    }, `Error: ${message}`);
  }
  
  // Send response
  res.status(statusCode).json({
    status: 'error',
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    ...(err.details && { details: err.details })
  });
};

module.exports = {
  ApiError,
  notFoundHandler,
  errorHandler
}; 