/**
 * Request validation middleware for the API Gateway
 * 
 * Provides input validation using express-validator
 */
const { validationResult } = require('express-validator');
const { ApiError } = require('./errorHandler');

/**
 * Middleware to validate request based on provided validation rules
 * @param {Array} validations - Array of express-validator validation rules
 * @returns {function} Middleware function
 */
const validate = (validations) => {
  return async (req, res, next) => {
    // Execute all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Format validation errors
      const formattedErrors = errors.array().map(err => ({
        field: err.param,
        message: err.msg,
        value: err.value
      }));
      
      // Create API error with validation details
      const error = new ApiError(
        400, 
        'Validation error', 
        formattedErrors
      );
      
      return next(error);
    }
    
    return next();
  };
};

module.exports = {
  validate,
}; 