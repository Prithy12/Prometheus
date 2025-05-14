/**
 * Authentication middleware for the API Gateway
 * 
 * Handles JWT token validation and role-based access control
 */
const jwt = require('jsonwebtoken');
const { ApiError } = require('./errorHandler');
const { logger } = require('../utils/logger');

// Get JWT secret from environment or use a default for development
const JWT_SECRET = process.env.JWT_SECRET || 'netguardian-dev-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

/**
 * Generate a JWT token for a user
 * @param {Object} user - User object
 * @returns {string} JWT token
 */
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

/**
 * Middleware to check if a request has a valid JWT token
 */
const authenticate = (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new ApiError(401, 'No token provided or invalid token format');
    }

    const token = authHeader.split(' ')[1];
    
    // Verify token
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        logger.warn({ err }, 'Failed to verify JWT token');
        throw new ApiError(401, 'Invalid or expired token');
      }
      
      // Attach user info to request object
      req.user = decoded;
      next();
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Middleware to check if a user has specific roles
 * @param {string[]} roles - Array of allowed roles
 * @returns {function} Middleware function
 */
const authorize = (roles = []) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new ApiError(401, 'Authentication required');
      }
      
      if (roles.length && !roles.includes(req.user.role)) {
        logger.warn({
          user: req.user.username,
          requiredRoles: roles,
          userRole: req.user.role
        }, 'Insufficient permissions');
        
        throw new ApiError(403, 'Insufficient permissions to access this resource');
      }
      
      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = {
  generateToken,
  authenticate,
  authorize,
  JWT_SECRET,
  JWT_EXPIRES_IN
}; 