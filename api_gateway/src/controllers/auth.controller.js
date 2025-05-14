/**
 * Authentication controller
 * 
 * Handles user authentication and authorization
 */
const { generateToken } = require('../middleware/authMiddleware');
const User = require('../models/user.model');
const { ApiError } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');

/**
 * Login a user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    // Authenticate user
    const user = await User.authenticate(username, password);
    if (!user) {
      throw new ApiError(401, 'Invalid username or password');
    }
    
    // Generate JWT token
    const token = generateToken(user);
    
    logger.info({ username: user.username, userId: user.id }, 'User logged in successfully');
    
    // Return user info and token
    res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        token,
        expiresIn: 86400, // 24 hours
        user
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Register a new user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const register = async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body;
    
    // Create new user
    const user = await User.createUser({
      username,
      email,
      password,
      role: role || 'user' // Default to 'user' role
    });
    
    logger.info({ username: user.username, userId: user.id }, 'New user registered');
    
    // Return user info
    res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      data: { user }
    });
  } catch (error) {
    if (error.message === 'Username already exists' || error.message === 'Email already exists') {
      next(new ApiError(409, error.message));
    } else {
      next(error);
    }
  }
};

/**
 * Get current user profile
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const getProfile = async (req, res, next) => {
  try {
    // User is already attached to request by auth middleware
    const { id } = req.user;
    
    // Find user by ID
    const user = User.findById(id);
    if (!user) {
      throw new ApiError(404, 'User not found');
    }
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  login,
  register,
  getProfile
}; 