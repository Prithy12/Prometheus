/**
 * User model for authentication
 * 
 * Simple in-memory user store for development purposes.
 * In production, this would be replaced with a database.
 */
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const { logger } = require('../utils/logger');

// In-memory user store
const users = [
  {
    id: '5f8d0cee-84fa-4e25-b7d3-f059fbac6d43',
    username: 'admin',
    email: 'admin@netguardian.org',
    password: '$2a$10$3GQfTe8xMqcsE/7Ihd3YpuwJZ8bnS65NhcJ9uXWHSeYJu0HH.7A/q', // hashed 'admin123'
    role: 'admin',
    created_at: '2023-01-01T00:00:00.000Z',
    last_login: null
  },
  {
    id: '9a6e2f12-5c4b-8d7e-1a9f-3b7c8e5d2a6f',
    username: 'analyst',
    email: 'analyst@netguardian.org',
    password: '$2a$10$NMNKT4pJ7LlQdRMGYxV9UuGKbSmLs6Y1KPPBU6r.53qswQJxL5AFq', // hashed 'analyst123'
    role: 'analyst',
    created_at: '2023-01-01T00:00:00.000Z',
    last_login: null
  },
  {
    id: '3c1e8a4d-9b7f-5e6d-2c3a-8b9e7f1d2c3a',
    username: 'user',
    email: 'user@netguardian.org',
    password: '$2a$10$xN5keMT48UkdD0JEUeS7w.v2Cj8zcYbQVuQbCY8TJ.QH0xiqh7pKK', // hashed 'user123'
    role: 'user',
    created_at: '2023-01-01T00:00:00.000Z',
    last_login: null
  }
];

/**
 * Find a user by username
 * @param {string} username - Username to find
 * @returns {Object|null} User object or null if not found
 */
const findByUsername = (username) => {
  const user = users.find(u => u.username === username);
  if (user) {
    // Return a copy without the password
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }
  return null;
};

/**
 * Find a user by ID
 * @param {string} id - User ID to find
 * @returns {Object|null} User object or null if not found
 */
const findById = (id) => {
  const user = users.find(u => u.id === id);
  if (user) {
    // Return a copy without the password
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }
  return null;
};

/**
 * Authenticate a user with username and password
 * @param {string} username - Username
 * @param {string} password - Password
 * @returns {Promise<Object|null>} User object if authenticated, null otherwise
 */
const authenticate = async (username, password) => {
  try {
    const user = users.find(u => u.username === username);
    if (!user) {
      logger.warn({ username }, 'Authentication failed: User not found');
      return null;
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn({ username }, 'Authentication failed: Password mismatch');
      return null;
    }
    
    // Update last login time
    user.last_login = new Date().toISOString();
    
    // Return a copy without the password
    const { password: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  } catch (error) {
    logger.error({ error }, 'Error during authentication');
    return null;
  }
};

/**
 * Create a new user
 * @param {Object} userData - User data
 * @returns {Promise<Object>} Created user object
 */
const createUser = async (userData) => {
  try {
    // Check if username or email already exists
    if (users.some(u => u.username === userData.username)) {
      throw new Error('Username already exists');
    }
    
    if (users.some(u => u.email === userData.email)) {
      throw new Error('Email already exists');
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(userData.password, salt);
    
    // Create new user
    const newUser = {
      id: uuidv4(),
      username: userData.username,
      email: userData.email,
      password: hashedPassword,
      role: userData.role || 'user',
      created_at: new Date().toISOString(),
      last_login: null
    };
    
    // Add to users array
    users.push(newUser);
    
    // Return a copy without the password
    const { password, ...userWithoutPassword } = newUser;
    return userWithoutPassword;
  } catch (error) {
    logger.error({ error }, 'Error creating user');
    throw error;
  }
};

module.exports = {
  findByUsername,
  findById,
  authenticate,
  createUser
}; 