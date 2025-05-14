/**
 * Unit tests for auth controller
 */
const { describe, it, expect, jest: jestLocal, beforeEach } = require('@jest/globals');
const authController = require('../../../src/controllers/auth.controller');
const User = require('../../../src/models/user.model');
const { ApiError } = require('../../../src/middleware/errorHandler');
const { generateToken } = require('../../../src/middleware/authMiddleware');

// Mock dependencies
jest.mock('../../../src/models/user.model');
jest.mock('../../../src/middleware/authMiddleware');
jest.mock('../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}));

describe('Auth Controller', () => {
  let req;
  let res;
  let next;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Set up request, response, and next function
    req = {
      body: {},
      user: {}
    };

    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    next = jest.fn();
  });

  describe('login', () => {
    it('should return 200 and token if credentials are valid', async () => {
      // Arrange
      const user = {
        id: '123',
        username: 'testuser',
        email: 'test@example.com',
        role: 'user'
      };
      const token = 'valid-token';
      req.body = { username: 'testuser', password: 'password123' };
      User.authenticate.mockResolvedValue(user);
      generateToken.mockReturnValue(token);

      // Act
      await authController.login(req, res, next);

      // Assert
      expect(User.authenticate).toHaveBeenCalledWith('testuser', 'password123');
      expect(generateToken).toHaveBeenCalledWith(user);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        message: 'Login successful',
        data: {
          token,
          expiresIn: 86400,
          user
        }
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should call next with error if credentials are invalid', async () => {
      // Arrange
      req.body = { username: 'testuser', password: 'wrongpassword' };
      User.authenticate.mockResolvedValue(null);

      // Act
      await authController.login(req, res, next);

      // Assert
      expect(User.authenticate).toHaveBeenCalledWith('testuser', 'wrongpassword');
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(401);
      expect(next.mock.calls[0][0].message).toBe('Invalid username or password');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });

    it('should call next with error if authentication throws', async () => {
      // Arrange
      const error = new Error('Database error');
      req.body = { username: 'testuser', password: 'password123' };
      User.authenticate.mockRejectedValue(error);

      // Act
      await authController.login(req, res, next);

      // Assert
      expect(User.authenticate).toHaveBeenCalledWith('testuser', 'password123');
      expect(next).toHaveBeenCalledWith(error);
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });
  });

  describe('register', () => {
    it('should return 201 and user data if registration is successful', async () => {
      // Arrange
      const userData = {
        username: 'newuser',
        email: 'new@example.com',
        password: 'password123',
        role: 'user'
      };
      const createdUser = {
        id: '456',
        username: 'newuser',
        email: 'new@example.com',
        role: 'user'
      };
      req.body = userData;
      User.createUser.mockResolvedValue(createdUser);

      // Act
      await authController.register(req, res, next);

      // Assert
      expect(User.createUser).toHaveBeenCalledWith(userData);
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        message: 'User registered successfully',
        data: { user: createdUser }
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should call next with conflict error if username already exists', async () => {
      // Arrange
      const error = new Error('Username already exists');
      req.body = {
        username: 'existinguser',
        email: 'new@example.com',
        password: 'password123'
      };
      User.createUser.mockRejectedValue(error);

      // Act
      await authController.register(req, res, next);

      // Assert
      expect(User.createUser).toHaveBeenCalled();
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(409);
      expect(next.mock.calls[0][0].message).toBe('Username already exists');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });
  });

  describe('getProfile', () => {
    it('should return 200 and user profile if user exists', async () => {
      // Arrange
      const user = {
        id: '123',
        username: 'testuser',
        email: 'test@example.com',
        role: 'user'
      };
      req.user = { id: '123' };
      User.findById.mockReturnValue(user);

      // Act
      await authController.getProfile(req, res, next);

      // Assert
      expect(User.findById).toHaveBeenCalledWith('123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { user }
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should call next with error if user does not exist', async () => {
      // Arrange
      req.user = { id: 'nonexistent' };
      User.findById.mockReturnValue(null);

      // Act
      await authController.getProfile(req, res, next);

      // Assert
      expect(User.findById).toHaveBeenCalledWith('nonexistent');
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(404);
      expect(next.mock.calls[0][0].message).toBe('User not found');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });
  });
}); 