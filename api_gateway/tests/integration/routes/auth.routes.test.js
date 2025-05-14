/**
 * Integration tests for auth routes
 */
const { describe, it, expect, jest: jestLocal, beforeAll, afterAll } = require('@jest/globals');
const request = require('supertest');
const app = require('../../../src/server');
const { generateToken } = require('../../../src/middleware/authMiddleware');
const User = require('../../../src/models/user.model');

// Mock dependencies
jest.mock('../../../src/models/user.model');
jest.mock('../../../src/middleware/authMiddleware');
jest.mock('../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  },
  httpLogger: (req, res, next) => next()
}));

describe('Auth Routes', () => {
  beforeAll(() => {
    // Setup mock implementations
    User.authenticate.mockImplementation(async (username, password) => {
      if (username === 'testuser' && password === 'password123') {
        return {
          id: '123',
          username: 'testuser',
          email: 'test@example.com',
          role: 'user'
        };
      }
      return null;
    });

    User.createUser.mockImplementation(async (userData) => {
      if (userData.username === 'existinguser') {
        throw new Error('Username already exists');
      }
      return {
        id: '456',
        username: userData.username,
        email: userData.email,
        role: userData.role || 'user'
      };
    });

    User.findById.mockImplementation((id) => {
      if (id === '123') {
        return {
          id: '123',
          username: 'testuser',
          email: 'test@example.com',
          role: 'user'
        };
      }
      return null;
    });

    generateToken.mockImplementation((user) => `mocked-token-for-${user.username}`);
  });

  describe('POST /api/auth/login', () => {
    it('should return 200 and token for valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('success');
      expect(response.body.message).toBe('Login successful');
      expect(response.body.data).toHaveProperty('token');
      expect(response.body.data.token).toBe('mocked-token-for-testuser');
      expect(response.body.data.user).toHaveProperty('username', 'testuser');
    });

    it('should return 401 for invalid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'wrongpassword'
        });

      expect(response.status).toBe(401);
      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Invalid username or password');
    });

    it('should return 400 for missing required fields', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser'
          // Missing password
        });

      expect(response.status).toBe(400);
      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Validation error');
    });
  });

  describe('POST /api/auth/register', () => {
    it('should return 201 for successful registration', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'new@example.com',
          password: 'password123'
        });

      expect(response.status).toBe(201);
      expect(response.body.status).toBe('success');
      expect(response.body.message).toBe('User registered successfully');
      expect(response.body.data.user).toHaveProperty('username', 'newuser');
      expect(response.body.data.user).toHaveProperty('email', 'new@example.com');
    });

    it('should return 409 if username already exists', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'existinguser',
          email: 'existing@example.com',
          password: 'password123'
        });

      expect(response.status).toBe(409);
      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Username already exists');
    });

    it('should return 400 for invalid email', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'invalid-email',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Validation error');
    });
  });

  describe('GET /api/auth/profile', () => {
    it('should return 200 and user profile for authenticated user', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', 'Bearer valid-token') // The auth middleware is mocked to accept this
        .send();

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('success');
      expect(response.body.data.user).toHaveProperty('username', 'testuser');
    });

    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .send();

      expect(response.status).toBe(401);
      expect(response.body.status).toBe('error');
    });
  });
}); 