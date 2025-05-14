/**
 * Logger utility for the API Gateway
 * 
 * Provides structured logging for the application
 */
const pino = require('pino');
const pinoHttp = require('pino-http');

// Configure the logger
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production' 
    ? { target: 'pino-pretty' } 
    : undefined,
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// HTTP logger middleware
const httpLogger = pinoHttp({
  logger,
  // Redact sensitive information
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.body.password',
      'req.body.token',
    ],
    remove: true,
  },
  customLogLevel: (res, err) => {
    if (res.statusCode >= 400 && res.statusCode < 500) return 'warn';
    if (res.statusCode >= 500 || err) return 'error';
    if (res.statusCode >= 300 && res.statusCode < 400) return 'silent';
    return 'info';
  },
  customSuccessMessage: (res) => {
    if (res.statusCode === 404) return 'Resource not found';
    return `Request completed with status ${res.statusCode}`;
  },
  customErrorMessage: (error, res) => {
    return `Request failed with status ${res.statusCode}: ${error.message}`;
  },
  customAttributeKeys: {
    req: 'request',
    res: 'response',
    err: 'error',
  },
});

module.exports = {
  logger,
  httpLogger,
}; 