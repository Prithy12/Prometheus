/**
 * Logger utility for NetGuardian Log Collector
 * 
 * Configurable logger with different log levels and output formats
 */
const pino = require('pino');

// Get log level from environment variable or use default
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

// Configure logger
const logger = pino({
  level: LOG_LEVEL,
  transport: process.env.NODE_ENV !== 'production' 
    ? { target: 'pino-pretty' } 
    : undefined,
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  base: {
    pid: process.pid,
    hostname: process.env.HOSTNAME || 'unknown',
    name: 'log-collector'
  },
  redact: {
    paths: [
      'password',
      'token',
      'secret',
      '*.password',
      '*.token',
      '*.secret'
    ],
    censor: '[REDACTED]'
  }
});

module.exports = {
  logger
}; 