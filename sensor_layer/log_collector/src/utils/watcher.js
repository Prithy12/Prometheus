/**
 * File and directory watcher utility
 * 
 * Handles monitoring of log files and directories for changes
 */
const fs = require('fs');
const path = require('path');
const chokidar = require('chokidar');
const { Tail } = require('tail');
const { logger } = require('./logger');

// Track active watchers
const activeWatchers = {
  files: new Map(),
  directories: new Map()
};

/**
 * Initialize watchers for all configured log sources
 * 
 * @param {Array<Object>} logSources - Array of log source configurations
 * @param {Function} processCallback - Callback function for processing log entries
 */
function initializeWatchers(logSources, processCallback) {
  if (!Array.isArray(logSources) || logSources.length === 0) {
    logger.warn('No log sources configured');
    return;
  }
  
  logSources.forEach(source => {
    try {
      if (source.type === 'file') {
        watchFile(source, processCallback);
      } else if (source.type === 'directory') {
        watchDirectory(source, processCallback);
      } else {
        logger.warn({ source }, 'Unknown log source type');
      }
    } catch (error) {
      logger.error({ error, source }, 'Error initializing watcher');
    }
  });
  
  logger.info(`Initialized ${activeWatchers.files.size} file watchers and ${activeWatchers.directories.size} directory watchers`);
}

/**
 * Watch a single log file
 * 
 * @param {Object} source - Log source configuration
 * @param {Function} processCallback - Callback function for processing log entries
 */
function watchFile(source, processCallback) {
  if (!source.path) {
    logger.warn({ source }, 'Missing file path in log source configuration');
    return;
  }
  
  try {
    // Check if file exists
    if (!fs.existsSync(source.path)) {
      logger.warn({ path: source.path }, 'Log file does not exist');
      return;
    }
    
    // Create tail instance
    const tail = new Tail(source.path, {
      follow: true,
      fromBeginning: source.fromBeginning || false,
      flushAtEOF: true,
      useWatchFile: true,
      fsWatchOptions: {
        interval: 1000
      }
    });
    
    // Handle new lines
    tail.on('line', line => {
      processCallback({
        source: source.format,
        content: line,
        metadata: {
          path: source.path,
          timestamp: new Date().toISOString()
        }
      });
    });
    
    // Handle errors
    tail.on('error', error => {
      logger.error({ error, path: source.path }, 'Error watching file');
    });
    
    // Store tail instance
    activeWatchers.files.set(source.path, tail);
    
    logger.info({ path: source.path, format: source.format }, 'File watcher initialized');
  } catch (error) {
    logger.error({ error, path: source.path }, 'Failed to initialize file watcher');
  }
}

/**
 * Watch a directory for log files
 * 
 * @param {Object} source - Log source configuration
 * @param {Function} processCallback - Callback function for processing log entries
 */
function watchDirectory(source, processCallback) {
  if (!source.path) {
    logger.warn({ source }, 'Missing directory path in log source configuration');
    return;
  }
  
  try {
    // Check if directory exists
    if (!fs.existsSync(source.path)) {
      logger.warn({ path: source.path }, 'Log directory does not exist');
      return;
    }
    
    // Create pattern for watching files
    const pattern = source.pattern || '*.log';
    const watchPattern = path.join(source.path, pattern);
    
    // Create watcher
    const watcher = chokidar.watch(watchPattern, {
      persistent: true,
      ignoreInitial: !source.processExisting,
      awaitWriteFinish: {
        stabilityThreshold: 2000,
        pollInterval: 100
      }
    });
    
    // Handle new files
    watcher.on('add', filePath => {
      logger.info({ path: filePath }, 'New log file detected');
      
      // If this is an existing file and we should process it
      if (source.processExisting) {
        processExistingFile(filePath, source.format, processCallback);
      }
      
      // Start watching this file for changes
      if (!activeWatchers.files.has(filePath)) {
        watchFile({
          path: filePath,
          format: source.format,
          fromBeginning: false
        }, processCallback);
      }
    });
    
    // Handle file changes
    watcher.on('change', filePath => {
      // The file is already being watched by its own tail instance
      // so we don't need to handle changes here
    });
    
    // Handle errors
    watcher.on('error', error => {
      logger.error({ error, path: source.path }, 'Error watching directory');
    });
    
    // Store watcher instance
    activeWatchers.directories.set(source.path, watcher);
    
    logger.info({ path: source.path, pattern, format: source.format }, 'Directory watcher initialized');
  } catch (error) {
    logger.error({ error, path: source.path }, 'Failed to initialize directory watcher');
  }
}

/**
 * Process an existing file's contents
 * 
 * @param {string} filePath - Path to the file
 * @param {string} format - Log format identifier
 * @param {Function} processCallback - Callback function for processing log entries
 */
function processExistingFile(filePath, format, processCallback) {
  try {
    // Read file contents
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);
    
    logger.info({ path: filePath, lineCount: lines.length }, 'Processing existing file');
    
    // Process each line
    lines.forEach(line => {
      if (line.trim()) {
        processCallback({
          source: format,
          content: line,
          metadata: {
            path: filePath,
            timestamp: new Date().toISOString(),
            isHistorical: true
          }
        });
      }
    });
  } catch (error) {
    logger.error({ error, path: filePath }, 'Error processing existing file');
  }
}

/**
 * Close all active watchers
 */
function closeWatchers() {
  // Close file watchers
  for (const [path, tail] of activeWatchers.files.entries()) {
    try {
      tail.unwatch();
      logger.debug({ path }, 'File watcher closed');
    } catch (error) {
      logger.error({ error, path }, 'Error closing file watcher');
    }
  }
  activeWatchers.files.clear();
  
  // Close directory watchers
  for (const [path, watcher] of activeWatchers.directories.entries()) {
    try {
      watcher.close();
      logger.debug({ path }, 'Directory watcher closed');
    } catch (error) {
      logger.error({ error, path }, 'Error closing directory watcher');
    }
  }
  activeWatchers.directories.clear();
  
  logger.info('All watchers closed');
}

module.exports = {
  initializeWatchers,
  closeWatchers
}; 