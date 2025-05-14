/**
 * Event Transformer
 * 
 * Transforms parsed log entries into security events
 */
const { v4: uuidv4 } = require('uuid');
const { logger } = require('../utils/logger');

/**
 * Transform a parsed log entry into a security event
 * 
 * @param {Object} parsedEntry - The parsed log entry
 * @param {string} source - The source of the log entry
 * @returns {Object|null} Security event or null if no event is generated
 */
function transform(parsedEntry, source) {
  if (!parsedEntry || !parsedEntry.event_type) {
    return null;
  }
  
  try {
    // Create base event with common fields
    const baseEvent = {
      event_id: uuidv4(),
      timestamp: parsedEntry.timestamp || new Date().toISOString(),
      source_ip: parsedEntry.source_ip,
      source_port: parsedEntry.source_port,
      destination_ip: parsedEntry.destination_ip,
      destination_port: parsedEntry.destination_port,
      protocol: parsedEntry.protocol,
      event_type: parsedEntry.event_type,
      severity: calculateSeverity(parsedEntry),
      confidence: calculateConfidence(parsedEntry),
      description: parsedEntry.description || generateDescription(parsedEntry),
      raw_data: JSON.stringify(parsedEntry.raw_data || parsedEntry),
      processed_by: 'netguardian-log-collector'
    };
    
    // Add source-specific fields based on the event type
    switch (parsedEntry.event_type) {
      case 'intrusion_attempt':
        return enhanceIntrusionEvent(baseEvent, parsedEntry);
      
      case 'authentication_failure':
      case 'credential_access':
        return enhanceAuthEvent(baseEvent, parsedEntry);
      
      case 'malware_detection':
        return enhanceMalwareEvent(baseEvent, parsedEntry);
      
      case 'reconnaissance':
        return enhanceReconEvent(baseEvent, parsedEntry);
      
      default:
        return baseEvent;
    }
  } catch (error) {
    logger.error({ error, source, parsedEntry }, 'Error transforming event');
    return null;
  }
}

/**
 * Calculate event severity based on parsed entry
 * 
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {number} Severity level (1-10)
 */
function calculateSeverity(parsedEntry) {
  // If severity is already set, use it
  if (parsedEntry.severity && parsedEntry.severity >= 1 && parsedEntry.severity <= 10) {
    return parsedEntry.severity;
  }
  
  // Calculate based on event type
  switch (parsedEntry.event_type) {
    case 'intrusion_attempt':
      return 8;
    
    case 'malware_detection':
      return 9;
    
    case 'reconnaissance':
      return 4;
    
    case 'authentication_failure':
      // Increase severity for multiple failures or privileged accounts
      if (parsedEntry.count > 3 || parsedEntry.username === 'root' || parsedEntry.username === 'admin') {
        return 7;
      }
      return 5;
    
    case 'credential_access':
      return 8;
    
    case 'lateral_movement':
      return 8;
    
    case 'privilege_escalation':
      return 9;
    
    case 'defense_evasion':
      return 8;
    
    case 'command_and_control':
      return 9;
    
    case 'data_exfiltration':
      return 10;
    
    case 'impact':
      return 10;
    
    default:
      return 5;
  }
}

/**
 * Calculate confidence level based on parsed entry
 * 
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {number} Confidence level (1-10)
 */
function calculateConfidence(parsedEntry) {
  // If confidence is already set, use it
  if (parsedEntry.confidence && parsedEntry.confidence >= 1 && parsedEntry.confidence <= 10) {
    return parsedEntry.confidence;
  }
  
  // Default confidence level
  let confidence = 7;
  
  // Adjust confidence based on various factors
  if (parsedEntry.matched_rule) {
    confidence += 1; // More confidence if it matched a specific rule
  }
  
  if (parsedEntry.raw_data) {
    confidence += 1; // More confidence if we have the raw data
  }
  
  // Cap confidence between 1 and 10
  return Math.min(Math.max(confidence, 1), 10);
}

/**
 * Generate a description for the event
 * 
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {string} Event description
 */
function generateDescription(parsedEntry) {
  switch (parsedEntry.event_type) {
    case 'intrusion_attempt':
      return `Possible intrusion attempt from ${parsedEntry.source_ip}${parsedEntry.attack_type ? ` using ${parsedEntry.attack_type}` : ''}`;
    
    case 'authentication_failure':
      return `Authentication failure for user ${parsedEntry.username || 'unknown'} from ${parsedEntry.source_ip || 'unknown IP'}`;
    
    case 'reconnaissance':
      return `Reconnaissance activity detected from ${parsedEntry.source_ip}${parsedEntry.scan_type ? ` (${parsedEntry.scan_type})` : ''}`;
    
    case 'malware_detection':
      return `Malware detected: ${parsedEntry.malware_name || 'unknown'} on ${parsedEntry.hostname || parsedEntry.destination_ip || 'unknown host'}`;
    
    default:
      return `Security event: ${parsedEntry.event_type}`;
  }
}

/**
 * Enhance intrusion attempt events with additional fields
 * 
 * @param {Object} baseEvent - The base security event
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {Object} Enhanced security event
 */
function enhanceIntrusionEvent(baseEvent, parsedEntry) {
  return {
    ...baseEvent,
    attack_vector: parsedEntry.attack_vector,
    attack_type: parsedEntry.attack_type,
    targeted_service: parsedEntry.targeted_service,
    matched_signatures: parsedEntry.matched_signatures,
    cve_id: parsedEntry.cve_id
  };
}

/**
 * Enhance authentication events with additional fields
 * 
 * @param {Object} baseEvent - The base security event
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {Object} Enhanced security event
 */
function enhanceAuthEvent(baseEvent, parsedEntry) {
  // Normalize event_type to conform to API schema
  baseEvent.event_type = 'credential_access';
  
  return {
    ...baseEvent,
    username: parsedEntry.username,
    auth_method: parsedEntry.auth_method,
    failure_reason: parsedEntry.failure_reason,
    attempt_count: parsedEntry.count || 1,
    hostname: parsedEntry.hostname
  };
}

/**
 * Enhance malware detection events with additional fields
 * 
 * @param {Object} baseEvent - The base security event
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {Object} Enhanced security event
 */
function enhanceMalwareEvent(baseEvent, parsedEntry) {
  return {
    ...baseEvent,
    malware_name: parsedEntry.malware_name,
    malware_type: parsedEntry.malware_type,
    detection_method: parsedEntry.detection_method,
    file_path: parsedEntry.file_path,
    file_hash: parsedEntry.file_hash,
    action_taken: parsedEntry.action_taken
  };
}

/**
 * Enhance reconnaissance events with additional fields
 * 
 * @param {Object} baseEvent - The base security event
 * @param {Object} parsedEntry - The parsed log entry
 * @returns {Object} Enhanced security event
 */
function enhanceReconEvent(baseEvent, parsedEntry) {
  return {
    ...baseEvent,
    scan_type: parsedEntry.scan_type,
    ports_scanned: parsedEntry.ports,
    scan_duration: parsedEntry.duration,
    tool_signature: parsedEntry.tool_signature
  };
}

module.exports = {
  transform
}; 